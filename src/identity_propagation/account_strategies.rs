// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The per-descriptor strategy registry: ONE credential boundary, two consumers.
//!
//! WHY A REGISTRY KEYED BY DESCRIPTOR. `MetaMcp::backend_identity_propagation`
//! is keyed by BACKEND NAME, which is the right key for an MCP backend and the
//! wrong one for a REST capability: a capability names an
//! `accounts.descriptors` MAP KEY directly and may be the only consumer of that
//! account. Keying this registry by descriptor id is what lets both consumers
//! hold the SAME `Arc<dyn IdentityPropagation>` — the shared installer inserts
//! once here and hands that very instance to `set_backend_identity_propagation`.
//! There is no second store, no second auth enum and no second lookup pipeline.
//!
//! DECLARATION IS NOT INSTALLATION. `declare` records what the validated
//! configuration says an account IS (its provider and mode) and runs BEFORE
//! capabilities are registered, so an unresolved reference or a provider
//! mismatch is refused at the registration boundary. `install` records what can
//! actually MINT for it. A declared-but-uninstalled descriptor is exactly the
//! state a reload leaves behind when a binding is dropped, and [`Self::resolve`]
//! refuses it rather than borrowing an unrelated strategy.
//!
//! NOTHING FALLS BACK. Every refusal below is an `Err`. The one non-error,
//! non-credential answer is [`AccountCredential::Legacy`], returned ONLY for an
//! explicit `shared` descriptor — an account the deployment already serves
//! statically, whose existing behaviour this increment must not tighten.
//!
//! AUDIT IS FAIL-CLOSED ON THE MINT PATH, identically to the Meta-MCP route: a
//! `required` account with no transparency log refuses rather than minting
//! blind, and an audit-write failure aborts the mint. Only subject, account,
//! audience and reason are ever written — never the credential.

use std::collections::BTreeMap;
use std::sync::Arc;

use parking_lot::RwLock;

use super::{BackendDescriptor, IdentityPropagation, audit_identity_propagation, audit_subject};
use crate::key_server::oidc::VerifiedIdentity;
use crate::personal_accounts::config::DescriptorMode;
use crate::security::TransparencyLogger;
use crate::{Error, Result};

/// What the validated configuration says an account IS. Keyed by the
/// `accounts.descriptors` map key — the logical `backend_id` of the account key,
/// and the only thing `auth.account` may name.
#[derive(Clone, Debug)]
pub(crate) struct DeclaredAccount {
    /// The descriptor's logical OAuth provider id. A capability's
    /// `auth.key` must be exactly `oauth:<provider>`; the provider NEVER
    /// selects an account on its own.
    pub(crate) provider: String,
    /// The declared mode, as written. No mode is ever inferred.
    pub(crate) mode: DescriptorMode,
}

/// What can actually mint for an account, installed before serving.
pub(crate) struct InstalledAccount {
    pub(crate) descriptor_id: String,
    pub(crate) provider: String,
    /// The audience the credential is scoped to: a managed descriptor's own
    /// RFC 8707 resource, or an external strategy's configured audience.
    pub(crate) audience: String,
    pub(crate) required: bool,
    pub(crate) token_exchange_endpoint: Option<String>,
    pub(crate) token_exchange_scope: Option<String>,
    /// The strategy instance. Shared with the per-backend install for the same
    /// descriptor, so two consumers can never drift onto two strategies.
    pub(crate) strategy: Arc<dyn IdentityPropagation>,
    /// The SAME instance as [`Self::strategy`], typed, when this descriptor is
    /// `personal_managed`.
    ///
    /// Not a second install and not a second strategy: the installer builds one
    /// `Arc<VaultStrategy>`, hands it here and coerces that very `Arc` into the
    /// trait object above and into the per-backend MCP map, so one descriptor
    /// has one key, one resolver and one store no matter which consumer reaches
    /// it. It is retained typed because durable custody is not expressible
    /// through [`IdentityPropagation`]: `propagate` mints, and a recheck must
    /// NOT mint. `None` for an external descriptor, whose published expiry and
    /// strategy behaviour stay exactly what they were.
    pub(crate) managed: Option<Arc<crate::personal_accounts::VaultStrategy>>,
}

/// What resolving an account reference produced.
pub(crate) enum AccountCredential {
    /// An explicit `shared` descriptor: use the EXISTING static credential
    /// path, unchanged. Never returned for `personal_managed` or `external`.
    Legacy,
    /// A credential minted for the verified identity, carrying the headers to
    /// put on the wire VERBATIM plus the opaque binding and expiry the strategy
    /// published. Resolved ONCE per dispatch, before any cache is consulted.
    Prepared(Arc<PreparedAccountCredential>),
}

/// One dispatch's account credential, resolved before the first cache lookup.
///
/// WHY THIS EXISTS. A cache key that is built before the account is resolved is
/// a key that cannot name the account holder, so the first caller's result
/// would be served to the next one. Resolving first and CARRYING the answer is
/// what lets the outer response cache, the inner capability cache and the
/// egress headers all speak about the same credential — the same shape the MCP
/// route already uses (`CallerCredential`, resolved once in
/// `invoke_tool_traced` and reused verbatim at dispatch).
///
/// The binding and the expiry are the STRATEGY's own values
/// ([`crate::identity_propagation::PropagatedCredential::cache_binding`] /
/// `expires_at`), copied and never re-derived here: the vault publishes the
/// five-field account digest widened with the grant generation, authorization
/// epoch, token revision and descriptor revision, and a re-authorized, rotated
/// or revoked account therefore produces a DIFFERENT binding rather than a
/// silently reused one.
///
/// `Debug` redacts header values: they carry the live credential (CWE-532).
pub(crate) struct PreparedAccountCredential {
    /// The `accounts.descriptors` map key this was minted for.
    pub(crate) descriptor_id: String,
    /// The capability's `auth.key`, revalidated against the descriptor's
    /// provider on every recheck.
    pub(crate) auth_key: String,
    /// The verified caller this credential belongs to, as the same
    /// length-prefixed issuer+subject derivation the account key uses. A
    /// recheck for any other principal refuses.
    pub(crate) actor_id: String,
    /// The audience the credential is scoped to, as installed.
    pub(crate) audience: String,
    /// The strategy's opaque cache binding. Copied into every cache key,
    /// never re-hashed and never parsed.
    pub(crate) cache_binding: String,
    /// The strategy's published expiry, in Unix seconds, exactly as minted.
    pub(crate) expires_at: i64,
    /// Unix seconds at which this credential was minted. Kept so a published
    /// LIFETIME can be told apart from a strategy that publishes none (the
    /// vault deliberately publishes `expires_at == minted_at`, because its
    /// credential is not reusable past the dispatch it was released for).
    pub(crate) minted_at: i64,
    /// The strategy instance that minted it, so a recheck can prove the
    /// installed strategy has not been swapped underneath this dispatch.
    strategy: Arc<dyn IdentityPropagation>,
    /// For a MANAGED descriptor: the concrete strategy and the LEASE this
    /// credential was released under.
    ///
    /// This is what makes the recheck a custody boundary rather than a registry
    /// comparison. The lease names the grant generation, authorization epoch,
    /// token revision and descriptor revision the credential came from, so
    /// re-releasing it asks the durable store the only question that matters
    /// before a cache entry is selected or a request goes out: is THIS still
    /// the current grant? A revocation committed after the credential was
    /// prepared answers no.
    ///
    /// It lives here — inside the REST registry — rather than on
    /// [`PropagatedCredential`], which every unrelated strategy produces and
    /// none of the others has a lease for. A lease is a non-secret binding; no
    /// token material is retained.
    managed: Option<ManagedLease>,
    /// The outbound headers, presented verbatim.
    headers: Vec<(String, String)>,
}

/// One managed credential's custody handle: the concrete strategy that released
/// it and the lease it was released under.
struct ManagedLease {
    strategy: Arc<crate::personal_accounts::VaultStrategy>,
    lease: crate::personal_accounts::CredentialLease,
}

impl PreparedAccountCredential {
    /// The headers to put on the wire, verbatim.
    pub(crate) fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    /// The opaque binding cache keys are partitioned by.
    pub(crate) fn cache_binding(&self) -> &str {
        &self.cache_binding
    }

    /// Whether a PUBLISHED lifetime is still open at `now`.
    ///
    /// THE PER-DISPATCH READING IS NOT UNIVERSAL. `expires_at <= minted_at` is
    /// the vault's deliberate "no reusable lifetime" signal, and treating it as
    /// neither fresh nor expired is only sound because a managed credential's
    /// real freshness is decided by the durable custody recheck below, under the
    /// store's authority lock. Applying that reading to EVERY strategy is what
    /// made an external credential whose issuer published an ALREADY-PAST expiry
    /// (`expires_at <= minted_at` is exactly what an expired token looks like at
    /// mint time) pass this check with nothing else able to catch it: an
    /// external descriptor has no lease, so the custody half below is skipped
    /// entirely and an expired credential would have gone on the wire.
    ///
    /// So the per-dispatch reading is available ONLY to a credential backed by
    /// concrete managed custody — the same `ManagedLease` the recheck uses, not
    /// a mode string that a reload could change underneath this dispatch. An
    /// external credential is held to the expiry ITS strategy published, and
    /// nothing here extends, rounds, defaults or invents a lifetime for it.
    fn published_lifetime_open(&self, now: i64) -> bool {
        if self.managed.is_some() {
            return self.expires_at <= self.minted_at || now <= self.expires_at;
        }
        now < self.expires_at
    }
}

impl std::fmt::Debug for PreparedAccountCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let header_names: Vec<&str> = self.headers.iter().map(|(k, _)| k.as_str()).collect();
        f.debug_struct("PreparedAccountCredential")
            .field("descriptor_id", &self.descriptor_id)
            .field("auth_key", &self.auth_key)
            .field("audience", &self.audience)
            .field("cache_binding", &self.cache_binding)
            .field("expires_at", &self.expires_at)
            .field("headers", &format_args!("{header_names:?} = <redacted>"))
            .finish()
    }
}

/// The one place a descriptor reference is resolved for a credential.
#[derive(Default)]
pub(crate) struct AccountStrategyRegistry {
    declared: RwLock<BTreeMap<String, DeclaredAccount>>,
    installed: RwLock<BTreeMap<String, Arc<InstalledAccount>>>,
    audit: RwLock<Option<Arc<TransparencyLogger>>>,
}

impl AccountStrategyRegistry {
    /// Record a configured descriptor. Idempotent: a reload declaring the same
    /// descriptor replaces the entry with an identical one.
    pub(crate) fn declare(&self, descriptor_id: &str, provider: &str, mode: DescriptorMode) {
        self.declared.write().insert(
            descriptor_id.to_string(),
            DeclaredAccount {
                provider: provider.to_string(),
                mode,
            },
        );
    }

    /// Install the strategy for one descriptor, carrying its DECLARED mode.
    ///
    /// The mode is a parameter rather than inferred from the strategy kind: an
    /// `external` descriptor must keep its declared mode, and collapsing it
    /// would make the registration check answer the wrong question.
    pub(crate) fn install(&self, account: InstalledAccount, mode: DescriptorMode) {
        self.declare(&account.descriptor_id, &account.provider, mode);
        self.installed
            .write()
            .insert(account.descriptor_id.clone(), Arc::new(account));
    }

    /// The configured descriptor under `descriptor_id`, if the configuration
    /// declared one.
    pub(crate) fn declared(&self, descriptor_id: &str) -> Option<DeclaredAccount> {
        self.declared.read().get(descriptor_id).cloned()
    }

    /// The installed strategy for `descriptor_id`, if one was installed.
    pub(crate) fn installed(&self, descriptor_id: &str) -> Option<Arc<InstalledAccount>> {
        self.installed.read().get(descriptor_id).map(Arc::clone)
    }

    /// Attach the durable audit sink. Called by `MetaMcp::enable_transparency_log`
    /// because this registry is reached through the capability executor rather
    /// than through `MetaMcp`.
    pub(crate) fn set_audit_logger(&self, logger: Arc<TransparencyLogger>) {
        *self.audit.write() = Some(logger);
    }

    /// The credential key a capability referencing `descriptor_id` must declare.
    pub(crate) fn expected_auth_key(provider: &str) -> String {
        format!("oauth:{provider}")
    }

    /// Resolve one `auth.account` reference into a credential, or refuse.
    ///
    /// # Errors
    ///
    /// [`Error::Config`] for an unresolved reference, a provider mismatch, a
    /// missing installation, a missing verified identity, a strategy refusal or
    /// an unusable minted header; [`Error::Internal`] when a required account
    /// would mint without a durable audit record. Every one of these is a
    /// refusal, never a fallback.
    pub(crate) async fn resolve(
        &self,
        descriptor_id: &str,
        auth_key: &str,
        identity: Option<&VerifiedIdentity>,
    ) -> Result<AccountCredential> {
        let Some(declared) = self.declared(descriptor_id) else {
            return Err(Error::Config(format!(
                "capability auth references account '{descriptor_id}', which is not a key in \
                 accounts.descriptors. The reference is the descriptor map key (the account's \
                 logical id) — never the provider id, an email or a display name. Refusing \
                 rather than falling back to the gateway-held credential for '{auth_key}'."
            )));
        };

        // The provider half of the key must MATCH the referenced descriptor. A
        // capability keyed `oauth:slack` pointing at a `google` descriptor is a
        // refusal, and no capability is ever joined to an account by provider
        // name alone.
        let expected = Self::expected_auth_key(&declared.provider);
        if auth_key != expected {
            return Err(Error::Config(format!(
                "capability auth key '{auth_key}' does not match account descriptor \
                 '{descriptor_id}', whose provider requires '{expected}'. A capability is never \
                 joined to an account by provider name alone."
            )));
        }

        // Existing shared behaviour, preserved verbatim.
        if declared.mode == DescriptorMode::Shared {
            return Ok(AccountCredential::Legacy);
        }

        let Some(installed) = self.installed(descriptor_id) else {
            return Err(Error::Config(format!(
                "capability auth references account '{descriptor_id}' but no account strategy is \
                 installed for it; refusing to dispatch without the account holder's credential."
            )));
        };

        let logger = self.audit.read().clone();
        let subject_id = audit_subject(identity);
        let audience = installed.audience.as_str();

        let Some(identity) = identity else {
            self.audit_refusal(
                logger.as_deref(),
                &subject_id,
                descriptor_id,
                audience,
                "the request carries no verified end-user identity",
            );
            return Err(Error::Config(format!(
                "capability auth references account '{descriptor_id}' but the request carries no \
                 verified end-user identity. Refusing rather than falling back to the \
                 gateway-held credential for '{auth_key}'."
            )));
        };

        let backend = BackendDescriptor {
            // The descriptor id is the logical backend id of the account key,
            // which is what the strategy's own audience check compares against.
            id: descriptor_id.to_string(),
            audience: installed.audience.clone(),
            token_exchange_endpoint: installed.token_exchange_endpoint.clone(),
            token_exchange_scope: installed.token_exchange_scope.clone(),
        };

        // ONE mint, two shapes. A managed descriptor mints through
        // `VaultStrategy::prepare` — the SAME body `propagate` runs — and keeps
        // the lease, so the recheck below can be the real custody release. An
        // external descriptor keeps the trait call, its published expiry and
        // its behaviour unchanged; there is no lease to keep and none is
        // invented.
        let minted = match installed.managed.as_ref() {
            Some(vault) => vault
                .prepare(identity, &backend)
                .await
                .map(|(credential, lease)| {
                    (
                        credential,
                        Some(ManagedLease {
                            strategy: Arc::clone(vault),
                            lease,
                        }),
                    )
                }),
            None => installed
                .strategy
                .propagate(identity, &backend)
                .await
                .map(|credential| (credential, None)),
        };
        let (credential, managed) = match minted {
            Ok(minted) => minted,
            Err(error) => {
                let reason = error.to_string();
                self.audit_refusal(
                    logger.as_deref(),
                    &subject_id,
                    descriptor_id,
                    audience,
                    &reason,
                );
                return Err(Error::Config(format!(
                    "account '{descriptor_id}' produced no credential for this caller: {reason}"
                )));
            }
        };

        // AN EXTERNAL CREDENTIAL IS CHECKED AGAINST ITS OWN PUBLISHED EXPIRY
        // HERE, at the INITIAL resolve — before the outer response cache is
        // keyed, before the inner capability cache is consulted and before any
        // egress. The revalidate below re-asks the same question, but only a
        // credential that got past THIS point can reach it, and the outer cache
        // key is built from the binding this function returns.
        //
        // A managed credential is exempt: `expires_at <= minted_at` is the
        // vault's per-dispatch signal, not staleness, and its real freshness is
        // decided by the lease recheck. Nothing here invents a lifetime for
        // either kind — an external strategy that publishes no usable expiry
        // publishes no usable credential.
        let minted_at = chrono::Utc::now().timestamp();
        if managed.is_none() && credential.expires_at <= minted_at {
            let reason = "the external strategy published an expiry that has already passed";
            self.audit_refusal(
                logger.as_deref(),
                &subject_id,
                descriptor_id,
                audience,
                reason,
            );
            return Err(Error::Config(format!(
                "account '{descriptor_id}' minted a credential that is already expired: {reason}. \
                 Refusing rather than caching or dispatching with it."
            )));
        }

        if credential.headers.is_empty() {
            return Err(Error::Config(format!(
                "account '{descriptor_id}' produced no credential header; an account binding \
                 must produce the account holder's own credential."
            )));
        }
        // Validate every header BEFORE dispatch, so an unusable minted
        // credential fails closed instead of silently leaving the request
        // unauthenticated.
        for (name, value) in &credential.headers {
            if name.parse::<reqwest::header::HeaderName>().is_err()
                || value.parse::<reqwest::header::HeaderValue>().is_err()
            {
                return Err(Error::Config(format!(
                    "account '{descriptor_id}' minted an unusable credential header '{name}'"
                )));
            }
        }

        // Operator-misconfig fail-OPEN guard, closed: the audit helper treats a
        // disabled transparency log as a no-op, which on a required account
        // would let a minted per-user credential go on the wire with NO durable
        // record. Same rule the Meta-MCP mint path applies.
        if installed.required && logger.is_none() {
            return Err(Error::Internal(format!(
                "account '{descriptor_id}' is required for this capability but no transparency \
                 log is configured; refusing to mint a per-user credential without a durable \
                 audit record"
            )));
        }
        if let Err(error) = audit_identity_propagation(
            logger.as_deref(),
            "idp_mint",
            &subject_id,
            descriptor_id,
            Some(audience),
            None,
        ) {
            // CWE-209: the audit error can carry a filesystem path. Keep it in
            // the server log; return a generic message to the caller.
            tracing::warn!(
                account = descriptor_id,
                error = %error,
                "account credential mint audit write failed"
            );
            return Err(Error::Internal(format!(
                "identity-propagation audit unavailable for account '{descriptor_id}'"
            )));
        }

        Ok(AccountCredential::Prepared(Arc::new(
            PreparedAccountCredential {
                descriptor_id: descriptor_id.to_string(),
                auth_key: auth_key.to_string(),
                actor_id: identity.stable_actor_id(),
                audience: installed.audience.clone(),
                // The strategy's own values, copied. Never re-derived, never
                // widened and never rounded.
                cache_binding: credential.cache_binding,
                expires_at: credential.expires_at,
                minted_at,
                strategy: Arc::clone(&installed.strategy),
                managed,
                headers: credential.headers,
            },
        )))
    }

    /// Recheck a credential resolved earlier in THIS dispatch, before it is
    /// allowed to select a cache entry or go on the wire.
    ///
    /// This is a validation, not a second mint: it re-answers, against the
    /// registry as it stands NOW, every question [`Self::resolve`] answered —
    /// the descriptor is still declared, still non-`shared`, still owned by the
    /// same provider, still installed, still installed with the SAME strategy
    /// instance and the same audience — and adds the two the carrying step
    /// makes possible: the credential belongs to the identity this call is
    /// being made as, and a published lifetime has not run out.
    ///
    /// AND, FOR A MANAGED ACCOUNT, IT ASKS DURABLE CUSTODY. The registry checks
    /// above are configuration checks: none of them can see a grant that was
    /// revoked, re-authorized or rotated after the credential was prepared,
    /// because the registry is not where that state lives. So a managed
    /// credential's lease is re-released through the SAME custody that released
    /// it (`VaultStrategy::recheck`), under the store's authority lock, and a
    /// retired lease — revoked, reconnect-required, superseded generation,
    /// authorization or token revision — refuses HERE, before an inner cache
    /// entry may be selected and before any egress. Nothing is refreshed and
    /// nothing is re-minted: acquiring a new lease to answer "still valid"
    /// would be pretending a retired credential is the current one. External
    /// descriptors keep exactly the published-expiry behaviour they had; there
    /// is no global fallback path here for either kind.
    ///
    /// A reload that dropped, re-pointed or re-installed the descriptor between
    /// the resolve and this point therefore refuses here rather than letting a
    /// credential minted under the previous configuration reach a cache lookup
    /// or an upstream.
    ///
    /// # Errors
    ///
    /// [`Error::Config`] for every mismatch and for a custody refusal. None of
    /// them falls back to the gateway-held credential, and none of them degrades
    /// into a cache miss.
    pub(crate) async fn revalidate(
        &self,
        prepared: &PreparedAccountCredential,
        identity: Option<&VerifiedIdentity>,
    ) -> Result<()> {
        let descriptor_id = prepared.descriptor_id.as_str();
        let refuse = |reason: &str| {
            Err(Error::Config(format!(
                "account '{descriptor_id}' no longer validates for this dispatch: {reason}. \
                 Refusing rather than serving a cached result or dispatching with a credential \
                 nothing rechecked."
            )))
        };

        let Some(declared) = self.declared(descriptor_id) else {
            return refuse("the descriptor is no longer declared");
        };
        if declared.mode == DescriptorMode::Shared {
            return refuse(
                "the descriptor is now declared shared, so a per-caller credential \
                           minted for it is no longer the configured behaviour",
            );
        }
        if prepared.auth_key != Self::expected_auth_key(&declared.provider) {
            return refuse("the descriptor's provider no longer matches the capability auth key");
        }
        let Some(installed) = self.installed(descriptor_id) else {
            return refuse("no account strategy is installed for it any more");
        };
        if installed.audience != prepared.audience {
            return refuse("the installed audience changed after the credential was minted");
        }
        if !Arc::ptr_eq(&installed.strategy, &prepared.strategy) {
            return refuse("the installed strategy was replaced after the credential was minted");
        }
        let Some(identity) = identity else {
            return refuse("the request carries no verified end-user identity");
        };
        if identity.stable_actor_id() != prepared.actor_id {
            return refuse("it was minted for a different verified caller");
        }
        if !prepared.published_lifetime_open(chrono::Utc::now().timestamp()) {
            return refuse("its published lifetime has run out");
        }

        // THE DURABLE HALF. Last, because the checks above are cheap and this
        // one takes the store's authority lock; first in importance, because it
        // is the only one that can see a revocation committed since the mint.
        if let Some(managed) = prepared.managed.as_ref() {
            // The installed managed strategy must still be the one that
            // released this lease. The pointer check above compares the trait
            // object; this compares the concrete instance the lease belongs to,
            // so a descriptor re-installed against different custody cannot be
            // rechecked with the previous one.
            match installed.managed.as_ref() {
                Some(current) if Arc::ptr_eq(current, &managed.strategy) => {}
                _ => {
                    return refuse(
                        "the managed custody backing it was replaced after the credential was \
                         minted",
                    );
                }
            }
            if let Err(error) = managed.strategy.recheck(&managed.lease).await {
                // The custody refusal text names the account state (revoked,
                // reconnect required, retired lease), never a token.
                return refuse(&format!("durable custody refused its lease: {error}"));
            }
        }
        Ok(())
    }

    /// Record a refusal. The request is already being refused, so an audit-write
    /// failure does not change the outcome — but it must not be dropped
    /// silently.
    fn audit_refusal(
        &self,
        logger: Option<&TransparencyLogger>,
        subject_id: &str,
        descriptor_id: &str,
        audience: &str,
        reason: &str,
    ) {
        if let Err(error) = audit_identity_propagation(
            logger,
            "idp_refuse",
            subject_id,
            descriptor_id,
            Some(audience),
            Some(reason),
        ) {
            tracing::warn!(
                account = descriptor_id,
                error = %error,
                "account credential refuse audit write failed"
            );
        }
    }
}

#[cfg(test)]
mod lifetime_tests {
    use super::*;

    struct NeverMints;

    #[async_trait::async_trait]
    impl IdentityPropagation for NeverMints {
        async fn propagate(
            &self,
            _identity: &VerifiedIdentity,
            _backend: &BackendDescriptor,
        ) -> std::result::Result<super::super::PropagatedCredential, super::super::PropagationError>
        {
            unreachable!("the lifetime predicate never mints")
        }
    }

    /// `managed: None` is the EXTERNAL shape: no lease, so the durable custody
    /// half of `revalidate` is skipped and this predicate is the only thing
    /// standing between a stale published expiry and the wire.
    fn external(expires_at: i64, minted_at: i64) -> PreparedAccountCredential {
        PreparedAccountCredential {
            descriptor_id: "acct".to_string(),
            auth_key: "oauth:google".to_string(),
            actor_id: "actor".to_string(),
            audience: "https://partner.invalid/".to_string(),
            cache_binding: "binding".to_string(),
            expires_at,
            minted_at,
            strategy: Arc::new(NeverMints),
            managed: None,
            headers: vec![("Authorization".to_string(), "Bearer x".to_string())],
        }
    }

    /// THE REGRESSION, at the predicate itself. An external credential whose
    /// published expiry is in the past looks exactly like `expires_at <=
    /// minted_at`, which the old universal reading treated as "no lifetime
    /// published" and therefore as usable.
    #[test]
    fn an_external_credential_with_a_past_expiry_is_closed() {
        let now = 1_800_000_000;
        assert!(
            !external(now - 3600, now).published_lifetime_open(now),
            "an external credential whose expiry has already passed must never be open"
        );
        assert!(
            !external(now, now).published_lifetime_open(now),
            "expiry exactly at now is not a lifetime an external credential may use"
        );
        assert!(
            !external(0, now).published_lifetime_open(now),
            "an external strategy publishing no usable expiry publishes no usable credential"
        );
        assert!(
            external(now + 60, now).published_lifetime_open(now),
            "an external credential inside its own published lifetime stays usable; nothing \
             here shortens it"
        );
    }
}
