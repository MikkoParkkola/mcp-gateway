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

use super::{
    BackendDescriptor, CallerProof, IdentityPropagation, PropagationError,
    audit_identity_propagation, audit_subject,
};
use crate::personal_accounts::{
    ManagedLease, config::DescriptorMode, identity::Principal, refusal::mark,
};
use crate::security::TransparencyLogger;
use crate::{Error, Result};

// The one strategy an installed descriptor mints through, in its own module.
mod minter;
pub(crate) use minter::Minter;

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
    /// `account_fingerprint` of the declared descriptor (MIK-8407).
    pub(crate) fingerprint: String,
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
    /// `account_fingerprint` of the declared descriptor (MIK-8407).
    pub(crate) fingerprint: String,
    /// What mints for this descriptor. Shared with the per-backend install for
    /// the same descriptor, so two consumers can never drift onto two strategies.
    pub(crate) minter: Minter,
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

impl PreparedAccountCredential {
    /// A11-c, the capability route's 401 site: force at most one refresh of
    /// the managed grant this credential came from and return the caller's
    /// answer. A credential with no managed custody (external) keeps
    /// `refused` unchanged, so only a vault-minted credential forces anything.
    pub(crate) async fn after_upstream_401(&self, refused: Error) -> Error {
        match self.managed.as_ref() {
            Some(managed) => managed.after_upstream_401(refused).await,
            None => refused,
        }
    }

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
            .finish_non_exhaustive()
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
    pub(crate) fn declare(
        &self,
        descriptor_id: &str,
        provider: &str,
        mode: DescriptorMode,
        fingerprint: &str,
    ) {
        self.declared.write().insert(
            descriptor_id.to_string(),
            DeclaredAccount {
                provider: provider.to_string(),
                mode,
                fingerprint: fingerprint.to_string(),
            },
        );
    }

    /// Install the strategy for one descriptor, carrying its DECLARED mode.
    ///
    /// The mode is a parameter rather than inferred from the strategy kind: an
    /// `external` descriptor must keep its declared mode, and collapsing it
    /// would make the registration check answer the wrong question.
    pub(crate) fn install(&self, account: InstalledAccount, mode: DescriptorMode) {
        self.declare(
            &account.descriptor_id,
            &account.provider,
            mode,
            &account.fingerprint,
        );
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

    /// The managed vault a descriptor was installed with, if any: the MCP
    /// route mints through it and asks it who the caller is (#1961).
    pub(crate) fn managed_vault(
        &self,
        descriptor_id: Option<&str>,
    ) -> Option<Arc<crate::personal_accounts::VaultStrategy>> {
        self.installed(descriptor_id?)?.minter.managed().cloned()
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

    /// Validate a minted credential's headers, then audit the mint. Split
    /// out of [`Self::resolve`] purely to keep that function under the line
    /// budget — logic, ordering and every error message are unchanged.
    async fn validate_and_audit_mint(
        logger: Option<&Arc<TransparencyLogger>>,
        subject_id: &str,
        descriptor_id: &str,
        audience: &str,
        required: bool,
        credential: &super::PropagatedCredential,
    ) -> Result<()> {
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
        if required && logger.is_none() {
            return Err(Error::Internal(format!(
                "account '{descriptor_id}' is required for this capability but no transparency \
                 log is configured; refusing to mint a per-user credential without a durable \
                 audit record"
            )));
        }
        if let Err(error) = audit_identity_propagation(
            logger,
            "idp_mint",
            subject_id,
            descriptor_id,
            Some(audience),
            None,
        )
        .await
        {
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
        Ok(())
    }

    /// Resolve `descriptor_id` to its declared descriptor, verify `auth_key`
    /// matches its provider, and look up its installed strategy. `Ok(None)`
    /// means the descriptor is in shared mode, and the caller returns
    /// [`AccountCredential::Legacy`] for it. Split out of [`Self::resolve`]
    /// purely to keep that function under the line budget — logic, ordering
    /// and every error message are unchanged.
    fn declared_installed(
        &self,
        descriptor_id: &str,
        auth_key: &str,
    ) -> Result<Option<Arc<InstalledAccount>>> {
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
            return Ok(None);
        }

        let Some(installed) = self.installed(descriptor_id) else {
            return Err(Error::Config(format!(
                "capability auth references account '{descriptor_id}' but no account strategy is \
                 installed for it; refusing to dispatch without the account holder's credential."
            )));
        };
        Ok(Some(installed))
    }

    /// ONE mint, two shapes. A managed descriptor mints through
    /// `VaultStrategy::prepare` — the SAME body `propagate` runs — and keeps
    /// the lease, so the caller's recheck can be the real custody release. An
    /// external descriptor keeps the trait call and its behaviour unchanged;
    /// there is no lease to keep and none is invented.
    async fn mint(
        installed: &InstalledAccount,
        principal: Principal<'_>,
        backend: &BackendDescriptor,
    ) -> std::result::Result<
        (super::PropagatedCredential, Option<ManagedLease>),
        crate::personal_accounts::MintError,
    > {
        match &installed.minter {
            Minter::Managed(vault) => vault
                .prepare_held_classified(principal, backend)
                .await
                .map(|(credential, managed)| (credential, Some(managed))),
            // An external strategy exchanges the CALLER'S OWN token, so it has
            // nothing to mint from but a proof. `Self::principal` offers the
            // sole-operator assertion only for a managed descriptor, so this is
            // the verified arm by construction — and it refuses rather than
            // assuming so, because a credential path should not rely on a
            // property enforced somewhere else.
            Minter::External(strategy) => match principal.verified() {
                Some(identity) => strategy
                    .propagate(identity, backend)
                    .await
                    .map(|credential| (credential, None))
                    .map_err(crate::personal_accounts::MintError::Other),
                None => Err(PropagationError::Refuse(
                    "an external account descriptor mints only for a verified caller".to_string(),
                )
                .into()),
            },
        }
    }

    /// Who a dispatch against this installation is made as, or `None` when
    /// nothing proves or asserts a principal.
    ///
    /// ONE ANSWER, TWO ASKERS: [`Self::resolve`] mints under it and
    /// [`Self::revalidate`] rechecks against it, and a second derivation in
    /// either is how a credential minted for one principal comes to be
    /// rechecked as another. The sole-operator assertion is asked of the
    /// INSTALLED strategy rather than recomputed from configuration here.
    fn principal<'a>(
        installed: &InstalledAccount,
        caller: CallerProof<'a>,
    ) -> Option<Principal<'a>> {
        match &installed.minter {
            Minter::Managed(vault) => vault.principal(caller),
            // No managed custody, no assertion to consult: an external
            // descriptor has always needed a verified caller and still does.
            Minter::External(_) => caller.verified().map(Principal::Verified),
        }
    }

    /// Whether `caller` has a principal for managed descriptor
    /// `descriptor_id` that can never bind an account key (MIK-8392): a
    /// permanent refusal, not a transient one. False for anything else,
    /// including an external descriptor or no principal at all.
    pub(crate) fn unbindable(&self, descriptor_id: &str, caller: CallerProof<'_>) -> bool {
        let Some(installed) = self.installed(descriptor_id) else {
            return false;
        };
        let Some(vault) = installed.minter.managed() else {
            return false;
        };
        Self::principal(installed.as_ref(), caller).is_some_and(|principal| !vault.binds(principal))
    }

    /// Record a refusal. The request is already being refused, so an audit-write
    /// failure does not change the outcome — but it must not be dropped
    /// silently.
    async fn audit_refusal(
        logger: Option<&Arc<TransparencyLogger>>,
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
        )
        .await
        {
            tracing::warn!(
                account = descriptor_id,
                error = %error,
                "account credential refuse audit write failed"
            );
        }
    }
}

#[path = "account_strategies_resolve.rs"]
mod resolve;

#[path = "account_strategies_view.rs"]
mod view;

#[cfg(test)]
#[path = "account_strategies_tests.rs"]
mod lifetime_tests;
