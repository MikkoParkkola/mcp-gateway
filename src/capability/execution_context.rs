// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use std::sync::Arc;

use crate::capability::CapabilityDefinition;
use crate::identity_grants::{CapabilityExposure, GrantSubject};
use crate::identity_propagation::{AccountStrategyRegistry, PreparedAccountCredential};
use crate::key_server::oidc::VerifiedIdentity;
use crate::security::validate_url_not_ssrf;
use crate::{Error, Result};

/// Request-scoped execution metadata for a capability call.
///
/// `PartialEq`/`Eq` are hand-written rather than derived: `VerifiedIdentity`
/// implements neither, and deriving over it would compare `email`, `name` and
/// `groups` — mutable display labels that must never decide whether two
/// requests are the same principal.
#[derive(Debug, Clone, Default)]
pub struct CapabilityExecutionContext {
    /// Verified caller subject associated with this request, when available.
    pub caller_identity: Option<GrantSubject>,
    /// Permit direct loopback IP egress for an explicitly isolated runtime.
    ///
    /// This is default-off. It exists for flows such as `TrustLab` active
    /// fixtures where the candidate server is launched inside a local sandbox
    /// and exposed on `127.0.0.1`. General capability execution must keep the
    /// standard SSRF deny list.
    pub allow_loopback_egress: bool,
    /// Pre-authorization policy epoch snapshot from the invoke path.
    ///
    /// Copied, never reloaded from the shared counter. `None` on isolated
    /// executor tests that do not attach an epoch.
    pub policy_epoch: Option<u64>,
    /// Classified protocol revision this request is served under.
    ///
    /// Same snapshot the outer response cache keys on. `None` is unknown:
    /// an attached executor must not cache.
    pub protocol_revision: Option<String>,
    /// Routing profile name this request was admitted under.
    ///
    /// Same snapshot the outer response cache keys on. `None` on isolated
    /// executor tests that do not attach a profile.
    pub routing_profile: Option<String>,
    /// Already-resolved outer identity `cache_binding`.
    ///
    /// Produced once by the account credential resolver (or identity
    /// propagation) before dispatch. Copied, never re-resolved, never
    /// re-hashed. `None` is the public/anonymous namespace.
    pub cache_binding: Option<String>,
    /// The VERIFIED end-user identity this call is made as.
    ///
    /// The verification-context seam for `auth.account`: the account key is
    /// built from a verified ISSUER and SUBJECT, and this is the only field on
    /// this context that carries both. [`Self::caller_identity`] is a
    /// `GrantSubject` — an authorization handle whose authority is not an OAuth
    /// issuer — so it can never stand in for this one. `None` means the request
    /// carries no verified identity, and a managed or external account
    /// reference then refuses.
    pub verified_identity: Option<Arc<VerifiedIdentity>>,
    /// The account credential this dispatch already resolved, when the caller
    /// resolved one before its OWN cache lookup.
    ///
    /// The invoke path resolves the capability's `auth.account` reference
    /// BEFORE the outer response cache is consulted — a key built before the
    /// account is known cannot name the account holder — and carries the answer
    /// here so the inner capability cache and the egress headers speak about
    /// that same credential instead of minting a second one. `None` means
    /// nothing was resolved yet: the executor then resolves it itself, before
    /// its own cache lookup, and never serves a cached entry for an account it
    /// has not resolved.
    ///
    /// Crate-visible because a prepared credential is not something an embedder
    /// may fabricate: the only producer is
    /// [`crate::identity_propagation::AccountStrategyRegistry::resolve`].
    pub(crate) account_credential: Option<Arc<PreparedAccountCredential>>,
}

impl PartialEq for CapabilityExecutionContext {
    fn eq(&self, other: &Self) -> bool {
        self.caller_identity == other.caller_identity
            && self.allow_loopback_egress == other.allow_loopback_egress
            && self.policy_epoch == other.policy_epoch
            && self.protocol_revision == other.protocol_revision
            && self.routing_profile == other.routing_profile
            && self.cache_binding == other.cache_binding
            && verified_binding(self.verified_identity.as_deref())
                == verified_binding(other.verified_identity.as_deref())
            // Compared on the opaque binding only: a prepared credential's
            // headers are live token material and are never compared, logged
            // or ordered.
            && self.account_binding() == other.account_binding()
    }
}

impl Eq for CapabilityExecutionContext {}

/// The only part of a verified identity two contexts are compared on: the
/// issuer+subject pair, via the same length-prefixed derivation the account key
/// and the governance audit use.
fn verified_binding(identity: Option<&VerifiedIdentity>) -> Option<String> {
    identity.map(VerifiedIdentity::stable_actor_id)
}

impl CapabilityExecutionContext {
    /// Build a context with a verified caller identity.
    #[must_use]
    pub fn with_caller_identity(caller_identity: GrantSubject) -> Self {
        Self {
            caller_identity: Some(caller_identity),
            allow_loopback_egress: false,
            policy_epoch: None,
            protocol_revision: None,
            routing_profile: None,
            cache_binding: None,
            verified_identity: None,
            account_credential: None,
        }
    }

    /// The opaque binding of the already-resolved account credential, if this
    /// context carries one.
    pub(crate) fn account_binding(&self) -> Option<&str> {
        self.account_credential
            .as_deref()
            .map(PreparedAccountCredential::cache_binding)
    }

    /// TEST SEAM: carry a credential resolved EARLIER, as the invoke path does.
    ///
    /// The gateway resolves the account once in the invoke path and hands the
    /// prepared credential down; the executor then rechecks it instead of
    /// re-minting. A test that needs to prove a revocation committed AFTER that
    /// resolve is refused has to reproduce exactly that carrying step, because
    /// re-resolving would refuse at the mint and never exercise the recheck.
    /// `cfg(test)` only, and it grants nothing: everything the field is used for
    /// is revalidated against the live registry before a cache lookup or egress.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_account_credential(
        mut self,
        credential: Arc<PreparedAccountCredential>,
    ) -> Self {
        self.account_credential = Some(credential);
        self
    }

    /// Return this context with isolated loopback egress enabled.
    #[must_use]
    pub const fn with_isolated_loopback_egress(mut self) -> Self {
        self.allow_loopback_egress = true;
        self
    }

    /// Return this context carrying the verified end-user identity.
    ///
    /// The value must come from an actual verification (the gateway's
    /// `MetaMcpCallerContext`), never from a grant subject, an API key name or
    /// a display name.
    #[must_use]
    pub fn with_verified_identity(mut self, identity: Arc<VerifiedIdentity>) -> Self {
        self.verified_identity = Some(identity);
        self
    }
}

pub(crate) fn validate_capability_url_for_context(
    url: &str,
    context: &CapabilityExecutionContext,
) -> Result<()> {
    match validate_url_not_ssrf(url) {
        Ok(()) => Ok(()),
        Err(_err) if context.allow_loopback_egress && url_targets_loopback_ip(url) => Ok(()),
        Err(err) => Err(err),
    }
}

fn url_targets_loopback_ip(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    match parsed.host() {
        Some(url::Host::Ipv4(addr)) => addr.is_loopback(),
        Some(url::Host::Ipv6(addr)) => addr.is_loopback(),
        _ => false,
    }
}

/// ADR-008 INV-2 parity for capability-backed OAuth (MIK-6751).
///
/// A capability whose credential `key` is `oauth:<provider>` fetches ONE
/// gateway-held token keyed only by provider name
/// (`CapabilityExecutor::fetch_oauth_token`, `src/capability/executor/credentials.rs`)
/// — there is no per-caller minting for capabilities, unlike the MCP-backend
/// identity-propagation path. On a multi-user gateway that means any caller
/// able to invoke the capability is served whoever's login is stored, which
/// is the same cross-user credential leak `MetaMcp::enforce_oauth_isolation`
/// closes for MCP backends. Refuse UNLESS the operator blessed the account as
/// shared (`auth.shared_account = true`) or the capability is
/// `exposure: personal` with a caller identity attached — `call_tool_with_context`
/// already runs [`validate_personal_capability_identity`] first, so reaching
/// this check with `exposure: personal` means the caller has already been
/// proven to be the sole permitted owner, structurally preventing the leak
/// without a second credential-minting subsystem.
pub(crate) fn validate_oauth_isolation(
    capability: &CapabilityDefinition,
    context: &CapabilityExecutionContext,
    multi_user: bool,
) -> Result<()> {
    if !multi_user {
        return Ok(());
    }

    let auth = &capability.auth;
    if !auth.key.starts_with("oauth:") || auth.shared_account {
        return Ok(());
    }
    if capability.metadata.exposure == CapabilityExposure::Personal
        && context.caller_identity.is_some()
    {
        return Ok(());
    }
    if account_credential_is_this_callers(capability, context) {
        return Ok(());
    }

    Err(Error::json_rpc(
        -32001,
        format!(
            "Capability '{}' uses a gateway-held OAuth login ('{}') that is not \
             isolated per user. On a multi-user gateway this call is refused so one \
             user's token is never served to another. Fix: mark the capability \
             `exposure: personal` with a matching `identity_owner`, or set \
             `auth.shared_account = true` if this is a genuinely shared service account.",
            capability.name, auth.key
        ),
    ))
}

/// THE ONE NARROW EXCEPTION to the guard above: this dispatch already holds an
/// account credential that is THIS capability's own, minted for THIS verified
/// caller.
///
/// The premise of the refusal is that an `oauth:<provider>` key names one
/// gateway-held login served to whoever calls. That premise is false exactly
/// when the account registry has already minted a per-caller credential for the
/// capability's `auth.account` descriptor: the credential on the wire is then
/// the caller's own, and refusing would deny the very deployment the account
/// binding exists for. Every conjunct is required:
///
/// * a credential was actually PREPARED — a `shared` descriptor resolves to
///   [`crate::identity_propagation::AccountCredential::Legacy`] and therefore
///   carries none, so it keeps facing the unchanged guard;
/// * it was minted for THIS capability's descriptor reference, so one
///   capability's account credential can never excuse another's;
/// * it was minted under THIS capability's `auth.key`, so a re-pointed provider
///   cannot ride an old mint;
/// * and its actor is EXACTLY this request's
///   [`VerifiedIdentity::stable_actor_id`] — the issuer+subject pair. A missing
///   verified identity is a refusal, never a wildcard.
///
/// [`CapabilityExecutionContext::caller_identity`] is a `GrantSubject`: an
/// authorization handle whose authority is not an OAuth issuer. It is
/// deliberately not consulted here and can never establish account authority.
/// Nothing here inspects `auth.shared_account`, extends an expiry, or mints:
/// the credential was produced and rechecked by
/// [`crate::capability::CapabilityExecutor::prepare_account_context`] against
/// the live registry before this function ever sees it.
fn account_credential_is_this_callers(
    capability: &CapabilityDefinition,
    context: &CapabilityExecutionContext,
) -> bool {
    let (Some(account), Some(prepared), Some(identity)) = (
        capability.auth.account.as_deref(),
        context.account_credential.as_deref(),
        context.verified_identity.as_deref(),
    ) else {
        return false;
    };
    prepared.descriptor_id == account
        && prepared.auth_key == capability.auth.key
        && prepared.actor_id == identity.stable_actor_id()
}

/// Refuse a capability whose `auth.account` does not resolve, or whose
/// `auth.key` is not this descriptor's `oauth:<provider>`.
///
/// THE REGISTRATION BOUNDARY, and re-checked at execution for a capability that
/// was registered dynamically. Admitting an unresolvable reference would publish
/// a tool that can only fail — and the failure would be found by a caller at
/// dispatch rather than by an operator at load.
///
/// `registry = None` is a standalone executor with no account catalogue at all.
/// Registration is then unchanged (there is nothing to check against) and the
/// EXECUTION path fails closed instead: it never falls through to the
/// gateway-held `oauth:<provider>` token.
///
/// # Errors
///
/// [`Error::Config`] naming the unresolved reference or the key the
/// descriptor's provider requires.
pub(crate) fn validate_capability_account_binding(
    capability: &CapabilityDefinition,
    registry: Option<&AccountStrategyRegistry>,
) -> Result<()> {
    let Some(account) = capability.auth.account.as_deref() else {
        return Ok(());
    };
    let Some(registry) = registry else {
        return Ok(());
    };
    let Some(declared) = registry.declared(account) else {
        return Err(Error::Config(format!(
            "Capability '{}' references account '{account}', which is not a key in \
             accounts.descriptors. The reference is the descriptor map key (the account's \
             logical id) — never the provider id, an email or a display name.",
            capability.name
        )));
    };
    let expected = AccountStrategyRegistry::expected_auth_key(&declared.provider);
    if capability.auth.key != expected {
        return Err(Error::Config(format!(
            "Capability '{}' references account '{account}' but declares auth.key '{}'. That \
             descriptor's provider requires '{expected}'; a capability is never joined to an \
             account by provider name alone.",
            capability.name, capability.auth.key
        )));
    }
    Ok(())
}

pub(crate) fn validate_personal_capability_identity(
    capability: &CapabilityDefinition,
    context: &CapabilityExecutionContext,
) -> Result<()> {
    if capability.metadata.exposure != CapabilityExposure::Personal {
        return Ok(());
    }

    let owner = capability.metadata.identity_owner.as_ref().ok_or_else(|| {
        Error::Config(format!(
            "Personal capability '{}' access denied: identity owner is required",
            capability.name
        ))
    })?;

    let caller = context.caller_identity.as_ref().ok_or_else(|| {
        Error::Config(format!(
            "Personal capability '{}' access denied: caller identity is required",
            capability.name
        ))
    })?;

    if caller != owner {
        return Err(Error::Config(format!(
            "Personal capability '{}' access denied: caller identity does not match owner",
            capability.name
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_context_keeps_loopback_blocked() {
        assert!(
            validate_capability_url_for_context(
                "http://127.0.0.1:39400/fixture",
                &CapabilityExecutionContext::default()
            )
            .is_err()
        );
    }

    #[test]
    fn isolated_loopback_context_bypasses_only_loopback_ip_literals() {
        let context = CapabilityExecutionContext::default().with_isolated_loopback_egress();

        assert!(
            validate_capability_url_for_context("http://127.0.0.1:39400/fixture", &context).is_ok()
        );
        assert!(validate_capability_url_for_context("http://10.0.0.1/fixture", &context).is_err());
        assert!(!url_targets_loopback_ip("http://localhost:39400/fixture"));
    }

    /// MIK-6751: capability-side ADR-008 INV-2 parity tests.
    ///
    /// `google_calendar_capability` names Google Calendar as the concrete
    /// motivating example from the gap report (`oauth:google`, no
    /// `shared_account`, `exposure` left at the `Shared` default) — the exact
    /// shape that let any caller ride a shared gateway-held OAuth login.
    fn google_calendar_capability(
        shared_account: bool,
        exposure_personal: bool,
    ) -> CapabilityDefinition {
        let exposure_yaml = if exposure_personal {
            "metadata:\n  exposure: personal\n  identity_owner:\n    authority: cloudflare_access\n    subject: owner-1\n"
        } else {
            ""
        };
        let shared_yaml = if shared_account {
            "  shared_account: true\n"
        } else {
            ""
        };
        crate::capability::parse_capability(&format!(
            "name: google_calendar_list_events\n\
             description: List events on a Google Calendar\n\
             auth:\n\
             \x20 required: true\n\
             \x20 type: bearer\n\
             \x20 key: oauth:google\n\
             {shared_yaml}\
             {exposure_yaml}\
             providers:\n\
             \x20 primary:\n\
             \x20   service: rest\n\
             \x20   config:\n\
             \x20     base_url: https://www.googleapis.com\n\
             \x20     path: /calendar/v3/calendars/primary/events\n\
             \x20     method: GET\n"
        ))
        .expect("fixture capability must parse")
    }

    #[test]
    fn oauth_isolation_refuses_shared_gateway_oauth_on_multi_user_gateway_with_no_per_user_cred() {
        let cap = google_calendar_capability(false, false);
        let err = validate_oauth_isolation(&cap, &CapabilityExecutionContext::default(), true)
            .expect_err(
                "shared oauth:<provider> credential on a multi-user gateway must be refused",
            );
        assert!(err.to_string().contains("not isolated per user"), "{err}");
    }

    #[test]
    fn oauth_isolation_allows_shared_oauth_on_single_user_gateway() {
        let cap = google_calendar_capability(false, false);
        assert!(
            validate_oauth_isolation(&cap, &CapabilityExecutionContext::default(), false).is_ok(),
            "single-user gateways have no cross-user caller to leak credentials to"
        );
    }

    #[test]
    fn oauth_isolation_allows_operator_blessed_shared_account() {
        let cap = google_calendar_capability(true, false);
        assert!(
            validate_oauth_isolation(&cap, &CapabilityExecutionContext::default(), true).is_ok(),
            "auth.shared_account = true is the explicit opt-in for a genuinely shared login"
        );
    }

    #[test]
    fn oauth_isolation_allows_personal_capability_with_matching_caller_identity() {
        let cap = google_calendar_capability(false, true);
        let context = CapabilityExecutionContext::with_caller_identity(GrantSubject::new(
            "cloudflare_access",
            "owner-1",
            None,
        ));
        assert!(
            validate_oauth_isolation(&cap, &context, true).is_ok(),
            "a resolved caller identity on a personal capability proves per-user isolation \
             (validate_personal_capability_identity already checked owner match upstream)"
        );
    }

    #[test]
    fn oauth_isolation_ignores_non_oauth_credentials() {
        let cap = crate::capability::parse_capability(
            "name: env_backed_capability\n\
             description: Uses a plain env-var credential, not a shared OAuth login\n\
             auth:\n\
             \x20 required: true\n\
             \x20 type: bearer\n\
             \x20 key: env:SOME_API_KEY\n\
             providers:\n\
             \x20 primary:\n\
             \x20   service: rest\n\
             \x20   config:\n\
             \x20     base_url: https://example.invalid\n\
             \x20     path: /widgets\n\
             \x20     method: GET\n",
        )
        .expect("fixture capability must parse");
        assert!(
            validate_oauth_isolation(&cap, &CapabilityExecutionContext::default(), true).is_ok(),
            "guard is scoped to oauth:<provider> keys; non-OAuth credentials are per-capability \
             secrets already, not a shared gateway-held login"
        );
    }
}
