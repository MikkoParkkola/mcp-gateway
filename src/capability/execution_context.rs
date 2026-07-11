// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use crate::capability::CapabilityDefinition;
use crate::identity_grants::{CapabilityExposure, GrantSubject};
use crate::security::validate_url_not_ssrf;
use crate::{Error, Result};

/// Request-scoped execution metadata for a capability call.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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
}

impl CapabilityExecutionContext {
    /// Build a context with a verified caller identity.
    #[must_use]
    pub fn with_caller_identity(caller_identity: GrantSubject) -> Self {
        Self {
            caller_identity: Some(caller_identity),
            allow_loopback_egress: false,
        }
    }

    /// Return this context with isolated loopback egress enabled.
    #[must_use]
    pub const fn with_isolated_loopback_egress(mut self) -> Self {
        self.allow_loopback_egress = true;
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
