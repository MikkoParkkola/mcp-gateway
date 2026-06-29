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
}
