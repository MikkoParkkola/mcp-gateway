use crate::capability::CapabilityDefinition;
use crate::identity_grants::{CapabilityExposure, GrantSubject};
use crate::{Error, Result};

/// Request-scoped execution metadata for a capability call.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapabilityExecutionContext {
    /// Verified caller subject associated with this request, when available.
    pub caller_identity: Option<GrantSubject>,
}

impl CapabilityExecutionContext {
    /// Build a context with a verified caller identity.
    #[must_use]
    pub fn with_caller_identity(caller_identity: GrantSubject) -> Self {
        Self {
            caller_identity: Some(caller_identity),
        }
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
