//! Fail-closed sandbox boot gate with attestation injection (MIK-5223 AC.1,
//! AC.6) — no token, no start.
//!
//! Both substrates — gVisor (`runsc`) on Ubuntu and Apple containerization on
//! macOS — expose OCI hook lifecycle points; the launcher injects the token
//! at the `createRuntime` hook through one shared code path, so the token
//! flow is byte-identical regardless of substrate.  The only substrate
//! difference is the runtime label stamped on the handle.
//!
//! Rollback: `SYMPHONY_PLUS_ATTESTATION=0` boots without a token (the
//! sandbox stays isolated but loses identity attribution).  Any other value,
//! including unset, enforces fail-closed.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Utc};

use super::token::TokenClaims;
use super::validator::{AttestationRejection, AttestationValidator};

/// Rollback feature flag: `0` disables boot-time attestation enforcement.
pub const ATTESTATION_FLAG_ENV: &str = "SYMPHONY_PLUS_ATTESTATION";

/// Environment variable injected into the sandbox at the OCI `createRuntime`
/// hook carrying the encoded attestation token.
pub const TOKEN_ENV_VAR: &str = "SYMPHONY_ATTESTATION_TOKEN";

/// Boundary label used for boot-time validations in the audit ring buffer.
pub const BOOT_BOUNDARY: &str = "sandbox_boot";

/// Sandbox substrate (MIK-NEW.RUNTIME-A.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Substrate {
    /// gVisor (`runsc`) on Ubuntu.
    GvisorLinux,
    /// Apple containerization framework on macOS.
    AppleContainerization,
}

impl Substrate {
    /// OCI runtime label for diagnostics; not part of the token flow.
    #[must_use]
    pub fn runtime_label(self) -> &'static str {
        match self {
            Self::GvisorLinux => "runsc",
            Self::AppleContainerization => "apple-containerization",
        }
    }

    /// OCI hook at which the token is injected — the same lifecycle point on
    /// both substrates, keeping the flow identical.
    #[must_use]
    pub fn token_injection_hook(self) -> &'static str {
        "createRuntime"
    }
}

/// Whether boot-time attestation is enforced (the default) or bypassed by
/// the rollback flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationEnforcement {
    /// Fail closed: no valid token, no start.
    Enforced,
    /// `SYMPHONY_PLUS_ATTESTATION=0` rollback: boot without a token.
    BypassedByFlag,
}

impl AttestationEnforcement {
    /// Interpret a raw flag value: `Some("0")` bypasses, anything else —
    /// including unset — enforces fail-closed.
    #[must_use]
    pub fn from_flag(value: Option<&str>) -> Self {
        match value {
            Some(v) if v.trim() == "0" => Self::BypassedByFlag,
            _ => Self::Enforced,
        }
    }

    /// Read [`ATTESTATION_FLAG_ENV`] from the process environment.
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_flag(std::env::var(ATTESTATION_FLAG_ENV).ok().as_deref())
    }
}

/// Why a sandbox boot was refused (MIK-NEW.RUNTIME-A.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootDenial {
    /// No token was presented at sandbox creation.
    MissingToken,
    /// A token was presented but failed gateway validation.
    InvalidToken(AttestationRejection),
}

impl std::fmt::Display for BootDenial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingToken => write!(f, "sandbox boot denied: no attestation token"),
            Self::InvalidToken(r) => write!(f, "sandbox boot denied: {r}"),
        }
    }
}

impl std::error::Error for BootDenial {}

/// What a caller asks the launcher to start.
#[derive(Debug, Clone)]
pub struct SandboxLaunchSpec {
    /// Caller-chosen sandbox identifier.
    pub sandbox_id: String,
    /// Which substrate hosts the sandbox.
    pub substrate: Substrate,
    /// Environment to seed the sandbox with; the launcher adds
    /// [`TOKEN_ENV_VAR`] at the OCI `createRuntime` hook.
    pub env: HashMap<String, String>,
}

/// A booted sandbox with its verified attestation context.
#[derive(Debug, Clone)]
pub struct SandboxHandle {
    /// The sandbox identifier from the launch spec.
    pub sandbox_id: String,
    /// Substrate hosting the sandbox.
    pub substrate: Substrate,
    /// Whether the boot was attested (`false` only under the rollback flag).
    pub attested: bool,
    /// Verified claims; `None` only under the rollback flag.
    pub claims: Option<TokenClaims>,
    /// Ordered token-flow steps the boot went through.  Identical for both
    /// substrates by construction (MIK-NEW.RUNTIME-A.6) — tests assert it.
    pub flow_trace: Vec<&'static str>,
    /// Final sandbox environment, including the injected token.
    pub env: HashMap<String, String>,
}

/// Boots sandboxes behind the fail-closed attestation gate.
#[derive(Debug)]
pub struct AttestedSandboxLauncher {
    validator: Arc<AttestationValidator>,
    enforcement: AttestationEnforcement,
    boots_attested_total: AtomicU64,
    boots_bypassed_total: AtomicU64,
}

impl AttestedSandboxLauncher {
    /// Create a launcher validating against `validator` under `enforcement`.
    #[must_use]
    pub fn new(validator: Arc<AttestationValidator>, enforcement: AttestationEnforcement) -> Self {
        Self {
            validator,
            enforcement,
            boots_attested_total: AtomicU64::new(0),
            boots_bypassed_total: AtomicU64::new(0),
        }
    }

    /// The validator boots are checked against.
    #[must_use]
    pub fn validator(&self) -> &AttestationValidator {
        &self.validator
    }

    /// Boot a sandbox.  Fail closed: without a valid token the sandbox does
    /// not start (MIK-NEW.RUNTIME-A.1), unless the rollback flag bypasses
    /// enforcement.
    ///
    /// The token flow is one shared code path for every substrate: require →
    /// verify signature + claims at the gateway → inject at the OCI
    /// `createRuntime` hook → start.
    ///
    /// # Errors
    ///
    /// Returns [`BootDenial`] when no token is presented or validation fails;
    /// the rejection is also recorded in the validator's audit ring buffer.
    pub fn boot(
        &self,
        spec: SandboxLaunchSpec,
        token: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<SandboxHandle, BootDenial> {
        if self.enforcement == AttestationEnforcement::BypassedByFlag {
            self.boots_bypassed_total.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                sandbox_id = %spec.sandbox_id,
                substrate = spec.substrate.runtime_label(),
                "attestation_boot_bypassed"
            );
            return Ok(SandboxHandle {
                sandbox_id: spec.sandbox_id,
                substrate: spec.substrate,
                attested: false,
                claims: None,
                flow_trace: vec!["attestation_bypassed_by_flag", "sandbox_started"],
                env: spec.env,
            });
        }

        // Shared, substrate-independent token flow.
        let mut flow_trace = vec!["token_required"];
        let claims = self
            .validator
            .validate_boundary_call(token, BOOT_BOUNDARY, now)
            .map_err(|rejection| match rejection {
                AttestationRejection::MissingToken => BootDenial::MissingToken,
                other => BootDenial::InvalidToken(other),
            })?;
        flow_trace.push("token_signature_verified");
        flow_trace.push("claims_validated");

        // Inject at the OCI createRuntime hook — same hook on both substrates.
        let mut env = spec.env;
        if let Some(encoded) = token {
            env.insert(TOKEN_ENV_VAR.to_string(), encoded.to_string());
        }
        debug_assert_eq!(spec.substrate.token_injection_hook(), "createRuntime");
        flow_trace.push("oci_create_runtime_hook_token_injected");
        flow_trace.push("sandbox_started");

        self.boots_attested_total.fetch_add(1, Ordering::Relaxed);
        tracing::info!(
            sandbox_id = %spec.sandbox_id,
            substrate = spec.substrate.runtime_label(),
            token_id = %claims.token_id,
            agent = %claims.agent_identity,
            "attestation_boot"
        );

        Ok(SandboxHandle {
            sandbox_id: spec.sandbox_id,
            substrate: spec.substrate,
            attested: true,
            claims: Some(claims),
            flow_trace,
            env,
        })
    }

    /// Count of attested boots — distinct from the bypass counter (B1-IDENT).
    #[must_use]
    pub fn boots_attested_total(&self) -> u64 {
        self.boots_attested_total.load(Ordering::Relaxed)
    }

    /// Count of boots that skipped attestation under the rollback flag.
    #[must_use]
    pub fn boots_bypassed_total(&self) -> u64 {
        self.boots_bypassed_total.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::signer::{BnautAttestationSigner, TokenRequest};
    use chrono::TimeDelta;
    use uuid::Uuid;

    const KEY: &[u8] = b"launcher-test-key";

    fn launcher(enforcement: AttestationEnforcement) -> AttestedSandboxLauncher {
        let validator = Arc::new(AttestationValidator::new(BnautAttestationSigner::new(
            KEY.to_vec(),
            "unit",
        )));
        AttestedSandboxLauncher::new(validator, enforcement)
    }

    fn spec(substrate: Substrate) -> SandboxLaunchSpec {
        SandboxLaunchSpec {
            sandbox_id: "sb-1".to_string(),
            substrate,
            env: HashMap::new(),
        }
    }

    fn token(now: DateTime<Utc>) -> String {
        BnautAttestationSigner::new(KEY.to_vec(), "unit")
            .issue(
                &TokenRequest {
                    agent_identity: "agent".to_string(),
                    task_uuid: Uuid::new_v4(),
                    capabilities: vec!["cap".to_string()],
                },
                now,
                TimeDelta::minutes(5),
            )
            .encoded()
            .to_string()
    }

    #[test]
    fn flag_zero_bypasses_anything_else_enforces() {
        assert_eq!(
            AttestationEnforcement::from_flag(Some("0")),
            AttestationEnforcement::BypassedByFlag
        );
        for v in [None, Some("1"), Some(""), Some("true"), Some("off")] {
            assert_eq!(
                AttestationEnforcement::from_flag(v),
                AttestationEnforcement::Enforced,
                "flag {v:?} must enforce"
            );
        }
    }

    #[test]
    fn enforced_boot_without_token_is_denied() {
        let l = launcher(AttestationEnforcement::Enforced);
        let err = l
            .boot(spec(Substrate::GvisorLinux), None, Utc::now())
            .unwrap_err();
        assert_eq!(err, BootDenial::MissingToken);
        assert_eq!(l.boots_attested_total(), 0);
        assert_eq!(l.validator().audit().len(), 1);
    }

    #[test]
    fn enforced_boot_with_valid_token_injects_env() {
        let l = launcher(AttestationEnforcement::Enforced);
        let now = Utc::now();
        let t = token(now);
        let handle = l.boot(spec(Substrate::GvisorLinux), Some(&t), now).unwrap();
        assert!(handle.attested);
        assert_eq!(handle.env.get(TOKEN_ENV_VAR), Some(&t));
        assert_eq!(l.boots_attested_total(), 1);
    }

    #[test]
    fn bypassed_boot_starts_without_token_and_counts_separately() {
        let l = launcher(AttestationEnforcement::BypassedByFlag);
        let handle = l
            .boot(spec(Substrate::AppleContainerization), None, Utc::now())
            .unwrap();
        assert!(!handle.attested);
        assert!(handle.claims.is_none());
        assert_eq!(l.boots_bypassed_total(), 1);
        assert_eq!(l.boots_attested_total(), 0);
    }

    #[test]
    fn substrates_share_one_injection_hook() {
        assert_eq!(
            Substrate::GvisorLinux.token_injection_hook(),
            "createRuntime"
        );
        assert_eq!(
            Substrate::AppleContainerization.token_injection_hook(),
            "createRuntime"
        );
        assert_ne!(
            Substrate::GvisorLinux.runtime_label(),
            Substrate::AppleContainerization.runtime_label()
        );
    }
}
