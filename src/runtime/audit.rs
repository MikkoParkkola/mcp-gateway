//! Runtime audit events — redacted, NDJSON-structured evidence.
//!
//! Every runtime decision (provider selection, policy enforcement, start/stop
//! transitions, policy denials) is emitted as a single-line NDJSON record.
//! Secret values are redacted (replaced with `"<redacted>"`) while
//! non-secret keys and content hashes are preserved.

use serde::Serialize;
use std::fmt;

/// An audit event emitted by a [`RuntimeProvider`](super::provider::RuntimeProvider).
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    /// Timestamp as ISO-8601.
    pub timestamp: String,

    /// Backend name.
    pub backend: String,

    /// Provider identifier (e.g. `"local_compat"`, `"docker"`).
    pub provider: String,

    /// Action that produced this event.
    pub action: AuditAction,

    /// Policy verdict: `"allow"`, `"deny"`, or `"error"`.
    pub verdict: String,

    /// Policy content hash (SHA-256 of serialized policy, hex-encoded).
    /// Preserved even when individual values are redacted.
    pub policy_hash: Option<String>,

    /// Additional context (keys/descriptions, never raw secret values).
    pub context: serde_json::Value,
}

/// Actions that produce audit events.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    /// Provider was selected for a backend.
    ProviderSelected,

    /// Effective policy was computed and validated.
    PolicyEvaluated,

    /// Backend process/container was started.
    Started,

    /// Backend process/container was stopped.
    Stopped,

    /// Health check was performed.
    HealthCheck,

    /// A policy violation was detected — launch denied.
    PolicyDenied,
}

impl fmt::Display for AuditAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::ProviderSelected => "provider_selected",
            Self::PolicyEvaluated => "policy_evaluated",
            Self::Started => "started",
            Self::Stopped => "stopped",
            Self::HealthCheck => "health_check",
            Self::PolicyDenied => "policy_denied",
        };
        f.write_str(s)
    }
}

impl AuditEvent {
    /// Create a new audit event.
    pub fn new(backend: &str, provider: &str, action: AuditAction, verdict: &str) -> Self {
        Self {
            timestamp: iso_now(),
            backend: backend.to_string(),
            provider: provider.to_string(),
            action,
            verdict: verdict.to_string(),
            policy_hash: None,
            context: serde_json::Value::Object(serde_json::Map::new()),
        }
    }

    /// Attach a policy hash.
    #[must_use]
    pub fn with_policy_hash(mut self, hash: &str) -> Self {
        self.policy_hash = Some(hash.to_string());
        self
    }

    /// Add a context key-value pair.
    #[must_use]
    pub fn with_context(mut self, key: &str, value: impl Into<serde_json::Value>) -> Self {
        if let serde_json::Value::Object(ref mut map) = self.context {
            map.insert(key.to_string(), value.into());
        }
        self
    }

    /// Format as NDJSON line.
    pub fn to_ndjson(&self) -> String {
        let mut line = serde_json::to_string(self).unwrap_or_else(|_| r#"{"error":"serialize"}"#.to_string());
        line.push('\n');
        line
    }
}

/// Redact a secret value, preserving length hint for auditing.
#[must_use]
pub fn redact_secret_value(_value: &str) -> String {
    "<redacted>".to_string()
}

/// Compute a SHA-256 policy hash from a serializable policy value.
pub fn policy_hash(policy: &impl Serialize) -> String {
    use sha2::{Digest, Sha256};
    let json = serde_json::to_string(policy).unwrap_or_default();
    let digest = Sha256::digest(json.as_bytes());
    hex::encode(digest)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn iso_now() -> String {
    chrono::Utc::now().to_rfc3339()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// AC.6: Audit events redact secret values but preserve keys and hashes
    #[test]
    fn audit_events_redact_secrets_and_include_policy_verdicts() {
        // GIVEN: a provider, backend name, and a secret value
        let backend_name = "test-backend";
        let provider_name = "docker";
        let secret_value = "super-secret-api-key-12345";

        // WHEN: creating an audit event with a redacted secret
        let event = AuditEvent::new(
            backend_name,
            provider_name,
            AuditAction::PolicyEvaluated,
            "allow",
        )
        .with_policy_hash("abc123def456")
        .with_context("env_key", "API_KEY")
        .with_context("env_value", redact_secret_value(secret_value));

        // THEN: the event NDJSON contains the provider, backend, action, verdict,
        // policy hash, and context key — but NOT the raw secret value
        let ndjson = event.to_ndjson();
        assert!(ndjson.contains(backend_name));
        assert!(ndjson.contains(provider_name));
        assert!(ndjson.contains("policy_evaluated"));
        assert!(ndjson.contains("allow"));
        assert!(ndjson.contains("abc123def456"));
        assert!(ndjson.contains("API_KEY"));
        assert!(!ndjson.contains(secret_value));
        assert!(ndjson.contains("<redacted>"));
    }

    /// AC.6: Policy denial events include verifiable context
    #[test]
    fn denial_events_include_policy_verdict_and_context() {
        let event = AuditEvent::new(
            "backend-x",
            "docker",
            AuditAction::PolicyDenied,
            "deny",
        )
        .with_policy_hash("deadbeef")
        .with_context("reason", "host network forbidden")
        .with_context("denied_field", "egress.deny_default");

        let ndjson = event.to_ndjson();
        assert!(ndjson.contains("policy_denied"));
        assert!(ndjson.contains("deny"));
        assert!(ndjson.contains("host network forbidden"));
        assert!(ndjson.contains("deadbeef"));
        // No secrets to leak in a denial event
        assert!(!ndjson.contains("<redacted>"));
    }

    /// Verify that policy_hash is deterministic
    #[test]
    fn policy_hash_is_deterministic() {
        use super::super::policy::RuntimeConfig;
        let cfg1 = RuntimeConfig::docker_restricted();
        let cfg2 = RuntimeConfig::docker_restricted();
        let h1 = policy_hash(&cfg1);
        let h2 = policy_hash(&cfg2);
        assert_eq!(h1, h2);
    }

    /// Different policies produce different hashes
    #[test]
    fn different_policies_produce_different_hashes() {
        use super::super::policy::RuntimeConfig;
        let h1 = policy_hash(&RuntimeConfig::local_compat());
        let h2 = policy_hash(&RuntimeConfig::docker_restricted());
        assert_ne!(h1, h2);
    }
}
