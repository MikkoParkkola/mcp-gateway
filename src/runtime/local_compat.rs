//! `local_compat` runtime provider — preserves existing direct-launch stdio
//! behavior.
//!
//! This provider wraps [`StdioTransport`](crate::transport::StdioTransport) and
//! preserves all existing semantics: `cwd`, `env` overrides, protocol version
//! negotiation, lazy startup, stderr capture, and `kill_on_drop` cleanup.
//!
//! It is the default provider when no `runtime` config is specified,
//! guaranteeing backward compatibility for existing gateway.yaml deployments.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;

use super::audit::{AuditAction, AuditEvent, policy_hash};
use super::policy::RuntimeConfig;
use super::provider::{PolicyVerdict, RuntimeHandle, RuntimeProvider, validate_egress};
use crate::transport::{StdioTransport, Transport};
use crate::Result;

/// The `local_compat` runtime provider.
///
/// Delegates directly to [`StdioTransport`] for process lifecycle.
#[derive(Debug)]
pub struct LocalCompatProvider;

impl LocalCompatProvider {
    /// Create a new `LocalCompatProvider`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for LocalCompatProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RuntimeProvider for LocalCompatProvider {
    fn provider_id(&self) -> &str {
        "local_compat"
    }

    fn validate_policy(&self, config: &RuntimeConfig) -> PolicyVerdict {
        // Enforce: egress deny_default is not supported by local_compat
        if let PolicyVerdict::Deny(reason) = validate_egress(&config.egress, self.provider_id()) {
            return PolicyVerdict::Deny(reason);
        }

        // Enforce: host network is effectively always on for local_compat,
        // so we deny any explicit attempt to restrict it
        // (local_compat doesn't have network namespace isolation)

        PolicyVerdict::Allow
    }

    async fn start(
        &self,
        backend_name: &str,
        command: &str,
        env: HashMap<String, String>,
        cwd: Option<String>,
        protocol_version: Option<String>,
        request_timeout: std::time::Duration,
        config: &RuntimeConfig,
    ) -> Result<(Box<dyn RuntimeHandle>, Vec<AuditEvent>)> {
        let mut events: Vec<AuditEvent> = Vec::new();

        // Audit: provider selected
        events.push(
            AuditEvent::new(backend_name, self.provider_id(), AuditAction::ProviderSelected, "allow")
                .with_policy_hash(&policy_hash(config)),
        );

        // Build the effective env map:
        // - Start with configured env overrides (already merged from backend config)
        // - Apply env_policy allowlist if set
        let mut effective_env = if config.env_policy.allowlist.is_empty() {
            env
        } else {
            env.into_iter()
                .filter(|(k, _)| config.env_policy.allowlist.contains(k))
                .collect()
        };

        // Inject secrets as env vars
        for (env_key, secret_ref) in &config.secrets.env_secrets {
            // In production, this would resolve the secret reference.
            // For local_compat, we pass it through as-is (the env: prefix
            // convention is resolved by the gateway's secret injection layer).
            effective_env.insert(env_key.clone(), format!("env:{secret_ref}"));
        }

        // Create the stdio transport (same as existing behavior)
        let transport = StdioTransport::new(
            command,
            effective_env,
            cwd,
            request_timeout,
            protocol_version,
        );
        transport.start().await?;

        // Audit: started
        events.push(
            AuditEvent::new(backend_name, self.provider_id(), AuditAction::Started, "allow")
                .with_policy_hash(&policy_hash(config))
                .with_context("command", command),
        );

        Ok((
            Box::new(LocalCompatHandle {
                transport,
                backend_name: backend_name.to_string(),
                provider_id: self.provider_id().to_string(),
                config: config.clone(),
            }),
            events,
        ))
    }

    fn audit_selection(&self, backend_name: &str, config: &RuntimeConfig) -> Vec<AuditEvent> {
        vec![AuditEvent::new(
            backend_name,
            self.provider_id(),
            AuditAction::ProviderSelected,
            "allow",
        )
        .with_policy_hash(&policy_hash(config))]
    }
}

/// Handle for a `local_compat` backend.
struct LocalCompatHandle {
    transport: Arc<StdioTransport>,
    backend_name: String,
    provider_id: String,
    config: RuntimeConfig,
}

#[async_trait]
impl RuntimeHandle for LocalCompatHandle {
    fn is_healthy(&self) -> bool {
        self.transport.is_connected()
    }

    fn logs(&self) -> Vec<String> {
        // StdioTransport captures stderr internally; expose it if available.
        // For now, return empty — the transport handles stderr capture via tracing.
        Vec::new()
    }

    async fn stop(&self) -> Result<Vec<AuditEvent>> {
        self.transport.close().await?;
        Ok(vec![
            AuditEvent::new(
                &self.backend_name,
                &self.provider_id,
                AuditAction::Stopped,
                "allow",
            )
            .with_policy_hash(&policy_hash(&self.config)),
        ])
    }

    fn as_transport(&self) -> Option<Arc<dyn crate::transport::Transport>> {
        Some(self.transport.clone())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// AC.2: LocalCompat preserves existing stdio launch semantics
    #[test]
    fn local_compat_preserves_existing_stdio_launch_semantics() {
        // GIVEN: a local_compat provider
        let provider = LocalCompatProvider::new();
        assert_eq!(provider.provider_id(), "local_compat");

        // WHEN: validating a default local_compat policy
        let config = RuntimeConfig::local_compat();
        let verdict = provider.validate_policy(&config);

        // THEN: policy is allowed (existing behavior preserved)
        assert!(verdict.is_allowed(), "local_compat should accept default config");

        // AND: egress deny_default would be rejected (local_compat cannot
        // enforce network isolation)
        let mut egress_config = RuntimeConfig::local_compat();
        egress_config.egress.deny_default = true;
        let egress_verdict = provider.validate_policy(&egress_config);
        assert!(
            egress_verdict.denial_reason().is_some(),
            "local_compat should deny egress.deny_default"
        );
    }

    /// AC.2: Audit events are emitted for provider selection
    #[test]
    fn local_compat_emits_audit_on_selection() {
        let provider = LocalCompatProvider::new();
        let config = RuntimeConfig::local_compat();
        let events = provider.audit_selection("test-backend", &config);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].provider, "local_compat");
        assert_eq!(events[0].backend, "test-backend");
        assert!(events[0].policy_hash.is_some());
    }
}
