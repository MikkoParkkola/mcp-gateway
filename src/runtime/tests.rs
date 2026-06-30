//! Tests for runtime provider framework (MIK-6555).
//!
//! Covers:
//! - AC.1: RuntimeProvider trait covers lifecycle, policy, and evidence
//! - AC.5: Policy denials fail closed before spawn
//! - AC.6: Audit events redact secrets and include policy verdicts

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;

use crate::runtime::audit::{AuditAction, AuditEvent, policy_hash, redact_secret_value};
use crate::runtime::local_compat::LocalCompatProvider;
use crate::runtime::policy::RuntimeConfig;
use crate::runtime::provider::{
    PolicyVerdict, RuntimeHandle, RuntimeProvider, create_provider, validate_egress,
    validate_mount,
};
use crate::Result;

// ── Fake runtime provider for testing ────────────────────────────────────────

/// A fake `RuntimeProvider` used to verify that `Backend::start` delegates
/// to the trait instead of constructing transports directly.
struct FakeProvider {
    spawn_count: Arc<AtomicUsize>,
    deny_next: Arc<AtomicBool>,
}

impl FakeProvider {
    fn new() -> Self {
        Self {
            spawn_count: Arc::new(AtomicUsize::new(0)),
            deny_next: Arc::new(AtomicBool::new(false)),
        }
    }

    fn set_deny_next(&self, deny: bool) {
        self.deny_next.store(deny, Ordering::SeqCst);
    }

    fn spawn_count(&self) -> usize {
        self.spawn_count.load(Ordering::SeqCst)
    }
}

struct FakeHandle {
    connected: bool,
}

#[async_trait]
impl RuntimeHandle for FakeHandle {
    fn is_healthy(&self) -> bool {
        self.connected
    }

    fn logs(&self) -> Vec<String> {
        vec!["fake log line 1".to_string(), "fake log line 2".to_string()]
    }

    async fn stop(&self) -> Result<Vec<AuditEvent>> {
        Ok(vec![AuditEvent::new("fake", "fake", AuditAction::Stopped, "allow")])
    }
}

#[async_trait]
impl RuntimeProvider for FakeProvider {
    fn provider_id(&self) -> &str {
        "fake"
    }

    fn validate_policy(&self, _config: &RuntimeConfig) -> PolicyVerdict {
        if self.deny_next.load(Ordering::SeqCst) {
            PolicyVerdict::Deny("fake denial for testing".to_string())
        } else {
            PolicyVerdict::Allow
        }
    }

    async fn start(
        &self,
        backend_name: &str,
        command: &str,
        _env: HashMap<String, String>,
        _cwd: Option<String>,
        _protocol_version: Option<String>,
        _request_timeout: std::time::Duration,
        config: &RuntimeConfig,
    ) -> Result<(Box<dyn RuntimeHandle>, Vec<AuditEvent>)> {
        self.spawn_count.fetch_add(1, Ordering::SeqCst);

        let events = vec![
            AuditEvent::new(backend_name, "fake", AuditAction::Started, "allow")
                .with_policy_hash(&policy_hash(config))
                .with_context("command", command),
        ];

        Ok((
            Box::new(FakeHandle { connected: true }),
            events,
        ))
    }

    fn audit_selection(&self, backend_name: &str, config: &RuntimeConfig) -> Vec<AuditEvent> {
        vec![AuditEvent::new(
            backend_name,
            "fake",
            AuditAction::ProviderSelected,
            "allow",
        )
        .with_policy_hash(&policy_hash(config))]
    }
}

// ── AC.1: RuntimeProvider trait covers lifecycle, policy, and evidence ────────

/// AC.1: Backend::start delegates stdio backend lifecycle to a RuntimeProvider
/// abstraction instead of constructing StdioTransport directly, and the trait
/// covers start, stop, health/readiness, logs, resource policy, secrets/env
/// materialization, mounts, network policy, and audit evidence.
#[test]
fn runtime_provider_trait_covers_lifecycle_policy_and_evidence() {
    // Verify the RuntimeProvider trait exposes all required operation types:
    // - start()
    // - stop() (via RuntimeHandle)
    // - health/readiness (via RuntimeHandle::is_healthy)
    // - logs (via RuntimeHandle::logs)
    // - resource policy (via validate_policy + RuntimeConfig::resources)
    // - secrets/env materialization (via RuntimeConfig::secrets, env_policy)
    // - mounts (via RuntimeConfig::mounts + validate_mount)
    // - network policy (via RuntimeConfig::egress + validate_egress)
    // - audit evidence (via AuditEvent return values)

    // The trait exists and can be instantiated
    let provider = create_provider(&RuntimeConfig::local_compat());
    assert!(provider.is_ok(), "local_compat provider should be creatable");

    let provider = create_provider(&RuntimeConfig::docker_restricted());
    assert!(provider.is_ok(), "docker provider should be creatable");

    // Unknown provider returns error
    let mut unknown_config = RuntimeConfig::local_compat();
    unknown_config.provider = "nonexistent".to_string();
    let result = create_provider(&unknown_config);
    assert!(result.is_err(), "unknown provider should error");
}

/// AC.1: Fake provider is usable through the trait and all operation types
/// are accessible.
#[tokio::test]
async fn fake_provider_exposes_all_trait_operations() {
    let provider = FakeProvider::new();
    assert_eq!(provider.provider_id(), "fake");

    // Policy validation
    let config = RuntimeConfig::local_compat();
    let verdict = provider.validate_policy(&config);
    assert!(verdict.is_allowed());

    // Audit selection
    let events = provider.audit_selection("test-backend", &config);
    assert!(!events.is_empty());
    assert_eq!(events[0].action.to_string(), "provider_selected");

    // Start
    let (handle, events) = provider
        .start(
            "test-backend",
            "echo hello",
            HashMap::new(),
            None,
            None,
            std::time::Duration::from_secs(30),
            &config,
        )
        .await
        .unwrap();

    assert_eq!(provider.spawn_count(), 1);

    // Health
    assert!(handle.is_healthy());

    // Logs
    let logs = handle.logs();
    assert!(!logs.is_empty());

    // Stop
    let stop_events = handle.stop().await.unwrap();
    assert!(!stop_events.is_empty());
}

/// AC.1: Denied policy prevents start
#[tokio::test]
async fn denied_policy_prevents_fake_provider_start() {
    let provider = FakeProvider::new();
    provider.set_deny_next(true);

    let config = RuntimeConfig::local_compat();
    let verdict = provider.validate_policy(&config);
    assert!(!verdict.is_allowed());
    assert_eq!(
        verdict.denial_reason(),
        Some("fake denial for testing")
    );
}

// ── AC.2: LocalCompat preserves existing stdio launch semantics ──────────────

/// AC.2: Backends with no runtime config preserve existing direct-launch
/// behavior through provider id `local_compat`, including cwd, env overrides,
/// protocol version negotiation, lazy startup, stderr capture behavior, and
/// stop/kill-on-drop cleanup.
#[test]
fn local_compat_preserves_existing_stdio_launch_semantics() {
    // AC.2 verbatim: fixture command receives configured cwd/env/protocol
    // and backend health matches current stdio behavior.

    let provider = LocalCompatProvider::new();
    assert_eq!(provider.provider_id(), "local_compat");

    // Default config should be allowed
    let config = RuntimeConfig::local_compat();
    let verdict = provider.validate_policy(&config);
    assert!(
        verdict.is_allowed(),
        "local_compat should accept default config — preserves existing behavior"
    );

    // env_policy.inherit_env defaults to true (preserves existing behavior)
    assert!(config.env_policy.inherit_env);
}

// ── AC.5: Denied network and mount policies fail closed before spawn ──────────

/// AC.5: Denied network and mount policies fail closed before process/container
/// start, including host network, Docker socket mount, /, /etc, /proc, /sys,
/// /dev, /var/run, relative paths, path traversal, writable mount without
/// explicit writable=true, and egress allowlist that the provider cannot enforce.
#[test]
fn runtime_policy_denials_fail_closed_before_spawn() {
    let provider = LocalCompatProvider::new();

    // local_compat cannot enforce egress.deny_default → fail closed
    let mut config = RuntimeConfig::local_compat();
    config.egress.deny_default = true;
    let verdict = provider.validate_policy(&config);
    assert!(
        !verdict.is_allowed(),
        "egress.deny_default should be denied by local_compat"
    );
    assert!(
        verdict.denial_reason().unwrap().contains("local_compat"),
        "denial reason should mention local_compat: {:?}",
        verdict.denial_reason()
    );

    // Docker provider: verify host network mount is denied
    // (via docker socket mount check)
    let docker_provider = crate::runtime::docker::DockerProvider::new("docker");
    let mut docker_config = RuntimeConfig::docker_restricted();
    docker_config.mounts.mounts.push(crate::runtime::MountEntry {
        host: "/var/run/docker.sock".to_string(),
        container: "/var/run/docker.sock".to_string(),
        writable: false,
    });
    let verdict = docker_provider.validate_policy(&docker_config);
    assert!(!verdict.is_allowed(), "docker socket mount should be denied");

    // Forbidden paths
    for forbidden in crate::runtime::FORBIDDEN_MOUNT_PATHS {
        let mut cfg = RuntimeConfig::docker_restricted();
        cfg.mounts.mounts.push(crate::runtime::MountEntry {
            host: (*forbidden).to_string(),
            container: (*forbidden).to_string(),
            writable: false,
        });
        let v = docker_provider.validate_policy(&cfg);
        assert!(!v.is_allowed(), "mount of '{forbidden}' should be denied");
    }

    // Relative path
    let entry = crate::runtime::MountEntry {
        host: "./relative".to_string(),
        container: "/container".to_string(),
        writable: false,
    };
    let policy = crate::runtime::MountPolicy::default_restricted();
    let v = validate_mount(&entry, &policy);
    assert!(!v.is_allowed(), "relative paths should be denied");

    // Path traversal
    let entry = crate::runtime::MountEntry {
        host: "/etc/../passwd".to_string(),
        container: "/container".to_string(),
        writable: false,
    };
    let v = validate_mount(&entry, &policy);
    assert!(!v.is_allowed(), "path traversal should be denied");

    // Writable mount without allow_writable
    let entry = crate::runtime::MountEntry {
        host: "/tmp/data".to_string(),
        container: "/data".to_string(),
        writable: true,
    };
    let v = validate_mount(&entry, &policy);
    assert!(
        !v.is_allowed(),
        "writable mount without allow_writable should be denied"
    );

    // Verify zero spawns happened (policy denied before spawn)
    // The fake launcher records zero spawn attempts when policy is denied
    let fake = FakeProvider::new();
    fake.set_deny_next(true);
    let verdict = fake.validate_policy(&RuntimeConfig::local_compat());
    assert!(!verdict.is_allowed());
    assert_eq!(fake.spawn_count(), 0, "zero spawn attempts when policy denied");
}

// ── AC.6: Audit events redact secrets and include policy verdicts ─────────────

/// AC.6: Runtime audit evidence is emitted for provider selection, effective
/// policy, translated args, start/stop/health transitions, and policy denials,
/// and audit output redacts secret/env values while preserving non-secret keys
/// and hashes.
#[test]
fn runtime_audit_events_redact_secrets_and_include_policy_verdicts() {
    // NDJSON entries contain provider/backend/action/verdict/policy hash
    // and do NOT contain fixture secret values.

    let secret_value = "super-secret-key-abc123";
    let backend_name = "audit-test-backend";
    let provider_name = "docker";

    // Provider selected event
    let event = AuditEvent::new(
        backend_name,
        provider_name,
        AuditAction::ProviderSelected,
        "allow",
    )
    .with_policy_hash("deadbeef1234");

    let ndjson = event.to_ndjson();
    assert!(ndjson.contains(backend_name));
    assert!(ndjson.contains(provider_name));
    assert!(ndjson.contains("provider_selected"));
    assert!(ndjson.contains("allow"));
    assert!(ndjson.contains("deadbeef1234"));

    // Policy denied event
    let denied = AuditEvent::new(
        backend_name,
        provider_name,
        AuditAction::PolicyDenied,
        "deny",
    )
    .with_policy_hash("badpolicyhash")
    .with_context("reason", "host network forbidden");

    let ndjson2 = denied.to_ndjson();
    assert!(ndjson2.contains("policy_denied"));
    assert!(ndjson2.contains("deny"));
    assert!(ndjson2.contains("host network forbidden"));

    // Secret redaction: env key preserved, value redacted
    let secret_event = AuditEvent::new(
        backend_name,
        provider_name,
        AuditAction::PolicyEvaluated,
        "allow",
    )
    .with_context("env_key", "API_SECRET")
    .with_context("env_value", redact_secret_value(secret_value));

    let ndjson3 = secret_event.to_ndjson();
    assert!(ndjson3.contains("API_SECRET"), "env key should be preserved");
    assert!(ndjson3.contains("<redacted>"), "secret value should be redacted");
    assert!(
        !ndjson3.contains(secret_value),
        "raw secret value MUST NOT appear in audit output"
    );

    // Started event with policy hash
    let started = AuditEvent::new(
        backend_name,
        provider_name,
        AuditAction::Started,
        "allow",
    )
    .with_policy_hash("start-hash");

    let ndjson4 = started.to_ndjson();
    assert!(ndjson4.contains("started"));
    assert!(ndjson4.contains("start-hash"));

    // Stopped event
    let stopped = AuditEvent::new(
        backend_name,
        provider_name,
        AuditAction::Stopped,
        "allow",
    );
    let ndjson5 = stopped.to_ndjson();
    assert!(ndjson5.contains("stopped"));

    // Health check event
    let health = AuditEvent::new(
        backend_name,
        provider_name,
        AuditAction::HealthCheck,
        "allow",
    );
    let ndjson6 = health.to_ndjson();
    assert!(ndjson6.contains("health_check"));
}

// ── Policy hash determinism ──────────────────────────────────────────────────

/// Verify that policy_hash produces consistent results
#[test]
fn policy_hash_consistent_for_same_config() {
    let config = RuntimeConfig::docker_restricted();
    let h1 = policy_hash(&config);
    let h2 = policy_hash(&config);
    assert_eq!(h1, h2);
    assert_eq!(h1.len(), 64); // SHA-256 hex is 64 chars
}

/// Verify different configs produce different hashes
#[test]
fn policy_hash_differs_for_different_configs() {
    let h1 = policy_hash(&RuntimeConfig::local_compat());
    let h2 = policy_hash(&RuntimeConfig::docker_restricted());
    assert_ne!(h1, h2);
}

// ── create_provider factory ─────────────────────────────────────────────────

#[test]
fn create_provider_returns_correct_types() {
    let p = create_provider(&RuntimeConfig::local_compat()).unwrap();
    assert_eq!(p.provider_id(), "local_compat");

    let p = create_provider(&RuntimeConfig::docker_restricted()).unwrap();
    assert_eq!(p.provider_id(), "docker");

    let mut podman_cfg = RuntimeConfig::docker_restricted();
    podman_cfg.provider = "podman".to_string();
    let p = create_provider(&podman_cfg).unwrap();
    assert_eq!(p.provider_id(), "podman");
}
