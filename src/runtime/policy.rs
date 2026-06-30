//! Runtime policy model for backend MCP server execution.
//!
//! Defines the canonical policy types for resource limits, filesystem mounts,
//! egress networking, environment allowlists, secrets, identity, timeouts, and
//! log capture. These are serializable into [`BackendConfig`] and enforced by
//! [`RuntimeProvider`](super::provider::RuntimeProvider) implementations.
//!
//! # Policy enforcement model
//!
//! Every policy field follows a **fail-closed** rule: if the provider cannot
//! enforce a requested policy (e.g. egress allowlist on a provider that lacks
//! network namespace support), it MUST reject the launch before any process or
//! container is started.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Runtime configuration for a backend.
///
/// Placed inside `BackendConfig.runtime`. When the entire `runtime` key is
/// absent from YAML, it defaults to [`RuntimeConfig::local_compat()`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RuntimeConfig {
    /// Provider identifier: `"local_compat"`, `"docker"`, or `"podman"`.
    ///
    /// Default: `"local_compat"` — preserves existing direct-launch behavior.
    #[serde(default = "default_provider")]
    pub provider: String,

    /// Resource limits (CPU, memory).
    #[serde(default)]
    pub resources: ResourcePolicy,

    /// Filesystem mount policy.
    #[serde(default)]
    pub mounts: MountPolicy,

    /// Egress network policy.
    #[serde(default)]
    pub egress: EgressPolicy,

    /// Environment variable allowlist.
    #[serde(default)]
    pub env_policy: EnvPolicy,

    /// Secrets materialization rules.
    #[serde(default)]
    pub secrets: SecretPolicy,

    /// Container / process identity.
    #[serde(default)]
    pub identity: IdentityPolicy,

    /// Timeout configuration.
    #[serde(default)]
    pub timeouts: TimeoutPolicy,

    /// Log capture policy.
    #[serde(default)]
    pub log_policy: LogPolicy,
}

fn default_provider() -> String {
    "local_compat".to_string()
}

impl RuntimeConfig {
    /// Return the `local_compat` default runtime config.
    #[must_use]
    pub fn local_compat() -> Self {
        Self {
            provider: "local_compat".to_string(),
            ..Default::default()
        }
    }

    /// Return the `docker` runtime config with restricted defaults.
    #[must_use]
    pub fn docker_restricted() -> Self {
        Self {
            provider: "docker".to_string(),
            egress: EgressPolicy::default_deny(),
            mounts: MountPolicy::default_restricted(),
            ..Default::default()
        }
    }

    /// Return the `podman` runtime config with restricted defaults.
    #[must_use]
    pub fn podman_restricted() -> Self {
        Self {
            provider: "podman".to_string(),
            egress: EgressPolicy::default_deny(),
            mounts: MountPolicy::default_restricted(),
            ..Default::default()
        }
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self::local_compat()
    }
}

// ── Resource limits ──────────────────────────────────────────────────────────

/// CPU and memory resource limits for a backend process or container.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResourcePolicy {
    /// CPU limit in fractional cores (e.g. 1.0 = one core).  0 means unlimited.
    #[serde(default)]
    pub cpu: f64,

    /// Memory limit as a human-readable string (e.g. `"256MiB"`, `"2GiB"`).
    /// Empty string means unlimited.
    #[serde(default)]
    pub memory: String,
}

// ── Mount policy ─────────────────────────────────────────────────────────────

/// Filesystem mount policy.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MountPolicy {
    /// Mounts to apply.  Empty = no mounts (read-only root when possible).
    #[serde(default)]
    pub mounts: Vec<MountEntry>,

    /// When `true`, writable mounts are allowed.  Default: `false` — all
    /// mounts are read-only unless explicitly annotated.
    #[serde(default)]
    pub allow_writable: bool,
}

impl MountPolicy {
    /// Restricted default: no mounts, read-only root, no writable.
    #[must_use]
    pub fn default_restricted() -> Self {
        Self::default()
    }
}

/// A single filesystem mount entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountEntry {
    /// Host path to mount.
    pub host: String,

    /// Container path.
    pub container: String,

    /// When `true`, mount is read-write.  Requires `allow_writable` on the
    /// parent [`MountPolicy`].
    #[serde(default)]
    pub writable: bool,
}

/// Paths that are denied for mounts regardless of policy.
pub const FORBIDDEN_MOUNT_PATHS: &[&str] = &[
    "/", "/etc", "/proc", "/sys", "/dev", "/var/run",
];

/// Docker socket paths that are denied.
pub const FORBIDDEN_DOCKER_SOCKET_PATHS: &[&str] = &[
    "/var/run/docker.sock", "/run/docker.sock",
];

// ── Egress policy ────────────────────────────────────────────────────────────

/// Egress network policy.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EgressPolicy {
    /// Allowlist of CIDR ranges or hostnames.
    #[serde(default)]
    pub allowlist: Vec<String>,

    /// When `true`, all egress is denied unless explicitly in the allowlist.
    /// When `false` (default for `local_compat`), egress is unrestricted.
    #[serde(default)]
    pub deny_default: bool,
}

impl EgressPolicy {
    /// Restricted default: deny all egress.
    #[must_use]
    pub fn default_deny() -> Self {
        Self {
            allowlist: Vec::new(),
            deny_default: true,
        }
    }
}

// ── Environment policy ───────────────────────────────────────────────────────

/// Environment variable policy.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EnvPolicy {
    /// Explicit allowlist of environment variable keys.  When non-empty, only
    /// these keys (plus backend-configured env overrides) are passed to the
    /// process/container.
    #[serde(default)]
    pub allowlist: Vec<String>,

    /// When `true`, the process inherits the gateway's own environment.
    /// Default: `false` for container providers, `true` for `local_compat` to
    /// preserve existing behavior.
    #[serde(default = "default_inherit")]
    pub inherit_env: bool,
}

fn default_inherit() -> bool {
    true
}

// ── Secrets policy ───────────────────────────────────────────────────────────

/// Secrets materialization policy.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecretPolicy {
    /// Secrets to inject as environment variables.  Key = env var name,
    /// value = reference to a secret (e.g. `"env:SECRET_KEY"` or a path).
    #[serde(default)]
    pub env_secrets: HashMap<String, String>,

    /// Paths to mount as secret files (host_path -> container_path).
    #[serde(default)]
    pub file_secrets: HashMap<String, String>,
}

// ── Identity policy ──────────────────────────────────────────────────────────

/// Process/container identity policy.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IdentityPolicy {
    /// User/UID to run as.
    #[serde(default)]
    pub user: Option<String>,

    /// Group/GID to run as.
    #[serde(default)]
    pub group: Option<String>,
}

// ── Timeout policy ───────────────────────────────────────────────────────────

/// Timeout configuration for runtime operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutPolicy {
    /// Maximum time to wait for a process/container to start (seconds).
    #[serde(default = "default_start_timeout_secs")]
    pub start_secs: u64,

    /// Maximum time to wait for a graceful stop (seconds).
    #[serde(default = "default_stop_timeout_secs")]
    pub stop_secs: u64,

    /// Idle timeout before hibernation (seconds).
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
}

fn default_start_timeout_secs() -> u64 {
    30
}
fn default_stop_timeout_secs() -> u64 {
    10
}
fn default_idle_timeout_secs() -> u64 {
    300
}

impl Default for TimeoutPolicy {
    fn default() -> Self {
        Self {
            start_secs: 30,
            stop_secs: 10,
            idle_timeout_secs: 300,
        }
    }
}

// ── Log policy ───────────────────────────────────────────────────────────────

/// Log capture policy.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LogPolicy {
    /// When `true`, capture stdout/stderr from the backend process.
    #[serde(default = "default_true_bool")]
    pub capture: bool,

    /// Maximum number of log lines to retain in memory.
    #[serde(default = "default_max_lines")]
    pub max_lines: usize,
}

fn default_true_bool() -> bool {
    true
}
fn default_max_lines() -> usize {
    1000
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// AC.3: Omitted runtime config defaults to local_compat
    #[test]
    fn runtime_config_default_is_local_compat() {
        let cfg = RuntimeConfig::default();
        assert_eq!(cfg.provider, "local_compat");
    }

    /// AC.3: RuntimeConfig serde round-trip preserves all fields
    #[test]
    fn runtime_config_roundtrip_preserves_fields() {
        let yaml = r#"
provider: docker
resources:
  cpu: 1.0
  memory: "512MiB"
mounts:
  allow_writable: true
  mounts:
    - host: /tmp/data
      container: /data
      writable: true
egress:
  deny_default: true
  allowlist:
    - "10.0.0.0/8"
env_policy:
  inherit_env: false
  allowlist:
    - PATH
    - HOME
secrets:
  env_secrets:
    API_KEY: "env:MCP_SECRET"
identity:
  user: "1000"
timeouts:
  start_secs: 60
log_policy:
  capture: true
  max_lines: 500
"#;
        let cfg: RuntimeConfig = serde_yaml::from_str(yaml).expect("parse YAML");
        let roundtripped: RuntimeConfig =
            serde_yaml::from_str(&serde_yaml::to_string(&cfg).unwrap()).unwrap();
        assert_eq!(roundtripped.provider, "docker");
        assert!((roundtripped.resources.cpu - 1.0f64).abs() < f64::EPSILON);
        assert_eq!(roundtripped.resources.memory, "512MiB");
        assert!(roundtripped.mounts.allow_writable);
        assert_eq!(roundtripped.mounts.mounts.len(), 1);
        assert!(roundtripped.egress.deny_default);
        assert_eq!(roundtripped.egress.allowlist.len(), 1);
        assert!(!roundtripped.env_policy.inherit_env);
        assert_eq!(roundtripped.env_policy.allowlist.len(), 2);
        assert_eq!(roundtripped.secrets.env_secrets.len(), 1);
        assert_eq!(
            roundtripped.identity.user.as_deref(),
            Some("1000")
        );
        assert_eq!(roundtripped.timeouts.start_secs, 60);
        assert!(roundtripped.log_policy.capture);
        assert_eq!(roundtripped.log_policy.max_lines, 500);
    }

    /// AC.3: YAML without runtime section becomes local_compat
    #[test]
    fn omitted_runtime_defaults_to_local_compat() {
        // Simulate what serde does when the `runtime` field is missing:
        // #[serde(default)] on the field fills in RuntimeConfig::default().
        let cfg = RuntimeConfig::default();
        assert_eq!(cfg.provider, "local_compat");
        // Default resources should be unlimited
        assert!((cfg.resources.cpu - 0.0f64).abs() < f64::EPSILON);
        assert!(cfg.resources.memory.is_empty());
        // Default should inherit env (local_compat behavior)
        assert!(cfg.env_policy.inherit_env);
    }
}
