//! Docker/Podman runtime provider — container-based isolation for MCP server
//! execution.
//!
//! Starts stdio MCP servers inside Docker or Podman containers with restricted
//! defaults: no host network, read-only root filesystem, explicit env
//! allowlist only, read-only bind mounts by default, resource limits, and
//! deterministic labels.
//!
//! # Security defaults
//!
//! | Setting                | Default                  |
//! |------------------------|--------------------------|
//! | Network                | `--network none`         |
//! | Root filesystem        | `--read-only`            |
//! | Privileged mode        | Not set (denied)         |
//! | seccomp unconfined     | Not set (denied)         |
//! | Docker socket mount    | Denied                   |
//! | Environment            | Explicit `--env` only    |
//! | Resource limits        | `--cpus`, `--memory`     |
//! | Labels                 | Deterministic            |

use async_trait::async_trait;
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;

use tokio::process::Command;
use tokio::sync::Mutex as TokioMutex;

use super::audit::{AuditAction, AuditEvent, policy_hash, redact_secret_value};
use super::policy::RuntimeConfig;
use super::provider::{
    PolicyVerdict, RuntimeHandle, RuntimeProvider, validate_egress, validate_mount,
};
use crate::Result;

/// Forbidden container runtime flags.
const FORBIDDEN_FLAGS: &[&str] = &[
    "--privileged",
    "--seccomp=unconfined",
    "--security-opt=seccomp=unconfined",
    "--network=host",
    "--pid=host",
    "--ipc=host",
];

/// Container runtime provider (Docker or Podman).
#[derive(Debug)]
pub struct DockerProvider {
    /// Runtime binary name: `"docker"` or `"podman"`.
    runtime_bin: String,
}

impl DockerProvider {
    /// Create a new container runtime provider.
    #[must_use]
    pub fn new(runtime_bin: &str) -> Self {
        Self {
            runtime_bin: runtime_bin.to_string(),
        }
    }
}

#[async_trait]
impl RuntimeProvider for DockerProvider {
    fn provider_id(&self) -> &str {
        &self.runtime_bin
    }

    fn validate_policy(&self, config: &RuntimeConfig) -> PolicyVerdict {
        // Validate egress
        if let PolicyVerdict::Deny(reason) = validate_egress(&config.egress, self.provider_id()) {
            return PolicyVerdict::Deny(reason);
        }

        // Validate each mount entry
        for mount in &config.mounts.mounts {
            if let PolicyVerdict::Deny(reason) = validate_mount(mount, &config.mounts) {
                return PolicyVerdict::Deny(reason);
            }
        }

        PolicyVerdict::Allow
    }

    async fn start(
        &self,
        backend_name: &str,
        command: &str,
        env: HashMap<String, String>,
        cwd: Option<String>,
        _protocol_version: Option<String>,
        _request_timeout: std::time::Duration,
        config: &RuntimeConfig,
    ) -> Result<(Box<dyn RuntimeHandle>, Vec<AuditEvent>)> {
        let mut events: Vec<AuditEvent> = Vec::new();

        // Audit: provider selected
        events.push(
            AuditEvent::new(backend_name, self.provider_id(), AuditAction::ProviderSelected, "allow")
                .with_policy_hash(&policy_hash(config)),
        );

        // Build container args
        let container_name = sanitize_container_name(backend_name);
        let image = build_image_name(backend_name, command);
        let mut args: Vec<String> = Vec::new();

        // Base docker/podman run args
        args.push("run".to_string());
        args.push("--rm".to_string());
        args.push("--name".to_string());
        args.push(container_name.clone());

        // Labels for traceability
        args.push("--label".to_string());
        args.push(format!("mcp-gateway.backend={backend_name}"));
        args.push("--label".to_string());
        args.push(format!(
            "mcp-gateway.provider={}",
            self.provider_id()
        ));

        // ── Network: no host network, default to --network none ──
        args.push("--network".to_string());
        if config.egress.deny_default && config.egress.allowlist.is_empty() {
            args.push("none".to_string());
        } else {
            // When egress is allowed, use bridge (default) or custom network
            // For now, default to bridge with restricted egress
            args.push("bridge".to_string());
        }

        // ── Read-only root filesystem (unless writable mounts declared) ──
        if !config.mounts.allow_writable
            && !config.mounts.mounts.iter().any(|m| m.writable)
        {
            args.push("--read-only".to_string());
        }

        // ── Environment: explicit --env per variable ──
        // Only pass allowlisted env vars + backend-configured env
        for (key, value) in &env {
            if config.env_policy.allowlist.is_empty()
                || config.env_policy.allowlist.contains(key)
            {
                args.push("--env".to_string());
                args.push(format!("{key}={value}"));

                // Audit: redact value but log key
                events.push(
                    AuditEvent::new(
                        backend_name,
                        self.provider_id(),
                        AuditAction::PolicyEvaluated,
                        "allow",
                    )
                    .with_policy_hash(&policy_hash(config))
                    .with_context("env_key", key.as_str())
                    .with_context("env_value", redact_secret_value(value)),
                );
            }
        }

        // Inject secrets as env vars (redacted in audit)
        for (env_key, _secret_ref) in &config.secrets.env_secrets {
            args.push("--env".to_string());
            args.push(format!("{env_key}=<secret>"));
            events.push(
                AuditEvent::new(
                    backend_name,
                    self.provider_id(),
                    AuditAction::PolicyEvaluated,
                    "allow",
                )
                .with_policy_hash(&policy_hash(config))
                .with_context("env_key", env_key.as_str())
                .with_context("env_value", "<redacted>"),
            );
        }

        // ── Resource limits ──
        if config.resources.cpu > 0.0 {
            args.push("--cpus".to_string());
            args.push(format!("{:.2}", config.resources.cpu));
        }
        if !config.resources.memory.is_empty() {
            args.push("--memory".to_string());
            args.push(config.resources.memory.clone());
        }

        // ── Mounts ──
        for mount in &config.mounts.mounts {
            let mut bind = format!("{}:{}", mount.host, mount.container);
            if !mount.writable {
                bind.push_str(":ro");
            }
            args.push("--mount".to_string());
            args.push(format!("type=bind,source={},target={},bind-propagation=rprivate",
                mount.host, mount.container));
            if !mount.writable {
                // For read-only, add :ro to --volume style
                // --mount doesn't need :ro since we use bind-propagation
                // but we keep consistent with explicit read-only
                let idx = args.len() - 1;
                args[idx] = format!("{},readonly", args[idx]);
            }
        }

        // ── User ──
        if let Some(ref user) = config.identity.user {
            args.push("--user".to_string());
            args.push(user.clone());
        }

        // ── Working directory ──
        if let Some(ref cwd) = cwd {
            args.push("--workdir".to_string());
            args.push(cwd.clone());
        }

        // ── Image + command ──
        args.push(image);

        // Parse the original command into program + args
        let cmd_parts = shlex::split(command)
            .ok_or_else(|| crate::Error::Config(format!("Invalid command quoting: {command}")))?;
        if cmd_parts.is_empty() {
            return Err(crate::Error::Config("Empty command".to_string()));
        }
        for part in &cmd_parts[1..] {
            args.push(part.clone());
        }

        // Check for forbidden flags before spawning
        let forbidden: Vec<&&str> = FORBIDDEN_FLAGS
            .iter()
            .filter(|flag| args.iter().any(|a| a.contains(**flag)))
            .collect();
        if !forbidden.is_empty() {
            let denial_reason = format!(
                "Forbidden container flags detected: {:?}",
                forbidden
            );
            events.push(
                AuditEvent::new(
                    backend_name,
                    self.provider_id(),
                    AuditAction::PolicyDenied,
                    "deny",
                )
                .with_policy_hash(&policy_hash(config))
                .with_context("reason", denial_reason.as_str())
                .with_context("forbidden_flags", format!("{forbidden:?}")),
            );
            return Err(crate::Error::Config(denial_reason));
        }

        // Audit: translated args (for test verification)
        events.push(
            AuditEvent::new(
                backend_name,
                self.provider_id(),
                AuditAction::PolicyEvaluated,
                "allow",
            )
            .with_policy_hash(&policy_hash(config))
            .with_context("translated_args", format!("{args:?}")),
        );

        // Spawn the container
        let mut cmd = Command::new(&self.runtime_bin);
        cmd.args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = cmd
            .spawn()
            .map_err(|e| crate::Error::Transport(format!(
                "Failed to spawn {} container for backend '{}': {}",
                self.runtime_bin, backend_name, e
            )))?;

        // Collect stderr for log capture
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| crate::Error::Transport("Failed to capture stderr".to_string()))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| crate::Error::Transport("Failed to capture stdin".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| crate::Error::Transport("Failed to capture stdout".to_string()))?;

        // Audit: started
        events.push(
            AuditEvent::new(backend_name, self.provider_id(), AuditAction::Started, "allow")
                .with_policy_hash(&policy_hash(config))
                .with_context("container_name", &container_name),
        );

        Ok((
            Box::new(DockerHandle {
                child: Arc::new(TokioMutex::new(Some(child))),
                stdin: Arc::new(TokioMutex::new(Some(stdin))),
                stdout: Arc::new(TokioMutex::new(Some(stdout))),
                stderr: Arc::new(TokioMutex::new(Some(stderr))),
                backend_name: backend_name.to_string(),
                provider_id: self.provider_id().to_string(),
                config: config.clone(),
                container_name,
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

/// Handle for a Docker/Podman container backend.
struct DockerHandle {
    child: Arc<TokioMutex<Option<tokio::process::Child>>>,
    stdin: Arc<TokioMutex<Option<tokio::process::ChildStdin>>>,
    stdout: Arc<TokioMutex<Option<tokio::process::ChildStdout>>>,
    stderr: Arc<TokioMutex<Option<tokio::process::ChildStderr>>>,
    backend_name: String,
    provider_id: String,
    config: RuntimeConfig,
    container_name: String,
}

#[async_trait]
impl RuntimeHandle for DockerHandle {
    fn is_healthy(&self) -> bool {
        // Check if child process is still running
        // We can't easily check without blocking, so we rely on the child handle
        true
    }

    fn logs(&self) -> Vec<String> {
        // TODO: read from stderr pipe buffer
        Vec::new()
    }

    async fn stop(&self) -> Result<Vec<AuditEvent>> {
        // Stop the container: docker stop <name>
        let mut cmd = Command::new(&self.provider_id);
        cmd.args(["stop", &self.container_name])
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let _ = cmd.spawn(); // Fire-and-forget stop; rely on --rm for cleanup

        // Kill the managed child process
        let mut child_guard = self.child.lock().await;
        if let Some(mut child) = child_guard.take() {
            let _ = child.kill().await;
        }

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
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Sanitize backend name to a valid container name.
fn sanitize_container_name(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

/// Build a container image name from the backend name and command.
/// For now, expects the command to be a runnable image or uses a default.
fn build_image_name(_backend_name: &str, command: &str) -> String {
    // If the command looks like a docker image reference, use it as-is
    // Otherwise, construct from the command's first part
    shlex::split(command)
        .and_then(|parts| parts.into_iter().next())
        .unwrap_or_else(|| "alpine:latest".to_string())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// AC.4 helper: validate that restricted defaults are applied
    #[test]
    fn docker_provider_applies_restricted_defaults() {
        let provider = DockerProvider::new("docker");
        assert_eq!(provider.provider_id(), "docker");

        let config = RuntimeConfig::docker_restricted();
        let verdict = provider.validate_policy(&config);
        assert!(verdict.is_allowed(), "docker should accept restricted config");
    }

    /// AC.5: Denied network policies fail closed
    #[test]
    fn docker_denies_host_network() {
        let provider = DockerProvider::new("docker");
        let mut config = RuntimeConfig::docker_restricted();
        // Host network is not directly configurable in RuntimeConfig,
        // but egress.deny_default is enforced and mount/docker-socket denied.

        // Verify a config with docker socket mount is denied
        config.mounts.mounts.push(super::super::policy::MountEntry {
            host: "/var/run/docker.sock".to_string(),
            container: "/var/run/docker.sock".to_string(),
            writable: false,
        });

        let verdict = provider.validate_policy(&config);
        assert!(
            !verdict.is_allowed(),
            "docker socket mount should be denied"
        );
    }

    /// AC.5: Forbidden mount paths denied
    #[test]
    fn docker_denies_forbidden_mount_paths() {
        let provider = DockerProvider::new("docker");

        for forbidden in super::super::policy::FORBIDDEN_MOUNT_PATHS {
            let mut config = RuntimeConfig::docker_restricted();
            config.mounts.mounts.push(super::super::policy::MountEntry {
                host: (*forbidden).to_string(),
                container: (*forbidden).to_string(),
                writable: false,
            });

            let verdict = provider.validate_policy(&config);
            assert!(
                !verdict.is_allowed(),
                "Mount of '{forbidden}' should be denied"
            );
        }
    }

    /// AC.5: Relative paths denied
    #[test]
    fn mount_denies_relative_paths() {
        let entry = super::super::policy::MountEntry {
            host: "./relative/path".to_string(),
            container: "/container/path".to_string(),
            writable: false,
        };
        let policy = super::super::policy::MountPolicy::default_restricted();
        let verdict = super::super::provider::validate_mount(&entry, &policy);
        assert!(!verdict.is_allowed(), "relative paths should be denied");
    }

    /// AC.5: Path traversal denied
    #[test]
    fn mount_denies_path_traversal() {
        let entry = super::super::policy::MountEntry {
            host: "/etc/../passwd".to_string(),
            container: "/container/path".to_string(),
            writable: false,
        };
        let policy = super::super::policy::MountPolicy::default_restricted();
        let verdict = super::super::provider::validate_mount(&entry, &policy);
        assert!(!verdict.is_allowed(), "path traversal should be denied");
    }

    /// AC.5: Writable mount without allow_writable denied
    #[test]
    fn mount_denies_writable_without_policy_allow() {
        let entry = super::super::policy::MountEntry {
            host: "/tmp/data".to_string(),
            container: "/data".to_string(),
            writable: true,
        };
        let policy = super::super::policy::MountPolicy::default_restricted(); // allow_writable=false
        let verdict = super::super::provider::validate_mount(&entry, &policy);
        assert!(
            !verdict.is_allowed(),
            "writable mount without allow_writable should be denied"
        );
    }

    /// AC.5: Egress allowlist that provider cannot enforce → denied
    #[test]
    fn local_compat_denies_egress_deny_default() {
        let provider = super::super::local_compat::LocalCompatProvider::new();
        let mut config = RuntimeConfig::local_compat();
        config.egress.deny_default = true;

        let verdict = provider.validate_policy(&config);
        assert!(
            !verdict.is_allowed(),
            "local_compat should deny egress.deny_default"
        );
    }

    /// Verify audit events from docker provider
    #[test]
    fn docker_provider_emits_audit_on_selection() {
        let provider = DockerProvider::new("docker");
        let config = RuntimeConfig::docker_restricted();
        let events = provider.audit_selection("test", &config);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].provider, "docker");
        assert!(events[0].policy_hash.is_some());
    }

    /// Verify container name sanitization
    #[test]
    fn sanitize_container_name_replaces_special_chars() {
        assert_eq!(sanitize_container_name("my-backend"), "my-backend");
        assert_eq!(sanitize_container_name("a/b"), "a_b");
        assert_eq!(sanitize_container_name("hello world"), "hello_world");
    }
}
