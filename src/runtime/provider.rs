//! RuntimeProvider trait — canonical abstraction for backend MCP server
//! execution.
//!
//! Every production MCP server lifecycle (start, stop, health, logs) and
//! isolation primitive (resource limits, mounts, egress, env, secrets) flows
//! through this trait.  Providers are selected by
//! [`RuntimeConfig::provider`](super::policy::RuntimeConfig::provider) and
//! instantiated by the backend lifecycle in
//! [`Backend::start`](crate::backend::Backend::start).
//!
//! # Relationship to `runtime-substrate`
//!
//! This trait governs **live MCP server execution** — spawning, monitoring,
//! and stopping backend processes.  It is distinct from the **descriptor
//! compilation** layer behind the `runtime-substrate` feature flag
//! ([`crate::runtime::compiler`]), which translates a
//! [`SandboxDescriptor`](crate::runtime::SandboxDescriptor) into an OCI bundle
//! or Apple VM-spec but never launches or manages a running process.  The
//! compiler answers "what should the sandbox look like?"; the
//! `RuntimeProvider` answers "run this MCP server now."

use async_trait::async_trait;
use std::collections::HashMap;

use super::audit::AuditEvent;
use super::policy::RuntimeConfig;
use crate::Result;

/// Outcome of a policy evaluation before launch.
#[derive(Debug, Clone)]
pub enum PolicyVerdict {
    /// Policy is compatible — proceed.
    Allow,
    /// Policy violates a rule — deny with a human-readable reason.
    Deny(String),
}

impl PolicyVerdict {
    /// Return `true` for `Allow`.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Return the denial reason if denied.
    #[must_use]
    pub fn denial_reason(&self) -> Option<&str> {
        match self {
            Self::Deny(reason) => Some(reason),
            _ => None,
        }
    }
}

/// RuntimeProvider — the canonical abstraction for backend MCP server
/// execution.
///
/// Covers: start, stop, health/readiness, logs, resource policy, secrets/env
/// materialization, mounts, network policy, and audit evidence.
#[async_trait]
pub trait RuntimeProvider: Send + Sync {
    /// Provider identifier (e.g. `"local_compat"`, `"docker"`, `"podman"`).
    fn provider_id(&self) -> &str;

    /// Validate the runtime policy BEFORE spawning anything.  Returns
    /// `PolicyVerdict::Deny(reason)` for any policy the provider cannot
    /// enforce.  Callers MUST abort the launch on `Deny`.
    fn validate_policy(&self, config: &RuntimeConfig) -> PolicyVerdict;

    /// Start the backend process/container.
    ///
    /// Receives the backend name, command to execute, environment variables,
    /// working directory, protocol version hint, and the full runtime config.
    ///
    /// Returns audit events for the start transition (provider MUST emit at
    /// least one [`AuditEvent`]).
    async fn start(
        &self,
        backend_name: &str,
        command: &str,
        env: HashMap<String, String>,
        cwd: Option<String>,
        protocol_version: Option<String>,
        request_timeout: std::time::Duration,
        config: &RuntimeConfig,
    ) -> Result<(Box<dyn RuntimeHandle>, Vec<AuditEvent>)>;

    /// Emit audit events for provider selection.
    fn audit_selection(&self, backend_name: &str, config: &RuntimeConfig) -> Vec<AuditEvent>;
}

/// Handle to a running backend — provides health, logs, and graceful stop.
#[async_trait]
pub trait RuntimeHandle: Send + Sync {
    /// Check if the backend is healthy/running.
    fn is_healthy(&self) -> bool;

    /// Retrieve captured log lines (stdout/stderr).
    fn logs(&self) -> Vec<String>;

    /// Stop the backend gracefully, returning audit events.
    async fn stop(&self) -> Result<Vec<AuditEvent>>;

    /// Get the underlying transport if this handle wraps a transport.
    /// Returns `None` for container-based providers (docker/podman) where
    /// the transport is an internal implementation detail.
    fn as_transport(&self) -> Option<std::sync::Arc<dyn crate::transport::Transport>> {
        None
    }
}

/// Builder/factory for creating [`RuntimeProvider`] instances from config.
pub fn create_provider(config: &RuntimeConfig) -> Result<Box<dyn RuntimeProvider>> {
    match config.provider.as_str() {
        "local_compat" => Ok(Box::new(super::local_compat::LocalCompatProvider::new())),
        "docker" => Ok(Box::new(super::docker::DockerProvider::new("docker"))),
        "podman" => Ok(Box::new(super::docker::DockerProvider::new("podman"))),
        other => Err(crate::Error::Config(format!(
            "Unknown runtime provider: '{other}'. Supported: local_compat, docker, podman"
        ))),
    }
}

/// Validate a mount entry and return a denial reason if it violates policy.
///
/// Checks for:
/// - Forbidden host paths (`/`, `/etc`, `/proc`, `/sys`, `/dev`, `/var/run`)
/// - Docker socket mounts
/// - Relative paths
/// - Path traversal attempts
/// - Writable mounts without explicit `writable=true`
pub fn validate_mount(
    entry: &super::policy::MountEntry,
    policy: &super::policy::MountPolicy,
) -> PolicyVerdict {
    // Check for relative paths
    if entry.host.starts_with("./") || entry.host.starts_with("../") || !entry.host.starts_with('/')
    {
        return PolicyVerdict::Deny(format!(
            "Mount host path must be absolute: '{}'",
            entry.host
        ));
    }

    // Check for path traversal
    if entry.host.contains("/../") || entry.host.ends_with("/..") {
        return PolicyVerdict::Deny(format!(
            "Mount host path contains path traversal: '{}'",
            entry.host
        ));
    }
    if entry.container.contains("/../") || entry.container.ends_with("/..") {
        return PolicyVerdict::Deny(format!(
            "Mount container path contains path traversal: '{}'",
            entry.container
        ));
    }

    // Check for forbidden host paths (exact match or prefix with trailing slash)
    for forbidden in super::policy::FORBIDDEN_MOUNT_PATHS {
        if entry.host == *forbidden
            || entry.host.starts_with(&format!("{forbidden}/"))
        {
            return PolicyVerdict::Deny(format!(
                "Mount host path '{forbidden}' is forbidden",
                forbidden = forbidden
            ));
        }
    }

    // Check for Docker socket mounts
    for sock in super::policy::FORBIDDEN_DOCKER_SOCKET_PATHS {
        if entry.host == *sock {
            return PolicyVerdict::Deny(format!(
                "Docker socket mount '{sock}' is forbidden for security reasons"
            ));
        }
    }

    // Check writable mounts require explicit writable=true
    if entry.writable && !policy.allow_writable {
        return PolicyVerdict::Deny(format!(
            "Mount '{}' requests writable access but allow_writable is false",
            entry.host
        ));
    }

    PolicyVerdict::Allow
}

/// Validate egress policy and return denial if provider cannot enforce it.
pub fn validate_egress(
    policy: &super::policy::EgressPolicy,
    provider_id: &str,
) -> PolicyVerdict {
    // local_compat cannot enforce egress restrictions
    if policy.deny_default && provider_id == "local_compat" {
        return PolicyVerdict::Deny(
            "Egress deny_default is not supported by local_compat provider. \
             Use docker or podman for network isolation."
                .to_string(),
        );
    }

    PolicyVerdict::Allow
}
