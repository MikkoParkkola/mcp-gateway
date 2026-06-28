//! `RuntimeProvider` policy and planning contract for MCP server execution.
//!
//! This module is intentionally compile-only: it chooses providers, compiles
//! least-privilege policy, and emits audit/rollback metadata, but it does not
//! start a process or container. Live backend routing can adopt this contract
//! after provider-specific launchers have integration coverage.

use serde::{Deserialize, Serialize};

mod planner;
pub use planner::RuntimePlanner;

/// Runtime provider family used to execute an MCP server.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeProviderKind {
    /// Existing direct process execution compatibility path.
    LocalProcess,
    /// Docker or Docker-compatible container execution.
    Docker,
    /// Podman container execution.
    Podman,
    /// Linux systemd unit execution.
    Systemd,
    /// macOS launchd service execution.
    Launchd,
    /// Kubernetes workload execution.
    Kubernetes,
}

impl RuntimeProviderKind {
    /// Return the license tier that owns advanced automation for this provider.
    #[must_use]
    pub fn license_tier(self) -> RuntimeLicenseTier {
        match self {
            Self::Kubernetes => RuntimeLicenseTier::Enterprise,
            Self::LocalProcess | Self::Docker | Self::Podman | Self::Systemd | Self::Launchd => {
                RuntimeLicenseTier::FreeCore
            }
        }
    }

    /// Return true when this provider is containerized.
    #[must_use]
    pub fn is_containerized(self) -> bool {
        matches!(self, Self::Docker | Self::Podman | Self::Kubernetes)
    }
}

/// License category for a runtime provider capability.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeLicenseTier {
    /// Free/core developer capability.
    FreeCore,
    /// Enterprise-only fleet capability.
    Enterprise,
}

/// Locally detected runtime availability.
#[allow(clippy::struct_excessive_bools)] // Availability is a flat capability bitmap exposed in docs and tests.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeAvailability {
    /// Existing local process execution is available.
    pub local_process: bool,
    /// Docker CLI/daemon is available.
    pub docker: bool,
    /// Podman CLI/service is available.
    pub podman: bool,
    /// systemd is available.
    pub systemd: bool,
    /// launchd is available.
    pub launchd: bool,
    /// Kubernetes target is configured.
    pub kubernetes: bool,
}

impl Default for RuntimeAvailability {
    fn default() -> Self {
        Self {
            local_process: true,
            docker: false,
            podman: false,
            systemd: false,
            launchd: false,
            kubernetes: false,
        }
    }
}

impl RuntimeAvailability {
    /// Return a local-only availability fixture.
    #[must_use]
    pub fn local_only() -> Self {
        Self::default()
    }

    /// Return availability with Docker enabled.
    #[must_use]
    pub fn with_docker() -> Self {
        Self {
            docker: true,
            ..Self::default()
        }
    }

    /// Return whether a provider is available.
    #[must_use]
    pub fn supports(&self, provider: RuntimeProviderKind) -> bool {
        match provider {
            RuntimeProviderKind::LocalProcess => self.local_process,
            RuntimeProviderKind::Docker => self.docker,
            RuntimeProviderKind::Podman => self.podman,
            RuntimeProviderKind::Systemd => self.systemd,
            RuntimeProviderKind::Launchd => self.launchd,
            RuntimeProviderKind::Kubernetes => self.kubernetes,
        }
    }
}

/// Coarse data sensitivity used for runtime planning.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeDataClass {
    /// Public or demonstration data.
    Public,
    /// Internal workspace data.
    #[default]
    Internal,
    /// Personal, customer, or regulated data.
    Sensitive,
    /// Host filesystem, browser, shell, or elevated system access.
    HighPrivilege,
}

/// MCP server execution intent before provider policy compilation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeIntent {
    /// Stable server name used in config, audit, and logs.
    pub server_name: String,
    /// Executable basename or declared package name. Arguments are excluded.
    #[serde(default)]
    pub executable: Option<String>,
    /// Container image reference when containerized execution is possible.
    #[serde(default)]
    pub image: Option<String>,
    /// Data class the server can access.
    #[serde(default)]
    pub data_class: RuntimeDataClass,
    /// Optional operator-selected provider.
    #[serde(default)]
    pub preferred_provider: Option<RuntimeProviderKind>,
    /// Requested network egress policy.
    #[serde(default)]
    pub requested_egress: RuntimeNetworkEgress,
    /// Requested host mounts.
    #[serde(default)]
    pub requested_mounts: Vec<RuntimeMount>,
    /// Environment variable names that may be passed to the runtime.
    #[serde(default)]
    pub env_keys: Vec<String>,
    /// Environment variable names that need owner approval before use.
    #[serde(default)]
    pub guarded_env_keys: Vec<String>,
    /// Whether the intent asks for privileged execution.
    #[serde(default)]
    pub privileged: bool,
}

impl RuntimeIntent {
    /// Build a minimal intent for a named server.
    #[must_use]
    pub fn named(server_name: impl Into<String>) -> Self {
        Self {
            server_name: server_name.into(),
            executable: None,
            image: None,
            data_class: RuntimeDataClass::Internal,
            preferred_provider: None,
            requested_egress: RuntimeNetworkEgress::None,
            requested_mounts: Vec::new(),
            env_keys: Vec::new(),
            guarded_env_keys: Vec::new(),
            privileged: false,
        }
    }
}

/// Runtime filesystem mount policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeMount {
    /// Host path.
    pub source: String,
    /// Runtime path.
    pub target: String,
    /// Mount access mode.
    pub mode: RuntimeMountMode,
}

/// Runtime mount access mode.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMountMode {
    /// Read-only host bind mount.
    ReadOnly,
    /// Copy-on-write overlay mount.
    WritableOverlay,
}

/// Network egress policy for a runtime.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeNetworkEgress {
    /// Deny all network egress.
    None,
    /// Permit loopback only.
    #[default]
    Loopback,
    /// Permit only listed hosts, CIDRs, or service names.
    Allowlist(Vec<String>),
    /// Permit unrestricted outbound network access.
    Full,
}

/// Runtime resource limits.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeResourcePolicy {
    /// CPU cores, rounded to milli-core granularity by providers.
    pub cpu_cores: u32,
    /// Memory limit in MiB.
    pub memory_mb: u64,
    /// Wall-clock timeout in seconds.
    pub timeout_secs: u64,
}

impl Default for RuntimeResourcePolicy {
    fn default() -> Self {
        Self {
            cpu_cores: 1,
            memory_mb: 512,
            timeout_secs: 60,
        }
    }
}

/// Environment policy. Values are intentionally not represented.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RuntimeEnvironmentPolicy {
    /// Names allowed to be passed to the runtime.
    #[serde(default)]
    pub allowed_keys: Vec<String>,
    /// Names that require owner approval before use.
    #[serde(default)]
    pub guarded_keys: Vec<String>,
}

/// Restart policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeRestartPolicy {
    /// Maximum restart attempts.
    pub max_restarts: u32,
    /// Backoff between restarts in seconds.
    pub backoff_secs: u64,
}

impl Default for RuntimeRestartPolicy {
    fn default() -> Self {
        Self {
            max_restarts: 2,
            backoff_secs: 5,
        }
    }
}

/// Canonical runtime policy consumed by every provider.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimePolicy {
    /// Stable policy identifier for audit correlation.
    pub id: String,
    /// Filesystem mounts.
    #[serde(default)]
    pub mounts: Vec<RuntimeMount>,
    /// Network egress policy.
    #[serde(default)]
    pub network_egress: RuntimeNetworkEgress,
    /// Resource limits.
    #[serde(default)]
    pub resources: RuntimeResourcePolicy,
    /// Environment variable policy.
    #[serde(default)]
    pub env: RuntimeEnvironmentPolicy,
    /// Restart behavior.
    #[serde(default)]
    pub restart: RuntimeRestartPolicy,
    /// Whether privileged execution is requested.
    #[serde(default)]
    pub privileged: bool,
}

/// Human confirmation required before applying a plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeConfirmation {
    /// Stable confirmation id.
    pub id: String,
    /// Human-readable reason.
    pub reason: String,
    /// Risk class.
    pub risk: RuntimeConfirmationRisk,
}

/// Confirmation severity.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeConfirmationRisk {
    /// Low-risk confirmation.
    Low,
    /// Medium-risk confirmation.
    Medium,
    /// High-risk confirmation.
    High,
}

/// Preflight check emitted by a plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimePreflightCheck {
    /// Stable check name.
    pub name: String,
    /// Whether the check must pass before apply.
    pub required: bool,
    /// Human-readable check command or instruction.
    pub check: String,
}

/// Fail-closed denial reason.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeDenial {
    /// Stable reason code.
    pub reason: RuntimeDenyReason,
    /// Human-readable detail.
    pub detail: String,
}

/// Stable denial reason code.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeDenyReason {
    /// Requested provider is not available.
    RuntimeUnavailable,
    /// Container provider lacks an image reference.
    MissingContainerImage,
    /// Resource limits are invalid.
    InvalidResourcePolicy,
    /// Host root or another hard-blocked mount was requested.
    ForbiddenMount,
}

/// Runtime audit event emitted with every plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeAuditEvent {
    /// Server name.
    pub server_name: String,
    /// Selected provider.
    pub provider: RuntimeProviderKind,
    /// Policy identifier.
    pub policy_id: String,
    /// License tier for the selected provider.
    pub license_tier: RuntimeLicenseTier,
    /// Confirmation ids required before apply.
    pub confirmation_ids: Vec<String>,
    /// Denial reason codes.
    pub denied_reasons: Vec<RuntimeDenyReason>,
    /// Guarded environment variable names only.
    pub guarded_env_keys: Vec<String>,
}

/// Provider recommendation explanation for operators and UI consumers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeRecommendation {
    /// Why this provider was selected.
    pub reason: String,
    /// Main security tradeoff of the selected provider.
    pub security_tradeoff: String,
    /// Selection path.
    pub selected_by: RuntimeProviderSelection,
}

impl Default for RuntimeRecommendation {
    fn default() -> Self {
        Self {
            reason: "provider selection has not been evaluated".to_string(),
            security_tradeoff: "unknown".to_string(),
            selected_by: RuntimeProviderSelection::CompatibilityFallback,
        }
    }
}

/// How a runtime provider was selected.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeProviderSelection {
    /// The operator explicitly selected this provider and it is available.
    OperatorPreference,
    /// The planner selected stronger isolation for the requested risk posture.
    IsolationPreferred,
    /// The planner preserved existing direct-launch compatibility.
    CompatibilityFallback,
}

/// Compile-only lifecycle hints for a runtime plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeLifecyclePlan {
    /// Start command hint. This is not executed by this slice.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_command_hint: Option<String>,
    /// Health check instruction or command.
    pub health_check: String,
    /// Log inspection hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logs_hint: Option<String>,
    /// Stop command hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_command_hint: Option<String>,
    /// Rollback instruction.
    pub rollback_step: String,
}

impl Default for RuntimeLifecyclePlan {
    fn default() -> Self {
        Self {
            start_command_hint: None,
            health_check: "provider-specific health check unavailable".to_string(),
            logs_hint: None,
            stop_command_hint: None,
            rollback_step: "Restore the previous gateway config.".to_string(),
        }
    }
}

/// Compile-only runtime launch plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimePlan {
    /// Server name.
    pub server_name: String,
    /// Selected provider.
    pub provider: RuntimeProviderKind,
    /// Compiled policy.
    pub policy: RuntimePolicy,
    /// Provider preflight checks.
    pub preflight_checks: Vec<RuntimePreflightCheck>,
    /// Human confirmations required before apply.
    pub confirmations: Vec<RuntimeConfirmation>,
    /// Fail-closed denial reasons.
    pub denied: Vec<RuntimeDenial>,
    /// Audit event for control planes and logs.
    pub audit: RuntimeAuditEvent,
    /// Provider recommendation explanation.
    #[serde(default)]
    pub recommendation: RuntimeRecommendation,
    /// Compile-only lifecycle hints for start, health, logs, stop, and rollback.
    #[serde(default)]
    pub lifecycle: RuntimeLifecyclePlan,
    /// Apply command hint. None means this slice is observe-only.
    #[serde(default)]
    pub apply_command: Option<String>,
    /// Rollback instruction.
    pub rollback_step: String,
}

impl RuntimePlan {
    /// Return true when policy denies execution.
    #[must_use]
    pub fn is_denied(&self) -> bool {
        !self.denied.is_empty()
    }

    /// Return true when apply must pause for human confirmation.
    #[must_use]
    pub fn requires_confirmation(&self) -> bool {
        !self.confirmations.is_empty()
    }
}

/// Runtime provider contract. Providers compile plans through the same policy interface.
pub trait RuntimeProvider {
    /// Provider kind.
    fn kind(&self) -> RuntimeProviderKind;

    /// Compile a launch plan without starting the runtime.
    fn compile_plan(
        &self,
        intent: &RuntimeIntent,
        policy: RuntimePolicy,
        availability: &RuntimeAvailability,
    ) -> RuntimePlan {
        planner::compile_provider_plan(self.kind(), intent, policy, availability)
    }
}

/// Existing local process compatibility provider.
#[derive(Debug, Clone, Copy, Default)]
pub struct LocalProcessProvider;

impl RuntimeProvider for LocalProcessProvider {
    fn kind(&self) -> RuntimeProviderKind {
        RuntimeProviderKind::LocalProcess
    }
}

/// Container runtime provider.
#[derive(Debug, Clone, Copy)]
pub struct ContainerProvider {
    kind: RuntimeProviderKind,
}

impl ContainerProvider {
    /// Build a Docker provider.
    #[must_use]
    pub fn docker() -> Self {
        Self {
            kind: RuntimeProviderKind::Docker,
        }
    }

    /// Build a Podman provider.
    #[must_use]
    pub fn podman() -> Self {
        Self {
            kind: RuntimeProviderKind::Podman,
        }
    }
}

impl RuntimeProvider for ContainerProvider {
    fn kind(&self) -> RuntimeProviderKind {
        self.kind
    }
}

#[cfg(test)]
#[path = "provider_tests.rs"]
mod tests;
