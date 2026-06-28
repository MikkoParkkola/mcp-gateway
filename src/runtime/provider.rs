//! `RuntimeProvider` policy, planning, and apply contract for MCP server execution.
//!
//! The planner compiles least-privilege policy first. Apply/start paths consume
//! structured launch commands instead of shell strings, so providers can start
//! runtimes while preserving fail-closed policy checks and value-free audit
//! records.

use std::{
    collections::BTreeSet,
    process::{Command, Stdio},
};

use crate::hashing::sha256_hex;
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

/// Lifecycle hints for a runtime plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeLifecyclePlan {
    /// Start command hint. Apply uses the structured launch command instead.
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

/// How a launch command is executed.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeLaunchMode {
    /// Spawn a long-running local child process.
    SpawnProcess,
    /// Run a short-lived launcher command and require a zero exit status.
    RunToCompletion,
}

/// Structured provider launch command. Arguments are never run through a shell.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeLaunchCommand {
    /// Executable to invoke.
    pub program: String,
    /// Argument vector.
    #[serde(default)]
    pub args: Vec<String>,
    /// Execution mode.
    pub mode: RuntimeLaunchMode,
}

impl RuntimeLaunchCommand {
    /// Human-readable command display for docs, UI, and review. Not shell input.
    #[must_use]
    pub fn display_command(&self) -> String {
        std::iter::once(self.program.as_str())
            .chain(self.args.iter().map(String::as_str))
            .map(shell_quote)
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Digest the argument vector for audit without storing raw arguments.
    #[must_use]
    pub fn args_digest_sha256(&self) -> String {
        let joined = self.args.join("\0");
        sha256_hex(joined.as_bytes())
    }
}

/// Apply request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeApplyRequest {
    /// Confirmation ids explicitly approved for this apply.
    pub approved_confirmations: Vec<String>,
}

impl RuntimeApplyRequest {
    /// Empty apply request.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }
}

/// Runtime apply action.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeApplyAction {
    /// Start the runtime.
    Start,
    /// Stop the runtime.
    Stop,
    /// Check runtime health.
    Health,
    /// Collect runtime logs.
    Logs,
}

/// Runtime apply status.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeApplyStatus {
    /// Provider start command was accepted.
    Started,
    /// Provider stop command completed.
    Stopped,
    /// Provider health command completed.
    Healthy,
    /// Provider log command completed.
    LogsCollected,
}

/// Runtime apply audit event. Environment values are intentionally excluded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeApplyAuditEvent {
    /// Server name.
    pub server_name: String,
    /// Selected provider.
    pub provider: RuntimeProviderKind,
    /// Policy identifier.
    pub policy_id: String,
    /// Action performed.
    pub action: RuntimeApplyAction,
    /// Result status.
    pub status: RuntimeApplyStatus,
    /// Program invoked.
    pub command_program: String,
    /// SHA-256 digest of the argument vector.
    pub command_args_sha256: String,
    /// Environment variable names passed to the runtime.
    pub env_keys: Vec<String>,
    /// Confirmation ids approved for this apply.
    pub approved_confirmation_ids: Vec<String>,
}

/// Runtime command runner outcome.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeCommandOutcome {
    /// Provider-specific runtime id such as process pid or container id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    /// Process exit status when the launcher exits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Launcher stdout, truncated by the runner if needed.
    #[serde(default)]
    pub stdout: String,
    /// Launcher stderr, truncated by the runner if needed.
    #[serde(default)]
    pub stderr: String,
}

/// Runtime apply result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeApplyResult {
    /// Provider launch command that was executed.
    pub command: RuntimeLaunchCommand,
    /// Command runner outcome.
    pub outcome: RuntimeCommandOutcome,
    /// Audit event safe for logs and control planes.
    pub audit: RuntimeApplyAuditEvent,
}

/// Error returned while applying a runtime plan.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeApplyError {
    /// Plan is denied by policy and must not start.
    #[error("runtime plan is denied by policy: {0:?}")]
    Denied(Vec<RuntimeDenyReason>),
    /// Plan needs human confirmations before apply.
    #[error("runtime plan requires confirmations before apply: {0:?}")]
    ConfirmationRequired(Vec<String>),
    /// Provider has no structured launch command.
    #[error("runtime provider {0:?} has no structured launch command")]
    MissingLaunchCommand(RuntimeProviderKind),
    /// Command launcher failed before a provider response was available.
    #[error("failed to start runtime command '{program}': {source}")]
    Io {
        /// Program invoked.
        program: String,
        /// I/O failure.
        #[source]
        source: std::io::Error,
    },
    /// Launcher exited unsuccessfully.
    #[error("runtime command '{program}' exited with status {exit_code:?}: {stderr}")]
    CommandFailed {
        /// Program invoked.
        program: String,
        /// Exit status code when available.
        exit_code: Option<i32>,
        /// Truncated stderr.
        stderr: String,
    },
}

/// Injectable command runner used by `RuntimeProvider` apply/start paths.
pub trait RuntimeCommandRunner {
    /// Execute a provider command.
    fn run(
        &mut self,
        command: &RuntimeLaunchCommand,
        env_keys: &[String],
    ) -> Result<RuntimeCommandOutcome, RuntimeApplyError>;
}

/// Default runtime command runner backed by `std::process::Command`.
#[derive(Debug, Clone, Copy, Default)]
pub struct StdRuntimeCommandRunner;

impl RuntimeCommandRunner for StdRuntimeCommandRunner {
    fn run(
        &mut self,
        command: &RuntimeLaunchCommand,
        env_keys: &[String],
    ) -> Result<RuntimeCommandOutcome, RuntimeApplyError> {
        let mut child = Command::new(&command.program);
        child.args(&command.args).env_clear();
        if let Some(path) = std::env::var_os("PATH") {
            child.env("PATH", path);
        }
        for key in env_keys {
            if let Some(item) = std::env::var_os(key) {
                child.env(key, item);
            }
        }

        match command.mode {
            RuntimeLaunchMode::SpawnProcess => {
                let process = child
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .map_err(|source| RuntimeApplyError::Io {
                        program: command.program.clone(),
                        source,
                    })?;
                Ok(RuntimeCommandOutcome {
                    external_id: Some(process.id().to_string()),
                    exit_code: None,
                    stdout: String::new(),
                    stderr: String::new(),
                })
            }
            RuntimeLaunchMode::RunToCompletion => {
                let output = child.output().map_err(|source| RuntimeApplyError::Io {
                    program: command.program.clone(),
                    source,
                })?;
                let stdout = truncate_process_text(String::from_utf8_lossy(&output.stdout));
                let stderr = truncate_process_text(String::from_utf8_lossy(&output.stderr));
                if !output.status.success() {
                    return Err(RuntimeApplyError::CommandFailed {
                        program: command.program.clone(),
                        exit_code: output.status.code(),
                        stderr,
                    });
                }
                Ok(RuntimeCommandOutcome {
                    external_id: first_nonempty_line(&stdout),
                    exit_code: output.status.code(),
                    stdout,
                    stderr,
                })
            }
        }
    }
}

/// Runtime launch plan.
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
    /// Lifecycle hints for start, health, logs, stop, and rollback.
    #[serde(default)]
    pub lifecycle: RuntimeLifecyclePlan,
    /// Structured launch command used by apply/start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch_command: Option<RuntimeLaunchCommand>,
    /// Structured health command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_command: Option<RuntimeLaunchCommand>,
    /// Structured logs command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logs_command: Option<RuntimeLaunchCommand>,
    /// Structured stop command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_command: Option<RuntimeLaunchCommand>,
    /// Apply command display string. This is review output, not shell input.
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

    /// Apply the plan with a command runner after policy and confirmation gates.
    pub fn apply_with<R: RuntimeCommandRunner>(
        &self,
        runner: &mut R,
        request: &RuntimeApplyRequest,
    ) -> Result<RuntimeApplyResult, RuntimeApplyError> {
        self.run_lifecycle_command(
            runner,
            request,
            RuntimeApplyAction::Start,
            RuntimeApplyStatus::Started,
            self.launch_command.as_ref(),
            true,
        )
    }

    /// Run the provider health check command after policy and confirmation gates.
    pub fn health_with<R: RuntimeCommandRunner>(
        &self,
        runner: &mut R,
        request: &RuntimeApplyRequest,
    ) -> Result<RuntimeApplyResult, RuntimeApplyError> {
        self.run_lifecycle_command(
            runner,
            request,
            RuntimeApplyAction::Health,
            RuntimeApplyStatus::Healthy,
            self.health_command.as_ref(),
            false,
        )
    }

    /// Run the provider logs command after policy and confirmation gates.
    pub fn logs_with<R: RuntimeCommandRunner>(
        &self,
        runner: &mut R,
        request: &RuntimeApplyRequest,
    ) -> Result<RuntimeApplyResult, RuntimeApplyError> {
        self.run_lifecycle_command(
            runner,
            request,
            RuntimeApplyAction::Logs,
            RuntimeApplyStatus::LogsCollected,
            self.logs_command.as_ref(),
            false,
        )
    }

    /// Run the provider stop command after policy and confirmation gates.
    pub fn stop_with<R: RuntimeCommandRunner>(
        &self,
        runner: &mut R,
        request: &RuntimeApplyRequest,
    ) -> Result<RuntimeApplyResult, RuntimeApplyError> {
        self.run_lifecycle_command(
            runner,
            request,
            RuntimeApplyAction::Stop,
            RuntimeApplyStatus::Stopped,
            self.stop_command.as_ref(),
            false,
        )
    }

    fn run_lifecycle_command<R: RuntimeCommandRunner>(
        &self,
        runner: &mut R,
        request: &RuntimeApplyRequest,
        action: RuntimeApplyAction,
        status: RuntimeApplyStatus,
        command: Option<&RuntimeLaunchCommand>,
        include_env: bool,
    ) -> Result<RuntimeApplyResult, RuntimeApplyError> {
        if self.is_denied() {
            return Err(RuntimeApplyError::Denied(
                self.denied.iter().map(|denial| denial.reason).collect(),
            ));
        }

        let approved = request
            .approved_confirmations
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let missing_confirmations = self
            .confirmations
            .iter()
            .filter(|confirmation| !approved.contains(confirmation.id.as_str()))
            .map(|confirmation| confirmation.id.clone())
            .collect::<Vec<_>>();
        if !missing_confirmations.is_empty() {
            return Err(RuntimeApplyError::ConfirmationRequired(
                missing_confirmations,
            ));
        }

        let command = command.ok_or(RuntimeApplyError::MissingLaunchCommand(self.provider))?;
        let env_keys = if include_env {
            self.policy.env.allowed_keys.clone()
        } else {
            Vec::new()
        };
        let outcome = runner.run(command, &env_keys)?;

        Ok(RuntimeApplyResult {
            command: command.clone(),
            outcome,
            audit: RuntimeApplyAuditEvent {
                server_name: self.server_name.clone(),
                provider: self.provider,
                policy_id: self.policy.id.clone(),
                action,
                status,
                command_program: command.program.clone(),
                command_args_sha256: command.args_digest_sha256(),
                env_keys,
                approved_confirmation_ids: request.approved_confirmations.clone(),
            },
        })
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

fn truncate_process_text(text: std::borrow::Cow<'_, str>) -> String {
    const LIMIT: usize = 4096;
    let mut output = text.into_owned();
    if output.len() > LIMIT {
        output.truncate(LIMIT);
        output.push_str("...[truncated]");
    }
    output
}

fn first_nonempty_line(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(ToString::to_string)
}

fn shell_quote(arg: &str) -> String {
    if !arg.is_empty()
        && arg
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '/' | ':' | '='))
    {
        return arg.to_string();
    }

    let escaped = arg.replace('\'', "'\\''");
    format!("'{escaped}'")
}

#[cfg(test)]
#[path = "provider_tests.rs"]
mod tests;
