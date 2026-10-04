// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The apply contract: the request, its result and audit record, and the
//! command runner that starts a planned runtime without a shell.

use std::{
    process::{Command, Stdio},
    sync::Arc,
};

use serde::{Deserialize, Serialize};

use super::{RuntimeDenyReason, RuntimeLaunchCommand, RuntimeLaunchMode, RuntimeProviderKind};

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
    /// Restart the runtime.
    Restart,
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
    /// Provider restart command completed.
    Restarted,
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
#[derive(Debug, Clone, Default)]
pub struct StdRuntimeCommandRunner {
    env: Option<Arc<crate::config::LiveEnv>>,
}

impl StdRuntimeCommandRunner {
    /// Resolves allowed keys through the env-file overlay as well as the
    /// process environment.
    ///
    /// Without this a key an env file supplies reaches nothing: env files no
    /// longer write the process environment, so `std::env` alone starts a
    /// sandboxed backend without the credential it was configured with.
    #[must_use]
    pub fn with_env(mut self, env: Arc<crate::config::LiveEnv>) -> Self {
        self.env = Some(env);
        self
    }
}

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
        let overlay = self.env.as_ref().map(|env| env.get());
        for key in env_keys {
            // The process environment is the fall-through inside `resolve`, so
            // the `else` only carries a value no overlay is in force for —
            // which keeps it an `OsString` rather than a lossy conversion.
            if let Some(value) = overlay.as_ref().and_then(|overlay| overlay.resolve(key)) {
                child.env(key, value);
            } else if let Some(item) = std::env::var_os(key) {
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
