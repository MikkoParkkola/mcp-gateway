// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Running a compiled plan through its lifecycle: apply, health, logs, stop
//! and restart, each refused while the policy denies or awaits confirmation.

use std::collections::BTreeSet;

use super::{
    RuntimeApplyAction, RuntimeApplyAuditEvent, RuntimeApplyError, RuntimeApplyRequest,
    RuntimeApplyResult, RuntimeApplyStatus, RuntimeCommandRunner, RuntimeLaunchCommand,
    RuntimePlan,
};

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

    /// Run the provider restart command after policy and confirmation gates.
    pub fn restart_with<R: RuntimeCommandRunner>(
        &self,
        runner: &mut R,
        request: &RuntimeApplyRequest,
    ) -> Result<RuntimeApplyResult, RuntimeApplyError> {
        self.run_lifecycle_command(
            runner,
            request,
            RuntimeApplyAction::Restart,
            RuntimeApplyStatus::Restarted,
            self.restart_command.as_ref(),
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
