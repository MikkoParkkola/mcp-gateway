// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Runtime launch planning for a backend (split from `lifecycle.rs`).

use std::collections::HashMap;

use tracing::info;

use super::Backend;
use crate::config::{BackendConfig, RuntimeConfig, TransportConfig};

use crate::runtime::{RuntimeLaunchCommand, RuntimeLaunchMode, RuntimePlan, RuntimeProviderKind};

use crate::{Error, Result};

/// Compile the runtime profile selected by a backend into a live-start plan.
#[must_use]
pub fn runtime_plan_for_backend(
    name: &str,
    config: &BackendConfig,
    runtime_config: &RuntimeConfig,
) -> Option<RuntimePlan> {
    let profile_name = config.runtime_profile.as_deref()?;
    let executable_hint = stdio_executable_hint(&config.transport);
    runtime_config.plan_backend_profile(profile_name, name, executable_hint.as_deref())
}

pub(super) fn stdio_executable_hint(transport: &TransportConfig) -> Option<String> {
    let TransportConfig::Stdio { command, .. } = transport else {
        return None;
    };
    crate::transport::split_command(command)?.into_iter().next()
}

pub(super) struct ResolvedStdioLaunch {
    pub(super) command: String,
    pub(super) env: HashMap<String, String>,
}

pub(super) fn container_stdio_bridge_command(plan: &RuntimePlan) -> Result<String> {
    let command = plan.launch_command.as_ref().ok_or_else(|| {
        Error::Config(format!(
            "runtime provider {:?} has no structured launch command for stdio bridge",
            plan.provider
        ))
    })?;
    if command.args.first().map(String::as_str) != Some("run") {
        return Err(Error::Config(format!(
            "runtime provider {:?} launch command is not a container run command",
            plan.provider
        )));
    }

    let mut args = vec![
        "run".to_string(),
        "--interactive".to_string(),
        "--rm".to_string(),
    ];
    let mut skip_restart_value = false;
    for arg in command.args.iter().skip(1) {
        if skip_restart_value {
            skip_restart_value = false;
            continue;
        }
        match arg.as_str() {
            "--detach" | "-d" | "--interactive" | "-i" | "--rm" => {}
            "--restart" => skip_restart_value = true,
            value if value.starts_with("--restart=") => {}
            _ => args.push(arg.clone()),
        }
    }

    Ok(RuntimeLaunchCommand {
        program: command.program.clone(),
        args,
        mode: RuntimeLaunchMode::RunToCompletion,
    }
    .display_command())
}

pub(super) fn filter_runtime_env(
    env: &HashMap<String, String>,
    allowed_keys: &[String],
) -> HashMap<String, String> {
    allowed_keys
        .iter()
        .filter_map(|key| env.get(key).map(|value| (key.clone(), value.clone())))
        .collect()
}

impl Backend {
    pub(super) fn resolve_stdio_runtime_launch(
        &self,
        configured_command: &str,
    ) -> Result<ResolvedStdioLaunch> {
        let Some(plan) = self.runtime_plan.as_ref() else {
            return Ok(ResolvedStdioLaunch {
                command: configured_command.to_string(),
                env: self.config.env.clone(),
            });
        };
        self.enforce_stdio_runtime_plan(plan)?;

        match plan.provider {
            RuntimeProviderKind::LocalProcess => {
                info!(
                    backend = %self.name,
                    provider = ?plan.provider,
                    policy_id = %plan.policy.id,
                    "RuntimeProvider profile accepted before stdio backend start"
                );
                Ok(ResolvedStdioLaunch {
                    command: configured_command.to_string(),
                    env: self.config.env.clone(),
                })
            }
            RuntimeProviderKind::Docker | RuntimeProviderKind::Podman => {
                let command = container_stdio_bridge_command(plan)?;
                info!(
                    backend = %self.name,
                    provider = ?plan.provider,
                    policy_id = %plan.policy.id,
                    "RuntimeProvider container stdio bridge accepted before backend start"
                );
                Ok(ResolvedStdioLaunch {
                    command,
                    env: filter_runtime_env(&self.config.env, &plan.policy.env.allowed_keys),
                })
            }
            RuntimeProviderKind::Systemd
            | RuntimeProviderKind::Launchd
            | RuntimeProviderKind::Kubernetes => Err(Error::Config(format!(
                "backend '{}' runtime profile selected {:?}, but live stdio backend lifecycle currently supports local_process plus docker/podman stdio bridge",
                self.name, plan.provider
            ))),
        }
    }

    pub(super) fn enforce_stdio_runtime_plan(&self, plan: &RuntimePlan) -> Result<()> {
        if plan.is_denied() {
            let reasons = plan
                .denied
                .iter()
                .map(|denial| format!("{:?}", denial.reason))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(Error::Config(format!(
                "backend '{}' runtime profile '{}' denied by policy: {reasons}",
                self.name, plan.policy.id
            )));
        }
        if plan.requires_confirmation() {
            let confirmations = plan
                .confirmations
                .iter()
                .map(|confirmation| confirmation.id.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(Error::Config(format!(
                "backend '{}' runtime profile '{}' requires confirmations before live start: {confirmations}",
                self.name, plan.policy.id
            )));
        }
        Ok(())
    }
}
