// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Execution gate and dispatch for capabilities that run a local process
//! (`service: cli` and `service: mcp`, MIK-7782).
//!
//! Every call passes [`admit`] before anything is resolved or spawned. The gate
//! fails closed: a definition that did not come from a file with a matching pin,
//! a command the operator did not list, or a disabled switch is refused.

use serde_json::Value;

use crate::capability::definition::{Integrity, ProcessConfig};
use crate::capability::{CapabilityDefinition, CapabilityExecutionContext};
use crate::config::{FileRoots, ProcessCommand, ProcessExecution};
use crate::{Error, Result};

use super::CapabilityExecutor;

/// What process-running capabilities may do on this gateway.
#[derive(Debug, Clone)]
pub(crate) struct ProcessPolicy {
    pub(crate) execution: ProcessExecution,
    pub(crate) commands: Vec<ProcessCommand>,
    pub(crate) files: FileRoots,
}

impl Default for ProcessPolicy {
    fn default() -> Self {
        Self {
            execution: ProcessExecution::Enabled,
            commands: ProcessCommand::shipped(),
            files: FileRoots::default(),
        }
    }
}

impl ProcessPolicy {
    /// The policy `capabilities:` configures.
    pub(crate) fn from_config(config: &crate::config::CapabilityConfig) -> Self {
        Self {
            execution: config.process_execution,
            commands: config
                .process_commands
                .clone()
                .unwrap_or_else(ProcessCommand::shipped),
            files: config.files.clone(),
        }
    }
}

/// Refuse unless this definition may run its process here.
pub(crate) fn admit(
    policy: &ProcessPolicy,
    capability: &CapabilityDefinition,
    process: &ProcessConfig,
) -> Result<()> {
    let name = &capability.name;
    if policy.execution == ProcessExecution::Disabled {
        return Err(Error::Config(format!(
            "capability '{name}' runs a local process, and capabilities.process_execution \
             is disabled"
        )));
    }
    if capability.providers.integrity != Integrity::Verified {
        return Err(Error::Config(format!(
            "capability '{name}' must be pinned (mcp-gateway cap pin) to run a local process"
        )));
    }
    let command = process.command();
    let static_args = process.static_args_prefix();
    if !policy
        .commands
        .iter()
        .any(|allowed| allowed.admits(command, &static_args))
    {
        return Err(Error::Config(format!(
            "capability '{name}' runs '{command}', which capabilities.process_commands \
             does not allow"
        )));
    }
    Ok(())
}

impl CapabilityExecutor {
    /// Run a process-running capability's primary provider.
    pub(super) async fn execute_process(
        &self,
        capability: &CapabilityDefinition,
        process: &ProcessConfig,
        params: &Value,
        context: &CapabilityExecutionContext,
    ) -> Result<Value> {
        admit(&self.process_policy, capability, process)?;
        let params = &with_schema_defaults(params, &capability.schema.input);
        match process {
            ProcessConfig::Cli(config) => {
                self.execute_cli(capability, config, params, context).await
            }
            ProcessConfig::Mcp(config) => {
                self.execute_mcp(capability, config, params, context).await
            }
        }
    }
}

/// The call's parameters plus every schema `default` the caller left out.
///
/// Validation does not apply defaults, and an argv template cannot invent one,
/// so a property such as `calendarId: primary` would otherwise be missing.
fn with_schema_defaults(params: &Value, input_schema: &Value) -> Value {
    let mut merged = params.clone();
    if let (Some(map), Some(props)) = (
        merged.as_object_mut(),
        input_schema.get("properties").and_then(Value::as_object),
    ) {
        for (name, prop) in props {
            if let Some(default) = prop.get("default")
                && map.get(name).is_none_or(Value::is_null)
            {
                map.insert(name.clone(), default.clone());
            }
        }
    }
    merged
}

#[cfg(test)]
#[path = "process_tests.rs"]
mod tests;
