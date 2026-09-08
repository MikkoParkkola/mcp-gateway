// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Current authorization and definition snapshots for keyed orchestration.

use serde_json::{Value, json};

use crate::gateway::meta_mcp_helpers::{
    extract_required_str, parse_code_mode_tool_ref, parse_tool_arguments,
};
use crate::playbook::PlaybookDefinition;
use crate::{Error, Result};

use super::super::{MetaMcp, MetaMcpCallerContext};

impl MetaMcp {
    /// Legacy unkeyed orchestration retains its existing per-step checks. A
    /// keyed retry must pass current checks before exposing any retained data.
    pub(super) fn authorize_execution_plan(
        &self,
        caller: &MetaMcpCallerContext<'_>,
        tool: &str,
        arguments: &Value,
        session: Option<&str>,
    ) -> Result<Option<PlaybookDefinition>> {
        if caller.retry.idempotency_key.is_none() {
            return Ok(None);
        }
        match tool {
            "gateway_execute" => {
                self.authorize_code_mode_plan(caller, arguments, session)?;
                Ok(None)
            }
            "gateway_run_playbook" => {
                let name = extract_required_str(arguments, "name")?;
                let definition =
                    self.playbook_engine
                        .read()
                        .get(name)
                        .cloned()
                        .ok_or_else(|| {
                            Error::json_rpc(-32602, format!("Playbook not found: {name}"))
                        })?;
                // Check even conditional steps: a cached orchestration result
                // cannot bypass a now-revoked target. The invoker still checks
                // the interpolated arguments immediately before each dispatch.
                for step in &definition.steps {
                    self.check_invocation_policy(
                        &json!({"server": step.server, "tool": step.tool,
                            "arguments": step.arguments}),
                        session,
                        caller,
                    )?;
                }
                Ok(Some(definition))
            }
            _ => Ok(None),
        }
    }

    fn authorize_code_mode_plan(
        &self,
        caller: &MetaMcpCallerContext<'_>,
        arguments: &Value,
        session: Option<&str>,
    ) -> Result<()> {
        let chain = arguments.get("chain").and_then(Value::as_array);
        let steps = chain.map_or_else(|| std::slice::from_ref(arguments), Vec::as_slice);
        if steps.is_empty() {
            return Err(Error::json_rpc(-32602, "Chain must not be empty"));
        }
        for step in steps {
            let tool_ref = extract_required_str(step, "tool")?;
            let (tool, server) = parse_code_mode_tool_ref(tool_ref);
            let server = server.ok_or_else(|| {
                Error::json_rpc(-32602, "Tool reference requires a server:tool_name prefix")
            })?;
            let arguments = if chain.is_some() {
                step.get("arguments").cloned().unwrap_or_else(|| json!({}))
            } else {
                parse_tool_arguments(step)?
            };
            self.check_invocation_policy(
                &json!({"server": server, "tool": tool, "arguments": arguments}),
                session,
                caller,
            )?;
        }
        Ok(())
    }
}
