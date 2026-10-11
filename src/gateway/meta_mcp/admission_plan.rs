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
    /// The backend targets a `gateway_run_playbook` call will reach, one per
    /// declared step, for the route stage to authorize and scan before any step
    /// runs (MIK-8362). `server` and `tool` are literal in the definition; only
    /// `arguments` are interpolated at run time, so the step's template
    /// arguments stand in for them. Empty when the meta-tool is not exposed or
    /// the name is unknown: the handler's own answer stays the answer, and the
    /// route never confirms a playbook it would not run.
    pub(crate) fn playbook_step_targets(
        &self,
        tool_name: &str,
        arguments: &Value,
    ) -> Vec<crate::gateway::authz::CallTarget<'static>> {
        if tool_name != "gateway_run_playbook" || !self.meta_tool_exposure.is_exposed(tool_name) {
            return Vec::new();
        }
        let Ok(name) = extract_required_str(arguments, "name") else {
            return Vec::new();
        };
        let engine = self.playbook_engine.read();
        let Some(definition) = engine.get(name) else {
            return Vec::new();
        };
        definition
            .steps
            .iter()
            .map(|step| crate::gateway::authz::CallTarget {
                server: step.server.clone(),
                tool: step.tool.clone(),
                arguments: std::borrow::Cow::Owned(Value::Object(
                    step.arguments
                        .iter()
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .collect(),
                )),
            })
            .collect()
    }

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
        // Keyed plans are checked step by step below, before the handler's own
        // refusal runs; refuse first so enforce answers with the plan message.
        if matches!(tool, "gateway_execute" | "gateway_run_playbook") {
            self.refuse_unattested_plan()?;
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
