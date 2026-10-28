// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Current authorization and definition snapshots for keyed orchestration.

use crate::error::rpc_codes::INVALID_PARAMS;
use serde_json::{Value, json};

use crate::gateway::meta_mcp_helpers::{
    extract_required_str, parse_code_mode_tool_ref, parse_tool_arguments,
};
use crate::playbook::PlaybookDefinition;
use crate::{Error, Result};

use super::super::{MetaMcp, MetaMcpCallerContext};

/// Each plan step the caller cannot see, as `(server, tool)`, with its
/// refusal, in plan order; empty when every step is visible.
pub(super) type Withheld = Vec<((String, String), Error)>;

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
    ///
    /// The second value is the refusal of the code-mode steps the caller
    /// cannot see, with those steps (MIK-8361 A5 ruling A): a fresh call does
    /// not give it, as its per-step gate answers the step absent, exactly like
    /// a missing step; a replay of a retained result that dispatched one of
    /// them does, unchanged, so none outlives a revocation (SUB.4).
    pub(super) fn authorize_execution_plan(
        &self,
        caller: &MetaMcpCallerContext<'_>,
        tool: &str,
        arguments: &Value,
        session: Option<&str>,
    ) -> Result<(Option<PlaybookDefinition>, Withheld)> {
        if caller.retry.idempotency_key.is_none() {
            return Ok((None, Vec::new()));
        }
        // Keyed plans are checked step by step below, before the handler's own
        // refusal runs; refuse first so enforce answers with the plan message.
        if crate::gateway::meta_mcp::is_composite_meta_tool(tool) {
            self.refuse_unattested_plan()?;
        }
        match tool {
            "gateway_execute" => Ok((
                None,
                self.authorize_code_mode_plan(caller, arguments, session)?,
            )),
            "gateway_run_playbook" => {
                let name = extract_required_str(arguments, "name")?;
                let definition =
                    self.playbook_engine
                        .read()
                        .get(name)
                        .cloned()
                        .ok_or_else(|| {
                            Error::json_rpc(INVALID_PARAMS, format!("Playbook not found: {name}"))
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
                Ok((Some(definition), Vec::new()))
            }
            _ => Ok((None, Vec::new())),
        }
    }

    /// Whether the caller cannot see the step `(server, tool)`: withheld by
    /// the shared judgement (policy, profile, descriptor), or by the caller's
    /// own catalogue as this request's verdict recorded it (MIK-8356).
    fn step_is_hidden(
        &self,
        caller: &MetaMcpCallerContext<'_>,
        (server, tool): (&str, &str),
        session: Option<&str>,
    ) -> bool {
        use crate::gateway::meta_mcp::visible::{Visibility, memo::recorded_visibility};
        matches!(
            recorded_visibility(server, tool),
            Some(Visibility::Withheld(_))
        ) || self.tool_visible_to(server, tool, caller.scope(), session) != Visibility::Visible
    }

    fn authorize_code_mode_plan(
        &self,
        caller: &MetaMcpCallerContext<'_>,
        arguments: &Value,
        session: Option<&str>,
    ) -> Result<Withheld> {
        let mut deferred: Withheld = Vec::new();
        let chain = arguments.get("chain").and_then(Value::as_array);
        let steps = chain.map_or_else(|| std::slice::from_ref(arguments), Vec::as_slice);
        if steps.is_empty() {
            return Err(Error::json_rpc(INVALID_PARAMS, "Chain must not be empty"));
        }
        for step in steps {
            let tool_ref = extract_required_str(step, "tool")?;
            let (tool, server) = parse_code_mode_tool_ref(tool_ref);
            let server = server.ok_or_else(|| {
                Error::json_rpc(
                    INVALID_PARAMS,
                    "Tool reference requires a server:tool_name prefix",
                )
            })?;
            let arguments = if chain.is_some() {
                step.get("arguments").cloned().unwrap_or_else(|| json!({}))
            } else {
                parse_tool_arguments(step)?
            };
            let checked = self.check_invocation_policy(
                &json!({"server": server, "tool": tool, "arguments": arguments}),
                session,
                caller,
            );
            match checked {
                // MIK-8387 S2b′: a scoped key's absent step is the per-step
                // gate's on a fresh call; a replay meets the backend miss, the
                // same for all three cells. Its policy check above has already
                // written the scope refusal's audit line; no kill switch is
                // judged for it by name.
                _ if self
                    .scoped(caller.scope().authorizer.backend_grant())
                    .absent_step(server, tool) =>
                {
                    let missing = Error::BackendNotFound(server.to_owned());
                    deferred.push(((server.to_owned(), tool.to_owned()), missing));
                }
                Ok(()) => {}
                // A step the caller cannot see, by the shared judgement or
                // by its own catalogue's verdict this request recorded, is
                // the per-step gate's on a fresh call; only a replay meets its
                // refusal, which a replayed key's holder was already shown
                // (SUB.4, ruling A).
                Err(refusal) if self.step_is_hidden(caller, (server, tool), session) => {
                    // The kill switch speaks about the backend, not the
                    // name: it refuses the whole call
                    // here, as a missing step's policy check does, rather
                    // than letting earlier steps run (#3872 FIX 2).
                    self.admit_backend_wide(server)?;
                    deferred.push(((server.to_owned(), tool.to_owned()), refusal));
                }
                Err(refusal) => return Err(refusal),
            }
        }
        Ok(deferred)
    }
}
