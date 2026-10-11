// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The playbook step invoker: bridges `MetaMcp::invoke_tool` to the
//! `ToolInvoker` trait, and the one neutral answer a refused step gets.

use serde_json::{Value, json};

use super::{MetaMcp, MetaMcpCallerContext};
use crate::Result;
use crate::playbook::ToolInvoker;

/// Bridges `MetaMcp::invoke_tool` to the `ToolInvoker` trait for playbook execution.
pub(in crate::gateway::meta_mcp) struct MetaMcpInvoker<'a, 'c> {
    pub(in crate::gateway::meta_mcp) meta: &'a MetaMcp,
    /// The caller that invoked the playbook, carried whole.
    ///
    /// Whole, and not field by field, because it holds the authorizer: each
    /// step faces exactly the checks the caller would face invoking that tool
    /// directly. An earlier version carried the caller's identity without the
    /// authorizer, which nothing on this path consulted — an identity no check
    /// reads is not a check.
    pub(in crate::gateway::meta_mcp) caller: &'c MetaMcpCallerContext<'c>,
    /// Each successful step call's gateway notes, taken out of the delivery's
    /// record, with the value they describe (MIK-7993 r5): put back onto the
    /// playbook's answer once its output is built.
    pub(in crate::gateway::meta_mcp) steps:
        parking_lot::Mutex<Vec<(crate::gateway::gateway_writes::WriteRecord, Value)>>,
}

impl MetaMcpInvoker<'_, '_> {
    /// Put each completed step's gateway notes back, rebased onto the
    /// playbook's stored answer (the `output` of its serialized result): by
    /// step name with no output mapping, through each mapping otherwise.
    /// Successful calls pair with `completed` in order; if the counts differ,
    /// nothing is carried, and those members stay receipted.
    pub(in crate::gateway::meta_mcp) fn carry_writes(
        &self,
        output: Option<&crate::playbook::PlaybookOutput>,
        completed: &[String],
    ) {
        let steps = std::mem::take(&mut *self.steps.lock());
        if steps.len() != completed.len() {
            return;
        }
        let named: Vec<(&String, crate::gateway::gateway_writes::WriteRecord, Value)> = completed
            .iter()
            .zip(steps)
            .map(|(name, (record, value))| (name, record, value))
            .collect();
        let Some(output) = output else {
            // The engine keeps the LAST result under a repeated name, so only
            // that call's notes describe what is stored there (delta D2).
            let mut last: Vec<(&String, crate::gateway::gateway_writes::WriteRecord)> = Vec::new();
            for (name, record, _) in named {
                if let Some(slot) = last.iter_mut().find(|(kept, _)| *kept == name) {
                    slot.1 = record;
                } else {
                    last.push((name, record));
                }
            }
            for (name, record) in last {
                crate::gateway::gateway_writes::restore(
                    &record.rebased(&["output".to_owned(), name.clone()]),
                );
            }
            return;
        };
        for (prop, mapping) in &output.properties {
            let path = mapping.path.trim_start_matches('$');
            let (step, rest) = path.split_once('.').unwrap_or((path, ""));
            // `inputs` is the caller's namespace even beside a step of that
            // name, as `PlaybookContext::resolve_var` reads it (impl F5).
            if step == "inputs" {
                continue;
            }
            // The engine keeps the LAST result under a repeated name (impl F4).
            let Some((_, record, value)) =
                named.iter().rev().find(|(name, ..)| name.as_str() == step)
            else {
                continue;
            };
            // One match is stored as itself, several as an array of them in
            // the order the resolver visits them (impl F3).
            let found = crate::gateway::gateway_writes::mapping_paths(value, rest);
            let to = ["output".to_owned(), prop.clone()];
            match found.as_slice() {
                [one] => {
                    crate::gateway::gateway_writes::restore(&record.projected(value, one, &to));
                }
                many => {
                    for (index, from) in many.iter().enumerate() {
                        let at = [to[0].clone(), to[1].clone(), index.to_string()];
                        crate::gateway::gateway_writes::restore(
                            &record.projected(value, from, &at),
                        );
                    }
                }
            }
        }
    }
}

/// The one answer a step gets when authorization refuses it or a content scan
/// flags its arguments (A3): a step's server, tool and arguments are
/// operator-defined, so the reason never names them. A budget, tenant or
/// anomaly refusal keeps the firewall's wording instead: it carries counts and
/// scores only, and the caller needs it to back off.
pub(crate) const STEP_NOT_PERMITTED: &str = "step not permitted for this caller";
/// Its JSON-RPC code and HTTP status.
pub(crate) const STEP_NOT_PERMITTED_CODE: i32 = -32003;
pub(crate) const STEP_NOT_PERMITTED_STATUS: u16 = 403;

pub(crate) fn step_not_permitted() -> crate::Error {
    crate::Error::Forbidden {
        code: STEP_NOT_PERMITTED_CODE,
        status: STEP_NOT_PERMITTED_STATUS,
        message: STEP_NOT_PERMITTED.to_string(),
    }
}

#[async_trait::async_trait]
impl ToolInvoker for MetaMcpInvoker<'_, '_> {
    async fn invoke(&self, server: &str, tool: &str, arguments: Value) -> Result<Value> {
        let args = internal_invoke_args(server, tool, arguments);
        let writes_mark = crate::gateway::gateway_writes::mark();
        // Steps inherit the invoking caller's standing, admin included.
        // Hard-coding non-admin meant an operator's own playbook failed on a
        // step they could run directly, which is a regression rather than a
        // control: a playbook is not a way AROUND a check, so it faces the same
        // one — now including the scope checks, at the chokepoint.
        // A step keeps the client's key and nothing else of the run's retry
        // (MIK-8341): the run has no continuation, so no step may redeem the
        // run's `requestState`/`inputResponses`, and `with_retry` drops
        // `task`, as Code Mode chain steps do. The key is scoped to the step
        // in `invoke_tool`, so steps never share the client's own entry.
        let step_retry = crate::protocol::mrtr::RetryFields {
            idempotency_key: self.caller.retry.idempotency_key.clone(),
            ..Default::default()
        };
        let step_caller = self.caller.with_retry(&step_retry);
        let outcome = crate::gateway::meta_mcp::invoke::relay::plan_step(
            crate::playbook::current_step(),
            self.meta.invoke_tool(&args, None, &step_caller),
        )
        .await;
        // A refused step's reason names an operator-defined target the caller
        // may not reach, so it is replaced with a neutral one (A3). Decided
        // from the refusal plus the silent non-authorizer pieces, so the
        // authorizer is consulted once per step, as before.
        let answered = match outcome {
            Err(e)
                if matches!(e, crate::Error::Forbidden { .. })
                    || self
                        .meta
                        .refused_beyond_authorizer(server, tool, self.caller.scope()) =>
            {
                Err(step_not_permitted())
            }
            other => other,
        };
        // A failed attempt's notes describe nothing the playbook keeps.
        let taken = crate::gateway::gateway_writes::take_since(writes_mark);
        if let Ok(value) = &answered {
            self.steps.lock().push((taken, value.clone()));
        }
        answered
    }

    fn sealed_state_in(
        &self,
        value: &Value,
        budget: &mut crate::protocol::continuation::ProbeBudget,
    ) -> std::result::Result<bool, crate::protocol::continuation::ProbeRefusal> {
        crate::protocol::continuation::sealed_state_in(
            self.meta.continuation.keyring(),
            value,
            budget,
        )
    }
}

/// Build the `invoke_tool` argument envelope for an internal (chain / playbook)
/// invocation.
///
/// Internal orchestration consumes the raw backend payload: steps reference
/// prior outputs by their original field paths (`$step.issue.id`). Canonical
/// projection (MIK-3534) is a client-presentation layer that would move those
/// fields under `_raw` and silently break interpolation, so internal calls opt
/// out via `_full`.
///
/// The directive is read (and stripped) from INSIDE the `arguments` map by
/// `invoke_tool_traced`, so it MUST be injected there — placing it as an outer
/// sibling of `arguments` leaves it invisible to `want_full`. Non-object
/// arguments are passed through unchanged (no data loss).
pub(in crate::gateway::meta_mcp) fn internal_invoke_args(
    server: &str,
    tool: &str,
    arguments: Value,
) -> Value {
    let arguments = match arguments {
        Value::Object(mut map) => {
            map.insert("_full".to_string(), Value::Bool(true));
            Value::Object(map)
        }
        other => other,
    };
    json!({
        "server": server,
        "tool": tool,
        "arguments": arguments
    })
}
