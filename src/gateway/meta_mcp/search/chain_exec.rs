// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `execute_chain`: Code Mode's sequential `{tool, arguments}` steps, split out
//! of `search.rs` to keep that file under its size ceiling.

use serde_json::{Value, json};

use super::super::MetaMcp;
use crate::gateway::meta_mcp_helpers::parse_code_mode_tool_ref;
use crate::{Error, Result};

impl MetaMcp {
    /// Execute a sequential chain of `{tool, arguments}` steps.
    ///
    /// Returns a JSON array of per-step results. Stops at the first error
    /// and surfaces the failing step index in the error message.
    pub(super) async fn execute_chain(
        &self,
        chain: Vec<Value>,
        session_id: Option<&str>,
        caller: &super::super::MetaMcpCallerContext<'_>,
    ) -> Result<Value> {
        use super::super::chain_interim::{presented_resume, seal_chain_stop, step_retry_for};
        use crate::gateway::meta_mcp::invoke::relay::plan_step;

        if chain.is_empty() {
            return Err(Error::json_rpc(-32602, "Chain must not be empty"));
        }

        let now = crate::protocol::continuation::clock_now().map_err(|_| {
            Error::json_rpc(-32603, "system clock reads before 1970; chain refused")
        })?;
        // A presented resume decides where the chain starts and how many rounds
        // this exchange has already spent. Both are sealed, so neither is a
        // number the caller can choose.
        let resume = presented_resume(
            &self.continuation,
            caller.retry,
            &chain,
            caller.verified_identity,
            now,
        )
        .await?;
        let (start_step, rounds_used) = resume
            .as_ref()
            .map_or((0, 0), |plan| (plan.next_step, plan.rounds_used));

        // The pending step is invoked through the ordinary redemption path, so
        // the chain-scoped handle is translated into one bound to that step.
        let step_resume = match resume.as_ref() {
            Some(plan) => Some(step_retry_for(
                &self.continuation,
                plan,
                &chain,
                caller.retry.input_responses.clone(),
                now,
            )?),
            None => None,
        };
        let frozen_expiry = resume.as_ref().map(|plan| plan.expires_at);
        let step_retry = step_resume
            .as_ref()
            .unwrap_or(&crate::protocol::mrtr::NO_RETRY);

        let mut run_step = |idx: usize, tool_ref: String, arguments: Value| async move {
            let (tool_name, server_opt) = parse_code_mode_tool_ref(&tool_ref);
            let server = server_opt.ok_or_else(|| {
                Error::json_rpc(
                    -32602,
                    format!(
                        "Chain step {idx}: tool reference '{tool_ref}' is missing server prefix. \
                         Use format 'server:tool_name'."
                    ),
                )
            })?;

            let invoke_args = json!({
                "server": server,
                "tool": tool_name,
                "arguments": arguments,
            });

            // The answers belong to the step that asked for them and to no
            // other. Successors run with an empty retry, which makes "applies
            // to the pending step only" structural rather than asserted: there
            // is nothing left for them to redeem or forward.
            let step_caller = caller.with_retry(if idx == start_step {
                step_retry
            } else {
                &crate::protocol::mrtr::NO_RETRY
            });

            let dispatch = self.invoke_tool(&invoke_args, session_id, &step_caller);
            match plan_step(chain_label(idx), dispatch).await {
                // A tool error in the success channel is still an error.
                Ok(result) => chain_step_result(idx, &tool_ref, result),
                Err(e) => Err(step_failure(idx, &tool_ref, e)),
            }
        };

        let chain_ref = &chain;
        let seal_stop = move |idx: usize, round: &crate::protocol::mrtr::InputRequired| {
            // The step already holds an exchange: `invoke_tool` opened one and
            // sealed it into the envelope it put in `requestState`. This re-seals
            // that envelope as a chain resume rather than minting a second one.
            let token = round.request_state.as_deref().ok_or_else(|| {
                Error::json_rpc(
                    -32603,
                    format!("Chain step {idx} asked without a continuation to seal"),
                )
            })?;
            let mut previous = self
                .continuation
                .keyring()
                .open(token, now)
                .map_err(|reason| Error::json_rpc(-32603, reason.client_message()))?;
            // The step's envelope counts the step's own rounds, which is zero on
            // every mint. The bound belongs to the chain exchange, so the count
            // carried by the resume is what gets incremented.
            previous.rounds_used = rounds_used;
            // The deadline belongs to the exchange, not to the round. The
            // envelope just minted for this question carries a fresh one, so a
            // resumed chain re-freezes it to the first stop's — including when
            // the chain stops at a *different* step, which is a new question
            // but the same exchange.
            if let Some(expiry) = frozen_expiry {
                previous.expires_at = expiry;
            }
            let backend_state = previous.backend_request_state.clone();
            // The resume seals the step's handle over this digest (MIK-8168).
            self.continuation.in_flight().bind_step(&previous);
            let payload = seal_chain_stop(&previous, chain_ref, idx, backend_state);
            self.continuation
                .keyring()
                .mint(&payload)
                .map_err(|error| Error::json_rpc(-32603, error.to_string()))
        };

        super::super::chain_interim::drive_chain(&chain, start_step, &mut run_step, seal_stop)
            .await
            .inspect(note_chain_members)
    }
}

/// A chain step's plan label: its execution index, as the chain's answer
/// names it (`results[i].step`), so a resumed chain's results keep their
/// steps (MIK-8113).
fn chain_label(idx: usize) -> Option<u32> {
    u32::try_from(idx).ok()
}

/// MIK-8113: each result of a chain's answer is its step's, by the execution
/// index the chain wrote beside it, so a resumed chain's results keep theirs.
fn note_chain_members(answer: &Value) {
    let results = answer.get("results").and_then(Value::as_array);
    for (i, done) in results.into_iter().flatten().enumerate() {
        if let Some(label) = done.get("step").and_then(Value::as_u64) {
            let label = u32::try_from(label).unwrap_or(u32::MAX);
            crate::gateway::meta_mcp::invoke::relay::note_plan_member(
                format!("/results/{i}/result"),
                label,
            );
        }
    }
}

/// A step's result, or the chain failure for one that is `isError: true`,
/// spelled as the error path spells it. The chain contract stops at the first
/// error, and a tool error returned in the success channel is still one: later
/// steps were written assuming this one ran (MIK-7570.SCHEMA.1).
fn chain_step_result(idx: usize, tool_ref: &str, result: Value) -> Result<Value> {
    if result.get("isError").and_then(Value::as_bool) != Some(true) {
        return Ok(result);
    }
    let detail: String = result["content"][0]["text"]
        .as_str()
        .map_or_else(|| result.to_string(), str::to_owned)
        .chars()
        .take(2048)
        .collect();
    Err(Error::json_rpc(
        -32603,
        format!("Chain step {idx} ({tool_ref}) failed: {detail}"),
    ))
}

/// A failed chain step, with its index and tool named. A refusal stays a
/// refusal: flattening it into -32603 told the caller their chain hit an
/// internal error when they were not allowed to run that step, and hid the
/// denial from anything downstream that classifies errors. A refused
/// continuation (-32602, e.g. a step whose backend was replaced while the
/// chain was paused, MIK-8168) likewise keeps its code, so the client asks
/// again instead of reporting a gateway fault.
fn step_failure(idx: usize, tool_ref: &str, error: Error) -> Error {
    match error {
        Error::Forbidden {
            code,
            status,
            message,
        } => Error::Forbidden {
            code,
            status,
            message: format!("Chain step {idx} ({tool_ref}) refused: {message}"),
        },
        Error::JsonRpc {
            code: -32602,
            message,
            data,
        } => Error::JsonRpc {
            code: -32602,
            message: format!("Chain step {idx} ({tool_ref}) refused: {message}"),
            data,
        },
        e => Error::json_rpc(-32603, format!("Chain step {idx} ({tool_ref}) failed: {e}")),
    }
}

#[cfg(test)]
mod member_tests {
    use serde_json::json;

    /// `MIK-8113` (chain provenance): each result is its step's by the
    /// execution index written beside it, not its place in the array, so a
    /// chain resumed at step 3 labels its first result 3.
    #[tokio::test]
    async fn a_resumed_chains_results_keep_their_execution_index() {
        let answer = json!({"steps": 2, "results": [
            {"step": 3, "tool": "mock:echo", "result": {}},
            {"step": 4, "tool": "mock:echo", "result": {}},
        ]});
        let ((), noted) = crate::gateway::meta_mcp::invoke::relay::noting_plan_members(async {
            super::note_chain_members(&answer);
        })
        .await;
        assert_eq!(
            noted,
            vec![
                ("/results/0/result".to_string(), 3),
                ("/results/1/result".to_string(), 4),
            ]
        );
    }
}
