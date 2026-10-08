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

        let now = crate::protocol::continuation::now_unix_secs();
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

            // Labelled by its execution index, as the chain's answer names it
            // (`results[i].step`), so a resumed chain's results keep their
            // steps (MIK-8113).
            let label = u32::try_from(idx).ok();
            match plan_step(
                label,
                self.invoke_tool(&invoke_args, session_id, &step_caller),
            )
            .await
            {
                // A tool error in the success channel is still an error.
                Ok(result) => chain_step_result(idx, &tool_ref, result),
                // A refusal stays a refusal. Flattening it into -32603 told
                // the caller their chain hit an internal error when in fact
                // they were not allowed to run that step — and it hid the
                // denial from anything downstream that classifies errors.
                Err(Error::Forbidden {
                    code,
                    status,
                    message,
                }) => Err(Error::Forbidden {
                    code,
                    status,
                    message: format!("Chain step {idx} ({tool_ref}) refused: {message}"),
                }),
                Err(e) => Err(Error::json_rpc(
                    -32603,
                    format!("Chain step {idx} ({tool_ref}) failed: {e}"),
                )),
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
            let payload = seal_chain_stop(&previous, chain_ref, idx, backend_state);
            self.continuation
                .keyring()
                .mint(&payload)
                .map_err(|error| Error::json_rpc(-32603, error.to_string()))
        };

        let answer =
            super::super::chain_interim::drive_chain(&chain, start_step, &mut run_step, seal_stop)
                .await?;
        // MIK-8113: each result is its step's, by the execution index the
        // chain wrote beside it, so a resumed chain's results keep theirs.
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
        Ok(answer)
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
