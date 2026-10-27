// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIN.1 gap 1: the settlement record of a recovered upstream task.

use std::collections::BTreeSet;

use super::{DispatchNotes, SettledTask, sha256_of};
use crate::Error;
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::tasks::TaskTransition;
use crate::security::audit::{AuditEnvelope, AuditFailurePolicy, AuditOutcome, AuditWho};

impl DispatchNotes {
    /// MIN.1 gap 1: a settlement's outcome. A gate refusal keeps the class a
    /// live call's record gives it, with the code the task commits. The
    /// settlement result is built from a committed code alone, so a bare
    /// `-32001`/`-32004` reads as `denied` in `from_result`: without a refusal
    /// a gate noted it is the peer's own answer, an `error` (MIK-7735). The
    /// same holds for a bare `-32602`, which `from_result` reads as `invalid`
    /// (MIK-7960).
    fn settled_outcome(&self, outcome: AuditOutcome) -> AuditOutcome {
        match (self.outcome(outcome), self.refusal) {
            (AuditOutcome::Denied(code) | AuditOutcome::Invalid(code), None) => {
                AuditOutcome::Error(code)
            }
            (AuditOutcome::Error(code), Some(AuditOutcome::Denied(_))) => {
                AuditOutcome::Denied(code)
            }
            (AuditOutcome::Error(code), Some(AuditOutcome::Invalid(_))) => {
                AuditOutcome::Invalid(code)
            }
            (outcome, _) => outcome,
        }
    }
}

impl MetaMcp {
    /// The tests' shorthand: the transition to commit alone.
    #[cfg(test)]
    pub(crate) async fn audit_settlement(
        &self,
        task: SettledTask<'_>,
        proposed: TaskTransition,
        notes: &DispatchNotes,
        principal: &str,
    ) -> TaskTransition {
        self.audit_settlement_kept(task, proposed, notes, principal)
            .await
            .0
    }

    /// MIN.1 gap 1: write the settlement record of a recovered upstream task,
    /// before `proposed` is committed, and return the transition to commit.
    ///
    /// `proposed` and `notes` come from `recover_task_result` or
    /// `recover_task_error` run in [`with_dispatch_scope`](super::with_dispatch_scope); the outcome and
    /// hash mapping is `audit_invocation`'s. `who` is the principal the task
    /// was admitted under and nothing more. A failed write under
    /// [`AuditFailurePolicy::FailClosed`] commits `-32005` instead, with no
    /// backend content, as a live call withholds its result (D1-f).
    ///
    /// Also says whether the transition it returns is the one proposed
    /// (`true`) or that fail-closed replacement (`false`), so a caller never
    /// infers it from the outcome (MIK-7887.RECEIPT.1).
    pub(crate) async fn audit_settlement_kept(
        &self,
        task: SettledTask<'_>,
        proposed: TaskTransition,
        notes: &DispatchNotes,
        principal: &str,
    ) -> (TaskTransition, bool) {
        let Some(log) = self.transparency_logger.as_ref() else {
            return (proposed, true);
        };
        let result = match &proposed {
            TaskTransition::Complete(value) => Ok(value.clone()),
            TaskTransition::Fail(error) => Err(Error::json_rpc(error.code, error.message.clone())),
            _ => return (proposed, true),
        };
        // Total here: only `Error::AuditUnavailable` maps to `None`, and the
        // mapping above builds `Ok` or `Error::JsonRpc` alone.
        let Some(outcome) = AuditOutcome::from_result(&result) else {
            return (proposed, true);
        };
        let attribution = notes.attribution(self, BTreeSet::new(), result.as_ref().ok());
        let envelope = AuditEnvelope {
            trace_id: Some(task.id.to_string()),
            otel_trace_id: None,
            outcome: notes.settled_outcome(outcome),
            // The task owner, keyed for the record when it is credential-derived;
            // the task lookup keeps the owner (MIK-8697 §16.12).
            who: AuditWho::from_actor_id(&crate::gateway::record_principal::record_owner(
                principal,
                self.record_key(),
            )),
        };
        let response_hash = result.as_ref().ok().map(sha256_of);
        let request_hash = sha256_of(&serde_json::json!({ "task_id": task.id }));
        let (id, server, tool) = (
            task.id.to_owned(),
            task.server.to_owned(),
            task.tool.to_owned(),
        );
        let written = log
            .append_bounded(move |log| {
                log.log_task_settlement(
                    &id,
                    &envelope,
                    &server,
                    &tool,
                    &request_hash,
                    response_hash.as_deref(),
                    attribution,
                )
            })
            .await;
        let (server, tool, task_id) = (task.server, task.tool, task.id);
        match written {
            Ok(()) => (proposed, true),
            Err(error) if log.failure_policy() == AuditFailurePolicy::FailClosed => {
                tracing::error!(target: "mcp_gateway::gateway::meta_mcp::invoke::audit", server, tool, task_id, %error, "settlement audit write failed; result withheld");
                let withheld = Error::AuditUnavailable;
                let replaced = TaskTransition::Fail(crate::protocol::JsonRpcError {
                    code: withheld.to_rpc_code(),
                    message: withheld.to_string(),
                    data: None,
                });
                (replaced, false)
            }
            Err(error) => {
                tracing::warn!(target: "mcp_gateway::gateway::meta_mcp::invoke::audit", server, tool, task_id, %error, "settlement audit write failed (non-fatal)");
                telemetry_metrics::counter!("mcp_audit_settlement_write_failures_total")
                    .increment(1);
                (proposed, true)
            }
        }
    }
}
