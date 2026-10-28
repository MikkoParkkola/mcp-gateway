// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIN.1 gap 1: the settlement record of a recovered upstream task.

use std::collections::BTreeSet;

use super::{DispatchNotes, SettledTask, sha256_of};
use crate::Error;
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::tasks::TaskTransition;
use crate::security::audit::{AuditEnvelope, AuditFailurePolicy, AuditOutcome, AuditWho};
use crate::security::transparency_log::TaskSettlementRoute;

impl DispatchNotes {
    /// MIN.1 gap 1: a settlement's outcome. A gate refusal keeps the class a
    /// live call's record gives it, with the code the task commits. The
    /// settlement result is built from a committed code alone, so a bare
    /// `-32001`/`-32004` reads as `denied` in `from_result`: without a refusal
    /// a gate noted it is the peer's own answer, an `error`. The
    /// same holds for a bare `-32602`, which `from_result` reads as `invalid`.
    fn settled_outcome(&self, outcome: AuditOutcome) -> AuditOutcome {
        match (self.outcome(outcome), self.refusal) {
            (AuditOutcome::Denied(code) | AuditOutcome::Invalid(code), None) => {
                AuditOutcome::Error(code)
            }
            // A refusal keeps the committed code, which may be a peer's
            // `-32602`: the class is the refusal's, not the code's.
            (
                AuditOutcome::Error(code) | AuditOutcome::Invalid(code),
                Some(AuditOutcome::Denied(_)),
            ) => AuditOutcome::Denied(code),
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
        if self.transparency_logger.is_none() {
            return (proposed, true);
        }
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
        let mut attribution = notes.attribution(self, BTreeSet::new(), result.as_ref().ok());
        // What this settlement's own gates did to the answer, only when they
        // refused or rewrote it: a clean recovery's record is unchanged.
        decided_fields(notes.refusal.is_some(), &mut attribution);
        let envelope = AuditEnvelope {
            trace_id: Some(task.id.to_string()),
            otel_trace_id: None,
            outcome: notes.settled_outcome(outcome),
            // The task owner, keyed for the record when it is credential-derived;
            // the task lookup keeps the owner.
            who: AuditWho::from_actor_id(&crate::gateway::record_principal::record_owner(
                principal,
                self.record_key(),
            )),
        };
        let response_hash = result.as_ref().ok().map(sha256_of);
        let kept = self
            .append_settlement(
                TaskSettlementRoute::Recovery,
                &task,
                envelope,
                response_hash,
                attribution,
            )
            .await;
        if kept {
            return (proposed, true);
        }
        let withheld = Error::AuditUnavailable;
        let replaced = TaskTransition::Fail(crate::protocol::JsonRpcError {
            code: withheld.to_rpc_code(),
            message: withheld.to_string(),
            data: None,
        });
        (replaced, false)
    }

    /// The settlement record of a task the gateway ran itself, written when its
    /// settlement refused (`refused`, with the code the task settles with) or
    /// rewrote the answer, before the transition commits. `trace_id` is the worker dispatch's invocation trace,
    /// so the record joins that dispatch record; `result` is the settled answer
    /// (`None` for a refusal). The facts come from the open cell.
    ///
    /// Returns whether the transition may commit as proposed: `false` only
    /// when the write failed under [`AuditFailurePolicy::FailClosed`], and the
    /// caller then withholds the answer.
    pub(crate) async fn record_task_settlement(
        &self,
        task: SettledTask<'_>,
        (trace_id, principal): (&str, &str),
        refused: Option<i32>,
        result: Option<&serde_json::Value>,
    ) -> bool {
        if self.transparency_logger.is_none() {
            return true;
        }
        let outcome = if let Some(code) = refused {
            AuditOutcome::Denied(code)
        } else {
            let answer = result.cloned().unwrap_or(serde_json::Value::Null);
            AuditOutcome::from_result(&Ok(answer)).unwrap_or(AuditOutcome::Ok)
        };
        let mut extra = serde_json::Map::new();
        decided_fields(refused.is_some(), &mut extra);
        let envelope = AuditEnvelope {
            trace_id: Some(trace_id.to_owned()),
            otel_trace_id: None,
            outcome,
            who: AuditWho::from_actor_id(&crate::gateway::record_principal::record_owner(
                principal,
                self.record_key(),
            )),
        };
        self.append_settlement(
            TaskSettlementRoute::Settlement,
            &task,
            envelope,
            result.map(sha256_of),
            extra,
        )
        .await
    }

    /// Append one settlement record. `false` only when the write failed under
    /// [`AuditFailurePolicy::FailClosed`]; a failure under any other policy is
    /// logged and counted, and the settlement proceeds.
    async fn append_settlement(
        &self,
        route: TaskSettlementRoute,
        task: &SettledTask<'_>,
        envelope: AuditEnvelope,
        response_hash: Option<String>,
        extra: serde_json::Map<String, serde_json::Value>,
    ) -> bool {
        let Some(log) = self.transparency_logger.as_ref() else {
            return true;
        };
        let request_hash = sha256_of(&serde_json::json!({ "task_id": task.id }));
        let (id, server, tool) = (
            task.id.to_owned(),
            task.server.to_owned(),
            task.tool.to_owned(),
        );
        let written = log
            .append_bounded(move |log| {
                log.log_task_settlement(
                    route,
                    &id,
                    &envelope,
                    &server,
                    &tool,
                    &request_hash,
                    response_hash.as_deref(),
                    extra,
                )
            })
            .await;
        let (server, tool, task_id) = (task.server, task.tool, task.id);
        match written {
            Ok(()) => true,
            Err(error) if log.failure_policy() == AuditFailurePolicy::FailClosed => {
                tracing::error!(target: "mcp_gateway::gateway::meta_mcp::invoke::audit", server, tool, task_id, %error, "settlement audit write failed; result withheld");
                false
            }
            Err(error) => {
                tracing::warn!(target: "mcp_gateway::gateway::meta_mcp::invoke::audit", server, tool, task_id, %error, "settlement audit write failed (non-fatal)");
                telemetry_metrics::counter!("mcp_audit_settlement_write_failures_total")
                    .increment(1);
                true
            }
        }
    }
}

/// The open cell's `response_effect` and `response_findings`, written into
/// `fields` only when this settlement refused (`frame_refused`) or its gates
/// rewrote the answer. Outside a cell nothing is written.
fn decided_fields(frame_refused: bool, fields: &mut serde_json::Map<String, serde_json::Value>) {
    let mut decided = serde_json::Map::new();
    crate::gateway::delivery_facts::record_fields(
        crate::gateway::delivery_facts::snapshot().as_ref(),
        frame_refused,
        &mut decided,
    );
    if matches!(
        decided
            .get("response_effect")
            .and_then(serde_json::Value::as_str),
        Some("refused" | "rewritten")
    ) {
        fields.extend(decided);
    }
}
