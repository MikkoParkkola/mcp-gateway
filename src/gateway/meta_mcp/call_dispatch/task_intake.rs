// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Task-augmented `tools/call` intake: the busy custody answered before any
//! task exists, and the task's creation or stored repeat.

use super::{
    Arc, JsonRpcResponse, MetaMcp, MetaMcpCallerContext, RequestId, Value,
    error_response_preserving_status, invoke, task_backend_name,
};

impl MetaMcp {
    /// A task-augmented call whose intake verdict met a busy custody
    /// (MIK-8392 G2): the transient lives only in this request's memo,
    /// which the task worker never gets, so answer it here, before any
    /// task exists — the shared transient answer, refund asked as the
    /// sync path asks it, settled when this call returns. `None` when the
    /// call is not task-augmented or its verdict recorded no transient.
    ///
    /// Any transient held here is this call's own, so no target parsing
    /// is needed to own it. `with_visibility_memo` opens a fresh memo
    /// unless the future already runs inside this request's one
    /// (visible.rs:623-630). On HTTP that scope wraps one POST's
    /// dispatch (router/handlers.rs:149-151). A stdio batch loop does not
    /// open a batch memo (server/stdio_loop.rs:460-485); each item goes
    /// through `dispatch_single_staged`, which opens its own
    /// (server/stdio_single.rs:334-338), awaited before the next item
    /// (server/stdio_notify.rs:100-144). Chain and playbook steps and
    /// nested relay rounds run inside this one `tools/call`, so their
    /// transient is this call's by definition.
    pub(super) fn task_intake_transient(
        caller: &MetaMcpCallerContext<'_>,
        id: &RequestId,
    ) -> Option<JsonRpcResponse> {
        caller.task.as_ref()?;
        // No policy check here: the invocation policy already ran before
        // intake for a `gateway_invoke` (signing.rs:642 when signed,
        // admission.rs:391 otherwise), for a surfaced name, signed or not
        // (admission.rs:368-391; signing prepares only `gateway_invoke`), and
        // for a keyed `gateway_execute` or playbook plan (admission_plan.rs:63-131).
        // An unkeyed task call never gets here: task creation without an
        // idempotency key is refused first (MIK-8428 Case D, not reproduced).
        // A view Busy is held as an account transient; a mint Busy at the
        // route stage as a sealed-transient resolution error (#3892 gpt F1).
        // Either one answers here, before any task or key exists.
        if super::super::visible::take_any_account_transient().is_none()
            && super::super::visible::take_any_transient_resolution_error().is_none()
        {
            return None;
        }
        caller.signing.inspect(|signing| signing.want_refund());
        Some(error_response_preserving_status(
            id.clone(),
            &crate::personal_accounts::refusal::transient_retry_error(None),
        ))
    }

    pub(in crate::gateway::meta_mcp) async fn begin_task(
        &self,
        id: RequestId,
        tool_name: &str,
        arguments: Value,
        intent: crate::gateway::task_service::TaskIntent,
        (session_id, caller): (Option<&str>, &MetaMcpCallerContext<'_>),
    ) -> JsonRpcResponse {
        use crate::gateway::task_service::execution::BeginOutcome;

        let task = crate::gateway::task_service::Task::create_undated(tool_name, intent.options);
        let backend = task_backend_name(self, tool_name, &arguments);
        let executor = Arc::clone(&intent.executor);
        // Every task passed the synchronous call's policy at admission
        // (`admit_meta_sync`, MIK-8315); its worker checks again at dispatch.
        // Only a `gateway_invoke` envelope's token is kept back from the move.
        let invoke_attestation = (tool_name == "gateway_invoke")
            .then(|| {
                arguments
                    .get("attestation")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .flatten();
        let call = crate::gateway::task_service::TaskCall {
            tool: tool_name.to_owned(),
            arguments,
        };
        match executor.begin(intent, task, backend, call).await {
            Ok(BeginOutcome::Existing(held)) => {
                // MIK-8176 N1: delivered into this request's scope first, so
                // its holds are adopted before any decision; a refusal below
                // only drops this request's clones, and the row keeps the slot.
                let stored = held.deliver(super::super::sealed_hold::HoldSink::Scope);
                // The calls that produced the stored result (R3.2) must hold
                // before it goes out; the request's own policy ran at admission.
                // The token rides where the current request's own check reads it.
                let attestation = if tool_name == "gateway_invoke" {
                    invoke_attestation.as_deref()
                } else {
                    caller.retry.attestation.as_deref()
                };
                // MIK-8392: the repeat runs the stored-read pre-pass too, so
                // a catalogue past its TTL is refreshed before it is judged
                // (otherwise it would answer retryable until other traffic
                // refreshed it) — but not its account fill: a repeat's
                // accounts are judged live, and the fill would read custody
                // and audit a busy custody for a call that serves stored
                // output (`prepare_repeated_call`).
                // Boxed as a trait object: its future (credential resolution,
                // fills) must not become part of this dispatch's own
                // recursive future type (the Send check overflows).
                let prepare: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> =
                    Box::pin(self.prepare_repeated_call(&stored, caller.scope(), session_id));
                prepare.await;
                // E9: a target hidden only because its account cannot be read
                // now answers as the live call does (retryable), before the
                // catalogue refusal; every other withholding is unchanged.
                if let Some(answer) = self
                    .unavailable_repeat_answer(&id, &stored, (tool_name, session_id), caller)
                    .await
                {
                    return answer;
                }
                // MIK-8392 site-5 split: the catalogue is judged here; an
                // account that is not live is the call's own live path.
                if let Some(refusal) =
                    self.refuse_stored_repeat(&id, &stored, attestation, session_id, caller)
                {
                    return refusal;
                }
                // Site 5 walks every recorded target (MIK-8406 PLANREPLAY.4). A
                // pre-v5 row was refused above (-32003, task_replay.rs); a v5 row
                // holds every authorized step (grant_audit.rs), never none.
                let targets = stored.targets.clone();
                // The holds already sit in this request's scope.
                let held = super::super::sealed_hold::Held::new(
                    stored,
                    super::super::sealed_hold::CarriedHolds::none(),
                );
                return self
                    .defer_or_serve_existing(id, tool_name, &targets, held, caller)
                    .await;
            }
            Ok(outcome) => invoke::ask_if_refused_submit(caller, outcome).into_response(id),
            Err(crate::gateway::task_service::ServiceError::AuditUnavailable) => {
                error_response_preserving_status(id, &crate::Error::AuditUnavailable)
            }
            Err(_) => JsonRpcResponse::error(Some(id), -32603, "task store unavailable"),
        }
    }
}
