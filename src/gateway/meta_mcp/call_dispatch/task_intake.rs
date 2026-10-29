// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Task-augmented `tools/call` intake: the busy custody answered before any
//! task exists, the task's creation, and a stored task's repeat: the walk
//! that proves every recorded target live before the stored answer goes out.

use super::{
    Arc, ChainSource, JsonRpcResponse, MetaMcp, MetaMcpCallerContext, RequestId, ResultShape,
    Value, error_response_preserving_status, invoke, response_security,
};
use crate::error::rpc_codes::INTERNAL_ERROR;

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
    /// (`visible::memo::with_visibility_memo`). On HTTP that scope wraps
    /// one POST's dispatch (`meta_mcp_handler` in
    /// `router/handlers/meta_handler.rs`). A stdio batch loop does not
    /// open a batch memo (the batch arm of `run_stdio_on` in
    /// `server/stdio_loop.rs`); each item goes through
    /// `dispatch_single_staged`, which opens its own
    /// (in `server/stdio_single.rs`), awaited
    /// before the next item (`dispatch_batch_read` in
    /// `server/stdio_notify.rs`). Chain and playbook steps and nested
    /// relay rounds run inside this one `tools/call`, so their transient
    /// is this call's by definition.
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
        if super::super::visible::memo::take_any_account_transient().is_none()
            && super::super::visible::memo::take_any_transient_resolution_error().is_none()
        {
            return None;
        }
        invoke::ask_refund(caller);
        Some(error_response_preserving_status(
            id.clone(),
            &crate::personal_accounts::refusal::transient_retry_error(None),
        ))
    }

    pub(super) async fn begin_task(
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
            // Read in this request's snapshot, so the task runs
            // where it was admitted or is refused.
            surfaced_server: self.surfaced_target_at_intake(tool_name),
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
                    return refusal.deliver();
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
            Err(_) => JsonRpcResponse::error(Some(id), INTERNAL_ERROR, "task store unavailable"),
        }
    }

    /// Site 5 (MIK-8392 STORED.2): the account step of a repeated task call,
    /// run after `refuse_stored_repeat` returned None (the catalogue
    /// judgement passed and the stored delivery's holds are already staged
    /// in this request). A single call passes its one recorded target;
    /// MIK-8406's plan caller passes the row's whole `stored.targets`.
    /// `tool_name` is the presented tool, for the live-shaped answer a
    /// carried fill failure takes (E4).
    ///
    /// Targets walk in recorded order. Each proves through the dispatch's own
    /// resolution step (`prove_target_live`), de-duplicated by account: a
    /// clean carried credential proves, a carried fill failure answers as the
    /// failed dispatch (E4), and the first refusal answers through the
    /// status-preserving error, keeping the connect offer. No task is
    /// created, and the row keeps its slot: a refusal drops only this
    /// request's clones. When every target is proven the stored answer is
    /// served, with no second catalogue check and no memo write. An empty
    /// slice serves as today: nothing was dispatched.
    ///
    /// Named residuals: an HTTP request reaches E4 here only across a gap of
    /// 10 s or more inside one request, since the cold view answers first
    /// (T6); T6u seeds it directly (M11). The stdio busy task repeat runs
    /// this same walk but has no stdio row. If custody recovers between E9's
    /// proof and this walk, one account can be proven twice (no
    /// deterministic row).
    pub(in crate::gateway::meta_mcp) async fn defer_or_serve_existing(
        &self,
        id: RequestId,
        tool_name: &str,
        targets: &[crate::gateway::task_service::Target],
        held: super::super::sealed_hold::Held<crate::gateway::task_service::CommittedTask>,
        caller: &MetaMcpCallerContext<'_>,
    ) -> JsonRpcResponse {
        use crate::gateway::task_service::execution::BeginOutcome;

        // Collected before the walk: an iterator adapter held across its
        // awaits makes the dispatch future's `Send` bound not general enough.
        let walk = crate::gateway::task_service::Target::pairs(targets);
        if let Some(answer) = Box::pin(self.first_refused(&id, tool_name, &walk, caller)).await {
            return answer;
        }
        BeginOutcome::Existing(held).into_response(id)
    }

    /// The account walk site 5 and the sync plan replay share (MIK-8406
    /// PLANREPLAY.3): `targets` in recorded order, skipping any that mints
    /// nothing per caller, each distinct `(server, account)` proven once
    /// through `prove_target_live`. `None` when every target is proven;
    /// otherwise the first non-proof's answer: a carried failed fill shaped
    /// as the live tool answer (E4), or the refusal through the
    /// status-preserving error, keeping the connect offer.
    pub(in crate::gateway::meta_mcp) async fn first_unproven(
        &self,
        id: &RequestId,
        tool_name: &str,
        targets: &[(&str, &str)],
        caller: &MetaMcpCallerContext<'_>,
    ) -> Option<JsonRpcResponse> {
        // (server, account) pairs this walk resolved already: each resolves once.
        let mut resolved = std::collections::HashSet::new();
        let view = self.scoped(caller.scope().authorizer.backend_grant());
        for &(server, tool) in targets {
            // A target that mints nothing per caller is exempt (U2); every
            // other one (a managed account, or a per-caller mint, E7) proves
            // only by a live resolution below. There is no shortcut for an
            // outcome already read Live: a carried credential is taken above
            // first, so it saved nothing measurable (E10b, T4).
            if !self.mints_per_caller(&view, server, tool) {
                continue;
            }
            if !resolved.insert((server.to_owned(), self.target_account(&view, server, tool))) {
                continue;
            }
            match self.prove_target_live((server, tool), caller).await {
                Ok(None) => {}
                Ok(Some(value)) => {
                    return Some(self.shape_repeat_fill(id.clone(), tool_name, value, caller));
                }
                Err(error) => return Some(error_response_preserving_status(id.clone(), &error)),
            }
        }
        None
    }

    /// A repeated task call's failed-fill answer (E4), shaped as the live
    /// arm shapes the tool result for `tool_name`.
    pub(in crate::gateway::meta_mcp) fn shape_repeat_fill(
        &self,
        id: RequestId,
        tool_name: &str,
        value: Value,
        caller: &MetaMcpCallerContext<'_>,
    ) -> JsonRpcResponse {
        let shape = ResultShape::of_presented(tool_name, &self.surfaced_state().map);
        response_security::shape_meta_result(
            id,
            tool_name,
            Ok(value),
            shape,
            caller.input_capabilities,
            (ChainSource::NotEligible, None),
        )
    }
}

fn task_backend_name(meta: &MetaMcp, tool_name: &str, arguments: &Value) -> String {
    if let Some(server) = meta.surfaced_server_unscoped(tool_name) {
        return server.to_owned();
    }
    match tool_name {
        "gateway_invoke" => arguments
            .get("server")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned(),
        "gateway_execute" => arguments
            .get("tool")
            .and_then(Value::as_str)
            .and_then(|tool_ref| tool_ref.split_once(':'))
            .map_or_else(|| "execute".to_owned(), |(server, _)| server.to_owned()),
        "gateway_run_playbook" => "playbook".to_owned(),
        other => other.to_owned(),
    }
}

#[cfg(test)]
mod shape_tests;
#[cfg(test)]
mod stored_site5_tests;
