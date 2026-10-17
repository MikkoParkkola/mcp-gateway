// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MetaMcp` `tools/call` routing and the dispatch below the gate.

use std::borrow::Cow;

use super::{
    Arc, CallerStanding, ChainSource, DispatchTarget, GateOutcome, JsonRpcResponse, MetaMcp,
    MetaMcpCallerContext, RequestId, ResultShape, Value, admission, destructive_confirmation_gate,
    error_response_preserving_status, invoke, response_security,
};

impl MetaMcp {
    /// Route a call that names a backend tool directly, or `None` when the
    /// name belongs to the meta-tool surface.
    ///
    /// Two ways a backend tool answers to its own name: an operator surfaced
    /// it, or the call is a retry whose origin the sealed envelope names.
    pub(super) async fn route_direct_backend_call(
        &self,
        id: RequestId,
        tool_name: &str,
        arguments: &Value,
        session_id: Option<&str>,
        caller: &MetaMcpCallerContext<'_>,
    ) -> Option<JsonRpcResponse> {
        match self.surfaced_for(tool_name, caller.scope(), session_id) {
            super::visible::Surfaced::Visible(server) => {
                // MIK-8356: on a per-user backend the caller's own catalogue
                // decides; a name it withholds or lacks answers exactly as
                // the absent name below. A resolution refused here is left to
                // the dispatch, which answers it as before.
                let verdict = self
                    .caller_verdict(
                        (server, tool_name),
                        caller,
                        session_id,
                        super::invoke::TargetNaming::SurfacedName,
                        // The route stage took the verdict first, holding the
                        // call's witness; this one is its memo hit.
                        None,
                    )
                    .await;
                if matches!(verdict, Ok((super::invoke::CallerVerdict::Absent, _))) {
                    let reason = match super::visible::recorded_visibility(server, tool_name) {
                        Some(super::visible::Visibility::Withheld(reason)) => reason,
                        _ => super::visible::Withholding::Lacked,
                    };
                    self.record_withheld(server, tool_name, reason, caller, session_id)
                        .await;
                    return self
                        .route_retry_to_origin_backend(id, tool_name, arguments, session_id, caller)
                        .await;
                }
                let server_name = server.to_owned();
                return Some(
                    self.invoke_named_backend_tool(
                        id,
                        &server_name,
                        tool_name,
                        arguments.clone(),
                        session_id,
                        caller,
                    )
                    .await,
                );
            }
            // A surfaced tool withheld from this caller answers exactly as a
            // name that matches no tool: the absent-name path below produces
            // the answer (MIK-8340). This is the one place its operator record
            // is written, best-effort.
            super::visible::Surfaced::Withheld(server, reason) => {
                self.record_withheld(server, tool_name, reason, caller, session_id)
                    .await;
            }
            super::visible::Surfaced::Absent => {}
        }
        self.route_retry_to_origin_backend(id, tool_name, arguments, session_id, caller)
            .await
    }

    /// Route a retry to the backend that opened the exchange, or `None` when
    /// the call is not a retry this gateway minted a continuation for.
    ///
    /// // A retry names the backend tool it continues, not `gateway_invoke`,
    /// // and a backend tool answers to its own name only where an operator
    /// // surfaced it. Routing this by name would refuse every honest retry on
    /// // an unpinned tool with the -32601 fallback below, so the backend comes
    /// // from the envelope the gateway itself minted. The name the client
    /// // presented is not trusted by being routed: it is checked against the
    /// // digest sealed in that same envelope before anything dispatches.
    /// //
    /// // Two meta-tools are left alone, and only two. `gateway_invoke` and
    /// // `gateway_execute` carry their own server and tool and route into
    /// // `invoke_tool`, where `redeem_retry` opens the same envelope: a retry
    /// // wrapped in either reaches the guard by its ordinary path, so routing
    /// // it from here would only open it twice.
    /// //
    /// // Every other meta-tool is answered by the gateway itself and never
    /// // enters that scope. Exempting the whole `gateway_` prefix therefore
    /// // let a retry naming one — `gateway_list_servers`, say — run as a fresh
    /// // call with its continuation never examined, which is the repeat the
    /// // envelope exists to prevent (MIK-7215). Such a retry is routed like
    /// // any other: the envelope names a backend, the presented name is not
    /// // that backend's tool, and the digest check refuses it downstream.
    pub(super) async fn route_retry_to_origin_backend(
        &self,
        id: RequestId,
        tool_name: &str,
        arguments: &Value,
        session_id: Option<&str>,
        caller: &MetaMcpCallerContext<'_>,
    ) -> Option<JsonRpcResponse> {
        if matches!(tool_name, "gateway_invoke" | "gateway_execute") {
            return None;
        }
        let server_name = match invoke::retry_origin_backend(&self.continuation, caller.retry)? {
            Ok(server) => server,
            Err(error) => return Some(error_response_preserving_status(id, &error)),
        };
        Some(
            self.invoke_named_backend_tool(
                id,
                &server_name,
                tool_name,
                arguments.clone(),
                session_id,
                caller,
            )
            .await,
        )
    }

    /// Dispatch a backend tool the client named directly, returning the
    /// backend's own result envelope untouched.
    ///
    /// `invoke_tool_with_source` already returns a complete MCP tools/call result
    /// (`{content, structuredContent?, isError}`) with output-schema
    /// enforcement applied. A tool called by its own name is a first-class
    /// tool to the client, so that envelope is returned verbatim: re-wrapping
    /// it via `wrap_tool_success` would stringify the whole envelope into a
    /// text block and drop `structuredContent`, which spec-compliant clients
    /// such as Open `WebUI` require when a tool advertises an `outputSchema`.
    pub(super) async fn invoke_named_backend_tool(
        &self,
        id: RequestId,
        server_name: &str,
        tool_name: &str,
        arguments: Value,
        session_id: Option<&str>,
        caller: &MetaMcpCallerContext<'_>,
    ) -> JsonRpcResponse {
        let invoke_args =
            admission::named_tool_envelope(server_name, tool_name, &arguments, caller);
        let mut chain = (ChainSource::NotEligible, None);
        let result = match self
            .invoke_tool_with_source(&invoke_args, session_id, caller)
            .await
        {
            Ok(invoke::SourcedOutcome::Live((content, source, upstream))) => {
                chain = (source, upstream);
                Ok(content)
            }
            // The lift's already-shaped answer: delivered unchanged (D8).
            Ok(invoke::SourcedOutcome::Stored(response)) => return response,
            Err(error) => Err(error),
        };
        // Native: the envelope verbatim. The dispatch's chain source rides on
        // a success only, as on `gateway_invoke` (A3 R5, MIK-8159).
        let declared = caller.input_capabilities;
        response_security::shape_meta_result(
            id,
            tool_name,
            result,
            ResultShape::Native,
            declared,
            chain,
        )
    }

    /// Handle `tools/call` — dispatch to the appropriate handler.
    ///
    /// Surfaced tool calls are intercepted before the meta-tool match arm and
    /// proxied directly to the owning backend via `gateway_invoke` semantics,
    /// giving callers transparent one-hop access to pinned tools.
    ///
    /// `api_key_name` — the name of the authenticated API key (for cost accounting).
    /// `agent_id` — optional caller agent identifier (OWASP ASI03).
    pub async fn handle_tools_call(
        &self,
        id: RequestId,
        tool_name: &str,
        arguments: Value,
        session_id: Option<&str>,
        caller: MetaMcpCallerContext<'_>,
    ) -> JsonRpcResponse {
        Box::pin(self.handle_tools_call_ref(
            id,
            tool_name,
            Cow::Owned(arguments),
            session_id,
            caller,
        ))
        .await
    }

    /// [`Self::handle_tools_call`] on arguments the caller may still own.
    ///
    /// MIK-8014: the HTTP and stdio request paths hand the request's own
    /// argument object down borrowed. Every tool arm reads it by reference,
    /// so the only branch that copies it is a task, which must store it.
    pub(crate) async fn handle_tools_call_ref(
        &self,
        id: RequestId,
        tool_name: &str,
        arguments: Cow<'_, Value>,
        session_id: Option<&str>,
        caller: MetaMcpCallerContext<'_>,
    ) -> JsonRpcResponse {
        // MIK-8150: a signed execution's nonce is given back here, once, after
        // every step has run or been refused, never at a step's refusal.
        let settle =
            (caller.signing).map(|context| (context, super::signing::nonce_principal(&caller)));
        // One visibility memo per call (MIK-8356): an entry with no request
        // scope of its own (a task worker, an in-process caller) still takes
        // one caller verdict and carries its resolution to dispatch. Inside
        // a transport's scope this reuses it.
        let response = super::visible::with_visibility_memo(Box::pin(
            self.handle_tools_call_unsettled(id, tool_name, arguments, session_id, caller),
        ))
        .await;
        if let Some((context, principal)) = settle {
            self.settle_nonce_refund(context, principal);
        }
        response
    }

    async fn handle_tools_call_unsettled(
        &self,
        id: RequestId,
        tool_name: &str,
        arguments: Cow<'_, Value>,
        session_id: Option<&str>,
        mut caller: MetaMcpCallerContext<'_>,
    ) -> JsonRpcResponse {
        // Operator exposure allow-list. Enforced ahead of the admin gate, not
        // beside it: a meta-tool hidden from `tools/list` but still executable is
        // security theatre, and the admin gate answering first would disclose the
        // tool's existence to the caller the allow-list is hiding it from.
        // `exposed_meta_tools` promises that an unlisted tool "is not callable
        // either"; names outside the governed set (surfaced and backend tools)
        // are unaffected. The refusal is worded exactly like the unrecognised-tool
        // fallback below: a reply confirming the tool exists would disclose it.
        if !self.meta_tool_exposure.is_exposed(tool_name) {
            // Built and returned exactly as the fallback below builds its
            // no-suggestion form, so the two answers are byte-identical (the
            // error type's "JSON-RPC error -32601: " prefix was itself a
            // disclosure). The did-you-mean hint is deliberately not reached:
            // a hidden tool name matches itself and would name it.
            return error_response_preserving_status(
                id,
                &crate::Error::json_rpc(-32601, format!("Unknown tool: {tool_name}")),
            );
        }
        // Answers without the requestState this gateway issued answer nothing
        // it asked: every tool refuses them, before any dispatch can repeat a
        // side effect.
        if let Err(error) = caller.retry.solicited_input_responses() {
            return error_response_preserving_status(id, &error);
        }
        if let Err(error) = caller.retry.refuse_on_playbook_run(tool_name) {
            return error_response_preserving_status(id, &error);
        }

        // Admin gate for the meta-tools that change the gateway for every
        // session, enforced HERE at the dispatcher.
        //
        // The router checks this too, and stdio marks its caller admin because
        // the client that spawned the process already holds whatever the
        // operator holds. Neither fact is why the check lives here: a gate at
        // one entry point is correct for every caller that exists today and
        // silently absent for the next one added, which is the shape that hid
        // the playbook defect. Placing it at the point of dispatch costs a
        // redundant comparison on the router path and removes the possibility.
        // Moving it here caught stdio passing a default non-admin context.
        // The same predicate `tools/list` filters with (`meta_tools_for`) and
        // the signing layer reads (`refused_before_dispatch`).
        if !CallerStanding::of_admin_flag(caller.is_admin).permits(tool_name) {
            return JsonRpcResponse::error(
                Some(id),
                -32600,
                format!("Tool '{tool_name}' requires admin access"),
            );
        }

        let confirmed_in_band =
            match destructive_confirmation_gate(&id, tool_name, &arguments, session_id, &caller)
                .await
            {
                GateOutcome::Refuse(response) => return *response,
                GateOutcome::RefuseUnasked(response) => {
                    self.release_unasked_nonce(&caller);
                    return *response;
                }
                GateOutcome::Proceed => false,
                GateOutcome::ProceedConfirmed => true,
            };

        // MIK-7698: nothing acts on a nonce the signing layer left unadmitted.
        if let Some(refusal) = self.refuse_unadmitted(&id, &caller) {
            return refusal;
        }
        // A capability account has no route-stage verdict, so its busy
        // custody is judged here for a task call (MIK-8428): after
        // admission/policy, before the transient answer below and before
        // any task or key. Sync calls skip it and gain no extra read. A
        // repeat of a key that already owns a task skips it too: it
        // serves stored output and must not be account-judged at intake
        // (`already_admitted` is read-only; `begin_task` re-decides).
        let repeated = caller.task.as_ref().is_some_and(|intent| {
            intent
                .executor
                .service
                .already_admitted(intent.request.borrow())
        });
        if caller.task.is_some() && !repeated {
            self.judge_capability_accounts_for_task(tool_name, &arguments, &caller, session_id)
                .await;
        }
        if let Some(answer) = Self::task_intake_transient(&caller, &id) {
            return answer;
        }
        if let Some(intent) = caller.task.take() {
            // A `require` backend's answer must be a checked chain (inc3 R2).
            if let Err(error) =
                self.refuse_chained_task(tool_name, &arguments, (caller.scope(), session_id))
            {
                return error_response_preserving_status(id, &error);
            }
            return self
                .begin_task(
                    id,
                    tool_name,
                    arguments.into_owned(),
                    intent,
                    (session_id, &caller),
                )
                .await;
        }

        // Straight to the shaped tail (MIK-8014 design item 2): the
        // `dispatch_below_gate` layer only builds this target.
        self.dispatch_below_gate_shaped(
            DispatchTarget {
                id,
                tool_name,
                arguments,
                session_id,
                caller: &caller,
            },
            ResultShape::Wrapped,
            confirmed_in_band,
        )
        .await
    }

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
    fn task_intake_transient(
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
        if super::visible::take_any_account_transient().is_none()
            && super::visible::take_any_transient_resolution_error().is_none()
        {
            return None;
        }
        caller.signing.inspect(|signing| signing.want_refund());
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
        };
        match executor.begin(intent, task, backend, call).await {
            Ok(BeginOutcome::Existing(held)) => {
                // MIK-8176 N1: delivered into this request's scope first, so
                // its holds are adopted before any decision; a refusal below
                // only drops this request's clones, and the row keeps the slot.
                let stored = held.deliver(super::sealed_hold::HoldSink::Scope);
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
                let held =
                    super::sealed_hold::Held::new(stored, super::sealed_hold::CarriedHolds::none());
                return self
                    .defer_or_serve_existing(id, tool_name, &targets, held, caller)
                    .await;
            }
            Ok(outcome) => outcome.into_response(id),
            Err(crate::gateway::task_service::ServiceError::AuditUnavailable) => {
                error_response_preserving_status(id, &crate::Error::AuditUnavailable)
            }
            Err(_) => JsonRpcResponse::error(Some(id), -32603, "task store unavailable"),
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
    pub(super) async fn defer_or_serve_existing(
        &self,
        id: RequestId,
        tool_name: &str,
        targets: &[crate::gateway::task_service::Target],
        held: super::sealed_hold::Held<crate::gateway::task_service::CommittedTask>,
        caller: &MetaMcpCallerContext<'_>,
    ) -> JsonRpcResponse {
        use crate::gateway::task_service::execution::BeginOutcome;

        // Collected before the walk: an iterator adapter held across its
        // awaits makes the dispatch future's `Send` bound not general enough.
        let walk: Vec<(&str, &str)> = targets
            .iter()
            .map(|target| (target.server.as_str(), target.tool.as_str()))
            .collect();
        if let Some(answer) = self.first_unproven(&id, tool_name, &walk, caller).await {
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
    pub(super) async fn first_unproven(
        &self,
        id: &RequestId,
        tool_name: &str,
        targets: &[(&str, &str)],
        caller: &MetaMcpCallerContext<'_>,
    ) -> Option<JsonRpcResponse> {
        // (server, account) resolved already in this walk: an account
        // resolved once is not resolved again.
        let mut resolved = std::collections::HashSet::new();
        for &(server, tool) in targets {
            // A target that mints nothing per caller is exempt (U2); every
            // other one (a managed account, or a per-caller mint, E7) proves
            // only by a live resolution below. There is no shortcut for an
            // outcome already read Live: a carried credential is taken above
            // first, so it saved nothing measurable (E10b, T4).
            if !self.mints_per_caller(server, tool) {
                continue;
            }
            if !resolved.insert((server.to_owned(), self.target_account(server, tool))) {
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
    pub(super) fn shape_repeat_fill(
        &self,
        id: RequestId,
        tool_name: &str,
        value: Value,
        caller: &MetaMcpCallerContext<'_>,
    ) -> JsonRpcResponse {
        let shape = if tool_name == "gateway_invoke"
            || self.surfaced_tools_map.unscoped(tool_name).is_none()
        {
            ResultShape::Wrapped
        } else {
            ResultShape::Native
        };
        response_security::shape_meta_result(
            id,
            tool_name,
            Ok(value),
            shape,
            caller.input_capabilities,
            (ChainSource::NotEligible, None),
        )
    }

    /// The dispatch tail below the confirmation gate, as the request thread
    /// takes it (it builds the target itself). Kept for tests.
    #[cfg(test)]
    pub(crate) async fn dispatch_below_gate(
        &self,
        id: RequestId,
        tool_name: &str,
        arguments: Cow<'_, Value>,
        session_id: Option<&str>,
        caller: &MetaMcpCallerContext<'_>,
        confirmed_in_band: bool,
    ) -> JsonRpcResponse {
        self.dispatch_below_gate_shaped(
            DispatchTarget {
                id,
                tool_name,
                arguments,
                session_id,
                caller,
            },
            ResultShape::Wrapped,
            confirmed_in_band,
        )
        .await
    }

    /// The same dispatch, answered with the tool's own result verbatim.
    ///
    /// One caller: the task worker, because a task settles on what the backend
    /// said and not on how a synchronous reply presents it (adapter design r3
    /// §4 — "result verbatim **including `isError: true`**"). The meta-tool
    /// wrapper below buries exactly that: it pretty-prints the result into a
    /// single text block, drops `structuredContent` for every tool without an
    /// output schema, and reads `isError` only from the payload's top level. It
    /// also hides an interim round — `resultType:
    /// "input_required"` inside a JSON string is not a claim the settlement
    /// classifier can read, so a question would be committed as an answer.
    ///
    /// Only this last step differs. The routing above is the identical call:
    /// the same direct-backend route, the same match arms, the same
    /// authorization, firewall, destructive, capability and signing contexts,
    /// and the same `error_response_preserving_status` on the error side.
    /// Settlement strips the internal HTTP-status key from that error itself.
    pub(crate) async fn dispatch_below_gate_native_result(
        &self,
        id: RequestId,
        tool_name: &str,
        arguments: Value,
        session_id: Option<&str>,
        caller: &MetaMcpCallerContext<'_>,
    ) -> JsonRpcResponse {
        self.dispatch_below_gate_shaped(
            DispatchTarget {
                id,
                tool_name,
                arguments: Cow::Owned(arguments),
                session_id,
                caller,
            },
            ResultShape::Native,
            // A task worker dispatches what was admitted on the request
            // thread; the confirmation, if there was one, was spent there and
            // this context carries no `requestState` to spend again.
            false,
        )
        .await
    }

    pub(super) async fn dispatch_below_gate_shaped_in_slot(
        &self,
        target: DispatchTarget<'_>,
        shape: ResultShape,
        confirmed_in_band: bool,
    ) -> JsonRpcResponse {
        let DispatchTarget {
            id,
            tool_name,
            arguments,
            session_id,
            caller,
        } = target;
        // T2.4: a call naming a backend tool directly — because an operator
        // surfaced it, or because it is a retry of an exchange this gateway
        // opened — is routed BEFORE the meta-tool match.
        //
        // Skipped for a retry the gate just redeemed: the envelope is a
        // single-use handle and the gate spent it, so routing this call by its
        // `requestState` would present an already-spent continuation to a
        // second consumer and the approved action would die as a stale retry.
        // A retry that reaches here confirmed is, by construction, ours.
        if !confirmed_in_band
            && let Some(response) = self
                .route_direct_backend_call(id.clone(), tool_name, &arguments, session_id, caller)
                .await
        {
            return response;
        }

        if let Some(execution) = caller.execution
            && let Err(error) =
                self.mark_management_dispatch(tool_name, &arguments, session_id, execution)
        {
            return error_response_preserving_status(id, &error);
        }

        // Only gateway_invoke can be chain-eligible; composites stay NotEligible.
        let (mut source, mut upstream) = (ChainSource::NotEligible, None);
        let result = match tool_name {
            "gateway_search" => self.code_mode_search(&arguments, session_id, caller).await,
            "gateway_execute" => self.code_mode_execute(&arguments, session_id, caller).await,
            "gateway_list_servers" => {
                self.revalidate_caller_slots(Self::proof_of(caller)).await;
                self.list_servers(caller, session_id).await
            }
            "gateway_list_tools" => self.list_tools(&arguments, session_id, caller).await,
            "gateway_search_tools" => self.search_tools(&arguments, session_id, caller).await,
            "gateway_invoke" => {
                let sourced = self
                    .invoke_tool_sourced(&arguments, session_id, caller)
                    .await;
                match sourced {
                    Ok(invoke::SourcedOutcome::Live((value, origin, chain))) => {
                        (source, upstream) = (origin, chain);
                        Ok(value)
                    }
                    // The lift's already-shaped answer: delivered unchanged (D8).
                    Ok(invoke::SourcedOutcome::Stored(response)) => return response,
                    Err(error) => Err(error),
                }
            }
            "gateway_get_stats" => self.get_stats(&arguments, caller.is_admin).await,
            "gateway_cost_report" => self.get_cost_report(&arguments, session_id, caller).await,
            "gateway_webhook_status" => self.webhook_status(),
            "gateway_run_playbook" => self.run_playbook(&arguments, caller).await,
            "gateway_kill_server" => self.kill_server(&arguments),
            "gateway_revive_server" => self.revive_server(&arguments),
            "gateway_list_disabled_capabilities" => {
                self.revalidate_caller_slots(Self::proof_of(caller)).await;
                self.list_disabled_capabilities(caller.scope(), session_id)
            }
            "gateway_set_profile" => self.set_profile(&arguments, session_id, caller.is_admin),
            "gateway_get_profile" => self.get_profile(session_id, caller.is_admin),
            "gateway_list_profiles" => self.list_profiles(),
            "gateway_set_state" => self.set_state(&arguments, session_id, caller.scope()),
            "gateway_reload_config" => self.reload_config().await,
            "gateway_reload_capabilities" => self.reload_capabilities().await,
            // A name that matches no tool is refused before any backend, so it
            // gives its signing nonce back (MIK-8340 A4, MIK-8150's rule). A
            // withheld surfaced name ends here too, so both answer alike.
            _ => {
                // `invoke::nonce_settle::ask_refund`, settled when the call returns.
                caller.signing.inspect(|signing| signing.want_refund());
                Err(self.no_such_meta_tool(tool_name, caller))
            }
        };

        // A discovery answer the canonical pass refused was scanned too.
        let scanned = matches!(result, Ok(_) | Err(crate::Error::ResponseFirewallRefused));
        let inspected = self.marks_discovery(tool_name, scanned);
        let (declared, chain) = (caller.input_capabilities, (source, upstream));
        let mut response =
            response_security::shape_meta_result(id, tool_name, result, shape, declared, chain);
        response.egress_scanned = inspected;
        response
    }
}

pub(super) fn task_backend_name(meta: &MetaMcp, tool_name: &str, arguments: &Value) -> String {
    if let Some(server) = meta.surfaced_tools_map.unscoped(tool_name) {
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
#[path = "stored_site5_tests.rs"]
mod stored_site5_tests;
