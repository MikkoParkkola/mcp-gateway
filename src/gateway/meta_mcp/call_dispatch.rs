// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MetaMcp` `tools/call` routing and the dispatch below the gate.

use crate::error::rpc_codes::{INVALID_REQUEST, METHOD_NOT_FOUND};
use std::borrow::Cow;
use std::ops::ControlFlow;

use super::dispatch_names::MetaArm;

use super::{
    Arc, CallerStanding, ChainSource, DispatchTarget, GateOutcome, JsonRpcResponse, MetaMcp,
    MetaMcpCallerContext, RequestId, ResultShape, Value, admission, destructive_confirmation_gate,
    error_response_preserving_status, invoke, response_security,
};

#[cfg(test)]
mod outcome_tests;
mod task_intake;

impl MetaMcp {
    /// Route a call that names a backend tool directly, or `None` when the
    /// name belongs to the meta-tool surface.
    ///
    /// Two ways a backend tool answers to its own name: an operator surfaced
    /// it, or the call is a retry whose origin the sealed envelope names.
    pub(super) async fn route_direct_backend_call(
        &self,
        target: &DispatchTarget<'_>,
    ) -> Option<JsonRpcResponse> {
        let (tool_name, session_id, caller) = (target.tool_name, target.session_id, target.caller);
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
                    let reason = match super::visible::memo::recorded_visibility(server, tool_name)
                    {
                        Some(super::visible::Visibility::Withheld(reason)) => reason,
                        _ => super::visible::Withholding::Lacked,
                    };
                    self.record_withheld(server, tool_name, reason, caller, session_id)
                        .await;
                    return self.route_retry_to_origin_backend(target).await;
                }
                let server_name = server.to_owned();
                return Some(self.invoke_named_backend_tool(target, &server_name).await);
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
        self.route_retry_to_origin_backend(target).await
    }

    /// Route a retry to the backend that opened the exchange, or `None` when
    /// the call is not a retry this gateway minted a continuation for.
    ///
    /// A retry names the backend tool it continues, not `gateway_invoke`,
    /// and a backend tool answers to its own name only where an operator
    /// surfaced it. Routing this by name would refuse every honest retry on
    /// an unpinned tool with the -32601 fallback below, so the backend comes
    /// from the envelope the gateway itself minted. The name the client
    /// presented is not trusted by being routed: it is checked against the
    /// digest sealed in that same envelope before anything dispatches.
    ///
    /// Two meta-tools are left alone, and only two. `gateway_invoke` and
    /// `gateway_execute` carry their own server and tool and route into
    /// `invoke_tool`, where `redeem_retry` opens the same envelope: a retry
    /// wrapped in either reaches the guard by its ordinary path, so routing
    /// it from here would only open it twice.
    ///
    /// Every other meta-tool is answered by the gateway itself and never
    /// enters that scope. Exempting the whole `gateway_` prefix therefore
    /// let a retry naming one — `gateway_list_servers`, say — run as a fresh
    /// call with its continuation never examined, which is the repeat the
    /// envelope exists to prevent (MIK-7215). Such a retry is routed like
    /// any other: the envelope names a backend, the presented name is not
    /// that backend's tool, and the digest check refuses it downstream.
    pub(super) async fn route_retry_to_origin_backend(
        &self,
        target: &DispatchTarget<'_>,
    ) -> Option<JsonRpcResponse> {
        if matches!(target.tool_name, "gateway_invoke" | "gateway_execute") {
            return None;
        }
        let server_name =
            match invoke::retry_origin_backend(&self.continuation, target.caller.retry)? {
                Ok(server) => server,
                Err(error) => {
                    return Some(error_response_preserving_status(target.id.clone(), &error));
                }
            };
        Some(self.invoke_named_backend_tool(target, &server_name).await)
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
        target: &DispatchTarget<'_>,
        server_name: &str,
    ) -> JsonRpcResponse {
        let (tool_name, caller) = (target.tool_name, target.caller);
        let invoke_args =
            admission::named_tool_envelope(server_name, tool_name, &target.arguments, caller);
        let trace_id = crate::gateway::trace::generate();
        let trace = Arc::<str>::from(trace_id.as_str());
        let sourced = self
            .invoke_tool_with_source(&invoke_args, target.session_id, caller, trace_id)
            .await;
        let (result, chain) = match live_or_stored(sourced) {
            ControlFlow::Continue(live) => live,
            // A stored answer carries its replay's trace, stamped where
            // `audit_replay` recorded it; a refused lift recorded nothing.
            ControlFlow::Break(stored) => return stored,
        };
        // Native: the envelope verbatim. The dispatch's chain source rides on
        // a success only, as on `gateway_invoke` (A3 R5, MIK-8159).
        let declared = caller.input_capabilities;
        response_security::shape_meta_result(
            target.id.clone(),
            tool_name,
            result,
            ResultShape::Native,
            declared,
            chain,
        )
        .with_invocation_trace(trace)
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
        let response = super::visible::memo::with_visibility_memo(Box::pin(
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
                &crate::Error::json_rpc(METHOD_NOT_FOUND, format!("Unknown tool: {tool_name}")),
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
                INVALID_REQUEST,
                format!("Tool '{tool_name}' requires admin access"),
            );
        }

        let confirmed_in_band =
            match destructive_confirmation_gate(&id, tool_name, &arguments, session_id, &caller)
                .await
            {
                GateOutcome::Refuse(response) => {
                    super::dispatch_log::note_round(super::dispatch_log::PreSend::Refused);
                    return *response;
                }
                GateOutcome::RefuseUnasked(response) => {
                    invoke::ask_refund(&caller); // MIK-8353 3d
                    super::dispatch_log::note_round(super::dispatch_log::PreSend::Refused);
                    return *response;
                }
                GateOutcome::Proceed => false,
                GateOutcome::ProceedConfirmed => true,
            };

        // MIK-7698: nothing acts on a nonce the signing layer left unadmitted.
        if let Some(refusal) = self.refuse_unadmitted(&id, &caller) {
            super::dispatch_log::note_round(super::dispatch_log::PreSend::Refused);
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
        // A web UI call never runs in a task worker: the worker is outside
        // the UI call's scope, so its confirm gate and send record would not
        // see it. Refused before the task exists.
        #[cfg(feature = "webui")]
        if caller.task.is_some() && crate::gateway::ui_call::refuses_task() {
            invoke::ask_refund(&caller);
            return error_response_preserving_status(id, &crate::gateway::ui_call::task_refused());
        }
        if let Some(intent) = caller.task.take() {
            // A `require` backend's answer must be a checked chain (inc3 R2).
            if let Err(error) =
                self.refuse_chained_task(tool_name, &arguments, (caller.scope(), session_id))
            {
                // The delivered refusal of the task submission.
                crate::gateway::delivery_facts::raise(
                    crate::gateway::delivery_facts::ResponseEffect::Refused,
                );
                return invoke::refused_submit_answer(&caller, id, &error);
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
            DispatchTarget::new(id, tool_name, arguments, session_id, &caller),
            ResultShape::Wrapped,
            confirmed_in_band,
        )
        .await
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
            DispatchTarget::new(id, tool_name, arguments, session_id, caller),
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
            DispatchTarget::new(id, tool_name, Cow::Owned(arguments), session_id, caller),
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
        // T2.4: a call naming a backend tool directly — because an operator
        // surfaced it, or because it is a retry of an exchange this gateway
        // opened — is routed BEFORE the meta-tool match.
        //
        // Skipped for a retry the gate just redeemed: the envelope is a
        // single-use handle and the gate spent it, so routing this call by its
        // `requestState` would present an already-spent continuation to a
        // second consumer and the approved action would die as a stale retry.
        // A retry that reaches here confirmed is, by construction, ours.
        if !confirmed_in_band && let Some(response) = self.route_direct_backend_call(&target).await
        {
            return response;
        }
        let DispatchTarget {
            id,
            tool_name,
            arguments,
            session_id,
            caller,
        } = target;

        if let Some(execution) = caller.execution
            && let Err(error) =
                self.mark_management_dispatch(tool_name, &arguments, session_id, execution)
        {
            return error_response_preserving_status(id, &error);
        }

        // Only gateway_invoke can be chain-eligible; composites stay NotEligible.
        let (mut source, mut upstream) = (ChainSource::NotEligible, None);
        // Only `gateway_invoke` answers for one invocation.
        let mut trace = None;
        let result = match MetaArm::parse(tool_name) {
            Some(MetaArm::Search) => self.code_mode_search(&arguments, session_id, caller).await,
            // Composites are unvouched at their arm, before any step runs: a
            // plan that runs no step delivers nothing of this request's either.
            Some(MetaArm::Execute) => {
                crate::gateway::delivery_facts::unvouched();
                let result = self.code_mode_execute(&arguments, session_id, caller).await;
                crate::gateway::delivery_facts::composite_ended(result.as_ref().err());
                result
            }
            Some(MetaArm::ListServers) => {
                self.revalidate_caller_slots(Self::proof_of(caller)).await;
                self.list_servers(caller, session_id).await
            }
            Some(MetaArm::ListTools) => self.list_tools(&arguments, session_id, caller).await,
            Some(MetaArm::SearchTools) => self.search_tools(&arguments, session_id, caller).await,
            Some(MetaArm::Invoke) => {
                let trace_id = crate::gateway::trace::generate();
                let invocation = Arc::<str>::from(trace_id.as_str());
                #[cfg(feature = "webui")]
                crate::gateway::ui_call::note_trace(&trace_id);
                let invoked = self
                    .invoke_tool_sourced(&arguments, session_id, caller, trace_id)
                    .await;
                // This path skips the step funnel: the task worker's round
                // still learns whether it was refused before its backend.
                super::dispatch_log::note_round(invoked.pre_send);
                let sourced = invoked.outcome;
                match live_or_stored(sourced) {
                    ControlFlow::Continue((result, chain)) => {
                        (source, upstream) = chain;
                        trace = Some(invocation);
                        result
                    }
                    // Traced by `audit_replay`, as on the named-tool path.
                    ControlFlow::Break(stored) => return stored,
                }
            }
            Some(MetaArm::GetStats) => self.get_stats(&arguments, caller.is_admin).await,
            Some(MetaArm::CostReport) => self.get_cost_report(&arguments, session_id, caller).await,
            Some(MetaArm::WebhookStatus) => self.webhook_status(),
            Some(MetaArm::RunPlaybook) => {
                crate::gateway::delivery_facts::unvouched();
                let result = self.run_playbook(&arguments, caller).await;
                crate::gateway::delivery_facts::composite_ended(result.as_ref().err());
                result
            }
            Some(MetaArm::KillServer) => self.kill_server(&arguments),
            Some(MetaArm::ReviveServer) => self.revive_server(&arguments),
            Some(MetaArm::ListDisabledCapabilities) => {
                self.revalidate_caller_slots(Self::proof_of(caller)).await;
                self.list_disabled_capabilities(caller.scope(), session_id)
            }
            Some(MetaArm::SetProfile) => self.set_profile(&arguments, session_id, caller.is_admin),
            Some(MetaArm::GetProfile) => self.get_profile(session_id, caller.is_admin),
            Some(MetaArm::ListProfiles) => self.list_profiles(),
            Some(MetaArm::SetState) => self.set_state(&arguments, session_id, caller.scope()),
            Some(MetaArm::ReloadConfig) => self.reload_config().await,
            Some(MetaArm::ReloadCapabilities) => self.reload_capabilities().await,
            // A name that matches no tool is refused before any backend, so it
            // gives its signing nonce back (MIK-8340 A4, MIK-8150's rule). A
            // withheld surfaced name ends here too, so both answer alike.
            None => {
                // Settled when the call returns.
                invoke::ask_refund(caller);
                super::dispatch_log::note_round(super::dispatch_log::PreSend::Refused);
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
        response.invocation_trace = trace;
        response
    }
}

/// A dispatch's result and the chain it may carry.
type Chain = (ChainSource, Option<Arc<crate::protocol::UpstreamChain>>);

/// Split a sourced invocation (MIK-8498 DISPATCH.2): a live result goes on to
/// be shaped with its chain source, which only a success carries (A3 R5); an
/// error keeps the default, ineligible chain; a lift's stored answer is
/// already shaped and is delivered unchanged (D8).
fn live_or_stored(
    sourced: crate::Result<invoke::SourcedOutcome>,
) -> ControlFlow<JsonRpcResponse, (crate::Result<Value>, Chain)> {
    match sourced {
        Ok(invoke::SourcedOutcome::Live((value, source, upstream))) => {
            ControlFlow::Continue((Ok(value), (source, upstream)))
        }
        Ok(invoke::SourcedOutcome::Stored(response)) => ControlFlow::Break(response),
        Err(error) => ControlFlow::Continue((Err(error), (ChainSource::NotEligible, None))),
    }
}
