// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MetaMcp` `tools/call` routing and the dispatch below the gate.

use std::borrow::Cow;

use super::{
    Arc, CallerStanding, ChainSource, DispatchTarget, Error, GateOutcome, JsonRpcResponse, MetaMcp,
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
        if let Some(server_name) = self.surfaced_tools_map.get(tool_name) {
            let server_name = server_name.clone();
            // A tool the catalogue will not disclose must not answer to its
            // own name either: unlisted-but-invocable is the same defect as
            // listed-but-refused, read the other way round. Worded like the
            // unrecognised-tool fallback so the refusal does not confirm the
            // existence of something the gateway declined to publish.
            if self.surfaced_schema_withheld(&server_name, tool_name) {
                return Some(error_response_preserving_status(
                    id,
                    &Error::json_rpc(-32601, format!("Unknown tool: {tool_name}")),
                ));
            }
            // Nor a surfaced tool this caller could not invoke (A3).
            if let Some(absent) =
                self.withheld_surfaced(&server_name, tool_name, caller, session_id)
            {
                return Some(error_response_preserving_status(id, &absent));
            }
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
    /// `invoke_tool` already returns a complete MCP tools/call result
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
        match self.invoke_tool(&invoke_args, session_id, caller).await {
            Ok(content) => JsonRpcResponse::success_serialized(id, content),
            Err(e) => error_response_preserving_status(id, &e),
        }
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
        let response = Box::pin(
            self.handle_tools_call_unsettled(id, tool_name, arguments, session_id, caller),
        )
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
        if let Some(intent) = caller.task.take() {
            // A `require` backend's answer must be a checked chain (inc3 R2).
            if let Err(error) = self.refuse_chained_task(tool_name, &arguments) {
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

        self.dispatch_below_gate(
            id,
            tool_name,
            arguments,
            session_id,
            &caller,
            confirmed_in_band,
        )
        .await
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

        let task = crate::gateway::task_service::Task::create_at(
            tool_name,
            chrono::Utc::now(),
            intent.options,
        );
        let backend = task_backend_name(self, tool_name, &arguments);
        let executor = Arc::clone(&intent.executor);
        // #2450: a repeat is answered from the stored task, so the policy a
        // sync replay passes runs first. A fresh task is checked by its worker.
        let policy_arguments = arguments.clone();
        let call = crate::gateway::task_service::TaskCall {
            tool: tool_name.to_owned(),
            arguments,
        };
        match executor.begin(intent, task, backend, call).await {
            Ok(BeginOutcome::Existing(stored)) => {
                // The request's own policy, then the calls that produced the
                // stored result (R3.2): both must hold before it goes out.
                if let Err(error) = self.check_task_admission_policy(
                    caller,
                    tool_name,
                    &policy_arguments,
                    session_id,
                ) {
                    return error_response_preserving_status(id, &error);
                }
                // The token rides where the current request's own check reads it.
                let attestation = if tool_name == "gateway_invoke" {
                    policy_arguments.get("attestation").and_then(Value::as_str)
                } else {
                    caller.retry.attestation.as_deref()
                };
                self.refuse_stored_delivery(&id, &stored, attestation, session_id, caller)
                    .unwrap_or_else(|| BeginOutcome::Existing(stored).into_response(id))
            }
            Ok(outcome) => outcome.into_response(id),
            Err(_) => JsonRpcResponse::error(Some(id), -32603, "task store unavailable"),
        }
    }

    /// The dispatch tail below the confirmation gate. The request thread and
    /// the task worker call the same function; there is no parallel handler.
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
            "gateway_list_servers" => self.list_servers(caller, session_id).await,
            "gateway_list_tools" => self.list_tools(&arguments, session_id, caller).await,
            "gateway_search_tools" => self.search_tools(&arguments, session_id, caller).await,
            "gateway_invoke" => {
                let sourced = self
                    .invoke_tool_sourced(&arguments, session_id, caller)
                    .await;
                sourced.map(|(value, origin, chain)| {
                    (source, upstream) = (origin, chain);
                    value
                })
            }
            "gateway_get_stats" => self.get_stats(&arguments, caller.is_admin).await,
            "gateway_cost_report" => self.get_cost_report(&arguments, session_id, caller).await,
            "gateway_webhook_status" => self.webhook_status(),
            "gateway_run_playbook" => self.run_playbook(&arguments, caller).await,
            "gateway_kill_server" => self.kill_server(&arguments),
            "gateway_revive_server" => self.revive_server(&arguments),
            "gateway_list_disabled_capabilities" => {
                self.list_disabled_capabilities(caller.scope(), session_id)
            }
            "gateway_set_profile" => self.set_profile(&arguments, session_id, caller.is_admin),
            "gateway_get_profile" => self.get_profile(session_id, caller.is_admin),
            "gateway_list_profiles" => self.list_profiles(),
            "gateway_set_state" => self.set_state(&arguments, session_id, caller.scope()),
            "gateway_reload_config" => self.reload_config().await,
            "gateway_reload_capabilities" => self.reload_capabilities().await,
            _ => Err(self.no_such_meta_tool(tool_name, caller)),
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
    if let Some(server) = meta.surfaced_tools_map.get(tool_name) {
        return server.clone();
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
