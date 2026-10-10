// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Stdio request dispatch: the relay, tools/call, signing, parsing and the caller context (moved from `server/mod.rs`, MIK-8144).

use std::sync::Arc;

use tracing::debug;

use super::Gateway;
use super::StdioNonce;
use super::stdio_route_stage::RouteStage;
use super::stdio_single::InputSanitizing;
use super::{
    STDIO_CREDENTIAL_PRINCIPAL, StdioClient, StdioTelemetry, stdio_catalogue, stdio_delivery,
    stdio_routing_keys_only, stdio_take_merged_client_meta, stdio_tasks,
};
use crate::gateway::authz::ToolPolicyAuthorizer;
use crate::gateway::meta_mcp::{InvokeScope, MetaMcp, MetaMcpCallerContext};

impl Gateway {
    #[expect(
        clippy::too_many_lines,
        reason = "one dispatch path; the telemetry-guard scope is part of it"
    )]
    pub(super) async fn dispatch_relay_scoped(
        meta_mcp: &Arc<MetaMcp>,
        tool_policy: &Arc<crate::security::ToolPolicy>,
        _mtls_policy: &Arc<crate::mtls::MtlsPolicy>,
        mut request: serde_json::Value,
        client: StdioClient<'_>,
        protocol_telemetry_sink: &StdioTelemetry,
    ) -> Option<stdio_delivery::StdioAnswer> {
        // Borrowed views throughout: a refused request is never copied.
        // Ownership is taken once, after admission, where it executes.
        use super::super::router::helpers::extract_tools_call_params_ref;
        use crate::protocol::JsonRpcResponse;

        let session_id = client.session_id;
        let prepared = Self::prepare_signing(meta_mcp, &mut request, client.sanitize);
        let (mut signing_context, chain_nonce) = match prepared {
            Ok(prepared) => prepared,
            Err(response) => return Some(stdio_delivery::StdioAnswer::Built(response)),
        };

        // Scoped so the guard is gone before the first await below: see
        // [`StdioTelemetry`].
        let parsed = {
            let mut sink = protocol_telemetry_sink
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Self::parse_and_observe(&request, session_id, sink.as_mut())
        };
        let (id, method, params, request_shape) = match parsed {
            Ok(parsed) => parsed,
            Err(early) => return early.map(stdio_delivery::StdioAnswer::Built),
        };

        let (external_tool, response_targets) = {
            // Response targets are derived here, before dispatch, so live backend
            // state cannot move an accepted call's provenance. The mapping is fed
            // the routing keys alone (same servers, tools, sort, dedup and
            // discovery handling), never a copy of the call arguments.
            // Declared out here: the targets borrow it past the branch.
            let routing_keys;
            let (external_tool, backend_targets) = if method == "tools/call" {
                let empty_arguments = serde_json::Value::Object(serde_json::Map::new());
                let (tool, arguments) = extract_tools_call_params_ref(params);
                routing_keys = stdio_routing_keys_only(arguments.unwrap_or(&empty_arguments));
                (
                    tool.to_string(),
                    super::super::router::backend_tool_targets_for_call(
                        meta_mcp,
                        tool,
                        &routing_keys,
                    ),
                )
            } else {
                (method.clone(), Vec::new())
            };
            let response_targets = super::super::meta_mcp::response_security::meta_response_targets(
                &external_tool,
                &backend_targets,
            );
            (external_tool, response_targets)
        };
        let policy = ToolPolicyAuthorizer { tool_policy };
        let scope = InvokeScope::stdio(&policy);
        let (mut response, execution) = if method == "tools/call" {
            // D3-a: one grant-decision slot spans signing, admission and dispatch.
            super::super::meta_mcp::grant_audit::slot_rpc(
                meta_mcp.transparency_logger.as_ref(),
                id.clone(),
                Box::pin(Self::dispatch_tools_call(
                    meta_mcp,
                    tool_policy,
                    &mut request,
                    id,
                    client,
                    &mut signing_context,
                    &request_shape,
                )),
            )
            .await
        } else {
            (
                match method.as_str() {
                    // 2026-07-28 MUST, answered without a handshake: on stdio it is
                    // also the backward-compatibility probe. It lists 2026-07-28 when
                    // `server.modern_protocol` was on at stdio start (MIK-7217.STDIO.1);
                    // a batch is a legacy shape and always gets the legacy list.
                    "server/discover" => stdio_tasks::advertised(
                        client.tasks,
                        JsonRpcResponse::success_serialized(
                            id,
                            meta_mcp.discover_document(client.modern),
                        ),
                    ),
                    "initialize" => stdio_tasks::advertised(
                        client.tasks,
                        meta_mcp.handle_initialize(
                            id,
                            params,
                            Some(session_id),
                            None,
                            request_shape.era(),
                            scope,
                        ),
                    ),
                    m @ ("tasks/get" | "tasks/update" | "tasks/cancel") => {
                        let retry = crate::protocol::mrtr::RetryFields::from_params(params);
                        let caller = Self::build_stdio_caller_context(
                            true,
                            None,
                            &policy,
                            &retry,
                            &request_shape,
                            client,
                        );
                        let shape = &request_shape;
                        stdio_tasks::serve(client.tasks, m, id, params, shape, &caller, session_id)
                            .await
                    }
                    "tools/list" => {
                        meta_mcp.handle_tools_list_with_params(id, params, Some(session_id), scope)
                    }
                    m if stdio_catalogue::METHODS.contains(&m) => {
                        stdio_catalogue::dispatch(meta_mcp, m, id, params).await
                    }
                    "logging/setLevel" => meta_mcp.handle_logging_set_level(id, params).await,
                    "ping" => JsonRpcResponse::success(id, serde_json::json!({})),
                    other => {
                        debug!(method = %other, "stdio: unknown method");
                        let message = format!("Method not found: {other}");
                        JsonRpcResponse::error(Some(id), -32601, message)
                    }
                },
                None,
            )
        };

        // As `POST /mcp` does: shaped before signing, receipts stamped to match.
        let stamps = if request_shape.era() == crate::protocol::meta::Era::Modern {
            super::super::router::shape_modern_response(&mut response, &method)
        } else {
            super::super::meta_mcp::invoke::relay::GatewayStamps::Legacy
        };
        let chain_source = response.chain_source;
        let mut response = meta_mcp.finalize_content(
            response,
            &super::super::meta_mcp::response_security::ResponseDeliveryContext {
                method: &method,
                targets: &response_targets,
                correlation: super::super::meta_mcp::response_security::ResponseCorrelation {
                    session_id,
                    caller: "stdio",
                    external_server: "gateway",
                    external_tool: &external_tool,
                    subject: None,
                },
                signing: signing_context.as_ref(),
                chain_source,
                chain_nonce: chain_nonce.as_deref(),
            },
        );
        meta_mcp.release_unsent_hold(&mut response).await; // MIK-8131
        // MIK-7887.RECEIPT.4: the receipt describes the delivered answer, with
        // the stamps its era got; the judge can only replace the answer.
        {
            let shape = super::super::meta_mcp::invoke::relay::AnswerShape::of(&external_tool);
            meta_mcp.rebuild_receipt_from_final(response.result.as_ref(), stamps, shape);
        }
        // MIK-7920: recorded after the judge, then settled, by the caller
        // (`judge_and_commit`), as `POST /mcp` does.
        Some(stdio_delivery::StdioAnswer::finalized(
            response,
            external_tool,
            execution,
            signing_context,
        ))
    }

    /// The intake `/mcp` runs (`router::handlers::dispatch_intake`), in its
    /// order: capture the signing envelope, take the chain nonce, sanitize,
    /// restore, then refuse a malformed nonce early. Sanitizing between
    /// capture and restore means nothing that judges the signature or the
    /// shape reads bytes the sanitizer would have changed (route-check-parity
    /// P3, MIK-8149.REQFW.2).
    fn prepare_signing(
        meta_mcp: &Arc<MetaMcp>,
        request: &mut serde_json::Value,
        sanitize: InputSanitizing,
    ) -> std::result::Result<
        (
            Option<super::super::meta_mcp::signing::SigningInvocationContext>,
            Option<String>,
        ),
        serde_json::Value,
    > {
        use super::super::meta_mcp::signing::wire_error_message;
        use crate::protocol::JsonRpcResponse;
        // A bad chain nonce keeps the caller's id; a bad envelope has none.
        let raw_id = crate::protocol::mrtr::raw_request_id(request);
        let refuse = |id, error: &crate::Error| {
            JsonRpcResponse::error(id, error.to_rpc_code(), wire_error_message(error))
                .to_value_lossy()
        };
        let mut signing_context = meta_mcp.signing_enabled().then(|| {
            super::super::meta_mcp::signing::SigningInvocationContext::capture_scoped(
                request,
                meta_mcp.signing_scope(),
            )
        });
        let chain_nonce = crate::protocol::mrtr::take_chain_nonce(request)
            .map_err(|error| refuse(raw_id.clone(), &error))?;
        if sanitize == InputSanitizing::On {
            *request =
                crate::security::sanitize::sanitize_json_value(request).map_err(|error| {
                    JsonRpcResponse::error(None, -32600, error.to_string()).to_value_lossy()
                })?;
        }
        if let Some(context) = signing_context.as_mut() {
            context
                .restore(request)
                .map_err(|error| refuse(None, &error))?;
        }
        if let Some(context) = signing_context.as_ref() {
            context
                .refuse_malformed_nonce_early()
                .map_err(|error| refuse(raw_id, &error))?;
        }
        Ok((signing_context, chain_nonce))
    }

    /// Parse, classify and durably observe one inbound stdio request.
    ///
    /// `Err(None)` means no response is due (a notification); `Err(Some(_))`
    /// carries an already-serialized error response.
    fn parse_and_observe<'r>(
        request: &'r serde_json::Value,
        session_id: &str,
        protocol_telemetry_sink: Option<
            &mut crate::protocol_revision_telemetry::DurableTelemetrySink,
        >,
    ) -> std::result::Result<
        (
            crate::protocol::RequestId,
            String,
            Option<&'r serde_json::Value>,
            crate::protocol::meta::RequestShape,
        ),
        Option<serde_json::Value>,
    > {
        use super::super::router::helpers::parse_request_ref;
        use crate::protocol::JsonRpcResponse;

        let (id, method, params) = match parse_request_ref(request) {
            Ok((id, method, params)) => (id, method.to_string(), params),
            Err(response) => return Err(Some(response.to_value_lossy())),
        };

        // NFR.OBS.1. Recorded here, above every early return below, so a
        // stdio session is observed on the same terms an HTTP one is. Stdio
        // carries no headers, so the transport declares no revision and a
        // modern request can only have sourced its own from `_meta`.
        //
        // The same classification also controls modern explicit-key admission.
        let request_shape = crate::protocol::meta::classify_and_observe(
            &method,
            params,
            None,
            // Stdio carries no header, so the revision this session negotiated
            // at `initialize` is the only thing a later legacy request can be
            // sourced to. `None` until the handshake happens, which is what
            // keeps the pre-handshake record at `absent`/`none`.
            crate::protocol_revision_telemetry::session_negotiated_revision(Some(session_id)),
        );
        Self::observe_stdio_inbound(
            request,
            params,
            &method,
            session_id,
            protocol_telemetry_sink,
        );

        // ADR-014 §4, the stdio half. Stdio classifies the same body HTTP does,
        // so it declares a level the same way and gets the same filter -- one
        // policy, not one per transport. This runs inside the sink installed by
        // `dispatch_streaming_notifications`.
        crate::transport::notification_sink::set_request_log_level(
            request_shape.declared_log_level(),
        );

        // Notifications have no id — send no response
        if method.starts_with("notifications/") {
            debug!(notification = %method, "stdio: notification (no response)");
            return Err(None);
        }

        // Requests must have an id
        let Some(id) = id else {
            let resp = JsonRpcResponse::error(None, -32600, "Missing id");
            return Err(Some(resp.to_value_lossy()));
        };

        Ok((id, method, params, request_shape))
    }

    /// Handle `tools/call`: policy, signing, admission/replay, then dispatch.
    ///
    /// Ownership of `arguments` is taken only past every refusal — signing,
    /// nonce, admission, replay — because only an executing call needs to
    /// own its payload. `params` is re-derived from `request` here (already
    /// validated by the caller) so the immutable borrow it needs can end
    /// before the one branch below that needs `request` mutably.
    /// Build the stdio-path `MetaMcpCallerContext`, split out of
    /// [`Self::dispatch_tools_call`] purely to keep that function under the
    /// line budget — every field and its rationale are unchanged.
    pub(super) fn build_stdio_caller_context<'a>(
        is_modern: bool,
        protocol_revision: Option<&'a str>,
        stdio_authorizer: &'a crate::gateway::authz::ToolPolicyAuthorizer<'a>,
        retry: &'a crate::protocol::mrtr::RetryFields,
        request_shape: &crate::protocol::meta::RequestShape,
        client: StdioClient<'a>,
    ) -> MetaMcpCallerContext<'a> {
        MetaMcpCallerContext {
            // Filled after the route stage, by the task intent, when the
            // session serves `tasks/*` (its store is open) and the call asked
            // for a task; X14 has decided a destructive one before that.
            task: None,
            execution: None,
            signing: None,
            is_modern,
            protocol_revision,
            credential_principal: Some(STDIO_CREDENTIAL_PRINCIPAL),
            authentication: crate::gateway::meta_mcp::Authentication::Authenticated,
            credential_kind: crate::security::audit::CredentialKind::LocalTransport,
            authorizer: stdio_authorizer,
            // Stdio has no network surface: the client SPAWNED
            // this process and holds what the operator holds.
            // Withholding admin would disarm the single-user setup
            // the origin gate protects, and protect nothing.
            //
            // Explicit since the admin gate moved to the
            // dispatcher: it previously lived on the HTTP path
            // alone, so stdio was never checked and the default
            // non-admin context went unnoticed.
            is_admin: true,
            surface_request: crate::gateway::recovery::SurfaceRequest::Configured,
            // MRTR.9 declares capabilities per request, in the same `_meta`
            // this shape was classified from, so a modern call is read there.
            //
            // A legacy or malformed shape carries no `_meta` to read, and on a
            // session transport that does not mean the client declared
            // nothing — it declared once, on the handshake. Falling back to it
            // is what lets a legacy stdio client be asked for the input it
            // announced; the bridge still refuses anything the handshake did
            // not name.
            input_capabilities: if is_modern {
                request_shape.declared_capabilities()
            } else {
                client.handshake_capabilities
            },
            retry,
            api_key_name: None,
            agent_id: None,
            agent_declared: None,
            grant_subject: None,
            verified_identity: None,
            // The one client this process serves, for binding continuations.
            stdio_nonce: Some(StdioNonce::process()),
            caller_key: None,
            // Same `RequestShape` the `initialize` arm advertises against.
            era: request_shape.era(),
            // The serve loop's own channel: a stdio client reads the same
            // pipe an outbound request is written to, so it can be asked.
            // Non-serve-loop callers still pass `NoClientChannel`.
            channel: client.channel,
            // stdio speaks to one process over two pipes and
            // has no elicitation channel: there is no operator
            // this transport can reach, so a destructive call
            // it cannot confirm is refused rather than asked
            // about. Not "found no session" -- no asker can
            // exist here at all.
            confirmation:
                crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
        }
    }

    /// Long by construction: the single place a `tools/call` is admitted,
    /// dispatched and accounted for, and splitting it would put the policy
    /// checks and the outcome they gate in different functions.
    #[expect(clippy::too_many_lines, reason = "one admission path, kept whole")]
    async fn dispatch_tools_call(
        meta_mcp: &Arc<MetaMcp>,
        tool_policy: &Arc<crate::security::ToolPolicy>,
        request: &mut serde_json::Value,
        id: crate::protocol::RequestId,
        client: StdioClient<'_>,
        signing_context: &mut Option<super::super::meta_mcp::signing::SigningInvocationContext>,
        request_shape: &crate::protocol::meta::RequestShape,
    ) -> (
        crate::protocol::JsonRpcResponse,
        Option<super::super::meta_mcp::admission::SyncLease>,
    ) {
        use super::super::router::helpers::{
            client_meta_insert_required, extract_tools_call_params_ref, merge_client_meta_ref,
        };
        use crate::protocol::JsonRpcResponse;

        let session_id = client.session_id;
        let empty_arguments = serde_json::Value::Object(serde_json::Map::new());
        let mut execution = None;
        let response = 'tool_call: {
            let params = request.get("params");
            let (tool_name, arguments) = extract_tools_call_params_ref(params);
            let is_meta_tool = meta_mcp.exposes_meta_tool(tool_name);
            let tool_name = tool_name.to_string();

            // The tool policy is applied at the dispatch chokepoint via the
            // authorizer below, not here. The inline check this replaces ran
            // for `gateway_invoke` alone, so a stdio playbook or code-mode
            // step reached a backend with no policy check at all.
            let stdio_authorizer = crate::gateway::authz::ToolPolicyAuthorizer {
                tool_policy: tool_policy.as_ref(),
            };

            let retry = crate::protocol::mrtr::RetryFields::from_params(params);
            // Read before the merge below moves `_meta` out of the request.
            let task_member = params.and_then(|params| params.get("task")).cloned();
            let wants_task = task_member.is_some();
            let is_modern = matches!(
                request_shape,
                crate::protocol::meta::RequestShape::Modern(_)
            );
            if matches!(
                request_shape,
                crate::protocol::meta::RequestShape::Malformed { .. }
            ) {
                break 'tool_call JsonRpcResponse::error(
                    Some(id),
                    -32602,
                    "Malformed protocol metadata",
                );
            }
            // MIK-7272.SUB.4 §P3 (#528): the same -32602 refusal route 1
            // gives at `router/handlers.rs`. An unusable retry field must not
            // run on as an unprotected fresh call: the caller believes it has
            // replay protection it does not have, and for a destructive tool
            // that is the duplicate side effect it asked to be spared.
            if retry.is_malformed() {
                break 'tool_call JsonRpcResponse::error(
                    Some(id),
                    -32602,
                    format!("malformed request fields: {}", retry.malformed.join(", ")),
                );
            }
            // Verified evidence only: stdio echoes no header, so the session's
            // negotiated revision is the whole reading. The body is not
            // consulted — `params.protocolVersion` is not a `tools/call` field.
            let protocol_revision_owned = crate::protocol::meta::cache_protocol_revision(
                request_shape,
                None,
                crate::protocol_revision_telemetry::session_negotiated_revision(Some(session_id)),
            )
            .map(str::to_owned);
            // The canonical merge, still ahead of everything that reads the
            // arguments — signing, policy, nonce, admission — and now below
            // the two things that need the request whole: the retry fields
            // read `params._meta`, which is exactly the subtree the owning
            // branch moves out, and the shape classification already
            // observed it.
            //
            // The borrowed form still answers the four cases where the
            // merge would insert nothing by aliasing the caller's tree.
            // Where it would insert, the copy it makes is the whole payload
            // and the whole metadata, so the dispatcher spends the
            // ownership it already has instead: same insertion, same
            // precedence, moved rather than copied.
            let arguments = if client_meta_insert_required(arguments, params, is_meta_tool) {
                std::borrow::Cow::Owned(stdio_take_merged_client_meta(request))
            } else {
                merge_client_meta_ref(arguments.unwrap_or(&empty_arguments), params, is_meta_tool)
            };
            // X14's granted retry fields, when it grants: declared ahead of
            // the caller context that borrows them.
            let granted;
            let mut caller = Self::build_stdio_caller_context(
                is_modern,
                protocol_revision_owned.as_deref(),
                &stdio_authorizer,
                &retry,
                request_shape,
                client,
            );
            // The signing nonce is admitted before the route stage, so a bad
            // nonce is refused without paying for the payload
            // (MIK-7377.SIGNING.5 row 40); a call the route stage refuses
            // gives it back below (lead ruling, P3).
            if let Some(context) = signing_context.as_mut()
                && let Err(error) = meta_mcp.prepare_signing_for_call(
                    context,
                    &tool_name,
                    arguments.as_ref(),
                    Some(session_id),
                    &caller,
                )
            {
                break 'tool_call JsonRpcResponse::gateway_error(
                    Some(id),
                    error.to_rpc_code(),
                    super::super::meta_mcp::signing::wire_error_message(&error),
                );
            }
            caller.signing = signing_context.as_ref();
            // The route stage `/mcp` runs, in its order: authorize, request
            // firewall, X14 (route-check-parity P3). A refusal here took no
            // key, lease or task, and gives back the nonce admitted above.
            match Self::stdio_route_stage(
                meta_mcp,
                &id,
                (&tool_name, arguments.as_ref(), task_member.as_ref()),
                &caller,
                client,
            )
            .await
            {
                RouteStage::Answer(answer) => {
                    meta_mcp.release_unasked_nonce(&caller);
                    break 'tool_call answer;
                }
                RouteStage::Proceed(Some(fields)) => {
                    granted = fields;
                    caller.retry = &granted;
                }
                RouteStage::Proceed(None) => {}
            }
            if wants_task && let Some(tasks) = client.tasks {
                match stdio_tasks::task_intent(
                    tasks,
                    &id,
                    &tool_name,
                    &arguments,
                    &caller,
                    request_shape,
                    session_id,
                ) {
                    Ok(intent) => caller.task = intent,
                    Err(refusal) => break 'tool_call *refusal,
                }
            }
            let admission = meta_mcp.admit_meta_sync(
                super::super::meta_mcp::AdmissionOwner::local_operator(),
                &caller,
                &tool_name,
                arguments.as_ref(),
                Some(session_id),
                &id,
            );
            execution = match admission {
                Ok(super::super::meta_mcp::admission::SyncAdmission::Unprotected) => None,
                Ok(super::super::meta_mcp::admission::SyncAdmission::Owned(lease)) => Some(lease),
                Ok(super::super::meta_mcp::admission::SyncAdmission::Replay(response, audit)) => {
                    // #2480: a replay is a delivered call, recorded as its first run was.
                    let (args, session) = (arguments.as_ref(), Some(session_id));
                    break 'tool_call meta_mcp
                        .audit_replay(&tool_name, args, session, &caller, response, audit)
                        .await;
                }
                Err(error) => {
                    break 'tool_call JsonRpcResponse::error(
                        Some(id),
                        error.to_rpc_code(),
                        error.to_string(),
                    );
                }
            };
            caller.execution = execution.as_ref();
            // Handed down borrowed (MIK-8014): only a task, which stores
            // the call, copies it.
            Box::pin(meta_mcp.handle_tools_call_ref(
                id,
                &tool_name,
                arguments,
                Some(session_id),
                caller,
            ))
            .await
        };
        (response, execution)
    }
}
