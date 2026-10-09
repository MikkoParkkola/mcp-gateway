// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Axum request handlers for the MCP gateway.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde_json::{Value, json};
use tracing::{debug, info};

use super::AppState;
use super::authorization::{
    CallerStanding, RouterAuthorizer, refusal_principal, require_admin_log_level,
};
use super::helpers::{build_error_response, parse_elicitation_params, parse_sampling_params};
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::meta_mcp::InvokeScope;
use crate::gateway::meta_mcp::invoke::relay::{self, CatalogueCaller};
use crate::gateway::outbound::{OutboundReply, judged_reply, stream_reply};
use crate::mtls::CertIdentity;
use crate::protocol::JsonRpcResponse;

#[cfg(test)]
mod cacheable_field_tests;
mod dispatch_intake;
mod dispatch_tools_call;
mod events;
mod health;
#[cfg(feature = "metrics")]
mod metrics_scrape;
mod modern_response;
mod owner;
pub(super) mod request_checks;
mod session_end;
mod sse;
mod tasks;

#[cfg(test)]
use health::backends_overall_healthy;
pub(super) use health::health_handler;
#[cfg(feature = "metrics")]
pub(super) use metrics_scrape::metrics_handler;
pub(crate) use modern_response::shape_modern_response;
pub(super) use owner::owner_of;
#[cfg(test)]
use owner::session_owner;
pub(super) use session_end::{mcp_delete_handler, sse_deprecated_handler};
pub(super) use sse::mcp_sse_handler;
use sse::unsupported_version_error;

/// The caller's `Mcp-Session-Id`, one rule for every session route: missing,
/// non-UTF-8, empty and whitespace-only values are all "no session" (F9).
fn session_id_header(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .filter(|id| !id.trim().is_empty())
}

/// The extension a task-augmented request must declare.
pub(super) const TASKS_EXTENSION: &str = "io.modelcontextprotocol/tasks";

/// Whether this request reaches the tasks extension AT ALL.
///
/// Deliberately not a method-family test: `subscriptions/listen` is not a
/// `tasks/*` method and reaches the extension the moment it names a task, so a
/// gate keyed on the prefix refuses the wrong set.
///
/// NOTHING TIES THIS LIST TO THE DISPATCHER. A method added below without an arm
/// here reaches the task store unguarded, and no test goes red: the arms and the
/// dispatcher agree today only because a person kept them in step. The residual
/// is recorded here rather than in a review document because here is where the
/// next method gets added -- ADD THE ARM IN THE SAME EDIT.
fn reaches_tasks_extension(method: &str, params: Option<&Value>) -> bool {
    match method {
        "tools/call" => params.is_some_and(|p| p.get("task").is_some()),
        "tasks/get" | "tasks/update" | "tasks/cancel" => true,
        "subscriptions/listen" => {
            params.is_some_and(crate::protocol::subscriptions::names_task_ids)
        }
        _ => false,
    }
}

/// The task ids a `subscriptions/listen` names, if it names any, in either
/// placement.
fn listened_task_ids(params: Option<&Value>) -> Vec<String> {
    params
        .map(crate::protocol::subscriptions::named_task_ids)
        .unwrap_or_default()
}

/// Meta-MCP handler (POST /mcp).
///
/// `Accept` ALONE decides the body shape (S-01): a stream carrying only the
/// result frame is a conforming answer, so branching on whether the backend
/// happened to raise a notification would give one `Accept` two body types.
///
/// The dispatch runs inside a notification sink, and the sink IS the request
/// scoping (S-03): two concurrent POSTs are two tasks, so a backend
/// notification can only ever be appended to the call that provoked it.
/// `MIK-7272.SUB.2b`.
pub(super) async fn meta_mcp_handler(
    state: State<Arc<AppState>>,
    http_request: axum::http::Request<axum::body::Body>,
) -> OutboundReply {
    let offers_event_stream = http_request
        .headers()
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|accept| accept.contains("text/event-stream"));

    // D3-a: one grant-decision slot spans signing, admission and dispatch.
    let logger = state.meta_mcp.transparency_logger.clone();
    // MIN.2: the dispatch notes what its inner calls read before transforms,
    // so the answer's judge sees tenants the delivered value no longer shows.
    let guard = super::helpers::read_guard(&state);
    let audit = offers_event_stream.then(|| state.meta_mcp.rejection_audit());
    let guard_for_scope = guard.clone();
    // MIK-8161: a backend's mid-call notifications meet the egress scan too.
    let screen = Some(state.meta_mcp.notification_screen("http", ""));
    // MIK-8176: the slots this request's mints take are owned here, outside
    // the grant-audit replacer, and by the dispatch future itself, so a
    // stream that polls it after this handler returns still has its scope.
    let dispatch = crate::gateway::meta_mcp::sealed_hold::scoped(
        crate::gateway::meta_mcp::grant_audit::slot_http(
            logger.clone(),
            // COLLUDE.1: one relay-receipt collector spans dispatch and finalize.
            Box::pin(async move {
                crate::gateway::outbound::read_scoped(
                    guard_for_scope,
                    Box::pin(crate::gateway::meta_mcp::invoke::relay::collecting_http(
                        Arc::clone(&state.meta_mcp),
                        meta_mcp_dispatch(state, http_request),
                    )),
                )
                .await
                .0
            }),
        ),
    );

    if let Some(audit) = audit {
        // Scope rather than collect: the client offered a stream, so the first
        // notification decides the body shape instead of waiting for dispatch.
        // Each notification is judged for this caller as it is queued.
        let judge = Arc::new(crate::gateway::outbound::StreamJudge::new(
            guard, audit, logger,
        ));
        let (scoped, rx) =
            crate::transport::notification_sink::scope_judged(screen, dispatch, Arc::clone(&judge));
        stream_reply(crate::gateway::streaming::first_event_wins_stream(scoped, rx, judge).await)
    } else {
        // Still scoped, and still drained alongside: `publish` sheds on a full
        // sink, and a client that did not offer a stream must not make a
        // backend's notifications count against that depth.
        let (response, _notifications) =
            crate::transport::notification_sink::collect(screen, dispatch).await;
        // The answer's read record, written after every late replacer.
        judged_reply(response, logger.as_ref()).await
    }
}

#[allow(clippy::too_many_lines)]
async fn meta_mcp_dispatch(
    State(state): State<Arc<AppState>>,
    http_request: axum::http::Request<axum::body::Body>,
) -> impl IntoResponse {
    // The prelude (MIK-8143). One `let` pattern drops its bindings in
    // reverse, so `intake` (holding the in-flight permit) drops before the
    // read guard and key, bound ahead of it here, as the original locals did.
    let (
        dispatch_intake::JudgeInputs {
            read_guard,
            read_key,
        },
        mut signing_context,
        intake,
    ) = match dispatch_intake::intake(&state, http_request).await {
        Ok(parts) => parts,
        Err(response) => return response,
    };
    // The prelude's facts under the names the arms below were written with.
    let (headers, client, cert_identity) = (&intake.headers, &intake.client, &intake.cert_identity);
    let (oauth_agent_identity, verified_identity) =
        (&intake.oauth_agent_identity, &intake.verified_identity);
    let (presented, agent_identity, grant_subject) = (
        &intake.presented,
        &intake.agent_identity,
        &intake.grant_subject,
    );
    let (session_id, chain_nonce) = (&intake.session_id, &intake.chain_nonce);
    let (request, method, external_tool) = (&intake.request, &intake.method, &intake.external_tool);
    let (owner, events_owner, header_profile) =
        (&intake.owner, &intake.events_owner, &intake.header_profile);
    let (code_mode_url_active, surface_request) =
        (intake.code_mode_url_active, intake.surface_request);
    let (era, is_modern, declared_capabilities) =
        (intake.era, intake.is_modern, intake.declared_capabilities);
    let params = intake.params();
    // Each arm consumes the id, as it consumed the prelude's local.
    let id = intake.id.clone();
    let mut response_targets =
        crate::gateway::meta_mcp::response_security::meta_response_targets(external_tool, &[]);
    let mut execution = None;

    // Route to appropriate handler
    // Fail-closed default: delivery inspects unless the `tools/call` arm below
    // proves it already inspected this exact artifact.
    #[cfg_attr(not(feature = "firewall"), allow(unused_mut))]
    // The scope and identity the resource and prompt arms forward under.
    let (scope, identity) = (client.as_ref(), verified_identity.as_ref());
    // The one derivation of what this caller may invoke, shared by
    // `tools/call`, `tools/list`, `initialize` and `tools/resolve` (A3), so an
    // identity-granted capability cannot drift between listing and invoking.
    // Constructed concretely, so the weaker stdio authorizer cannot reach the
    // network path.
    let router_authorizer = RouterAuthorizer {
        state: state.as_ref(),
        client: client.as_ref(),
        oauth_agent_identity: oauth_agent_identity.as_ref(),
        cert_identity: cert_identity.as_ref(),
        principal: refusal_principal(
            client.as_ref(),
            oauth_agent_identity.as_ref(),
            cert_identity.as_ref(),
        ),
    };
    let invoke_scope = InvokeScope {
        authorizer: &router_authorizer,
        is_admin: client.as_ref().is_some_and(|c| c.admin),
        api_key_name: client.as_ref().map(|c| c.name.as_str()),
        agent_id: agent_identity.proven_agent_id(),
        grant_subject: grant_subject.as_ref(),
    };
    // Every shared backend's one level, set over the gateway's own credential:
    // an operator action. Checked before dispatch so a case variant of the
    // method meets the same refusal as the canonical name.
    if let Err(e) = require_admin_log_level(
        method,
        scope,
        router_authorizer.principal.as_deref(),
        "gateway",
    ) {
        return build_error_response(Some(id), e.code, e.message, session_id, e.status);
    }
    let mut response = match method.as_str() {
        "subscriptions/listen" => {
            use crate::gateway::subscription_registry::ListenRefusal;
            // The single long-lived stream that replaces the GET endpoint.
            //
            // Returns EARLY with an SSE body rather than falling through to the
            // ordinary response builder: the specification's response to this
            // method is a stream that stays open, and an acknowledgement that
            // closes is a subscription the client waits on forever.
            let Some(request) = crate::protocol::subscriptions::ListenRequest::from_params(params)
            else {
                // No `notifications` filter at all. An *empty* filter is valid
                // and opens a quiet stream; this is a request that never said
                // what it wanted.
                return build_error_response(
                    Some(id),
                    -32602,
                    "subscriptions/listen requires a 'notifications' filter",
                    session_id,
                    StatusCode::BAD_REQUEST,
                );
            };

            // The permit IS the admission. A caller may open streams and walk
            // away — the specification says a server must not assume otherwise
            // — so this ceiling is a resource bound, and one checked as a count
            // before subscribing can be raced past by concurrent callers.
            //
            // A caller whose credential does not authenticate is refused before
            // a permit is taken: nothing could ever be delivered to its stream,
            // so admitting it would only hold one of the slots.
            let listener = match state
                .subscriptions
                .subscribe_as(crate::gateway::auth::live::held_credential(headers))
                .await
            {
                Ok(listener) => listener,
                Err(ListenRefusal::Unauthenticated) => {
                    return build_error_response(
                        Some(id),
                        -32001,
                        "subscriptions/listen requires a credential that authenticates",
                        session_id,
                        StatusCode::UNAUTHORIZED,
                    );
                }
                Err(ListenRefusal::Full) => {
                    return build_error_response(
                        Some(id),
                        -32003,
                        "too many open subscriptions",
                        session_id,
                        StatusCode::SERVICE_UNAVAILABLE,
                    );
                }
            };

            // The request's own id, never minted: the specification defines the
            // subscription id as the JSON-RPC id of the listen request, and it
            // is how a client correlates a notification with the subscription
            // that asked for it.
            let subscription = crate::protocol::subscriptions::SubscriptionId::of_request(id);
            let acknowledgement = request.acknowledgement(&subscription);
            debug!(
                empty = request.is_empty(),
                resources = request.resource_uris().len(),
                "subscriptions/listen opened"
            );

            // A stream that named tasks gets their full state, rebuilt per
            // reader at delivery; the names were narrowed to this caller's own
            // tasks above, and each frame is re-authorized against the
            // reader's credential as it is resolved at that moment.
            let task_frames = (!request.task_ids().is_empty()).then(|| {
                let reader = tasks::RecoveryCaller {
                    client: client.as_ref(),
                    oauth_agent_identity: oauth_agent_identity.as_ref(),
                    cert_identity: cert_identity.as_ref(),
                    api_key_name: client.as_ref().map(|client| client.name.as_str()),
                    agent_id: agent_identity.proven_agent_id(),
                    agent_declared: None,
                    grant_subject: grant_subject.clone(),
                    verified_identity: verified_identity.as_ref(),
                    is_admin: client.as_ref().is_some_and(|client| client.admin),
                    input_capabilities: declared_capabilities,
                    session_id: Some(session_id.as_str()),
                };
                tasks::task_frames(&state, owner, &reader)
            });
            let judge = state.meta_mcp.stream_judge(read_guard, read_key);
            return crate::gateway::streaming::subscription_stream(
                listener,
                request,
                subscription,
                acknowledgement,
                state.streaming_config.keep_alive_interval,
                judge,
                params.cloned(),
                task_frames,
            );
        }
        // MIK-7630. Answered here, never proxied; with events off the guard
        // fails and the method falls through to `-32601`.
        "events/list" | "events/subscribe" | "events/unsubscribe"
            if state.meta_mcp.events().is_some() =>
        'events: {
            let hub = std::sync::Arc::clone(state.meta_mcp.events().expect("guarded above"));
            let session = Some(session_id.as_str());
            let credential = match presented.credential(client.as_ref(), &state) {
                Ok(credential) => credential,
                Err(why) => break 'events JsonRpcResponse::error(Some(id), -32603, why),
            };
            let caller = crate::events::Caller {
                principal: events::principal(events_owner, state.auth_config.enabled),
                read_key: read_key.clone(),
                credential,
                visible_backends: hub
                    .scope_backends()
                    .into_iter()
                    .filter(|b| state.meta_mcp.admits_backend(b, invoke_scope, session))
                    .collect(),
                admin: CallerStanding::of_client(client.as_ref()) == CallerStanding::Admin,
            };
            events::answer(&hub, id, method, params, &caller).await
        }
        // 2026-07-28 MUST. Deliberately ahead of `initialize`: discovery is what
        // a peer calls when it has no handshake to make.
        "server/discover" => crate::protocol::JsonRpcResponse::success_serialized(
            id,
            state
                .meta_mcp
                .discover_document(state.live_config.running().server.modern_protocol),
        ),
        "initialize" => state.meta_mcp.handle_initialize(
            id,
            params,
            Some(session_id.as_str()),
            header_profile.as_deref(),
            era,
            invoke_scope,
        ),
        "tools/list" => {
            // NFR.OBS.2. The inputs that decide this surface, and the
            // cacheScope the response will carry — recorded before the list is
            // built, so the record cannot be written from the answer it exists to check.
            //
            // Inputs, not applied filters. The branching lives behind a file
            // boundary this change does not cross, so a record naming filters
            // that "ran" would be this site's guess about another module's
            // control flow — and it guessed wrong: it named a session profile
            // on every request, including those carrying none. Each field below
            // is read from the value it names, so a reader can check the record
            // against the request rather than against an assumption.
            let query_present = params
                .and_then(|p| p.get("query"))
                .and_then(serde_json::Value::as_str)
                .is_some_and(|query| !query.is_empty());
            info!(
                target: "mcp_gateway::observed",
                profile = header_profile.as_deref().unwrap_or("none"),
                code_mode = state.meta_mcp.code_mode_enabled || code_mode_url_active,
                query_present,
                cache_scope = crate::protocol::cacheable::scope_for_method("tools/list").as_str(),
                // A legacy result carries no `cacheScope`, so a record naming
                // one without saying whether it reaches the client would be
                // reporting a field that was never sent.
                cache_scope_advertised = is_modern,
                "tools/list surface inputs and cache scope"
            );
            state.meta_mcp.handle_tools_list_with_url_override(
                id,
                params,
                Some(session_id.as_str()),
                code_mode_url_active,
                invoke_scope,
            )
        }
        // `Ok` answers *through* the tail below rather than around it, so a
        // destructive-confirmation challenge is shaped, finalized and serialized
        // by the same code every other response takes. `Err` is a refusal that
        // already carries the status it must be sent with, returned as it is.
        "tools/call" => {
            // Boxed: an inline future would enlarge this dispatcher's own state.
            match Box::pin(dispatch_tools_call::tools_call(
                &state,
                &intake,
                id,
                &router_authorizer,
                invoke_scope,
                &mut signing_context,
                &mut response_targets,
                &mut execution,
            ))
            .await
            {
                Ok(response) => response,
                Err(response) => return response,
            }
        }
        // Resources
        "resources/list" => {
            let meta = &state.meta_mcp;
            meta.handle_resources_list(id, params, scope, identity)
                .await
        }
        "resources/read" => {
            let standing = CallerStanding::of_client(scope);
            let meta = &state.meta_mcp;
            let caller = catalogue_caller(
                grant_subject.as_ref(),
                cert_identity.as_ref(),
                client.as_ref(),
                session_id,
            );
            // Boxed like `handle_tools_call` above: an inline future would
            // enlarge `meta_mcp_dispatch`'s own state, which every request
            // through it holds on the stack (a 2 MiB test thread overflowed).
            Box::pin(relay::as_caller(
                caller,
                meta.handle_resources_read(id, params, standing, scope, identity),
            ))
            .await
        }
        "resources/templates/list" => {
            let meta = &state.meta_mcp;
            meta.handle_resources_templates_list(id, params, scope, identity)
                .await
        }
        // F24: the gateway never delivers `resources/updated`, so a
        // subscription it accepted would wait forever. Refuse it outright.
        "resources/subscribe" | "resources/unsubscribe" => JsonRpcResponse::error(
            Some(id),
            crate::protocol::era::METHOD_NOT_FOUND_CODE,
            format!("{method} is not supported: this gateway does not deliver resources/updated"),
        ),

        // Prompts
        "prompts/list" => {
            let meta = &state.meta_mcp;
            meta.handle_prompts_list(id, params, scope, identity).await
        }
        "prompts/get" => {
            let meta = &state.meta_mcp;
            let caller = catalogue_caller(
                grant_subject.as_ref(),
                cert_identity.as_ref(),
                client.as_ref(),
                session_id,
            );
            Box::pin(relay::as_caller(
                caller,
                meta.handle_prompts_get(id, params, scope, identity),
            ))
            .await
        }

        // Logging. Admin standing is checked before this match, for every
        // spelling of the method (see `require_admin_log_level`).
        "logging/setLevel" => state.meta_mcp.handle_logging_set_level(id, params).await,

        "ping" => JsonRpcResponse::success(id, json!({})),

        "sampling/createMessage" => {
            let sampling_params =
                match parse_sampling_params(id.clone(), params.cloned(), session_id) {
                    Ok(p) => p,
                    Err(resp) => return resp,
                };

            // To the session that asked, and only that one.
            let timeout = std::time::Duration::from_secs(120);
            match state
                .proxy_manager
                .forward_sampling_with_response(session_id, &sampling_params, timeout)
                .await
            {
                Ok(result) => JsonRpcResponse::success(id, result),
                Err(e) => JsonRpcResponse::error(Some(id), -32002, e.to_string()),
            }
        }

        "elicitation/create" => {
            let elicitation_params =
                match parse_elicitation_params(id.clone(), params.cloned(), session_id) {
                    Ok(p) => p,
                    Err(resp) => return resp,
                };

            // To the session that asked, and only that one.
            let timeout = std::time::Duration::from_secs(120);
            match state
                .proxy_manager
                .forward_elicitation_with_response(session_id, &elicitation_params, timeout)
                .await
            {
                Ok(result) => JsonRpcResponse::success(id, result),
                Err(e) => JsonRpcResponse::error(Some(id), -32002, e.to_string()),
            }
        }

        // SEP-1862: resolve a single tool schema by name (spec-preview feature).
        #[cfg(feature = "spec-preview")]
        "tools/resolve" => {
            state
                .meta_mcp
                .handle_tools_resolve(id, params, Some(session_id.as_str()), invoke_scope)
                .await
        }

        // The owner is `task_principal`'s answer, not the raw session key: it is
        // what admission was keyed on when the record was created, and reading
        // with anything else would miss a task the caller does own.
        // Both arms act for THIS request's live context: a recovery read
        // re-authorizes the original target with it, and an update that
        // completes an input round resumes the call as it.
        "tasks/get" | "tasks/update" => {
            let caller = tasks::RecoveryCaller {
                client: client.as_ref(),
                oauth_agent_identity: oauth_agent_identity.as_ref(),
                cert_identity: cert_identity.as_ref(),
                api_key_name: client.as_ref().map(|client| client.name.as_str()),
                // An AUTHORIZATION context, not an attribution record: the
                // proven principal, never the declared label.
                agent_id: agent_identity.proven_agent_id(),
                agent_declared: agent_identity.declared_agent_label(),
                grant_subject: grant_subject.clone(),
                verified_identity: verified_identity.as_ref(),
                is_admin: client.as_ref().is_some_and(|client| client.admin),
                input_capabilities: declared_capabilities,
                session_id: Some(session_id.as_str()),
            };
            if method == "tasks/get" {
                tasks::tasks_get(&state, owner, id.clone(), params, &caller).await
            } else {
                let update = (params, surface_request);
                tasks::tasks_update(&state, owner, id.clone(), update, &caller).await
            }
        }
        "tasks/cancel" => tasks::tasks_cancel(&state, owner, id.clone(), params).await,
        _ => JsonRpcResponse::error(Some(id), -32601, format!("Method not found: {method}")),
    };

    let stamps = if is_modern {
        shape_modern_response(&mut response, method)
    } else {
        crate::gateway::meta_mcp::invoke::relay::GatewayStamps::Legacy
    };
    let caller = client
        .as_ref()
        .map_or("anonymous", |client| client.name.as_str());
    let delivery = crate::gateway::meta_mcp::response_security::ResponseDeliveryContext {
        method,
        targets: &response_targets,
        correlation: crate::security::response_policy::ResponseCorrelation {
            session_id,
            caller,
            external_server: "gateway",
            external_tool,
            subject: grant_subject.as_ref(),
        },
        signing: signing_context.as_ref(),
        chain_source: response.chain_source,
        chain_nonce: chain_nonce.as_deref(),
    };
    #[cfg(feature = "firewall")]
    let router = state.firewall.as_deref();
    #[cfg(not(feature = "firewall"))]
    let router = None;
    let mut response = (state.meta_mcp).finalize_routed(response, &delivery, router);
    state.meta_mcp.release_unsent_hold(&mut response).await; // MIK-8131
    // Kept for the stored delivery (cloned only when an execution stores it).
    let finalized = execution.as_ref().map(|_| response.clone());
    // MIN.2: judged on the finalized answer; the verdict rides its delivery
    // record (MIK-7799), and the sink commits when the body is read.
    let hidden = crate::gateway::outbound::noted_reads();
    let frame = crate::gateway::outbound::answer(
        read_guard.as_deref(),
        read_key.as_deref(),
        response,
        request.get("params"),
        hidden.as_ref(),
    );
    let (frame, finalized) = super::judged_answer::record_delivery(
        &state.meta_mcp,
        frame,
        &delivery.correlation,
        finalized,
    )
    .await;
    if let (Some(execution), Some(finalized)) = (execution, finalized) {
        execution.complete_delivery(&finalized, signing_context.as_ref());
    }
    let response = frame
        .response()
        .expect("an answer frame stays an answer through its replacements");
    // MIK-7887.RECEIPT.4: the receipt describes this, the delivered answer.
    {
        use crate::gateway::meta_mcp::invoke::relay::AnswerShape;
        let shape = AnswerShape::of(external_tool);
        state
            .meta_mcp
            .rebuild_receipt_from_final(response.result.as_ref(), stamps, shape);
    }
    // COLLUDE.1: receipts ride on the response to `emit_http`, after the last replacer.
    state.meta_mcp.settle_relay_receipts(response);

    telemetry_metrics::counter!(
        "mcp_jsonrpc_requests_total",
        "method" => method.clone(),
        "status" => if response.error.is_some() { "error" } else { "ok" }
    )
    .increment(1);

    // A confirmation or delivery refusal is the gate working, not a misbehaving
    // client: excluded from BOTH arms (a success would clear a tripped breaker).
    if let Some(client) = client
        && !response.excludes_client_accounting()
    {
        if response.error.is_some() {
            state.auth_config.record_client_failure(&client.name);
        } else {
            state.auth_config.record_client_success(&client.name);
        }
    }

    // A refusal the router gate caught already answered 403 above. A refusal
    // only the dispatch chokepoint can see — a playbook step, whose targets the
    // router never inspects — arrives here as a JSON-RPC error, and answering
    // it 200 tells every caller and intermediary the call succeeded. The status
    // travels on the error precisely so this line can honour it.
    let status = refusal_status(response).unwrap_or(StatusCode::OK);
    if is_modern {
        // An unimplemented method is 404 on this revision, not 200-with-error.
        // The status is what a client uses to tell "this server does not have
        // that method" from "this is not a modern endpoint at all" — and the
        // JSON-RPC body is what tells it apart from a legacy transport's bare
        // 404. Both halves are needed; neither alone decides it.
        let status = if response
            .error
            .as_ref()
            .is_some_and(|error| error.code == -32601)
        {
            StatusCode::NOT_FOUND
        } else {
            status
        };
        // A stateless client has no handshake in which to learn who answered,
        // so every result says. And it holds no session, so it is sent no
        // session header — the legacy path below keeps both unchanged.
        return crate::gateway::outbound::to_http(frame, status, "");
    }
    crate::gateway::outbound::to_http(frame, status, session_id)
}

/// The HTTP status a response deserves when it carries an authorization
/// refusal, or `None` for anything else.
///
/// Reads the status the dispatch layer stamped, rather than inferring one from
/// the JSON-RPC code — see `HTTP_STATUS_DATA_KEY` for why inference is wrong
/// here. An error with no stamp is not a refusal and keeps its own status, so
/// nothing else is reclassified.
pub(super) fn refusal_status(response: &JsonRpcResponse) -> Option<StatusCode> {
    let raw = response
        .error
        .as_ref()?
        .data
        .as_ref()?
        .get(crate::gateway::authz::HTTP_STATUS_DATA_KEY)?
        .as_u64()?;
    StatusCode::from_u16(u16::try_from(raw).ok()?).ok()
}

// ── destructive-confirmation helpers ─────────────────────────────────────────

#[cfg(test)]
#[path = "handlers_health_predicate_tests.rs"]
mod health_predicate_tests;

#[cfg(test)]
#[path = "handlers_session_tests.rs"]
mod session_tests;

#[cfg(test)]
#[path = "handlers_session_subject_tests.rs"]
mod session_subject_tests;

/// The caller a `prompts/get` or `resources/read` runs for, keyed as the same
/// caller's `tools/call` is: the key the grant, certificate or API key names,
/// else the unkeyed session bucket.
fn catalogue_caller(
    grant_subject: Option<&crate::identity_grants::GrantSubject>,
    cert_identity: Option<&CertIdentity>,
    client: Option<&AuthenticatedClient>,
    session_id: &str,
) -> CatalogueCaller {
    let key = super::identity::caller_key(grant_subject, cert_identity, client);
    let keyed = !key.is_empty();
    CatalogueCaller {
        key: if keyed { key } else { session_id.to_owned() },
        keyed,
        name: client.map_or_else(|| "anonymous".to_owned(), |c| c.name.clone()),
        session: session_id.to_owned(),
    }
}
