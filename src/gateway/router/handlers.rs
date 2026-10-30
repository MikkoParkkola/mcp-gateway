// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Axum request handlers for the MCP gateway.

use crate::error::rpc_codes::{INTERNAL_ERROR, INVALID_PARAMS, METHOD_NOT_FOUND};
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
pub(in crate::gateway::router) mod events;
mod health;
mod meta_handler;
#[cfg(feature = "metrics")]
mod metrics_scrape;
mod modern_response;
mod owner;
pub(super) mod request_checks;
mod request_facts;
mod session_end;
mod sse;
pub(super) mod tasks;

#[cfg(test)]
use health::backends_overall_healthy;
pub(super) use health::health_handler;
#[cfg(feature = "metrics")]
pub(super) use metrics_scrape::metrics_handler;
pub(crate) use modern_response::shape_modern_response;
pub(super) use owner::owner_of;
// The direct route admits its execution lease under the same owner (MIK-8154).
pub(in crate::gateway) use meta_handler::meta_mcp_handler;
#[cfg(test)]
use owner::session_owner;
pub(super) use request_facts::TASKS_EXTENSION;
use request_facts::{
    catalogue_caller, listened_task_ids, reaches_tasks_extension, session_id_header,
};
pub(super) use session_end::{mcp_delete_handler, sse_deprecated_handler};
pub(super) use sse::mcp_sse_handler;
use sse::unsupported_version_error;

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
    let (request, method, external_tool) =
        (&intake.request, &intake.method, intake.external_tool());
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
        generation: &intake.generation,
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
        grant_key: client
            .as_ref()
            .and_then(AuthenticatedClient::api_key_identity),
        agent_id: agent_identity.proven_agent_id(),
        grant_subject: grant_subject.as_ref(),
        caller: crate::identity_propagation::CallerProof::new(
            verified_identity.as_ref(),
            crate::identity_propagation::CallerProvenance::classify(
                client
                    .as_ref()
                    .map(|client| client.principal.storage_form()),
            ),
        ),
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
    let mut pending_view = crate::gateway::streaming::PendingRefresh::default();
    let mut response = match method.as_str() {
        "subscriptions/listen" => {
            // The single long-lived stream that replaces the GET endpoint.
            //
            // No provisional session needs holding for this stream (MIK-8504):
            // only a request declaring 2026 reaches here, and one that declares it
            // by header mints no session, while one that declares it only in the
            // body is refused by the mirrored-header check (`protocol::headers`,
            // `HeaderCheck::validate`) before dispatch. A change that lets a
            // header-less 2026 request through must hold the session for the
            // stream, as the GET stream does (`sse::held_body`).
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
                    INVALID_PARAMS,
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
                .admit_listener(headers, intake.view_subject(), (id.clone(), session_id))
                .await
            {
                Ok(listener) => listener,
                Err(refusal) => return *refusal,
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
                    generation: &intake.generation,
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
                Err(why) => break 'events JsonRpcResponse::error(Some(id), INTERNAL_ERROR, why),
            };
            let caller = crate::events::Caller {
                principal: events::principal(events_owner, state.auth_config.enabled),
                identity: verified_identity.clone(),
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
        "initialize" => {
            // Its greeting counts tools per backend: the same managed-grant
            // recheck as every listing, so a rotated grant's stale slot never
            // contributes (MIK-8356 R4.2).
            state
                .meta_mcp
                .revalidate_caller_slots(invoke_scope.caller)
                .await;
            state.meta_mcp.handle_initialize(
                id,
                params,
                Some(session_id.as_str()),
                header_profile.as_deref(),
                era,
                invoke_scope,
            )
        }
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
            // MIK-8356: a rotated or revoked managed grant's slot is never this
            // caller's listing view; one recheck for every listing path.
            pending_view = state
                .begin_listing(session_id, &intake.view_subject(), invoke_scope.caller)
                .await;
            // A backend with no shared session lists only the
            // caller's own view, re-established here under the caller's grant.
            state
                .meta_mcp
                .warm_listing_views(invoke_scope, Some(session_id.as_str()))
                .await;
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
            // MIK-7642 PR.C: registered so this caller's own explicit cancel
            // aborts the call (the transport then cancels it on the backend
            // by the backend's id); held until the call ends.
            let (_cancel_entry, cancel_on) = serde_json::to_value(&id)
                .ok()
                .and_then(|key_id| {
                    let caller = (
                        grant_subject.as_ref(),
                        cert_identity.as_ref(),
                        client.as_ref(),
                    );
                    dispatch_intake::mcp_cancel_key(caller, session_id, &key_id)
                })
                .and_then(|key| state.meta_mcp.inflight_calls().register(key))
                .unzip();
            let answer_id = id.clone();
            // Boxed: an inline future would enlarge this dispatcher's own state.
            // The request's visibility memo is already open (see the handler).
            let call = Box::pin(dispatch_tools_call::tools_call(
                &state,
                &intake,
                id,
                &router_authorizer,
                invoke_scope,
                &mut signing_context,
                &mut response_targets,
                &mut execution,
            ));
            let called = match cancel_on {
                Some(cancel_on) => cancel_on.run(call).await,
                None => Some(call.await),
            };
            match called {
                Some(Ok(response)) => {
                    let subject = intake.view_subject();
                    let (response, pending) = state
                        .after_call((session_id, &subject), invoke_scope.caller, params, response)
                        .await;
                    pending_view = pending;
                    response
                }
                Some(Err(response)) => {
                    // Refused before dispatch: recorded here, as the tail is skipped.
                    let correlation = crate::security::response_policy::ResponseCorrelation {
                        session_id,
                        caller: client.as_ref().map_or("anonymous", |c| c.name.as_str()),
                        external_server: "gateway",
                        external_tool,
                        subject: grant_subject.as_ref(),
                        trace_id: None,
                        key: crate::security::response_policy::KeyOf::of_client(
                            client.as_ref().and_then(
                                crate::gateway::auth::AuthenticatedClient::api_key_identity,
                            ),
                        ),
                    };
                    let credential =
                        crate::gateway::meta_mcp::response_security::DeliveryCredential::of(
                            client.as_ref(),
                            state.auth_config.record_key(),
                        );
                    return super::judged_answer::record_error_exit(
                        &state.meta_mcp,
                        response,
                        &correlation,
                        credential,
                        session_id,
                    )
                    .await;
                }
                None => {
                    // Not counted against the client: the cancel was its
                    // own choice. The admission lease settles on drop as
                    // dispatched, so a retry never re-runs the call.
                    return build_error_response(
                        Some(answer_id),
                        crate::gateway::router::inflight_calls::CLIENT_CANCELLED_CODE,
                        crate::gateway::router::inflight_calls::CLIENT_CANCELLED_MESSAGE,
                        session_id,
                        StatusCode::OK,
                    );
                }
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
            METHOD_NOT_FOUND,
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
            // The same managed-grant recheck as every listing, so a rotated
            // grant's slot never resolves a tool.
            state
                .meta_mcp
                .revalidate_caller_slots(invoke_scope.caller)
                .await;
            state
                .meta_mcp
                .handle_tools_resolve(id, params, Some(session_id.as_str()), invoke_scope)
                .await
        }

        // The owner is the routed task owner (`route_owners`), not the raw session key: it is
        // what admission was keyed on when the record was created, and reading
        // with anything else would miss a task the caller does own.
        // Both arms act for THIS request's live context: a recovery read
        // re-authorizes the original target with it, and an update that
        // completes an input round resumes the call as it.
        "tasks/get" | "tasks/update" => {
            let caller = tasks::RecoveryCaller {
                generation: &intake.generation,
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
                // A task read serves a stored answer: not this request's.
                crate::gateway::delivery_facts::unvouched();
                // Boxed: the stored-read pre-pass (MIK-8392 / #3892) grew this
                // future past the large-future cap, as stdio `tasks/get` is.
                Box::pin(tasks::tasks_get(&state, owner, id.clone(), params, &caller)).await
            } else {
                let update = (params, surface_request);
                tasks::tasks_update(&state, owner, id.clone(), update, &caller).await
            }
        }
        "tasks/cancel" => tasks::tasks_cancel(&state, owner, id.clone(), params).await,
        _ => JsonRpcResponse::error(
            Some(id),
            METHOD_NOT_FOUND,
            format!("Method not found: {method}"),
        ),
    };

    let stamps = if is_modern {
        shape_modern_response(&mut response, method)
    } else {
        crate::gateway::meta_mcp::invoke::relay::GatewayStamps::Legacy
    };
    let caller = client
        .as_ref()
        .map_or("anonymous", |client| client.name.as_str());
    // Taken before finalizing, which may replace the answer.
    let invocation_trace = response.invocation_trace.clone();
    let delivery = crate::gateway::meta_mcp::response_security::ResponseDeliveryContext {
        method,
        targets: &response_targets,
        correlation: crate::security::response_policy::ResponseCorrelation {
            session_id,
            caller,
            external_server: "gateway",
            external_tool,
            subject: grant_subject.as_ref(),
            trace_id: invocation_trace.as_deref(),
            key: crate::security::response_policy::KeyOf::of_client(
                client
                    .as_ref()
                    .and_then(crate::gateway::auth::AuthenticatedClient::api_key_identity),
            ),
        },
        signing: signing_context.as_ref(),
        chain_source: response.chain_source,
        chain_nonce: chain_nonce.as_deref(),
    };
    #[cfg(feature = "firewall")]
    let router = state.firewall.as_deref();
    #[cfg(not(feature = "firewall"))]
    let router = None;
    let response = (state.meta_mcp).finalize_routed(response, &delivery, router);
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
        crate::gateway::meta_mcp::response_security::DeliveryCredential::of(
            client.as_ref(),
            state.auth_config.record_key(),
        ),
        finalized,
    )
    .await;
    if let (Some(execution), Some(finalized)) = (execution, finalized) {
        execution.complete_delivery(&finalized, signing_context.as_ref());
    }
    let response = frame
        .response()
        .expect("an answer frame stays an answer through its replacements");
    pending_view.settle(response.error.is_none());
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
            state.auth_config.record_client_failure(client);
        } else {
            state.auth_config.record_client_success(client);
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
            .is_some_and(|error| error.code == METHOD_NOT_FOUND)
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
