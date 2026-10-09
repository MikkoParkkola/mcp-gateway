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
use tracing::{debug, info, warn};

use super::AppState;
use super::authorization::{
    CallerStanding, RouterAuthorizer, authorize_tool_target, backend_tool_targets_for_call,
    is_admin_meta_tool, refusal_principal, require_admin_log_level, require_admin_tool_access,
};
use super::helpers::{
    build_error_response, build_response, extract_tools_call_params, merge_client_meta,
    parse_elicitation_params, parse_sampling_params,
};
use super::meta_refusal_audit::Refused;
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::meta_mcp::invoke::relay::{self, CatalogueCaller};
use crate::gateway::meta_mcp::{InvokeScope, MetaMcpCallerContext};
use crate::gateway::outbound::{OutboundReply, judged_reply, stream_reply};
use crate::gateway::session_lifecycle;
use crate::mtls::CertIdentity;
use crate::protocol::JsonRpcResponse;
#[cfg(feature = "firewall")]
use crate::security::firewall::FirewallAction;

#[cfg(test)]
mod cacheable_field_tests;
mod dispatch_intake;
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
    let dispatch = crate::gateway::meta_mcp::grant_audit::slot_http(
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
    // The prelude (MIK-8143). One `let` drops its bindings in reverse, so
    // `intake` (holding the in-flight permit) drops before `judge` (holding
    // the read guard), as the two locals did.
    let (judge, mut signing_context, intake) =
        match dispatch_intake::intake(&state, http_request).await {
            Ok(parts) => parts,
            Err(response) => return response,
        };
    let dispatch_intake::JudgeInputs {
        read_guard,
        read_key,
    } = judge;
    // The prelude's facts under the names the arms below were written with.
    let (headers, client, cert_identity) = (&intake.headers, &intake.client, &intake.cert_identity);
    let (oauth_agent_identity, verified_identity) =
        (&intake.oauth_agent_identity, &intake.verified_identity);
    let (presented, agent_identity, grant_subject) = (
        &intake.presented,
        &intake.agent_identity,
        &intake.grant_subject,
    );
    let (session_id, existing_session_id, chain_nonce) = (
        &intake.session_id,
        &intake.existing_session_id,
        &intake.chain_nonce,
    );
    let (request, method, external_tool) = (&intake.request, &intake.method, &intake.external_tool);
    let (owner, events_owner, admission_owner) =
        (&intake.owner, &intake.events_owner, &intake.admission_owner);
    let (protocol_revision_owned, header_profile) =
        (&intake.protocol_revision_owned, &intake.header_profile);
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
        {
            let hub = std::sync::Arc::clone(state.meta_mcp.events().expect("guarded above"));
            let session = Some(session_id.as_str());
            let caller = crate::events::Caller {
                principal: events::principal(events_owner, state.auth_config.enabled),
                read_key: read_key.clone(),
                credential: presented.credential(client.as_ref(), &state),
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
        // Labelled so the destructive-confirmation gate can answer *through* the
        // tail below rather than around it: an answer that leaves this block is
        // shaped, finalized and serialized by the same code every other response
        // takes. Only that one arm breaks; the refusals that return directly
        // still do, because each already carries the status it must be sent with.
        "tools/call" => 'tools_call: {
            let (tool_name, arguments) = extract_tools_call_params(params);
            // A conforming client's `_meta` is a sibling of `arguments`, and
            // the meta layer reads it off the argument object it is handed.
            // Meta-tool path only -- the direct backend route runs before the
            // meta-tool match and must stay byte-identical.
            let arguments = merge_client_meta(
                arguments,
                params,
                state.meta_mcp.exposes_meta_tool(tool_name),
            );

            // A task-augmented call used to be answered HERE, with a handle
            // minted from a volatile store before anything was authorized. That
            // return is gone. A handle is a promise that work is under way, and
            // this site is upstream of every gate that decides whether the work
            // may happen at all — so it promised dispatch to callers the
            // authorization loop, the firewall and the destructive-confirmation
            // gate were about to refuse, and it did so without a durable record
            // behind the handle. The intent is built below, after those gates,
            // and travels on the caller context that the dispatch chokepoint
            // takes once the call is cleared to run.

            // A multi-round-trip retry carries `inputResponses` and
            // `requestState` as siblings of `name` and `arguments` (MIK-7212).
            // They are read here and travel to the invoke funnel on the caller
            // context, which is the only scope that can act on them: redeeming
            // the continuation reproduces the digest sealed at mint time, and
            // that digest is over the *backend's* server, tool and argument
            // object. Here `tool_name` is the gateway-facing name and
            // `arguments` the wrapper carrying them, so a binding check
            // attempted at this site would refuse every honest retry.
            //
            // What cannot wait is the malformed shape, refused below before
            // anything dispatches.
            let retry = crate::protocol::mrtr::RetryFields::from_params(params);
            // A refusal below is written to the chain as the meta layer would (#2420).
            let refused = Refused::of(
                &arguments,
                client.as_ref(),
                grant_subject.as_ref(),
                session_id,
            );
            if retry.is_malformed() {
                // Neither a usable retry nor a fresh call. Running it as a fresh
                // call would repeat whatever the first attempt already did, and
                // for a destructive tool that is the whole risk.
                let message = format!("malformed request fields: {}", retry.malformed.join(", "));
                return refused.answer_malformed(&state, id, message).await;
            }
            // Exposure decides before admin does, here as well as in the
            // dispatcher. The dispatcher orders these two correctly for its own
            // callers, and this pre-check runs earlier still, so on the HTTP
            // path an unexposed admin tool used to be answered by an admin
            // refusal -- which confirms the tool exists to exactly the caller
            // the allow-list hides it from, while stdio answered with the
            // unrecognised-tool refusal. Declining to pre-check what we will
            // not confirm leaves the dispatcher the single owner of that
            // refusal instead of asking two sites to word one answer alike.
            if state.meta_mcp.exposes_meta_tool(tool_name)
                && is_admin_meta_tool(tool_name)
                && let Err(e) = require_admin_tool_access(
                    state.transparency_log.as_ref(),
                    client.as_ref(),
                    grant_subject.as_ref(),
                    tool_name,
                )
                .await
            {
                return build_error_response(Some(id), e.code, e.message, session_id, e.status);
            }

            let backend_targets =
                backend_tool_targets_for_call(&state.meta_mcp, tool_name, &arguments);
            response_targets = crate::gateway::meta_mcp::response_security::meta_response_targets(
                tool_name,
                &backend_targets,
            );
            for target in &backend_targets {
                // A surfaced name this caller could not invoke is answered by
                // the meta layer exactly as an unknown name is (`-32601`), and
                // audited there: a 403 here would confirm the backend (A3).
                if state.meta_mcp.surfaced_tool_server(tool_name).is_some()
                    && state
                        .meta_mcp
                        .may_invoke(
                            &target.server,
                            &target.tool,
                            invoke_scope,
                            Some(session_id.as_str()),
                        )
                        .is_err()
                {
                    continue;
                }
                if let Err(e) = authorize_tool_target(
                    state.as_ref(),
                    client.as_ref(),
                    oauth_agent_identity.as_ref(),
                    cert_identity.as_ref(),
                    target.as_target(),
                ) {
                    // This gate returns without entering the meta layer, so the
                    // chokepoint's emitter never fires for a shape the router
                    // covers. Both gates call the one helper, or HTTP scope
                    // denials — the ones most worth seeing — go unrecorded.
                    crate::gateway::authz::audit_refusal(
                        crate::gateway::authz::Transport::Http,
                        refusal_principal(
                            client.as_ref(),
                            oauth_agent_identity.as_ref(),
                            cert_identity.as_ref(),
                        )
                        .as_deref(),
                        &target.server,
                        &target.tool,
                        &e.message,
                    );
                    return refused
                        .answer(&state, target.as_target(), id, e.code, e.message, e.status)
                        .await;
                }

                // Firewall: pre-invocation request scan
                #[cfg(feature = "firewall")]
                if let Some(ref fw) = state.firewall {
                    let target = target.as_target();
                    let caller_name = client.as_ref().map_or("anonymous", |c| c.name.as_str());
                    // The key the per-caller controls score on (MIK-7971):
                    // never the display name, which every anonymous caller
                    // shares. Empty is no identity: refused.
                    let control_identity = super::identity::control_identity(
                        super::identity::caller_key(
                            grant_subject.as_ref(),
                            cert_identity.as_ref(),
                            client.as_ref(),
                        ),
                        session_id,
                        existing_session_id.as_deref(),
                    );
                    // Renew the reclaim deadline on every call (`IDLE_TTL`). An
                    // empty identity holds no per-identity state: not tracked.
                    if let Some(ref lifecycle) = state.session_lifecycle
                        && !control_identity.is_empty()
                    {
                        lifecycle.track(
                            control_identity.clone(),
                            session_lifecycle::now_unix() + session_lifecycle::IDLE_TTL.as_secs(),
                        );
                    }
                    let verdict = fw.check_request(
                        session_id,
                        target.server,
                        target.tool,
                        target.arguments,
                        caller_name,
                        &control_identity,
                    );
                    if verdict.action == FirewallAction::Warn {
                        warn!(
                            server = target.server,
                            tool = target.tool,
                            findings = verdict.findings.len(),
                            "Firewall: request warning"
                        );
                    }
                    if !verdict.allowed {
                        // OWASP ASI10 (Rogue Agents): anomaly blocks use -32002;
                        // all other firewall blocks use -32600 (invalid request).
                        let (code, reason) = if verdict.is_asi10_block() {
                            let desc = verdict.findings.first().map_or(
                                "Anomaly detection triggered: unusual tool sequence blocked",
                                |f| f.description.as_str(),
                            );
                            (-32002_i32, format!("Anomaly detection blocked: {desc}"))
                        } else {
                            let desc = verdict
                                .findings
                                .first()
                                .map_or("Security firewall blocked this request", |f| {
                                    f.description.as_str()
                                });
                            (-32600_i32, format!("Firewall blocked: {desc}"))
                        };
                        return refused
                            .answer(&state, target, id, code, reason, StatusCode::BAD_REQUEST)
                            .await;
                    }
                }
            }

            let api_key_name = client.as_ref().map(|c| c.name.as_str());
            // Authorization reads the PROVEN principal. This value reaches
            // `IdentityGrantRequest.agent_id` -> `GrantAgent::matches`, which
            // is a bare string compare: before this change it carried the
            // header-first conflated id, so a grant scoped to `agent-a` was
            // satisfied by anyone sending `X-Agent-ID: agent-a`. That path has
            // no `agent_identity.enabled` gate, so the escalation was reachable
            // on shipped defaults.
            //
            // Cost attribution wants the caller's own tag instead
            // (`AgentIdentity::attribution_id`). Routing the two apart needs
            // separate fields on `MetaMcpCallerContext` and
            // `TaskIntentRequest`; until those carry both, authorization
            // correctness wins the single field.
            let agent_id = agent_identity.proven_agent_id();
            // Audit and cost attribution read the caller's own tag. It travels
            // beside the proven principal, never instead of it.
            let agent_declared = agent_identity.declared_agent_label();

            // The modern destructive gate (X14). Every authorization, admin and
            // firewall check above has already run, and nothing below has yet
            // acted: a challenge mints no task, reserves no idempotency key and
            // reaches no backend, and neither does a refusal.
            //
            // Awaited into its own binding before the match, so the borrow of
            // `retry` ends with the statement and the `NotRequired` arm can hand
            // the same fields straight back.
            let confirmation = state
                .meta_mcp
                .confirm_destructive_task(&crate::gateway::meta_mcp::TaskConfirmationRequest {
                    id: id.clone(),
                    // The outer name the client called, never a wrapper's
                    // target, and the same `arguments` binding that reaches
                    // `task_intent_for_call` — that value is both the admission
                    // operation's `arguments` and its representation, so the
                    // grant must digest what admission will key on.
                    tool_name,
                    arguments: &arguments,
                    task: params.and_then(|p| p.get("task")),
                    retry: &retry,
                    verified_identity: verified_identity.as_ref(),
                    input_capabilities: declared_capabilities,
                    is_modern,
                    admission: state.task_executor.service.admission(),
                })
                .await;
            let retry = match confirmation {
                crate::gateway::meta_mcp::TaskConfirmation::NotRequired => retry,
                // Confirmed: dispatch the original call, with the confirmation
                // metadata removed.
                crate::gateway::meta_mcp::TaskConfirmation::Granted(granted) => granted,
                // The challenge, or the refusal of a grant that does not
                // authorise this call. Answered here because there is nothing
                // below to run.
                crate::gateway::meta_mcp::TaskConfirmation::Answer(answer) => {
                    // Out through the tail, not around it. A challenge is a
                    // client-visible result like any other: it needs this
                    // revision's metadata shaped onto it *before* the response
                    // security finalizer runs, and it needs that finalizer —
                    // whose `PreserveInputRequired` policy is what leaves the
                    // challenge's own discriminator alone, and whose signing
                    // step is the only one entitled to sign what goes out.
                    // Serialization then follows the request's own era, so a
                    // legacy caller still gets its session header. The status
                    // is re-derived there from this same response, by the same
                    // `refusal_status` call, so a refusal keeps its code.
                    //
                    // Nothing has been admitted at this point — no lease, no
                    // task, no backend — so the tail's execution settlement has
                    // nothing to settle, which is the honest state for a call
                    // that was stopped at the gate.
                    break 'tools_call *answer;
                }
            };

            // Destructive-action confirmation is decided at the dispatcher,
            // for every transport. What this edge owns is the one fact the
            // dispatcher cannot see: which era the request was written
            // against, and therefore what to do when nobody can be asked.
            // Handed over finished, so the shape is read once, here. Hardened
            // gives a legacy caller the modern answer: refuse what nobody can
            // confirm (GH1942.HARDEN.1 row 11).
            let confirmation_policy = if is_modern
                || state.live_config.running().security.posture
                    == crate::security::SecurityPosture::Hardened
            {
                crate::gateway::destructive_confirmation::ConfirmationPolicy::for_modern()
            } else {
                crate::gateway::destructive_confirmation::ConfirmationPolicy::for_legacy()
            };

            // Authorization is handed to the dispatch chokepoint rather than
            // applied here, so the shapes an edge cannot see — a playbook
            // step, whose targets are not in the request — face it too. The
            // authorizer is the one derived above, before the method match.

            // The background-task intent, or a refusal, or nothing at all.
            //
            // Built here — after the authorization loop, the firewall scan and
            // the admin pre-check, and before the dispatch chokepoint that owns
            // the destructive-confirmation gate — because a handle must not be
            // minted for a call that is about to be refused. Only a request that
            // actually carries a `task` member is offered to the builder: an
            // ordinary `tools/call` must reach the synchronous path unchanged,
            // and the builder's own refusals (no verified owner, no idempotency
            // key) are conditions on asking for a task, not on calling a tool.
            let task_intent = if params.is_some_and(|p| p.get("task").is_some()) {
                match tasks::task_intent_for_call(
                    &state,
                    id.clone(),
                    tasks::TaskIntentRequest {
                        tool_name,
                        arguments: &arguments,
                        is_modern,
                        retry: &retry,
                        verified_identity: verified_identity.as_ref(),
                        owner,
                        client: client.as_ref(),
                        oauth_agent_identity: oauth_agent_identity.as_ref(),
                        cert_identity: cert_identity.as_ref(),
                        api_key_name,
                        agent_id,
                        agent_declared,
                        grant_subject: grant_subject.clone(),
                        is_admin: client.as_ref().is_some_and(|c| c.admin),
                        input_capabilities: declared_capabilities,
                        session_id: Some(session_id.as_str()),
                        protocol_revision: protocol_revision_owned.as_deref(),
                        surface_request,
                    },
                ) {
                    Ok(intent) => intent,
                    Err(refusal) => {
                        return build_response(*refusal, session_id, StatusCode::BAD_REQUEST);
                    }
                }
            } else {
                None
            };

            // One request owns admission through dispatch and secured delivery.
            // A route change may conflict on representation, never create a
            // second owner for the same verified principal and explicit key.
            // The A/B arm and the prefetch hints key on the caller (G4). Its
            // reclaim deadline is renewed here, in every build, because those
            // entries have no session end to reclaim them.
            let caller_key = super::identity::caller_key(
                grant_subject.as_ref(),
                cert_identity.as_ref(),
                client.as_ref(),
            );
            if let Some(ref lifecycle) = state.session_lifecycle
                && !caller_key.is_empty()
            {
                lifecycle.track(
                    caller_key.clone(),
                    session_lifecycle::now_unix() + session_lifecycle::IDLE_TTL.as_secs(),
                );
            }
            let mut caller = MetaMcpCallerContext {
                // Built above, after every gate that can still refuse, and only
                // carried here: the dispatch chokepoint is what hands it over.
                task: task_intent,
                execution: None,
                signing: None,
                is_modern,
                protocol_revision: protocol_revision_owned.as_deref(),
                credential_principal: client.as_ref().map(|client| client.principal.as_str()),
                authentication: crate::gateway::meta_mcp::Authentication::of(client.as_ref()),
                credential_kind: crate::security::audit::CredentialKind::of(client.as_ref()),
                authorizer: &router_authorizer,
                api_key_name,
                agent_id,
                agent_declared,
                grant_subject: grant_subject.clone(),
                stdio_nonce: None,
                caller_key: Some(caller_key.as_str()).filter(|key| !key.is_empty()),
                verified_identity: verified_identity.as_ref(),
                is_admin: client.as_ref().is_some_and(|c| c.admin),
                surface_request,
                input_capabilities: declared_capabilities,
                retry: &retry,
                // Already derived at the top of this handler from the
                // same classification `initialize` advertises against;
                // re-deriving it here is the drift `classify_request`
                // exists to prevent.
                era,
                // HTTP holds the multiplexer, so this caller really can
                // be sent a request of the gateway's own.
                channel: state.proxy_manager.as_ref(),
                // Era decides who can be asked. A modern caller has no
                // session to hold an elicitation open, so it is asked
                // in-band and bound to its answer by a continuation.
                //
                // A legacy caller always gets `Elicit`, including when no
                // session was presented. HTTP can carry an asker; whether
                // one answered is what `policy` decides. Mapping a
                // sessionless request to `Unavailable` would refuse the
                // legacy caller this path deliberately still warns.
                confirmation: match era {
                    crate::protocol::meta::Era::Modern => {
                        crate::gateway::destructive_confirmation::ConfirmationChannel::InBand {
                            continuation: &state.continuation,
                        }
                    }
                    crate::protocol::meta::Era::Legacy => {
                        crate::gateway::destructive_confirmation::ConfirmationChannel::Elicit {
                            proxy: &state.proxy_manager,
                            policy: confirmation_policy,
                        }
                    }
                },
            };
            if let Some(context) = signing_context.as_mut()
                && let Err(error) = state.meta_mcp.prepare_signing_for_call(
                    context,
                    tool_name,
                    &arguments,
                    Some(session_id),
                    &caller,
                )
            {
                return build_error_response(
                    Some(id),
                    error.to_rpc_code(),
                    crate::gateway::meta_mcp::signing::wire_error_message(&error),
                    session_id,
                    StatusCode::BAD_REQUEST,
                );
            }
            caller.signing = signing_context.as_ref();
            let admission = state.meta_mcp.admit_meta_sync(
                crate::gateway::meta_mcp::AdmissionOwner::routed(admission_owner),
                &caller,
                tool_name,
                &arguments,
                Some(session_id),
                &id,
            );
            let (owned_execution, replay) = match admission {
                Ok(crate::gateway::meta_mcp::admission::SyncAdmission::Owned(lease)) => {
                    (Some(lease), None)
                }
                Ok(crate::gateway::meta_mcp::admission::SyncAdmission::Replay(response, audit)) => {
                    (None, Some((response, audit)))
                }
                Ok(crate::gateway::meta_mcp::admission::SyncAdmission::Unprotected) => (None, None),
                Err(error) => {
                    let status = match &error {
                        crate::Error::Forbidden { status, .. } => {
                            StatusCode::from_u16(*status).unwrap_or(StatusCode::FORBIDDEN)
                        }
                        _ if error.to_rpc_code() == 409 => StatusCode::CONFLICT,
                        _ => StatusCode::BAD_REQUEST,
                    };
                    return build_error_response(
                        Some(id),
                        error.to_rpc_code(),
                        error.to_string(),
                        session_id,
                        status,
                    );
                }
            };
            execution = owned_execution;
            caller.execution = execution.as_ref();
            // Screened at delivery, in `finalize_content`, with every other frame.
            if let Some((response, audit)) = replay {
                // #2472: a replay is a delivered call, recorded as its first run was.
                let session = Some(session_id.as_str());
                (state.meta_mcp)
                    .audit_replay(tool_name, &arguments, session, &caller, response, audit)
                    .await
            } else {
                Box::pin(state.meta_mcp.handle_tools_call(
                    id,
                    tool_name,
                    arguments,
                    Some(session_id.as_str()),
                    caller,
                ))
                .await
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
