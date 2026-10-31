// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Stage 1 of the direct backend route: who is calling.
//!
//! Resolved before the body is read, so a refused identity header reaches no
//! passthrough, propagation or idempotency work. The order of every check and
//! every early return is the order `backend_handler_inner` always had.

use crate::error::rpc_codes::{INVALID_REQUEST, PARSE_ERROR};
use crate::gateway::meta_mcp::invoke::egress::Egressed;
use axum::{Json, http::HeaderMap, http::StatusCode};
use serde_json::Value;

use super::super::AppState;
use super::super::authorization::{refusal_principal, slot_principal};
use super::super::hardened_identity::hardened_identity_refusal;
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::oauth::OAuthAgentIdentity;
use crate::gateway::router::helpers::build_http_error_response;
use crate::identity_grants::GrantSubject;
use crate::key_server::oidc::VerifiedIdentity;
use crate::mtls::CertIdentity;

/// A refusal already shaped as the route's HTTP answer.
pub(super) type Rejection = (StatusCode, Json<Value>);

/// Everything the route learns about the caller before the body is read.
pub(super) struct Caller {
    /// The generation pinned on arrival; every judgement on this call reads
    /// it (ADR-023).
    pub(super) generation: std::sync::Arc<crate::config_reload::Generation>,
    pub(super) client: Option<AuthenticatedClient>,
    pub(super) cert_identity: Option<CertIdentity>,
    pub(super) oauth_agent_identity: Option<OAuthAgentIdentity>,
    pub(super) proven: Option<String>,
    pub(super) slot: Option<String>,
    pub(super) verified_identity: Option<VerifiedIdentity>,
    /// Captured before the body is consumed: the passthrough path reads the
    /// caller's own backend credential from the operator-named header.
    pub(super) inbound_headers: HeaderMap,
    pub(super) grant_subject: Option<GrantSubject>,
    /// The caller's own spend key (MIK-7653), empty for a keyless caller.
    /// Owned here so a session-less call's `BackendCall` can borrow it for
    /// the whole route.
    pub(super) spend_key: String,
    /// The agent identity `validate_agent` extracted, kept so the dispatch
    /// chokepoint judges the proven agent the entry check saw (MIK-8351).
    pub(super) agent_identity: Option<crate::security::AgentIdentity>,
}

impl Caller {
    /// The caller as the identity resolvers take it. Classified once for every
    /// credential this route resolves, notifications included (#2190): a
    /// validated credential can be the sole operator.
    pub(super) fn proof(&self) -> crate::identity_propagation::CallerProof<'_> {
        crate::identity_propagation::CallerProof::new(
            self.verified_identity.as_ref(),
            crate::identity_propagation::CallerProvenance::classify(
                self.client
                    .as_ref()
                    .map(|client| client.principal.storage_form()),
            ),
        )
    }

    pub(super) fn task_caller(
        &self,
    ) -> crate::gateway::router::handlers::tasks::owner::TaskCaller<'_> {
        crate::gateway::router::handlers::tasks::owner::TaskCaller {
            verified_identity: self.verified_identity.as_ref(),
            agent: self.oauth_agent_identity.as_ref(),
            subject: self.grant_subject.as_ref(),
            cert: self.cert_identity.as_ref(),
            client: self.client.as_ref(),
        }
    }
}

/// C5 route parity (MIK-6746): `require_id` and the `known_agents` allowlist
/// are enforced in `meta_mcp_dispatch` for /mcp, so this route runs the same
/// check, before the body is read. Without it the allowlist is bypassable by
/// choosing the /mcp/{name} URL.
fn validate_agent(
    state: &AppState,
    request: &axum::http::Request<axum::body::Body>,
    caller: &Caller,
) -> Result<crate::security::AgentIdentity, Rejection> {
    let agent_identity = crate::security::extract_agent_identity(
        &caller.inbound_headers,
        request.uri().query(),
        caller.cert_identity.as_ref(),
        caller
            .oauth_agent_identity
            .as_ref()
            .map(|a| a.client_id.as_str()),
    );
    match crate::security::validate_agent_identity(&agent_identity, &state.agent_identity_config) {
        Ok(audit) => {
            crate::security::log_agent_identity(&agent_identity, audit, None);
            Ok(agent_identity)
        }
        Err(reason) => {
            crate::security::log_agent_identity(
                &agent_identity,
                crate::security::IdentityAudit::Clean,
                Some(&reason),
            );
            Err(build_http_error_response(
                None,
                INVALID_REQUEST,
                reason,
                StatusCode::FORBIDDEN,
            ))
        }
    }
}

/// Stage 1: resolve the caller. Returns it with the subject key, which the
/// routing stage consumes by value (`owner_of` takes it), and the request,
/// owned across the awaits as it always was (a `&Request` is not `Send`).
pub(super) async fn resolve_caller(
    state: &AppState,
    request: axum::http::Request<axum::body::Body>,
) -> Result<
    (
        Caller,
        Option<String>,
        axum::http::Request<axum::body::Body>,
    ),
    Rejection,
> {
    // Fail closed: a reader never falls back to the current generation.
    let generation =
        crate::gateway::router::pinned_generation(request.extensions()).ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": crate::gateway::router::UNPINNED })),
            )
        })?;
    let client = request.extensions().get::<AuthenticatedClient>().cloned();
    let cert_identity = request.extensions().get::<CertIdentity>().cloned();
    let oauth_agent_identity = request.extensions().get::<OAuthAgentIdentity>().cloned();
    let proven = refusal_principal(
        client.as_ref(),
        oauth_agent_identity.as_ref(),
        cert_identity.as_ref(),
    );
    let slot = slot_principal(
        client.as_ref(),
        oauth_agent_identity.as_ref(),
        cert_identity.as_ref(),
    );
    // End-user identity for propagation (MIK-6704): the auth middleware may
    // attach a VerifiedIdentity for temporary/delegated OIDC tokens.
    let verified_identity = request.extensions().get::<VerifiedIdentity>().cloned();
    let mut caller = Caller {
        generation,
        client,
        cert_identity,
        oauth_agent_identity,
        proven,
        slot,
        verified_identity,
        inbound_headers: request.headers().clone(),
        grant_subject: None,
        spend_key: String::new(),
        agent_identity: None,
    };
    caller.agent_identity = Some(validate_agent(state, &request, &caller)?);

    // The caller as the meta route resolves it, resolved before the body is
    // read, so a refused identity header reaches no passthrough, propagation
    // or idempotency work on this route either.
    let peer = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0);
    caller.grant_subject = match super::super::identity::caller_grant_subject(
        caller.verified_identity.as_ref(),
        &caller.inbound_headers,
        peer,
        state.meta_mcp.caller_identity(),
        state.meta_mcp.access_verifier(),
        caller.cert_identity.as_ref(),
        caller.oauth_agent_identity.as_ref(),
    )
    .await
    {
        Ok(admission) => admission.subject,
        Err(refusal) => return Err(super::super::identity::identity_refusal_response(refusal)),
    };
    caller.spend_key = super::super::identity::caller_key(
        caller.grant_subject.as_ref(),
        caller.cert_identity.as_ref(),
        caller.client.as_ref(),
    );
    let key = super::super::identity::subject_key(
        caller.grant_subject.as_ref(),
        caller.cert_identity.as_ref(),
    );
    if let Some(no) = hardened_identity_refusal(state, key.as_deref(), request.extensions().get()) {
        return Err(no);
    }
    // The caller holds its generation; a reload from here on must not reach it.
    #[cfg(test)]
    crate::gateway::meta_mcp::visible::seams::caller_resolved();
    Ok((caller, key, request))
}

/// The request as parsed: the body, the attestation token taken off it, and
/// the JSON-RPC envelope.
pub(super) struct Envelope {
    pub(super) json_request: Value,
    pub(super) attestation: Option<String>,
    pub(super) id: Option<crate::protocol::RequestId>,
    pub(super) method: String,
    pub(super) params: Option<Value>,
    /// What the request declared, read once by
    /// `hardened_elicitation::classify_direct`: a modern request gets the
    /// 2026-07-28 result shape on the way out (MIK-8022).
    pub(super) era: crate::protocol::meta::Era,
    /// What a modern request declared it can be asked (MIK-8089); nothing for
    /// a legacy one, as on `/mcp`. Read from the same classification as `era`.
    pub(super) declared: crate::protocol::meta::Declared,
}

/// Stage 2: read and parse the body, fill the D2-a audit slot, refuse a keyed
/// call with no execution principal (MIK-8382 intake), then refuse what the
/// envelope and the key's scope forbid. Consumes `request`.
pub(super) async fn read_envelope(
    state: &AppState,
    name: &str,
    request: axum::http::Request<axum::body::Body>,
    caller: &Caller,
    (call, reads): (
        &mut Option<super::direct_audit::DirectCall>,
        &mut super::direct_audit::DirectReads,
    ),
) -> Result<Envelope, Rejection> {
    reads.name_caller(caller.client.as_ref(), caller.grant_subject.as_ref());
    let sanitize_input = caller.generation.sanitize_input();
    let body_bytes = crate::gateway::router::helpers::read_body(request).await?;
    let mut json_request: Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(e) => {
            return Err(build_http_error_response(
                None,
                PARSE_ERROR,
                format!("Invalid JSON: {e}"),
                StatusCode::BAD_REQUEST,
            ));
        }
    };

    // D2-a: the slot is filled before the envelope is validated, so a
    // malformed tools/call is recorded as `invalid` too.
    *call = super::direct_audit::DirectCall::of(
        &json_request,
        caller.client.as_ref(),
        caller.grant_subject.as_ref(),
        state.live_config.generation().auth().record_key(),
    );
    reads.capture(state, &json_request, || caller.spend_key.clone());

    // After the audit hash (D2-e: params as sent), before anything else reads
    // the request: parse, telemetry and every forwarding arm see no token.
    let attestation = super::take_attestation_token(json_request.get_mut("params"));

    // MIK-8382 intake: protocol fields are validated first (with sanitizing
    // on, as `/mcp` does), then a keyed call with no execution principal is
    // refused before sanitizing, the parse, the backend lookup and every
    // backend touch, so it gets one answer whatever the tool or backend name.
    // It reads only fields validation checked and sanitizing never changes.
    if sanitize_input {
        validated(&json_request)?;
    }
    if let Some(refusal) = intake_refusal(state, &json_request, caller) {
        return Err(refusal);
    }
    if sanitize_input {
        let grant = crate::gateway::authz::BackendGrant::of(caller.client.as_ref());
        json_request = sanitized(state, (name, grant), json_request)?;
    }

    let (id, method, params) = match crate::gateway::router::helpers::parse_request(&json_request) {
        Ok(parsed) => parsed,
        Err(response) => {
            return Err(crate::gateway::router::helpers::build_http_response(
                &Egressed::gateway_own(response),
                StatusCode::BAD_REQUEST,
            ));
        }
    };

    // MIK-8387 S4: for a scoped key, a backend outside its scope answers as a
    // missing one (404), so the key cannot tell which names exist. The record
    // keeps the scope refusal's code for a tool call. Before the backend
    // lookup and the idempotency short-circuit. An empty grant keeps its own
    // named 403 below (D2), and so does an unscoped caller.
    let grant = crate::gateway::authz::BackendGrant::of(caller.client.as_ref());
    if let Some(absence) = state.meta_mcp.scoped(grant).absence(name) {
        let tool = params
            .as_ref()
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str);
        if absence == crate::gateway::meta_mcp::scoped_backends::Absence::OutOfScope
            && method == "tools/call"
            && let Some(tool) = tool
        {
            crate::gateway::meta_mcp::visible::memo::note_denial_code(name, tool, -32003);
        }
        return Err(backend_not_found(name));
    }
    // D2-b: scope is checked after the parse, so its refusal names the tool,
    // and before the backend lookup. Only an empty grant reaches it now.
    if let Some(ref client) = caller.client
        && !client.can_access_backend(name)
    {
        return Err(build_http_error_response(
            None,
            -32003,
            client.backend_refusal(name),
            StatusCode::FORBIDDEN,
        ));
    }

    let reading = super::super::hardened_elicitation::classify_direct(
        &caller.inbound_headers,
        &method,
        params.as_ref(),
    );
    // Before the backend lookup, under every posture (MIK-8040): what `/mcp`
    // refuses is refused here with the same code and status, so an unknown
    // backend gets the request refusal (no existence oracle). Under
    // `hardened` (GH1942.HARDEN.1 row 10) this route, which keeps no
    // handshake state, also serves no legacy request other than an
    // `initialize` that declares elicitation.
    if let Some(refusal) = super::super::hardened_elicitation::direct_refusal(
        state,
        &caller.inbound_headers,
        &json_request,
        (&method, params.as_ref()),
        id.as_ref(),
        (&reading.0, reading.1),
    ) {
        return Err(refusal);
    }
    // Every modern request reaching here passed the `/mcp` checks above, so
    // its reading is the era `/mcp` would answer in.
    let era = reading.0.era();
    let declared = if era == crate::protocol::meta::Era::Modern {
        reading.0.declared_capabilities()
    } else {
        crate::protocol::meta::Declared::NONE
    };
    Ok(Envelope {
        json_request,
        attestation,
        id,
        method,
        params,
        era,
        declared,
    })
}

/// The key a caller's explicit cancel of its own call `id` is registered and
/// looked up under on this route (MIK-7642 PR.C, design r5 D3, r4 R4.2): the
/// backend, the caller's key (`identity::caller_key`: its subject, else its
/// authenticated credential), its validated session, and the client's id.
/// `None` for a caller with neither: its cancels are always dropped.
pub(super) fn explicit_cancel_key(
    backend: &str,
    caller: &Caller,
    session: Option<&str>,
    id: &Value,
) -> Option<crate::gateway::router::inflight_calls::CallKey> {
    let owner = Some(caller.spend_key.as_str());
    crate::gateway::router::inflight_calls::CallKey::new(backend, owner, session, id)
}

/// The direct route's answer for a backend it cannot reach: 404, -32001.
fn backend_not_found(name: &str) -> Rejection {
    build_http_error_response(
        None,
        -32001,
        format!("Backend not found: {name}"),
        StatusCode::NOT_FOUND,
    )
}

/// What stage 3 resolved: the backend and the session the caller owns.
pub(super) struct Route<'a> {
    pub(super) backend: std::sync::Arc<crate::backend::Backend>,
    pub(super) session_id: Option<&'a str>,
}

/// The session `caller` presents, counted only when the caller owns it, by
/// the `/mcp` owner rule; presenting it counts as the session's activity.
/// Resolved once, before the hiding judgment, so the call is judged and
/// routed under one profile. `key` is consumed: `owner_of` takes it by value.
pub(super) fn owned_session<'a>(
    state: &AppState,
    caller: &'a Caller,
    key: Option<String>,
) -> Option<&'a str> {
    let owner =
        super::super::handlers::owner_of(key, &caller.inbound_headers, caller.client.as_ref());
    caller
        .inbound_headers
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
        .filter(|id| state.multiplexer.touch_if_owned(id, &owner))
}

/// Stage 3: find the backend and apply the admin gate, under the caller's
/// owned session ([`owned_session`]).
pub(super) fn route<'a>(
    state: &AppState,
    name: &str,
    caller: &'a Caller,
    session_id: Option<&'a str>,
    envelope: &Envelope,
) -> Result<Route<'a>, Rejection> {
    let Some(backend) = super::super::backend_choke::backend_for(
        state,
        crate::gateway::authz::BackendGrant::of(caller.client.as_ref()),
        name,
    ) else {
        return Err(backend_not_found(name));
    };

    if !crate::gateway::router::helpers::observe_http(
        &envelope.json_request,
        envelope.params.as_ref(),
        &envelope.method,
        &caller.inbound_headers,
        session_id,
        &state.meta_mcp.window_seal,
    ) {
        return Err(crate::gateway::router::helpers::window_sealed_response(
            &envelope.json_request,
        ));
    }
    let client_name = caller.client.as_ref().map(|c| &c.name);
    tracing::debug!(backend = %name, method = %envelope.method, client = ?client_name, "Backend request");

    // One backend's level is still shared by every user of that backend, so
    // this route applies the meta route's admin gate before anything forwards.
    // The helper owns the (case-insensitive) method match.
    if let Err(e) = super::super::authorization::require_admin_log_level(
        &envelope.method,
        caller.client.as_ref(),
        caller.proven.as_deref(),
        name,
    ) {
        return Err(build_http_error_response(
            envelope.id.clone(),
            e.code,
            e.message,
            e.status,
        ));
    }
    Ok(Route {
        backend,
        session_id,
    })
}

/// Answers `events/lease` itself, never forwarded,
/// so the backend sees no request. The owner is the events owner principal
/// subscribe keys rows by (D4); the token is the caller's own passthrough
/// header, moved straight into a wiping buffer.
pub(super) async fn events_lease(
    state: &AppState,
    name: &str,
    caller: &Caller,
    params: Option<&Value>,
    id: crate::protocol::RequestId,
) -> Rejection {
    let answer = match state.meta_mcp.events() {
        None => Err(crate::events::RpcError::method_not_found()),
        Some(hub) => {
            let owners = crate::gateway::router::handlers::tasks::owner::route_owners(
                state,
                &caller.task_caller(),
            );
            let principal = crate::gateway::router::handlers::events::principal(
                &owners.events,
                state.live_config.generation().auth().enabled,
            );
            let token = caller
                .inbound_headers
                .get(super::PASSTHROUGH_HEADER)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(|v| zeroize::Zeroizing::new(v.to_owned()));
            hub.lease(principal.as_deref(), name, params, token).await
        }
    };
    let reply = match answer {
        Ok(result) => crate::protocol::JsonRpcResponse::success(id, result),
        Err(crate::events::RpcError {
            code,
            message,
            data: Some(data),
        }) => crate::protocol::JsonRpcResponse::error_with_data(Some(id), code, message, data),
        Err(crate::events::RpcError { code, message, .. }) => {
            crate::protocol::JsonRpcResponse::error(Some(id), code, message)
        }
    };
    (
        StatusCode::OK,
        Json(serde_json::to_value(reply).unwrap_or(Value::Null)),
    )
}

/// Terminal arm for `notifications/*`: forward to the backend, answer 202.
/// The bucket is the one a matching `request_with_headers` call for this
/// caller would use (MIK-6735 fix 2), so a notification correlating that
/// request lands on the same upstream session. Not routed through the
/// `isolation_guarded` gate (no id, no tool policy), but refused where this
/// caller's request would be refused for its identity (#2240).
pub(super) async fn forward_notification(
    state: &AppState,
    name: &str,
    caller: &Caller,
    route: &Route<'_>,
    envelope: Envelope,
) -> Rejection {
    // MIK-8072: a client's cancel names the client's request id, which the
    // backend never saw (each transport numbers its own requests), so it is
    // never forwarded: another caller's call may hold that number. MIK-7642
    // PR.C: it aborts the call this same caller registered under that id, if
    // one is in flight, and the transport then cancels that call on the
    // backend by the backend's own id. Answered before any per-caller
    // credential is minted or leased.
    if envelope.method == "notifications/cancelled" {
        let aborted = envelope
            .params
            .as_ref()
            .and_then(|params| params.get("requestId"))
            .and_then(|id| explicit_cancel_key(name, caller, route.session_id, id))
            .is_some_and(|key| state.meta_mcp.inflight_calls().cancel(&key));
        tracing::debug!(backend = %name, aborted, "Client cancel never forwarded");
        return (StatusCode::ACCEPTED, Json(serde_json::json!({})));
    }
    let Ok(super::notification_key::Resolved { headers, binding }) =
        super::notification_key::resolve(
            state,
            &route.backend,
            name,
            &caller.inbound_headers,
            caller.proof(),
            // The credential's slot principal, as the request arm charges it,
            // not the display label two credentials can share (MIK-7885).
            caller.slot.as_deref(),
        )
        .await
    else {
        // Refused as this caller's request would be (#2240): nothing is
        // forwarded, and the client breaker is untouched, as for
        // `direct_refusal`. `{}` is what an accepted notification gets.
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({})));
    };
    match route
        .backend
        .notify_with_headers_lent(
            &envelope.method,
            envelope.params,
            headers,
            binding.as_deref(),
        )
        .await
    {
        Ok(()) => {
            super::record_client_success(state, caller.client.as_ref());
            (StatusCode::ACCEPTED, Json(serde_json::json!({})))
        }
        // No free caller slot (#2300): dropped, counted at admission, and
        // answered with no JSON-RPC body, as a notification must be.
        Err(e @ crate::Error::IdentitySlotsExhausted { .. }) => {
            tracing::warn!(backend = %name, error = %e, "Notification dropped");
            (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({})))
        }
        Err(e) => {
            super::record_client_failure(state, caller.client.as_ref());
            // The code only: the error's text can be the backend's.
            tracing::error!(backend = %name, code = e.to_rpc_code(), "Backend notification failed");
            let mut response =
                crate::protocol::JsonRpcResponse::error(None, e.to_rpc_code(), e.to_string());
            let call = crate::gateway::meta_mcp::invoke::dispatch_guards::BackendCall {
                server: name,
                tool: &envelope.method,
                session_id: None,
                api_key_name: None,
                cost_key: None,
                trace_id: &envelope.method,
                caller_key: None,
            };
            let screen = (
                &call,
                crate::gateway::meta_mcp::invoke::egress::ContentChecks::Here,
            );
            let client = caller.client.as_ref();
            super::super::direct_guards::scan_direct_egress(state, screen, client, &mut response);
            crate::gateway::router::helpers::build_http_response(
                &Egressed::of(response),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
}

/// A refusal of the sanitize step's: HTTP 400 with the error's code and text.
fn refused(id: Option<crate::protocol::RequestId>, e: &crate::Error) -> Rejection {
    build_http_error_response(id, e.to_rpc_code(), e.to_string(), StatusCode::BAD_REQUEST)
}

/// MIK-8154 S2': the request's protocol fields validated, before the intake
/// check reads any of them. Its refusal answers no id (the id may be what is
/// dirty).
fn validated(request: &Value) -> Result<(), Rejection> {
    crate::security::sanitize::validate_protocol_fields(
        request,
        &crate::gateway::PROTOCOL_NONCES,
        crate::security::sanitize::ProtocolRoute::Direct,
    )
    .map_err(|e| refused(None, &e))
}

/// MIK-8382 UNIFY.1a′: the intake refusal for a keyed `tools/call` from a
/// caller with no execution principal: -32003, HTTP 400, the request's own
/// id. The owner and principal are read as admission reads them
/// (`direct_idempotency.rs`), through the one shared function.
fn intake_refusal(state: &AppState, request: &Value, caller: &Caller) -> Option<Rejection> {
    let task_caller = caller.task_caller();
    let owner = super::super::handlers::tasks::owner::route_owners(state, &task_caller).admission;
    let error = crate::gateway::meta_mcp::intake_refusal(
        request,
        crate::gateway::meta_mcp::AdmissionOwner::routed(&owner),
        caller
            .client
            .as_ref()
            .map(|client| client.principal.storage_form()),
        caller.grant_subject.as_ref(),
        Some(caller.spend_key.as_str()).filter(|key| !key.is_empty()),
    )?;
    Some(refused(
        crate::protocol::mrtr::raw_request_id(request),
        &error,
    ))
}

/// MIK-8154 SAN.1: the one sanitize step on the direct route, after protocol
/// fields are validated and the intake check: the whole request sanitized
/// unless the backend this route names is `passthrough` (option (a)), whose
/// instance is then recorded (F2).
fn sanitized(
    state: &AppState,
    (name, grant): (&str, crate::gateway::authz::BackendGrant<'_>),
    request: Value,
) -> Result<Value, Rejection> {
    use crate::security::sanitize::{ProtocolRoute, sanitize_request_in_place};
    let exempt = state.meta_mcp.passthrough_instance(grant, name);
    if let Some(instance) = &exempt {
        crate::gateway::meta_mcp::visible::memo::record_exempt_instances(std::slice::from_ref(
            instance,
        ));
    }
    // Intake has judged; the window a reload must not reach (MIK-8154 F2).
    #[cfg(test)]
    crate::gateway::meta_mcp::visible::seams::intake_judged();
    if exempt.is_some() {
        return Ok(request);
    }
    let id = crate::protocol::mrtr::raw_request_id(&request);
    // In place (MIK-8499): refused on an error, so a partly rewritten tree
    // is never used.
    let mut request = request;
    sanitize_request_in_place(&mut request, ProtocolRoute::Direct).map_err(|e| refused(id, &e))?;
    Ok(request)
}
