// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Stage 1 of the direct backend route: who is calling.
//!
//! Resolved before the body is read, so a refused identity header reaches no
//! passthrough, propagation or idempotency work. The order of every check and
//! every early return is the order `backend_handler_inner` always had.

use axum::{Json, http::HeaderMap, http::StatusCode};
use serde_json::Value;

use super::super::AppState;
use super::super::authorization::{refusal_principal, slot_principal};
use super::super::hardened_identity::hardened_identity_refusal;
use super::super::helpers::build_http_error_response;
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::oauth::AgentIdentity as OAuthAgentIdentity;
use crate::identity_grants::GrantSubject;
use crate::key_server::oidc::VerifiedIdentity;
use crate::mtls::CertIdentity;

/// A refusal already shaped as the route's HTTP answer.
pub(super) type Rejection = (StatusCode, Json<Value>);

/// Everything the route learns about the caller before the body is read.
pub(super) struct Caller {
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
}

impl Caller {
    /// The caller as the identity resolvers take it. Classified once for every
    /// credential this route resolves, notifications included (#2190): a
    /// validated credential can be the sole operator.
    pub(super) fn proof(&self) -> crate::identity_propagation::CallerProof<'_> {
        crate::identity_propagation::CallerProof::new(
            self.verified_identity.as_ref(),
            crate::identity_propagation::CallerProvenance::classify(
                self.client.as_ref().map(|client| client.principal.as_str()),
            ),
        )
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
) -> Result<(), Rejection> {
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
            Ok(())
        }
        Err(reason) => {
            crate::security::log_agent_identity(
                &agent_identity,
                crate::security::IdentityAudit::Clean,
                Some(&reason),
            );
            Err(build_http_error_response(
                None,
                -32600,
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
        client,
        cert_identity,
        oauth_agent_identity,
        proven,
        slot,
        verified_identity,
        inbound_headers: request.headers().clone(),
        grant_subject: None,
        spend_key: String::new(),
    };
    validate_agent(state, &request, &caller)?;

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
        Ok(subject) => subject,
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
}

/// Stage 2: read and parse the body, fill the D2-a audit slot, then refuse
/// what the envelope and the key's scope forbid. Consumes `request`.
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
    let body_bytes = super::super::helpers::read_body(request).await?;
    let mut json_request: Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(e) => {
            return Err(build_http_error_response(
                None,
                -32700,
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
    );
    reads.capture(state, &json_request, || caller.spend_key.clone());

    // After the audit hash (D2-e: params as sent), before anything else reads
    // the request: parse, telemetry and every forwarding arm see no token.
    let attestation = super::take_attestation_token(json_request.get_mut("params"));

    let (id, method, params) = match super::super::helpers::parse_request(&json_request) {
        Ok(parsed) => parsed,
        Err(response) => {
            return Err(super::super::helpers::build_http_response(
                &response,
                StatusCode::BAD_REQUEST,
            ));
        }
    };

    // D2-b: scope is checked after the parse, so its refusal names the tool,
    // and before the backend lookup, so a scoped key gets 403 for an unknown
    // backend as for a forbidden one, never a 404 existence oracle.
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
    // Hardened (GH1942.HARDEN.1 row 10), before the backend lookup: this
    // route keeps no handshake state, so it serves no legacy request other
    // than an `initialize` that declares elicitation.
    if super::super::hardened_elicitation::is_hardened(state)
        && let Some(refusal) = super::super::hardened_elicitation::direct_refusal(
            state,
            &caller.inbound_headers,
            &json_request,
            (&method, params.as_ref()),
            id.as_ref(),
            (&reading.0, reading.1),
        )
    {
        return Err(refusal);
    }
    let era = reading.0.era();
    Ok(Envelope {
        json_request,
        attestation,
        id,
        method,
        params,
        era,
    })
}

/// What stage 3 resolved: the backend and the session the caller owns.
pub(super) struct Route<'a> {
    pub(super) backend: std::sync::Arc<crate::backend::Backend>,
    pub(super) session_id: Option<&'a str>,
}

/// Stage 3: find the backend, the caller's session, and apply the admin gate.
/// `key` is consumed: `owner_of` takes it by value.
pub(super) fn route<'a>(
    state: &AppState,
    name: &str,
    caller: &'a Caller,
    key: Option<String>,
    envelope: &Envelope,
) -> Result<Route<'a>, Rejection> {
    let Some(backend) = state.backends.get(name) else {
        return Err(build_http_error_response(
            None,
            -32001,
            format!("Backend not found: {name}"),
            StatusCode::NOT_FOUND,
        ));
    };

    let protocol_header = caller
        .inbound_headers
        .get("mcp-protocol-version")
        .and_then(|value| value.to_str().ok());
    // A presented session counts only for its owner, by the `/mcp` owner rule.
    let owner =
        super::super::handlers::owner_of(key, &caller.inbound_headers, caller.client.as_ref());
    let session_id = caller
        .inbound_headers
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
        .filter(|id| state.multiplexer.touch_if_owned(id, &owner));
    crate::protocol_revision_telemetry::observe_inbound_request(
        &envelope.json_request,
        envelope.params.as_ref(),
        &envelope.method,
        protocol_header,
        session_id,
        crate::protocol_revision_telemetry::Transport::Http,
    );
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
        .notify_with_headers(
            &envelope.method,
            envelope.params,
            &headers,
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
            tracing::error!(backend = %name, error = %e, "Backend notification failed");
            let response =
                crate::protocol::JsonRpcResponse::error(None, e.to_rpc_code(), e.to_string());
            super::super::helpers::build_http_response(&response, StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
