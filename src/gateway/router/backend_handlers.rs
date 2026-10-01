// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Backend and cost API request handlers.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::{debug, error, warn};

use super::AppState;
use super::authorization::{
    ToolTarget, authorize_tool_target, refusal_principal, require_admin_log_level,
};
use super::direct_guards::{DirectRouteGuards, refusal};
use super::hardened_identity::hardened_identity_refusal;
use super::helpers::{build_http_error_response, build_http_response, parse_request};
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::meta_mcp::invoke::dispatch_guards::BackendCall;
use crate::gateway::oauth::AgentIdentity as OAuthAgentIdentity;
use crate::mtls::CertIdentity;
use crate::personal_accounts::refusal::refusal_text;
use crate::protocol::{JsonRpcResponse, RequestId, Tool};
#[cfg(feature = "firewall")]
use crate::security::firewall::FirewallAction;
use crate::security::{sanitize_json_value, validate_tool_name};
use crate::trust::project_tool_descriptors_trust_cards;

type BackendRejection = (StatusCode, Json<Value>);
type BackendSecurityResult = Result<Option<Value>, BackendRejection>;

/// Forwarded passthrough headers paired with the caller's stable upstream-session
/// bucket key (MIK-6785): `Some(sha256_hex(credential))` when a credential is
/// forwarded, `None` on the no-credential path. See [`resolve_passthrough_headers`].
type PassthroughResolution = (Vec<(String, String)>, Option<String>);

#[derive(Clone, Copy)]
struct BackendAuthContext<'a> {
    client: Option<&'a AuthenticatedClient>,
    oauth_agent_identity: Option<&'a OAuthAgentIdentity>,
    cert_identity: Option<&'a CertIdentity>,
    /// The caller as a grant subject, resolved for this request: the only
    /// carrier of an OIDC or trusted-header subject on this route.
    #[cfg(feature = "firewall")]
    grant_subject: Option<&'a crate::identity_grants::GrantSubject>,
}

/// The key the direct route's per-caller firewall controls score on: the
/// caller's `CallerKey`, as on the meta route, so one caller has one budget on
/// both. With no key (authentication off) it is the shared per-backend bucket,
/// never tracked; a keyed caller's reclaim deadline is renewed (CONTROL.4).
#[cfg(feature = "firewall")]
fn direct_control_identity(
    state: &AppState,
    auth: BackendAuthContext<'_>,
    per_backend: &str,
) -> String {
    let key = super::identity::caller_key(auth.grant_subject, auth.cert_identity, auth.client);
    if key.is_empty() {
        return per_backend.to_string();
    }
    if let Some(ref lifecycle) = state.session_lifecycle {
        use crate::gateway::session_lifecycle::{IDLE_TTL, now_unix};
        lifecycle.track(key.clone(), now_unix() + IDLE_TTL.as_secs());
    }
    key
}

/// Apply tool policy, name validation, and input sanitization to a `tools/call`
/// request arriving at the direct backend endpoint.
///
/// Returns `Ok(Some(sanitized))` when all checks pass, `Ok(None)` for a
/// passthrough backend, or `Err(response)` when a check fails and the caller
/// should return an HTTP error immediately. A call with no params or no tool
/// name is refused (400, -32602): with no name there is nothing to authorize,
/// so forwarding it would skip the per-tool check (D2).
///
/// Order of checks matches `meta_mcp_handler`:
/// 1. `validate_tool_name` — rejects dangerous names before any policy lookup.
/// 2. `tool_policy.check` — enforces global allow/deny rules.
/// 3. `sanitize_json_value` — strips/rejects dangerous byte sequences.
#[allow(clippy::result_large_err)]
async fn apply_backend_tool_call_security(
    state: &AppState,
    backend_name: &str,
    auth: BackendAuthContext<'_>,
    params: Option<&Value>,
    id: &RequestId,
    backend: &crate::backend::Backend,
    (slot, failed): (key_check::CallerSlot<'_>, &DirectFailure<'_>),
) -> BackendSecurityResult {
    let unnamed = || {
        let message = "tools/call requires params.name";
        build_http_error_response(Some(id.clone()), -32602, message, StatusCode::BAD_REQUEST)
    };
    let Some(params) = params else {
        return Err(unnamed());
    };
    let tool_name = params.get("name").and_then(Value::as_str).unwrap_or("");
    if tool_name.is_empty() {
        return Err(unnamed());
    }

    if let Err(e) = validate_tool_name(tool_name) {
        warn!(backend = %backend_name, tool = %tool_name, "Tool name rejected by validation");
        return Err(backend_security_error(id, &e));
    }

    let arguments = params.get("arguments").unwrap_or(params);
    let target = ToolTarget {
        server: backend_name,
        tool: tool_name,
        arguments,
    };
    if let Err(e) = authorize_tool_target(
        state,
        auth.client,
        auth.oauth_agent_identity,
        auth.cert_identity,
        target,
    ) {
        warn!(backend = %backend_name, tool = %tool_name, "Tool blocked by authorization");
        return Err(backend_security_error_with_status(
            id, e.code, &e.message, e.status,
        ));
    }

    #[cfg(feature = "firewall")]
    if let Some(ref fw) = state.firewall {
        let caller_name = auth.client.map_or("anonymous", |c| c.name.as_str());
        let session_id = format!("direct:{backend_name}");
        let control_identity = direct_control_identity(state, auth, &session_id);
        let verdict = fw.check_request(
            &session_id,
            backend_name,
            tool_name,
            arguments,
            caller_name,
            &control_identity,
        );
        if verdict.action == FirewallAction::Warn {
            warn!(
                backend = %backend_name,
                tool = %tool_name,
                findings = verdict.findings.len(),
                "Firewall: direct backend request warning"
            );
        }
        if !verdict.allowed {
            let desc = verdict
                .findings
                .first()
                .map_or("Security firewall blocked this request", |f| {
                    f.description.as_str()
                });
            // OWASP ASI10: an anomaly block carries -32002 on every route, as
            // on the meta route, so a caller can tell it from other refusals.
            if verdict.is_anomaly_block() {
                return Err(backend_security_error_with_status(
                    id,
                    -32002,
                    &format!("Anomaly detection blocked: {desc}"),
                    StatusCode::FORBIDDEN,
                ));
            }
            return Err(backend_security_error(
                id,
                &format!("Firewall blocked: {desc}"),
            ));
        }
    }

    // MIK-7570.SCHEMA.1 (R2), F13: above the passthrough return, so a
    // passthrough backend is checked too.
    if let Some(rejection) = key_check::key_refusal(backend, (slot, failed), params, id).await {
        return Err(rejection);
    }

    if backend.passthrough() {
        return Ok(None);
    }

    match sanitize_json_value(params) {
        Ok(sanitized) => Ok(Some(sanitized)),
        Err(e) => {
            warn!(backend = %backend_name, tool = %tool_name, "Input sanitization failed");
            Err(backend_security_error(id, &e.to_string()))
        }
    }
}

/// What a direct-route call's token must grant (MIK-7570.ATTEST.1 part 3).
///
/// A missing target field is matched as the empty capability, which only a
/// `"*"` token satisfies: a malformed call never falls back to authenticity.
/// A method outside the table needs `"*"`, so a narrowly scoped token cannot
/// drive a vendor method whose side effects the gateway cannot see.
fn direct_route_attestation_scope<'a>(
    method: &str,
    params: Option<&'a Value>,
) -> crate::attestation::validator::AttestationScope<'a> {
    use crate::attestation::validator::AttestationScope;
    let field = |name: &str| {
        let value = params.and_then(|p| p.get(name));
        value.and_then(Value::as_str).unwrap_or_default()
    };
    match method {
        "tools/call" | "prompts/get" => AttestationScope::Capability(field("name")),
        "resources/read" | "resources/subscribe" | "resources/unsubscribe" => {
            AttestationScope::Capability(field("uri"))
        }
        "tools/list"
        | "resources/list"
        | "resources/templates/list"
        | "prompts/list"
        | "completion/complete"
        | "logging/setLevel" => AttestationScope::AuthenticOnly,
        _ => AttestationScope::Capability("*"),
    }
}

/// Remove the attestation token from `params._meta` and return it if a string.
fn take_attestation_token(params: Option<&mut Value>) -> Option<String> {
    let meta = params?.get_mut("_meta")?.as_object_mut()?;
    let token = meta.remove(crate::protocol::mrtr::ATTESTATION_META)?;
    token.as_str().map(str::to_owned)
}

/// Build a `403 Forbidden` JSON-RPC error response for security rejections.
fn backend_security_error(id: &RequestId, message: &str) -> (StatusCode, Json<Value>) {
    build_http_error_response(Some(id.clone()), -32600, message, StatusCode::FORBIDDEN)
}

fn backend_security_error_with_status(
    id: &RequestId,
    code: i32,
    message: &str,
    status: StatusCode,
) -> (StatusCode, Json<Value>) {
    build_http_error_response(Some(id.clone()), code, message, status)
}

/// Fill missing MCP tool annotation hints on direct backend `tools/list`
/// responses before returning them to clients.
fn normalize_tools_list_response(
    backend: &crate::backend::Backend,
    response: &mut JsonRpcResponse,
) {
    let backend_name = backend.name.as_str();
    if response.error.is_some() {
        // Never forward an unjudged list beside an error (#1441).
        response.result = None;
        return;
    }

    let Some(result) = response.result.as_mut() else {
        return;
    };
    let Some(tools_value) = result.get_mut("tools") else {
        return;
    };

    let Some(items) = tools_value.as_array() else {
        warn!(backend = %backend_name, "Backend tools/list result is not an array");
        return;
    };

    // Element by element: one unparseable descriptor must not forward the
    // whole list verbatim (a bypass). It is dropped, since it cannot be judged
    // and would disclose a name the caller may not invoke (A3).
    let mut tools = Vec::with_capacity(items.len());
    for item in items {
        match serde_json::from_value::<Tool>(item.clone()) {
            Ok(tool) => tools.push(tool),
            Err(e) => {
                warn!(backend = %backend_name, error = %e, "Backend tools/list entry could not be normalized; dropped");
            }
        }
    }

    backend.prepare_judged_tools(&mut tools);

    let server_id = format!("backend:{backend_name}");
    let tools = project_tool_descriptors_trust_cards(&server_id, backend_name, &tools);

    // Rebuilt from an allowlist: `{ "tools": [...] }` and nothing else. An
    // upstream sibling key or cursor could name a withheld tool (A3).
    match serde_json::to_value(tools) {
        Ok(normalized_tools) => *result = json!({ "tools": normalized_tools }),
        Err(e) => {
            warn!(backend = %backend_name, error = %e, "Failed to serialize normalized tools/list");
        }
    }
}

/// Stable, collision-safe upstream-session bucket key for a passthrough caller
/// (MIK-6785). On the passthrough route the forwarded backend credential is the
/// only value that distinguishes one caller from another (there is usually no
/// gateway-verified identity), so the caller's `MCP-Session-Id` bucket is keyed
/// by the SHA-256 hex digest of that credential.
///
/// Privacy is load-bearing: the raw credential is hashed HERE, at the single
/// point it is read from the inbound header, and the digest — never the token —
/// becomes the in-memory `HttpTransport::sessions` map key. SHA-256 is one-way,
/// so a leaked bucket key cannot recover the credential, and the raw token is
/// never logged or stored anywhere else.
///
/// Correctness: distinct credentials produce distinct 64-char hex digests, hence
/// distinct session buckets (isolation); the same credential always produces the
/// same digest, hence a reused bucket (session continuity). A 64-char lowercase
/// hex digest can never collide with the minting path's `idp:`-prefixed bindings
/// nor with the shared default (`""`) bucket.
fn passthrough_identity_key(credential: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(credential.as_bytes());
    hex::encode(hasher.finalize())
}

/// The slot binding of a passthrough credential digest, charged to the
/// caller's principal so one caller cannot hold more than its share of the
/// backend's slots however many header values it sends (#2300). The principal
/// is the verified identity, else `proven` (the API key, agent token or client
/// certificate, as `refusal_principal` names it), else the one anonymous
/// principal every unauthenticated caller shares.
fn charged_binding(
    state: &AppState,
    name: &str,
    caller: crate::identity_propagation::CallerProof<'_>,
    proven: Option<&str>,
    digest: Option<String>,
) -> Option<String> {
    let principal = match (caller.verified(), proven) {
        (None, Some(proven)) => format!("proven:{proven}"),
        _ => state.meta_mcp.audit_subject_for(name, caller),
    };
    digest.map(|digest| crate::backend::passthrough_binding(&principal, &digest))
}

/// Resolve passthrough headers for the direct backend route (ADR-008 rung 2,
/// MIK-6746). Reads the caller's own backend credential from a fixed,
/// gateway-specific inbound header and forwards it to the backend under
/// `Authorization`. The gateway mints and stores NOTHING (INV-4). A dedicated
/// header (never the gateway-auth `Authorization`) means a multi-user gateway
/// can never forward its own inbound credential to a backend. Fail-closed: a
/// `required` backend with no caller credential returns `Err` (mapped to 403 by
/// the caller); a non-required backend with none returns an empty vec (static
/// path, after which the INV-2 guard decides whether a shared token may serve).
///
/// Returns `(headers, identity_key)`. `identity_key` (MIK-6785) is the caller's
/// stable upstream-session bucket key — `Some(sha256_hex(credential))` when a
/// credential is forwarded, so each distinct passthrough caller gets its own
/// `MCP-Session-Id` bucket and a stateful upstream cannot serve one caller's
/// session-bound data to another; `None` on the no-credential path (shared
/// default bucket, behavior unchanged). The credential is hashed at this single
/// read point (see [`passthrough_identity_key`]) so the raw token is never
/// re-extracted from the header vec downstream.
///
/// Also fails closed (MIK-6710) BEFORE reading the inbound header when
/// `transport_carries_headers` is `false` for a `required` backend — a stdio
/// or websocket backend would otherwise accept the caller's credential here
/// and then silently drop it in `request_with_headers`, running
/// unauthenticated while the audit trail records a resolved passthrough.
fn resolve_passthrough_headers(
    cfg: &crate::identity_propagation::IdentityPropagationConfig,
    inbound: &axum::http::HeaderMap,
    transport_carries_headers: bool,
) -> Result<PassthroughResolution, String> {
    // The inbound header a capable client attaches its backend credential in
    // (advertised via RFC 9728 protected-resource metadata, MIK-6750). Distinct
    // from `Authorization` so the gateway-auth token is never forwarded.
    const PASSTHROUGH_HEADER: &str = "x-mcp-passthrough-authorization";
    crate::identity_propagation::ensure_transport_carries_identity_headers(
        cfg.required,
        transport_carries_headers,
    )?;
    let missing = || {
        if cfg.required {
            Err(
                "identity propagation required for this backend but the caller supplied no \
                 passthrough credential (ADR-008 D.3, fail-closed)"
                    .to_string(),
            )
        } else {
            // No credential on a non-required backend: static path, and no
            // per-caller session bucket — the shared default bucket is used,
            // exactly as before MIK-6785.
            Ok((Vec::new(), None))
        }
    };
    match inbound
        .get(PASSTHROUGH_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        Some(v) => Ok((
            vec![("Authorization".to_string(), v.to_string())],
            // Hash the credential at its single read point (MIK-6785): the raw
            // token stays in the forwarded header vec only; the digest is the
            // caller's per-identity upstream session bucket key.
            Some(passthrough_identity_key(v)),
        )),
        None => missing(),
    }
}

// The audit subject is the resolver's (`MetaMcp::audit_subject_for`); the
// identity-only form stays in reach of this module's tests.
#[cfg(test)]
use crate::identity_propagation::audit_subject;

// One writer for identity-propagation audit on both routes (the direct
// route used to carry a hand copy of it).
use crate::identity_propagation::audit_identity_propagation;

/// Dispatch a direct-route request to a backend inside a notification scope.
///
/// The scope is the only reason this wrapper exists: without one,
/// `mint_progress_token` returns `None` and `Backend::request*` hands the
/// backend the caller's own `_meta.progressToken` (MIK-7272.SUB.2b / ADR-014
/// section 2), which is precisely what the mint exists to prevent. This route
/// has no client-facing stream, so the drained notifications are discarded --
/// unscoped they were already dropped inside `publish`, so scoping changes
/// nothing about delivery and buys the substitution.
async fn dispatch_in_scope(
    backend: &crate::backend::Backend,
    method: &str,
    id: &RequestId,
    params: Option<Value>,
    propagated_headers: &[(String, String)],
    identity_key: Option<&str>,
) -> crate::Result<JsonRpcResponse> {
    // `method` here is client-chosen, so this funnel refuses whatever the
    // peer's era removed before it reaches the wire (MIK-7217, OUTBOUND.1),
    // with the caller's own id: an `id: null` error cannot be correlated.
    if crate::gateway::meta_mcp::era_removed_method(backend, method).await {
        return Ok(JsonRpcResponse::error(
            Some(id.clone()),
            crate::protocol::era::METHOD_NOT_FOUND_CODE,
            format!("{method} was removed in protocol revision 2026-07-28"),
        ));
    }
    let (response, _discarded) = crate::transport::notification_sink::collect(async {
        if propagated_headers.is_empty() && identity_key.is_none() {
            backend.request(method, params).await
        } else {
            backend
                .request_with_headers(method, params, propagated_headers, identity_key)
                .await
        }
    })
    .await;
    response
}

/// Whether a direct-route request reaches task state.
///
/// Every `tasks/*` method, in any letter case, because a backend that matches
/// names loosely acts on a case variant as the real method; plus
/// `subscriptions/listen` naming `taskIds`. KEEP IN STEP with
/// `reaches_tasks_extension` in `router/handlers.rs`: a task-reaching method
/// added there and not here is forwarded here without an owner check.
/// The one intended difference: `tools/call` carrying `task` still forwards;
/// task creation on this route is separate work (LIFECYCLE.1).
fn is_task_method(method: &str, params: Option<&Value>) -> bool {
    method
        .get(..6)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("tasks/"))
        || (method.eq_ignore_ascii_case("subscriptions/listen")
            && params.is_some_and(|p| p.get("taskIds").is_some()))
}

/// Backend handler (POST /mcp/{name})
pub(super) async fn backend_handler(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    request: axum::http::Request<axum::body::Body>,
) -> impl IntoResponse {
    // Track in-flight request for graceful drain
    let _inflight_permit = state.inflight.acquire().await;

    // D1-f: while the audit log is down this route must not serve, or it is a
    // second, unaudited route. Checked before the body is read, so no D2 slot
    // exists yet and no record is attempted for this refusal.
    if let Some(log) = &state.transparency_log
        && log.admit().await.is_err()
    {
        let error = crate::Error::AuditUnavailable;
        return build_http_error_response(
            None,
            error.to_rpc_code(),
            error.to_string(),
            StatusCode::SERVICE_UNAVAILABLE,
        );
    }

    direct_audit::audited_call(Arc::clone(&state), name, request).await
}

#[allow(clippy::too_many_lines)]
async fn backend_handler_inner(
    state: Arc<AppState>,
    name: String,
    request: axum::http::Request<axum::body::Body>,
    call: &mut Option<direct_audit::DirectCall>,
) -> (StatusCode, Json<Value>) {
    // Extract authenticated client from extensions (injected by auth middleware)
    let client = request.extensions().get::<AuthenticatedClient>().cloned();
    let cert_identity = request.extensions().get::<CertIdentity>().cloned();
    let oauth_agent_identity = request.extensions().get::<OAuthAgentIdentity>().cloned();
    let proven = refusal_principal(
        client.as_ref(),
        oauth_agent_identity.as_ref(),
        cert_identity.as_ref(),
    );
    // End-user identity for propagation (MIK-6704): the auth middleware may
    // attach a VerifiedIdentity for temporary/delegated OIDC tokens. Extracted
    // before the body is consumed so the direct route can propagate it too.
    let verified_identity = request
        .extensions()
        .get::<crate::key_server::oidc::VerifiedIdentity>()
        .cloned();
    // Classified once for every credential this route resolves, notifications
    // included (#2190): a validated credential can be the sole operator.
    let caller = crate::identity_propagation::CallerProof::new(
        verified_identity.as_ref(),
        crate::identity_propagation::CallerProvenance::classify(
            client.as_ref().map(|client| client.principal.as_str()),
        ),
    );
    // Inbound headers, captured before the body is consumed, so the passthrough
    // path (ADR-008 rung 2, MIK-6746) can read the caller's own backend
    // credential from the operator-named header.
    let inbound_headers = request.headers().clone();

    // === C5 route parity (MIK-6746) ===
    //
    // `require_id` and the `known_agents` allowlist are enforced in
    // `meta_mcp_dispatch` for /mcp. This route reaches the same backends, so
    // the same check has to run here: without it the allowlist is bypassable
    // by choosing the /mcp/{name} URL. Checked before the body is read, which
    // is where the meta route checks it too.
    let agent_identity = crate::security::extract_agent_identity(
        &inbound_headers,
        request.uri().query(),
        cert_identity.as_ref(),
        oauth_agent_identity.as_ref().map(|a| a.client_id.as_str()),
    );
    match crate::security::validate_agent_identity(&agent_identity, &state.agent_identity_config) {
        Ok(audit) => {
            crate::security::log_agent_identity(&agent_identity, audit, None);
        }
        Err(reason) => {
            crate::security::log_agent_identity(
                &agent_identity,
                crate::security::IdentityAudit::Clean,
                Some(&reason),
            );
            return build_http_error_response(None, -32600, reason, StatusCode::FORBIDDEN);
        }
    }

    // The caller as the meta route resolves it, resolved before the body is
    // read, so a refused identity header reaches no passthrough, propagation
    // or idempotency work on this route either.
    let peer = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0);
    let grant_subject = match super::identity::caller_grant_subject(
        verified_identity.as_ref(),
        &inbound_headers,
        peer,
        state.meta_mcp.caller_identity(),
        state.meta_mcp.access_verifier(),
        cert_identity.as_ref(),
        oauth_agent_identity.as_ref(),
    )
    .await
    {
        Ok(subject) => subject,
        Err(refusal) => return super::identity::identity_refusal_response(refusal),
    };
    let key = super::identity::subject_key(grant_subject.as_ref(), cert_identity.as_ref());
    if let Some(no) = hardened_identity_refusal(&state, key.as_deref(), request.extensions().get())
    {
        return no;
    }
    // Parse JSON body
    let body_bytes = match super::helpers::read_body(request).await {
        Ok(bytes) => bytes,
        Err(refusal) => return refusal,
    };

    let mut json_request: Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(e) => {
            return build_http_error_response(
                None,
                -32700,
                format!("Invalid JSON: {e}"),
                StatusCode::BAD_REQUEST,
            );
        }
    };

    // D2-a: the slot is filled before the envelope is validated, so a
    // malformed tools/call is recorded as `invalid` too.
    *call = direct_audit::DirectCall::of(&json_request, client.as_ref(), grant_subject.as_ref());

    // After the audit hash (D2-e: params as sent), before anything else reads
    // the request: parse, telemetry and every forwarding arm see no token.
    let attestation = take_attestation_token(json_request.get_mut("params"));

    // Parse request
    let (id, method, mut params) = match parse_request(&json_request) {
        Ok(parsed) => parsed,
        Err(response) => {
            return build_http_response(&response, StatusCode::BAD_REQUEST);
        }
    };

    // D2-b: scope is checked after the parse, so its refusal names the tool,
    // and before the backend lookup, so a scoped key gets 403 for an unknown
    // backend as for a forbidden one, never a 404 existence oracle.
    if let Some(ref client) = client
        && !client.can_access_backend(&name)
    {
        return build_http_error_response(
            None,
            -32003,
            client.backend_refusal(&name),
            StatusCode::FORBIDDEN,
        );
    }

    // Hardened (GH1942.HARDEN.1 row 10), before the backend lookup: this
    // route keeps no handshake state, so it serves no legacy request other
    // than an `initialize` that declares elicitation.
    if super::hardened_elicitation::is_hardened(&state)
        && let Some(refusal) = super::hardened_elicitation::direct_refusal(
            &state,
            &inbound_headers,
            &json_request,
            &method,
            params.as_ref(),
            id.as_ref(),
        )
    {
        return refusal;
    }

    // Find backend
    let Some(backend) = state.backends.get(&name) else {
        return build_http_error_response(
            None,
            -32001,
            format!("Backend not found: {name}"),
            StatusCode::NOT_FOUND,
        );
    };

    let protocol_header = inbound_headers
        .get("mcp-protocol-version")
        .and_then(|value| value.to_str().ok());
    // A presented session counts only for its owner, by the `/mcp` owner rule.
    let owner = super::handlers::owner_of(key, &inbound_headers, client.as_ref());
    let session_id = inbound_headers
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
        .filter(|id| state.multiplexer.touch_if_owned(id, &owner));
    crate::protocol_revision_telemetry::observe_inbound_request(
        &json_request,
        params.as_ref(),
        &method,
        protocol_header,
        session_id,
        crate::protocol_revision_telemetry::Transport::Http,
    );

    debug!(backend = %name, method = %method, client = ?client.as_ref().map(|c| &c.name), "Backend request");

    // One backend's level is still shared by every user of that backend, so
    // this route applies the meta route's admin gate before anything forwards.
    // The helper owns the (case-insensitive) method match.
    if let Err(e) = require_admin_log_level(&method, client.as_ref(), proven.as_deref(), &name) {
        return build_http_error_response(id, e.code, e.message, e.status);
    }

    // Handle notifications - forward to backend but return 202 Accepted.
    // The bucket is the one a matching `request_with_headers` call for this
    // caller would use (MIK-6735 fix 2), so a notification correlating that
    // request lands on the same upstream session. Not routed through the
    // `isolation_guarded` gate below (no id, no tool policy), but refused where
    // this caller's request would be refused for its identity (#2240).
    if method.starts_with("notifications/") {
        let Ok(notification_key::Resolved { headers, binding }) = notification_key::resolve(
            &state,
            &backend,
            &name,
            &inbound_headers,
            caller,
            proven.as_deref(),
        )
        .await
        else {
            // Refused as this caller's request would be (#2240): nothing is
            // forwarded, and the client breaker is untouched, as for
            // `direct_refusal`. `{}` is what an accepted notification gets.
            return (StatusCode::FORBIDDEN, Json(json!({})));
        };
        return match backend
            .notify_with_headers(&method, params, &headers, binding.as_deref())
            .await
        {
            Ok(()) => {
                record_client_success(&state, client.as_ref());
                (StatusCode::ACCEPTED, Json(json!({})))
            }
            // No free caller slot (#2300): dropped, counted at admission, and
            // answered with no JSON-RPC body, as a notification must be.
            Err(e @ crate::Error::IdentitySlotsExhausted { .. }) => {
                warn!(backend = %name, error = %e, "Notification dropped");
                (StatusCode::TOO_MANY_REQUESTS, Json(json!({})))
            }
            Err(e) => {
                record_client_failure(&state, client.as_ref());
                error!(backend = %name, error = %e, "Backend notification failed");
                let response = JsonRpcResponse::error(None, e.to_rpc_code(), e.to_string());
                build_http_response(&response, StatusCode::INTERNAL_SERVER_ERROR)
            }
        };
    }

    // For requests, id is guaranteed to exist
    let id = id.expect("id should exist for non-notification requests");

    // F1 (#1442): task access is never forwarded. Callers sharing this
    // backend's static credential are one principal to it, so a forwarded
    // `tasks/get` or `tasks/cancel` would read or cancel another caller's
    // task. The owner-checked task arms serve `/mcp` only. Refused before
    // propagation, attestation and idempotency, so a refusal mints nothing.
    if is_task_method(&method, params.as_ref()) {
        return build_http_error_response(
            Some(id),
            crate::protocol::era::METHOD_NOT_FOUND_CODE,
            format!("{method} is not served on /mcp/{{name}}; use /mcp"),
            StatusCode::OK,
        );
    }

    // MIK-7272.SUB.4 §P3: an unusable retry field is refused with -32602, as on
    // route 1, after the notification branch (no id to answer). Ignoring it
    // would fake the replay protection a destructive call asked for.
    let retry = crate::protocol::mrtr::RetryFields::from_params(params.as_ref());
    if retry.is_malformed() {
        return build_http_error_response(
            Some(id.clone()),
            -32602,
            format!("malformed request fields: {}", retry.malformed.join(", ")),
            StatusCode::BAD_REQUEST,
        );
    }
    // Valid (checked above), and off the params before sanitization (ASI07).
    let chain_nonce = crate::protocol::mrtr::take_chain_nonce_params(params.as_mut())
        .ok()
        .flatten();
    // Hardened signs every `tools/call` here too (GH1942.HARDEN.1 row 7). Its
    // nonce comes off the params before sanitization, checked as the meta
    // route checks it.
    let signing_scope = crate::gateway::meta_mcp::signing::SigningScope::of(
        state.live_config.running().security.posture,
    );
    let signs = method == "tools/call"
        && state.meta_mcp.signing_enabled()
        && signing_scope == crate::gateway::meta_mcp::signing::SigningScope::EveryToolCall;
    let signing_nonce = if signs {
        match crate::gateway::meta_mcp::signing::take_direct_nonce(params.as_mut()) {
            Ok(nonce) => nonce,
            Err(e) => {
                let message = crate::gateway::meta_mcp::signing::wire_error_message(&e);
                return build_http_error_response(
                    Some(id.clone()),
                    e.to_rpc_code(),
                    message,
                    StatusCode::BAD_REQUEST,
                );
            }
        }
    } else {
        None
    };
    // Then this dispatch's own challenge for a chained backend (ASI07 R7).
    let mut challenge = None;
    if let (Some(sent), "tools/call") = (params.as_mut(), method.as_str()) {
        match state
            .meta_mcp
            .chain_challenge(backend.chain_policy().0, sent)
        {
            Ok(minted) => challenge = minted,
            Err(e) => return build_http_response(&refusal(Some(id.clone()), &e), StatusCode::OK),
        }
    }

    // End-user identity propagation for the direct backend route (MIK-6704 /
    // ADR-007). Parity with the meta dispatch path: for a propagation-configured
    // backend, resolve the per-user credential and forward it via
    // request_with_headers; fail closed (403) for a `required` backend with no
    // verified identity rather than silently forwarding with only the static
    // credential. Empty for a non-propagation backend → unchanged static path.
    //
    // Applies to every caller-data method, not just `tools/call`: otherwise a
    // required backend could serve them on the shared static credential and
    // leak one user's data under another's account (F2, MIK-6746, MIK-6728).
    // `resolve_propagation_headers` returns an empty set for a non-propagation or
    // non-`required` backend, so the static path below is unchanged for those
    // (IDP.5 backward-compat). Exempt: the handshake (`initialize`, `ping`) and
    // `notifications/*` (answered above). `tools/list` is guarded: a catalogue is
    // identity-dependent, so it lists from the caller's slot (MIK-7546).
    let isolation_guarded =
        !matches!(method.as_str(), "initialize" | "ping") && !method.starts_with("notifications/");

    // MIK-7570.ATTEST.1: every method that reaches the backend is attested, on
    // the same predicate as identity propagation, and BEFORE it: an unattested
    // call must not mint a per-user credential or write a mint audit row. Also
    // ahead of the idempotency guard, so a replay needs a token too.
    if isolation_guarded {
        let scope = direct_route_attestation_scope(&method, params.as_ref());
        let agent = client.as_ref().map(|c| c.name.as_str());
        if let Err(e) = state.meta_mcp.check_attestation_scoped(
            attestation.as_deref(),
            scope,
            agent,
            "direct_route",
        ) {
            let (code, message) = (e.to_rpc_code(), e.to_string());
            return build_http_error_response(Some(id), code, message, StatusCode::FORBIDDEN);
        }
    }
    // Caller's stable identity binding (MIK-6784) for per-identity upstream
    // session partitioning on this direct route. Set only when a minting
    // strategy resolves a binding; passthrough / no-identity keep `None` (shared
    // default session bucket — passthrough forwards the caller's own credential
    // inline and is gated to trusted internals).
    let mut identity_key: Option<String> = None;
    // A11-e′: the managed lease the headers were released under, for the 401 site.
    let mut managed = None;
    let mut typed = None;
    let propagated_headers: Vec<(String, String)> = if isolation_guarded {
        // Fetched once so both the passthrough-vs-minting branch below and the
        // audit write (MIK-6740) share a single lookup/clone of the backend's
        // propagation config.
        let idp_cfg = state
            .backends
            .get(&name)
            .and_then(|b| b.identity_propagation_config().cloned());
        // Passthrough (ADR-008 rung 2, MIK-6746): the caller's OWN credential is
        // forwarded verbatim, nothing minted or stored (INV-4); other strategies
        // use the shared minting chokepoint. Isolation (INV-3) holds: each
        // request forwards its own header, with no per-user cache.
        let passthrough_cfg = idp_cfg.clone().filter(|c| {
            c.strategy == crate::identity_propagation::PropagationStrategyKind::Passthrough
        });
        let resolved = if let Some(cfg) = passthrough_cfg {
            match resolve_passthrough_headers(
                &cfg,
                &inbound_headers,
                backend.transport_carries_identity_headers(),
            ) {
                Ok((headers, binding)) => {
                    // Bind the upstream session bucket to this passthrough caller
                    // (MIK-6785): keyed by the SHA-256 of the forwarded
                    // credential, so distinct callers never share a stateful
                    // upstream's session-bound data. `None` on the no-credential
                    // path keeps the shared default bucket (behavior unchanged).
                    identity_key =
                        charged_binding(&state, &name, caller, proven.as_deref(), binding);
                    Ok(headers)
                }
                Err(e) => Err(e),
            }
        } else {
            match state
                .meta_mcp
                .resolve_propagation_credential_held(&name, caller)
                .await
            {
                Ok((headers, binding, held)) => {
                    // Bind the upstream session bucket to this caller (MIK-6784).
                    identity_key = binding;
                    managed = held;
                    Ok(headers)
                }
                Err(e) => Err(refusal_text(&e)).inspect_err(|_| typed = Some(e)),
            }
        };
        // The principal resolved for (passthrough: the verified identity).
        let subject = state.meta_mcp.audit_subject_for(&name, caller);
        let audience = idp_cfg.as_ref().map(|c| c.audience.as_str());
        match resolved {
            Ok(headers) => {
                // A successful resolution that yields no headers is the
                // unchanged static-credential fallback (IDP.5), not a mint —
                // only audit when a per-user credential was actually attached.
                if !headers.is_empty() {
                    // Fail-closed hardening: a minted credential must never
                    // reach the caller without a durable audit record, so an
                    // audit-write failure here aborts the mint instead of
                    // proceeding with the headers below (mirrors
                    // `identity_propagation::mod.rs`'s `resolve_caller_credential`).
                    //
                    // Operator-misconfig fail-OPEN guard: the audit helper
                    // treats a missing logger (`None`) as a no-op `Ok(())`. On a
                    // `required` backend that would ship a per-user credential
                    // with NO audit record. When propagation is REQUIRED for
                    // this backend but no transparency log is configured, fail
                    // closed on the same error path as an audit-write failure.
                    // (Non-required backends keep the best-effort `None -> Ok`.)
                    let required = idp_cfg.as_ref().is_some_and(|c| c.required);
                    if required && state.transparency_log.is_none() {
                        warn!(
                            backend = %name,
                            "identity-propagation required but no transparency log is \
                             configured; refusing to mint without a durable audit record"
                        );
                        return build_http_error_response(
                            Some(id.clone()),
                            -32603,
                            // CWE-209: generic client-facing message; the
                            // operational detail stays in the server log above.
                            "identity-propagation audit unavailable".to_string(),
                            StatusCode::INTERNAL_SERVER_ERROR,
                        );
                    }
                    if let Err(audit_err) = audit_identity_propagation(
                        state.transparency_log.as_ref(),
                        "idp_mint",
                        &subject,
                        &name,
                        audience,
                        None,
                    )
                    .await
                    {
                        // CWE-209: the audit error can name a filesystem path; it
                        // stays in the server log, the client gets a generic message.
                        warn!(
                            backend = %name,
                            error = %audit_err,
                            "identity-propagation mint audit write failed; failing closed"
                        );
                        return build_http_error_response(
                            Some(id.clone()),
                            -32603,
                            "identity-propagation audit unavailable".to_string(),
                            StatusCode::INTERNAL_SERVER_ERROR,
                        );
                    }
                }
                headers
            }
            Err(e) => {
                // Refused either way: unlike the mint path above, a failed audit
                // write here is logged rather than failing the call closed.
                if let Err(audit_err) = audit_identity_propagation(
                    state.transparency_log.as_ref(),
                    "idp_refuse",
                    &subject,
                    &name,
                    audience,
                    Some(&e),
                )
                .await
                {
                    warn!(
                        backend = %name,
                        error = %audit_err,
                        "identity-propagation refuse audit write failed"
                    );
                }
                let (rid, who) = (Some(id.clone()), verified_identity.as_ref());
                return state.meta_mcp.direct_refusal(rid, e, typed, who).await;
            }
        }
    } else {
        Vec::new()
    };

    // ADR-008 INV-2: the direct backend route bypasses `invoke_tool_traced`, so
    // it must enforce the same fail-closed OAuth-isolation guard. This covers
    // every caller-data method that forwards with the gateway-held token —
    // `tools/call`, `resources/read`, `prompts/get`, etc. — not just
    // `tools/call`. A per-user credential was resolved above iff
    // `propagated_headers` is non-empty, so a per-user OAuth backend on a
    // multi-user gateway is refused rather than served the shared token.
    if isolation_guarded
        && let Err(e) = state
            .meta_mcp
            .enforce_oauth_isolation(&name, !propagated_headers.is_empty())
    {
        return build_http_error_response(
            Some(id.clone()),
            e.to_rpc_code(),
            e.to_string(),
            StatusCode::FORBIDDEN,
        );
    }

    // MIK-7272.SUB.4: the bypass re-enforces the idempotency guard locally, the
    // same shape as the isolation guard above. A broken stream forces re-issue
    // with a NEW request id, so without this the duplicate side effect lands
    // twice on the one route that never reaches `invoke_tool_traced`.
    // One answer for a dispatched failure, used by whichever arm dispatches.
    let failed = DirectFailure {
        state: &state,
        name: &name,
        id: id.clone(),
        client: client.as_ref(),
        identity: verified_identity.as_ref(),
        managed: managed.as_ref(),
    };
    // MIK-7597: the shared dispatch controls, S1 and G7 before the reservation.
    let call = BackendCall {
        server: &name,
        tool: params
            .as_ref()
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str)
            .unwrap_or_default(),
        session_id,
        api_key_name: client.as_ref().map(|c| c.name.as_str()),
        trace_id: "",
    };
    if method == "tools/call"
        && let Err(e) = DirectRouteGuards::run(&state.meta_mcp, &call, signing_scope)
    {
        return build_http_response(&refusal(Some(id.clone()), &e), StatusCode::OK);
    }
    // SECURITY: apply tool policy, name validation, and input sanitization to
    // tools/call requests unless the backend explicitly opts into pass-through
    // mode (passthrough: true in config — only for fully-trusted internals).
    // #2445: before the idempotency cache below, so a call the gate now
    // refuses is refused on the re-issue too, never answered from the cache.
    let sanitized = if method == "tools/call" {
        match apply_backend_tool_call_security(
            &state,
            &name,
            BackendAuthContext {
                client: client.as_ref(),
                oauth_agent_identity: oauth_agent_identity.as_ref(),
                cert_identity: cert_identity.as_ref(),
                #[cfg(feature = "firewall")]
                grant_subject: grant_subject.as_ref(),
            },
            params.as_ref(),
            &id,
            &backend,
            ((identity_key.as_deref(), &propagated_headers), &failed),
        )
        .await
        {
            Err(rejection) => return rejection,
            Ok(sanitized) => sanitized, // `None`: pass-through, forwarded as sent
        }
    } else {
        None
    };
    // Admitted once, here: after every refusal above, so a refused call
    // consumes no nonce, and before the cache below, so a replayed result is
    // signed against the replaying request's own nonce. The store is the one
    // the meta route admits into.
    if signs {
        // The meta route's own derivation (an authenticated key, then an OAuth
        // agent, then a certificate), so one caller has one bucket on both.
        let authorizer = super::authorization::RouterAuthorizer {
            state: state.as_ref(),
            client: client.as_ref(),
            oauth_agent_identity: oauth_agent_identity.as_ref(),
            cert_identity: cert_identity.as_ref(),
            principal: None,
        };
        let principal = crate::gateway::authz::ToolAuthorizer::quota_principal(&authorizer).map_or(
            "anonymous",
            crate::gateway::auth::QuotaPrincipal::as_store_key,
        );
        if let Err(e) = state
            .meta_mcp
            .admit_signing_nonce(signing_nonce.as_deref(), principal)
        {
            let message = crate::gateway::meta_mcp::signing::wire_error_message(&e);
            return build_http_error_response(
                Some(id.clone()),
                e.to_rpc_code(),
                message,
                StatusCode::BAD_REQUEST,
            );
        }
    }
    let mut idem_reservation: Option<crate::idempotency::IdempotencyReservation> = None;
    if method == "tools/call" {
        match state.meta_mcp.direct_route_idempotency(
            retry.idempotency_key.as_deref(),
            &name,
            identity_key.as_deref(),
            verified_identity.as_ref(),
            grant_subject.as_ref(),
            client.as_ref().map(|client| client.principal.as_str()),
            crate::gateway::meta_mcp::Authentication::of(client.as_ref()),
            params.as_ref(),
        ) {
            Ok(Some(crate::idempotency::GuardOutcome::CachedResult(cached))) => {
                crate::gateway::meta_mcp::invoke::audit::note_cached();
                let mut response = JsonRpcResponse::success(id.clone(), cached);
                if signs {
                    let nonce = signing_nonce.as_deref();
                    state.meta_mcp.sign_direct_delivery(&mut response, nonce);
                }
                return build_http_response(&response, StatusCode::OK);
            }
            Ok(Some(crate::idempotency::GuardOutcome::CachedError(error))) => {
                crate::gateway::meta_mcp::invoke::audit::note_cached();
                let response = cached_error_response(Some(id.clone()), &error);
                return build_http_response(&response, StatusCode::OK);
            }
            Ok(Some(crate::idempotency::GuardOutcome::Proceed(reservation))) => {
                idem_reservation = Some(reservation);
            }
            Ok(None) => {}
            Err(e) => {
                let code = e.to_rpc_code();
                let status = u16::try_from(code)
                    .ok()
                    .and_then(|c| StatusCode::from_u16(c).ok())
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                return build_http_error_response(Some(id.clone()), code, e.to_string(), status);
            }
        }
    }

    if let Some(sanitized_params) = sanitized {
        let warnings = match DirectRouteGuards::before_dispatch(&state.meta_mcp, &call) {
            Ok(warnings) => warnings,
            Err(e) => {
                return build_http_response(&refusal(Some(id.clone()), &e), StatusCode::OK);
            }
        };
        // Forward the sanitized params to the backend
        let forward = Box::pin(dispatch_armed(
            idem_reservation.as_mut(),
            dispatch_in_scope(
                &backend,
                &method,
                &id,
                Some(sanitized_params),
                &propagated_headers,
                identity_key.as_deref(),
            ),
        ))
        .await;
        let (params, client) = (params.as_ref(), client.as_ref());
        let seen = (&call, challenge.as_deref());
        let forward =
            DirectRouteGuards::after_dispatch(&state, seen, params, client, &warnings, forward);
        return match forward {
            Ok(mut response) => {
                // Restore the caller's ID over the transport's own.
                response.id = Some(id.clone());
                stamp_direct_provenance(&state, &name, params, client, &mut response);
                settle_direct_idempotency(idem_reservation.as_mut(), &response);
                let nonce = chain_nonce.as_deref();
                state.meta_mcp.finish_direct(&mut response, &method, nonce);
                if signs {
                    let nonce = signing_nonce.as_deref();
                    state.meta_mcp.sign_direct_delivery(&mut response, nonce);
                }
                build_http_response(&response, StatusCode::OK)
            }
            // Settled as terminal unless raised before dispatch
            // (ADR-012 consequence 1; see `settle_direct_failure`).
            Err(e) => failed.answer(idem_reservation.as_mut(), e).await,
        };
    }

    // Forward to backend. `tools/list` drains the whole upstream catalogue
    // so it can be filtered per caller and answered without a cursor (A3).
    let forward = if method == "tools/list" {
        let (headers, key) = (&propagated_headers, identity_key.as_deref());
        direct_list::drain(&backend, &id, params.as_ref(), headers, key, &name)
            .await
            .inspect(|_| record_client_success(&state, client.as_ref()))
    } else {
        let warnings = if method == "tools/call" {
            match DirectRouteGuards::before_dispatch(&state.meta_mcp, &call) {
                Ok(warnings) => warnings,
                Err(e) => {
                    return build_http_response(&refusal(Some(id.clone()), &e), StatusCode::OK);
                }
            }
        } else {
            Vec::new()
        };
        let key = identity_key.as_deref();
        let dispatch = dispatch_in_scope(
            &backend,
            &method,
            &id,
            params.clone(),
            &propagated_headers,
            key,
        );
        let forward = Box::pin(dispatch_armed(idem_reservation.as_mut(), dispatch)).await;
        if method == "tools/call" {
            let (params, client) = (params.as_ref(), client.as_ref());
            let seen = (&call, challenge.as_deref());
            DirectRouteGuards::after_dispatch(&state, seen, params, client, &warnings, forward)
        } else {
            forward.inspect(|_| record_client_success(&state, client.as_ref()))
        }
    };
    match forward {
        Ok(mut response) => {
            // Upstream transport IDs are private gateway correlation state;
            // direct-route clients must receive the ID they supplied.
            response.id = Some(id.clone());
            if method == "tools/list" {
                // Redaction FIRST, then the trust stamp. The firewall may remove
                // a `$defs` entry a surviving `$ref` points at, so a verdict
                // computed before it can say `within` about a document the
                // client never receives.
                scan_direct_tools_list_response(&state, &name, client.as_ref(), &mut response);
                normalize_tools_list_response(&backend, &mut response);
                // List = invoke: only what this route's `tools/call` admits.
                let (oauth, cert) = (oauth_agent_identity.as_ref(), cert_identity.as_ref());
                let client = client.as_ref();
                direct_list::retain_invocable(&state, client, oauth, cert, &name, &mut response);
            } else if method == "tools/call" {
                stamp_direct_provenance(
                    &state,
                    &name,
                    params.as_ref(),
                    client.as_ref(),
                    &mut response,
                );
            }
            settle_direct_idempotency(idem_reservation.as_mut(), &response);
            let nonce = chain_nonce.as_deref();
            state.meta_mcp.finish_direct(&mut response, &method, nonce);
            if signs {
                let nonce = signing_nonce.as_deref();
                state.meta_mcp.sign_direct_delivery(&mut response, nonce);
            }
            build_http_response(&response, StatusCode::OK)
        }
        // Settled, never dropped: an unsettled reservation releases the key and
        // lets a retry re-execute a side effect (ADR-012 consequence 1).
        Err(e) => failed.answer(idem_reservation.as_mut(), e).await,
    }
}

/// #1962: run a backend dispatch with the reservation armed, so a caller
/// that disconnects mid-call leaves the key settled, not free.
async fn dispatch_armed<T>(
    reservation: Option<&mut crate::idempotency::IdempotencyReservation>,
    dispatch: impl std::future::Future<Output = T>,
) -> T {
    crate::gateway::meta_mcp::MetaMcp::arm_direct_dispatch(reservation);
    dispatch.await
}

/// Store the direct route's result under the client's idempotency key so a
/// re-issue replays it instead of invoking the backend again. Runs after the
/// scan and provenance stamp, before any chain link. Both terminal outcomes
/// settle: a dispatched JSON-RPC error may follow a committed side effect, so
/// the retry is served the same error (ADR-012 consequence 1).
fn settle_direct_idempotency(
    reservation: Option<&mut crate::idempotency::IdempotencyReservation>,
    response: &JsonRpcResponse,
) {
    let Some(reservation) = reservation else {
        return;
    };
    if response.delivery_refusal {
        reservation
            .fail(&crate::gateway::meta_mcp::invoke::dispatch_guards::firewall_refusal_body());
        return;
    }
    if let Some(error) = response.error.as_ref() {
        if let Ok(error) = serde_json::to_value(error) {
            reservation.fail(&error);
        }
        return;
    }
    if let Some(result) = response.result.as_ref() {
        reservation.complete(result);
    }
}

/// Settle a failed direct-route call, releasing the key when the gateway can
/// prove the request never reached the backend.
///
/// ADR-012 consequence 1 caches a dispatched failure so a retry cannot duplicate
/// a side effect that may already have committed. A refusal the gateway raised
/// itself — an open circuit, an unknown backend or tool — carries no such
/// ambiguity: nothing ran, so caching it for the entry's whole lifetime would
/// deny the caller a retry of work that provably never happened. See
/// [`crate::Error::is_pre_dispatch`] for why that allowlist stays tight.
fn settle_direct_failure(
    reservation: Option<&mut crate::idempotency::IdempotencyReservation>,
    error: &crate::Error,
    response: &JsonRpcResponse,
) {
    if error.is_pre_dispatch() {
        if let Some(reservation) = reservation {
            reservation.release();
        }
        return;
    }
    settle_direct_idempotency(reservation, response);
}

/// Rebuild the JSON-RPC error response stored under an idempotency key.
///
/// `data` is lifted back out of the stored error object because a backend puts
/// the machine-readable half of its refusal there — a retry-after hint, a
/// validation path. [`crate::idempotency::cached_error_parts`] returns only the
/// code and message, so a replay that used it alone answered the retry with a
/// strictly poorer error than the first caller received, which defeats the
/// point of replaying it at all.
fn cached_error_response(id: Option<RequestId>, error: &Value) -> JsonRpcResponse {
    if crate::gateway::meta_mcp::invoke::dispatch_guards::is_firewall_refusal(error) {
        return refusal(id, &crate::Error::ResponseFirewallRefused);
    }
    let (code, message) = crate::idempotency::cached_error_parts(error);
    match error.get("data") {
        Some(data) => JsonRpcResponse::error_with_data(id, code, message, data.clone()),
        None => JsonRpcResponse::error(id, code, message),
    }
}

fn record_client_success(state: &AppState, client: Option<&AuthenticatedClient>) {
    if let Some(client) = client {
        state.auth_config.record_client_success(&client.name);
    }
}

/// Stamp a signed runtime-provenance receipt onto a direct-route `tools/call`
/// result (MIK-6905 rung 3). The `/mcp/{name}` passthrough bypasses the meta
/// chokepoint, so without this a client could route around provenance simply
/// by choosing the direct URL. No-op unless the tool name is present (a
/// `tools/call`) and stamping is enabled on the shared `MetaMcp`.
fn stamp_direct_provenance(
    state: &AppState,
    backend_name: &str,
    params: Option<&Value>,
    client: Option<&AuthenticatedClient>,
    response: &mut JsonRpcResponse,
) {
    let tool = params
        .and_then(|p| p.get("name"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if tool.is_empty() {
        return;
    }
    let Some(result) = response.result.take() else {
        return;
    };
    let api_key_name = client.map(|c| c.name.as_str());
    response.result = Some(state.meta_mcp.stamp_direct_result(
        result,
        backend_name,
        tool,
        api_key_name,
    ));
}

fn record_client_failure(state: &AppState, client: Option<&AuthenticatedClient>) {
    if let Some(client) = client {
        state.auth_config.record_client_failure(&client.name);
    }
}

/// Scan a `tools/list` response through the same firewall response scanner used
/// for `tools/call` (OWASP ASI01 tool-poisoning defense).
///
/// Backend-supplied tool `description`/metadata strings are scanned for prompt
/// injection and have embedded credentials redacted in place before the tool
/// list reaches the client; a blocking verdict refuses the list. Gated on the
/// same firewall config as the `tools/call` path, so behavior is unchanged
/// when the feature/config is off.
#[cfg(feature = "firewall")]
fn scan_direct_tools_list_response(
    state: &AppState,
    backend_name: &str,
    client: Option<&AuthenticatedClient>,
    response: &mut JsonRpcResponse,
) {
    use crate::security::response_policy::{ResponseCorrelation, ResponsePolicyTarget};

    // The router's one pass, shared with `tools/call`: a Block (or no
    // admitting target) replaces the list with the refusal, never a redacted
    // success (#2349). No later pass inspects a direct response.
    let caller = client.map_or("anonymous", |c| c.name.as_str());
    let session_id = format!("direct:{backend_name}");
    let targets = [ResponsePolicyTarget {
        server: backend_name.to_owned(),
        tool: "tools/list".to_owned(),
    }];
    let correlation = ResponseCorrelation {
        session_id: &session_id,
        caller,
        external_server: backend_name,
        external_tool: "tools/list",
    };
    let _ = super::response_pass::inspect_tools_call_response(
        state.firewall.as_deref(),
        response,
        &targets,
        &correlation,
    );
}

#[cfg(not(feature = "firewall"))]
fn scan_direct_tools_list_response(
    _state: &AppState,
    _backend_name: &str,
    _client: Option<&AuthenticatedClient>,
    _response: &mut JsonRpcResponse,
) {
}

mod costs;
mod direct_audit;
mod direct_failure;
mod direct_list;
mod key_check;
mod notification_key;
pub(super) use costs::costs_handler;
use direct_failure::DirectFailure;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod passthrough_slot_cap_tests;

#[cfg(test)]
mod idempotency_settlement_tests;

#[cfg(test)]
mod direct_route_scope_tests;
