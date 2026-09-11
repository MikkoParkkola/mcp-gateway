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
use super::authorization::{ToolTarget, authorize_tool_target};
use super::helpers::{build_http_error_response, build_http_response, parse_request};
use crate::backend::prepare_tool_metadata;
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::oauth::AgentIdentity as OAuthAgentIdentity;
use crate::mtls::CertIdentity;
use crate::protocol::{JsonRpcResponse, RequestId, Tool};
#[cfg(feature = "firewall")]
use crate::security::firewall::FirewallAction;
use crate::security::{sanitize_json_value, validate_tool_name};
use crate::trust::project_tool_descriptors_trust_cards;

type BackendRejection = (StatusCode, Json<Value>);
type BackendSecurityResult = Option<Result<Option<Value>, BackendRejection>>;

/// Forwarded passthrough headers paired with the caller's stable upstream-session
/// bucket key (MIK-6785): `Some(sha256_hex(credential))` when a credential is
/// forwarded, `None` on the no-credential path. See [`resolve_passthrough_headers`].
type PassthroughResolution = (Vec<(String, String)>, Option<String>);

#[derive(Clone, Copy)]
struct BackendAuthContext<'a> {
    client: Option<&'a AuthenticatedClient>,
    oauth_agent_identity: Option<&'a OAuthAgentIdentity>,
    cert_identity: Option<&'a CertIdentity>,
}

/// Apply tool policy, name validation, and input sanitization to a `tools/call`
/// request arriving at the direct backend endpoint.
///
/// Returns `None` when there are no params or no tool name (nothing to check),
/// `Some(Ok(sanitized))` when all checks pass, or `Some(Err(response))` when
/// a check fails and the caller should return an HTTP error immediately.
///
/// Order of checks matches `meta_mcp_handler`:
/// 1. `validate_tool_name` — rejects dangerous names before any policy lookup.
/// 2. `tool_policy.check` — enforces global allow/deny rules.
/// 3. `sanitize_json_value` — strips/rejects dangerous byte sequences.
#[allow(clippy::result_large_err)]
fn apply_backend_tool_call_security(
    state: &AppState,
    backend_name: &str,
    auth: BackendAuthContext<'_>,
    params: Option<&Value>,
    id: &RequestId,
    sanitize: bool,
) -> BackendSecurityResult {
    let params = params?;
    let tool_name = params.get("name").and_then(Value::as_str).unwrap_or("");
    if tool_name.is_empty() {
        return None;
    }

    if let Err(e) = validate_tool_name(tool_name) {
        warn!(backend = %backend_name, tool = %tool_name, "Tool name rejected by validation");
        return Some(Err(backend_security_error(id, &e)));
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
        return Some(Err(backend_security_error_with_status(
            id, e.code, &e.message, e.status,
        )));
    }

    #[cfg(feature = "firewall")]
    if let Some(ref fw) = state.firewall {
        let caller_name = auth.client.map_or("anonymous", |c| c.name.as_str());
        let session_id = format!("direct:{backend_name}");
        let verdict =
            // A direct backend call always has this synthetic per-backend key,
            // so the per-caller controls have a stable identity to score on.
            fw.check_request(
                &session_id,
                backend_name,
                tool_name,
                arguments,
                caller_name,
                &session_id,
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
            return Some(Err(backend_security_error(
                id,
                &format!("Firewall blocked: {desc}"),
            )));
        }
    }

    if !sanitize {
        return Some(Ok(None));
    }

    match sanitize_json_value(params) {
        Ok(sanitized) => Some(Ok(Some(sanitized))),
        Err(e) => {
            warn!(backend = %backend_name, tool = %tool_name, "Input sanitization failed");
            Some(Err(backend_security_error(id, &e.to_string())))
        }
    }
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
fn normalize_tools_list_response(backend_name: &str, response: &mut JsonRpcResponse) {
    if response.error.is_some() {
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

    // Parsed element by element on purpose. A single descriptor the `Tool`
    // shape cannot accept used to abort the whole pass and forward the list
    // verbatim — which handed a backend a one-element bypass for the exclusion
    // applied to all of its siblings. An unparseable element is now carried
    // through untouched (dropping it would hide a tool the client may already
    // depend on) while every element we can read is still filtered.
    let mut tools = Vec::with_capacity(items.len());
    let mut unparsed = Vec::new();
    for item in items {
        match serde_json::from_value::<Tool>(item.clone()) {
            Ok(tool) => tools.push(tool),
            Err(e) => {
                warn!(backend = %backend_name, error = %e, "Backend tools/list entry could not be normalized");
                unparsed.push(item.clone());
            }
        }
    }

    prepare_tool_metadata(backend_name, &mut tools);

    let server_id = format!("backend:{backend_name}");
    let tools = project_tool_descriptors_trust_cards(&server_id, backend_name, &tools);

    match serde_json::to_value(tools) {
        Ok(Value::Array(mut normalized)) => {
            normalized.extend(unparsed);
            *tools_value = Value::Array(normalized);
        }
        Ok(normalized_tools) => *tools_value = normalized_tools,
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

/// Stable actor id for an identity-propagation audit entry (MIK-6740). Uses
/// the same `issuer`+`subject` derivation as the control-plane governance
/// audit (`stable_actor_id`) so the two audit trails describe the same actor
/// under the same id. `"unauthenticated"` covers the non-`required` path,
/// where a mint/refuse decision can be reached with no verified identity.
fn audit_subject(verified_identity: Option<&crate::key_server::oidc::VerifiedIdentity>) -> String {
    verified_identity.map_or_else(
        || "unauthenticated".to_string(),
        crate::key_server::oidc::VerifiedIdentity::stable_actor_id,
    )
}

/// Record an identity-propagation credential decision (`idp_mint` /
/// `idp_refuse`) into the tamper-evident transparency log (MIK-6740, IDP4).
///
/// Takes the logger directly (rather than `&AppState`) so this function is
/// independently unit-testable against a real [`crate::security::TransparencyLogger`]
/// over a tempfile, with no need to construct a full `AppState`. `logger` is
/// `None` when the transparency log is disabled — the call is then a no-op.
///
/// Redaction is the load-bearing property here: only `subject`, `backend`,
/// `audience`, `action`, `reason`, and `timestamp` are ever passed to
/// [`crate::security::TransparencyLogger::append_event`] — never the resolved
/// credential header value or a raw assertion.
///
/// ponytail: duplicate of `identity_propagation::audit_identity_propagation`;
/// kept in place to avoid a large-deletion refactor — dedup is follow-up debt.
///
/// Fail-closed hardening (mirrors `identity_propagation::audit_identity_propagation`,
/// MIK-6740 hardening carried forward to this hand-duplicated copy): a
/// transparency-log write failure is no longer swallowed. It is `warn!`'d AND
/// returned as `Err(PropagationError::AuditFailed)`.
///
/// - **`idp_mint` callers MUST fail-closed**: propagate the `Err` and abort
///   the mint/request. No mint without a durable audit record.
/// - **`idp_refuse` callers**: the request is already being refused on other
///   grounds, so the `Err` does not need to change the outcome, but MUST NOT
///   be silently dropped (log via `tracing::warn!`).
///
/// `logger = None` (transparency log disabled) is `Ok(())` — a no-op, not a
/// failure.
///
/// # Errors
/// [`crate::identity_propagation::PropagationError::AuditFailed`] when
/// [`crate::security::TransparencyLogger::append_event`] fails (e.g. disk
/// full, permission revoked, filesystem gone read-only underneath the
/// gateway).
fn audit_identity_propagation(
    logger: Option<&crate::security::TransparencyLogger>,
    action: &'static str,
    subject: &str,
    backend: &str,
    audience: Option<&str>,
    reason: Option<&str>,
) -> Result<(), crate::identity_propagation::PropagationError> {
    let Some(logger) = logger else {
        return Ok(());
    };

    let mut fields = serde_json::Map::new();
    fields.insert("action".into(), action.into());
    fields.insert("subject".into(), subject.into());
    fields.insert("backend".into(), backend.into());
    fields.insert("timestamp".into(), chrono::Utc::now().to_rfc3339().into());
    if let Some(audience) = audience {
        fields.insert("audience".into(), audience.into());
    }
    if let Some(reason) = reason {
        fields.insert("reason".into(), reason.into());
    }

    logger.append_event(fields).map(|_| ()).map_err(|e| {
        warn!(
            backend,
            action, error = %e,
            "Failed to write identity-propagation audit entry (transparency log); \
             fail-closed on idp_mint"
        );
        crate::identity_propagation::PropagationError::AuditFailed(format!(
            "transparency-log write failed for action '{action}' on backend '{backend}': {e}"
        ))
    })
}

/// Resolve just the identity-key session-bucket binding for a notification
/// (MIK-6735 fix 2), WITHOUT the full propagation/OAuth-isolation enforcement
/// gate `isolation_guarded` applies to id-bearing requests below.
///
/// `isolation_guarded` deliberately excludes `notifications/*` from that gate
/// (the `idp_refuse` 403 path, `enforce_oauth_isolation`, and tool-policy) —
/// notifications are fire-and-forget MCP protocol plumbing (e.g.
/// `notifications/cancelled`), never a caller-data operation, so a
/// propagation failure must never turn a notification into a hard error.
/// Before this fix, `backend.notify()` also hardcoded the shared session
/// bucket unconditionally, so even a successfully resolved per-user identity
/// went unused and a notification correlating a per-user request could land
/// on the wrong upstream session.
///
/// This is deliberately best-effort and side-effect free (no audit log entry,
/// no error surfaced to the caller): any resolution failure — including no
/// identity-propagation config on the backend at all, the overwhelmingly
/// common case — falls back to `None`, the shared default bucket, exactly
/// what every notification used unconditionally before this fix (IDP.5).
async fn resolve_notification_identity_key(
    state: &AppState,
    backend: &crate::backend::Backend,
    name: &str,
    inbound_headers: &axum::http::HeaderMap,
    verified_identity: Option<&crate::key_server::oidc::VerifiedIdentity>,
) -> Option<String> {
    let idp_cfg = backend.identity_propagation_config()?;
    if idp_cfg.strategy == crate::identity_propagation::PropagationStrategyKind::Passthrough {
        let (_headers, binding) = resolve_passthrough_headers(
            idp_cfg,
            inbound_headers,
            backend.transport_carries_identity_headers(),
        )
        .ok()?;
        return binding;
    }
    let (_headers, binding) = state
        .meta_mcp
        .resolve_propagation_credential(name, verified_identity)
        .await
        .ok()?;
    binding
}

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
    params: Option<Value>,
    propagated_headers: &[(String, String)],
    identity_key: Option<&str>,
) -> crate::Result<JsonRpcResponse> {
    // Unlike the three meta-dispatch call sites (each gating one hardcoded
    // method), `method` here is client-chosen: this is the one place every
    // direct-route request funnels through, so it is the one place that must
    // refuse whatever the peer's era removed before it reaches the wire
    // (MIK-7217, OUTBOUND.1). The id is restored by both callers after this
    // returns, so `None` here is never seen by the client.
    if crate::gateway::meta_mcp::era_removed_method(backend, method).await {
        return Ok(JsonRpcResponse::error(
            None,
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

/// Backend handler (POST /mcp/{name})
#[allow(clippy::too_many_lines)]
pub(super) async fn backend_handler(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    request: axum::http::Request<axum::body::Body>,
) -> impl IntoResponse {
    // Track in-flight request for graceful drain
    let _inflight_permit = state.inflight.acquire().await;

    // Extract authenticated client from extensions (injected by auth middleware)
    let client = request.extensions().get::<AuthenticatedClient>().cloned();
    let cert_identity = request.extensions().get::<CertIdentity>().cloned();
    let oauth_agent_identity = request.extensions().get::<OAuthAgentIdentity>().cloned();
    // End-user identity for propagation (MIK-6704): the auth middleware may
    // attach a VerifiedIdentity for temporary/delegated OIDC tokens. Extracted
    // before the body is consumed so the direct route can propagate it too.
    let verified_identity = request
        .extensions()
        .get::<crate::key_server::oidc::VerifiedIdentity>()
        .cloned();
    // Inbound headers, captured before the body is consumed, so the passthrough
    // path (ADR-008 rung 2, MIK-6746) can read the caller's own backend
    // credential from the operator-named header.
    let inbound_headers = request.headers().clone();

    // Check backend access if auth is enabled
    if let Some(ref client) = client
        && !client.can_access_backend(&name)
    {
        return build_http_error_response(
            None,
            -32003,
            format!(
                "Client '{}' not authorized for backend '{}'",
                client.name, name
            ),
            StatusCode::FORBIDDEN,
        );
    }

    // Parse JSON body
    let body_bytes = match axum::body::to_bytes(request.into_body(), 10 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(e) => {
            return build_http_error_response(
                None,
                -32700,
                format!("Failed to read body: {e}"),
                StatusCode::BAD_REQUEST,
            );
        }
    };

    let json_request: Value = match serde_json::from_slice(&body_bytes) {
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

    // Find backend
    let Some(backend) = state.backends.get(&name) else {
        return build_http_error_response(
            None,
            -32001,
            format!("Backend not found: {name}"),
            StatusCode::NOT_FOUND,
        );
    };

    // Parse request
    let (id, method, params) = match parse_request(&json_request) {
        Ok(parsed) => parsed,
        Err(response) => {
            return build_http_response(&response, StatusCode::BAD_REQUEST);
        }
    };

    let protocol_header = inbound_headers
        .get("mcp-protocol-version")
        .and_then(|value| value.to_str().ok());
    let session_id = inbound_headers
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok());
    crate::protocol_revision_telemetry::observe_inbound_request(
        &json_request,
        params.as_ref(),
        &method,
        protocol_header,
        session_id,
        crate::protocol_revision_telemetry::Transport::Http,
    );

    debug!(backend = %name, method = %method, client = ?client.as_ref().map(|c| &c.name), "Backend request");

    // Handle notifications - forward to backend but return 202 Accepted.
    // Resolve (best-effort) the same session-bucket identity_key a matching
    // `request_with_headers` call for this caller would have used (MIK-6735
    // fix 2), so a notification correlating that request lands on the same
    // upstream session instead of always the shared default bucket. Deliberately
    // NOT routed through the `isolation_guarded` enforcement gate below —
    // notifications stay exempt from the idp_refuse-403 / OAuth-isolation /
    // tool-policy checks that apply to id-bearing requests.
    if method.starts_with("notifications/") {
        let notif_identity_key = resolve_notification_identity_key(
            &state,
            &backend,
            &name,
            &inbound_headers,
            verified_identity.as_ref(),
        )
        .await;
        return match backend
            .notify_with_headers(&method, params, notif_identity_key.as_deref())
            .await
        {
            Ok(()) => {
                record_client_success(&state, client.as_ref());
                (StatusCode::ACCEPTED, Json(json!({})))
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

    // MIK-7272.SUB.4 §P3: an unusable retry field is refused with -32602 here,
    // the same answer route 1 gives at `router/handlers.rs:1223`. Refused after
    // the notification branch above, which has no id to answer with. Silently
    // ignoring it would leave the caller believing it has replay protection it
    // does not have — a fail-open on the exact guarantee, and for a destructive
    // tool that fail-open IS the duplicate side effect it asked to be spared.
    let retry = crate::protocol::mrtr::RetryFields::from_params(params.as_ref());
    if retry.is_malformed() {
        return build_http_error_response(
            Some(id.clone()),
            -32602,
            format!("malformed request fields: {}", retry.malformed.join(", ")),
            StatusCode::BAD_REQUEST,
        );
    }

    // End-user identity propagation for the direct backend route (MIK-6704 /
    // ADR-007). Parity with the meta dispatch path: for a propagation-configured
    // backend, resolve the per-user credential and forward it via
    // request_with_headers; fail closed (403) for a `required` backend with no
    // verified identity rather than silently forwarding with only the static
    // credential. Empty for a non-propagation backend → unchanged static path.
    //
    // Applies to every caller-data method (`tools/call`, `resources/read`,
    // `prompts/get`, `resources/list`, `prompts/list`, …), not just `tools/call`
    // — otherwise a required backend could serve those methods without the caller
    // credential, downgrading to the shared static credential and leaking one
    // user's backend data/metadata under another's account (GPT review F2,
    // MIK-6746; merged with ADR-007 IDP.2/IDP.3 fail-closed gate, MIK-6728).
    // `resolve_propagation_headers` returns an empty set for a non-propagation or
    // non-`required` backend, so the static path below is unchanged for those
    // (IDP.5 backward-compat). Pure discovery/plumbing (`initialize`, `tools/list`,
    // `ping`) carries no per-user data and is exempt so the MCP handshake and tool
    // schema stay reachable; every other id-bearing request is guarded.
    let isolation_guarded = !matches!(method.as_str(), "initialize" | "tools/list" | "ping")
        && !method.starts_with("notifications/");
    // Caller's stable identity binding (MIK-6784) for per-identity upstream
    // session partitioning on this direct route. Set only when a minting
    // strategy resolves a binding; passthrough / no-identity keep `None` (shared
    // default session bucket — passthrough forwards the caller's own credential
    // inline and is gated to trusted internals).
    let mut identity_key: Option<String> = None;
    let propagated_headers: Vec<(String, String)> = if isolation_guarded {
        // Fetched once so both the passthrough-vs-minting branch below and the
        // audit write (MIK-6740) share a single lookup/clone of the backend's
        // propagation config.
        let idp_cfg = state
            .backends
            .get(&name)
            .and_then(|b| b.identity_propagation_config().cloned());
        // Passthrough (ADR-008 rung 2, MIK-6746): a backend whose caller attaches
        // its OWN credential is handled here — forward it verbatim, mint/store
        // NOTHING (INV-4). Any other propagation strategy is resolved by the
        // shared minting chokepoint. Isolation (INV-3) holds by construction:
        // each request forwards its own header via `request_with_headers`, never
        // via the shared transport, and the direct route keeps no per-user cache.
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
                    identity_key = binding;
                    Ok(headers)
                }
                Err(e) => Err(e),
            }
        } else {
            match state
                .meta_mcp
                .resolve_propagation_credential(&name, verified_identity.as_ref())
                .await
            {
                Ok((headers, binding)) => {
                    // Bind the upstream session bucket to this caller (MIK-6784).
                    identity_key = binding;
                    Ok(headers)
                }
                Err(e) => Err(e.to_string()),
            }
        };
        let subject = audit_subject(verified_identity.as_ref());
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
                        state.transparency_log.as_deref(),
                        "idp_mint",
                        &subject,
                        &name,
                        audience,
                        None,
                    ) {
                        // CWE-209: the audit error can carry the transparency-log
                        // filesystem path / IO error. Keep it in the server log
                        // only; return a generic client-facing message.
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
                // The request is already being refused on identity-propagation
                // grounds; an audit-write failure here does not change that
                // outcome (unlike the mint path above, which is fail-closed on
                // the audit write itself) — but it must not be silently
                // dropped, so it is logged.
                if let Err(audit_err) = audit_identity_propagation(
                    state.transparency_log.as_deref(),
                    "idp_refuse",
                    &subject,
                    &name,
                    audience,
                    Some(&e),
                ) {
                    warn!(
                        backend = %name,
                        error = %audit_err,
                        "identity-propagation refuse audit write failed"
                    );
                }
                return build_http_error_response(
                    Some(id.clone()),
                    -32003,
                    e,
                    StatusCode::FORBIDDEN,
                );
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
    let mut idem_reservation: Option<crate::idempotency::IdempotencyReservation> = None;
    if method == "tools/call" {
        match state.meta_mcp.direct_route_idempotency(
            retry.idempotency_key.as_deref(),
            &name,
            identity_key.as_deref(),
            verified_identity.as_ref(),
            params.as_ref(),
        ) {
            Ok(Some(crate::idempotency::GuardOutcome::CachedResult(cached))) => {
                let response = JsonRpcResponse::success(id.clone(), cached);
                return build_http_response(&response, StatusCode::OK);
            }
            Ok(Some(crate::idempotency::GuardOutcome::CachedError(error))) => {
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

    // SECURITY: apply tool policy, name validation, and input sanitization to
    // tools/call requests unless the backend explicitly opts into pass-through
    // mode (passthrough: true in config — only for fully-trusted internals).
    if method == "tools/call" {
        match apply_backend_tool_call_security(
            &state,
            &name,
            BackendAuthContext {
                client: client.as_ref(),
                oauth_agent_identity: oauth_agent_identity.as_ref(),
                cert_identity: cert_identity.as_ref(),
            },
            params.as_ref(),
            &id,
            !backend.passthrough(),
        ) {
            Some(Ok(Some(sanitized_params))) => {
                // Forward the sanitized params to the backend
                let forward = dispatch_in_scope(
                    &backend,
                    &method,
                    Some(sanitized_params),
                    &propagated_headers,
                    identity_key.as_deref(),
                )
                .await;
                return match forward {
                    Ok(mut response) => {
                        record_client_success(&state, client.as_ref());
                        // The transport uses its own request IDs to correlate
                        // concurrent upstream calls. Restore the caller's ID at
                        // the HTTP boundary so the client can correlate this
                        // response with its original JSON-RPC request.
                        response.id = Some(id.clone());
                        scan_direct_backend_response(
                            &state,
                            &name,
                            params.as_ref(),
                            client.as_ref(),
                            &mut response,
                        );
                        stamp_direct_provenance(
                            &state,
                            &name,
                            params.as_ref(),
                            client.as_ref(),
                            &mut response,
                        );
                        settle_direct_idempotency(idem_reservation.as_mut(), &response);
                        build_http_response(&response, StatusCode::OK)
                    }
                    Err(e) => {
                        record_client_failure(&state, client.as_ref());
                        error!(backend = %name, error = %e, "Backend request failed");
                        let response =
                            JsonRpcResponse::error(Some(id), e.to_rpc_code(), e.to_string());
                        // Dispatched failures settle as terminal: a transport
                        // failure after the backend acted is indistinguishable
                        // from one before it (ADR-012 consequence 1). A failure
                        // the gateway raised before dispatch is the exception —
                        // see `settle_direct_failure`.
                        settle_direct_failure(idem_reservation.as_mut(), &e, &response);
                        build_http_response(&response, StatusCode::INTERNAL_SERVER_ERROR)
                    }
                };
            }
            Some(Err(rejection)) => return rejection,
            Some(Ok(None)) | None => {} // no tool name present; fall through to normal forwarding
        }
    }

    // Forward to backend
    let forward = dispatch_in_scope(
        &backend,
        &method,
        params.clone(),
        &propagated_headers,
        identity_key.as_deref(),
    )
    .await;
    match forward {
        Ok(mut response) => {
            record_client_success(&state, client.as_ref());
            // Upstream transport IDs are private gateway correlation state;
            // direct-route clients must receive the ID they supplied.
            response.id = Some(id.clone());
            if method == "tools/list" {
                // Redaction FIRST, then the trust stamp. The firewall may remove
                // a `$defs` entry a surviving `$ref` points at, so a verdict
                // computed before it can say `within` about a document the
                // client never receives.
                scan_direct_tools_list_response(&state, &name, client.as_ref(), &mut response);
                normalize_tools_list_response(&name, &mut response);
            } else if method == "tools/call" {
                scan_direct_backend_response(
                    &state,
                    &name,
                    params.as_ref(),
                    client.as_ref(),
                    &mut response,
                );
                stamp_direct_provenance(
                    &state,
                    &name,
                    params.as_ref(),
                    client.as_ref(),
                    &mut response,
                );
            }
            settle_direct_idempotency(idem_reservation.as_mut(), &response);
            build_http_response(&response, StatusCode::OK)
        }
        Err(e) => {
            record_client_failure(&state, client.as_ref());
            error!(backend = %name, error = %e, "Backend request failed");
            let response = JsonRpcResponse::error(Some(id), e.to_rpc_code(), e.to_string());
            // Without this the reservation is dropped unsettled, which releases
            // the key and lets a retry re-execute a side effect the backend may
            // already have performed (ADR-012 consequence 1).
            settle_direct_failure(idem_reservation.as_mut(), &e, &response);
            build_http_response(&response, StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Store the direct route's result under the client's idempotency key so a
/// re-issue after a broken stream replays it instead of invoking the backend a
/// second time. Called after the response scan and provenance stamp so the
/// replay is byte-identical to what the first caller received.
///
/// Both terminal outcomes settle. A JSON-RPC error from a call that was
/// dispatched is an outcome, not an absence of one: the backend answered, so
/// the side effect may have landed, and releasing the key would hand the
/// caller's retry a clean slate for a mutation that may already have committed
/// (ADR-012 consequence 1). The retry is served the same error instead.
fn settle_direct_idempotency(
    reservation: Option<&mut crate::idempotency::IdempotencyReservation>,
    response: &JsonRpcResponse,
) {
    let Some(reservation) = reservation else {
        return;
    };
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

#[cfg(feature = "firewall")]
fn scan_direct_backend_response(
    state: &AppState,
    backend_name: &str,
    params: Option<&Value>,
    client: Option<&AuthenticatedClient>,
    response: &mut JsonRpcResponse,
) {
    let Some(ref fw) = state.firewall else {
        return;
    };
    let Some(params) = params else {
        return;
    };
    let Some(tool_name) = params.get("name").and_then(Value::as_str) else {
        return;
    };
    let Some(ref mut result) = response.result else {
        return;
    };

    let caller_name = client.map_or("anonymous", |c| c.name.as_str());
    let session_id = format!("direct:{backend_name}");
    let verdict = fw.check_response(&session_id, backend_name, tool_name, result, caller_name);
    if verdict.action == FirewallAction::Warn {
        warn!(
            backend = %backend_name,
            tool = %tool_name,
            findings = verdict.findings.len(),
            "Firewall: direct backend response warning"
        );
    }
}

#[cfg(not(feature = "firewall"))]
fn scan_direct_backend_response(
    _state: &AppState,
    _backend_name: &str,
    _params: Option<&Value>,
    _client: Option<&AuthenticatedClient>,
    _response: &mut JsonRpcResponse,
) {
}

/// Scan a `tools/list` response through the same firewall response scanner used
/// for `tools/call` (OWASP ASI01 tool-poisoning defense).
///
/// Backend-supplied tool `description`/metadata strings are scanned for prompt
/// injection and have embedded credentials redacted in place before the tool
/// list reaches the client — closing the gap where `tools/list` previously
/// bypassed all content scanning. Gated on the same firewall config as the
/// `tools/call` path: [`Firewall::check_response`] is a no-op when the firewall
/// is absent or response scanning is disabled, so behavior is unchanged when
/// the feature/config is off.
#[cfg(feature = "firewall")]
fn scan_direct_tools_list_response(
    state: &AppState,
    backend_name: &str,
    client: Option<&AuthenticatedClient>,
    response: &mut JsonRpcResponse,
) {
    let Some(ref fw) = state.firewall else {
        return;
    };
    let Some(ref mut result) = response.result else {
        return;
    };

    let caller_name = client.map_or("anonymous", |c| c.name.as_str());
    let session_id = format!("direct:{backend_name}");
    let verdict = fw.check_response(&session_id, backend_name, "tools/list", result, caller_name);
    if verdict.action == FirewallAction::Warn {
        warn!(
            backend = %backend_name,
            findings = verdict.findings.len(),
            "Firewall: direct tools/list response warning"
        );
    }
}

#[cfg(not(feature = "firewall"))]
fn scan_direct_tools_list_response(
    _state: &AppState,
    _backend_name: &str,
    _client: Option<&AuthenticatedClient>,
    _response: &mut JsonRpcResponse,
) {
}

/// GET /api/costs — REST endpoint for per-key and aggregate cost views.
///
/// Query parameters:
/// - `key=<name>`: view cost for a single API key
/// - `session=<id>`: view cost for a specific session
/// - (no params): aggregate view across all sessions and keys
pub(super) async fn costs_handler(
    State(state): State<Arc<AppState>>,
    request: axum::http::Request<axum::body::Body>,
) -> impl IntoResponse {
    use std::collections::HashMap;

    // Spend per session and per API key is cross-tenant inventory, and this
    // endpoint consulted no identity at all. `/ui/api/costs` already requires
    // admin; the two views of the same data now agree.
    if !request
        .extensions()
        .get::<AuthenticatedClient>()
        .is_some_and(|c| c.admin)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Admin authentication required" })),
        )
            .into_response();
    }

    let query: HashMap<String, String> = request
        .uri()
        .query()
        .map(|q| {
            q.split('&')
                .filter_map(|part| {
                    let mut kv = part.splitn(2, '=');
                    let k = kv.next()?;
                    let v = kv.next().unwrap_or("");
                    Some((k.to_string(), v.to_string()))
                })
                .collect()
        })
        .unwrap_or_default();

    let tracker = state.meta_mcp.cost_tracker();

    let body = if let Some(key_name) = query.get("key") {
        match tracker.key_snapshot(key_name) {
            Some(snap) => serde_json::to_value(snap).unwrap_or(serde_json::json!(null)),
            None => serde_json::json!({
                "error": format!("No data for key '{key_name}'")
            }),
        }
    } else if let Some(session_id) = query.get("session") {
        match tracker.session_snapshot(session_id) {
            Some(snap) => serde_json::to_value(snap).unwrap_or(serde_json::json!(null)),
            None => serde_json::json!({
                "error": format!("No data for session '{session_id}'")
            }),
        }
    } else {
        // Aggregate view: all sessions, all keys, totals
        serde_json::json!({
            "aggregate": serde_json::to_value(tracker.aggregate()).unwrap_or(serde_json::json!(null)),
            "sessions": serde_json::to_value(tracker.all_sessions()).unwrap_or(serde_json::json!([])),
            "keys": serde_json::to_value(tracker.all_keys()).unwrap_or(serde_json::json!([])),
        })
    };

    (StatusCode::OK, Json(body)).into_response()
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod idempotency_settlement_tests {
    use std::sync::Arc;

    use serde_json::json;

    use super::{cached_error_response, settle_direct_failure};
    use crate::Error;
    use crate::idempotency::{GuardOutcome, IdempotencyCache, enforce};
    use crate::protocol::JsonRpcResponse;

    fn reserve(cache: &Arc<IdempotencyCache>) -> crate::idempotency::IdempotencyReservation {
        match enforce(cache, "key", "fingerprint").expect("a fresh key is admitted") {
            GuardOutcome::Proceed(reservation) => reservation,
            other => panic!("expected Proceed, got {other:?}"),
        }
    }

    #[test]
    fn pre_dispatch_failure_frees_the_key_for_a_retry() {
        // GIVEN a reserved key whose call the circuit breaker refused outright.
        let cache = Arc::new(IdempotencyCache::new());
        let mut reservation = reserve(&cache);
        let error = Error::CircuitOpen("backend".to_string());
        let response = JsonRpcResponse::error(None, error.to_rpc_code(), error.to_string());

        // WHEN the failure is settled.
        settle_direct_failure(Some(&mut reservation), &error, &response);

        // THEN the key is admissible again. Asserted while the reservation is
        // still alive on purpose: `Drop` releases an unsettled reservation too,
        // so an assertion after the drop passes without the explicit release.
        assert!(
            matches!(
                enforce(&cache, "key", "fingerprint"),
                Ok(GuardOutcome::Proceed(_))
            ),
            "a refusal raised before dispatch must not consume the key"
        );
    }

    #[test]
    fn dispatched_failure_is_cached_as_terminal() {
        // GIVEN a reserved key whose call reached the backend and failed.
        let cache = Arc::new(IdempotencyCache::new());
        let mut reservation = reserve(&cache);
        let error = Error::Transport("connection reset".to_string());
        let response = JsonRpcResponse::error(None, error.to_rpc_code(), error.to_string());

        // WHEN the failure is settled.
        settle_direct_failure(Some(&mut reservation), &error, &response);

        // THEN a retry replays the error instead of re-running the side effect.
        assert!(
            matches!(
                enforce(&cache, "key", "fingerprint"),
                Ok(GuardOutcome::CachedError(_))
            ),
            "ADR-012 consequence 1: a dispatched failure settles as terminal"
        );
    }

    #[test]
    fn replayed_error_carries_the_stored_data_field() {
        // GIVEN a stored error whose machine-readable half lives in `data`.
        let stored =
            json!({"code": -32000, "message": "rate limited", "data": {"retry_after": 30}});

        // WHEN the replay response is rebuilt.
        let response = cached_error_response(None, &stored);

        // THEN the retry sees the same error the first caller did.
        let error = response.error.expect("a stored error replays as an error");
        assert_eq!(error.code, -32000);
        assert_eq!(error.message, "rate limited");
        assert_eq!(error.data, Some(json!({"retry_after": 30})));
    }

    #[test]
    fn replayed_error_without_data_stays_data_free() {
        // GIVEN a stored error that carried no `data` (the field is skipped when
        // `None`, so it is absent rather than null).
        let stored = json!({"code": -32603, "message": "boom"});

        // WHEN the replay response is rebuilt.
        let response = cached_error_response(None, &stored);

        // THEN no `data` key is invented.
        let error = response.error.expect("a stored error replays as an error");
        assert_eq!(error.data, None);
    }
}

#[cfg(test)]
mod direct_route_scope_tests {
    use std::sync::Mutex;

    use async_trait::async_trait;

    use super::*;
    use crate::backend::Backend;
    use crate::config::BackendConfig;
    use crate::protocol::RequestId;
    use crate::transport::Transport;

    /// Records the params as the backend would see them on the wire.
    struct Recorder(Mutex<Option<Value>>);

    #[async_trait]
    impl Transport for Recorder {
        async fn request(
            &self,
            _method: &str,
            params: Option<Value>,
        ) -> crate::Result<JsonRpcResponse> {
            *self.0.lock().unwrap() = params;
            Ok(JsonRpcResponse::success(RequestId::Number(1), json!({})))
        }

        async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
            Ok(())
        }

        fn is_connected(&self) -> bool {
            true
        }

        async fn close(&self) -> crate::Result<()> {
            Ok(())
        }
    }

    fn recording_backend() -> (Arc<Backend>, Arc<Recorder>) {
        let backend = Arc::new(Backend::new(
            "direct",
            BackendConfig::default(),
            &crate::config::FailsafeConfig::default(),
            std::time::Duration::from_secs(5),
        ));
        let recorder = Arc::new(Recorder(Mutex::new(None)));
        backend.set_transport_for_test(recorder.clone() as Arc<dyn Transport>);
        (backend, recorder)
    }

    /// `POST /mcp/{name}` is a client request like any other, so the token the
    /// backend sees must be the gateway's own. The mint no-ops outside a
    /// request scope, so dropping the wrapper here would be silent -- this row
    /// is what makes it loud.
    #[tokio::test]
    async fn a_call_on_this_route_sends_the_backend_a_minted_token() {
        let (backend, recorder) = recording_backend();

        dispatch_in_scope(
            &backend,
            "tools/call",
            Some(json!({ "name": "t", "_meta": { "progressToken": 7 } })),
            &[],
            None,
        )
        .await
        .expect("the recording transport answers");

        let sent = recorder.0.lock().unwrap().clone().expect("params recorded");
        let token = &sent["_meta"]["progressToken"];
        assert_ne!(
            token,
            &json!(7),
            "the caller's own token reached the backend"
        );
        assert!(
            token.as_str().is_some_and(|t| t.starts_with("gw-")),
            "backend was sent {token:?}"
        );
    }
}
