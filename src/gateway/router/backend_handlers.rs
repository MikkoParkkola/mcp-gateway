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
use crate::backend::normalize_tool_annotations;
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
            fw.check_request(&session_id, backend_name, tool_name, arguments, caller_name);
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

    let Ok(mut tools) = serde_json::from_value::<Vec<Tool>>(tools_value.clone()) else {
        warn!(backend = %backend_name, "Backend tools/list result could not be normalized");
        return;
    };

    normalize_tool_annotations(backend_name, &mut tools);

    let server_id = format!("backend:{backend_name}");
    let tools = project_tool_descriptors_trust_cards(&server_id, backend_name, &tools);

    match serde_json::to_value(tools) {
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
                let forward = if propagated_headers.is_empty() && identity_key.is_none() {
                    backend.request(&method, Some(sanitized_params)).await
                } else {
                    backend
                        .request_with_headers(
                            &method,
                            Some(sanitized_params),
                            &propagated_headers,
                            identity_key.as_deref(),
                        )
                        .await
                };
                return match forward {
                    Ok(mut response) => {
                        record_client_success(&state, client.as_ref());
                        scan_direct_backend_response(
                            &state,
                            &name,
                            params.as_ref(),
                            client.as_ref(),
                            &mut response,
                        );
                        build_http_response(&response, StatusCode::OK)
                    }
                    Err(e) => {
                        record_client_failure(&state, client.as_ref());
                        error!(backend = %name, error = %e, "Backend request failed");
                        let response =
                            JsonRpcResponse::error(Some(id), e.to_rpc_code(), e.to_string());
                        build_http_response(&response, StatusCode::INTERNAL_SERVER_ERROR)
                    }
                };
            }
            Some(Err(rejection)) => return rejection,
            Some(Ok(None)) | None => {} // no tool name present; fall through to normal forwarding
        }
    }

    // Forward to backend
    let forward = if propagated_headers.is_empty() && identity_key.is_none() {
        backend.request(&method, params.clone()).await
    } else {
        backend
            .request_with_headers(
                &method,
                params.clone(),
                &propagated_headers,
                identity_key.as_deref(),
            )
            .await
    };
    match forward {
        Ok(mut response) => {
            record_client_success(&state, client.as_ref());
            if method == "tools/list" {
                normalize_tools_list_response(&name, &mut response);
                scan_direct_tools_list_response(&state, &name, client.as_ref(), &mut response);
            } else if method == "tools/call" {
                scan_direct_backend_response(
                    &state,
                    &name,
                    params.as_ref(),
                    client.as_ref(),
                    &mut response,
                );
            }
            build_http_response(&response, StatusCode::OK)
        }
        Err(e) => {
            record_client_failure(&state, client.as_ref());
            error!(backend = %name, error = %e, "Backend request failed");
            let response = JsonRpcResponse::error(Some(id), e.to_rpc_code(), e.to_string());
            build_http_response(&response, StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

fn record_client_success(state: &AppState, client: Option<&AuthenticatedClient>) {
    if let Some(client) = client {
        state.auth_config.record_client_success(&client.name);
    }
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

    (StatusCode::OK, Json(body))
}

#[cfg(test)]
mod tests;
