//! Backend and cost API request handlers.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::{Value, json};
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
/// Also fails closed (MIK-6710) BEFORE reading the inbound header when
/// `transport_carries_headers` is `false` for a `required` backend — a stdio
/// or websocket backend would otherwise accept the caller's credential here
/// and then silently drop it in `request_with_headers`, running
/// unauthenticated while the audit trail records a resolved passthrough.
fn resolve_passthrough_headers(
    cfg: &crate::identity_propagation::IdentityPropagationConfig,
    inbound: &axum::http::HeaderMap,
    transport_carries_headers: bool,
) -> Result<Vec<(String, String)>, String> {
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
            Ok(Vec::new())
        }
    };
    match inbound
        .get(PASSTHROUGH_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        Some(v) => Ok(vec![("Authorization".to_string(), v.to_string())]),
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
/// ponytail: audit is best-effort, not fail-closed — a write failure is
/// `warn!`'d and the caller's request proceeds/fails on its own merits,
/// mirroring how `TransparencyLogger::log_invocation` failures are handled
/// elsewhere in the gateway. A regulated buyer that needs "no mint without a
/// durable audit record" would need this gated fail-closed instead; tracked
/// as a possible future hardening, not required for MIK-6740.
fn audit_identity_propagation(
    logger: Option<&crate::security::TransparencyLogger>,
    action: &'static str,
    subject: &str,
    backend: &str,
    audience: Option<&str>,
    reason: Option<&str>,
) {
    let Some(logger) = logger else {
        return;
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

    if let Err(e) = logger.append_event(fields) {
        warn!(
            backend,
            action, error = %e,
            "Failed to write identity-propagation audit entry (transparency log)"
        );
    }
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

    // Handle notifications - forward to backend but return 202 Accepted
    if method.starts_with("notifications/") {
        return match backend.notify(&method, params).await {
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
            resolve_passthrough_headers(
                &cfg,
                &inbound_headers,
                backend.transport_carries_identity_headers(),
            )
        } else {
            state
                .meta_mcp
                .resolve_propagation_headers(&name, verified_identity.as_ref())
                .await
                .map_err(|e| e.to_string())
        };
        let subject = audit_subject(verified_identity.as_ref());
        let audience = idp_cfg.as_ref().map(|c| c.audience.as_str());
        match resolved {
            Ok(headers) => {
                // A successful resolution that yields no headers is the
                // unchanged static-credential fallback (IDP.5), not a mint —
                // only audit when a per-user credential was actually attached.
                if !headers.is_empty() {
                    audit_identity_propagation(
                        state.transparency_log.as_deref(),
                        "idp_mint",
                        &subject,
                        &name,
                        audience,
                        None,
                    );
                }
                headers
            }
            Err(e) => {
                audit_identity_propagation(
                    state.transparency_log.as_deref(),
                    "idp_refuse",
                    &subject,
                    &name,
                    audience,
                    Some(&e),
                );
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
                let forward = if propagated_headers.is_empty() {
                    backend.request(&method, Some(sanitized_params)).await
                } else {
                    backend
                        .request_with_headers(&method, Some(sanitized_params), &propagated_headers)
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
    let forward = if propagated_headers.is_empty() {
        backend.request(&method, params.clone()).await
    } else {
        backend
            .request_with_headers(&method, params.clone(), &propagated_headers)
            .await
    };
    match forward {
        Ok(mut response) => {
            record_client_success(&state, client.as_ref());
            if method == "tools/list" {
                normalize_tools_list_response(&name, &mut response);
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
