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
fn resolve_passthrough_headers(
    cfg: &crate::identity_propagation::IdentityPropagationConfig,
    inbound: &axum::http::HeaderMap,
) -> Result<Vec<(String, String)>, String> {
    // The inbound header a capable client attaches its backend credential in
    // (advertised via RFC 9728 protected-resource metadata, MIK-6750). Distinct
    // from `Authorization` so the gateway-auth token is never forwarded.
    const PASSTHROUGH_HEADER: &str = "x-mcp-passthrough-authorization";
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
    let propagated_headers: Vec<(String, String)> = if method == "tools/call" {
        // Passthrough (ADR-008 rung 2, MIK-6746): a backend whose caller attaches
        // its OWN credential is handled here — forward it verbatim, mint/store
        // NOTHING (INV-4). Any other propagation strategy is resolved by the
        // shared minting chokepoint. Isolation (INV-3) holds by construction:
        // each request forwards its own header via `request_with_headers`, never
        // via the shared transport, and the direct route keeps no per-user cache.
        let passthrough_cfg = state
            .backends
            .get(&name)
            .and_then(|b| b.identity_propagation_config().cloned())
            .filter(|c| {
                c.strategy == crate::identity_propagation::PropagationStrategyKind::Passthrough
            });
        let resolved = if let Some(cfg) = passthrough_cfg {
            resolve_passthrough_headers(&cfg, &inbound_headers)
        } else {
            state
                .meta_mcp
                .resolve_propagation_headers(&name, verified_identity.as_ref())
                .await
                .map_err(|e| e.to_string())
        };
        match resolved {
            Ok(headers) => headers,
            Err(e) => {
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
    // `tools/call`. Discovery/plumbing (`initialize`, `tools/list`, `ping`,
    // `notifications/*`) is exempt: it carries no user data. A per-user
    // credential was resolved above iff `propagated_headers` is non-empty (only
    // populated for `tools/call`); any other guarded method has none, so a
    // per-user OAuth backend on a multi-user gateway is refused rather than
    // served the shared token.
    let isolation_guarded = !matches!(method.as_str(), "initialize" | "tools/list" | "ping")
        && !method.starts_with("notifications/");
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
mod tests {
    use serde_json::json;

    use super::*;

    // MIK-6746 D.4 — passthrough resolution (ADR-008 rung 2).
    mod passthrough {
        use axum::http::HeaderMap;

        use super::*;
        use crate::identity_propagation::{
            IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
        };

        const HEADER: &str = "x-mcp-passthrough-authorization";

        fn cfg(required: bool) -> IdentityPropagationConfig {
            IdentityPropagationConfig {
                strategy: PropagationStrategyKind::Passthrough,
                audience: "https://backend".to_string(),
                required,
                session_mode: SessionMode::PerUser,
            }
        }

        fn headers_with(cred: &str) -> HeaderMap {
            let mut h = HeaderMap::new();
            h.insert(HEADER, cred.parse().unwrap());
            h
        }

        // D.1/D.4 — the caller's own credential is forwarded verbatim to the
        // backend under `Authorization`. Nothing else is emitted; the function
        // is pure over its inputs, so it cannot persist a token (INV-4).
        #[test]
        fn present_credential_is_forwarded_as_authorization() {
            let out = resolve_passthrough_headers(&cfg(true), &headers_with("Bearer caller-tok"))
                .expect("present credential resolves");
            assert_eq!(
                out,
                vec![("Authorization".to_string(), "Bearer caller-tok".to_string())]
            );
        }

        // D.4 — concurrent callers are isolated: each request forwards only its
        // own header value; there is no shared/mutable state between calls.
        #[test]
        fn concurrent_callers_are_isolated() {
            let a = resolve_passthrough_headers(&cfg(true), &headers_with("Bearer alice")).unwrap();
            let b = resolve_passthrough_headers(&cfg(true), &headers_with("Bearer bob")).unwrap();
            assert_eq!(a[0].1, "Bearer alice");
            assert_eq!(b[0].1, "Bearer bob");
            assert_ne!(a[0].1, b[0].1);
        }

        // D.3 — a required backend with no caller credential fails closed.
        #[test]
        fn required_and_absent_refuses() {
            assert!(resolve_passthrough_headers(&cfg(true), &HeaderMap::new()).is_err());
            // A blank credential counts as absent.
            assert!(resolve_passthrough_headers(&cfg(true), &headers_with("   ")).is_err());
        }

        // A non-required backend with no caller credential yields the static
        // path (empty), after which the INV-2 shared-token guard decides.
        #[test]
        fn optional_and_absent_is_empty() {
            let out = resolve_passthrough_headers(&cfg(false), &HeaderMap::new()).unwrap();
            assert!(out.is_empty());
        }
    }

    #[test]
    fn normalize_tools_list_response_fills_direct_backend_proxy_annotations() {
        let mut response = JsonRpcResponse::success(
            RequestId::Number(1),
            json!({
                "tools": [
                    {
                        "name": "search",
                        "description": "Search things",
                        "inputSchema": {"type": "object"},
                        "annotations": {"readOnlyHint": true}
                    },
                    {
                        "name": "archive_chat",
                        "description": "Archive a chat",
                        "inputSchema": {"type": "object"},
                        "annotations": {}
                    }
                ],
                "nextCursor": "abc",
                "extra": "preserved"
            }),
        );

        normalize_tools_list_response("beeper", &mut response);

        let result = response.result.expect("success result");
        assert_eq!(result["nextCursor"], "abc");
        assert_eq!(result["extra"], "preserved");

        let search = &result["tools"][0]["annotations"];
        assert_eq!(search["readOnlyHint"], true);
        assert_eq!(search["destructiveHint"], false);
        assert_eq!(search["idempotentHint"], true);
        assert_eq!(search["openWorldHint"], true);
        assert_eq!(
            result["tools"][0]["trustCard"]["schemaVersion"],
            "trust_card.v1"
        );
        assert_eq!(
            result["tools"][0]["trustCard"]["serverId"],
            "backend:beeper"
        );
        assert_eq!(result["tools"][0]["trustCard"]["toolName"], "search");
        assert_eq!(
            result["tools"][0]["trustCard"]["trustCardDigestSha256"]
                .as_str()
                .unwrap()
                .len(),
            64
        );

        let archive = &result["tools"][1]["annotations"];
        assert_eq!(archive["readOnlyHint"], false);
        assert_eq!(archive["destructiveHint"], true);
        assert_eq!(archive["idempotentHint"], false);
        assert_eq!(archive["openWorldHint"], true);
    }
}
