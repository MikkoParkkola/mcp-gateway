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

    match serde_json::to_value(tools) {
        Ok(normalized_tools) => *tools_value = normalized_tools,
        Err(e) => {
            warn!(backend = %backend_name, error = %e, "Failed to serialize normalized tools/list");
        }
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
            Ok(()) => (StatusCode::ACCEPTED, Json(json!({}))),
            Err(e) => {
                error!(backend = %name, error = %e, "Backend notification failed");
                let response = JsonRpcResponse::error(None, e.to_rpc_code(), e.to_string());
                build_http_response(&response, StatusCode::INTERNAL_SERVER_ERROR)
            }
        };
    }

    // For requests, id is guaranteed to exist
    let id = id.expect("id should exist for non-notification requests");

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
                return match backend.request(&method, Some(sanitized_params)).await {
                    Ok(mut response) => {
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
    match backend.request(&method, params.clone()).await {
        Ok(mut response) => {
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
            error!(backend = %name, error = %e, "Backend request failed");
            let response = JsonRpcResponse::error(Some(id), e.to_rpc_code(), e.to_string());
            build_http_response(&response, StatusCode::INTERNAL_SERVER_ERROR)
        }
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

        let archive = &result["tools"][1]["annotations"];
        assert_eq!(archive["readOnlyHint"], false);
        assert_eq!(archive["destructiveHint"], true);
        assert_eq!(archive["idempotentHint"], false);
        assert_eq!(archive["openWorldHint"], true);
    }
}
