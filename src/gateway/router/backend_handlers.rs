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
use super::helpers::parse_request;
use crate::gateway::auth::AuthenticatedClient;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::{sanitize_json_value, validate_tool_name};

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
    params: Option<&Value>,
    id: &RequestId,
) -> Option<Result<Value, (StatusCode, Json<Value>)>> {
    let params = params?;
    let tool_name = params.get("name").and_then(Value::as_str).unwrap_or("");
    if tool_name.is_empty() {
        return None;
    }

    if let Err(e) = validate_tool_name(tool_name) {
        warn!(backend = %backend_name, tool = %tool_name, "Tool name rejected by validation");
        return Some(Err(backend_security_error(id, &e)));
    }

    if let Err(e) = state.tool_policy.check(backend_name, tool_name) {
        warn!(backend = %backend_name, tool = %tool_name, "Tool blocked by policy");
        return Some(Err(backend_security_error(id, &e.to_string())));
    }

    match sanitize_json_value(params) {
        Ok(sanitized) => Some(Ok(sanitized)),
        Err(e) => {
            warn!(backend = %backend_name, tool = %tool_name, "Input sanitization failed");
            Some(Err(backend_security_error(id, &e.to_string())))
        }
    }
}

/// Build a `403 Forbidden` JSON-RPC error response for security rejections.
fn backend_security_error(id: &RequestId, message: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "jsonrpc": "2.0",
            "error": {"code": -32600, "message": message},
            "id": serde_json::to_value(id).unwrap_or(Value::Null)
        })),
    )
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

    // Check backend access if auth is enabled
    if let Some(ref client) = client
        && !client.can_access_backend(&name)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "jsonrpc": "2.0",
                "error": {
                    "code": -32003,
                    "message": format!("Client '{}' not authorized for backend '{}'", client.name, name)
                },
                "id": null
            })),
        );
    }

    // Parse JSON body
    let body_bytes = match axum::body::to_bytes(request.into_body(), 10 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "jsonrpc": "2.0",
                    "error": {"code": -32700, "message": format!("Failed to read body: {e}")},
                    "id": null
                })),
            );
        }
    };

    let json_request: Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "jsonrpc": "2.0",
                    "error": {"code": -32700, "message": format!("Invalid JSON: {e}")},
                    "id": null
                })),
            );
        }
    };

    // Find backend
    let Some(backend) = state.backends.get(&name) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "jsonrpc": "2.0",
                "error": {"code": -32001, "message": format!("Backend not found: {name}")},
                "id": null
            })),
        );
    };

    // Parse request
    let (id, method, params) = match parse_request(&json_request) {
        Ok(parsed) => parsed,
        Err(response) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::to_value(response).unwrap()),
            );
        }
    };

    debug!(backend = %name, method = %method, client = ?client.as_ref().map(|c| &c.name), "Backend request");

    // Handle notifications - forward to backend but return 202 Accepted
    if method.starts_with("notifications/") {
        // Forward notification to backend (fire and forget)
        let _ = backend.request(&method, params).await;
        return (StatusCode::ACCEPTED, Json(json!({})));
    }

    // For requests, id is guaranteed to exist
    let id = id.expect("id should exist for non-notification requests");

    // SECURITY: apply tool policy, name validation, and input sanitization to
    // tools/call requests unless the backend explicitly opts into pass-through
    // mode (passthrough: true in config — only for fully-trusted internals).
    if method == "tools/call" && !backend.passthrough() {
        match apply_backend_tool_call_security(&state, &name, params.as_ref(), &id) {
            Some(Ok(sanitized_params)) => {
                // Forward the sanitized params to the backend
                return match backend.request(&method, Some(sanitized_params)).await {
                    Ok(response) => (
                        StatusCode::OK,
                        Json(serde_json::to_value(response).unwrap()),
                    ),
                    Err(e) => {
                        error!(backend = %name, error = %e, "Backend request failed");
                        let response =
                            JsonRpcResponse::error(Some(id), e.to_rpc_code(), e.to_string());
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::to_value(response).unwrap()),
                        )
                    }
                };
            }
            Some(Err(rejection)) => return rejection,
            None => {} // no tool name present; fall through to normal forwarding
        }
    }

    // Forward to backend
    match backend.request(&method, params).await {
        Ok(response) => (
            StatusCode::OK,
            Json(serde_json::to_value(response).unwrap()),
        ),
        Err(e) => {
            error!(backend = %name, error = %e, "Backend request failed");
            let response = JsonRpcResponse::error(Some(id), e.to_rpc_code(), e.to_string());
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::to_value(response).unwrap()),
            )
        }
    }
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
