//! HTTP router and handlers

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use serde_json::{Value, json};
use tower_http::{catch_panic::CatchPanicLayer, compression::CompressionLayer, trace::TraceLayer};
use tracing::{debug, error};

use super::meta_mcp::MetaMcp;
use crate::backend::BackendRegistry;
use crate::protocol::{JsonRpcResponse, RequestId};

/// Shared application state
pub struct AppState {
    /// Backend registry
    pub backends: Arc<BackendRegistry>,
    /// Meta-MCP handler
    pub meta_mcp: Arc<MetaMcp>,
    /// Whether Meta-MCP is enabled
    pub meta_mcp_enabled: bool,
}

/// Create the router
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/mcp", post(meta_mcp_handler))
        .route("/mcp/{name}", post(backend_handler))
        .route("/mcp/{name}/{*path}", post(backend_handler))
        .layer(CatchPanicLayer::new())
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Health check handler
async fn health_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let statuses = state.backends.statuses();

    let healthy = statuses.values().all(|s| s.circuit_state != "Open");

    let response = json!({
        "status": if healthy { "healthy" } else { "degraded" },
        "version": env!("CARGO_PKG_VERSION"),
        "backends": statuses
    });

    if healthy {
        (StatusCode::OK, Json(response))
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, Json(response))
    }
}

/// Meta-MCP handler (POST /mcp)
async fn meta_mcp_handler(
    State(state): State<Arc<AppState>>,
    _headers: HeaderMap,
    Json(request): Json<Value>,
) -> impl IntoResponse {
    if !state.meta_mcp_enabled {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "jsonrpc": "2.0",
                "error": {"code": -32600, "message": "Meta-MCP disabled"},
                "id": null
            })),
        );
    }

    // Parse request
    let (id, method, params) = match parse_request(&request) {
        Ok(parsed) => parsed,
        Err(response) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::to_value(response).unwrap()),
            );
        }
    };

    debug!(method = %method, "Meta-MCP request");

    // Handle notifications (no id) - return 202 Accepted with empty body
    if method.starts_with("notifications/") {
        debug!(notification = %method, "Handling notification");
        return (
            StatusCode::ACCEPTED,
            Json(json!({})),
        );
    }

    // For requests, id is guaranteed to exist (checked in parse_request)
    let id = id.expect("id should exist for non-notification requests");

    // Route to appropriate handler
    let response = match method.as_str() {
        "initialize" => state.meta_mcp.handle_initialize(id, params.as_ref()),
        "tools/list" => state.meta_mcp.handle_tools_list(id),
        "tools/call" => {
            let tool_name = params
                .as_ref()
                .and_then(|p| p.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let arguments = params
                .as_ref()
                .and_then(|p| p.get("arguments"))
                .cloned()
                .unwrap_or(json!({}));
            state
                .meta_mcp
                .handle_tools_call(id, tool_name, arguments)
                .await
        }
        "ping" => JsonRpcResponse::success(id, json!({})),
        _ => JsonRpcResponse::error(Some(id), -32601, format!("Method not found: {method}")),
    };

    (
        StatusCode::OK,
        Json(serde_json::to_value(response).unwrap()),
    )
}

/// Backend handler (POST /mcp/{name})
async fn backend_handler(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    _headers: HeaderMap,
    Json(request): Json<Value>,
) -> impl IntoResponse {
    // Find backend
    let backend = match state.backends.get(&name) {
        Some(b) => b,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "jsonrpc": "2.0",
                    "error": {"code": -32001, "message": format!("Backend not found: {name}")},
                    "id": null
                })),
            );
        }
    };

    // Parse request
    let (id, method, params) = match parse_request(&request) {
        Ok(parsed) => parsed,
        Err(response) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::to_value(response).unwrap()),
            );
        }
    };

    debug!(backend = %name, method = %method, "Backend request");

    // Handle notifications - forward to backend but return 202 Accepted
    if method.starts_with("notifications/") {
        // Forward notification to backend (fire and forget)
        let _ = backend.request(&method, params).await;
        return (
            StatusCode::ACCEPTED,
            Json(json!({})),
        );
    }

    // For requests, id is guaranteed to exist
    let id = id.expect("id should exist for non-notification requests");

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

/// Parse JSON-RPC request or notification
/// Returns (Option<RequestId>, method, params) - id is None for notifications
fn parse_request(value: &Value) -> Result<(Option<RequestId>, String, Option<Value>), JsonRpcResponse> {
    // Check jsonrpc version
    let jsonrpc = value.get("jsonrpc").and_then(|v| v.as_str());
    if jsonrpc != Some("2.0") {
        return Err(JsonRpcResponse::error(
            None,
            -32600,
            "Invalid JSON-RPC version",
        ));
    }

    // Get ID (required for requests, missing for notifications)
    let id = value.get("id").and_then(|v| {
        if v.is_string() {
            Some(RequestId::String(v.as_str().unwrap().to_string()))
        } else if v.is_i64() {
            Some(RequestId::Number(v.as_i64().unwrap()))
        } else if v.is_u64() {
            Some(RequestId::Number(v.as_u64().unwrap() as i64))
        } else {
            None
        }
    });

    // Get method
    let method = value
        .get("method")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcResponse::error(id.clone(), -32600, "Missing method"))?;

    // Get params (optional)
    let params = value.get("params").cloned();

    // For notifications (methods starting with "notifications/"), id is optional
    // For requests, id is required
    if !method.starts_with("notifications/") && id.is_none() {
        return Err(JsonRpcResponse::error(None, -32600, "Missing id"));
    }

    Ok((id, method.to_string(), params))
}
