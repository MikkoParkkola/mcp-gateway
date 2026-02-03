//! HTTP router and handlers

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::IntoResponse,
    routing::{get, post},
};
use serde_json::{Value, json};
use tower_http::{catch_panic::CatchPanicLayer, compression::CompressionLayer, trace::TraceLayer};
use tracing::{debug, error, info};

use super::auth::{AuthenticatedClient, ResolvedAuthConfig, auth_middleware};
use super::meta_mcp::MetaMcp;
use super::streaming::{NotificationMultiplexer, create_sse_response};
use crate::backend::BackendRegistry;
use crate::config::StreamingConfig;
use crate::protocol::{JsonRpcResponse, RequestId};

/// Shared application state
pub struct AppState {
    /// Backend registry
    pub backends: Arc<BackendRegistry>,
    /// Meta-MCP handler
    pub meta_mcp: Arc<MetaMcp>,
    /// Whether Meta-MCP is enabled
    pub meta_mcp_enabled: bool,
    /// Notification multiplexer for streaming
    pub multiplexer: Arc<NotificationMultiplexer>,
    /// Streaming configuration
    pub streaming_config: StreamingConfig,
    /// Authentication configuration
    pub auth_config: Arc<ResolvedAuthConfig>,
}

/// Create the router
pub fn create_router(state: Arc<AppState>) -> Router {
    let auth_config = Arc::clone(&state.auth_config);

    Router::new()
        .route("/health", get(health_handler))
        .route(
            "/mcp",
            post(meta_mcp_handler)
                .get(mcp_sse_handler)
                .delete(mcp_delete_handler),
        )
        .route("/mcp/{name}", post(backend_handler))
        .route("/mcp/{name}/{*path}", post(backend_handler))
        // Helpful error for deprecated SSE endpoint (common misconfiguration)
        .route(
            "/sse",
            get(sse_deprecated_handler).post(sse_deprecated_handler),
        )
        // Authentication middleware (applied before other layers)
        .layer(middleware::from_fn_with_state(auth_config, auth_middleware))
        .layer(CatchPanicLayer::new())
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// GET /mcp handler - SSE stream for server→client notifications
/// Per MCP spec 2025-03-26, servers MAY return SSE stream or 405 Method Not Allowed.
/// We implement the full streaming support.
async fn mcp_sse_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Check if streaming is enabled
    if !state.streaming_config.enabled {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            Json(json!({
                "jsonrpc": "2.0",
                "error": {
                    "code": -32600,
                    "message": "Streaming not enabled. Use POST to send JSON-RPC requests to /mcp"
                },
                "id": null
            })),
        )
            .into_response();
    }

    // Check Accept header - must accept text/event-stream
    let accept = headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !accept.contains("text/event-stream") {
        return (
            StatusCode::NOT_ACCEPTABLE,
            Json(json!({
                "error": "Must accept text/event-stream for SSE notifications"
            })),
        )
            .into_response();
    }

    // Get or create session - convert to owned strings for Rust 2024 lifetime rules
    let existing_session_id = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let last_event_id = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let (session_id, _rx) = state
        .multiplexer
        .get_or_create_session(existing_session_id.as_deref());

    info!(session_id = %session_id, "Client connected to SSE stream");

    // Auto-subscribe to configured backends
    let multiplexer = Arc::clone(&state.multiplexer);
    let sid = session_id.clone();
    tokio::spawn(async move {
        multiplexer.auto_subscribe(&sid).await;
    });

    // Clone Arc for the stream (outlives the handler)
    let multiplexer_for_stream = Arc::clone(&state.multiplexer);
    let keep_alive = state.streaming_config.keep_alive_interval;

    // Create SSE response with owned data
    match create_sse_response(
        multiplexer_for_stream,
        session_id.clone(),
        last_event_id,
        keep_alive,
    ) {
        Some(sse) => {
            // Add session ID header to response
            let mut response = sse.into_response();
            response
                .headers_mut()
                .insert("mcp-session-id", session_id.parse().unwrap());
            response
        }
        None => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "Failed to create SSE stream"
            })),
        )
            .into_response(),
    }
}

/// DELETE /mcp handler - Session termination
/// Per MCP spec 2025-03-26, clients SHOULD send DELETE to terminate session.
async fn mcp_delete_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let session_id = headers.get("mcp-session-id").and_then(|v| v.to_str().ok());

    match session_id {
        Some(id) if state.multiplexer.has_session(id) => {
            state.multiplexer.remove_session(id);
            info!(session_id = %id, "Session terminated by client");
            StatusCode::NO_CONTENT
        }
        Some(id) => {
            debug!(session_id = %id, "Session not found for DELETE");
            StatusCode::NOT_FOUND
        }
        None => StatusCode::BAD_REQUEST,
    }
}

/// Deprecated SSE endpoint handler - surfaces a clear error instead of silent 404
async fn sse_deprecated_handler() -> impl IntoResponse {
    (
        StatusCode::GONE,
        Json(json!({
            "error": "SSE transport is deprecated. Use Streamable HTTP (POST /mcp) instead.",
            "migration": "In settings.json, change: \"type\": \"sse\" -> \"type\": \"http\" and \"url\": \"http://localhost:39400/sse\" -> \"url\": \"http://localhost:39400/mcp\"",
            "spec": "https://modelcontextprotocol.io/specification/2025-03-26/basic/transports#streamable-http"
        })),
    )
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
        return (StatusCode::ACCEPTED, Json(json!({})));
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
    request: axum::http::Request<axum::body::Body>,
) -> impl IntoResponse {
    // Extract authenticated client from extensions (injected by auth middleware)
    let client = request.extensions().get::<AuthenticatedClient>().cloned();

    // Check backend access if auth is enabled
    if let Some(ref client) = client {
        if !client.can_access_backend(&name) {
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
fn parse_request(
    value: &Value,
) -> Result<(Option<RequestId>, String, Option<Value>), JsonRpcResponse> {
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
