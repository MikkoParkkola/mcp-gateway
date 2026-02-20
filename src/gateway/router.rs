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
use tracing::{debug, error, info, warn};

use super::auth::{AuthenticatedClient, ResolvedAuthConfig, auth_middleware};
use super::meta_mcp::MetaMcp;
use super::proxy::ProxyManager;
use super::streaming::{NotificationMultiplexer, create_sse_response};
use crate::backend::BackendRegistry;
use crate::config::StreamingConfig;
use crate::protocol::{ElicitationCreateParams, JsonRpcResponse, RequestId, SamplingCreateMessageParams};
use crate::security::{ToolPolicy, sanitize_json_value, validate_url_not_ssrf};

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
    /// Proxy manager for server-to-client capability forwarding
    pub proxy_manager: Arc<ProxyManager>,
    /// Streaming configuration
    pub streaming_config: StreamingConfig,
    /// Authentication configuration
    pub auth_config: Arc<ResolvedAuthConfig>,
    /// Tool access policy
    pub tool_policy: Arc<ToolPolicy>,
    /// Whether input sanitization is enabled
    pub sanitize_input: bool,
    /// Whether SSRF protection is enabled for outbound URLs
    pub ssrf_protection: bool,
    /// In-flight request tracker for graceful drain.
    /// Each in-flight request holds a permit; shutdown waits for all permits
    /// to be returned.
    pub inflight: Arc<tokio::sync::Semaphore>,
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
///
/// For unauthenticated (public) clients, backend details are redacted
/// to avoid leaking internal topology. Only authenticated admin clients
/// see full backend names and circuit breaker state.
async fn health_handler(
    State(state): State<Arc<AppState>>,
    request: axum::http::Request<axum::body::Body>,
) -> impl IntoResponse {
    let statuses = state.backends.statuses();
    let healthy = statuses.values().all(|s| s.circuit_state != "Open");

    // Check if the caller is an authenticated (non-public) client
    let is_admin = request
        .extensions()
        .get::<AuthenticatedClient>()
        .is_some_and(|c| c.name != "public" && c.name != "anonymous");

    let backends_json = if is_admin {
        // Full details for authenticated clients
        serde_json::to_value(&statuses).unwrap_or(json!({}))
    } else {
        // Redacted: only count and overall health, no names/paths
        json!({
            "count": statuses.len(),
            "all_healthy": healthy
        })
    };

    let response = json!({
        "status": if healthy { "healthy" } else { "degraded" },
        "version": env!("CARGO_PKG_VERSION"),
        "backends": backends_json
    });

    if healthy {
        (StatusCode::OK, Json(response))
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, Json(response))
    }
}

/// Meta-MCP handler (POST /mcp)
#[allow(clippy::too_many_lines)]
async fn meta_mcp_handler(
    State(state): State<Arc<AppState>>,
    http_request: axum::http::Request<axum::body::Body>,
) -> impl IntoResponse {
    // Extract headers and authenticated client from request
    let headers = http_request.headers().clone();
    let client = http_request
        .extensions()
        .get::<AuthenticatedClient>()
        .cloned();

    // Parse JSON body
    let body_bytes = match axum::body::to_bytes(http_request.into_body(), 10 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "jsonrpc": "2.0",
                    "error": {"code": -32700, "message": format!("Failed to read body: {e}")},
                    "id": null
                })),
            )
                .into_response();
        }
    };

    let request: Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "jsonrpc": "2.0",
                    "error": {"code": -32700, "message": format!("Invalid JSON: {e}")},
                    "id": null
                })),
            )
                .into_response();
        }
    };
    // Track in-flight request for graceful drain
    let _inflight_permit = state.inflight.acquire().await;

    if !state.meta_mcp_enabled {
        return (
            StatusCode::FORBIDDEN,
            [(
                axum::http::header::HeaderName::from_static("content-type"),
                axum::http::header::HeaderValue::from_static("application/json"),
            )],
            Json(json!({
                "jsonrpc": "2.0",
                "error": {"code": -32600, "message": "Meta-MCP disabled"},
                "id": null
            })),
        )
            .into_response();
    }

    // Get or create session for this client
    let existing_session_id = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let (session_id, _rx) = state
        .multiplexer
        .get_or_create_session(existing_session_id.as_deref());

    // Optionally sanitize input
    let request = if state.sanitize_input {
        match sanitize_json_value(&request) {
            Ok(sanitized) => sanitized,
            Err(e) => {
                let response = JsonRpcResponse::error(None, -32600, e.to_string());
                let mut resp = Json(serde_json::to_value(response).unwrap()).into_response();
                resp.headers_mut().insert(
                    axum::http::header::HeaderName::from_static("mcp-session-id"),
                    session_id.parse().unwrap(),
                );
                return (StatusCode::BAD_REQUEST, resp).into_response();
            }
        }
    } else {
        request
    };

    // Detect client POST-back responses (has "result" or "error" but no "method").
    // These are replies to server-to-client requests such as `sampling/createMessage`.
    // Must be handled BEFORE `parse_request`, which rejects messages without "method".
    if request.get("method").is_none()
        && (request.get("result").is_some() || request.get("error").is_some())
    {
        if let Some(resp_id) = request.get("id").and_then(|v| v.as_str()) {
            if resp_id.starts_with("sampling-") || resp_id.starts_with("elicitation-") {
                let resolved = state.proxy_manager.resolve_pending(resp_id, request.clone());
                if resolved {
                    debug!(id = %resp_id, "Routed proxy response to caller");
                } else {
                    warn!(id = %resp_id, "No pending request for response");
                }
                let mut resp = Json(json!({})).into_response();
                resp.headers_mut().insert(
                    axum::http::header::HeaderName::from_static("mcp-session-id"),
                    session_id.parse().unwrap(),
                );
                return (StatusCode::ACCEPTED, resp).into_response();
            }
        }
    }

    // Parse request
    let (id, method, params) = match parse_request(&request) {
        Ok(parsed) => parsed,
        Err(response) => {
            let mut resp = Json(serde_json::to_value(response).unwrap()).into_response();
            resp.headers_mut().insert(
                axum::http::header::HeaderName::from_static("mcp-session-id"),
                session_id.parse().unwrap(),
            );
            return (StatusCode::BAD_REQUEST, resp).into_response();
        }
    };

    debug!(method = %method, session_id = %session_id, "Meta-MCP request");

    // Handle notifications (no id) - return 202 Accepted with empty body
    if method.starts_with("notifications/") {
        debug!(notification = %method, "Handling notification");
        let mut resp = Json(json!({})).into_response();
        resp.headers_mut().insert(
            axum::http::header::HeaderName::from_static("mcp-session-id"),
            session_id.parse().unwrap(),
        );
        return (StatusCode::ACCEPTED, resp).into_response();
    }

    // For requests, id is guaranteed to exist (checked in parse_request)
    let id = id.expect("id should exist for non-notification requests");

    // Route to appropriate handler
    let response = match method.as_str() {
        "initialize" => MetaMcp::handle_initialize(id, params.as_ref()),
        "tools/list" => state.meta_mcp.handle_tools_list(id),
        "tools/call" => {
            let (tool_name, arguments) = extract_tools_call_params(params.as_ref());

            // Apply tool policy check and SSRF validation for gateway_invoke calls
            if tool_name == "gateway_invoke" {
                if let Some(ref args) = params {
                    let server = args
                        .get("arguments")
                        .and_then(|a| a.get("server"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let tool = args
                        .get("arguments")
                        .and_then(|a| a.get("tool"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if !server.is_empty() && !tool.is_empty() {
                        // Global policy check
                        if let Err(e) = state.tool_policy.check(server, tool) {
                            let resp = JsonRpcResponse::error(Some(id), -32600, e.to_string());
                            let mut response =
                                Json(serde_json::to_value(resp).unwrap()).into_response();
                            response.headers_mut().insert(
                                axum::http::header::HeaderName::from_static("mcp-session-id"),
                                session_id.parse().unwrap(),
                            );
                            return (StatusCode::FORBIDDEN, response).into_response();
                        }

                        // Per-client tool scope check
                        if let Some(ref c) = client {
                            if let Err(e) = c.check_tool_scope(server, tool) {
                                let resp = JsonRpcResponse::error(Some(id), -32600, e);
                                let mut response =
                                    Json(serde_json::to_value(resp).unwrap()).into_response();
                                response.headers_mut().insert(
                                    axum::http::header::HeaderName::from_static("mcp-session-id"),
                                    session_id.parse().unwrap(),
                                );
                                return (StatusCode::FORBIDDEN, response).into_response();
                            }
                        }
                    }

                    // SSRF protection: validate backend URL before proxying
                    if state.ssrf_protection && !server.is_empty() {
                        if let Some(backend) = state.backends.get(server) {
                            if let Some(url) = backend.transport_url() {
                                if let Err(e) = validate_url_not_ssrf(url) {
                                    let resp =
                                        JsonRpcResponse::error(Some(id), -32600, e.to_string());
                                    let mut response =
                                        Json(serde_json::to_value(resp).unwrap()).into_response();
                                    response.headers_mut().insert(
                                        axum::http::header::HeaderName::from_static(
                                            "mcp-session-id",
                                        ),
                                        session_id.parse().unwrap(),
                                    );
                                    return (StatusCode::FORBIDDEN, response).into_response();
                                }
                            }
                        }
                    }
                }
            }

            state
                .meta_mcp
                .handle_tools_call(id, tool_name, arguments)
                .await
        }
        // Resources
        "resources/list" => {
            state
                .meta_mcp
                .handle_resources_list(id, params.as_ref())
                .await
        }
        "resources/read" => {
            state
                .meta_mcp
                .handle_resources_read(id, params.as_ref())
                .await
        }
        "resources/templates/list" => {
            state
                .meta_mcp
                .handle_resources_templates_list(id, params.as_ref())
                .await
        }
        "resources/subscribe" => {
            state
                .meta_mcp
                .handle_resources_subscribe(id, params.as_ref())
                .await
        }
        "resources/unsubscribe" => {
            state
                .meta_mcp
                .handle_resources_unsubscribe(id, params.as_ref())
                .await
        }

        // Prompts
        "prompts/list" => {
            state
                .meta_mcp
                .handle_prompts_list(id, params.as_ref())
                .await
        }
        "prompts/get" => state.meta_mcp.handle_prompts_get(id, params.as_ref()).await,

        // Logging
        "logging/setLevel" => {
            state
                .meta_mcp
                .handle_logging_set_level(id, params.as_ref())
                .await
        }

        "ping" => JsonRpcResponse::success(id, json!({})),

        "sampling/createMessage" => {
            let Some(sid) = state.proxy_manager.first_session_id() else {
                return build_response(
                    JsonRpcResponse::error(Some(id), -32002, "No sampling-capable client connected"),
                    &session_id,
                    StatusCode::OK,
                );
            };

            let sampling_params = match parse_sampling_params(id.clone(), params, &session_id) {
                Ok(p) => p,
                Err(resp) => return resp,
            };

            let timeout = std::time::Duration::from_secs(120);
            match state
                .proxy_manager
                .forward_sampling_with_response(&sid, &sampling_params, timeout)
                .await
            {
                Ok(result) => JsonRpcResponse::success(id, result),
                Err(e) => JsonRpcResponse::error(Some(id), -32002, e.to_string()),
            }
        }

        "elicitation/create" => {
            let Some(sid) = state.proxy_manager.first_session_id() else {
                return build_response(
                    JsonRpcResponse::error(Some(id), -32002, "No elicitation-capable client connected"),
                    &session_id,
                    StatusCode::OK,
                );
            };

            let elicitation_params: ElicitationCreateParams = match params {
                Some(p) => match serde_json::from_value(p) {
                    Ok(ep) => ep,
                    Err(e) => {
                        return build_response(
                            JsonRpcResponse::error(Some(id), -32602, format!("Invalid elicitation params: {e}")),
                            &session_id,
                            StatusCode::OK,
                        );
                    }
                },
                None => {
                    return build_response(
                        JsonRpcResponse::error(Some(id), -32602, "Missing elicitation params"),
                        &session_id,
                        StatusCode::OK,
                    );
                }
            };

            let timeout = std::time::Duration::from_secs(120);
            match state
                .proxy_manager
                .forward_elicitation_with_response(&sid, &elicitation_params, timeout)
                .await
            {
                Ok(result) => JsonRpcResponse::success(id, result),
                Err(e) => JsonRpcResponse::error(Some(id), -32002, e.to_string()),
            }
        }

        _ => JsonRpcResponse::error(Some(id), -32601, format!("Method not found: {method}")),
    };

    // Return response with session ID header
    let mut resp = Json(serde_json::to_value(response).unwrap()).into_response();
    resp.headers_mut().insert(
        axum::http::header::HeaderName::from_static("mcp-session-id"),
        session_id.parse().unwrap(),
    );
    (StatusCode::OK, resp).into_response()
}

/// Backend handler (POST /mcp/{name})
async fn backend_handler(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    request: axum::http::Request<axum::body::Body>,
) -> impl IntoResponse {
    // Track in-flight request for graceful drain
    let _inflight_permit = state.inflight.acquire().await;

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

/// Build an HTTP response with a `mcp-session-id` header and a given status.
fn build_response(
    rpc: JsonRpcResponse,
    session_id: &str,
    status: StatusCode,
) -> axum::response::Response {
    let mut resp = Json(serde_json::to_value(rpc).unwrap()).into_response();
    resp.headers_mut().insert(
        axum::http::header::HeaderName::from_static("mcp-session-id"),
        session_id.parse().unwrap(),
    );
    (status, resp).into_response()
}

/// Parse `sampling/createMessage` params from raw JSON, returning an early
/// HTTP error response on failure.
#[allow(clippy::result_large_err)] // early-return pattern mirrors existing handlers
fn parse_sampling_params(
    id: RequestId,
    params: Option<Value>,
    session_id: &str,
) -> Result<SamplingCreateMessageParams, axum::response::Response> {
    let Some(p) = params else {
        return Err(build_response(
            JsonRpcResponse::error(Some(id), -32602, "Missing sampling params"),
            session_id,
            StatusCode::BAD_REQUEST,
        ));
    };
    serde_json::from_value(p).map_err(|e| {
        build_response(
            JsonRpcResponse::error(Some(id), -32602, format!("Invalid sampling params: {e}")),
            session_id,
            StatusCode::BAD_REQUEST,
        )
    })
}

/// Extract a `RequestId` from a JSON value.
///
/// Supports string and integer ID values per JSON-RPC 2.0 spec.
/// Returns `None` if the value is not a recognised ID type.
fn extract_request_id(value: &Value) -> Option<RequestId> {
    if value.is_string() {
        Some(RequestId::String(value.as_str().unwrap().to_string()))
    } else if value.is_i64() {
        Some(RequestId::Number(value.as_i64().unwrap()))
    } else if value.is_u64() {
        #[allow(clippy::cast_possible_wrap)]
        Some(RequestId::Number(value.as_u64().unwrap() as i64))
    } else {
        None
    }
}

/// Check whether a method name represents a notification (no response expected).
fn is_notification_method(method: &str) -> bool {
    method.starts_with("notifications/")
}

/// Extract the `tools/call` parameters (tool name and arguments) from request params.
///
/// Returns `("", {})` when the expected fields are absent so callers never
/// need to deal with `Option`.
fn extract_tools_call_params(params: Option<&Value>) -> (&str, Value) {
    let tool_name = params
        .and_then(|p| p.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let arguments = params
        .and_then(|p| p.get("arguments"))
        .cloned()
        .unwrap_or(json!({}));
    (tool_name, arguments)
}

/// Parse JSON-RPC request or notification
/// Returns (Option<RequestId>, method, params) - id is None for notifications
#[allow(clippy::result_large_err)] // JsonRpcResponse used directly as HTTP error body
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
    let id = value.get("id").and_then(extract_request_id);

    // Get method
    let method = value
        .get("method")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcResponse::error(id.clone(), -32600, "Missing method"))?;

    // Get params (optional)
    let params = value.get("params").cloned();

    // For notifications (methods starting with "notifications/"), id is optional
    // For requests, id is required
    if !is_notification_method(method) && id.is_none() {
        return Err(JsonRpcResponse::error(None, -32600, "Missing id"));
    }

    Ok((id, method.to_string(), params))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    // =====================================================================
    // extract_request_id
    // =====================================================================

    #[test]
    fn extract_request_id_string_value() {
        let val = json!("abc-123");
        let id = extract_request_id(&val).unwrap();
        assert_eq!(id, RequestId::String("abc-123".to_string()));
    }

    #[test]
    fn extract_request_id_positive_integer() {
        let val = json!(42);
        let id = extract_request_id(&val).unwrap();
        assert_eq!(id, RequestId::Number(42));
    }

    #[test]
    fn extract_request_id_negative_integer() {
        let val = json!(-1);
        let id = extract_request_id(&val).unwrap();
        assert_eq!(id, RequestId::Number(-1));
    }

    #[test]
    fn extract_request_id_zero() {
        let val = json!(0);
        let id = extract_request_id(&val).unwrap();
        assert_eq!(id, RequestId::Number(0));
    }

    #[test]
    fn extract_request_id_null_returns_none() {
        let val = json!(null);
        assert!(extract_request_id(&val).is_none());
    }

    #[test]
    fn extract_request_id_bool_returns_none() {
        let val = json!(true);
        assert!(extract_request_id(&val).is_none());
    }

    #[test]
    fn extract_request_id_float_returns_none() {
        let val = json!(3.14);
        assert!(extract_request_id(&val).is_none());
    }

    #[test]
    fn extract_request_id_array_returns_none() {
        let val = json!([1, 2]);
        assert!(extract_request_id(&val).is_none());
    }

    #[test]
    fn extract_request_id_object_returns_none() {
        let val = json!({"id": 1});
        assert!(extract_request_id(&val).is_none());
    }

    // =====================================================================
    // is_notification_method
    // =====================================================================

    #[test]
    fn notification_method_recognized() {
        assert!(is_notification_method("notifications/initialized"));
        assert!(is_notification_method("notifications/cancelled"));
        assert!(is_notification_method("notifications/"));
    }

    #[test]
    fn regular_method_not_notification() {
        assert!(!is_notification_method("initialize"));
        assert!(!is_notification_method("tools/list"));
        assert!(!is_notification_method("tools/call"));
        assert!(!is_notification_method("ping"));
        assert!(!is_notification_method(""));
    }

    // =====================================================================
    // extract_tools_call_params
    // =====================================================================

    #[test]
    fn extract_tools_call_params_full() {
        let params = json!({"name": "my_tool", "arguments": {"key": "value"}});
        let (name, args) = extract_tools_call_params(Some(&params));
        assert_eq!(name, "my_tool");
        assert_eq!(args, json!({"key": "value"}));
    }

    #[test]
    fn extract_tools_call_params_missing_name() {
        let params = json!({"arguments": {"key": "value"}});
        let (name, args) = extract_tools_call_params(Some(&params));
        assert_eq!(name, "");
        assert_eq!(args, json!({"key": "value"}));
    }

    #[test]
    fn extract_tools_call_params_missing_arguments() {
        let params = json!({"name": "my_tool"});
        let (name, args) = extract_tools_call_params(Some(&params));
        assert_eq!(name, "my_tool");
        assert_eq!(args, json!({}));
    }

    #[test]
    fn extract_tools_call_params_none_input() {
        let (name, args) = extract_tools_call_params(None);
        assert_eq!(name, "");
        assert_eq!(args, json!({}));
    }

    #[test]
    fn extract_tools_call_params_empty_object() {
        let params = json!({});
        let (name, args) = extract_tools_call_params(Some(&params));
        assert_eq!(name, "");
        assert_eq!(args, json!({}));
    }

    // =====================================================================
    // parse_request - valid requests
    // =====================================================================

    #[test]
    fn parse_request_valid_with_string_id() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": "req-1",
            "method": "tools/list"
        });
        let (id, method, params) = parse_request(&req).unwrap();
        assert_eq!(id, Some(RequestId::String("req-1".to_string())));
        assert_eq!(method, "tools/list");
        assert!(params.is_none());
    }

    #[test]
    fn parse_request_valid_with_numeric_id() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 42,
            "method": "ping"
        });
        let (id, method, params) = parse_request(&req).unwrap();
        assert_eq!(id, Some(RequestId::Number(42)));
        assert_eq!(method, "ping");
        assert!(params.is_none());
    }

    #[test]
    fn parse_request_valid_with_params() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "my_tool", "arguments": {"q": "test"}}
        });
        let (id, method, params) = parse_request(&req).unwrap();
        assert_eq!(id, Some(RequestId::Number(1)));
        assert_eq!(method, "tools/call");
        assert!(params.is_some());
        let p = params.unwrap();
        assert_eq!(p["name"], "my_tool");
    }

    #[test]
    fn parse_request_notification_without_id() {
        let req = json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        });
        let (id, method, _params) = parse_request(&req).unwrap();
        assert!(id.is_none());
        assert_eq!(method, "notifications/initialized");
    }

    #[test]
    fn parse_request_notification_with_id_accepted() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 99,
            "method": "notifications/cancelled"
        });
        let (id, method, _params) = parse_request(&req).unwrap();
        assert_eq!(id, Some(RequestId::Number(99)));
        assert_eq!(method, "notifications/cancelled");
    }

    // =====================================================================
    // parse_request - error cases
    // =====================================================================

    #[test]
    fn parse_request_missing_jsonrpc_field() {
        let req = json!({"id": 1, "method": "ping"});
        let err = parse_request(&req).unwrap_err();
        assert!(err.error.is_some());
        assert_eq!(err.error.as_ref().unwrap().code, -32600);
        assert!(
            err.error
                .as_ref()
                .unwrap()
                .message
                .contains("JSON-RPC version")
        );
    }

    #[test]
    fn parse_request_wrong_jsonrpc_version() {
        let req = json!({"jsonrpc": "1.0", "id": 1, "method": "ping"});
        let err = parse_request(&req).unwrap_err();
        assert_eq!(err.error.as_ref().unwrap().code, -32600);
    }

    #[test]
    fn parse_request_missing_method() {
        let req = json!({"jsonrpc": "2.0", "id": 1});
        let err = parse_request(&req).unwrap_err();
        assert_eq!(err.error.as_ref().unwrap().code, -32600);
        assert!(err.error.as_ref().unwrap().message.contains("method"));
    }

    #[test]
    fn parse_request_non_notification_without_id() {
        let req = json!({"jsonrpc": "2.0", "method": "tools/list"});
        let err = parse_request(&req).unwrap_err();
        assert_eq!(err.error.as_ref().unwrap().code, -32600);
        assert!(err.error.as_ref().unwrap().message.contains("id"));
    }

    #[test]
    fn parse_request_null_jsonrpc() {
        let req = json!({"jsonrpc": null, "id": 1, "method": "ping"});
        let err = parse_request(&req).unwrap_err();
        assert_eq!(err.error.as_ref().unwrap().code, -32600);
    }

    #[test]
    fn parse_request_numeric_jsonrpc() {
        let req = json!({"jsonrpc": 2, "id": 1, "method": "ping"});
        let err = parse_request(&req).unwrap_err();
        assert_eq!(err.error.as_ref().unwrap().code, -32600);
    }

    #[test]
    fn parse_request_method_is_not_string() {
        let req = json!({"jsonrpc": "2.0", "id": 1, "method": 123});
        let err = parse_request(&req).unwrap_err();
        assert_eq!(err.error.as_ref().unwrap().code, -32600);
    }

    #[test]
    fn parse_request_empty_object() {
        let req = json!({});
        let err = parse_request(&req).unwrap_err();
        assert_eq!(err.error.as_ref().unwrap().code, -32600);
    }

    #[test]
    fn parse_request_initialize_method() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": "init-1",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1.0"}
            }
        });
        let (id, method, params) = parse_request(&req).unwrap();
        assert_eq!(id, Some(RequestId::String("init-1".to_string())));
        assert_eq!(method, "initialize");
        assert!(params.is_some());
    }
}
