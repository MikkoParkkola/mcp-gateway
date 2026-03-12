//! Axum request handlers for the MCP gateway.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde_json::{Value, json};
use tracing::{debug, error, info, warn};

use super::AppState;
use super::helpers::{
    build_response, extract_tools_call_params, parse_request, parse_sampling_params,
};
use crate::mtls::CertIdentity;
use crate::protocol::{ElicitationCreateParams, JsonRpcResponse, RequestId};
use crate::security::{sanitize_json_value, validate_tool_name, validate_url_not_ssrf};
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::streaming::create_sse_response;

/// GET /mcp handler - SSE stream for server→client notifications
/// Per MCP spec 2025-03-26, servers MAY return SSE stream or 405 Method Not Allowed.
/// We implement the full streaming support.
pub(super) async fn mcp_sse_handler(
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
pub(super) async fn mcp_delete_handler(
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
pub(super) async fn sse_deprecated_handler() -> impl IntoResponse {
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
pub(super) async fn health_handler(
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
pub(super) async fn meta_mcp_handler(
    State(state): State<Arc<AppState>>,
    http_request: axum::http::Request<axum::body::Body>,
) -> impl IntoResponse {
    // Extract headers and authenticated client from request
    let headers = http_request.headers().clone();
    let client = http_request
        .extensions()
        .get::<AuthenticatedClient>()
        .cloned();
    // Extract mTLS certificate identity (present when mTLS is active and a valid
    // client certificate was presented during the TLS handshake).
    let cert_identity = http_request
        .extensions()
        .get::<CertIdentity>()
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
                debug!(id = %resp_id, body = %request, "Received sampling/elicitation response POST-back");
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

    // Extract optional profile hint from X-MCP-Profile header (used at initialize time).
    let header_profile: Option<String> = headers
        .get("x-mcp-profile")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    // Route to appropriate handler
    let response = match method.as_str() {
        "initialize" => state.meta_mcp.handle_initialize(
            id,
            params.as_ref(),
            Some(session_id.as_str()),
            header_profile.as_deref(),
        ),
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

                        // mTLS certificate-based policy check (defense-in-depth layer)
                        if !state.mtls_policy.is_empty() {
                            use crate::mtls::PolicyDecision;
                            let decision = state
                                .mtls_policy
                                .evaluate(cert_identity.as_ref(), server, tool);
                            if decision == PolicyDecision::Deny {
                                let identity_label = cert_identity
                                    .as_ref()
                                    .map_or("<unauthenticated>", |id| id.display_name.as_str());
                                warn!(
                                    server = server,
                                    tool = tool,
                                    identity = identity_label,
                                    "Tool invocation denied by mTLS policy"
                                );
                                let resp = JsonRpcResponse::error(
                                    Some(id),
                                    -32600,
                                    format!(
                                        "Tool '{tool}' on server '{server}' is blocked by \
                                         certificate policy"
                                    ),
                                );
                                let mut response =
                                    Json(serde_json::to_value(resp).unwrap()).into_response();
                                response.headers_mut().insert(
                                    axum::http::header::HeaderName::from_static("mcp-session-id"),
                                    session_id.parse().unwrap(),
                                );
                                return (StatusCode::FORBIDDEN, response).into_response();
                            }
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

            let api_key_name = client.as_ref().map(|c| c.name.as_str());
            state
                .meta_mcp
                .handle_tools_call(id, tool_name, arguments, Some(session_id.as_str()), api_key_name)
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
            let sampling_params = match parse_sampling_params(id.clone(), params, &session_id) {
                Ok(p) => p,
                Err(resp) => return resp,
            };

            // Broadcast to all sessions — first responder wins.
            let timeout = std::time::Duration::from_secs(120);
            match state
                .proxy_manager
                .forward_sampling_with_response("broadcast", &sampling_params, timeout)
                .await
            {
                Ok(result) => JsonRpcResponse::success(id, result),
                Err(e) => JsonRpcResponse::error(Some(id), -32002, e.to_string()),
            }
        }

        "elicitation/create" => {
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

            // Broadcast to all sessions — first responder wins.
            let timeout = std::time::Duration::from_secs(120);
            match state
                .proxy_manager
                .forward_elicitation_with_response("broadcast", &elicitation_params, timeout)
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

    // SECURITY: apply tool policy, name validation, and input sanitization to
    // tools/call requests unless the backend explicitly opts into pass-through
    // mode (passthrough: true in config — only for fully-trusted internals).
    if method == "tools/call" && !backend.passthrough() {
        match apply_backend_tool_call_security(&state, &name, params.as_ref(), &id) {
            Some(Ok(sanitized_params)) => {
                // Forward the sanitized params to the backend
                return match backend.request(&method, Some(sanitized_params)).await {
                    Ok(response) => (StatusCode::OK, Json(serde_json::to_value(response).unwrap())),
                    Err(e) => {
                        error!(backend = %name, error = %e, "Backend request failed");
                        let response = JsonRpcResponse::error(Some(id), e.to_rpc_code(), e.to_string());
                        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::to_value(response).unwrap()))
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
