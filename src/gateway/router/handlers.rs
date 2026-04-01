//! Axum request handlers for the MCP gateway.

use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde_json::{Value, json};
use tracing::{debug, info, warn};

use super::AppState;
use super::helpers::{
    attach_session_header, build_accepted_response, build_error_response,
    build_http_error_response, build_http_response, build_response, extract_tools_call_params,
    parse_elicitation_params, parse_request, parse_sampling_params,
};
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::streaming::create_sse_response;
use crate::mtls::CertIdentity;
use crate::protocol::JsonRpcResponse;
#[cfg(feature = "firewall")]
use crate::security::firewall::FirewallAction;
use crate::security::{sanitize_json_value, validate_url_not_ssrf};

/// GET /mcp handler - SSE stream for server→client notifications
/// Per MCP spec 2025-03-26, servers MAY return SSE stream or 405 Method Not Allowed.
/// We implement the full streaming support.
pub(super) async fn mcp_sse_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Check if streaming is enabled
    if !state.streaming_config.enabled {
        return build_http_error_response(
            None,
            -32600,
            "Streaming not enabled. Use POST to send JSON-RPC requests to /mcp",
            StatusCode::METHOD_NOT_ALLOWED,
        )
        .into_response();
    }

    // Check Accept header - must accept text/event-stream
    let accept = headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !accept.contains("text/event-stream") {
        return build_http_error_response(
            None,
            -32600,
            "Must accept text/event-stream for SSE notifications",
            StatusCode::NOT_ACCEPTABLE,
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
            attach_session_header(response.headers_mut(), &session_id);
            response
        }
        None => build_http_error_response(
            None,
            -32603,
            "Failed to create SSE stream",
            StatusCode::INTERNAL_SERVER_ERROR,
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
    build_http_response(
        JsonRpcResponse::error_with_data(
            None,
            -32600,
            "SSE transport is deprecated. Use Streamable HTTP (POST /mcp) instead.",
            json!({
                "migration": "In settings.json, change: \"type\": \"sse\" -> \"type\": \"http\" and \"url\": \"http://localhost:39400/sse\" -> \"url\": \"http://localhost:39400/mcp\"",
                "spec": "https://modelcontextprotocol.io/specification/2025-03-26/basic/transports#streamable-http"
            }),
        ),
        StatusCode::GONE,
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
    let cert_identity = http_request.extensions().get::<CertIdentity>().cloned();

    // Parse JSON body
    let body_bytes = match axum::body::to_bytes(http_request.into_body(), 10 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(e) => {
            return build_http_error_response(
                None,
                -32700,
                format!("Failed to read body: {e}"),
                StatusCode::BAD_REQUEST,
            )
            .into_response();
        }
    };

    let request: Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(e) => {
            return build_http_error_response(
                None,
                -32700,
                format!("Invalid JSON: {e}"),
                StatusCode::BAD_REQUEST,
            )
            .into_response();
        }
    };
    // Track in-flight request for graceful drain
    let _inflight_permit = state.inflight.acquire().await;

    if !state.meta_mcp_enabled {
        return (
            [(
                axum::http::header::HeaderName::from_static("content-type"),
                axum::http::header::HeaderValue::from_static("application/json"),
            )],
            build_http_error_response(None, -32600, "Meta-MCP disabled", StatusCode::FORBIDDEN),
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
                return build_error_response(
                    None,
                    -32600,
                    e.to_string(),
                    &session_id,
                    StatusCode::BAD_REQUEST,
                );
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
        && let Some(resp_id) = request.get("id").and_then(|v| v.as_str())
        && (resp_id.starts_with("sampling-") || resp_id.starts_with("elicitation-"))
    {
        debug!(id = %resp_id, body = %request, "Received sampling/elicitation response POST-back");
        let resolved = state
            .proxy_manager
            .resolve_pending(resp_id, request.clone());
        if resolved {
            debug!(id = %resp_id, "Routed proxy response to caller");
        } else {
            warn!(id = %resp_id, "No pending request for response");
        }
        return build_accepted_response(&session_id);
    }

    // Parse request
    let (id, method, params) = match parse_request(&request) {
        Ok(parsed) => parsed,
        Err(response) => {
            return build_response(response, &session_id, StatusCode::BAD_REQUEST);
        }
    };

    debug!(method = %method, session_id = %session_id, "Meta-MCP request");

    // Handle notifications (no id) - return 202 Accepted with empty body
    if method.starts_with("notifications/") {
        debug!(notification = %method, "Handling notification");
        return build_accepted_response(&session_id);
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
        "tools/list" => state.meta_mcp.handle_tools_list_with_params(
            id,
            params.as_ref(),
            Some(session_id.as_str()),
        ),
        "tools/call" => {
            let (tool_name, arguments) = extract_tools_call_params(params.as_ref());

            // Apply tool policy check and SSRF validation for gateway_invoke calls
            if tool_name == "gateway_invoke"
                && let Some(ref args) = params
            {
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
                        return build_error_response(
                            Some(id),
                            -32600,
                            e.to_string(),
                            &session_id,
                            StatusCode::FORBIDDEN,
                        );
                    }

                    // mTLS certificate-based policy check (defense-in-depth layer)
                    if !state.mtls_policy.is_empty() {
                        use crate::mtls::PolicyDecision;
                        let decision =
                            state
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
                            return build_error_response(
                                Some(id),
                                -32600,
                                format!(
                                    "Tool '{tool}' on server '{server}' is blocked by \
                                         certificate policy"
                                ),
                                &session_id,
                                StatusCode::FORBIDDEN,
                            );
                        }
                    }

                    // Per-client tool scope check
                    if let Some(ref c) = client
                        && let Err(e) = c.check_tool_scope(server, tool)
                    {
                        return build_error_response(
                            Some(id),
                            -32600,
                            e,
                            &session_id,
                            StatusCode::FORBIDDEN,
                        );
                    }
                }

                // Firewall: pre-invocation request scan
                #[cfg(feature = "firewall")]
                if let Some(ref fw) = state.firewall
                    && !server.is_empty()
                    && !tool.is_empty()
                {
                    let caller_name = client.as_ref().map_or("anonymous", |c| c.name.as_str());
                    let invoke_args = args
                        .get("arguments")
                        .cloned()
                        .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
                    let verdict =
                        fw.check_request(&session_id, server, tool, &invoke_args, caller_name);
                    if verdict.action == FirewallAction::Warn {
                        warn!(
                            server = server,
                            tool = tool,
                            findings = verdict.findings.len(),
                            "Firewall: request warning"
                        );
                    }
                    if !verdict.allowed {
                        let reason = verdict
                            .findings
                            .first()
                            .map_or("Security firewall blocked this request", |f| {
                                f.description.as_str()
                            });
                        return build_error_response(
                            Some(id),
                            -32600,
                            format!("Firewall blocked: {reason}"),
                            &session_id,
                            StatusCode::BAD_REQUEST,
                        );
                    }
                }

                // SSRF protection: validate backend URL before proxying
                if state.ssrf_protection
                    && !server.is_empty()
                    && let Some(backend) = state.backends.get(server)
                    && let Some(url) = backend.transport_url()
                    && let Err(e) = validate_url_not_ssrf(url)
                {
                    return build_error_response(
                        Some(id),
                        -32600,
                        e.to_string(),
                        &session_id,
                        StatusCode::FORBIDDEN,
                    );
                }
            }

            let api_key_name = client.as_ref().map(|c| c.name.as_str());

            // Capture server/tool for post-invoke firewall scan (before borrows move).
            #[cfg(feature = "firewall")]
            let (fw_server, fw_tool, fw_caller) = {
                let srv = params
                    .as_ref()
                    .and_then(|p| p.get("arguments"))
                    .and_then(|a| a.get("server"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let tl = params
                    .as_ref()
                    .and_then(|p| p.get("arguments"))
                    .and_then(|a| a.get("tool"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let cl = client
                    .as_ref()
                    .map_or("anonymous", |c| c.name.as_str())
                    .to_string();
                (srv, tl, cl)
            };

            let mut call_response = state
                .meta_mcp
                .handle_tools_call(
                    id,
                    tool_name,
                    arguments,
                    Some(session_id.as_str()),
                    api_key_name,
                )
                .await;

            // Firewall: post-invocation response scan + credential redaction.
            #[cfg(feature = "firewall")]
            if let Some(ref fw) = state.firewall
                && !fw_server.is_empty()
                && !fw_tool.is_empty()
                && let Some(ref mut result_val) = call_response.result
            {
                let verdict =
                    fw.check_response(&session_id, &fw_server, &fw_tool, result_val, &fw_caller);
                if verdict.action == FirewallAction::Warn {
                    warn!(
                        server = %fw_server,
                        tool = %fw_tool,
                        findings = verdict.findings.len(),
                        "Firewall: response warning"
                    );
                }
            }

            call_response
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
            let elicitation_params = match parse_elicitation_params(id.clone(), params, &session_id)
            {
                Ok(p) => p,
                Err(resp) => return resp,
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

        // SEP-1862: resolve a single tool schema by name (spec-preview feature).
        #[cfg(feature = "spec-preview")]
        "tools/resolve" => {
            state
                .meta_mcp
                .handle_tools_resolve(id, params.as_ref())
                .await
        }

        _ => JsonRpcResponse::error(Some(id), -32601, format!("Method not found: {method}")),
    };

    telemetry_metrics::counter!(
        "mcp_jsonrpc_requests_total",
        "method" => method.clone(),
        "status" => if response.error.is_some() { "error" } else { "ok" }
    )
    .increment(1);

    // Return response with session ID header
    build_response(response, &session_id, StatusCode::OK)
}

/// GET /metrics — Prometheus text exposition format scrape endpoint.
///
/// Exposed without authentication so that Prometheus scrapers can reach it
/// directly.  Returns an empty 200 when the recorder is not installed (e.g.
/// when running without the `metrics` feature or before server startup).
#[cfg(feature = "metrics")]
pub(super) async fn metrics_handler() -> impl IntoResponse {
    use axum::http::{HeaderValue, header};
    let body = crate::metrics::render();
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
        )],
        body,
    )
}
