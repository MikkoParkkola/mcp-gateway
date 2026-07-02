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
use super::authorization::{
    authorize_tool_target, backend_tool_targets_for_call, is_admin_meta_tool,
    require_admin_tool_access,
};
use super::helpers::{
    attach_session_header, build_accepted_response, build_error_response,
    build_http_error_response, build_http_response, build_response, extract_tools_call_params,
    parse_elicitation_params, parse_request, parse_sampling_params,
};
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::destructive_confirmation::{
    ConfirmationOutcome, is_destructive_meta_tool, require_destructive_confirmation,
};
use crate::gateway::meta_mcp::MetaMcpCallerContext;
use crate::gateway::oauth::AgentIdentity as OAuthAgentIdentity;
use crate::gateway::streaming::create_sse_response;
use crate::identity_grants::GrantSubject;
use crate::key_server::oidc::VerifiedIdentity;
use crate::mtls::CertIdentity;
use crate::protocol::JsonRpcResponse;
#[cfg(feature = "firewall")]
use crate::security::firewall::FirewallAction;
use crate::security::{extract_agent_identity, sanitize_json_value, validate_agent_identity};

const HEADER_GATEWAY_IDENTITY: &str = "x-gateway-identity";
const HEADER_GATEWAY_IDENTITY_AUTHORITY: &str = "x-gateway-identity-authority";
const HEADER_GATEWAY_IDENTITY_LABEL: &str = "x-gateway-identity-label";
const HEADER_GATEWAY_IDENTITY_SUBJECT: &str = "x-gateway-identity-subject";
const HEADER_CF_ACCESS_EMAIL: &str = "cf-access-authenticated-user-email";
const HEADER_CF_ACCESS_USER_ID: &str = "cf-access-authenticated-user-id";
const HEADER_IDENTITY_MAX_LEN: usize = 512;

fn caller_grant_subject(
    verified_identity: Option<&VerifiedIdentity>,
    headers: &HeaderMap,
    trust_identity_headers: bool,
    cert_identity: Option<&CertIdentity>,
    oauth_agent_identity: Option<&OAuthAgentIdentity>,
) -> Option<GrantSubject> {
    verified_identity
        .and_then(grant_subject_from_verified_identity)
        .or_else(|| {
            trust_identity_headers
                .then(|| grant_subject_from_trusted_headers(headers))
                .flatten()
        })
        .or_else(|| cert_identity.and_then(grant_subject_from_cert_identity))
        .or_else(|| oauth_agent_identity.and_then(grant_subject_from_oauth_agent))
}

fn grant_subject_from_verified_identity(identity: &VerifiedIdentity) -> Option<GrantSubject> {
    let subject = trimmed_non_empty(&identity.subject)?;
    let authority = trimmed_non_empty(&identity.issuer).unwrap_or_else(|| "oidc".to_string());
    let label = trimmed_non_empty(&identity.email)
        .or_else(|| identity.name.as_deref().and_then(trimmed_non_empty));

    Some(GrantSubject::new(authority, subject, label))
}

fn grant_subject_from_trusted_headers(headers: &HeaderMap) -> Option<GrantSubject> {
    let explicit_subject = header_text(headers, HEADER_GATEWAY_IDENTITY_SUBJECT)
        .or_else(|| header_text(headers, HEADER_GATEWAY_IDENTITY));
    let cloudflare_subject = header_text(headers, HEADER_CF_ACCESS_USER_ID)
        .or_else(|| header_text(headers, HEADER_CF_ACCESS_EMAIL));

    let subject = explicit_subject.or(cloudflare_subject)?;
    let authority = header_text(headers, HEADER_GATEWAY_IDENTITY_AUTHORITY)
        .unwrap_or_else(|| "trusted_header".to_string());
    let label = header_text(headers, HEADER_GATEWAY_IDENTITY_LABEL)
        .or_else(|| header_text(headers, HEADER_CF_ACCESS_EMAIL));

    Some(GrantSubject::new(authority, subject, label))
}

fn grant_subject_from_cert_identity(identity: &CertIdentity) -> Option<GrantSubject> {
    let subject = identity
        .san_uris
        .first()
        .and_then(|value| trimmed_non_empty(value))
        .or_else(|| identity.common_name.as_deref().and_then(trimmed_non_empty))
        .or_else(|| trimmed_non_empty(&identity.display_name))?;
    let label = trimmed_non_empty(&identity.display_name);

    Some(GrantSubject::new("mtls", subject, label))
}

fn grant_subject_from_oauth_agent(identity: &OAuthAgentIdentity) -> Option<GrantSubject> {
    let subject = trimmed_non_empty(&identity.client_id)?;
    let label = trimmed_non_empty(&identity.agent_name);

    Some(GrantSubject::new("agent_oauth", subject, label))
}

fn header_text(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(trimmed_non_empty)
}

fn trimmed_non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.chars().take(HEADER_IDENTITY_MAX_LEN).collect())
    }
}

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
        &JsonRpcResponse::error_with_data(
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

/// Decide overall gateway health from per-backend status.
///
/// Overall health must reflect more than the circuit breaker. A backend that is
/// timing out under load records consecutive failures and the health tracker
/// flips it unhealthy *before* the breaker trips Open; deriving health from
/// circuit state alone reports "healthy" while backends are silently failing
/// (MIK-5080). A backend is considered healthy only when its breaker is not
/// Open AND the health tracker still considers it live.
fn backends_overall_healthy(
    statuses: &std::collections::HashMap<String, crate::backend::BackendStatus>,
) -> bool {
    statuses
        .values()
        .all(|s| s.circuit_state != "Open" && s.healthy)
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
    // The in-process capability backend is not in the registry; pull its health
    // separately so a degraded capability backend (e.g. upstream timeouts under
    // load) is reflected in `/health` too (MIK-5080).
    let capability_status = state.meta_mcp.get_capabilities().map(|c| c.status());
    let capability_healthy = capability_status.as_ref().is_none_or(|s| s.healthy);
    let healthy = backends_overall_healthy(&statuses) && capability_healthy;

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

    // Capability-backend health surfaced as a sibling field (admin only) so the
    // existing `backends` shape stays backward-compatible.
    let capability_json = if is_admin {
        capability_status
            .as_ref()
            .map(|s| serde_json::to_value(s).unwrap_or(json!({})))
    } else {
        None
    };

    let response = json!({
        "status": if healthy { "healthy" } else { "degraded" },
        "version": env!("CARGO_PKG_VERSION"),
        "backends": backends_json,
        "capability_backend": capability_json
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
    let oauth_agent_identity = http_request
        .extensions()
        .get::<OAuthAgentIdentity>()
        .cloned();
    let verified_identity = http_request.extensions().get::<VerifiedIdentity>().cloned();

    // === OWASP ASI03: per-agent identity extraction ===
    //
    // Extract the caller's agent_id from: X-Agent-ID header, JWT claim, or query param.
    // Enforcement (require_id / known_agents allowlist) is config-gated.
    let bearer_token = http_request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        });
    let query_str = http_request.uri().query();
    let agent_identity = extract_agent_identity(&headers, query_str, bearer_token);

    // Per-connection Code Mode override (issue #146 / RFC-0132).
    // Accepted value: ?codemode=search_and_execute
    // When the static config already enables Code Mode, this is a no-op.
    let code_mode_url_active: bool = query_str.is_some_and(|q| {
        q.split('&')
            .any(|pair| pair == "codemode=search_and_execute")
    });
    if let Err(reason) =
        validate_agent_identity(agent_identity.as_ref(), &state.agent_identity_config)
    {
        return build_http_error_response(None, -32600, reason, StatusCode::FORBIDDEN)
            .into_response();
    }

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
        "tools/list" => state.meta_mcp.handle_tools_list_with_url_override(
            id,
            params.as_ref(),
            Some(session_id.as_str()),
            code_mode_url_active,
        ),
        "tools/call" => {
            let (tool_name, arguments) = extract_tools_call_params(params.as_ref());

            if is_admin_meta_tool(tool_name)
                && let Err(e) = require_admin_tool_access(client.as_ref(), tool_name)
            {
                return build_error_response(Some(id), e.code, e.message, &session_id, e.status);
            }

            let backend_targets =
                backend_tool_targets_for_call(&state.meta_mcp, tool_name, &arguments);
            for target in &backend_targets {
                if let Err(e) = authorize_tool_target(
                    state.as_ref(),
                    client.as_ref(),
                    oauth_agent_identity.as_ref(),
                    cert_identity.as_ref(),
                    target.as_target(),
                ) {
                    return build_error_response(
                        Some(id),
                        e.code,
                        e.message,
                        &session_id,
                        e.status,
                    );
                }

                // Firewall: pre-invocation request scan
                #[cfg(feature = "firewall")]
                if let Some(ref fw) = state.firewall {
                    let target = target.as_target();
                    let caller_name = client.as_ref().map_or("anonymous", |c| c.name.as_str());
                    let verdict = fw.check_request(
                        &session_id,
                        target.server,
                        target.tool,
                        target.arguments,
                        caller_name,
                    );
                    if verdict.action == FirewallAction::Warn {
                        warn!(
                            server = target.server,
                            tool = target.tool,
                            findings = verdict.findings.len(),
                            "Firewall: request warning"
                        );
                    }
                    if !verdict.allowed {
                        // OWASP ASI10 (Rogue Agents): anomaly blocks use -32002;
                        // all other firewall blocks use -32600 (invalid request).
                        let (code, reason) = if verdict.is_anomaly_block() {
                            let desc = verdict.findings.first().map_or(
                                "Anomaly detection triggered: unusual tool sequence blocked",
                                |f| f.description.as_str(),
                            );
                            (-32002_i32, format!("Anomaly detection blocked: {desc}"))
                        } else {
                            let desc = verdict
                                .findings
                                .first()
                                .map_or("Security firewall blocked this request", |f| {
                                    f.description.as_str()
                                });
                            (-32600_i32, format!("Firewall blocked: {desc}"))
                        };
                        return build_error_response(
                            Some(id),
                            code,
                            reason,
                            &session_id,
                            StatusCode::BAD_REQUEST,
                        );
                    }
                }
            }

            let api_key_name = client.as_ref().map(|c| c.name.as_str());
            let agent_id = agent_identity.as_ref().map(|a| a.id.as_str());
            let grant_subject = caller_grant_subject(
                verified_identity.as_ref(),
                &headers,
                state.meta_mcp.trust_caller_identity_headers(),
                cert_identity.as_ref(),
                oauth_agent_identity.as_ref(),
            );

            // OWASP ASI09 — destructive meta-tool confirmation gate.
            //
            // For any meta-tool carrying `destructiveHint: true`, require explicit
            // human confirmation via MCP elicitation before execution proceeds.
            // Non-destructive tools and all backend tool calls skip this check.
            if is_destructive_meta_tool(tool_name) {
                let action_desc = describe_destructive_action(tool_name, params.as_ref());
                let outcome = require_destructive_confirmation(
                    &state.proxy_manager,
                    &session_id,
                    &action_desc,
                )
                .await;
                if outcome == ConfirmationOutcome::Declined {
                    return build_response(
                        JsonRpcResponse::error(
                            Some(id),
                            -32001,
                            format!("Operator declined: {action_desc}"),
                        ),
                        &session_id,
                        StatusCode::OK,
                    );
                }
                // Confirmed or Unsupported → fall through to execute
            }

            let mut call_response = state
                .meta_mcp
                .handle_tools_call(
                    id,
                    tool_name,
                    arguments,
                    Some(session_id.as_str()),
                    MetaMcpCallerContext {
                        api_key_name,
                        agent_id,
                        grant_subject,
                        verified_identity: verified_identity.as_ref(),
                    },
                )
                .await;

            // Firewall: post-invocation response scan + credential redaction.
            #[cfg(feature = "firewall")]
            if let Some(ref fw) = state.firewall
                && let Some(ref mut result_val) = call_response.result
            {
                let caller_name = client.as_ref().map_or("anonymous", |c| c.name.as_str());
                for target in &backend_targets {
                    let target = target.as_target();
                    let verdict = fw.check_response(
                        &session_id,
                        target.server,
                        target.tool,
                        result_val,
                        caller_name,
                    );
                    if verdict.action == FirewallAction::Warn {
                        warn!(
                            server = target.server,
                            tool = target.tool,
                            findings = verdict.findings.len(),
                            "Firewall: response warning"
                        );
                    }
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

    if let Some(ref client) = client {
        if response.error.is_some() {
            state.auth_config.record_client_failure(&client.name);
        } else {
            state.auth_config.record_client_success(&client.name);
        }
    }

    // Return response with session ID header
    build_response(response, &session_id, StatusCode::OK)
}

// ── destructive-confirmation helpers ─────────────────────────────────────────

/// Build a human-readable description of the destructive action for the
/// elicitation message.  Extracts the relevant argument(s) from `params`.
fn describe_destructive_action(tool_name: &str, params: Option<&Value>) -> String {
    match tool_name {
        "gateway_kill_server" => {
            let server = params
                .and_then(|p| p.get("arguments"))
                .and_then(|a| a.get("server"))
                .and_then(Value::as_str)
                .unwrap_or("<unknown>");
            format!("kill server '{server}'")
        }
        other => format!("execute destructive meta-tool '{other}'"),
    }
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

#[cfg(test)]
mod health_predicate_tests {
    use super::backends_overall_healthy;
    use crate::backend::BackendStatus;
    use std::collections::HashMap;

    fn status(name: &str, circuit: &str, healthy: bool) -> BackendStatus {
        BackendStatus {
            name: name.to_string(),
            running: true,
            transport: "http".to_string(),
            tools_cached: 0,
            circuit_state: circuit.to_string(),
            request_count: 0,
            healthy,
            consecutive_failures: if healthy { 0 } else { 3 },
            latency_p95_ms: None,
            runtime: None,
        }
    }

    fn map(items: Vec<BackendStatus>) -> HashMap<String, BackendStatus> {
        items.into_iter().map(|s| (s.name.clone(), s)).collect()
    }

    #[test]
    fn all_healthy_is_healthy() {
        let m = map(vec![
            status("a", "Closed", true),
            status("b", "Closed", true),
        ]);
        assert!(backends_overall_healthy(&m));
    }

    #[test]
    fn open_circuit_is_unhealthy() {
        let m = map(vec![status("a", "Closed", true), status("b", "Open", true)]);
        assert!(!backends_overall_healthy(&m));
    }

    #[test]
    fn tracker_unhealthy_with_closed_circuit_is_unhealthy() {
        // MIK-5080: a backend timing out under load flips the health tracker
        // unhealthy before the circuit breaker trips Open. /health must catch it.
        let m = map(vec![
            status("a", "Closed", true),
            status("b", "Closed", false),
        ]);
        assert!(!backends_overall_healthy(&m));
    }
}

#[cfg(test)]
mod caller_identity_tests {
    use super::*;

    #[test]
    fn trusted_identity_headers_are_ignored_until_enabled() {
        let mut headers = HeaderMap::new();
        headers.insert(HEADER_GATEWAY_IDENTITY, "user-123".parse().unwrap());

        let subject = caller_grant_subject(None, &headers, false, None, None);

        assert!(subject.is_none());
    }

    #[test]
    fn trusted_identity_headers_build_grant_subject_when_enabled() {
        let mut headers = HeaderMap::new();
        headers.insert(HEADER_GATEWAY_IDENTITY_SUBJECT, "user-123".parse().unwrap());
        headers.insert(
            HEADER_GATEWAY_IDENTITY_AUTHORITY,
            "cloudflare_access".parse().unwrap(),
        );
        headers.insert(
            HEADER_GATEWAY_IDENTITY_LABEL,
            "owner@example.com".parse().unwrap(),
        );

        let subject = caller_grant_subject(None, &headers, true, None, None).unwrap();

        assert_eq!(subject.authority, "cloudflare_access");
        assert_eq!(subject.subject, "user-123");
        assert_eq!(subject.label.as_deref(), Some("owner@example.com"));
    }

    #[test]
    fn verified_identity_precedes_trusted_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_GATEWAY_IDENTITY_SUBJECT,
            "spoofed-user".parse().unwrap(),
        );
        let verified = VerifiedIdentity {
            subject: "oidc-subject".to_string(),
            email: "owner@example.com".to_string(),
            name: Some("Owner".to_string()),
            groups: Vec::new(),
            issuer: "https://issuer.example".to_string(),
        };

        let subject = caller_grant_subject(Some(&verified), &headers, true, None, None).unwrap();

        assert_eq!(subject.authority, "https://issuer.example");
        assert_eq!(subject.subject, "oidc-subject");
        assert_eq!(subject.label.as_deref(), Some("owner@example.com"));
    }
}
