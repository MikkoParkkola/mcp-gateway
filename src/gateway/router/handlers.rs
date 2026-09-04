// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
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
    RouterAuthorizer, authorize_tool_target, backend_tool_targets_for_call, is_admin_meta_tool,
    refusal_principal, require_admin_tool_access,
};
use super::helpers::{
    attach_session_header, build_accepted_response, build_error_response,
    build_http_error_response, build_http_response, build_response, extract_tools_call_params,
    parse_elicitation_params, parse_request, parse_sampling_params,
};
use crate::gateway::auth::AuthenticatedClient;
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
/// A stable owner key for a session.
///
/// Not the display name: `name` is operator-configured and two API keys may
/// share one, which would let them attach to each other's sessions. The key
/// records whether a credential was actually validated, so an API key named
/// "anonymous" cannot claim the unauthenticated identity's sessions.
fn session_owner(client: Option<&AuthenticatedClient>) -> String {
    client.map_or_else(
        || "unauthenticated:anonymous".to_string(),
        |c| {
            if c.authenticated && !c.principal.is_empty() {
                // A digest of the validated secret. Two API keys configured
                // with the same display name are different principals, and
                // keying on the name would let either attach to the other's
                // sessions.
                format!("credential:{}", c.principal)
            } else {
                format!("unauthenticated:{}", c.name)
            }
        },
    )
}

/// The stable identity of a caller with no session.
///
/// Empty when the caller is unauthenticated: that is not an identity, and the
/// controls that key on this refuse rather than pool every anonymous caller
/// into one bucket.
fn session_owner_key(client: Option<&AuthenticatedClient>) -> String {
    client.map_or_else(String::new, |c| {
        if c.authenticated && !c.principal.is_empty() {
            format!("credential:{}", c.principal)
        } else {
            String::new()
        }
    })
}

/// The stateless path's answer to a protocol version this build cannot serve.
///
/// The client is told which revisions it *could* retry on rather than left to
/// guess. Shared by the POST classifier and the `GET /mcp` era gate so the two
/// cannot drift into giving one client two different answers.
fn unsupported_version_error(
    id: Option<crate::protocol::RequestId>,
    version: &str,
    modern_enabled: bool,
) -> JsonRpcResponse {
    let supported: &[&str] = if modern_enabled {
        crate::protocol::meta::MODERN_VERSIONS
    } else {
        &[]
    };
    JsonRpcResponse::error_with_data(
        id,
        crate::protocol::era::UNSUPPORTED_PROTOCOL_VERSION,
        format!("unsupported protocol version '{version}'"),
        serde_json::json!({ "supportedVersions": supported }),
    )
}

/// The refusal a `GET /mcp` earns from the era it declares, if any.
///
/// `None` means the caller did not declare the 2026 era, and keeps the stream
/// it has always had.
///
/// Every token of every field line is examined, and the first that declares the
/// modern era decides. Two properties fall out of that, and both are the point:
///
/// RFC 9110 lets any intermediary fold two field lines into one comma-separated
/// value, so a caller reaching the modern era through `2025-06-18, 2026-07-28`
/// must be refused on its second token. Reading only the first, or refusing the
/// whole request as a duplicate, would either serve it or break the legacy
/// caller that sends its own version twice -- a path this change does not own.
///
/// Tokenising the raw bytes is what makes the scan honest. A `HeaderValue` may
/// carry `obs-text` (bytes above 0x7F), and `HeaderValue::to_str` refuses the
/// *whole* value when it does; a caller could then hide a modern token behind
/// one high byte and be served the legacy stream. Splitting first and decoding
/// each token separately discards only the token that is actually undecodable.
fn get_era_refusal(state: &AppState, headers: &HeaderMap) -> Option<axum::response::Response> {
    let version = headers
        .get_all("mcp-protocol-version")
        .iter()
        .flat_map(|value| value.as_bytes().split(|byte| *byte == b','))
        .filter_map(|token| std::str::from_utf8(token).ok())
        .map(str::trim)
        // Broader than the served list on purpose: a 2026 revision this build
        // does not serve is still stateless, so it is not a legacy caller.
        // Which refusal it gets is the served list's question, below.
        .find(|token| crate::protocol::meta::declares_modern_era(token))?;

    let modern_enabled = state.live_config.running().server.modern_protocol;
    if modern_enabled && crate::protocol::meta::MODERN_VERSIONS.contains(&version) {
        // The status is the specification's, not a choice: "HTTP GET or DELETE
        // to the MCP endpoint: respond with `405 Method Not Allowed`". RFC 9110
        // then requires a 405 to name the methods that do work, so `Allow`
        // carries POST rather than leaving the caller to guess.
        let mut response = build_http_error_response(
            None,
            crate::error::rpc_codes::INVALID_REQUEST,
            "GET /mcp was removed in MCP 2026-07-28; use subscriptions/listen",
            StatusCode::METHOD_NOT_ALLOWED,
        )
        .into_response();
        response.headers_mut().insert(
            axum::http::header::ALLOW,
            axum::http::HeaderValue::from_static("POST"),
        );
        return Some(response);
    }

    // Naming `subscriptions/listen` here would send the caller to a method that
    // refuses this same version, so it gets the POST path's answer instead.
    Some(
        build_http_response(
            &unsupported_version_error(None, version, modern_enabled),
            StatusCode::BAD_REQUEST,
        )
        .into_response(),
    )
}

pub(super) async fn mcp_sse_handler(
    State(state): State<Arc<AppState>>,
    client: Option<axum::Extension<AuthenticatedClient>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let client = client.map(|axum::Extension(c)| c);

    // Before the streaming and Accept checks, and before any session work: a
    // refusal that ran later would mint a session per refused caller and
    // overwrite the resumption point of whoever owns the id it presented.
    if let Some(refusal) = get_era_refusal(&state, &headers) {
        return refusal;
    }
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

    let (session_id, _rx) = state.multiplexer.get_or_create_session_for(
        existing_session_id.as_deref(),
        // The identity that owns the session. Every caller is "anonymous"
        // when authentication is off, so a single-user gateway behaves
        // exactly as before.
        &session_owner(client.as_ref()),
    );

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

    // Admin is a grant, not a name. Comparing against "public"/"anonymous"
    // gave full backend detail to every authenticated non-admin key the moment
    // an operator removed /health from `auth.public_paths`.
    let is_admin = request
        .extensions()
        .get::<AuthenticatedClient>()
        .is_some_and(|c| c.admin);

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

    // 2026-07-28 removed protocol-level sessions, so a request written against
    // it gets none — and answering it with a session header would hand a
    // stateless client state the revision deleted, and an intermediary a value
    // to route on.
    //
    // Decided from the header, before the body is parsed, because the session
    // is created before the body is parsed. That is sound rather than a
    // shortcut: the mirrored-header check refuses a modern request that omits
    // `MCP-Protocol-Version`, so every modern request that survives carries it.
    // Any modern declaration, not only a version this build serves. A client
    // naming an unsupported 2026 revision is still a stateless client: minting
    // it a session hands it state its own revision deleted and grows a table on
    // behalf of a caller that is about to be refused.
    // Read duplicate-safe, and read ONCE. `headers.get` returns the FIRST
    // value, so a request sending the header twice — legacy first, modern
    // second — would be classified legacy here and modern by the check further
    // down, and the disagreement mints a session for a request that is about to
    // be refused. Two occurrences is not a request to interpret; it is one to
    // refuse, so an ambiguous header takes the modern reading and reaches the
    // refusal with no session behind it.
    let mut version_headers = headers.get_all("mcp-protocol-version").iter();
    let declared_version = match (version_headers.next(), version_headers.next()) {
        (Some(only), None) => only.to_str().ok(),
        (None, _) => None,
        (Some(_), Some(_)) => Some(crate::protocol::meta::MODERN_VERSIONS[0]),
    };
    let declares_modern_by_header =
        declared_version.is_some_and(crate::protocol::meta::declares_modern_era);

    // Get or create session for this client
    let existing_session_id = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let (session_id, session_rx) = if declares_modern_by_header {
        // No session, and none minted. Minting one per request grew a table of
        // sessions nothing could reach, and handed the sequence-anomaly
        // detector a fresh identity every call — a detector that sees a first
        // request every time keeps running and stops protecting.
        (String::new(), None)
    } else {
        let (id, rx) = state.multiplexer.get_or_create_session_for(
            existing_session_id.as_deref(),
            // The identity that owns the session. Every caller is "anonymous"
            // when authentication is off, so a single-user gateway behaves
            // exactly as before.
            &session_owner(client.as_ref()),
        );
        (id, Some(rx))
    };
    // This handler is not a stream reader. Holding the subscription would make
    // a server-to-client prompt look deliverable to a caller with no live SSE
    // stream: the send succeeds into a receiver nobody polls, and the caller
    // waits out the 120-second response timeout instead of being told there is
    // nobody to ask.
    drop(session_rx);

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
            .resolve_pending(resp_id, &session_id, request.clone());
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

    let protocol_header = headers
        .get("mcp-protocol-version")
        .and_then(|value| value.to_str().ok());
    crate::protocol_revision_telemetry::observe_inbound_request(
        &request,
        params.as_ref(),
        &method,
        protocol_header,
        Some(session_id.as_str()),
        crate::protocol_revision_telemetry::Transport::Http,
    );

    // Which protocol generation is this request written against? Decided per
    // request, not per connection: 2026-07-28 removed the handshake precisely so
    // one connection can carry both.
    //
    // The header is read here as well as the body. A request declaring
    // `2026-07-28` in the header an upstream routes on, while carrying no body
    // metadata, would otherwise classify as legacy and pass the feature gate
    // and every mirrored-header check behind it.
    // Read duplicate-safe. `headers.get` returns the FIRST value, so a request
    // sending the header twice — legacy first, modern second — could hide its
    // modern declaration behind the legacy one and be classified legacy, which
    // is the bypass this argument exists to close. Two occurrences is not a
    // request to interpret; it is one to refuse, and the mirrored-header check
    // below refuses it. The value is read once, above the session decision, so
    // the two readings cannot disagree.
    // NFR.OBS.1 is recorded by the classifier itself, so the HTTP and stdio
    // dispatchers cannot drift apart on what a request declared.
    let shape =
        crate::protocol::meta::classify_and_observe(&method, params.as_ref(), declared_version);
    if let crate::protocol::meta::RequestShape::Malformed { ref missing } = shape {
        // Declared itself modern and then omitted a required field. The
        // specification is specific about both halves of the answer: -32602,
        // and 400 on HTTP.
        return build_error_response(
            id,
            -32602,
            format!("missing required request metadata: {}", missing.join(", ")),
            &session_id,
            StatusCode::BAD_REQUEST,
        );
    }
    let is_modern = matches!(shape, crate::protocol::meta::RequestShape::Modern(_));

    // Derived alongside `is_modern` so every shape-derived fact is read once,
    // here, rather than re-classified where the caller context is built. This
    // is not the per-method capability check further down: that one answers
    // "did the client declare the capability THIS method needs" for a method
    // the *client* called; this one is consulted before the gateway asks the
    // *client* for something. Owned rather than borrowed because `shape` is
    // moved by the per-method check below, ~100 lines before the caller context
    // is built.
    let declared_capabilities = shape.declared_capabilities();

    debug!(method = %method, session_id = %session_id, "Meta-MCP request");

    if let crate::protocol::meta::RequestShape::Modern(ref fields) = shape {
        // A version we cannot serve statelessly. The client is told which ones
        // we can, so it can retry on a shared revision rather than guess.
        let modern_enabled = state.live_config.running().server.modern_protocol;
        if !modern_enabled
            || !crate::protocol::meta::MODERN_VERSIONS.contains(&fields.protocol_version.as_str())
        {
            return build_response(
                unsupported_version_error(id.clone(), &fields.protocol_version, modern_enabled),
                &session_id,
                StatusCode::BAD_REQUEST,
            );
        }

        // Header against body, before anything acts on either. The
        // specification's own rationale for this check is a load balancer
        // routing on the header while the server executes on the body — which
        // is this gateway with the check missing.
        //
        // The mirrored field is chosen by the method, never searched for: a
        // `resources/read` executes on `uri`, and validating a `name` it happens
        // to carry would authorise a decoy while reading something else.
        let body_name = crate::protocol::headers::mcp_name_body_field(&method)
            .and_then(|field| params.as_ref().and_then(|p| p.get(field)))
            .and_then(serde_json::Value::as_str);

        // Exactly one occurrence, or none. Two lines of the same header let one
        // intermediary route on the first and another act on the second, and
        // the disagreement between them is the bypass — the same class of
        // defect the body/header check closes, arriving through the header
        // list instead of past it.
        let single_header = |name: &'static str| -> Result<Option<&str>, &'static str> {
            let mut values = headers.get_all(name).iter();
            match (values.next(), values.next()) {
                (Some(only), None) => Ok(only.to_str().ok()),
                (None, _) => Ok(None),
                (Some(_), Some(_)) => Err(name),
            }
        };
        let duplicated = |name: &'static str| {
            build_error_response(
                id.clone(),
                -32020,
                format!("{name} appears more than once"),
                &session_id,
                StatusCode::BAD_REQUEST,
            )
        };
        // Three explicit calls rather than a collected array: the conversion
        // back out of a collection needs a fallback, and the only fallback
        // available here blanks the headers, which passes the check it was
        // meant to run.
        let header_protocol_version = match single_header("mcp-protocol-version") {
            Ok(value) => value,
            Err(name) => return duplicated(name),
        };
        let header_method = match single_header("mcp-method") {
            Ok(value) => value,
            Err(name) => return duplicated(name),
        };
        let header_name = match single_header("mcp-name") {
            Ok(value) => value,
            Err(name) => return duplicated(name),
        };
        let check = crate::protocol::headers::HeaderCheck {
            header_protocol_version,
            body_protocol_version: Some(fields.protocol_version.as_str()),
            header_method,
            body_method: method.as_str(),
            header_name,
            body_name,
        };
        if let Err(mismatch) = check.validate() {
            return build_error_response(
                id.clone(),
                -32020,
                mismatch.to_string(),
                &session_id,
                StatusCode::BAD_REQUEST,
            );
        }

        // A capability the client never declared. Checked before dispatch:
        // a handler that discovers this halfway through has already acted.
        if let Some(capability) = crate::protocol::meta::required_capability(&method)
            && !fields.declares_capability(capability)
        {
            let mut rpc = crate::protocol::JsonRpcResponse::error(
                id.clone(),
                -32021,
                format!("client did not declare the '{capability}' capability"),
            );
            if let Some(ref mut error) = rpc.error {
                error.data = Some(serde_json::json!({
                    "requiredCapabilities": [capability],
                }));
            }
            return build_response(rpc, &session_id, StatusCode::BAD_REQUEST);
        }

        // Methods this revision removed. Refusing them is the difference
        // between claiming the revision and speaking it.
        if crate::protocol::meta::REMOVED_IN_2026_07_28.contains(&method.as_str()) {
            return build_error_response(
                id.clone(),
                -32601,
                format!("method '{method}' was removed in MCP 2026-07-28"),
                &session_id,
                StatusCode::NOT_FOUND,
            );
        }
    }

    // Validated first, answered second. A notification carries no id and gets no
    // response body, but "no body" is not "no checks": returning 202 before the
    // era, version, mirrored-header and removed-method checks ran accepted a
    // malformed or disabled modern notification as though it had been honoured.
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

    if !is_modern && crate::protocol::meta::ADDED_IN_2026_07_28.contains(&method.as_str()) {
        // A 2026 method reached by a 2025 client. Serving it would tell that
        // client the gateway speaks a revision it cannot hold up its end of.
        return build_error_response(
            Some(id.clone()),
            -32601,
            format!("method '{method}' requires MCP 2026-07-28"),
            &session_id,
            StatusCode::NOT_FOUND,
        );
    }

    // Route to appropriate handler
    let response = match method.as_str() {
        "subscriptions/listen" => {
            // The single long-lived stream that replaces the GET endpoint.
            //
            // Returns EARLY with an SSE body rather than falling through to the
            // ordinary response builder: the specification's response to this
            // method is a stream that stays open, and an acknowledgement that
            // closes is a subscription the client waits on forever.
            let Some(request) =
                crate::protocol::subscriptions::ListenRequest::from_params(params.as_ref())
            else {
                // No `notifications` filter at all. An *empty* filter is valid
                // and opens a quiet stream; this is a request that never said
                // what it wanted.
                return build_error_response(
                    Some(id),
                    -32602,
                    "subscriptions/listen requires a 'notifications' filter",
                    &session_id,
                    StatusCode::BAD_REQUEST,
                );
            };

            // The permit IS the admission. A caller may open streams and walk
            // away — the specification says a server must not assume otherwise
            // — so this ceiling is a resource bound, and one checked as a count
            // before subscribing can be raced past by concurrent callers.
            let Some(listener) = state.subscriptions.subscribe() else {
                return build_error_response(
                    Some(id),
                    -32003,
                    "too many open subscriptions",
                    &session_id,
                    StatusCode::SERVICE_UNAVAILABLE,
                );
            };

            // The request's own id, never minted: the specification defines the
            // subscription id as the JSON-RPC id of the listen request, and it
            // is how a client correlates a notification with the subscription
            // that asked for it.
            let subscription =
                crate::protocol::subscriptions::SubscriptionId::of_request(id.clone());
            let acknowledgement = crate::protocol::JsonRpcResponse::success(
                id,
                serde_json::json!({
                    "_meta": {
                        "io.modelcontextprotocol/subscriptionId": subscription.as_value(),
                    },
                }),
            );
            debug!(
                empty = request.is_empty(),
                resources = request.resource_uris().len(),
                "subscriptions/listen opened"
            );

            return crate::gateway::streaming::subscription_stream(
                listener,
                request,
                subscription,
                &acknowledgement,
                state.streaming_config.keep_alive_interval,
            );
        }
        // 2026-07-28 MUST. Deliberately ahead of `initialize`: discovery is what
        // a peer calls when it has no handshake to make.
        "server/discover" => crate::protocol::JsonRpcResponse::success_serialized(
            id,
            state
                .meta_mcp
                .discover_document(state.live_config.running().server.modern_protocol),
        ),
        "initialize" => state.meta_mcp.handle_initialize(
            id,
            params.as_ref(),
            Some(session_id.as_str()),
            header_profile.as_deref(),
        ),
        "tools/list" => {
            // NFR.OBS.2. The inputs that decide this surface, and the
            // cacheScope the response will carry — recorded before the list is
            // built, so the record cannot be written from the answer it exists
            // to check.
            //
            // Inputs, not applied filters. The branching lives behind a file
            // boundary this change does not cross, so a record naming filters
            // that "ran" would be this site's guess about another module's
            // control flow — and it guessed wrong: it named a session profile
            // on every request, including those carrying none. Each field below
            // is read from the value it names, so a reader can check the record
            // against the request rather than against an assumption.
            let query_present = params
                .as_ref()
                .and_then(|p| p.get("query"))
                .and_then(serde_json::Value::as_str)
                .is_some_and(|query| !query.is_empty());
            info!(
                target: "mcp_gateway::observed",
                profile = header_profile.as_deref().unwrap_or("none"),
                code_mode = state.meta_mcp.code_mode_enabled || code_mode_url_active,
                query_present,
                cache_scope = crate::protocol::cacheable::scope_for_method("tools/list").as_str(),
                // A legacy result carries no `cacheScope`, so a record naming
                // one without saying whether it reaches the client would be
                // reporting a field that was never sent.
                cache_scope_advertised = is_modern,
                "tools/list surface inputs and cache scope"
            );
            state.meta_mcp.handle_tools_list_with_url_override(
                id,
                params.as_ref(),
                Some(session_id.as_str()),
                code_mode_url_active,
            )
        }
        "tools/call" => {
            let (tool_name, arguments) = extract_tools_call_params(params.as_ref());

            // A multi-round-trip retry carries `inputResponses` and
            // `requestState` as siblings of `name` and `arguments` (MIK-7212).
            // They are read here and travel to the invoke funnel on the caller
            // context, which is the only scope that can act on them: redeeming
            // the continuation reproduces the digest sealed at mint time, and
            // that digest is over the *backend's* server, tool and argument
            // object. Here `tool_name` is the gateway-facing name and
            // `arguments` the wrapper carrying them, so a binding check
            // attempted at this site would refuse every honest retry.
            //
            // What cannot wait is the malformed shape, refused below before
            // anything dispatches.
            let retry = crate::protocol::mrtr::RetryFields::from_params(params.as_ref());
            if retry.is_malformed() {
                // Neither a usable retry nor a fresh call. Running it as a fresh
                // call would repeat whatever the first attempt already did, and
                // for a destructive tool that is the whole risk.
                return build_error_response(
                    Some(id),
                    -32602,
                    format!("malformed request fields: {}", retry.malformed.join(", ")),
                    &session_id,
                    StatusCode::BAD_REQUEST,
                );
            }
            // Exposure decides before admin does, here as well as in the
            // dispatcher. The dispatcher orders these two correctly for its own
            // callers, and this pre-check runs earlier still, so on the HTTP
            // path an unexposed admin tool used to be answered by an admin
            // refusal -- which confirms the tool exists to exactly the caller
            // the allow-list hides it from, while stdio answered with the
            // unrecognised-tool refusal. Declining to pre-check what we will
            // not confirm leaves the dispatcher the single owner of that
            // refusal instead of asking two sites to word one answer alike.
            if state.meta_mcp.exposes_meta_tool(tool_name)
                && is_admin_meta_tool(tool_name)
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
                    // This gate returns without entering the meta layer, so the
                    // chokepoint's emitter never fires for a shape the router
                    // covers. Both gates call the one helper, or HTTP scope
                    // denials — the ones most worth seeing — go unrecorded.
                    crate::gateway::authz::audit_refusal(
                        crate::gateway::authz::Transport::Http,
                        refusal_principal(
                            client.as_ref(),
                            oauth_agent_identity.as_ref(),
                            cert_identity.as_ref(),
                        )
                        .as_deref(),
                        &target.server,
                        &target.tool,
                        &e.message,
                    );
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
                    // The key the per-caller controls are scored on. A session
                    // when there is one; otherwise the validated credential.
                    //
                    // Never the display name: it is operator-configured, two
                    // API keys may share one, and every unauthenticated caller
                    // presents the same one — so scoring on it lets one caller
                    // poison another's sequence history or trigger its blocks.
                    // Empty means no identity at all, which the firewall
                    // refuses rather than scores.
                    let control_identity = if session_id.is_empty() {
                        session_owner_key(client.as_ref())
                    } else {
                        session_id.clone()
                    };
                    let verdict = fw.check_request(
                        &session_id,
                        target.server,
                        target.tool,
                        target.arguments,
                        caller_name,
                        &control_identity,
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

            // Destructive-action confirmation is decided at the dispatcher,
            // for every transport. What this edge owns is the one fact the
            // dispatcher cannot see: which era the request was written
            // against, and therefore what to do when nobody can be asked.
            // Handed over finished, so the shape is read once, here.
            let confirmation_policy = if is_modern {
                crate::gateway::destructive_confirmation::ConfirmationPolicy::for_modern()
            } else {
                crate::gateway::destructive_confirmation::ConfirmationPolicy::for_legacy()
            };

            // Authorization is handed to the dispatch chokepoint rather than
            // applied here, so the shapes an edge cannot see — a playbook
            // step, whose targets are not in the request — face it too.
            // Constructed concretely rather than taken as a parameter, so the
            // weaker stdio authorizer cannot reach the network path.
            let router_authorizer = RouterAuthorizer {
                state: state.as_ref(),
                client: client.as_ref(),
                oauth_agent_identity: oauth_agent_identity.as_ref(),
                cert_identity: cert_identity.as_ref(),
                principal: refusal_principal(
                    client.as_ref(),
                    oauth_agent_identity.as_ref(),
                    cert_identity.as_ref(),
                ),
            };

            let mut call_response = state
                .meta_mcp
                .handle_tools_call(
                    id,
                    tool_name,
                    arguments,
                    Some(session_id.as_str()),
                    MetaMcpCallerContext {
                        authorizer: &router_authorizer,
                        api_key_name,
                        agent_id,
                        grant_subject,
                        verified_identity: verified_identity.as_ref(),
                        is_admin: client.as_ref().is_some_and(|c| c.admin),
                        input_capabilities: declared_capabilities,
                        retry: &retry,
                        // Always `Elicit`, including when no session was
                        // presented. HTTP can carry an asker; whether one
                        // answered is what `policy` decides. Mapping a
                        // sessionless request to `Unavailable` would refuse the
                        // legacy caller this path deliberately still warns.
                        confirmation:
                            crate::gateway::destructive_confirmation::ConfirmationChannel::Elicit {
                                proxy: &state.proxy_manager,
                                policy: confirmation_policy,
                            },
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

            // To the session that asked, and only that one.
            let timeout = std::time::Duration::from_secs(120);
            match state
                .proxy_manager
                .forward_sampling_with_response(&session_id, &sampling_params, timeout)
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

            // To the session that asked, and only that one.
            let timeout = std::time::Duration::from_secs(120);
            match state
                .proxy_manager
                .forward_elicitation_with_response(&session_id, &elicitation_params, timeout)
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

    // A confirmation refusal is the gate working, not the client
    // misbehaving. It is excluded from BOTH arms, not just the failure one:
    // `record_client_success` resets the consecutive-failure count, so
    // treating a refusal as a success would clear a breaker the caller had
    // genuinely tripped.
    if let Some(ref client) = client
        && !response.confirmation_refusal
    {
        if response.error.is_some() {
            state.auth_config.record_client_failure(&client.name);
        } else {
            state.auth_config.record_client_success(&client.name);
        }
    }

    // A refusal the router gate caught already answered 403 above. A refusal
    // only the dispatch chokepoint can see — a playbook step, whose targets the
    // router never inspects — arrives here as a JSON-RPC error, and answering
    // it 200 tells every caller and intermediary the call succeeded. The status
    // travels on the error precisely so this line can honour it.
    let status = refusal_status(&response).unwrap_or(StatusCode::OK);
    if is_modern {
        // An unimplemented method is 404 on this revision, not 200-with-error.
        // The status is what a client uses to tell "this server does not have
        // that method" from "this is not a modern endpoint at all" — and the
        // JSON-RPC body is what tells it apart from a legacy transport's bare
        // 404. Both halves are needed; neither alone decides it.
        let status = if response
            .error
            .as_ref()
            .is_some_and(|error| error.code == -32601)
        {
            StatusCode::NOT_FOUND
        } else {
            status
        };
        // A stateless client has no handshake in which to learn who answered,
        // so every result says. And it holds no session, so it is sent no
        // session header — the legacy path below keeps both unchanged.
        return build_modern_response(response, status, &method);
    }
    build_response(response, &session_id, status)
}

/// Build a response for a request written against 2026-07-28.
///
/// Two differences from the legacy path, and they are the same difference: the
/// connection carries no state. There is no `Mcp-Session-Id`, because the
/// revision deleted protocol sessions; and the result names the server, because
/// there was no handshake in which to say so.
/// The methods whose results carry `ttlMs` and `cacheScope`.
///
/// Five, from the `CacheableResult` interface. `server/discover` supports
/// caching too, but is not in this list — its document is built elsewhere and
/// the fields are added there when its own scope is decided.
const CACHEABLE_METHODS: &[&str] = &[
    "tools/list",
    "prompts/list",
    "resources/list",
    "resources/read",
    "resources/templates/list",
];

/// How long a client may consider a list fresh. A freshness hint, not a
/// promise: `listChanged` notifications remain the authority on change, and
/// this only stops a client re-listing on every turn.
const LIST_TTL_MS: u64 = 60_000;

fn build_modern_response(
    mut response: crate::protocol::JsonRpcResponse,
    status: StatusCode,
    method: &str,
) -> axum::response::Response {
    if let Some(ref mut result) = response.result
        && let Some(object) = result.as_object_mut()
    {
        // Required on every result in this revision, and supplied here only
        // when the result does not already carry one.
        //
        // Inserting unconditionally overwrote the discriminator that the
        // multi-round-trip path had just set: an `input_required` result was
        // relabelled `complete` on its way out, so a client saw a finished call
        // where the server was waiting for an answer and could no longer supply
        // one. The comment said this value was safe because interim results own
        // their own; the code then overwrote exactly those.
        object
            .entry("resultType")
            .or_insert_with(|| serde_json::Value::String("complete".to_string()));

        if CACHEABLE_METHODS.contains(&method) {
            object.insert("ttlMs".to_string(), serde_json::json!(LIST_TTL_MS));
            // Per method, from the table that records which ones were
            // assessed. Answering with one method's decision for all five
            // would make `resources/read` inherit `tools/list`'s reasoning.
            object.insert(
                "cacheScope".to_string(),
                serde_json::Value::String(
                    crate::protocol::cacheable::scope_for_method(method)
                        .as_str()
                        .to_string(),
                ),
            );
        }
        let meta = object
            .entry("_meta")
            .or_insert_with(|| serde_json::json!({}));
        if let Some(meta) = meta.as_object_mut() {
            meta.insert(
                crate::protocol::meta::KEY_SERVER_INFO.to_string(),
                serde_json::json!({
                    "name": "mcp-gateway",
                    "version": env!("CARGO_PKG_VERSION"),
                }),
            );
        }
    }
    (status, axum::Json(response)).into_response()
}

/// The HTTP status a response deserves when it carries an authorization
/// refusal, or `None` for anything else.
///
/// Reads the status the dispatch layer stamped, rather than inferring one from
/// the JSON-RPC code — see `HTTP_STATUS_DATA_KEY` for why inference is wrong
/// here. An error with no stamp is not a refusal and keeps its own status, so
/// nothing else is reclassified.
pub(super) fn refusal_status(response: &JsonRpcResponse) -> Option<StatusCode> {
    let raw = response
        .error
        .as_ref()?
        .data
        .as_ref()?
        .get(crate::gateway::authz::HTTP_STATUS_DATA_KEY)?
        .as_u64()?;
    StatusCode::from_u16(u16::try_from(raw).ok()?).ok()
}

// ── destructive-confirmation helpers ─────────────────────────────────────────

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
            lifecycle: crate::backend::BackendLifecycle::Running,
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

#[cfg(test)]
mod cacheable_field_tests {
    use super::{CACHEABLE_METHODS, build_modern_response};
    use crate::protocol::{JsonRpcResponse, RequestId};
    use axum::http::StatusCode;

    /// CACHE.1a and CACHE.1b claim both fields on **all five** methods. The
    /// HTTP acceptance test can only reach four of them -- `resources/read`
    /// needs a backend serving a URI, and an error result carries nothing to
    /// decorate. Driving the builder directly covers the fifth, and iterating
    /// the constant rather than a hand-copied list means a sixth method cannot
    /// be added without this test demanding its fields too.
    #[tokio::test]
    async fn every_cacheable_method_gets_both_fields() {
        // "All five" is half the claim; iterating the constant alone would
        // still pass if a method were dropped from it.
        assert_eq!(
            CACHEABLE_METHODS.len(),
            5,
            "the criterion names five methods: {CACHEABLE_METHODS:?}"
        );
        for method in CACHEABLE_METHODS {
            let response = JsonRpcResponse::success(RequestId::Number(1), serde_json::json!({}));
            let built = build_modern_response(response, StatusCode::OK, method);
            let bytes = axum::body::to_bytes(built.into_body(), usize::MAX)
                .await
                .expect("the builder produces a complete in-memory body");
            let body: serde_json::Value =
                serde_json::from_slice(&bytes).expect("the body is JSON-RPC");

            assert!(
                body["result"]["ttlMs"].as_u64().is_some_and(|ttl| ttl > 0),
                "{method} must carry a positive ttlMs: {body}"
            );
            assert!(
                body["result"]["cacheScope"].as_str().is_some(),
                "{method} must carry a cacheScope: {body}"
            );
        }
    }

    /// The mirror: a method outside the list gets neither field. Without this,
    /// a builder that decorated everything would pass the case above.
    #[tokio::test]
    async fn a_non_cacheable_method_gets_neither_field() {
        let response = JsonRpcResponse::success(RequestId::Number(1), serde_json::json!({}));
        let built = build_modern_response(response, StatusCode::OK, "server/discover");
        let bytes = axum::body::to_bytes(built.into_body(), usize::MAX)
            .await
            .expect("the builder produces a complete in-memory body");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("the body is JSON-RPC");

        assert!(body["result"].get("ttlMs").is_none(), "{body}");
        assert!(body["result"].get("cacheScope").is_none(), "{body}");
    }
}
