// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /mcp`: the legacy server-to-client notification stream, and the
//! refusal a caller declaring the 2026 era gets instead.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use tracing::info;

use super::owner::request_session_owner;
use super::session_id_header;
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::outbound::{OutboundReply, gateway_reply, stream_reply};
use crate::gateway::router::AppState;
use crate::gateway::router::helpers::{
    attach_session_header, build_http_error_response, build_http_response,
};
use crate::gateway::streaming::create_sse_response;
use crate::mtls::CertIdentity;
use crate::protocol::JsonRpcResponse;

/// The stateless path's answer to a protocol version this build cannot serve.
///
/// The client is told which revisions it *could* retry on rather than left to
/// guess. Shared by the POST classifier and the `GET /mcp` era gate so the two
/// cannot drift into giving one client two different answers.
pub(super) fn unsupported_version_error(
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

/// GET /mcp handler - SSE stream for server→client notifications
/// Per MCP spec 2025-03-26, servers MAY return SSE stream or 405 Method Not Allowed.
/// We implement the full streaming support.
pub(in crate::gateway::router) async fn mcp_sse_handler(
    State(state): State<Arc<AppState>>,
    client: Option<axum::Extension<AuthenticatedClient>>,
    headers: HeaderMap,
    extensions: axum::http::Extensions,
) -> OutboundReply {
    let client = client.map(|axum::Extension(c)| c);

    // Before the streaming and Accept checks, and before any session work: a
    // refusal that ran later would mint a session per refused caller and
    // overwrite the resumption point of whoever owns the id it presented.
    if let Some(refusal) = get_era_refusal(&state, &headers) {
        return gateway_reply(refusal);
    }
    // The owner the POST that minted the session used, so a subject resumes
    // its own stream and nobody else's.
    let (subject, owner) =
        match request_session_owner(&state, &headers, &extensions, client.as_ref()).await {
            Ok(resolved) => resolved,
            Err(refusal) => return gateway_reply(refusal),
        };
    // MIN.2: the caller this stream writes to, keyed as on POST (H7, §4.2).
    let read_key = state
        .multiplexer
        .judges_reads()
        .then(|| {
            crate::gateway::router::identity::caller_key(
                subject.as_ref(),
                extensions.get::<CertIdentity>(),
                client.as_ref(),
            )
        })
        .filter(|key| !key.is_empty());
    // Check if streaming is enabled
    if !state.streaming_config.enabled {
        return gateway_reply(build_http_error_response(
            None,
            -32600,
            "Streaming not enabled. Use POST to send JSON-RPC requests to /mcp",
            StatusCode::METHOD_NOT_ALLOWED,
        ));
    }

    // Check Accept header - must accept text/event-stream
    let accept = headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !accept.contains("text/event-stream") {
        return gateway_reply(build_http_error_response(
            None,
            -32600,
            "Must accept text/event-stream for SSE notifications",
            StatusCode::NOT_ACCEPTABLE,
        ));
    }

    let existing_session_id = session_id_header(&headers).map(String::from);

    let last_event_id = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let held = crate::gateway::auth::live::held_credential(&headers);
    let opened = if crate::gateway::router::hardened_elicitation::is_hardened(&state) {
        // Hardened (row 10): a stream only resumes a session a declaring
        // `initialize` opened; it never opens one.
        match state.multiplexer.resume_session_id_scoped(
            existing_session_id.as_deref(),
            &owner,
            held,
        ) {
            Some(resumed) => resumed,
            None => return gateway_reply(crate::gateway::router::hardened_elicitation::refusal()),
        }
    } else {
        state.multiplexer.get_or_create_session_id_scoped(
            existing_session_id.as_deref(),
            &owner,
            held,
        )
    };
    let session_id = opened.expose_secret().to_owned();

    if let Some(key) = read_key {
        state.multiplexer.bind_session_reader(&session_id, key);
    }
    // Read before the macro so its count is graded (MIK-7725).
    let session = opened.fp();
    info!(session_id = %session, "Client connected to SSE stream");

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
            stream_reply(response)
        }
        None => gateway_reply(build_http_error_response(
            None,
            -32603,
            "Failed to create SSE stream",
            StatusCode::INTERNAL_SERVER_ERROR,
        )),
    }
}
