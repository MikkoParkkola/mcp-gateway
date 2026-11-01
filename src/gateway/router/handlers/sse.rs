// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /mcp`: the legacy server-to-client notification stream, and the
//! refusal a caller declaring the 2026 era gets instead.

use crate::error::rpc_codes::{INTERNAL_ERROR, INVALID_REQUEST};
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
use crate::gateway::meta_mcp::invoke::egress::Egressed;
use crate::gateway::outbound::{OutboundReply, gateway_reply, stream_reply};
use crate::gateway::router::AppState;
use crate::gateway::router::helpers::{
    RpcHttp, attach_session_header, build_http_error_response, build_http_response,
    session_capacity_refusal,
};
use crate::gateway::session_id::SessionId;
use crate::gateway::streaming::{
    InFlightHold, MintKind, SessionCapacity, create_sse_response_with_view,
};
use crate::mtls::CertIdentity;

pub(super) use crate::protocol::modern_refusal::unsupported_version_error;

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
            &Egressed::gateway_own(unsupported_version_error(None, version, modern_enabled)),
            StatusCode::BAD_REQUEST,
        )
        .into_response(),
    )
}

/// Why a GET cannot open a stream at all: streaming is off, or the client does
/// not accept an event stream.
fn stream_request_refusal(state: &AppState, headers: &HeaderMap) -> Option<RpcHttp> {
    if !state.streaming_config.enabled {
        return Some(build_http_error_response(
            None,
            INVALID_REQUEST,
            "Streaming not enabled. Use POST to send JSON-RPC requests to /mcp",
            StatusCode::METHOD_NOT_ALLOWED,
        ));
    }
    let accept = headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    (!accept.contains("text/event-stream")).then(|| {
        build_http_error_response(
            None,
            INVALID_REQUEST,
            "Must accept text/event-stream for SSE notifications",
            StatusCode::NOT_ACCEPTABLE,
        )
    })
}

/// The session a GET streams under, and what holds it. Hardened (row 10):
/// a stream only resumes a session a declaring `initialize` opened. Otherwise
/// a GET is not `initialize`, so a session it mints is provisional and refused
/// at the cap before anything else happens (MIK-8504).
fn open_stream_session(
    state: &AppState,
    existing: Option<&str>,
    owner: &crate::gateway::session_id::SessionOwner,
    credential: Option<crate::gateway::auth::live::HeldCredential>,
) -> Result<(SessionId, Option<InFlightHold>), Box<axum::response::Response>> {
    if crate::gateway::router::hardened_elicitation::is_hardened(state) {
        return state
            .multiplexer
            .resume_session_id_scoped(existing, owner, credential)
            .map(|resumed| (resumed, None))
            .ok_or_else(|| {
                Box::new(crate::gateway::router::hardened_elicitation::refusal().into_response())
            });
    }
    match state.multiplexer.open_request_session_scoped(
        existing,
        owner,
        credential,
        MintKind::ProvisionalStream,
    ) {
        Ok((opened, request_hold)) => Ok((opened, Some(request_hold))),
        Err(SessionCapacity) => Err(Box::new(session_capacity_refusal(None))),
    }
}

/// `body`, holding `hold` until it is dropped: a provisional session is never
/// reaped under an open stream, and the drop starts its idle clock (MIK-8504).
fn held_body(body: axum::body::Body, hold: Option<InFlightHold>) -> axum::body::Body {
    axum::body::Body::from_stream(futures::StreamExt::map(
        body.into_data_stream(),
        move |chunk| {
            let _ = &hold;
            chunk
        },
    ))
}

/// GET /mcp handler - SSE stream for server→client notifications
/// Per MCP spec 2025-03-26, servers MAY return SSE stream or 405 Method Not Allowed.
/// We implement the full streaming support.
pub(in crate::gateway::router) async fn mcp_sse_handler(
    State(state): State<Arc<AppState>>,
    client: Option<axum::Extension<AuthenticatedClient>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
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
    let (admission, owner) =
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
                admission.subject.as_ref(),
                extensions.get::<CertIdentity>(),
                client.as_ref(),
            )
        })
        .filter(|key| !key.is_empty());
    if let Some(refusal) = stream_request_refusal(&state, &headers) {
        return gateway_reply(refusal);
    }

    let held = crate::gateway::auth::live::held_credential(&headers);
    // MIK-8350 L1: the request's own credential is judged before any session
    // effect, so a refused GET has opened, resumed, rekeyed and bound nothing.
    // Opening or resuming installs this same credential on the session.
    let subject = Arc::new(super::super::view_judge::get_view_subject((
        admission.subject,
        admission.source,
        &extensions,
        uri.query(),
    )));
    let judge = super::super::view_judge::OwnedViewJudge::shared(&state);
    let Ok(admitted) = state
        .multiplexer
        .admit_view(&subject, held.as_ref(), judge.as_ref())
        .await
    else {
        return gateway_reply(super::super::view_judge::dead_attach_refusal());
    };

    let existing_session_id = session_id_header(&headers).map(String::from);

    let last_event_id = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let (opened, session_hold) =
        match open_stream_session(&state, existing_session_id.as_deref(), &owner, held) {
            Ok(opened) => opened,
            Err(refusal) => return gateway_reply(*refusal),
        };
    let session_id = opened.expose_secret().to_owned();

    if let Some(key) = read_key {
        state.multiplexer.bind_session_reader(&session_id, key);
    }
    // MIK-8350: what this stream's caller is shown, so the first change after
    // attach is judged against it, baselined against the caller admitted above.
    let view = state
        .multiplexer
        .attach_admitted(&session_id, subject, judge, admitted)
        .await;
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
    match create_sse_response_with_view(
        multiplexer_for_stream,
        session_id.clone(),
        (last_event_id, keep_alive),
        view,
    ) {
        Some(sse) => {
            // Add session ID header to response
            let mut response = sse.into_response();
            attach_session_header(response.headers_mut(), &session_id);
            let response = response.map(|body| held_body(body, session_hold));
            stream_reply(response)
        }
        None => gateway_reply(build_http_error_response(
            None,
            INTERNAL_ERROR,
            "Failed to create SSE stream",
            StatusCode::INTERNAL_SERVER_ERROR,
        )),
    }
}
