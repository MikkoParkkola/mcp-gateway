// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! build_mcp_headers: the header builder and the close headers.

use super::*;

// =========================================================================
// build_mcp_headers — regression tests for the header builder
//
// These tests verify the behavioral asymmetries across SSE, send_request,
// notify, and close modes are preserved by the shared helper. No network
// calls are made unless the test explicitly exercises close() end to end.
// =========================================================================

/// SSE mode: no Content-Type, SSE-only Accept, no session header even when
/// session is set, custom headers included, no x-trace-id.
#[tokio::test]
async fn build_headers_sse_mode_baseline() {
    let mut custom = HashMap::new();
    custom.insert("X-Auth-Token".to_string(), "secret".to_string());
    let t = make_transport_with_headers("http://localhost", custom);
    // Pretend a session was established — SSE must NOT forward it.
    set_default_session(&t, "should-not-appear");

    let map = t.build_mcp_headers(HeaderMode::Sse, None).await.unwrap();

    assert!(
        !map.contains_key(header::CONTENT_TYPE),
        "SSE must not set Content-Type"
    );
    assert_eq!(
        map[header::ACCEPT],
        "text/event-stream",
        "SSE Accept must be text/event-stream only"
    );
    assert!(
        map.contains_key("mcp-protocol-version"),
        "protocol version header must be present"
    );
    assert!(
        !map.contains_key("mcp-session-id"),
        "SSE must not include session header"
    );
    assert!(
        map.contains_key("x-auth-token"),
        "SSE must include custom headers"
    );
    assert!(
        !map.contains_key("x-trace-id"),
        "SSE must not include trace header"
    );
}

/// `send_request` mode: Content-Type + combined Accept, session forwarded when
/// present, custom headers included, x-trace-id from ambient trace context.
#[tokio::test]
async fn build_headers_send_request_with_session_and_trace() {
    use crate::gateway::trace;

    let mut custom = HashMap::new();
    custom.insert("X-Custom".to_string(), "val".to_string());
    let t = make_transport_with_headers("http://localhost", custom);
    set_default_session(&t, "sess-abc");

    let map = trace::with_trace_id("gw-trace-123".to_string(), async {
        t.build_mcp_headers(
            HeaderMode::Request {
                method: "tools/list",
            },
            None,
        )
        .await
        .unwrap()
    })
    .await;

    assert_eq!(map[header::CONTENT_TYPE], "application/json");
    assert_eq!(map[header::ACCEPT], "application/json, text/event-stream");
    assert_eq!(
        map["mcp-session-id"], "sess-abc",
        "session header must be forwarded"
    );
    assert!(
        map.contains_key("x-custom"),
        "send_request must include custom headers"
    );
    assert_eq!(
        map["x-trace-id"], "gw-trace-123",
        "trace header must be propagated"
    );
}

/// `send_request` mode without a session: no mcp-session-id header at all.
#[tokio::test]
async fn build_headers_send_request_no_session() {
    let t = make_transport("http://localhost");

    let map = t
        .build_mcp_headers(
            HeaderMode::Request {
                method: "tools/list",
            },
            None,
        )
        .await
        .unwrap();

    assert!(
        !map.contains_key("mcp-session-id"),
        "no session must produce no session header"
    );
    assert!(
        !map.contains_key("x-trace-id"),
        "no ambient trace must produce no trace header"
    );
}

/// notify mode: Content-Type + combined Accept, session and custom headers
/// forwarded, NO x-trace-id even when ambient trace exists.
#[tokio::test]
async fn build_headers_notify_includes_custom_but_excludes_trace() {
    use crate::gateway::trace;

    let mut custom = HashMap::new();
    custom.insert("X-Notify-Auth".to_string(), "notify-token".to_string());
    let t = make_transport_with_headers("http://localhost", custom);
    set_default_session(&t, "notify-sess");

    let map = trace::with_trace_id("gw-trace-xyz".to_string(), async {
        t.build_mcp_headers(HeaderMode::Notify, None).await.unwrap()
    })
    .await;

    assert_eq!(map[header::CONTENT_TYPE], "application/json");
    assert_eq!(map[header::ACCEPT], "application/json, text/event-stream");
    assert_eq!(
        map["mcp-session-id"], "notify-sess",
        "notify must include session header"
    );
    assert_eq!(
        map["x-notify-auth"], "notify-token",
        "notify must include custom headers"
    );
    assert!(
        !map.contains_key("x-trace-id"),
        "notify must NOT include trace header"
    );
}

/// notify mode without session: no mcp-session-id header.
#[tokio::test]
async fn build_headers_notify_no_session_when_unset() {
    let t = make_transport("http://localhost");

    let map = t.build_mcp_headers(HeaderMode::Notify, None).await.unwrap();

    assert!(!map.contains_key("mcp-session-id"));
}

/// close mode: session + protocol + custom headers, but no trace header and no
/// JSON body content type.
#[tokio::test]
async fn build_headers_close_includes_session_and_custom_headers() {
    use crate::gateway::trace;

    let mut custom = HashMap::new();
    custom.insert("X-Close-Auth".to_string(), "close-token".to_string());
    let t = make_transport_with_headers("http://localhost", custom);
    set_default_session(&t, "close-sess");

    let map = trace::with_trace_id("gw-close-trace".to_string(), async {
        t.build_mcp_headers(HeaderMode::Close, None).await.unwrap()
    })
    .await;

    assert!(
        !map.contains_key(header::CONTENT_TYPE),
        "close must not set Content-Type without a body"
    );
    assert_eq!(map[header::ACCEPT], "application/json, text/event-stream");
    assert_eq!(map["mcp-session-id"], "close-sess");
    assert_eq!(map["x-close-auth"], "close-token");
    assert_eq!(map["mcp-protocol-version"], PROTOCOL_VERSION);
    assert!(
        !map.contains_key("x-trace-id"),
        "close must not include trace header"
    );
}

/// `close()` should send the same close-mode headers on the DELETE wire path.
#[tokio::test]
async fn close_sends_shared_close_headers() {
    use axum::{
        Router,
        extract::State,
        http::{HeaderMap, StatusCode},
        routing::delete,
    };
    use tokio::sync::{Mutex, oneshot};

    async fn capture_close_headers(
        State(sender): State<Arc<Mutex<Option<oneshot::Sender<HeaderMap>>>>>,
        headers: HeaderMap,
    ) -> StatusCode {
        if let Some(sender) = sender.lock().await.take() {
            let _ = sender.send(headers);
        }
        StatusCode::NO_CONTENT
    }

    let (tx, rx) = oneshot::channel();
    let state = Arc::new(Mutex::new(Some(tx)));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/messages", delete(capture_close_headers))
        .with_state(state);
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let mut custom = HashMap::new();
    custom.insert("X-Close-Auth".to_string(), "close-token".to_string());
    let transport = make_transport_with_headers(&format!("http://{addr}/mcp"), custom);
    *transport.message_url.write() = Some(format!("http://{addr}/messages"));
    set_default_session(&transport, "close-session");

    transport.close().await.unwrap();

    let headers = tokio::time::timeout(Duration::from_secs(10), rx)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(headers["mcp-session-id"], "close-session");
    assert_eq!(headers["mcp-protocol-version"], PROTOCOL_VERSION);
    assert_eq!(headers["x-close-auth"], "close-token");
    assert_eq!(
        headers[header::ACCEPT],
        "application/json, text/event-stream"
    );
    assert!(
        !headers.contains_key(header::CONTENT_TYPE),
        "close must not send a JSON content type without a body"
    );
    assert!(!headers.contains_key("x-trace-id"));

    server.abort();
}

/// Protocol version override is honoured by the helper.
#[tokio::test]
async fn build_headers_uses_overridden_protocol_version() {
    let t = HttpTransport::new_with_oauth(
        "http://localhost",
        HashMap::new(),
        Duration::from_secs(5),
        true,
        None,
        Some("2024-11-05".to_string()),
    )
    .unwrap();

    let map = t.build_mcp_headers(HeaderMode::Sse, None).await.unwrap();

    assert_eq!(map["mcp-protocol-version"], "2024-11-05");
}

/// Only request mode emits `x-trace-id`; notify mode suppresses it.
#[tokio::test]
async fn build_headers_trace_flag_gates_trace_header() {
    use crate::gateway::trace;

    let t = make_transport("http://localhost");

    // Notify mode must suppress trace propagation even when ambient trace exists.
    let map_no_trace = trace::with_trace_id("gw-abc".to_string(), async {
        t.build_mcp_headers(HeaderMode::Notify, None).await.unwrap()
    })
    .await;

    assert!(
        !map_no_trace.contains_key("x-trace-id"),
        "trace:false must suppress x-trace-id"
    );

    // Request mode must include trace propagation when ambient trace exists.
    let map_with_trace = trace::with_trace_id("gw-abc".to_string(), async {
        t.build_mcp_headers(HeaderMode::Request { method: "m" }, None)
            .await
            .unwrap()
    })
    .await;

    assert_eq!(
        map_with_trace["x-trace-id"], "gw-abc",
        "trace:true must emit x-trace-id"
    );
}
