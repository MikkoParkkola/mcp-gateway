use super::*;
use std::collections::HashMap;
use std::time::Duration;

/// Helper: create an `HttpTransport` for testing (streamable HTTP mode, no OAuth)
fn make_transport(url: &str) -> Arc<HttpTransport> {
    HttpTransport::new(url, HashMap::new(), Duration::from_secs(30), true).unwrap()
}

fn make_transport_sse(url: &str) -> Arc<HttpTransport> {
    HttpTransport::new(url, HashMap::new(), Duration::from_secs(30), false).unwrap()
}

fn make_transport_with_headers(url: &str, hdrs: HashMap<String, String>) -> Arc<HttpTransport> {
    HttpTransport::new(url, hdrs, Duration::from_secs(30), true).unwrap()
}

/// Set the shared default-bucket (no-identity) session id, mirroring the
/// pre-MIK-6784 single-session behavior these tests were written against.
fn set_default_session(t: &HttpTransport, id: &str) {
    t.sessions.write().insert(String::new(), id.to_string());
}

/// Read the shared default-bucket session id, if any.
fn default_session(t: &HttpTransport) -> Option<String> {
    t.sessions.read().get("").cloned()
}

// =========================================================================
// Construction
// =========================================================================

#[test]
fn new_creates_transport_with_defaults() {
    let t = make_transport("http://localhost:8080/mcp");
    assert_eq!(t.base_url, "http://localhost:8080/mcp");
    assert!(t.streamable_http);
    assert!(!t.is_connected());
    assert!(t.message_url.read().is_none());
    assert!(default_session(&t).is_none());
    assert!(t.oauth_client.is_none());
}

#[test]
fn new_with_custom_headers() {
    let mut headers = HashMap::new();
    headers.insert("X-Custom".to_string(), "value".to_string());
    let t = HttpTransport::new(
        "http://localhost:8080",
        headers,
        Duration::from_secs(5),
        false,
    )
    .unwrap();
    assert_eq!(t.headers.get("X-Custom").unwrap(), "value");
    assert!(!t.streamable_http);
}

#[test]
fn new_with_oauth_and_protocol_version() {
    let t = HttpTransport::new_with_oauth(
        "http://localhost:8080",
        HashMap::new(),
        Duration::from_secs(30),
        true,
        None,
        Some("2024-11-05".to_string()),
    )
    .unwrap();
    assert_eq!(*t.protocol_version.read(), Some("2024-11-05".to_string()));
}

// =========================================================================
// parse_supported_versions
// =========================================================================

// Version parsing tests moved to protocol::negotiate module.
// These tests verify HttpTransport delegates correctly.

#[test]
fn parse_supported_versions_from_paren_format() {
    use crate::protocol::parse_supported_versions_from_error;
    let msg = "Bad Request: Unsupported protocol version (supported versions: 2025-06-18, 2025-03-26, 2024-11-05)";
    let versions = parse_supported_versions_from_error(msg).unwrap();
    assert_eq!(versions, vec!["2025-06-18", "2025-03-26", "2024-11-05"]);
}

#[test]
fn parse_supported_versions_from_supported_colon() {
    use crate::protocol::parse_supported_versions_from_error;
    let msg = "Supported: 2024-11-05, 2024-10-07";
    let versions = parse_supported_versions_from_error(msg).unwrap();
    assert_eq!(versions, vec!["2024-11-05", "2024-10-07"]);
}

#[test]
fn parse_supported_versions_case_insensitive() {
    use crate::protocol::parse_supported_versions_from_error;
    let msg = "SUPPORTED VERSIONS: 2025-03-26";
    let versions = parse_supported_versions_from_error(msg).unwrap();
    assert_eq!(versions, vec!["2025-03-26"]);
}

#[test]
fn parse_supported_versions_returns_none_for_no_match() {
    use crate::protocol::parse_supported_versions_from_error;
    let msg = "Some random error message without versions";
    assert!(parse_supported_versions_from_error(msg).is_none());
}

#[test]
fn parse_supported_versions_empty_after_colon() {
    use crate::protocol::parse_supported_versions_from_error;
    let msg = "supported versions:)";
    // After colon there's ")" which yields an empty string before it
    assert!(parse_supported_versions_from_error(msg).is_none());
}

// =========================================================================
// resolve_message_url
// =========================================================================

#[test]
fn resolve_message_url_absolute_http() {
    let t = make_transport("http://localhost:8080/sse");
    let result = t.resolve_message_url("http://other:9090/messages").unwrap();
    assert_eq!(result, "http://other:9090/messages");
}

#[test]
fn resolve_message_url_absolute_https() {
    let t = make_transport("https://api.example.com/sse");
    let result = t
        .resolve_message_url("https://api.example.com/messages?session_id=abc")
        .unwrap();
    assert_eq!(result, "https://api.example.com/messages?session_id=abc");
}

#[test]
fn resolve_message_url_relative_path() {
    let t = make_transport_sse("http://localhost:8080/sse");
    let result = t.resolve_message_url("/messages?session_id=123").unwrap();
    assert_eq!(result, "http://localhost:8080/messages?session_id=123");
}

#[test]
fn resolve_message_url_relative_sibling() {
    let t = make_transport_sse("http://localhost:8080/api/sse");
    let result = t.resolve_message_url("messages").unwrap();
    assert_eq!(result, "http://localhost:8080/api/messages");
}

// =========================================================================
// get_message_url
// =========================================================================

#[test]
fn get_message_url_returns_base_when_not_set() {
    let t = make_transport("http://localhost:8080/mcp");
    assert_eq!(t.get_message_url(), "http://localhost:8080/mcp");
}

#[test]
fn get_message_url_returns_set_url() {
    let t = make_transport("http://localhost:8080/mcp");
    *t.message_url.write() = Some("http://localhost:8080/messages".to_string());
    assert_eq!(t.get_message_url(), "http://localhost:8080/messages");
}

// =========================================================================
// next_id
// =========================================================================

#[test]
fn next_id_increments() {
    let t = make_transport("http://localhost");
    let id1 = t.next_id();
    let id2 = t.next_id();
    let id3 = t.next_id();
    assert_eq!(id1, RequestId::Number(1));
    assert_eq!(id2, RequestId::Number(2));
    assert_eq!(id3, RequestId::Number(3));
}

// =========================================================================
// is_connected / connected state
// =========================================================================

#[test]
fn initially_not_connected() {
    let t = make_transport("http://localhost");
    assert!(!t.is_connected());
}

#[test]
fn connected_state_toggles() {
    let t = make_transport("http://localhost");
    assert!(!t.is_connected());
    t.connected.store(true, Ordering::Relaxed);
    assert!(t.is_connected());
    t.connected.store(false, Ordering::Relaxed);
    assert!(!t.is_connected());
}

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

    let headers = tokio::time::timeout(Duration::from_secs(1), rx)
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

// =========================================================================
// Session expiry → re-initialize → retry (MIK-5982)
// =========================================================================

/// When the backend daemon restarts, the stored session ID is dead and the
/// backend answers `-32015 Session not found`. The transport must drop the
/// session, re-run the initialize handshake, and retry the original request
/// once. Regression test for the 2026-06-11 incident (hebb unreachable 6.5h
/// behind a permanently re-opening circuit breaker).
#[tokio::test]
async fn request_reinitializes_session_and_retries_on_session_not_found() {
    use axum::{
        Json, Router,
        extract::State,
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
        routing::post,
    };
    use serde_json::json;

    const FRESH_SESSION: &str = "fresh-session-after-restart";

    async fn mcp_handler(
        State(hits): State<Arc<std::sync::atomic::AtomicU32>>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> axum::response::Response {
        hits.fetch_add(1, Ordering::Relaxed);
        let session = headers
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let method = body["method"].as_str().unwrap_or("");

        // Notifications (no id) are acknowledged unconditionally.
        if body.get("id").is_none() {
            return StatusCode::ACCEPTED.into_response();
        }

        if method == "initialize" {
            // Restarted daemon: hands out a fresh session on initialize.
            let mut resp_headers = HeaderMap::new();
            resp_headers.insert("mcp-session-id", FRESH_SESSION.parse().unwrap());
            return (
                StatusCode::OK,
                resp_headers,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "result": {
                        "protocolVersion": PROTOCOL_VERSION,
                        "capabilities": {},
                        "serverInfo": {"name": "mock", "version": "0"}
                    }
                })),
            )
                .into_response();
        }

        if session == FRESH_SESSION {
            // Post-restart session: requests succeed.
            (
                StatusCode::OK,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "result": {"ok": true}
                })),
            )
                .into_response()
        } else {
            // Stale (pre-restart) session: the rust-mcp-sdk signature.
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "code": -32015,
                    "data": null,
                    "message": "Bad Request: Session not found"
                })),
            )
                .into_response()
        }
    }

    // GIVEN: a mock backend that rejects the stale session
    let hits = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/mcp", post(mcp_handler))
        .with_state(Arc::clone(&hits));
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let transport = make_transport(&format!("http://{addr}/mcp"));
    *transport.message_url.write() = Some(format!("http://{addr}/mcp"));
    set_default_session(&transport, "stale-session-from-before-restart");

    // WHEN: a request rides the dead session
    let response = transport.request("tools/list", None).await.unwrap();

    // THEN: the transport re-initialized and the retry succeeded
    assert!(response.error.is_none(), "retried request must succeed");
    assert_eq!(
        default_session(&transport).as_deref(),
        Some(FRESH_SESSION),
        "fresh session ID must replace the stale one"
    );

    server.abort();
}

/// robn's case (#247): a remote that invalidates the session on OAuth token
/// refresh answers a live request with a bare HTTP 404. Per the MCP 2025-11-25
/// transport spec (2.5.4), the client must open a new session with a fresh
/// `InitializeRequest` (no session id) and retry. The transport must drop the
/// dead session, re-run the initialize handshake, and retry the original
/// request once. This is the 404 sibling of the `-32015` regression above;
/// #248 added the `http 404` clause to the expiry classifier, and this test
/// pins the end-to-end behaviour for the exact shape reported in #247.
#[tokio::test]
async fn request_reinitializes_session_and_retries_on_http_404() {
    use axum::{
        Json, Router,
        extract::State,
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
        routing::post,
    };
    use serde_json::json;

    const FRESH_SESSION: &str = "fresh-session-after-404";

    async fn mcp_handler(
        State(hits): State<Arc<std::sync::atomic::AtomicU32>>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> axum::response::Response {
        hits.fetch_add(1, Ordering::Relaxed);
        let session = headers
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let method = body["method"].as_str().unwrap_or("");

        // Notifications (no id) are acknowledged unconditionally.
        if body.get("id").is_none() {
            return StatusCode::ACCEPTED.into_response();
        }

        if method == "initialize" {
            // Remote hands out a fresh session on re-initialize (the refreshed
            // OAuth token is already on the request at this point).
            let mut resp_headers = HeaderMap::new();
            resp_headers.insert("mcp-session-id", FRESH_SESSION.parse().unwrap());
            return (
                StatusCode::OK,
                resp_headers,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "result": {
                        "protocolVersion": PROTOCOL_VERSION,
                        "capabilities": {},
                        "serverInfo": {"name": "mock", "version": "0"}
                    }
                })),
            )
                .into_response();
        }

        if session == FRESH_SESSION {
            // Post-reinit session: requests succeed.
            (
                StatusCode::OK,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "result": {"ok": true}
                })),
            )
                .into_response()
        } else {
            // Stale session invalidated on token refresh: bare HTTP 404, the
            // exact shape robn reported in #247.
            (StatusCode::NOT_FOUND, "session terminated".to_string()).into_response()
        }
    }

    // GIVEN: a streamable backend that 404s the session the remote just killed
    let hits = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/mcp", post(mcp_handler))
        .with_state(Arc::clone(&hits));
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let transport = make_transport(&format!("http://{addr}/mcp"));
    *transport.message_url.write() = Some(format!("http://{addr}/mcp"));
    set_default_session(&transport, "stale-session-pre-refresh");

    // WHEN: a request rides the session the remote just invalidated
    let response = transport.request("tools/list", None).await.unwrap();

    // THEN: the 404 read as session-expiry; transport re-initialized and retried
    assert!(
        response.error.is_none(),
        "retried request must succeed after the 404 triggers a re-initialize"
    );
    assert_eq!(
        default_session(&transport).as_deref(),
        Some(FRESH_SESSION),
        "fresh session ID must replace the one invalidated on token refresh"
    );

    server.abort();
}

/// MIK-6040 (#247): a remote that invalidates the MCP session on OAuth token
/// refresh may answer a live request with HTTP **200** and the expiry encoded as
/// a JSON-RPC `error` member (code `-32600`/`-32015`, message "Session not
/// found") rather than a non-2xx status. The transport sees this as
/// `Ok(JsonRpcResponse)` with `error: Some(..)`, so the `Err`-string classifier
/// never fires. The `is_session_expired_response` path must catch it and run the
/// same drop-session / re-initialize / retry-once recovery as the 404 and
/// `-32015` cases above.
#[tokio::test]
async fn request_reinitializes_on_jsonrpc_session_error_response() {
    use axum::{
        Json, Router,
        extract::State,
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
        routing::post,
    };
    use serde_json::json;

    const FRESH_SESSION: &str = "fresh-session-after-jsonrpc-session-err";

    async fn mcp_handler(
        State(hits): State<Arc<std::sync::atomic::AtomicU32>>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> axum::response::Response {
        hits.fetch_add(1, Ordering::Relaxed);
        let session = headers
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let method = body["method"].as_str().unwrap_or("");

        if body.get("id").is_none() {
            return StatusCode::ACCEPTED.into_response();
        }

        if method == "initialize" {
            let mut resp_headers = HeaderMap::new();
            resp_headers.insert("mcp-session-id", FRESH_SESSION.parse().unwrap());
            return (
                StatusCode::OK,
                resp_headers,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "result": {
                        "protocolVersion": PROTOCOL_VERSION,
                        "capabilities": {},
                        "serverInfo": {"name": "mock", "version": "0"}
                    }
                })),
            )
                .into_response();
        }

        if session == FRESH_SESSION {
            (
                StatusCode::OK,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "result": {"ok": true}
                })),
            )
                .into_response()
        } else {
            // Stale session: HTTP 200 + JSON-RPC error (the MIK-6040 shape).
            (
                StatusCode::OK,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "error": {"code": -32600, "message": "Session not found"}
                })),
            )
                .into_response()
        }
    }

    // GIVEN: a backend that signals stale-session via 200 + jsonrpc error
    let hits = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/mcp", post(mcp_handler))
        .with_state(Arc::clone(&hits));
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let transport = make_transport(&format!("http://{addr}/mcp"));
    *transport.message_url.write() = Some(format!("http://{addr}/mcp"));
    set_default_session(&transport, "stale-session-before-refresh");

    // WHEN: a request rides the dead session and the remote answers 200 + error
    let response = transport.request("tools/list", None).await.unwrap();

    // THEN: recovery re-initialized (no stale session) and the retry succeeded
    assert!(
        response.error.is_none(),
        "retried request after jsonrpc session error must succeed"
    );
    assert_eq!(
        default_session(&transport).as_deref(),
        Some(FRESH_SESSION),
        "fresh session ID must replace the stale one"
    );

    server.abort();
}

/// A request without any session that fails with a non-session error must NOT
/// trigger the re-initialize path (no retry storm on genuinely broken backends).
#[tokio::test]
async fn request_does_not_reinitialize_without_a_session() {
    use axum::{Json, Router, http::StatusCode, routing::post};
    use serde_json::json;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().route(
        "/mcp",
        post(|| async {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "Bad Request: Session not found"})),
            )
        }),
    );
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let transport = make_transport(&format!("http://{addr}/mcp"));
    *transport.message_url.write() = Some(format!("http://{addr}/mcp"));
    // No session_id set: the expiry signature without a prior session must
    // surface as a plain error (nothing to re-initialize).

    let err = transport.request("tools/list", None).await.unwrap_err();
    assert!(err.to_string().contains("Session not found"));

    server.abort();
}

#[test]
fn session_expired_detection_matches_known_signatures() {
    // rust-mcp-sdk shape (hebb-serve, observed live 2026-06-11)
    assert!(is_session_expired_error(&Error::Transport(
        "HTTP 400 Bad Request: {\"code\":-32015,\"data\":null,\"message\":\"Bad Request: Session not found\"}".to_string()
    )));
    // MCP spec: 404 = session terminated/expired
    assert!(is_session_expired_error(&Error::Transport(
        "HTTP 404 Not Found: ".to_string()
    )));
    // Plain transport failure must not match
    assert!(!is_session_expired_error(&Error::Transport(
        "Request failed: connection refused".to_string()
    )));
    // Non-transport errors must not match
    assert!(!is_session_expired_error(&Error::Protocol(
        "Session not found".to_string()
    )));
}

#[test]
fn session_expired_response_detection_matches_known_signatures() {
    use crate::protocol::JsonRpcError;

    let make = |code: i32, message: &str| JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id: None,
        result: None,
        error: Some(JsonRpcError {
            code,
            message: message.to_string(),
            data: None,
        }),
    };

    // MIK-6040: 200 + JSON-RPC error shapes a remote may use for session expiry.
    assert!(is_session_expired_response(&make(
        -32600,
        "Session not found"
    )));
    assert!(is_session_expired_response(&make(
        -32015,
        "Bad Request: Session not found"
    )));
    // Match on message alone, even with an unexpected code.
    assert!(is_session_expired_response(&make(
        -32000,
        "session not found"
    )));
    // Unrelated JSON-RPC errors must not match.
    assert!(!is_session_expired_response(&make(
        -32601,
        "Method not found"
    )));
    // A successful response (no error) must not match.
    assert!(!is_session_expired_response(&JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id: None,
        result: Some(serde_json::json!({"ok": true})),
        error: None,
    }));
}

// MIK-6734 slice 2b-i — request_with_headers injects per-request headers on the
// wire (the spine for identity-credential propagation), and a per-request header
// overrides a static header of the same name for that call only.
#[tokio::test]
async fn request_with_headers_injects_and_overrides_on_the_wire() {
    use axum::{Json, Router, extract::State, http::HeaderMap, routing::post};
    use tokio::sync::{Mutex, oneshot};

    async fn capture(
        State(sender): State<Arc<Mutex<Option<oneshot::Sender<HeaderMap>>>>>,
        headers: HeaderMap,
        _body: axum::body::Bytes,
    ) -> Json<serde_json::Value> {
        if let Some(s) = sender.lock().await.take() {
            let _ = s.send(headers);
        }
        Json(serde_json::json!({"jsonrpc":"2.0","id":1,"result":{}}))
    }

    let (tx, rx) = oneshot::channel();
    let state = Arc::new(Mutex::new(Some(tx)));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/messages", post(capture))
        .with_state(state);
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // Static header "Authorization: static" on the transport.
    let mut custom = HashMap::new();
    custom.insert("Authorization".to_string(), "static".to_string());
    let transport = make_transport_with_headers(&format!("http://{addr}/mcp"), custom);
    *transport.message_url.write() = Some(format!("http://{addr}/messages"));

    // Per-request headers: override Authorization + add a fresh header.
    let extra = vec![
        (
            "Authorization".to_string(),
            "Bearer per-user-assertion".to_string(),
        ),
        ("X-Idp-Audience".to_string(), "https://mem".to_string()),
    ];
    let _ = transport
        .request_with_headers("tools/call", None, &extra, None)
        .await;

    let headers = tokio::time::timeout(Duration::from_secs(1), rx)
        .await
        .unwrap()
        .unwrap();
    // Per-request value wins over the static one.
    assert_eq!(headers["authorization"], "Bearer per-user-assertion");
    assert_eq!(headers["x-idp-audience"], "https://mem");
    server.abort();
}

// The default trait method ignores extra headers: plain request() behaves the
// same as request_with_headers(&[]) — no accidental leakage into a call that
// passes none.
#[tokio::test]
async fn request_without_extra_headers_uses_static_only() {
    use axum::{Json, Router, extract::State, http::HeaderMap, routing::post};
    use tokio::sync::{Mutex, oneshot};

    async fn capture(
        State(sender): State<Arc<Mutex<Option<oneshot::Sender<HeaderMap>>>>>,
        headers: HeaderMap,
        _body: axum::body::Bytes,
    ) -> Json<serde_json::Value> {
        if let Some(s) = sender.lock().await.take() {
            let _ = s.send(headers);
        }
        Json(serde_json::json!({"jsonrpc":"2.0","id":1,"result":{}}))
    }

    let (tx, rx) = oneshot::channel();
    let state = Arc::new(Mutex::new(Some(tx)));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/messages", post(capture))
        .with_state(state);
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let mut custom = HashMap::new();
    custom.insert("Authorization".to_string(), "static".to_string());
    let transport = make_transport_with_headers(&format!("http://{addr}/mcp"), custom);
    *transport.message_url.write() = Some(format!("http://{addr}/messages"));

    let _ = transport.request("tools/call", None).await;

    let headers = tokio::time::timeout(Duration::from_secs(1), rx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(headers["authorization"], "static");
    assert!(!headers.contains_key("x-idp-audience"));
    server.abort();
}

// F3 reload sink-completeness (MIK-6746): close() must abort the OAuth
// token-refresh background task, or a stopped/hot-reloaded backend leaves an
// orphaned task that keeps the OAuth client Arc alive and can still refresh +
// persist a gateway-held backend token via TokenStorage::save.
#[tokio::test]
async fn close_aborts_oauth_refresh_task() {
    let t = make_transport("http://127.0.0.1:1/mcp");
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    // A long-lived task standing in for the refresh loop: it only sends if it
    // is NOT aborted.
    let handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(3600)).await;
        let _ = tx.send(());
    });
    *t.refresh_task.write() = Some(handle);

    // No session_id was ever set, so close() skips the network DELETE.
    t.close().await.unwrap();

    assert!(
        t.refresh_task.read().is_none(),
        "close() must take the refresh task handle"
    );
    // Aborted task drops its sender without sending -> receiver resolves to Err.
    assert!(
        rx.await.is_err(),
        "close() must abort the refresh task (sender dropped without sending)"
    );
}

// F3 / MIK-6746 reconnect regression: initialize() is re-entered on
// session-expiry (request() -> initialize()), so storing a new refresh task
// must abort the prior one. Dropping a JoinHandle does NOT cancel the task, so
// a plain overwrite would orphan the old refresh loop, keeping the OAuth client
// Arc alive and still persisting a gateway-held token. store_refresh_task() is
// the idempotent slot used by initialize().
#[tokio::test]
async fn store_refresh_task_aborts_previous() {
    let t = make_transport("http://127.0.0.1:1/mcp");
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    // First task standing in for the pre-reconnect refresh loop: only sends if
    // it is NOT aborted.
    let first = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(3600)).await;
        let _ = tx.send(());
    });
    t.store_refresh_task(first);

    // Simulate reconnect storing a fresh refresh task.
    let second = tokio::spawn(async { tokio::time::sleep(Duration::from_secs(3600)).await });
    t.store_refresh_task(second);

    assert!(
        t.refresh_task.read().is_some(),
        "the reconnect refresh task must be stored"
    );
    // The first task was aborted -> its sender dropped without sending.
    assert!(
        rx.await.is_err(),
        "storing a new refresh task must abort the previous one (no orphan)"
    );
}

// =========================================================================
// Drop impl — RAII backstop for the refresh task (ADR-008 / F3, MIK-6746)
// =========================================================================

/// A transport dropped without `close()` must abort its stored refresh task.
///
/// Regression guard for the partial-init leak: `initialize()` stores the
/// refresh `JoinHandle` before `establish_sse_connection().await?`, so when
/// that `?` fails the transport is discarded without ever calling `close()`.
/// Without the `Drop` impl the detached tokio task would keep running,
/// refreshing + persisting a gateway-held OAuth token indefinitely.
#[tokio::test]
async fn drop_aborts_refresh_task_without_close() {
    // GIVEN: a transport with a long-lived background task stored as its
    // refresh handle (simulating a successful OAuth handshake followed by a
    // failed SSE connection, where close() is never called).
    let t = make_transport("http://127.0.0.1:1/mcp");
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let refresh = tokio::spawn(async move {
        // Stands in for the real token-refresh loop: only sends if NOT aborted.
        tokio::time::sleep(Duration::from_secs(3600)).await;
        let _ = tx.send(());
    });
    t.store_refresh_task(refresh);

    // WHEN: the transport is dropped without close() — the Arc count must
    // reach zero, triggering Drop. Unwrap the Arc to guarantee ownership.
    let raw: HttpTransport =
        Arc::try_unwrap(t).unwrap_or_else(|_| panic!("Arc must be uniquely owned for this test"));
    drop(raw);

    // THEN: the refresh task was aborted by Drop, so the sender is dropped
    // immediately — rx must resolve to Err within a short deadline.
    // Without the RAII backstop the task sleeps for 3600 s; wrapping in a
    // tight timeout converts that hang into a prompt CI failure.
    match tokio::time::timeout(Duration::from_millis(500), rx).await {
        Err(elapsed) => {
            panic!(
                "Drop did NOT abort the refresh task — timed out after {elapsed} \
                 waiting for the channel to close (MIK-6746 RAII regression)"
            );
        }
        Ok(Ok(())) => {
            panic!(
                "refresh task ran to completion — Drop did not abort it \
                 (MIK-6746 RAII regression)"
            );
        }
        Ok(Err(_recv_err)) => {
            // Sender was dropped by task abort — correct RAII behavior.
        }
    }
}

// =========================================================================
// MIK-6784 (GW.1): per-identity MCP-Session-Id partitioning
// =========================================================================

/// GW.1 unit: `build_mcp_headers` selects the session bound to the caller's
/// identity bucket, so two identities never share a session and a caller with
/// no negotiated session gets no session header at all.
#[tokio::test]
async fn build_headers_selects_session_per_identity_bucket() {
    let t = make_transport("http://localhost");
    t.sessions
        .write()
        .insert("alice".to_string(), "sess-alice".to_string());
    t.sessions
        .write()
        .insert("bob".to_string(), "sess-bob".to_string());
    t.sessions
        .write()
        .insert(String::new(), "sess-default".to_string());

    let alice = t
        .build_mcp_headers(HeaderMode::Request { method: "m" }, Some("alice"))
        .await
        .unwrap();
    let bob = t
        .build_mcp_headers(HeaderMode::Request { method: "m" }, Some("bob"))
        .await
        .unwrap();
    let anon = t
        .build_mcp_headers(HeaderMode::Request { method: "m" }, None)
        .await
        .unwrap();
    let absent = t
        .build_mcp_headers(HeaderMode::Request { method: "m" }, Some("carol"))
        .await
        .unwrap();

    assert_eq!(alice["mcp-session-id"], "sess-alice");
    assert_eq!(bob["mcp-session-id"], "sess-bob");
    assert_ne!(
        alice["mcp-session-id"], bob["mcp-session-id"],
        "two identities must never share a session id"
    );
    assert_eq!(
        anon["mcp-session-id"], "sess-default",
        "no-identity path uses the shared default bucket"
    );
    assert!(
        !absent.contains_key("mcp-session-id"),
        "an identity with no negotiated session sends no session header"
    );
}

/// Stateful mock backend for the session-partition test: a caller with no
/// session is minted a fresh unique one (and told which); a caller presenting a
/// session has it echoed back verbatim. Extracted from the test body to keep
/// the test under the line cap.
async fn partition_mock_handler(
    axum::extract::State(counter): axum::extract::State<Arc<std::sync::atomic::AtomicU32>>,
    headers: axum::http::HeaderMap,
    axum::Json(body): axum::Json<Value>,
) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use serde_json::json;

    if body.get("id").is_none() {
        return StatusCode::ACCEPTED.into_response();
    }
    let incoming = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if incoming.is_empty() {
        let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
        let minted = format!("sess-{n}");
        let mut resp_headers = axum::http::HeaderMap::new();
        resp_headers.insert("mcp-session-id", minted.parse().unwrap());
        (
            StatusCode::OK,
            resp_headers,
            axum::Json(json!({"jsonrpc": "2.0", "id": body["id"], "result": {"session": minted}})),
        )
            .into_response()
    } else {
        (
            StatusCode::OK,
            axum::Json(
                json!({"jsonrpc": "2.0", "id": body["id"], "result": {"session": incoming}}),
            ),
        )
            .into_response()
    }
}

/// GW.1 integration: against a stateful backend that mints a distinct session
/// per handshake, each caller identity negotiates and reuses its OWN session;
/// one identity's session is never stamped onto another's request. Regression
/// test for the Arc-shared single-session slot (MIK-6784).
#[tokio::test]
async fn stateful_backend_partitions_sessions_across_identities() {
    use axum::{Router, routing::post};

    let counter = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/mcp", post(partition_mock_handler))
        .with_state(Arc::clone(&counter));
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let transport = make_transport(&format!("http://{addr}/mcp"));

    let session_of = |resp: &JsonRpcResponse| -> String {
        resp.result.as_ref().unwrap()["session"]
            .as_str()
            .unwrap()
            .to_string()
    };

    // Each identity's first request negotiates its own session.
    let a1 = transport
        .request_with_headers("tools/call", None, &[], Some("alice"))
        .await
        .unwrap();
    let b1 = transport
        .request_with_headers("tools/call", None, &[], Some("bob"))
        .await
        .unwrap();
    let alice_session = session_of(&a1);
    let bob_session = session_of(&b1);
    assert_ne!(
        alice_session, bob_session,
        "distinct identities must negotiate distinct sessions"
    );

    // Second round: each identity reuses ITS OWN session — never the other's.
    let a2 = transport
        .request_with_headers("tools/call", None, &[], Some("alice"))
        .await
        .unwrap();
    let b2 = transport
        .request_with_headers("tools/call", None, &[], Some("bob"))
        .await
        .unwrap();
    assert_eq!(
        session_of(&a2),
        alice_session,
        "alice must reuse alice's session, not bob's"
    );
    assert_eq!(
        session_of(&b2),
        bob_session,
        "bob must reuse bob's session, not alice's"
    );

    // The transport's own bucket map reflects the partition.
    assert_eq!(
        transport.sessions.read().get("alice").cloned(),
        Some(alice_session)
    );
    assert_eq!(
        transport.sessions.read().get("bob").cloned(),
        Some(bob_session)
    );

    server.abort();
}
