// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
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
    let msg = "Supported: 2024-11-05, 2025-03-26";
    let versions = parse_supported_versions_from_error(msg).unwrap();
    assert_eq!(versions, vec!["2024-11-05", "2025-03-26"]);
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
fn resolve_message_url_absolute_cross_origin_rejected() {
    // A backend-advertised absolute endpoint on a different origin than the SSE
    // stream must be rejected: sending per-user credentials there is the SSRF +
    // credential-exfil vector this guard closes.
    let t = make_transport("http://localhost:8080/sse");
    let err = t
        .resolve_message_url("http://other:9090/messages")
        .unwrap_err();
    assert!(
        err.to_string().contains("cross-origin"),
        "expected cross-origin rejection, got: {err}"
    );
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

// Authority-replacing endpoints that do NOT start with `http://`/`https://`
// but resolve cross-origin via WHATWG URL rules (network-path, backslash,
// scheme-relative). A prefix classifier routes these to the relative branch and
// misses them; resolve-then-check catches them. All four MUST be rejected.
fn assert_cross_origin_rejected(base: &str, endpoint: &str) {
    let t = make_transport(base);
    let err = t.resolve_message_url(endpoint).unwrap_err();
    assert!(
        matches!(&err, crate::Error::Transport(m) if m.contains("cross-origin")),
        "expected cross-origin rejection for endpoint {endpoint:?}, got: {err:?}"
    );
}

#[test]
fn resolve_message_url_network_path_metadata_host_rejected() {
    assert_cross_origin_rejected(
        "http://localhost:8080/sse",
        "//169.254.169.254/latest/meta-data/",
    );
}

#[test]
fn resolve_message_url_backslash_authority_rejected() {
    assert_cross_origin_rejected("http://localhost:8080/sse", "\\\\169.254.169.254/x");
}

#[test]
fn resolve_message_url_slash_backslash_authority_rejected() {
    assert_cross_origin_rejected("http://localhost:8080/sse", "/\\attacker-host/x");
}

#[test]
fn resolve_message_url_scheme_relative_authority_rejected() {
    assert_cross_origin_rejected("http://localhost:8080/sse", "https:/\\/\\attacker-host/x");
}

// =========================================================================
// evaluate_redirect (redirect-policy same-origin credential-exfil guard)
// =========================================================================

fn url(s: &str) -> url::Url {
    url::Url::parse(s).unwrap()
}

#[test]
fn evaluate_redirect_cross_origin_public_host_rejected() {
    // A same-origin backend answering with `30x Location: https://evil…` points
    // at a PUBLIC host that clears the SSRF check but is a different origin.
    // Following it would replay the per-user bearer cross-origin: must reject.
    let decision = evaluate_redirect(
        &url("https://api.example.com/sse"),
        &url("https://evil.example.com/steal"),
        0,
    );
    match decision {
        RedirectDecision::Reject(msg) => assert!(
            msg.contains("cross-origin"),
            "expected cross-origin rejection, got: {msg}"
        ),
        other => panic!("expected Reject, got {other:?}"),
    }
}

#[test]
fn evaluate_redirect_same_origin_allowed() {
    // A redirect that stays on the base origin (different path) is legitimate
    // per the MCP spec and must be followed.
    let decision = evaluate_redirect(
        &url("https://api.example.com/sse"),
        &url("https://api.example.com/messages?session_id=abc"),
        0,
    );
    assert_eq!(decision, RedirectDecision::Follow);
}

#[test]
fn evaluate_redirect_same_origin_different_port_rejected() {
    // Same host+scheme but a different port is a distinct origin (WHATWG) —
    // still a credential-exfil target, so reject.
    let decision = evaluate_redirect(
        &url("https://api.example.com/sse"),
        &url("https://api.example.com:8443/messages"),
        0,
    );
    assert!(
        matches!(&decision, RedirectDecision::Reject(m) if m.contains("cross-origin")),
        "expected cross-origin rejection, got: {decision:?}"
    );
}

#[test]
fn evaluate_redirect_internal_range_still_ssrf_rejected() {
    // An internal/metadata target is rejected by the SSRF guard, which runs
    // before the same-origin check, so the reason names SSRF (not cross-origin).
    let decision = evaluate_redirect(
        &url("https://api.example.com/sse"),
        &url("http://169.254.169.254/latest/meta-data/"),
        0,
    );
    match decision {
        RedirectDecision::Reject(msg) => {
            assert!(
                msg.contains("SSRF"),
                "expected SSRF rejection reason, got: {msg}"
            );
            assert!(
                !msg.contains("cross-origin"),
                "SSRF guard must fire before same-origin, got: {msg}"
            );
        }
        other => panic!("expected Reject, got {other:?}"),
    }
}

#[test]
fn evaluate_redirect_hop_cap_stops() {
    // At the fifth prior hop the policy stops following, matching the prior cap,
    // regardless of whether the target would otherwise be allowed.
    let decision = evaluate_redirect(
        &url("https://api.example.com/sse"),
        &url("https://api.example.com/again"),
        5,
    );
    assert_eq!(decision, RedirectDecision::Stop);
}

#[test]
fn evaluate_redirect_cross_origin_rejected_mid_chain() {
    // A same-origin first hop must not become a springboard for a later
    // cross-origin pivot: every target is compared against the ORIGINAL base
    // origin, not the immediately-preceding hop. Here the chain has already
    // followed same-origin hops (previous_hops in 1..5) and now pivots to a
    // public but foreign origin — it must still Reject, not Follow.
    for previous_hops in [2, 4] {
        let decision = evaluate_redirect(
            &url("https://api.example.com/sse"),
            &url("https://evil.example.com/steal"),
            previous_hops,
        );
        match decision {
            RedirectDecision::Reject(msg) => assert!(
                msg.contains("cross-origin"),
                "expected cross-origin rejection at hop {previous_hops}, got: {msg}"
            ),
            other => panic!("expected Reject at hop {previous_hops}, got {other:?}"),
        }
    }
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
    // The marker, not the backend's own wording: the body is redacted at the
    // boundary now, so "Session not found" never reaches an error string.
    assert!(err.to_string().contains("session expired"), "{err}");
    assert!(
        !err.to_string().contains("-32015"),
        "the untrusted body must not survive into the error: {err}"
    );

    server.abort();
}

#[test]
fn session_expired_detection_matches_known_signatures() {
    // The raw body no longer reaches the classifier: `safe_http_status_error`
    // converts it at the HTTP boundary, because the body is backend-controlled
    // and may echo our own credentials. So the contract under test is the PAIR
    // — the conversion, then the match. Testing either half alone is how this
    // broke: the redaction landed without the classifier change and session
    // recovery stopped, silently, with every other test still green (MIK-7221).
    let raw_rust_mcp_sdk =
        "{\"code\":-32015,\"data\":null,\"message\":\"Bad Request: Session not found\"}";
    let converted = safe_http_status_error(reqwest::StatusCode::BAD_REQUEST, raw_rust_mcp_sdk);
    assert!(
        !converted.to_string().contains("-32015"),
        "the untrusted body must not survive into the error: {converted}"
    );
    assert!(
        is_session_expired_error(&converted),
        "expiry must still be recognised after redaction: {converted}"
    );

    // The lowercase-only shape, which is the other half of the boundary check.
    let converted_lower =
        safe_http_status_error(reqwest::StatusCode::BAD_REQUEST, "session not found, sorry");
    assert!(is_session_expired_error(&converted_lower));

    // MCP spec: 404 = session terminated/expired. Reaches the classifier directly.
    assert!(is_session_expired_error(&Error::Transport(
        "HTTP 404 Not Found: ".to_string()
    )));

    // A non-expiry body converts to a bare status and must NOT match. Without
    // this, a conversion that returned the marker unconditionally would pass.
    let other = safe_http_status_error(reqwest::StatusCode::BAD_REQUEST, "malformed json");
    assert!(!is_session_expired_error(&other), "{other}");

    // Plain transport failure must not match
    assert!(!is_session_expired_error(&Error::Transport(
        "Request failed: connection refused".to_string()
    )));
    // Non-transport errors must not match
    assert!(!is_session_expired_error(&Error::Protocol(
        "session expired".to_string()
    )));

    // The status-carried carriage: a peer that words its expiry rather than
    // coding it used to match as `HTTP 404`, and now arrives parsed. Both arms
    // read the same marker set, or a peer loses session recovery by the
    // accident of having sent a body that parses.
    assert!(is_session_expired_error(&Error::JsonRpc {
        code: -32001,
        message: "Session expired".to_string(),
        data: None,
    }));
    // ...and the narrowness holds: an ordinary refusal is not an expiry.
    assert!(!is_session_expired_error(&Error::JsonRpc {
        code: crate::protocol::era::METHOD_NOT_FOUND_CODE,
        message: "Method not found: tools/list".to_string(),
        data: None,
    }));
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
        confirmation_refusal: false,
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
        confirmation_refusal: false,
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
        .request_with_headers(
            "tools/call",
            None,
            &extra,
            None,
            ResendPermission::Permitted,
        )
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
        .request_with_headers(
            "tools/call",
            None,
            &[],
            Some("alice"),
            ResendPermission::Permitted,
        )
        .await
        .unwrap();
    let b1 = transport
        .request_with_headers(
            "tools/call",
            None,
            &[],
            Some("bob"),
            ResendPermission::Permitted,
        )
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
        .request_with_headers(
            "tools/call",
            None,
            &[],
            Some("alice"),
            ResendPermission::Permitted,
        )
        .await
        .unwrap();
    let b2 = transport
        .request_with_headers(
            "tools/call",
            None,
            &[],
            Some("bob"),
            ResendPermission::Permitted,
        )
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

// =========================================================================
// bearer_header_value — invalid-byte token must not panic (MIK-6909, AC.5)
// =========================================================================

#[test]
fn bearer_header_value_accepts_a_well_formed_token() {
    // GIVEN a token containing only header-legal bytes
    // WHEN we build the Authorization value
    // THEN it succeeds and carries the Bearer prefix.
    let value = bearer_header_value("abc123.DEF-456").expect("valid token must produce a header");
    assert_eq!(value.to_str().unwrap(), "Bearer abc123.DEF-456");
}

#[test]
fn bearer_header_value_rejects_invalid_bytes_without_panicking() {
    // GIVEN a token with bytes illegal in an HTTP header value (newline, NUL, CR)
    // WHEN we build the Authorization value
    // THEN it returns a clean OAuth error rather than panicking, and the error
    //      never echoes the token (credential hygiene, CWE-532).
    for bad in ["tok\nen", "tok\0en", "tok\ren"] {
        let err = bearer_header_value(bad).expect_err("invalid token must be rejected");
        assert!(
            matches!(err, Error::OAuth(_)),
            "expected a clean OAuth error, got {err:?}"
        );
        assert!(
            !format!("{err}").contains(bad),
            "error must not leak the raw token"
        );
    }
}

/// One canary, every redaction helper. Each site was found by a reviewer AFTER a
/// previous round claimed the class was closed — five in round one, three more in
/// round two, including two session-ID logs and a config line that was the twin
/// of one already fixed. A per-site fix does not generalise; a sweep does.
#[test]
fn no_diagnostic_helper_passes_a_canary_through() {
    const CANARY: &str = "SENTINEL_TRANSPORT_9f3c";

    // URL redaction: the secret in each position a URL can hide one.
    for raw in [
        format!("https://user:{CANARY}@svc.example.com/mcp"),
        format!("https://svc.example.com/services/{CANARY}"),
        format!("https://svc.example.com/mcp?token={CANARY}"),
        format!("https://svc.example.com/mcp#{CANARY}"),
    ] {
        let out = sanitize_url_for_diagnostics(&raw);
        assert!(!out.contains(CANARY), "URL redaction leaked: {out}");
        assert!(
            out.starts_with("https://svc.example.com"),
            "origin lost: {out}"
        );
    }

    // Unparseable input must not be echoed — the failure path is where a
    // redaction usually gets undone.
    let bad = sanitize_url_for_diagnostics(&format!(":://not a url {CANARY}"));
    assert!(!bad.contains(CANARY), "invalid-URL path leaked: {bad}");

    // A backend error body is untrusted and may quote our own credentials back.
    for body in [
        format!("{{\"error\":\"{CANARY}\"}}"),
        format!("{{\"code\":-32015,\"message\":\"Session not found {CANARY}\"}}"),
    ] {
        let err = safe_http_status_error(reqwest::StatusCode::BAD_REQUEST, &body);
        assert!(
            !err.to_string().contains(CANARY),
            "status error leaked: {err}"
        );
    }

    // The expiry marker still survives that redaction, or session recovery breaks.
    let expired = safe_http_status_error(
        reqwest::StatusCode::BAD_REQUEST,
        &format!("{{\"code\":-32015,\"message\":\"Session not found {CANARY}\"}}"),
    );
    assert!(
        is_session_expired_error(&expired),
        "expiry lost to redaction: {expired}"
    );

    // A cross-origin redirect rejection names both URLs; neither may carry one.
    let base = Url::parse("https://svc.example.com/mcp").expect("base");
    let target = Url::parse(&format!("https://evil.example.com/x?t={CANARY}")).expect("target");
    if let RedirectDecision::Reject(reason) = evaluate_redirect(&base, &target, 0) {
        assert!(
            !reason.contains(CANARY),
            "redirect rejection leaked: {reason}"
        );
    } else {
        panic!("a cross-origin redirect must be rejected");
    }
}

/// Feed a whole body to the streaming decoder as one chunk.
///
/// Chunk-boundary independence is the decoder's own property, proven in
/// `sse_decoder_tests`. These rows are about what a decoded exchange delivers
/// to the caller and to its sink, so one chunk is the right fixture here.
fn sse_stream(body: impl Into<bytes::Bytes>) -> impl futures::Stream<Item = Result<bytes::Bytes>> {
    futures::stream::iter(vec![Ok(body.into())])
}

/// The SSE body may carry a server-to-client *request* rather than the answer
/// to the call in flight. Handing that back to the caller as its response is
/// the defect this guards.
#[tokio::test]
async fn sse_decode_rejects_inbound_request_frame() {
    // GIVEN: an SSE body whose first data line is a request, not a response
    let body = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"sampling/createMessage\",\"params\":{}}\n\n";

    // WHEN: the transport decodes it
    let outcome = sse_decoder::decode_sse_exchange(sse_stream(body)).await;

    // THEN: it is refused, never returned as an empty successful response
    assert!(
        outcome.is_err(),
        "a frame carrying `method` must not decode as a response, got {outcome:?}"
    );
}

/// Guard the extraction: a genuine response still decodes.
#[tokio::test]
async fn sse_decode_accepts_response_frame() {
    let body = "data: {\"jsonrpc\":\"2.0\",\"id\":5,\"result\":{\"tools\":[]}}\n";
    let response = sse_decoder::decode_sse_exchange(sse_stream(body))
        .await
        .expect("valid response must decode");
    assert!(response.result.is_some());
    assert!(response.error.is_none());
}

// =========================================================================
// OAuth cleartext-transmission guard (CodeQL rust/cleartext-transmission
// alerts #90/#91, CWE-319). An OAuth bearer token must never leave the
// process over plaintext `http://` unless the peer is loopback.
//
// Test plan — one row per acceptance criterion:
//   1  https + non-loopback + oauth      -> ALLOW  (guard must not over-refuse)
//   2  http  + non-loopback + oauth      -> REFUSE (the alert itself; RED today)
//   3  http://localhost + oauth          -> ALLOW  (operator-ruled exemption)
//   4  http://127.0.0.2 + oauth          -> ALLOW  (127.0.0.0/8, not one address)
//   5  http://[::1] + oauth              -> ALLOW  (v6 loopback)
//   6  http://localhost.evil.com + oauth -> REFUSE (kills a substring host check)
//   7  http://127.0.0.1.evil.com + oauth -> REFUSE (kills a prefix host check)
//   8  http://[::ffff:127.0.0.1] + oauth -> REFUSE (mapped v4 is not loopback here)
//   9  ftp://localhost + oauth           -> REFUSE (only http/https are transports)
//  10  http + non-loopback, NO oauth     -> ALLOW  (no credential, no change)
//  11  request time: message endpoint downgraded -> get_oauth_token refuses
//  12  request time: no oauth configured -> Ok(None) even over cleartext
// =========================================================================

fn oauth_client_for(resource: &str) -> crate::oauth::OAuthClient {
    use crate::oauth::{OAuthClient, OAuthClientConfig, TokenStorage};
    let storage =
        Arc::new(TokenStorage::new(std::env::temp_dir().join("http_transport_tls_guard")).unwrap());
    OAuthClient::new(
        reqwest::Client::new(),
        "test-backend".to_string(),
        resource.to_string(),
        vec![],
        storage,
        OAuthClientConfig {
            token_refresh_buffer_secs: 300,
            ..Default::default()
        },
    )
}

fn transport_with_oauth(url: &str) -> Result<Arc<HttpTransport>> {
    HttpTransport::new_with_oauth(
        url,
        HashMap::new(),
        Duration::from_secs(5),
        true,
        Some(oauth_client_for(url)),
        None,
    )
}

#[test]
fn oauth_over_tls_is_allowed() {
    assert!(
        transport_with_oauth("https://backend.example/mcp").is_ok(),
        "row 1: TLS is the normal case and must keep working"
    );
}

#[test]
fn oauth_over_cleartext_non_loopback_is_refused() {
    let Err(err) = transport_with_oauth("http://backend.example/mcp") else {
        panic!("row 2: a bearer token must not travel in cleartext to a remote host");
    };
    assert!(
        err.to_string().contains("cleartext"),
        "the refusal must name the reason, got: {err}"
    );
    // Permanent, not transient: warm-start retries a plain `Transport` error
    // forever at debug level, so a misclassification hides the refusal from the
    // operator entirely.
    assert!(
        matches!(err, Error::TransportPermanent(_)),
        "a cleartext origin never becomes secure by waiting, got: {err}"
    );
}

#[test]
fn oauth_over_cleartext_loopback_is_allowed() {
    // Rows 3-5: local MCP backends legitimately bind loopback without TLS.
    for url in [
        "http://localhost:8080/mcp",
        "http://127.0.0.1:8080/mcp",
        "http://127.0.0.2:9000/mcp",
        "http://[::1]:8080/mcp",
    ] {
        assert!(
            transport_with_oauth(url).is_ok(),
            "{url} is loopback and must stay allowed"
        );
    }
}

#[test]
fn oauth_over_cleartext_loopback_lookalikes_are_refused() {
    // Rows 6-9: hosts that a substring/prefix check would wave through, plus a
    // scheme that is not an HTTP transport at all.
    for url in [
        "http://localhost.evil.com/mcp",
        "http://127.0.0.1.evil.com/mcp",
        "http://[::ffff:127.0.0.1]/mcp",
        "ftp://localhost/mcp",
    ] {
        assert!(
            transport_with_oauth(url).is_err(),
            "{url} must not be treated as a loopback HTTP peer"
        );
    }
}

#[test]
fn cleartext_without_oauth_is_unchanged() {
    // Row 10: no credential is attached, so the guard must not fire.
    assert!(
        HttpTransport::new(
            "http://backend.example/mcp",
            HashMap::new(),
            Duration::from_secs(5),
            true,
        )
        .is_ok(),
        "transports without OAuth keep working over plaintext"
    );
}

#[tokio::test]
async fn get_oauth_token_refuses_a_downgraded_message_endpoint() {
    // Row 11: the request-time barrier, independent of construction. The
    // message endpoint is the URL the token is actually posted to.
    let t = transport_with_oauth("https://backend.example/sse").unwrap();
    *t.message_url.write() = Some("http://backend.example/messages".to_string());

    let err = t
        .get_oauth_token()
        .await
        .expect_err("a downgraded message endpoint must not receive the token");
    assert!(
        err.to_string().contains("cleartext"),
        "the refusal must name the reason, got: {err}"
    );
}

#[tokio::test]
async fn get_oauth_token_without_oauth_is_none_over_cleartext() {
    // Row 12: the guard is about credentials, not about plaintext per se.
    let t = make_transport("http://backend.example/mcp");
    assert!(t.get_oauth_token().await.unwrap().is_none());
}

// =========================================================================
// MIK-7272.SUB.2b — request-scoped notifications MUST flow on the response
// stream of their own request. The inbound half: the transport stops
// discarding a notification it saw on a request's stream and returns it
// alongside the response, in stream order, from one call.
//
// Governing plan: docs/design/2026-08-31-cluster-b-connection-invariance
// -test-plan.md S-02 (forwarding) and S-03 (per-request isolation).
// Design: docs/design/2026-09-09-sub2b-request-scoped-notifications.md.
// =========================================================================

/// A notification seen ahead of the response is CAPTURED, not dropped.
///
/// A conforming server may interleave `notifications/progress` on the response
/// stream of the call in flight. It belongs to that call, and reaches the
/// caller's sink rather than being discarded on the way to the result.
#[tokio::test]
async fn sse_decode_captures_the_notification_seen_before_the_response() {
    // GIVEN: a progress notification ahead of the answer, on one stream
    let body = concat!(
        "event: message\n",
        "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":\"t-1\",\"progress\":1}}\n",
        "\n",
        "event: message\n",
        "data: {\"jsonrpc\":\"2.0\",\"id\":5,\"result\":{\"tools\":[]}}\n",
    );

    // WHEN: the transport decodes it inside the caller's sink scope
    let (response, notifications) = crate::transport::notification_sink::collect(
        sse_decoder::decode_sse_exchange(sse_stream(body)),
    )
    .await;

    // THEN: the response still reaches the caller ...
    assert!(
        response
            .expect("the response after a notification must decode")
            .result
            .is_some(),
        "the response frame must still be returned"
    );
    // ... AND the notification is no longer lost.
    assert_eq!(
        notifications
            .iter()
            .map(|n| n.method.as_str())
            .collect::<Vec<_>>(),
        vec!["notifications/progress"],
        "the notification seen on this request's stream must reach its sink"
    );
}

/// Stream order is preserved: two notifications reach the sink in the order the
/// server sent them, ahead of the response that ended the scan.
///
/// Order is a property of publishing each frame as it decodes: a driver that
/// buffered and replayed could not promise it.
#[tokio::test]
async fn sse_decode_preserves_the_order_two_notifications_arrived_in() {
    // GIVEN: message then progress, in that order, before the answer
    let body = concat!(
        "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{\"level\":\"info\"}}\n",
        "\n",
        "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progress\":2}}\n",
        "\n",
        "data: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{}}\n",
    );

    // WHEN: the transport decodes it
    let (_, notifications) = crate::transport::notification_sink::collect(
        sse_decoder::decode_sse_exchange(sse_stream(body)),
    )
    .await;

    // THEN: both are delivered, in arrival order
    assert_eq!(
        notifications
            .iter()
            .map(|n| n.method.as_str())
            .collect::<Vec<_>>(),
        vec!["notifications/message", "notifications/progress"],
        "stream order must survive the capture"
    );
}

/// A body with no notifications leaves the sink empty, never a phantom entry.
///
/// The negative case an empty world would also satisfy is guarded by equality
/// against a literal count, not by `is_empty()` alone on an untouched channel.
#[tokio::test]
async fn sse_decode_delivers_no_notifications_when_the_server_sent_none() {
    let body = "data: {\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{\"ok\":true}}\n";
    let (response, notifications) = crate::transport::notification_sink::collect(
        sse_decoder::decode_sse_exchange(sse_stream(body)),
    )
    .await;
    assert!(
        response
            .expect("valid response must decode")
            .result
            .is_some()
    );
    assert_eq!(
        notifications.len(),
        0,
        "a clean stream must not manufacture a notification"
    );
}

// =========================================================================
// MIK-7272.SUB.4 -- a connect failure is pre-dispatch only without a redirect
// =========================================================================

/// The falsifier for the pre-dispatch signal, at the only level where a
/// redirect can actually be followed.
///
/// `safe_request_error_for` is told whether the transport's redirect counter
/// moved across the send. That claim is worth nothing unless the policy
/// closure really increments on a followed hop, and the classifier's own unit
/// rows cannot show it -- they pass the bit in by hand. This row builds the
/// real client, makes it follow a real 307 into a closed port, and asserts
/// both halves: the counter moved, and the resulting connect failure was NOT
/// released as pre-dispatch. A 307 re-submits the body, so the origin that
/// redirected may already have executed the call.
#[tokio::test]
async fn a_connect_failure_after_a_followed_redirect_is_not_pre_dispatch() {
    use tokio::io::AsyncWriteExt;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    // Same host AND port as the base URL: `evaluate_redirect` refuses a
    // cross-origin hop, so a redirect is only ever followed within one origin.
    // `localhost` is a name rather than an IP literal, which is what clears the
    // SSRF guard on a loopback target.
    let target = format!("http://localhost:{port}/moved");
    let server = tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            // Close the port BEFORE answering, so the hop the client is about
            // to take is deterministically refused rather than racing this
            // task's exit.
            drop(listener);
            let response = format!(
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: {target}\r\n\
                 Content-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    });

    let base = format!("http://localhost:{port}/mcp");
    let transport =
        HttpTransport::new(&base, HashMap::new(), Duration::from_secs(5), true).unwrap();
    *transport.message_url.write() = Some(base);

    let err = transport.request("tools/call", None).await.unwrap_err();
    assert_eq!(
        transport.redirects_followed.load(Ordering::SeqCst),
        1,
        "precondition: the policy must have followed exactly one hop, or this \
         row proves nothing about the redirect case: {err}"
    );
    assert!(
        err.to_string().contains("connection failed"),
        "precondition: the hop must have been REFUSED. A timeout or a rejected \
         redirect would satisfy every other assertion here while testing \
         nothing about the redirect case: {err}"
    );
    assert!(
        !err.is_pre_dispatch(),
        "the 307 re-submitted the body, so the redirecting origin may already \
         have executed the call; releasing the idempotency key here would \
         admit a second execution: {err}"
    );
    assert!(matches!(err, Error::Transport(_)), "{err}");

    server.abort();
}

/// The positive control beside it: no redirect, connect refused, key released.
/// Without this row the counter could be wired to a constant `false` and the
/// falsifier above would still be green.
#[tokio::test]
async fn an_unredirected_connect_failure_is_pre_dispatch_end_to_end() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let base = format!("http://{addr}/mcp");
    let transport =
        HttpTransport::new(&base, HashMap::new(), Duration::from_secs(5), true).unwrap();
    *transport.message_url.write() = Some(base);

    let err = transport.request("tools/call", None).await.unwrap_err();
    assert_eq!(transport.redirects_followed.load(Ordering::SeqCst), 0);
    assert!(
        err.to_string().contains("connection failed"),
        "precondition: the port must have refused, not timed out: {err}"
    );
    assert!(
        err.is_pre_dispatch(),
        "a refused connection wrote no bytes, so the key must be released: {err}"
    );
}

// =============================================================================
// MIK-7272.SUB.2b — the outbound half over HTTP.
//
// Plan rows: docs/design/2026-08-31-cluster-b-connection-invariance-test-plan.md
// :58 (S-02, "over stdio and over HTTP") and :59 (S-03, per-request isolation).
// The correlation here is the framing, not a token: every frame on a response
// stream belongs to the request that opened it.
// =============================================================================

fn sse_body(notifications: &[&str], id: u64) -> String {
    use std::fmt::Write as _;
    let mut body = String::new();
    for note in notifications {
        body.push_str("data: ");
        body.push_str(note);
        body.push_str("\n\n");
    }
    let _ = write!(
        body,
        "data: {{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{\"ok\":true}}}}\n\n"
    );
    body
}

const PROGRESS: &str = r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"tok-a","progress":1}}"#;
const MESSAGE: &str = r#"{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"working"}}"#;

/// S-02 over HTTP, both methods. The token-less `notifications/message` is the
/// half stdio cannot carry: here the stream itself names the owner.
#[tokio::test]
async fn http_forwards_both_notification_methods_to_the_callers_sink() {
    let body = sse_body(&[PROGRESS, MESSAGE], 1);

    let (response, notifications) = crate::transport::notification_sink::collect(
        sse_decoder::decode_sse_exchange(sse_stream(body)),
    )
    .await;

    assert!(response.is_ok(), "the caller still gets its result");
    assert_eq!(notifications.len(), 2);
    assert_eq!(notifications[0].method, "notifications/progress");
    assert_eq!(
        notifications[1].method, "notifications/message",
        "a token-less notification is attributable over HTTP, and only here"
    );
}

/// S-03 over HTTP, the negative control. Two calls in flight; a notification on
/// one response stream must not cross into the other's sink. The isolation is
/// structural -- two calls are two tasks, so two sinks -- and the identical
/// progress token in both bodies is there to prove the token is not what does
/// the routing on this transport.
#[tokio::test]
async fn http_never_crosses_a_notification_between_two_calls_in_flight() {
    let mine = sse_body(&[PROGRESS], 1);
    let theirs = sse_body(
        &[
            r#"{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"not yours"}}"#,
        ],
        2,
    );

    let left = tokio::spawn(crate::transport::notification_sink::collect(async move {
        tokio::task::yield_now().await;
        sse_decoder::decode_sse_exchange(sse_stream(mine))
            .await
            .map(|_| ())
    }));
    let right = tokio::spawn(crate::transport::notification_sink::collect(async move {
        sse_decoder::decode_sse_exchange(sse_stream(theirs))
            .await
            .map(|_| ())
    }));

    let (_, l) = left.await.unwrap();
    let (_, r) = right.await.unwrap();

    assert_eq!(l.len(), 1);
    assert_eq!(l[0].method, "notifications/progress");
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].method, "notifications/message");
}

/// A backend that raises nothing still answers, and the sink stays empty --
/// the `Accept`-negotiated stream is a conforming answer either way.
#[tokio::test]
async fn http_leaves_the_sink_empty_when_the_backend_raises_nothing() {
    let (response, notifications) = crate::transport::notification_sink::collect(
        sse_decoder::decode_sse_exchange(sse_stream(sse_body(&[], 1))),
    )
    .await;

    assert!(response.is_ok());
    assert!(notifications.is_empty());
}

/// Serve one fixed status and body to every POST, substituting the caller's own
/// JSON-RPC `id` wherever the template contains `{id}`, and count the POSTs.
/// The count is what rows 16 and 16b read: the retry decision is not observable
/// from the error alone, only from how many times the peer was asked.
async fn spawn_fixed_response_server(
    status: axum::http::StatusCode,
    body_template: &'static str,
) -> (
    std::net::SocketAddr,
    Arc<std::sync::atomic::AtomicU32>,
    tokio::task::JoinHandle<()>,
) {
    use axum::{Router, extract::State, http::StatusCode, response::IntoResponse, routing::post};

    type FixedState = (StatusCode, &'static str, Arc<std::sync::atomic::AtomicU32>);

    async fn handler(
        State((status, template, hits)): State<FixedState>,
        body: String,
    ) -> axum::response::Response {
        hits.fetch_add(1, Ordering::Relaxed);
        let id = serde_json::from_str::<Value>(&body)
            .ok()
            .and_then(|v| v.get("id").cloned())
            .map_or_else(|| "null".to_string(), |v| v.to_string());
        (status, template.replace("{id}", &id)).into_response()
    }

    let hits = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().route("/mcp", post(handler)).with_state((
        status,
        body_template,
        Arc::clone(&hits),
    ));
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, hits, server)
}

/// Three attempts with no real backoff, so a row can distinguish "asked once"
/// from "asked until the policy ran out" without spending wall time on it.
fn three_attempt_policy() -> crate::failsafe::RetryPolicy {
    crate::failsafe::RetryPolicy {
        enabled: true,
        max_attempts: 3,
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(1),
        multiplier: 1.0,
    }
}

/// Drive one request through the same retry wrapper `Backend::request` uses
/// (`src/backend/ops.rs:257`), so the retry assertion reads the production
/// decision rather than a classifier this test invented.
async fn request_through_retry(
    transport: &Arc<HttpTransport>,
    method: &str,
) -> std::result::Result<crate::protocol::JsonRpcResponse, Error> {
    let policy = three_attempt_policy();
    crate::failsafe::with_retry(&policy, "row-16", || {
        let transport = Arc::clone(transport);
        let method = method.to_string();
        async move { transport.request(&method, None).await }
    })
    .await
}

/// Row 16 - a non-probe caller receiving a status-carried JSON-RPC error sees
/// the peer's own refusal, and is not retried. The assertions read the variant
/// and the ask count, never the rendered string. What this row separates is a
/// classification, and the error type has a rendering collision by design:
/// `Error::TransportConnect`'s `Display` is byte-identical to
/// `Error::Transport`'s (`src/error.rs:158-167`), so a string assertion cannot
/// say which transport variant it caught, and the message this row does read -
/// the peer's own text - would survive a wrong variant intact.
///
/// The status is 405 and not 404 deliberately. A 404 is the one status already
/// entangled with session recovery - `is_session_expired_error`
/// (`src/transport/http/mod.rs:164`) matches on a message starting `http 404` -
/// so a 404 here would make this row and row 16d the same response shape,
/// distinguished only by the error code and whether a session was set. Nothing
/// this row pins needs 404; leaving it to row 16d keeps the two verdicts
/// independent. 400 and 426 are likewise avoided: they are the version-mismatch
/// statuses the branch above already claims (`mod.rs:1289`).
#[tokio::test]
async fn row_16_a_status_carried_json_rpc_error_reaches_the_caller_as_json_rpc() {
    let (addr, hits, server) = spawn_fixed_response_server(
        axum::http::StatusCode::METHOD_NOT_ALLOWED,
        r#"{"jsonrpc":"2.0","id":{id},"error":{"code":-32601,"message":"Method not found: tools/list"}}"#,
    )
    .await;

    let transport = make_transport(&format!("http://{addr}/mcp"));
    *transport.message_url.write() = Some(format!("http://{addr}/mcp"));

    let err = request_through_retry(&transport, "tools/list")
        .await
        .expect_err("a refused call must not report success");

    match &err {
        Error::JsonRpc { code, message, .. } => {
            assert_eq!(
                *code,
                crate::protocol::era::METHOD_NOT_FOUND_CODE,
                "the peer's own code must survive the status carriage"
            );
            assert!(
                message.contains("Method not found"),
                "the peer's message must replace the rendered status, got: {message}"
            );
        }
        other => panic!(
            "a status-carried JSON-RPC error must reach the caller as Error::JsonRpc, got: {other:?}"
        ),
    }
    assert_eq!(
        hits.load(Ordering::Relaxed),
        1,
        "a refusal is terminal: retrying it asks a peer that already answered"
    );

    server.abort();
}

/// Row 16e - the referee for section 3's ruling 2b, which rows 16 and 16d
/// cannot settle between them: 16 uses a 405 and 16d a session-shaped 404, so
/// neither forces a 404 *refusal* to become `Error::JsonRpc`. A design that
/// exempted 404 from body parsing to protect session recovery would keep both
/// green while making the status-carried arm unreachable on the real HTTP path,
/// because 404 is the refusal carriage `STATELESS.5b` names.
///
/// The stale session is planted deliberately. Without it the 404 branch of
/// `is_session_expired_error` (`src/transport/http/mod.rs:164`) has nothing to
/// recover and the row would pass for the wrong reason; with it, one hit proves
/// the refusal neither re-initialized nor retried.
#[tokio::test]
async fn row_16e_a_404_carrying_a_refusal_is_terminal_and_does_not_reinitialize() {
    let (addr, hits, server) = spawn_fixed_response_server(
        axum::http::StatusCode::NOT_FOUND,
        r#"{"jsonrpc":"2.0","id":{id},"error":{"code":-32601,"message":"Method not found: tools/list"}}"#,
    )
    .await;

    let transport = make_transport(&format!("http://{addr}/mcp"));
    *transport.message_url.write() = Some(format!("http://{addr}/mcp"));
    transport
        .sessions
        .write()
        .insert(String::new(), "stale-session".to_string());

    let err = request_through_retry(&transport, "tools/list")
        .await
        .expect_err("a refused call must not report success");

    match &err {
        Error::JsonRpc { code, .. } => assert_eq!(
            *code,
            crate::protocol::era::METHOD_NOT_FOUND_CODE,
            "a 404 is the spec's refusal carriage; the peer's code must survive it"
        ),
        other => panic!(
            "a 404 carrying a refusal must reach the caller as Error::JsonRpc, got: {other:?}"
        ),
    }
    assert_eq!(
        hits.load(Ordering::Relaxed),
        1,
        "a refusal is terminal even under 404: no retry and no re-initialize"
    );

    server.abort();
}

/// Row 16b - the other half of the same branch, and it passes today: a non-2xx
/// whose body carries no JSON-RPC error is still an opaque fault, and is still
/// retried. Split from row 16 so neither verdict masks the other.
#[tokio::test]
async fn row_16b_a_non_2xx_without_a_json_rpc_error_body_is_still_retried() {
    let (addr, hits, server) = spawn_fixed_response_server(
        axum::http::StatusCode::BAD_GATEWAY,
        "<html><body>502 Bad Gateway</body></html>",
    )
    .await;

    let transport = make_transport(&format!("http://{addr}/mcp"));
    *transport.message_url.write() = Some(format!("http://{addr}/mcp"));

    let err = request_through_retry(&transport, "tools/list")
        .await
        .expect_err("a 502 must not report success");

    assert!(
        matches!(err, Error::Transport(_)),
        "an opaque gateway fault is not the peer speaking, got: {err:?}"
    );
    assert_eq!(
        hits.load(Ordering::Relaxed),
        3,
        "an opaque fault stays retryable; narrowing that is a silent availability loss"
    );

    server.abort();
}

/// Row 16f - the retry boundary of the same branch. A peer under load can echo
/// the request id in a JSON-RPC error body while its status says "ask again".
/// Reading that as the peer's considered answer would take the retry away from
/// exactly the case the retry exists for, so a transient status keeps the
/// opaque fault the retry classifiers already understand.
#[tokio::test]
async fn row_16f_a_transient_status_carrying_a_json_rpc_error_is_still_retried() {
    let (addr, hits, server) = spawn_fixed_response_server(
        axum::http::StatusCode::TOO_MANY_REQUESTS,
        r#"{"jsonrpc":"2.0","id":{id},"error":{"code":-32000,"message":"rate limited"}}"#,
    )
    .await;

    let transport = make_transport(&format!("http://{addr}/mcp"));
    *transport.message_url.write() = Some(format!("http://{addr}/mcp"));

    let err = request_through_retry(&transport, "tools/list")
        .await
        .expect_err("a 429 must not report success");

    assert!(
        matches!(err, Error::Transport(_)),
        "a peer that says 'ask again' has not answered, got: {err:?}"
    );
    assert_eq!(
        hits.load(Ordering::Relaxed),
        3,
        "a transient status stays retryable; a JSON-RPC body must not make it terminal"
    );

    server.abort();
}

/// Row 12 - the four body shapes the new parsing branch must NOT claim. Each
/// stays an opaque transport fault, which is what keeps the health probe
/// restarting a dead backend rather than filing a proxy's error page as a
/// considered refusal. Passes today and must keep passing: it exists to catch
/// the branch widening past what it was scoped to.
#[tokio::test]
async fn row_12_a_non_2xx_body_that_is_not_the_peers_refusal_stays_a_transport_fault() {
    const SHAPES: [(&str, &str); 4] = [
        ("absent", ""),
        ("not JSON", "<html><body>502 Bad Gateway</body></html>"),
        (
            "JSON with no error member",
            r#"{"jsonrpc":"2.0","id":{id},"result":{}}"#,
        ),
        (
            "an error under a foreign id",
            r#"{"jsonrpc":"2.0","id":"not-the-callers-id","error":{"code":-32601,"message":"Method not found"}}"#,
        ),
    ];

    for (label, body) in SHAPES {
        let (addr, _hits, server) =
            spawn_fixed_response_server(axum::http::StatusCode::BAD_GATEWAY, body).await;

        let transport = make_transport(&format!("http://{addr}/mcp"));
        *transport.message_url.write() = Some(format!("http://{addr}/mcp"));

        let err = transport
            .request("tools/list", None)
            .await
            .expect_err("a 502 must not report success");

        assert!(
            matches!(err, Error::Transport(_)),
            "a body that is {label} is not the peer refusing, got: {err:?}"
        );

        server.abort();
    }
}

/// Row 16d - a 404 whose body carries the session-expiry refusal as a JSON-RPC
/// error must still drive session recovery.
///
/// `is_session_expired_error` (`src/transport/http/mod.rs:164`) only inspects
/// `Error::Transport` text, and only matches a message starting `http 404`. The
/// new parsing branch turns exactly this response into `Error::JsonRpc`, at
/// which point the classifier stops firing and a remote that invalidates its
/// session on token refresh is never re-initialized. The existing 404 recovery
/// test answers with a bare text body, so it cannot see this: it keeps passing
/// through the same regression.
#[tokio::test]
async fn row_16d_a_404_carrying_a_session_error_body_still_reinitializes() {
    use axum::{
        Json, Router,
        extract::State,
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
        routing::post,
    };
    use serde_json::json;

    const FRESH_SESSION: &str = "fresh-session-after-json-404";

    async fn mcp_handler(
        State(hits): State<Arc<std::sync::atomic::AtomicU32>>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> axum::response::Response {
        hits.fetch_add(1, Ordering::Relaxed);
        let session = headers
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();

        if body["method"] == "initialize" {
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
            return (
                StatusCode::OK,
                Json(json!({"jsonrpc": "2.0", "id": body["id"], "result": {"ok": true}})),
            )
                .into_response();
        }

        // The stale session, refused as a well-formed JSON-RPC error under a
        // 404 rather than as opaque text.
        (
            StatusCode::NOT_FOUND,
            Json(json!({
                "jsonrpc": "2.0",
                "id": body["id"],
                "error": {"code": -32015, "message": "Session not found"}
            })),
        )
            .into_response()
    }

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
    set_default_session(&transport, "stale-session-killed-on-refresh");

    let response = transport
        .request("tools/list", None)
        .await
        .expect("session recovery must carry the request through");

    assert!(
        response.error.is_none(),
        "the retried request after re-initialize must succeed"
    );
    assert_eq!(
        default_session(&transport).as_deref(),
        Some(FRESH_SESSION),
        "the stale session must be replaced, not kept"
    );

    server.abort();
}
