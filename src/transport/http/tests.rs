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
    assert!(t.session_id.read().is_none());
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
// and notify modes are preserved by the shared helper. No network calls are
// made; HeaderMode is exercised directly.
// =========================================================================

/// SSE mode: no Content-Type, SSE-only Accept, no session header even when
/// session is set, custom headers included, no x-trace-id.
#[tokio::test]
async fn build_headers_sse_mode_baseline() {
    let mut custom = HashMap::new();
    custom.insert("X-Auth-Token".to_string(), "secret".to_string());
    let t = make_transport_with_headers("http://localhost", custom);
    // Pretend a session was established — SSE must NOT forward it.
    *t.session_id.write() = Some("should-not-appear".to_string());

    let map = t.build_mcp_headers(HeaderMode::Sse).await.unwrap();

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

/// send_request mode: Content-Type + combined Accept, session forwarded when
/// present, custom headers included, x-trace-id from ambient trace context.
#[tokio::test]
async fn build_headers_send_request_with_session_and_trace() {
    use crate::gateway::trace;

    let mut custom = HashMap::new();
    custom.insert("X-Custom".to_string(), "val".to_string());
    let t = make_transport_with_headers("http://localhost", custom);
    *t.session_id.write() = Some("sess-abc".to_string());

    let map = trace::with_trace_id("gw-trace-123".to_string(), async {
        t.build_mcp_headers(HeaderMode::Request {
            method: "tools/list",
        })
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

/// send_request mode without a session: no mcp-session-id header at all.
#[tokio::test]
async fn build_headers_send_request_no_session() {
    let t = make_transport("http://localhost");

    let map = t
        .build_mcp_headers(HeaderMode::Request {
            method: "tools/list",
        })
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

/// notify mode: Content-Type + combined Accept, session forwarded, NO custom
/// headers, NO x-trace-id even when ambient trace and custom headers exist.
#[tokio::test]
async fn build_headers_notify_excludes_custom_and_trace() {
    use crate::gateway::trace;

    let mut custom = HashMap::new();
    custom.insert("X-Should-Not-Appear".to_string(), "nope".to_string());
    let t = make_transport_with_headers("http://localhost", custom);
    *t.session_id.write() = Some("notify-sess".to_string());

    let map = trace::with_trace_id("gw-trace-xyz".to_string(), async {
        t.build_mcp_headers(HeaderMode::Notify).await.unwrap()
    })
    .await;

    assert_eq!(map[header::CONTENT_TYPE], "application/json");
    assert_eq!(map[header::ACCEPT], "application/json, text/event-stream");
    assert_eq!(
        map["mcp-session-id"], "notify-sess",
        "notify must include session header"
    );
    assert!(
        !map.contains_key("x-should-not-appear"),
        "notify must NOT include custom headers"
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

    let map = t.build_mcp_headers(HeaderMode::Notify).await.unwrap();

    assert!(!map.contains_key("mcp-session-id"));
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

    let map = t.build_mcp_headers(HeaderMode::Sse).await.unwrap();

    assert_eq!(map["mcp-protocol-version"], "2024-11-05");
}

/// Only request mode emits `x-trace-id`; notify mode suppresses it.
#[tokio::test]
async fn build_headers_trace_flag_gates_trace_header() {
    use crate::gateway::trace;

    let t = make_transport("http://localhost");

    // Notify mode must suppress trace propagation even when ambient trace exists.
    let map_no_trace = trace::with_trace_id("gw-abc".to_string(), async {
        t.build_mcp_headers(HeaderMode::Notify).await.unwrap()
    })
    .await;

    assert!(
        !map_no_trace.contains_key("x-trace-id"),
        "trace:false must suppress x-trace-id"
    );

    // Request mode must include trace propagation when ambient trace exists.
    let map_with_trace = trace::with_trace_id("gw-abc".to_string(), async {
        t.build_mcp_headers(HeaderMode::Request { method: "m" })
            .await
            .unwrap()
    })
    .await;

    assert_eq!(
        map_with_trace["x-trace-id"], "gw-abc",
        "trace:true must emit x-trace-id"
    );
}
