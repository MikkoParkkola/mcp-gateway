// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;
use crate::security::http_diagnostics::safe_http_status_error;
use std::collections::HashMap;
use std::time::Duration;

/// RFC-0061 §2.4 startup, driven through the lifecycle rather than through this
/// transport alone: the handshake decision is taken in `Backend::start_entry`,
/// so a case that called `HttpTransport` directly could not see it.
mod modern_startup;

/// #2292: per-caller headers on a notification.
mod notify_headers;

/// MIK-7324.COV.3: the legacy SSE handshake, session capture, OAuth bearer.
mod handshake_and_session;

/// build_mcp_headers: the header builder and the close headers.
mod headers;

/// Session expiry, re-initialise and retry (MIK-5982), and per-call headers.
mod session_expiry;

/// An unpinned flavour connects as a Streamable pin does (MIK-8044).
mod unpinned_flavour;

/// Per-identity MCP-Session-Id partitioning (MIK-6784, GW.1).
mod session_partition;

/// Bearer header value and the OAuth cleartext-transmission guard.
mod oauth_guards;

/// The upstream-tasks capability (the typed opt-in).
mod upstream_tasks;

/// Request-scoped notifications and pre-dispatch connect failures (MIK-7272).
mod notifications;

/// The outbound half over HTTP, and status-carried JSON-RPC errors.
mod outbound;

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

// Helpers shared by more than one behaviour area below.

/// Feed a whole body to the streaming decoder as one chunk.
///
/// Chunk-boundary independence is the decoder's own property, proven in
/// `sse_decoder_tests`. These rows are about what a decoded exchange delivers
/// to the caller and to its sink, so one chunk is the right fixture here.
fn sse_stream(body: impl Into<bytes::Bytes>) -> impl futures::Stream<Item = Result<bytes::Bytes>> {
    futures::stream::iter(vec![Ok(body.into())])
}

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

// =========================================================================
// Construction
// =========================================================================

#[test]
fn new_creates_transport_with_defaults() {
    let t = make_transport("http://localhost:8080/mcp");
    assert_eq!(t.base_url, "http://localhost:8080/mcp");
    assert_eq!(*t.streamable_http.read(), Some(true));
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
    assert_eq!(*t.streamable_http.read(), Some(false));
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

#[path = "status_typing_tests.rs"]
mod status_typing;
