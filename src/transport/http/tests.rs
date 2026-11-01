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

/// A resend the lender refuses after an expired session (Unix only: it uses
/// the resend row's held port).
#[cfg(unix)]
mod refusal_over_http;
/// Session expiry, re-initialise and retry (MIK-5982), and per-call headers.
mod session_expiry;
/// A resend after an expired session that never connected may have run.
/// Unix only: the row holds its port with `SO_REUSEPORT`.
#[cfg(unix)]
mod session_expiry_resend;

/// An unpinned flavour connects as a Streamable pin does (MIK-8044).
mod unpinned_flavour;

/// The legacy handshake's protocol-version refusals (MIK-8195 W1).
mod version_refusals;

/// A peer's error body is surfaced only for its own request (MIK-8195 W1).
mod peer_refusal;

/// Per-identity MCP-Session-Id partitioning (MIK-6784, GW.1).
mod session_partition;

/// Bearer header value and the OAuth cleartext-transmission guard.
mod oauth_guards;

/// The upstream-tasks capability (the typed opt-in).
mod upstream_tasks;

/// Request-scoped notifications and pre-dispatch connect failures (MIK-7272).
mod notifications;

/// `MIK-7642.PR.B`: a dropped legacy exchange cancels the backend's call.
mod cancel_on_drop;

/// The outbound half over HTTP, and status-carried JSON-RPC errors.
mod outbound;

/// A required binding's per-user slot sends only what a dispatch
/// in flight lends.
mod lent_slot;
/// The endpoint URL and redirect checks: each refuses a cross-origin hop.
mod origin_checks;

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
            token_refresh_buffer_secs: Some(300),
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

/// MIK-8339: an OAuth transport always shares one login gate with its client.
/// A gated client keeps its own gate; an ungated one is given the transport's.
#[tokio::test]
async fn an_oauth_transport_shares_one_gate_with_its_client() {
    let url = "http://127.0.0.1:1/mcp";
    let gate = Arc::new(crate::oauth::login_gate::LoginGate::default());
    let gated = oauth_client_for(url).with_login_gate(Arc::clone(&gate));
    let t = HttpTransport::new_with_oauth(
        url,
        HashMap::new(),
        Duration::from_secs(5),
        true,
        Some(gated),
        None,
    )
    .unwrap();
    assert!(
        Arc::ptr_eq(&t.login_gate, &gate),
        "a gated client's gate is kept"
    );

    let t = transport_with_oauth(url).unwrap();
    let client_gate = t
        .oauth_client
        .as_ref()
        .expect("an OAuth transport")
        .lock()
        .await
        .login_gate()
        .expect("the ungated client was given a gate");
    assert!(
        Arc::ptr_eq(&t.login_gate, &client_gate),
        "an ungated client is given the transport's own gate"
    );
}

/// One row of [`FOLLOW_CASES`].
type FollowCase = (
    bool,
    &'static [&'static str],
    u16,
    &'static str,
    &'static str,
    bool,
);

/// MIK-8660 G4 cases for `transport_follows_redirect`, as
/// (`hardened`, `private_backends`, status, base, target, followed). A listing
/// matters only under hardened and only for the backend it names ("b").
const FOLLOW_CASES: &[FollowCase] = &[
    (
        false,
        &[],
        301,
        "https://h.test/a",
        "https://h.test/b",
        true,
    ),
    (
        false,
        &[],
        302,
        "https://h.test/a",
        "https://h.test/b",
        true,
    ),
    (
        false,
        &[],
        303,
        "https://h.test/a",
        "https://h.test/b",
        true,
    ),
    (
        false,
        &[],
        307,
        "https://h.test/a",
        "https://h.test/b",
        true,
    ),
    (
        false,
        &[],
        308,
        "https://h.test/a",
        "https://h.test:443/b",
        true,
    ),
    (
        false,
        &[],
        300,
        "https://h.test/a",
        "https://h.test/b",
        false,
    ),
    (
        false,
        &[],
        304,
        "https://h.test/a",
        "https://h.test/b",
        false,
    ),
    (
        false,
        &[],
        302,
        "https://h.test/a",
        "https://g.test/b",
        false,
    ),
    (
        false,
        &[],
        301,
        "http://127.0.0.1:9/a",
        "http://127.0.0.1:9/b",
        false,
    ),
    (
        false,
        &["b"],
        301,
        "http://127.0.0.1:9/a",
        "http://127.0.0.1:9/b",
        false,
    ),
    (
        true,
        &[],
        301,
        "http://127.0.0.1:9/a",
        "http://127.0.0.1:9/b",
        false,
    ),
    (
        true,
        &["c"],
        301,
        "http://127.0.0.1:9/a",
        "http://127.0.0.1:9/b",
        false,
    ),
    (
        true,
        &["b"],
        307,
        "http://127.0.0.1:9/a",
        "http://127.0.0.1:9/b",
        true,
    ),
    (
        true,
        &["b"],
        301,
        "http://127.0.0.1:9/a",
        "http://127.0.0.1:10/b",
        false,
    ),
    (
        true,
        &["b"],
        301,
        "http://[::1]:9/a",
        "http://[::1]:9/b",
        true,
    ),
    (
        false,
        &[],
        301,
        "http://[::1]:9/a",
        "http://[::1]:9/b",
        false,
    ),
];

/// MIK-8660 G4: `transport_follows_redirect` is the transport's decision under
/// the backend's own destination policy, plus the statuses reqwest follows.
#[test]
fn transport_follows_redirect_matches_the_runtime_decision() {
    for &(hardened, private, status, base, target, followed) in FOLLOW_CASES {
        let mut config = crate::config::Config::default();
        if hardened {
            config.security.posture = crate::security::SecurityPosture::Hardened;
        }
        config.security.hardened.private_backends =
            private.iter().map(|name| (*name).to_string()).collect();
        let base_url = Url::parse(base).expect("case URL parses");
        let target_url = Url::parse(target).expect("case URL parses");
        assert_eq!(
            super::transport_follows_redirect(&config, "b", status, &base_url, &target_url),
            followed,
            "{status} {base} -> {target}, hardened {hardened}, private {private:?}"
        );
    }
}

/// C2: a backend's session-expiry refusal carried as its own JSON-RPC error
/// (a non-2xx JSON body) still triggers session recovery, by code or by text.
#[test]
fn a_backends_own_session_expiry_refusal_triggers_recovery() {
    let refusal = |code: i32, message: &str| {
        Error::backend_json_rpc(crate::protocol::JsonRpcError {
            code,
            message: message.to_owned(),
            data: None,
        })
    };
    assert!(is_session_expired_error(&refusal(
        SESSION_NOT_FOUND_CODE,
        "x"
    )));
    assert!(is_session_expired_error(&refusal(
        -32000,
        "Session not found"
    )));
    assert!(!is_session_expired_error(&refusal(-32600, "bad request")));
}
