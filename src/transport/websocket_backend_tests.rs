// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F17 transport rows against a real in-process peer: headers (T3), fail-fast
//! on close (T6), configured timeout (T7), teardown on a failed start (T9),
//! no raw URL in diagnostics (T10, T10c), `protocol_version` (T12).
//!
//! Timing: every row runs on the real clock. Fail-fast rows bound the wait
//! with a wall-clock `timeout`; the fix answers in milliseconds, the mutant
//! waits out a 30 s default.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use serde_json::json;

use super::{Transport, WebSocketTransport};
use crate::protocol::PROTOCOL_VERSION;
use crate::transport::websocket_test_server::{Behaviour, WsPeer};

const FAST: Duration = Duration::from_secs(1);
const WAIT: Duration = Duration::from_secs(10);

fn transport(url: &str, timeout: Duration) -> Arc<WebSocketTransport> {
    WebSocketTransport::new(url, HashMap::new(), timeout, None)
}

async fn connected(peer: &WsPeer) -> Arc<WebSocketTransport> {
    let t = transport(&peer.url, WAIT);
    tokio::time::timeout(WAIT, t.connect())
        .await
        .expect("connect must not hang")
        .expect("the peer must initialize");
    t
}

// ── T3 ───────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn t3_static_headers_ride_the_upgrade_request() {
    let peer = WsPeer::start(Behaviour::Normal).await;
    let headers = HashMap::from([
        ("Authorization".to_string(), "Bearer rt-token".to_string()),
        ("X-Tenant".to_string(), "acme".to_string()),
    ]);
    let t = WebSocketTransport::new(&peer.url, headers, WAIT, None);
    tokio::time::timeout(WAIT, t.connect())
        .await
        .unwrap()
        .unwrap();
    let seen = peer.seen.upgrade_headers.lock().clone();
    assert_eq!(seen.len(), 1, "one upgrade");
    assert_eq!(
        seen[0].get("authorization").map(String::as_str),
        Some("Bearer rt-token")
    );
    assert_eq!(seen[0].get("x-tenant").map(String::as_str), Some("acme"));
}

/// The header value an operator writes as `${VAR}` reaches the wire expanded:
/// config load expands `headers` for every transport, and the lifecycle hands
/// the loaded map to the transport unchanged.
#[tokio::test]
async fn t3_an_env_reference_in_a_header_reaches_the_upgrade_expanded() {
    let peer = WsPeer::start(Behaviour::Normal).await;
    let dir = tempfile::tempdir().unwrap();
    let env_file = dir.path().join(".env");
    crate::gateway::test_helpers::write_owner_only(&env_file, "F17_RT_TOKEN=expanded-value\n")
        .unwrap();
    let config_path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(
        &config_path,
        format!(
            "env_files: ['{}']\nbackends:\n  rt:\n    ws_url: \"{}\"\n    headers:\n      Authorization: \"Bearer ${{F17_RT_TOKEN}}\"\n",
            env_file.display(),
            peer.url
        ),
    )
    .unwrap();
    let config = crate::config::Config::load(Some(&config_path)).expect("config loads");
    let backend = crate::backend::Backend::new(
        "rt",
        config.backends["rt"].clone(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    );
    tokio::time::timeout(WAIT, backend.start())
        .await
        .unwrap()
        .unwrap();
    let seen = peer.seen.upgrade_headers.lock().clone();
    assert_eq!(
        seen[0].get("authorization").map(String::as_str),
        Some("Bearer expanded-value")
    );
}

// ── T6 ───────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn t6_a_peer_that_closes_mid_call_fails_the_caller_at_once() {
    let peer = WsPeer::start(Behaviour::CloseFirstCall).await;
    let t = connected(&peer).await;
    let started = Instant::now();
    let result = tokio::time::timeout(FAST, t.request("tools/call", Some(json!({"name": "echo"}))))
        .await
        .expect("an in-flight call must fail when the socket closes, not wait out its timeout");
    assert!(
        result.is_err(),
        "the call cannot succeed on a closed socket"
    );
    assert!(started.elapsed() < FAST);
    assert!(!t.is_connected(), "the transport reports the loss");
}

// ── T7 ───────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn t7_the_configured_timeout_bounds_a_request() {
    let peer = WsPeer::start(Behaviour::SilentRequests).await;
    let t = transport(&peer.url, Duration::from_secs(1));
    tokio::time::timeout(WAIT, t.connect())
        .await
        .unwrap()
        .unwrap();
    let started = Instant::now();
    let err = tokio::time::timeout(WAIT, t.request("tools/list", None))
        .await
        .expect("the configured 1 s timeout must fire well before the 30 s default")
        .expect_err("a silent peer times out");
    let elapsed = started.elapsed();
    assert!(matches!(err, crate::Error::BackendTimeout(_)), "{err:?}");
    assert!(
        elapsed >= Duration::from_millis(900),
        "not before the deadline: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "at the configured deadline: {elapsed:?}"
    );
}

// ── T9 ───────────────────────────────────────────────────────────────────────

/// A peer that upgrades and then refuses `initialize`: the start fails naming
/// initialize, and the socket it authenticated does not survive.
#[tokio::test]
async fn t9_a_rejected_initialize_closes_the_socket() {
    let peer = WsPeer::start(Behaviour::RejectInitialize).await;
    let t = transport(&peer.url, WAIT);
    let err = tokio::time::timeout(WAIT, t.connect())
        .await
        .unwrap()
        .expect_err("a rejected initialize fails the start");
    assert!(err.to_string().contains("initialize"), "{err}");
    tokio::time::timeout(FAST, peer.wait_closed(1))
        .await
        .expect("the socket must be closed once the start has failed");
    assert_eq!(peer.seen.accepts.load(Ordering::SeqCst), 1);
    drop(t);
}

/// A peer that never answers `initialize`: the configured timeout fails the
/// start, and the socket closes too.
#[tokio::test]
async fn t9_an_unanswered_initialize_closes_the_socket_at_the_timeout() {
    let peer = WsPeer::start(Behaviour::SilentInitialize).await;
    let t = transport(&peer.url, Duration::from_millis(500));
    tokio::time::timeout(WAIT, t.connect())
        .await
        .unwrap()
        .expect_err("an unanswered initialize fails the start");
    tokio::time::timeout(FAST, peer.wait_closed(1))
        .await
        .expect("the socket must be closed once the start has failed");
    drop(t);
}

/// Drop alone tears the socket down: a transport the lifecycle discards
/// without `close()` cannot orphan its I/O task. Driven through `do_connect`
/// so `connect()`'s own close-on-error cannot be what closes it.
#[tokio::test]
async fn t9_dropping_a_connected_transport_without_close_closes_the_socket() {
    let peer = WsPeer::start(Behaviour::Normal).await;
    let t = transport(&peer.url, WAIT);
    tokio::time::timeout(WAIT, t.do_connect())
        .await
        .unwrap()
        .unwrap();
    drop(t);
    tokio::time::timeout(FAST, peer.wait_closed(1))
        .await
        .expect("dropping the transport must close its socket");
}

// ── T12 ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn t12_a_configured_protocol_version_is_sent_in_initialize() {
    let peer = WsPeer::start(Behaviour::Normal).await;
    let t = WebSocketTransport::new(&peer.url, HashMap::new(), WAIT, Some("2025-06-18".into()));
    tokio::time::timeout(WAIT, t.connect())
        .await
        .unwrap()
        .unwrap();
    let params = peer.seen.initialize_params.lock().clone();
    assert_eq!(params[0]["protocolVersion"], json!("2025-06-18"));
}

#[tokio::test]
async fn t12_an_unset_protocol_version_sends_the_default() {
    let peer = WsPeer::start(Behaviour::Normal).await;
    let _t = connected(&peer).await;
    let params = peer.seen.initialize_params.lock().clone();
    assert_eq!(params[0]["protocolVersion"], json!(PROTOCOL_VERSION));
}

// ── T10 / T10c: no raw URL or handshake credential in diagnostics ────────────

mod diagnostics {
    use std::io::Write;
    use std::sync::Mutex;

    use super::*;

    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Run `body` on a current-thread runtime under a subscriber that writes
    /// through `filter`, so the I/O task spawned on that runtime logs into the
    /// same buffer. Returns the body's value and the captured text.
    fn captured<T>(filter: &str, body: impl std::future::Future<Output = T>) -> (T, String) {
        use tracing_subscriber::layer::SubscriberExt;
        // Keep callsite interest live across tests that log without a scoped
        // subscriber (see `security::firewall::response_tests::capture`).
        static INTEREST: std::sync::Once = std::sync::Once::new();
        INTEREST.call_once(|| {
            let _ = tracing::subscriber::set_global_default(
                tracing_subscriber::Registry::default()
                    .with(tracing::level_filters::LevelFilter::TRACE),
            );
            // tungstenite logs through `log`; bridge it as production does.
            let _ = tracing_log::LogTracer::init();
        });
        let buffer = Buffer::default();
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::registry()
            .with(crate::cap_handshake_logging(
                tracing_subscriber::EnvFilter::new(filter),
            ))
            .with(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .with_writer(move || writer.clone()),
            );
        let value = tracing::subscriber::with_default(subscriber, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(body)
        });
        let text = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        (value, text)
    }

    fn assert_clean(text: &str, secrets: &[&str]) {
        for secret in secrets {
            assert!(
                !text.contains(secret),
                "`{secret}` leaked into diagnostics:\n{text}"
            );
        }
    }

    /// A refused upgrade: the connect line is logged with the origin only, and
    /// neither the log nor the returned error carries userinfo or the token.
    #[test]
    fn t10_a_refused_connect_logs_and_returns_the_origin_only() {
        let (err, text) = captured("debug", async {
            let peer = WsPeer::start(Behaviour::RefuseUpgrade).await;
            let url = format!(
                "ws://f17user:f17pass@127.0.0.1:{}/mcp?token=F17SECRET",
                peer.port
            );
            transport(&url, WAIT)
                .connect()
                .await
                .expect_err("a refused upgrade fails the connect")
                .to_string()
        });
        assert!(
            text.contains("WebSocket connecting"),
            "the connect line is captured:\n{text}"
        );
        assert!(
            text.contains("ws://127.0.0.1"),
            "the origin is logged:\n{text}"
        );
        assert_clean(&text, &["f17user", "f17pass", "F17SECRET"]);
        assert_clean(&err, &["f17user", "f17pass", "F17SECRET"]);
    }

    /// A successful connect: the handshake-complete and initialized lines are
    /// captured, with the origin only.
    #[test]
    fn t10_a_successful_connect_logs_the_origin_only() {
        let ((), text) = captured("debug", async {
            let peer = WsPeer::start(Behaviour::Normal).await;
            let url = format!(
                "ws://f17user:f17pass@127.0.0.1:{}/mcp?token=F17SECRET",
                peer.port
            );
            transport(&url, WAIT)
                .connect()
                .await
                .expect("the peer initializes");
        });
        assert!(text.contains("WebSocket handshake complete"), "{text}");
        assert!(text.contains("WebSocket transport initialized"), "{text}");
        assert_clean(&text, &["f17user", "f17pass", "F17SECRET"]);
    }

    /// Coordinator ruling: at TRACE, with tungstenite named explicitly, the
    /// handshake request dump (query and headers) stays out of the log. The
    /// bridged DEBUG record is the positive control that the bridge is live.
    #[test]
    fn t10c_trace_logging_never_prints_the_handshake_request() {
        let ((), text) = captured("trace,tungstenite=trace", async {
            log::debug!(target: "tungstenite::handshake::client", "f17 bridge control");
            let peer = WsPeer::start(Behaviour::Normal).await;
            let url = format!("ws://127.0.0.1:{}/mcp?token=F17SECRET", peer.port);
            let headers = HashMap::from([(
                "Authorization".to_string(),
                "Bearer F17TOPSECRET".to_string(),
            )]);
            let t = WebSocketTransport::new(&url, headers, WAIT, None);
            t.connect().await.expect("the peer initializes");
        });
        assert!(
            text.contains("f17 bridge control"),
            "the log bridge is live:\n{text}"
        );
        assert_clean(&text, &["F17SECRET", "F17TOPSECRET"]);
    }
}
