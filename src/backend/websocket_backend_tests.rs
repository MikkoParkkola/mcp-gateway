// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F17 rows through `Backend`: reconnect after a drop (T6), start failures
//! feed the breaker and `CircuitOpen` names why (T13, T14, T17), one shared
//! socket with transport-minted ids (T15).

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::Backend;
use crate::Error;
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
use crate::transport::websocket_test_server::{Behaviour, WsPeer};

const WAIT: Duration = Duration::from_secs(10);
const THRESHOLD: u32 = 2;

fn failsafe() -> FailsafeConfig {
    let mut config = FailsafeConfig::default();
    config.circuit_breaker.failure_threshold = THRESHOLD;
    config.retry.enabled = false;
    config
}

fn backend(transport: TransportConfig, timeout: Duration) -> Arc<Backend> {
    let config = BackendConfig {
        transport,
        timeout,
        ..Default::default()
    };
    Arc::new(Backend::new("rt", config, &failsafe(), Duration::from_secs(60)))
}

fn ws_backend(url: &str, timeout: Duration) -> Arc<Backend> {
    backend(
        TransportConfig::WebSocket {
            ws_url: url.to_string(),
            protocol_version: None,
        },
        timeout,
    )
}

fn stdio_backend(command: &str) -> Arc<Backend> {
    backend(
        TransportConfig::Stdio {
            command: command.to_string(),
            cwd: None,
            protocol_version: None,
        },
        WAIT,
    )
}

/// A credential-shaped URL for `peer`: none of these literals may surface.
fn credentialed(peer: &WsPeer) -> String {
    format!("ws://f17user:f17pass@127.0.0.1:{}/mcp?token=F17SECRET", peer.port)
}

const CREDENTIALS: [&str; 3] = ["f17user", "f17pass", "F17SECRET"];

async fn call(backend: &Backend, params: Value) -> crate::Result<crate::protocol::JsonRpcResponse> {
    tokio::time::timeout(WAIT, backend.request_with_headers("tools/call", Some(params), &[], None))
        .await
        .expect("the call must not hang")
}

// ── T6 ───────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn t6_the_next_call_after_a_dropped_socket_reconnects() {
    let peer = WsPeer::start(Behaviour::CloseFirstCall).await;
    let backend = ws_backend(&peer.url, WAIT);
    let started = Instant::now();
    call(&backend, json!({"name": "echo"}))
        .await
        .expect_err("the first call dies with its socket");
    assert!(started.elapsed() < Duration::from_secs(2), "fail fast, not at the timeout");
    let response = call(&backend, json!({"name": "echo"}))
        .await
        .expect("the next call rebuilds the transport and succeeds");
    assert!(response.result.is_some());
    assert_eq!(peer.seen.accepts.load(Ordering::SeqCst), 2, "one reconnect");
}

// ── T13 / T14(a) ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn t13_t14a_a_stalled_upgrade_times_out_and_opens_the_breaker_with_its_reason() {
    let peer = WsPeer::start(Behaviour::StallUpgrade).await;
    let backend = ws_backend(&credentialed(&peer), Duration::from_secs(1));
    for attempt in 0..THRESHOLD {
        let started = Instant::now();
        let err = call(&backend, json!({"name": "echo"}))
            .await
            .expect_err("a stalled upgrade fails the call");
        let elapsed = started.elapsed();
        assert!(
            err.to_string().contains("WebSocket connect timed out"),
            "attempt {attempt}: {err}"
        );
        assert!(elapsed >= Duration::from_millis(900), "not before the deadline: {elapsed:?}");
        assert!(elapsed < Duration::from_secs(5), "at the deadline: {elapsed:?}");
    }
    let accepts = peer.seen.accepts.load(Ordering::SeqCst);
    let err = call(&backend, json!({"name": "echo"}))
        .await
        .expect_err("the breaker is open");
    let Error::CircuitOpen { backend: name, .. } = &err else {
        panic!("expected CircuitOpen, got {err:?}");
    };
    assert_eq!(name, "rt");
    assert_eq!(
        peer.seen.accepts.load(Ordering::SeqCst),
        accepts,
        "an open breaker does not connect"
    );
    let text = err.to_string();
    assert!(text.contains("'rt'"), "{text}");
    assert!(text.contains("WebSocket connect timed out"), "{text}");
    for secret in CREDENTIALS {
        assert!(!text.contains(secret), "{text}");
    }
}

// ── T14(b), T14(c): every transport ──────────────────────────────────────────

const MISSING: &str = "/nonexistent/f17-no-such-mcp-server";

#[tokio::test]
async fn t14b_a_stdio_backend_that_cannot_spawn_opens_the_breaker_naming_the_spawn_error() {
    let backend = stdio_backend(MISSING);
    let mut start_error = String::new();
    for _ in 0..THRESHOLD {
        start_error = call(&backend, json!({"name": "echo"}))
            .await
            .expect_err("the command does not exist")
            .to_string();
    }
    let err = call(&backend, json!({"name": "echo"}))
        .await
        .expect_err("the breaker is open");
    assert!(matches!(err, Error::CircuitOpen { .. }), "{err:?}");
    let text = err.to_string();
    assert!(text.contains("'rt'"), "{text}");
    assert!(
        text.contains(&start_error),
        "the refusal carries the start error `{start_error}`: {text}"
    );
}

#[tokio::test]
async fn t14c_a_breaker_that_never_opened_keeps_todays_text() {
    let backend = stdio_backend(MISSING);
    // Forced open with no recorded open event.
    backend.trip_circuit_breaker_for_test();
    let err = call(&backend, json!({"name": "echo"}))
        .await
        .expect_err("the breaker is open");
    assert_eq!(err.to_string(), "Circuit breaker open for backend 'rt'");
}

// ── T17 ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn t17_a_start_failure_on_the_notify_path_counts_toward_the_breaker() {
    let backend = stdio_backend(MISSING);
    tokio::time::timeout(
        WAIT,
        backend.notify_with_headers("notifications/cancelled", None, None),
    )
    .await
    .expect("must not hang")
    .expect_err("the command does not exist");
    assert_eq!(backend.circuit_breaker_stats().current_failures, 1);
}

// ── T15 ──────────────────────────────────────────────────────────────────────

/// Eight callers on one backend, each choosing JSON-RPC id 1 and progress
/// token 1. One socket, one `initialize`; every caller gets its own answer,
/// because the transport mints wire ids and the gateway mints tokens.
#[tokio::test]
async fn t15_concurrent_callers_share_one_socket_and_never_cross_answers() {
    let peer = WsPeer::start(Behaviour::Normal).await;
    let backend = ws_backend(&peer.url, WAIT);
    let calls = (0..8).map(|n| {
        let backend = Arc::clone(&backend);
        let params = json!({
            "name": "echo",
            "arguments": { "caller": n },
            "_meta": { "progressToken": 1 },
            "id": 1
        });
        async move {
            let (fut, _rx) = crate::transport::notification_sink::scope(async move {
                call(&backend, params).await
            });
            (n, fut.await)
        }
    });
    let mut wire_ids = std::collections::HashSet::new();
    let mut tokens = std::collections::HashSet::new();
    for (n, result) in futures::future::join_all(calls).await {
        let response = result.expect("every caller is answered");
        let text = response.result.unwrap()["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string();
        let echo: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(echo["arguments"]["caller"], json!(n), "caller {n} got another's answer");
        wire_ids.insert(echo["wire_id"].to_string());
        tokens.insert(echo["token"].to_string());
    }
    assert_eq!(wire_ids.len(), 8, "the transport mints a distinct wire id per call");
    assert!(!tokens.contains("1"), "the caller's token never reaches the socket");
    assert_eq!(tokens.len(), 8, "each call carries its own minted token");
    assert_eq!(peer.seen.accepts.load(Ordering::SeqCst), 1, "one socket");
    assert_eq!(peer.seen.initialize_params.lock().len(), 1, "one initialize");
}
