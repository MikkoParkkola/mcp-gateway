// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The wire values the web shell branches on, read from the real
//! `GET /ui/api/status` serialization, never from source text: the server
//! `state` words its glossary table keys on, `circuit_state` (including
//! `half_open`), `running` and `next_retry_at`.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::Request;
use serde_json::Value;
use tower::ServiceExt;

use super::{http_backend_at, scoped_auth_config, test_router_app_state_with_auth_and_config};
use crate::backend::Backend;
use crate::backend::server_state::ServerState;
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
use crate::failsafe::CircuitState;
use crate::gateway::router::create_router;

/// The admin view's row for the one registered backend, `reset` after it trips.
async fn row_of(backend: Arc<Backend>, act: impl FnOnce(&Backend)) -> Value {
    let (state, _dir) = test_router_app_state_with_auth_and_config(
        &scoped_auth_config(true),
        crate::config::Config::default(),
    )
    .await;
    assert!(state.backends.register(Arc::clone(&backend)), "registered");
    act(&backend);
    let response = create_router(state)
        .oneshot(
            Request::builder()
                .uri("/ui/api/status")
                .header("authorization", "Bearer scoped-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).expect("JSON");
    body["servers"][0].clone()
}

fn quick_reset_backend() -> Arc<Backend> {
    let mut failsafe = FailsafeConfig::default();
    failsafe.circuit_breaker.reset_timeout = Duration::from_millis(200);
    Arc::new(Backend::new(
        "wire",
        BackendConfig {
            transport: TransportConfig::Http {
                http_url: "http://127.0.0.1:9".to_string(),
                streamable_http: Some(false),
                protocol_version: None,
            },
            enabled: true,
            ..BackendConfig::default()
        },
        &failsafe,
        Duration::from_secs(60),
    ))
}

/// A server nothing has gone wrong with: closed, not running, no retry time.
#[tokio::test]
async fn a_quiet_server_reads_closed_not_running_and_no_retry_time() {
    let row = row_of(http_backend_at("wire", "http://127.0.0.1:9"), |_| {}).await;
    assert_eq!(row["circuit_state"], "closed", "{row}");
    assert_eq!(row["running"], false, "a boolean, not a string: {row}");
    assert!(row["next_retry_at"].is_null(), "{row}");
    assert_eq!(row["state"], "dormant", "{row}");
}

/// An open breaker reads `open`, state `paused`, and a retry time the shell can parse.
#[tokio::test]
async fn an_open_breaker_reads_open_paused_with_an_rfc3339_retry_time() {
    let row = row_of(http_backend_at("wire", "http://127.0.0.1:9"), |b| {
        b.trip_circuit_breaker_for_test();
    })
    .await;
    assert_eq!(row["circuit_state"], "open", "{row}");
    assert_eq!(row["state"], "paused", "{row}");
    let at = row["next_retry_at"].as_str().expect("a string");
    chrono::DateTime::parse_from_rfc3339(at).expect("an RFC 3339 time");
}

/// After the reset timeout the breaker lets a probe through: `half_open`, still `paused`.
#[tokio::test]
async fn a_half_open_breaker_reads_half_open_paused_with_a_retry_time() {
    let row = row_of(quick_reset_backend(), |b| {
        b.trip_circuit_breaker_for_test();
        std::thread::sleep(Duration::from_millis(300));
        let breaker = Arc::clone(&b.shared_entry_for_test().failsafe.circuit_breaker);
        assert!(breaker.can_proceed(), "the probe is let through");
        assert_eq!(breaker.state(), CircuitState::HalfOpen);
    })
    .await;
    assert_eq!(row["circuit_state"], "half_open", "{row}");
    assert_eq!(row["state"], "paused", "{row}");
    let at = row["next_retry_at"].as_str().expect("a string");
    chrono::DateTime::parse_from_rfc3339(at).expect("an RFC 3339 time");
}

/// Every word the shell's glossary keys on, and every breaker word it reads.
#[test]
fn every_state_and_breaker_word_the_shell_reads_is_what_the_server_sends() {
    let states = [
        (ServerState::Running, "running"),
        (ServerState::Slow, "slow"),
        (ServerState::Paused, "paused"),
        (ServerState::Dormant, "dormant"),
        (ServerState::Unhealthy, "unhealthy"),
        (ServerState::Refused, "refused"),
        (ServerState::NeedsSignIn, "needs_sign_in"),
        (ServerState::Unmanaged, "unmanaged"),
    ];
    for (state, word) in states {
        assert_eq!(serde_json::to_value(state).unwrap(), word);
    }
    for (state, word) in [
        (CircuitState::Closed, "closed"),
        (CircuitState::Open, "open"),
        (CircuitState::HalfOpen, "half_open"),
    ] {
        assert_eq!(state.as_str(), word);
    }
}
