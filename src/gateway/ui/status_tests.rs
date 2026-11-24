// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The status row's wire values, beside the private type that serializes them,
//! and the full view's rows for servers the config holds switched off.

use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use serde_json::Value;
use tower::ServiceExt;

use super::ServerStatus;
use crate::backend::Backend;
use crate::clock::test_clock;
use crate::config::{
    ApiKeyConfig, ApiKeyKind, AuthConfig, BackendConfig, FailsafeConfig, TransportConfig,
};
use crate::counters::{Call, CounterStore, Label, Tally};
use crate::gateway::router::{AppState, create_router};

/// Every server `state` word the web shell's glossary keys on, as the status
/// row type serializes it (the struct `GET /ui/api/status` returns per server).
#[test]
fn every_server_state_serializes_to_the_word_the_shell_reads() {
    use crate::backend::server_state::ServerState;
    let row = |state| ServerStatus {
        name: "x".to_owned(),
        running: false,
        transport: "http".to_owned(),
        tools_cached: 0,
        request_count: Some(0),
        calls_24h: None,
        calls_prev_24h: None,
        circuit_state: Some("closed".to_owned()),
        circuit_trips: Some(0),
        current_failures: Some(0),
        healthy: Some(true),
        success_count: Some(0),
        failure_count: Some(0),
        latency_p50_ms: None,
        latency_p95_ms: None,
        latency_p99_ms: None,
        state,
        reason: String::new(),
        next_retry_at: None,
        cleartext_credentials_accepted: false,
        needs_sign_in: false,
        sign_in: None,
        sign_in_flow: None,
    };
    for (state, word) in [
        (ServerState::Running, "running"),
        (ServerState::Slow, "slow"),
        (ServerState::Paused, "paused"),
        (ServerState::Dormant, "dormant"),
        (ServerState::Unhealthy, "unhealthy"),
        (ServerState::Refused, "refused"),
        (ServerState::NeedsSignIn, "needs_sign_in"),
        (ServerState::Unmanaged, "unmanaged"),
    ] {
        let wire = serde_json::to_value(row(state)).expect("serializes");
        assert_eq!(wire["state"], word, "{wire}");
    }
}

const ADMIN_KEY: &str = "status-off-admin";
const VIEWER_KEY: &str = "status-off-viewer";
/// The server the registry holds.
const LIVE: &str = "alpha";
/// The server the config holds with `enabled: false`.
const OFF: &str = "zeta";
/// 2026-06-15T12:00:00Z, a day with no clock change.
const NOW: u64 = 1_781_524_800;

fn key(name: &str, admin: bool) -> ApiKeyConfig {
    ApiKeyConfig {
        key_sha256: Some(crate::config::api_key_digest_spec(name.as_bytes())),
        name: name.to_owned(),
        backends: vec!["*".to_owned()],
        admin,
        kind: ApiKeyKind::Shared,
        ..ApiKeyConfig::default()
    }
}

fn server(enabled: bool, streamable: bool) -> BackendConfig {
    BackendConfig {
        transport: TransportConfig::Http {
            http_url: "http://127.0.0.1:9/mcp".to_owned(),
            streamable_http: Some(streamable),
            protocol_version: None,
        },
        enabled,
        ..BackendConfig::default()
    }
}

/// A gateway running `LIVE`, with `OFF` written in its config switched off,
/// and three calls to `OFF` kept in the counter store from before.
async fn gateway() -> (Arc<AppState>, impl Sized) {
    let auth = AuthConfig {
        enabled: true,
        api_keys: vec![key(ADMIN_KEY, true), key(VIEWER_KEY, false)],
        ..AuthConfig::default()
    };
    let made = crate::gateway::router::tests::audience_state(&auth, (None, None), |m| m).await;
    let state = &made.0;
    let live = Arc::new(Backend::new(
        LIVE,
        server(true, false),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    assert!(state.backends.register(live), "register {LIVE}");
    state.live_config.edit(|c| {
        c.backends.insert(LIVE.to_owned(), server(true, false));
        c.backends.insert(OFF.to_owned(), server(false, true));
    });
    let store = Arc::new(CounterStore::new(0));
    state.meta_mcp.set_counters(Arc::clone(&store));
    for _ in 0..3 {
        let call = Call {
            caller: "key:a",
            server: Label::Known(OFF),
            tool: Label::Untrusted,
            tally: Tally::default(),
        };
        store.record(&call, NOW - 600, &crate::local_day::host_zone());
    }
    made
}

async fn status(state: &Arc<AppState>, bearer: &str) -> Value {
    let request = Request::builder()
        .uri("/ui/api/status")
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .body(Body::empty())
        .expect("request builds");
    let response = create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .expect("the router is infallible");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body reads");
    serde_json::from_slice(&bytes).expect("a JSON body")
}

/// A server switched off in the config is a row of the full view: not
/// running, the `off` state, its configured transport, no tools, the calls
/// its history keeps, and null wherever only a live backend could answer.
/// The counts-only view still counts the running servers alone.
#[tokio::test]
async fn a_switched_off_server_is_listed_off_with_null_live_figures() {
    let _clock = test_clock::at_secs(NOW);
    let (state, _dir) = gateway().await;
    let body = status(&state, ADMIN_KEY).await;
    let rows = body["servers"]
        .as_array()
        .unwrap_or_else(|| panic!("premise: the admin gets the full view: {body}"));
    assert_eq!(rows.len(), 2, "both servers are listed: {body}");
    let find = |name: &str| rows.iter().find(|row| row["name"] == name);
    let off = find(OFF).unwrap_or_else(|| panic!("no row for {OFF}: {body}"));
    assert_eq!(off["running"], false, "{off}");
    assert_eq!(off["state"], "off", "{off}");
    assert_eq!(off["transport"], "streamable-http", "{off}");
    assert_eq!(off["tools_cached"], 0, "{off}");
    assert_eq!(off["calls_24h"], 3, "its kept history: {off}");
    assert_eq!(off["reason"], "", "{off}");
    assert_eq!(off["next_retry_at"], Value::Null, "{off}");
    assert_eq!(off["cleartext_credentials_accepted"], false, "{off}");
    assert_eq!(off["needs_sign_in"], false, "{off}");
    assert!(off.get("sign_in").is_none(), "{off}");
    assert!(off.get("sign_in_flow").is_none(), "{off}");
    for member in [
        "circuit_state",
        "circuit_trips",
        "current_failures",
        "healthy",
        "request_count",
        "success_count",
        "failure_count",
        "latency_p50_ms",
        "latency_p95_ms",
        "latency_p99_ms",
    ] {
        assert!(
            off.get(member).is_some_and(Value::is_null),
            "`{member}` is null on the off row: {off}"
        );
    }
    let live = find(LIVE).unwrap_or_else(|| panic!("no row for {LIVE}: {body}"));
    assert_eq!(live["circuit_state"], "closed", "{live}");
    assert!(live["healthy"].is_boolean(), "{live}");
    for member in [
        "circuit_trips",
        "current_failures",
        "request_count",
        "success_count",
        "failure_count",
    ] {
        assert!(live[member].is_u64(), "`{member}` is a number: {live}");
    }
    assert_eq!(body["server_count"], 2, "{body}");
    let breakers: u64 = ["closed", "open", "half_open"]
        .iter()
        .map(|word| body["circuit_breakers"][word].as_u64().unwrap_or(0))
        .sum();
    assert_eq!(breakers, 1, "only the running server has a breaker: {body}");

    let counts = status(&state, VIEWER_KEY).await;
    assert!(
        counts.get("servers").is_none(),
        "premise: counts only: {counts}"
    );
    assert_eq!(counts["server_count"], 1, "{counts}");
}

/// A server the config now holds switched off while the registry still runs
/// it (a reload not yet applied) is listed once, as the running row.
#[tokio::test]
async fn a_switched_off_entry_still_running_is_listed_once() {
    let _clock = test_clock::at_secs(NOW);
    let (state, _dir) = gateway().await;
    state.live_config.edit(|c| {
        c.backends.insert(LIVE.to_owned(), server(false, false));
    });
    let body = status(&state, ADMIN_KEY).await;
    let names: Vec<&str> = body["servers"]
        .as_array()
        .unwrap_or_else(|| panic!("premise: the full view: {body}"))
        .iter()
        .filter_map(|row| row["name"].as_str())
        .collect();
    assert_eq!(names, [LIVE, OFF], "{body}");
    assert_ne!(
        body["servers"][0]["state"], "off",
        "the registry's row: {body}"
    );
    assert_eq!(body["servers"][0]["circuit_state"], "closed", "{body}");
    assert_eq!(body["server_count"], 2, "{body}");
}
