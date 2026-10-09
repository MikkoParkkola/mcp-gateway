// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7969: upstream-notification events follow the transport a backend
//! actually connected with, not the `streamable_http` key alone.
//!
//! Since #3072 an unset key means "detect at connect", and `add --url` writes
//! none, so a backend that speaks Streamable HTTP was refused
//! `backend.<x>.resources_changed` with `sse_handshake_transport` by config
//! alone. A subscribe now resolves the transport first. Receiver rows trust its CA
//! through `Receiver::trust_env` (MIK-8188).
#![cfg(unix)]

#[path = "mik_7630_events/delivery.rs"]
#[allow(dead_code, reason = "shared helpers; each binary uses a subset")]
mod delivery;
#[path = "mik_7630_events/gateway.rs"]
#[allow(dead_code, reason = "shared harness; each binary uses a subset")]
mod gateway;
#[path = "common/mcp_http_servers.rs"]
#[allow(dead_code, reason = "shared fixtures; each binary uses a subset")]
mod mcp_http_servers;
#[path = "mik_7630_events/receiver.rs"]
#[allow(dead_code, reason = "shared receiver; each binary uses a subset")]
mod receiver;
#[path = "mik_7630_events/upstream_peer.rs"]
#[allow(dead_code, reason = "mock peers; each row uses a subset")]
mod upstream_peer;
#[path = "mik_7630_events/upstream_sub.rs"]
#[allow(dead_code, reason = "shared helpers; each binary uses a subset")]
mod upstream_sub;

use std::time::{Duration, Instant};

use delivery::{DEADLINE, records, start_cfg, wait_until};
use gateway::{ALICE, BOB, Gateway, error};
use mcp_http_servers::{Hits, recording, serve, sse_server, streamable_server};
use receiver::{Receiver, whsec};
use serde_json::{Value, json};
use upstream_peer::{Era, HttpPeer};
use upstream_sub::{expect_events, sub, sub_params, upstream_config};

const RESOURCES_CHANGED: &str = "backend.x.resources_changed";
const PROMPTS_CHANGED: &str = "backend.x.prompts_changed";
const RES_CHANGED: &str = "notifications/resources/list_changed";

/// `upstream_config` with no backend warm-started at boot (an empty
/// `warm_start` starts them all), so a connect is the subscribe's own.
#[allow(
    clippy::needless_pass_by_value,
    reason = "call sites build the value inline with json!"
)]
fn cold_config(root: &std::path::Path, backend: Value, extra: &[(&str, Value)]) -> Value {
    let mut cfg = upstream_config(root, backend, extra);
    cfg["meta_mcp"]["warm_start"] = json!(["hooks"]);
    cfg
}

/// A port with no listener.
const DEAD: &str = "http://127.0.0.1:9/mcp";

/// The raw answer to alice subscribing to `backend.x.resources_changed`.
async fn subscribe(gw: &Gateway, receiver: &Receiver) -> Value {
    gw.rpc(
        Some(ALICE),
        "events/subscribe",
        sub_params(
            RESOURCES_CHANGED,
            &receiver.localhost_url(),
            &whsec(32),
            json!({}),
        ),
    )
    .await
}

/// ELIG.1: an unset key on a Streamable HTTP backend, never called before,
/// is offered the events. Before the fix: `-32014 sse_handshake_transport`.
#[tokio::test]
async fn an_unset_key_on_a_streamable_backend_is_offered_the_events() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let peer = HttpPeer::start(Era::Legacy).await;
    let cfg = cold_config(dir.path(), json!({"http_url": peer.url}), &[]);
    let gw = start_cfg(dir.path(), &receiver, cfg).await;
    let id = sub(&gw, ALICE, RESOURCES_CHANGED, &receiver, json!({})).await;
    // Accepted is not enough: a listener must attach and deliver.
    assert!(
        wait_until(DEADLINE, || peer.open_gets() == 1).await,
        "a listener opens the session GET"
    );
    peer.push(RES_CHANGED, json!({}));
    expect_events(&receiver, &id, RESOURCES_CHANGED, 1).await;
}

/// ELIG.3 with a fallback: an explicit `true` on a server that only speaks
/// legacy SSE is refused once the transport is known. Before the fix the
/// key alone made it eligible.
#[tokio::test]
async fn an_explicit_true_that_falls_back_to_sse_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let hits = Hits::default();
    let url = sse_server(&hits).await;
    let cfg = cold_config(
        dir.path(),
        json!({"http_url": url, "streamable_http": true}),
        &[],
    );
    let gw = start_cfg(dir.path(), &receiver, cfg).await;
    let answer = subscribe(&gw, &receiver).await;
    let err = error(&answer);
    assert_eq!(err["code"], -32014, "typed refusal, got {answer}");
    assert_eq!(err["data"]["reason"], "sse_handshake_transport", "{answer}");
}

/// An unset key on an unreachable backend: the transport was never learned,
/// so the subscribe answers the connect failure, not an SSE refusal.
#[tokio::test]
async fn an_unreachable_backend_is_not_reported_as_sse() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let cfg = cold_config(dir.path(), json!({"http_url": DEAD}), &[]);
    let gw = start_cfg(dir.path(), &receiver, cfg).await;
    let answer = subscribe(&gw, &receiver).await;
    let err = error(&answer);
    assert_eq!(
        err["code"], -32000,
        "the backend error, as tools/call answers it: {answer}"
    );
}

/// ELIG.3: an explicit `false` whose connect switched to Streamable HTTP is
/// judged by the transport that answered. Before the fix: refused by config.
#[tokio::test]
async fn an_explicit_false_that_switched_to_streamable_is_offered() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let hits = Hits::default();
    let url = streamable_server(&hits).await;
    let cfg = cold_config(
        dir.path(),
        json!({"http_url": url, "streamable_http": false}),
        &[],
    );
    let gw = start_cfg(dir.path(), &receiver, cfg).await;
    // Connect it once: the SSE GET is refused with 405 and the POST answers.
    let invoked = gw
        .tool_call(
            ALICE,
            "gateway_invoke",
            json!({"server": "x", "tool": "ping", "arguments": {}}),
        )
        .await;
    assert_ne!(invoked["isError"], true, "the backend connects: {invoked}");
    sub(&gw, ALICE, RESOURCES_CHANGED, &receiver, json!({})).await;
}

/// `initialize` requests the peer has answered: one per backend start.
fn starts(peer: &HttpPeer) -> usize {
    peer.frames("initialize").len()
}

/// T2, ELIG.2: an unset key on a server that only speaks legacy SSE is
/// refused, but only after a connect learned it. Red before the fix at the
/// GET assertion: config alone refused it with no connect.
#[tokio::test]
async fn an_unset_key_on_an_sse_server_is_refused_after_connecting() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let hits = Hits::default();
    let url = sse_server(&hits).await;
    let cfg = cold_config(dir.path(), json!({"http_url": url}), &[]);
    let gw = start_cfg(dir.path(), &receiver, cfg).await;
    let answer = subscribe(&gw, &receiver).await;
    let err = error(&answer);
    assert_eq!(err["code"], -32014, "typed refusal, got {answer}");
    assert_eq!(err["data"]["reason"], "sse_handshake_transport", "{answer}");
    let gets = hits
        .lock()
        .expect("hits")
        .iter()
        .filter(|(method, path)| method == axum::http::Method::GET && path == "/sse")
        .count();
    assert!(
        gets >= 1,
        "the transport was learned by a connect: {hits:?}"
    );
}

/// T5 guard (green before the fix): identity propagation is refused before
/// the transport is judged, so the subscribe never connects the backend.
#[tokio::test]
async fn an_identity_backend_is_refused_without_a_connect() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let peer = HttpPeer::start(Era::Legacy).await;
    let backend = json!({
        "http_url": peer.url,
        "identity_propagation": {"strategy": "passthrough",
            "audience": "https://idp.example", "session_mode": "per_user"},
    });
    let gw = start_cfg(dir.path(), &receiver, cold_config(dir.path(), backend, &[])).await;
    let answer = subscribe(&gw, &receiver).await;
    assert_eq!(
        error(&answer)["data"]["reason"],
        "identity_propagation",
        "{answer}"
    );
    assert_eq!(starts(&peer), 0, "no connect for a refused backend");
}

/// T17 guard (green before the fix): an explicit `true` on a Streamable HTTP
/// server, never started, subscribes.
#[tokio::test]
async fn an_explicit_true_on_a_streamable_server_subscribes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let peer = HttpPeer::start(Era::Legacy).await;
    let backend = json!({"http_url": peer.url, "streamable_http": true});
    let gw = start_cfg(dir.path(), &receiver, cold_config(dir.path(), backend, &[])).await;
    sub(&gw, ALICE, RESOURCES_CHANGED, &receiver, json!({})).await;
}

/// T6: an unset key is listed provisionally, and listing connects nothing.
/// Red before the fix at the listing assertion: config alone hid it.
#[tokio::test]
async fn an_unset_key_is_listed_without_a_connect() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let peer = HttpPeer::start(Era::Legacy).await;
    let cfg = cold_config(dir.path(), json!({"http_url": peer.url}), &[]);
    let gw = start_cfg(dir.path(), &receiver, cfg).await;
    let names = gw.event_names(Some(ALICE), Some(RESOURCES_CHANGED)).await;
    assert!(
        names.iter().any(|n| n == RESOURCES_CHANGED),
        "listed while undetected: {names:?}"
    );
    assert_eq!(starts(&peer), 0, "listing never connects a backend");
}

/// T7: concurrent subscribes to one undetected backend share one start.
/// Red before the fix at the first subscribe (refused by config).
#[tokio::test]
async fn concurrent_subscribes_share_one_start() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let peer = HttpPeer::start(Era::Legacy).await;
    let cfg = cold_config(dir.path(), json!({"http_url": peer.url}), &[]);
    let gw = start_cfg(dir.path(), &receiver, cfg).await;
    tokio::join!(
        sub(&gw, ALICE, RESOURCES_CHANGED, &receiver, json!({})),
        sub(&gw, ALICE, PROMPTS_CHANGED, &receiver, json!({})),
        sub(&gw, BOB, RESOURCES_CHANGED, &receiver, json!({})),
    );
    assert_eq!(starts(&peer), 1, "one start for three subscribes");
}

/// A server that accepts connections and never answers: a start that
/// cannot complete.
async fn silent_server() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind silent server");
    let address = listener.local_addr().expect("silent address");
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            held.push(socket);
        }
    });
    format!("http://{address}/mcp")
}

/// T8: a start that never completes bounds the subscribe by the backend
/// timeout, and answers the backend error. Red before the fix at the code
/// assertion: `-32014` by config.
#[tokio::test]
async fn a_start_that_never_completes_is_bounded_by_the_backend_timeout() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let backend = json!({"http_url": silent_server().await, "timeout": "2s"});
    let gw = start_cfg(dir.path(), &receiver, cold_config(dir.path(), backend, &[])).await;
    let began = Instant::now();
    let answer = subscribe(&gw, &receiver).await;
    let took = began.elapsed();
    assert_eq!(
        error(&answer)["code"],
        -32000,
        "the backend error: {answer}"
    );
    assert!(
        took < Duration::from_secs(12),
        "bounded by the timeout: {took:?}"
    );
}

/// T9: an open circuit refuses the subscribe as it refuses `tools/call`,
/// with no connect. Red before the fix at the code assertion.
#[tokio::test]
async fn an_open_circuit_refuses_the_subscribe_without_a_connect() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let hits = Hits::default();
    let record = recording(&hits);
    let app = axum::Router::new().fallback(move |method: axum::http::Method| {
        let record = record.clone();
        async move {
            record(method, "/mcp".into());
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        }
    });
    let url = format!("{}/mcp", serve(app).await);
    let mut cfg = cold_config(dir.path(), json!({"http_url": url}), &[]);
    cfg["failsafe"] = json!({"circuit_breaker":
        {"failure_threshold": 1, "reset_timeout": "10m"}});
    let gw = start_cfg(dir.path(), &receiver, cfg).await;
    let invoke = json!({"server": "x", "tool": "ping", "arguments": {}});
    gw.tool_call(ALICE, "gateway_invoke", invoke.clone()).await;
    let tripped = hits.lock().expect("hits").len();
    assert!(tripped > 0, "the failing start reached the server");
    gw.tool_call(ALICE, "gateway_invoke", invoke).await;
    assert_eq!(
        hits.lock().expect("hits").len(),
        tripped,
        "precondition: the circuit is open"
    );
    let answer = subscribe(&gw, &receiver).await;
    assert_eq!(
        error(&answer)["code"],
        -32000,
        "the circuit refusal: {answer}"
    );
    assert_eq!(hits.lock().expect("hits").len(), tripped, "no connect");
}

/// T21, H2 (MIK-7969 k11c): a backend redeployed as legacy SSE behind the
/// same URL, found by a session recovery while its event stream sits quiet,
/// loses the listener and its listener-only subscription. Nothing on the
/// stream announces the switch and the transport is the same one: only the
/// listener's per-tick live read of the detected transport can end it.
#[tokio::test]
async fn a_recovery_onto_sse_ends_a_quiet_listener() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let peer = HttpPeer::start(Era::Legacy).await;
    let cfg = cold_config(dir.path(), json!({"http_url": peer.url}), &[]);
    let gw = start_cfg(dir.path(), &receiver, cfg).await;
    sub(&gw, ALICE, RESOURCES_CHANGED, &receiver, json!({})).await;
    assert!(
        wait_until(DEADLINE, || peer.open_gets() == 1).await,
        "control: a listener opens the session GET"
    );
    assert_eq!(records(dir.path(), "subs").len(), 1, "control: stored");

    peer.redeploy_as_sse();
    // Any request on the old session finds it gone; the recovery's
    // `initialize` is refused, so the transport falls back to SSE in place.
    let invoke = json!({"server": "x", "tool": "ping", "arguments": {}});
    let call = json!({"name": "gateway_invoke", "arguments": invoke});
    gw.rpc(Some(ALICE), "tools/call", call).await;
    assert!(
        wait_until(DEADLINE, || peer.sse_handshakes() > 0).await,
        "control: the recovery fell back to SSE: {:?}",
        peer.seen()
    );
    assert!(
        wait_until(DEADLINE, || peer.open_gets() == 0).await,
        "the listener outlived the switch to SSE: {}",
        gw.stall_report()
    );
    assert!(
        wait_until(DEADLINE, || records(dir.path(), "subs").is_empty()).await,
        "the listener-only subscription outlived the switch to SSE: {}",
        gw.stall_report()
    );
}
