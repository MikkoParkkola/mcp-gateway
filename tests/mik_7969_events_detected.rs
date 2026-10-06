// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7969: upstream-notification events follow the transport a backend
//! actually connected with, not the `streamable_http` key alone.
//!
//! Since #3072 an unset key means "detect at connect", and `add --url` writes
//! none, so a backend that speaks Streamable HTTP was refused
//! `backend.<x>.resources_changed` with `sse_handshake_transport` by config
//! alone. A subscribe now resolves the transport first. Receiver rows need
//! `SSL_CERT_FILE`, honoured only on Unix other than Apple.
#![cfg(all(unix, not(target_vendor = "apple")))]

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

use delivery::start_cfg;
use gateway::{ALICE, Gateway, error};
use mcp_http_servers::{Hits, sse_server, streamable_server};
use receiver::{Receiver, whsec};
use serde_json::{Value, json};
use upstream_peer::{Era, HttpPeer};
use upstream_sub::{sub, sub_params, upstream_config};

const RESOURCES_CHANGED: &str = "backend.x.resources_changed";

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
    let cfg = upstream_config(dir.path(), json!({"http_url": peer.url}), &[]);
    let gw = start_cfg(dir.path(), &receiver, cfg).await;
    sub(&gw, ALICE, RESOURCES_CHANGED, &receiver, json!({})).await;
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
    let cfg = upstream_config(
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
    let cfg = upstream_config(dir.path(), json!({"http_url": DEAD}), &[]);
    let gw = start_cfg(dir.path(), &receiver, cfg).await;
    let answer = subscribe(&gw, &receiver).await;
    let err = error(&answer);
    assert!(
        !err.is_null(),
        "an unreachable backend cannot subscribe: {answer}"
    );
    assert_ne!(
        err["data"]["reason"], "sse_handshake_transport",
        "the transport was never learned: {answer}"
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
    let cfg = upstream_config(
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
