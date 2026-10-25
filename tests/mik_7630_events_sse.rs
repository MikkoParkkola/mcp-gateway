// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7630.SOURCE.1 P3: upstream events from a legacy HTTP+SSE-handshake
//! backend. The listener runs its own session (GET, `endpoint`, initialize,
//! initialized, then `resources/subscribe`), separate from the calls'.
//!
//! Before P3 a subscription here is refused `-32014 sse_handshake_transport`,
//! so each row goes red at its first subscribe.
#![cfg(unix)]

#[path = "mik_7630_events/delivery.rs"]
#[allow(dead_code, reason = "shared helpers; each binary uses a subset")]
mod delivery;
#[path = "mik_7630_events/gateway.rs"]
#[allow(dead_code, reason = "shared harness; each binary uses a subset")]
mod gateway;
#[path = "mik_7630_events/receiver.rs"]
#[allow(dead_code, reason = "shared receiver; each binary uses a subset")]
mod receiver;
#[path = "mik_7630_events/sse_peer.rs"]
#[allow(dead_code, reason = "mock peer; each row uses a subset")]
mod sse_peer;
#[path = "mik_7630_events/upstream_sub.rs"]
#[allow(dead_code, reason = "shared helpers; each binary uses a subset")]
mod upstream_sub;

use std::time::Duration;

use delivery::{DEADLINE, start_cfg, wait_until};
use gateway::{ALICE, Gateway};
use receiver::Receiver;
use serde_json::{Value, json};
use sse_peer::{Seen, SsePeer, URI_A, URI_B};
use upstream_sub::{delivered, expect_events, sub, unsub, upstream_config};

const UPDATED: &str = "notifications/resources/updated";
const RES_CHANGED: &str = "notifications/resources/list_changed";
const PROMPTS_CHANGED: &str = "notifications/prompts/list_changed";
const TOOLS_CHANGED: &str = "notifications/tools/list_changed";
/// Past the 1 s coalescing window plus delivery.
const QUIET: Duration = Duration::from_secs(3);

fn event(kind: &str) -> String {
    format!("backend.x.{kind}")
}

async fn eventually(what: &str, check: impl FnMut() -> bool) {
    assert!(
        wait_until(DEADLINE, check).await,
        "timed out waiting for: {what}"
    );
}

/// A gateway whose backend `x` is `peer`, by its explicit SSE key.
async fn start(dir: &std::path::Path, receiver: &Receiver, peer: &SsePeer) -> Gateway {
    let cfg = upstream_config(
        dir,
        json!({"http_url": peer.url, "streamable_http": false}),
        &[],
    );
    start_cfg(dir, receiver, cfg).await
}

/// The sessions (other than the calls' session 1) that sent `initialize`:
/// the listener's.
fn listener_sessions(peer: &SsePeer) -> Vec<u32> {
    let mut sessions: Vec<u32> = peer
        .seen()
        .into_iter()
        .filter_map(|s| match s {
            Seen::Post {
                session, method, ..
            } if session > 1 && method == "initialize" => Some(session),
            _ => None,
        })
        .collect();
    sessions.dedup();
    sessions
}

/// The listener's newest session, once it has subscribed `uri`.
async fn subscribed_listener(peer: &SsePeer, uri: &str) -> u32 {
    eventually("the listener session subscribed", || {
        listener_sessions(peer)
            .last()
            .is_some_and(|n| peer.subscribed_on(uri).contains(n))
    })
    .await;
    *listener_sessions(peer).last().expect("a listener session")
}

/// S1 + S2 + S4: a resource update reaches the subscriber; the listener's
/// session is its own and ran the handshake in order.
#[tokio::test]
async fn s1_sse_resource_updates_become_events() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let peer = SsePeer::start().await;
    let gw = start(dir.path(), &receiver, &peer).await;
    let updated = event("resource_updated");

    let alice = sub(&gw, ALICE, &updated, &receiver, json!({"uri": URI_A})).await;
    let session = subscribed_listener(&peer, URI_A).await;

    // S2: the order the spec transport requires, nothing refused before it.
    let methods = peer.methods_on(session);
    assert_eq!(
        methods[..3],
        [
            "initialize",
            "notifications/initialized",
            "resources/subscribe"
        ],
        "handshake order on the listener session: {methods:?}"
    );
    // S4: the calls session is not the listener's.
    assert_ne!(session, 1, "the listener runs its own session");
    assert!(
        !peer
            .methods_on(1)
            .iter()
            .any(|m| m == "resources/subscribe"),
        "no subscribe on the calls session"
    );

    peer.push(session, UPDATED, json!({"uri": URI_A}));
    let got = expect_events(&receiver, &alice, &updated, 1).await;
    assert_eq!(got[0]["data"], json!({"uri": URI_A}));
    peer.push(session, UPDATED, json!({"uri": URI_B}));
    // timing: absence
    tokio::time::sleep(QUIET).await;
    assert_eq!(
        delivered(&receiver, &alice, &updated).len(),
        1,
        "no event for b"
    );
}

/// S3: a peer that answers every POST in its body (as the calls path
/// expects today) works for the listener too.
#[tokio::test]
async fn s3_a_body_answering_peer_also_listens() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let peer = SsePeer::start().await;
    peer.answer_in_body();
    let gw = start(dir.path(), &receiver, &peer).await;
    let updated = event("resource_updated");
    let alice = sub(&gw, ALICE, &updated, &receiver, json!({"uri": URI_A})).await;
    let session = subscribed_listener(&peer, URI_A).await;
    peer.push(session, UPDATED, json!({"uri": URI_A}));
    expect_events(&receiver, &alice, &updated, 1).await;
}

/// S5 + S9: list changes on the listener session become one event each.
#[tokio::test]
async fn s5_sse_list_changes_become_events() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let peer = SsePeer::start().await;
    let gw = start(dir.path(), &receiver, &peer).await;
    let kinds = [
        ("resources_changed", RES_CHANGED),
        ("prompts_changed", PROMPTS_CHANGED),
        ("tools_changed", TOOLS_CHANGED),
    ];
    let mut subs = Vec::new();
    for (kind, _) in kinds {
        subs.push(sub(&gw, ALICE, &event(kind), &receiver, json!({})).await);
    }
    eventually("a listener session open", || {
        listener_sessions(&peer).last().is_some_and(|n| {
            peer.methods_on(*n)
                .iter()
                .any(|m| m == "notifications/initialized")
        })
    })
    .await;
    let session = *listener_sessions(&peer).last().expect("listener");
    tokio::time::sleep(QUIET).await;
    for (_, method) in kinds {
        peer.push(session, method, json!({}));
    }
    for ((kind, _), id) in kinds.iter().zip(&subs) {
        expect_events(&receiver, id, &event(kind), 1).await;
    }
}

/// S6: the last unsubscribe unsubscribes on the listener session and
/// closes its stream.
#[tokio::test]
async fn s6_the_last_unsubscribe_releases_the_listener_session() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let peer = SsePeer::start().await;
    let gw = start(dir.path(), &receiver, &peer).await;
    let updated = event("resource_updated");
    sub(&gw, ALICE, &updated, &receiver, json!({"uri": URI_A})).await;
    let session = subscribed_listener(&peer, URI_A).await;
    unsub(&gw, ALICE, &updated, &receiver, json!({"uri": URI_A})).await;
    eventually("unsubscribed on the listener session", || {
        peer.methods_on(session)
            .iter()
            .any(|m| m == "resources/unsubscribe")
            && peer.subscribed_on(URI_A).is_empty()
    })
    .await;
    eventually("the listener stream closed", || {
        !peer.open_sessions().contains(&session)
    })
    .await;
}

/// S7: a dropped stream is a new handshake, re-subscribed, and delivers.
#[tokio::test]
async fn s7_a_dropped_listener_stream_reconnects_and_resubscribes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let peer = SsePeer::start().await;
    let gw = start(dir.path(), &receiver, &peer).await;
    let updated = event("resource_updated");
    let alice = sub(&gw, ALICE, &updated, &receiver, json!({"uri": URI_A})).await;
    let first = subscribed_listener(&peer, URI_A).await;
    peer.drop_stream(first);
    eventually("a second listener session subscribed", || {
        listener_sessions(&peer)
            .last()
            .is_some_and(|n| *n != first && peer.subscribed_on(URI_A).contains(n))
    })
    .await;
    let second = *listener_sessions(&peer).last().expect("listener");
    peer.push(second, UPDATED, json!({"uri": URI_A}));
    expect_events(&receiver, &alice, &updated, 1).await;
}

/// S8: an `endpoint` naming another origin is never POSTed to.
#[tokio::test]
async fn s8_a_cross_origin_endpoint_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let peer = SsePeer::start().await;
    // Another origin's listener counts any request it gets.
    let elsewhere = SsePeer::start().await;
    let gw = start(dir.path(), &receiver, &peer).await;
    // Session 1 (the calls') keeps the real endpoint; later ones name the
    // other origin.
    let other = elsewhere.url.replace("/sse", "/messages?session_id=1");
    peer.send_endpoint(&other);
    let updated = event("resource_updated");
    let answer: Value = gw
        .rpc(
            Some(ALICE),
            "events/subscribe",
            upstream_sub::sub_params(
                &updated,
                &receiver.localhost_url(),
                &receiver::whsec(32),
                json!({"uri": URI_A}),
            ),
        )
        .await;
    // timing: absence
    tokio::time::sleep(QUIET).await;
    assert!(
        elsewhere.seen().is_empty(),
        "nothing reaches the other origin: {:?} (subscribe answered {answer})",
        elsewhere.seen()
    );
}

/// A `gateway_invoke` of the peer's `echo` tool.
async fn invoke(gw: &Gateway) -> Value {
    let call = json!({"name": "gateway_invoke",
        "arguments": {"server": "x", "tool": "echo", "arguments": {}}});
    gw.rpc(Some(ALICE), "tools/call", call).await
}

fn timed_backend(peer: &SsePeer, timeout: &str) -> Value {
    json!({"http_url": peer.url, "streamable_http": false, "timeout": timeout})
}

/// K1 + K2 (MIK-8835.SSE.2): calls work on a stream-only peer. When the
/// calls' stream ends under a pending call, that call fails promptly (not at
/// its timeout), the next call reconnects first and succeeds, and the failed
/// call is never sent again.
#[tokio::test]
async fn k2_a_dead_calls_stream_fails_the_pending_call_and_reconnects() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let peer = SsePeer::start().await;
    let cfg = upstream_config(dir.path(), timed_backend(&peer, "20s"), &[]);
    let gw = start_cfg(dir.path(), &receiver, cfg).await;
    let first = invoke(&gw).await;
    assert!(
        first.get("error").is_none(),
        "K1: a call on a stream-only peer: {first}"
    );
    assert_eq!(peer.posted("tools/call"), 1);

    peer.hold_calls(true);
    let began = std::time::Instant::now();
    let held = invoke(&gw);
    let cut = async {
        eventually("the held call reached the peer", || {
            peer.posted("tools/call") == 2
        })
        .await;
        peer.drop_stream(1);
    };
    let (held, ()) = tokio::join!(held, cut);
    assert!(
        began.elapsed() < Duration::from_secs(15),
        "failed promptly, not at the 20 s timeout: {:?} {held}",
        began.elapsed()
    );

    peer.hold_calls(false);
    let next = invoke(&gw).await;
    assert!(
        next.get("error").is_none(),
        "the next call succeeds: {next}"
    );
    assert!(peer.gets() >= 2, "a new handshake replaced the dead stream");
    assert_eq!(
        peer.posted("tools/call"),
        3,
        "the failed call was not resent"
    );
}

/// K3 (design B8): the calls' stream is not cut at the backend's request
/// timeout; a call after it still uses the same stream.
#[tokio::test]
async fn k3_the_calls_stream_outlives_the_request_timeout() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let peer = SsePeer::start().await;
    let cfg = upstream_config(dir.path(), timed_backend(&peer, "2s"), &[]);
    let gw = start_cfg(dir.path(), &receiver, cfg).await;
    assert!(invoke(&gw).await.get("error").is_none());
    let gets = peer.gets();
    // timing: precondition
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(
        invoke(&gw).await.get("error").is_none(),
        "a call past the timeout"
    );
    assert_eq!(peer.gets(), gets, "no reconnect: the stream was kept");
    assert!(
        peer.open_sessions().contains(&1),
        "the calls' stream is still open"
    );
}

/// K6 (design B7'): with the calls' stream dead, two calls at once share one
/// replacement and both succeed; neither fails because the other is replacing.
#[tokio::test]
async fn k6_concurrent_calls_share_one_replacement() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let peer = SsePeer::start().await;
    let cfg = upstream_config(dir.path(), timed_backend(&peer, "20s"), &[]);
    let gw = start_cfg(dir.path(), &receiver, cfg).await;
    assert!(invoke(&gw).await.get("error").is_none(), "control");
    let gets = peer.gets();
    peer.drop_stream(1);
    eventually("the calls stream closed", || {
        !peer.open_sessions().contains(&1)
    })
    .await;
    let (a, b) = tokio::join!(invoke(&gw), invoke(&gw));
    assert!(a.get("error").is_none() && !is_tool_error(&a), "first: {a}");
    assert!(
        b.get("error").is_none() && !is_tool_error(&b),
        "second: {b}"
    );
    assert_eq!(peer.gets(), gets + 1, "one shared replacement");
}

/// A `tools/call` result the gateway reports as a failed call.
fn is_tool_error(answer: &Value) -> bool {
    answer["result"]["isError"].as_bool().unwrap_or(false)
}
