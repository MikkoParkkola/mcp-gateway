// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A stream judges each delivery by the key table current at that delivery
//! (ADR-023): a key a reload removes, or a backend grant it takes away, ends
//! what the stream already held, on the GET stream and on
//! `subscriptions/listen` alike, with no restart.

use super::audience_fixture::{World, tool};
use crate::gateway::streaming::TaggedNotification;

/// The ordinary backend notification (not a tool-list change) each channel
/// carries: the GET stream relays any backend notification, while
/// `subscriptions/listen` here subscribes to resource-list changes only.
const GET_NOTE: &str = "notifications/resources/updated";
const LISTEN_NOTE: &str = "notifications/resources/list_changed";

/// Push one ordinary notification from `backend` into each channel.
async fn push(w: &World, backend: &str) {
    let tagged = TaggedNotification {
        source: backend.to_string(),
        event_type: "message".to_string(),
        data: serde_json::json!({"jsonrpc": "2.0", "method": GET_NOTE}),
        event_id: None,
    };
    w.state
        .multiplexer
        .broadcast_to_backend(&tagged, backend)
        .await;
    let note = serde_json::json!({"jsonrpc": "2.0", "method": LISTEN_NOTE});
    w.state.subscriptions.publish_for_backend(note, backend);
}

/// Reload the key table with `edit` applied to `k-std`, or with `k-std`
/// removed when `edit` returns false. The other keys stay, so the gateway
/// stays multi-user and the reload is accepted.
fn reload_k_std(w: &World, edit: impl Fn(&mut crate::config::ApiKeyConfig) -> bool) {
    w.state.live_config.edit(|c| {
        c.auth
            .api_keys
            .retain_mut(|key| key.name != "k-std" || edit(key));
    });
}

/// STREAM.1: a key a reload removes has its held streams' next ordinary
/// notification withheld: both streams end instead of delivering it.
#[tokio::test]
async fn stream1_a_removed_key_ends_its_held_streams() {
    let w = World::start().await;
    w.store_shared("alpha", vec![tool("read", "r")]);
    w.settle().await;
    let (mut get, mut listen) = (w.sse("k-std").await, w.listen("k-std").await);
    push(&w, "alpha").await;
    assert!(
        get.frames(&w).await.iter().any(|m| m == GET_NOTE),
        "premise: GET delivered"
    );
    assert!(
        listen.frames(&w).await.iter().any(|m| m == LISTEN_NOTE),
        "premise: listen delivered"
    );

    reload_k_std(&w, |_| false);
    push(&w, "alpha").await;
    assert!(
        get.closed(&w).await,
        "STREAM.1: the GET stream still serves a removed key"
    );
    assert!(
        listen.closed(&w).await,
        "STREAM.1: listen still serves a removed key"
    );
}

/// STREAM.3: a kept key whose grant for one backend a reload removes: that
/// backend's next notification is withheld, another backend's still
/// delivers, and the streams stay open.
#[tokio::test]
async fn stream3_a_removed_grant_withholds_that_backend_only() {
    let w = World::start().await;
    w.store_shared("alpha", vec![tool("read", "r")]);
    w.settle().await;
    let (mut get, mut listen) = (w.sse("k-std").await, w.listen("k-std").await);
    push(&w, "alpha").await;
    assert!(
        get.frames(&w).await.iter().any(|m| m == GET_NOTE),
        "premise: GET delivered"
    );
    assert!(
        listen.frames(&w).await.iter().any(|m| m == LISTEN_NOTE),
        "premise: listen delivered"
    );

    reload_k_std(&w, |key| {
        key.backends = vec!["beta".to_string()];
        true
    });
    push(&w, "alpha").await;
    assert!(
        !get.frames(&w).await.iter().any(|m| m == GET_NOTE),
        "STREAM.3: GET delivered a backend the key lost"
    );
    assert!(
        !listen.frames(&w).await.iter().any(|m| m == LISTEN_NOTE),
        "STREAM.3: listen delivered a backend the key lost"
    );
    push(&w, "beta").await;
    assert!(
        get.frames(&w).await.iter().any(|m| m == GET_NOTE),
        "STREAM.3: GET lost beta too"
    );
    assert!(
        listen.frames(&w).await.iter().any(|m| m == LISTEN_NOTE),
        "STREAM.3: listen lost beta too"
    );
}

/// STREAM.2: for a backend a kept key lost by reload, a list change still
/// delivers its one owed hint (the caller's view moved), then the stream
/// stays quiet for that backend.
#[tokio::test]
async fn stream2_a_lost_backend_owes_one_list_hint_then_stays_quiet() {
    let w = World::start().await;
    w.store_shared("alpha", vec![tool("read", "r")]);
    w.settle().await;
    let (mut get, mut listen) = (w.sse("k-std").await, w.listen("k-std").await);

    reload_k_std(&w, |key| {
        key.backends = vec!["beta".to_string()];
        true
    });
    w.store_shared("alpha", vec![tool("read", "r"), tool("write", "w")]);
    assert_eq!(get.told(&w).await, 1, "STREAM.2: GET was not owed one hint");
    assert_eq!(
        listen.told(&w).await,
        1,
        "STREAM.2: listen was not owed one hint"
    );
    w.store_shared("alpha", vec![tool("read", "r")]);
    assert_eq!(
        get.told(&w).await,
        0,
        "STREAM.2: GET heard a backend it lost"
    );
    assert_eq!(
        listen.told(&w).await,
        0,
        "STREAM.2: listen heard a backend it lost"
    );
}
