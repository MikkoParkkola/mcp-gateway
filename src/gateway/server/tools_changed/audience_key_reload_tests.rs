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

/// Publish a key table with `edit` applied to `k-std`, or with `k-std`
/// removed when `edit` returns false, as a reload of an edited key list
/// does. The other keys stay, so the gateway stays multi-user. Asserts the
/// published table changed, so no row can pass or fail on a reload that did
/// not happen.
fn reload_k_std(w: &World, edit: impl Fn(&mut crate::gateway::auth::ResolvedApiKey) -> bool) {
    let live = &w.state.live_config;
    let published = live.generation();
    let before: Vec<(String, Vec<String>)> = published
        .auth()
        .api_keys()
        .iter()
        .map(|k| (k.name.clone(), k.backends.clone()))
        .collect();
    assert!(
        before.iter().any(|(name, _)| name == "k-std"),
        "premise: k-std is a key"
    );
    let auth = published
        .auth()
        .with_keys_edited(|keys| keys.retain_mut(|key| key.name != "k-std" || edit(key)));
    live.publish(std::sync::Arc::new(
        crate::config_reload::Generation::prepare_startup(
            (*live.get()).clone(),
            std::sync::Arc::new(auth),
        ),
    ));
    let after: Vec<(String, Vec<String>)> = live
        .generation()
        .auth()
        .api_keys()
        .iter()
        .map(|k| (k.name.clone(), k.backends.clone()))
        .collect();
    assert_ne!(before, after, "the reload changed the key table");
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

/// The names `tools/list` shows `bearer` in its own legacy session `id`.
async fn listed(w: &World, bearer: &str, id: &str) -> Vec<String> {
    let _session = w.legacy_owned(id, bearer).await;
    let answer = w
        .post_in(bearer, id, "tools/list", serde_json::json!({}))
        .await;
    answer["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("a tools/list answer: {answer}"))
        .iter()
        .filter_map(|tool| tool["name"].as_str().map(str::to_owned))
        .collect()
}

/// A key a reload takes `alpha` away from lists none of `alpha`'s tools,
/// surfaced ones included, exactly as a key that never had it.
#[tokio::test]
async fn a_key_that_lost_a_backend_lists_none_of_its_tools() {
    let w = World::start().await;
    w.store_shared("alpha", vec![tool("read", "r"), tool("write", "w")]);
    w.settle().await;
    let alpha_tools = |names: &[String]| {
        names
            .iter()
            .filter(|n| *n == "read" || *n == "write")
            .cloned()
            .collect::<Vec<_>>()
    };
    let before = listed(&w, "k-std", "before").await;
    assert!(
        !alpha_tools(&before).is_empty(),
        "premise: k-std lists alpha's surfaced tools: {before:?}"
    );
    let narrow = listed(&w, "k-narrow", "narrow").await;
    assert_eq!(
        alpha_tools(&narrow),
        Vec::<String>::new(),
        "control: k-narrow lists none: {narrow:?}"
    );

    reload_k_std(&w, |key| {
        key.backends = vec!["beta".to_string()];
        true
    });
    let after = listed(&w, "k-std", "after").await;
    assert_eq!(
        alpha_tools(&after),
        Vec::<String>::new(),
        "a key that lost alpha still lists alpha's tools: {after:?}"
    );
}

/// Whether a `tools/call` answer reports success.
fn succeeded(answer: &serde_json::Value) -> bool {
    answer.get("error").is_none() && answer["result"]["isError"] != serde_json::json!(true)
}

/// A key a reload takes `alpha` away from can no longer call `alpha`'s
/// tools, by the surfaced name or through `gateway_invoke`.
#[cfg(feature = "spec-preview")]
#[tokio::test]
async fn a_key_that_lost_a_backend_cannot_call_its_tools() {
    let w = World::start().await;
    w.alpha_answers_calls(vec![tool("read", "r")]);
    let _session = w.legacy_owned("calls", "k-std").await;
    let invoke = serde_json::json!({
        "name": "gateway_invoke",
        "arguments": { "server": "alpha", "tool": "read", "arguments": {} }
    });
    let before = w
        .post_in("k-std", "calls", "tools/call", invoke.clone())
        .await;
    assert!(
        succeeded(&before),
        "premise: k-std may call alpha's read: {before}"
    );

    reload_k_std(&w, |key| {
        key.backends = vec!["beta".to_string()];
        true
    });
    let invoked = w.post_in("k-std", "calls", "tools/call", invoke).await;
    assert!(
        !succeeded(&invoked),
        "gateway_invoke still reaches alpha: {invoked}"
    );
    let direct = w
        .post_in(
            "k-std",
            "calls",
            "tools/call",
            serde_json::json!({"name": "read", "arguments": {}}),
        )
        .await;
    assert!(
        !succeeded(&direct),
        "the surfaced read still reaches alpha: {direct}"
    );
}
