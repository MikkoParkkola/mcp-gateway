// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A stream judges each delivery by the key table current at that delivery
//! (ADR-023): a key a reload removes, or a backend grant it takes away, ends
//! what the stream already held, on the GET stream and on
//! `subscriptions/listen` alike, with no restart.

use super::audience_fixture::{World, tool};
use crate::gateway::streaming::TaggedNotification;

/// An ordinary backend notification (not a tool-list change), which the GET
/// stream relays. On `subscriptions/listen` the per-backend kind this fixture
/// delivers is a tool-list change, which STREAM.2 covers.
const GET_NOTE: &str = "notifications/resources/updated";

/// Push one ordinary notification from `backend` into the GET stream.
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
    // `frames` reads up to its sentinel; a listen stream that ended panics.
    let _ = listen.frames(&w).await;

    reload_k_std(&w, |_| false);
    push(&w, "alpha").await;
    assert!(
        !get.is_open(&w).await,
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
    // `frames` reads up to its sentinel; a listen stream that ended panics.
    let _ = listen.frames(&w).await;

    reload_k_std(&w, |key| {
        key.backends = vec!["beta".to_string()];
        true
    });
    push(&w, "alpha").await;
    assert!(
        !get.frames(&w).await.iter().any(|m| m == GET_NOTE),
        "STREAM.3: GET delivered a backend the key lost"
    );
    // On listen the per-backend kind is a tool-list change (STREAM.2); a
    // kept key's listen stream stays open.
    let _ = listen.frames(&w).await;
    push(&w, "beta").await;
    assert!(
        get.frames(&w).await.iter().any(|m| m == GET_NOTE),
        "STREAM.3: GET lost beta too"
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

/// Reload through the real file path: write the published config with
/// `k-std` edited (the security flags off, as the fixture runs) to a
/// `gateway.yaml` and reload it through a `ReloadContext`, as the file
/// watcher and the reload meta-tool do. Asserts the published key table
/// changed.
async fn file_reload_k_std(w: &World, edit: impl Fn(&mut crate::config::ApiKeyConfig) -> bool) {
    let live = &w.state.live_config;
    let table = |live: &crate::config_reload::LiveConfig| -> Vec<(String, Vec<String>)> {
        live.generation()
            .auth()
            .api_keys()
            .iter()
            .map(|k| (k.name.clone(), k.backends.clone()))
            .collect()
    };
    let before = table(live);
    let mut auth = live.get().auth.clone();
    assert!(
        auth.api_keys.iter().any(|k| k.name == "k-std"),
        "premise: the running config holds k-std"
    );
    auth.api_keys
        .retain_mut(|key| key.name != "k-std" || edit(key));
    let doc = serde_json::json!({
        "security": { "sanitize_input": false, "ssrf_protection": false },
        "auth": auth,
    });
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, doc.to_string()).expect("write");
    crate::config_reload::ReloadContext::new(
        path,
        std::sync::Arc::clone(live),
        std::sync::Arc::clone(&w.state.backends),
        crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    )
    .expect("the registry pairs with the config")
    .reload_outcome()
    .await
    .expect("the key edit applies");
    assert_ne!(before, table(live), "the file reload changed the key table");
}

/// The deciding row, through the real file reload: a key whose grant for
/// `alpha` the reload removes lists none of `alpha`'s tools and cannot call
/// them; a key that never had `alpha` is refused the same call.
#[cfg(feature = "spec-preview")]
#[tokio::test]
async fn file_reload_a_key_that_lost_a_backend_neither_lists_nor_calls_it() {
    let w = World::start().await;
    w.alpha_answers_calls(vec![tool("read", "r"), tool("write", "w")]);
    w.store_shared("alpha", vec![tool("read", "r"), tool("write", "w")]);
    w.settle().await;
    let invoke = serde_json::json!({
        "name": "gateway_invoke",
        "arguments": { "server": "alpha", "tool": "read", "arguments": {} }
    });
    let _narrow = w.legacy_owned("narrow-call", "k-narrow").await;
    let refused = w
        .post_in("k-narrow", "narrow-call", "tools/call", invoke.clone())
        .await;
    assert!(
        !succeeded(&refused),
        "control: a key without alpha is refused: {refused}"
    );
    let _std = w.legacy_owned("std-call", "k-std").await;
    let before = w
        .post_in("k-std", "std-call", "tools/call", invoke.clone())
        .await;
    assert!(
        succeeded(&before),
        "premise: k-std may call alpha: {before}"
    );

    file_reload_k_std(&w, |key| {
        key.backends = vec!["beta".to_string()];
        true
    })
    .await;
    let names = listed(&w, "k-std", "after-file").await;
    assert!(
        !names.iter().any(|n| n == "read" || n == "write"),
        "after a file reload k-std still lists alpha's tools: {names:?}"
    );
    let after = w.post_in("k-std", "std-call", "tools/call", invoke).await;
    assert!(
        !succeeded(&after),
        "after a file reload k-std still calls alpha: {after}"
    );
}

/// `subscriptions/listen` relays only what the gateway advertises: tool-list
/// changes (and named tasks), never a backend's ordinary notification. The
/// gateway advertises `resources: { subscribe: false, listChanged: false }`
/// (`build_server_capabilities`), and its only listen publishers send
/// `tools/list_changed` (`announce_tools_changed`,
/// `announce_backend_view_changed`) and task notifications. A resource-list
/// change published for a backend is not delivered, and the stream stays open.
#[tokio::test]
async fn listen_relays_no_ordinary_backend_notification() {
    let w = World::start().await;
    let mut listen = w.listen("k-std").await;
    w.state.subscriptions.publish_for_backend(
        serde_json::json!({"jsonrpc": "2.0", "method": "notifications/resources/list_changed"}),
        "alpha",
    );
    let heard = listen.frames(&w).await;
    assert!(
        heard.is_empty(),
        "listen relayed an unadvertised notification: {heard:?}"
    );
    let _ = listen.frames(&w).await;
}
