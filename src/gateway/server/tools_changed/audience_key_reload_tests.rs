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

/// The running config with the fixture's own key list, published through
/// the real preparation, so every reload below edits the keys the gateway
/// runs. Called before any stream opens.
fn carry_auth(w: &World) {
    let live = &w.state.live_config;
    let mut config = (*live.get()).clone();
    config.auth =
        super::audience_fixture::fixture_auth(&super::audience_access::McpAccess::Authenticated);
    live.set(config);
}

/// The published key table, by name and backends.
fn key_table(w: &World) -> Vec<(String, Vec<String>)> {
    w.state
        .live_config
        .generation()
        .auth()
        .api_keys()
        .iter()
        .map(|k| (k.name.clone(), k.backends.clone()))
        .collect()
}

/// A reload of the running config with `edit` applied to `k-std`, or with
/// `k-std` removed when `edit` returns false, prepared as every reload is
/// (`LiveConfig::set` prepares an edited `auth`). The other keys stay.
/// Asserts the published table changed.
fn reload_k_std(w: &World, edit: impl Fn(&mut crate::config::ApiKeyConfig) -> bool) {
    let live = &w.state.live_config;
    let before = key_table(w);
    let mut config = (*live.get()).clone();
    assert!(
        config.auth.api_keys.iter().any(|k| k.name == "k-std"),
        "premise: the running config holds k-std (carry_auth)"
    );
    config
        .auth
        .api_keys
        .retain_mut(|key| key.name != "k-std" || edit(key));
    live.set(config);
    assert_ne!(before, key_table(w), "the reload changed the key table");
}

/// A world whose running config carries its key list.
async fn world() -> World {
    let w = World::start().await;
    carry_auth(&w);
    w
}

/// STREAM.1 on the GET stream: a key a reload removes has its next ordinary
/// notification withheld. The fan-out queues no copy for a dead key, so the
/// stream stays quiet.
#[tokio::test]
async fn stream1_a_removed_key_gets_nothing_on_its_get_stream() {
    let w = world().await;
    w.store_shared("alpha", vec![tool("read", "r")]);
    w.settle().await;
    let mut get = w.sse("k-std").await;
    push(&w, "alpha").await;
    assert!(
        get.frames(&w).await.iter().any(|m| m == GET_NOTE),
        "premise: GET delivered"
    );

    assert_ne!(
        status_as(&w, "k-std").await,
        axum::http::StatusCode::UNAUTHORIZED,
        "premise: k-std is admitted before the reload"
    );
    reload_k_std(&w, |_| false);
    assert_eq!(
        status_as(&w, "k-std").await,
        axum::http::StatusCode::UNAUTHORIZED,
        "premise: a request as the removed key is refused"
    );
    push(&w, "alpha").await;
    assert!(
        !get.frames(&w).await.iter().any(|m| m == GET_NOTE),
        "STREAM.1: the GET stream still serves a removed key"
    );
}

/// STREAM.1 on `subscriptions/listen`: a key a reload removes has its
/// listener ended at its next delivery.
#[tokio::test]
async fn stream1_a_removed_key_ends_its_listen_stream() {
    let w = world().await;
    w.store_shared("alpha", vec![tool("read", "r")]);
    w.settle().await;
    let mut listen = w.listen("k-std").await;
    // `frames` reads up to its sentinel; a listen stream that ended panics.
    let _ = listen.frames(&w).await;

    assert_ne!(
        status_as(&w, "k-std").await,
        axum::http::StatusCode::UNAUTHORIZED,
        "premise: k-std is admitted before the reload"
    );
    reload_k_std(&w, |_| false);
    assert_eq!(
        status_as(&w, "k-std").await,
        axum::http::StatusCode::UNAUTHORIZED,
        "premise: a request as the removed key is refused"
    );
    push(&w, "alpha").await;
    assert!(
        listen.closed(&w).await,
        "STREAM.1: listen still serves a removed key"
    );
}

/// STREAM.3: a kept key whose grant for one backend a reload removes: that
/// backend's next notification is withheld, another backend's still
/// delivers, and the streams stay open. On listen the per-backend kind is a
/// tool-list change: after the one hint the lost backend is owed (STREAM.2),
/// its changes are withheld and the kept backend's still deliver.
#[tokio::test]
async fn stream3_a_removed_grant_withholds_that_backend_only() {
    let w = world().await;
    w.store_shared("alpha", vec![tool("read", "r")]);
    w.store_shared("beta", vec![tool("fetch", "f")]);
    w.settle().await;
    let (mut get, mut listen) = (w.sse("k-std").await, w.listen("k-std").await);
    push(&w, "alpha").await;
    assert!(
        get.frames(&w).await.iter().any(|m| m == GET_NOTE),
        "premise: GET delivered"
    );
    assert_eq!(listen.told(&w).await, 0, "premise: listen starts quiet");

    reload_k_std(&w, |key| {
        key.backends = vec!["beta".to_string()];
        true
    });
    push(&w, "alpha").await;
    assert!(
        !get.frames(&w).await.iter().any(|m| m == GET_NOTE),
        "STREAM.3: GET delivered a backend the key lost"
    );
    push(&w, "beta").await;
    assert!(
        get.frames(&w).await.iter().any(|m| m == GET_NOTE),
        "STREAM.3: GET lost beta too"
    );

    w.store_shared("alpha", vec![tool("read", "r"), tool("write", "w")]);
    assert_eq!(
        listen.told(&w).await,
        1,
        "premise: listen is owed alpha's one hint"
    );
    w.store_shared("alpha", vec![tool("read", "r")]);
    assert_eq!(
        listen.told(&w).await,
        0,
        "STREAM.3: listen heard a backend the key lost"
    );
    w.store_shared("beta", vec![tool("fetch", "f"), tool("get", "g")]);
    assert_eq!(listen.told(&w).await, 1, "STREAM.3: listen lost beta too");
}

/// STREAM.2 reads: "For a backend the removed key lost, a `tools/list_changed`
/// still delivers its one owed hint, then the stream stays quiet." A hint is
/// owed only to a caller whose view moved, so this row is a kept key that
/// loses a backend: one hint, then quiet. A removed key is owed nothing; the
/// row after this one pins that.
#[tokio::test]
async fn stream2_a_lost_backend_owes_one_list_hint_then_stays_quiet() {
    let w = world().await;
    w.store_shared("alpha", vec![tool("read", "r")]);
    w.settle().await;
    let (mut get, mut listen) = (w.sse("k-std").await, w.listen("k-std").await);
    assert_eq!(get.told(&w).await, 0, "premise: GET starts quiet");
    assert_eq!(listen.told(&w).await, 0, "premise: listen starts quiet");

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

/// STREAM.2's other half: a removed key is owed no hint. A tool-list change
/// after the removal writes nothing to either stream; listen ends, and
/// nothing it heard before ending is a tool-list change.
#[tokio::test]
async fn stream2_a_removed_key_is_owed_no_list_hint() {
    let w = world().await;
    w.store_shared("alpha", vec![tool("read", "r")]);
    w.settle().await;
    let (mut get, mut listen) = (w.sse("k-std").await, w.listen("k-std").await);
    assert_eq!(get.told(&w).await, 0, "premise: GET starts quiet");
    assert_eq!(listen.told(&w).await, 0, "premise: listen starts quiet");

    reload_k_std(&w, |_| false);
    w.store_shared("alpha", vec![tool("read", "r"), tool("write", "w")]);
    assert_eq!(get.told(&w).await, 0, "STREAM.2: GET hinted a removed key");
    let heard = listen
        .heard_until_closed(&w)
        .await
        .expect("STREAM.1: listen still serves a removed key");
    assert!(
        !heard
            .iter()
            .any(|m| m == "notifications/tools/list_changed"),
        "STREAM.2: listen hinted a removed key: {heard:?}"
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
    let w = world().await;
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
#[cfg(feature = "spec-preview")]
fn succeeded(answer: &serde_json::Value) -> bool {
    answer.get("error").is_none() && answer["result"]["isError"] != serde_json::json!(true)
}

/// Reload through the real file path: write the published config with
/// `k-std` edited (the security flags off, as the fixture runs) to a
/// `gateway.yaml` and reload it through a `ReloadContext`, as the file
/// watcher and the reload meta-tool do. Asserts the published key table
/// changed.
async fn file_reload_k_std(w: &World, edit: impl Fn(&mut crate::config::ApiKeyConfig) -> bool) {
    let live = &w.state.live_config;
    let before = key_table(w);
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
    let dir = crate::test_dir_keep::kept_tempdir();
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
    assert_ne!(
        before,
        key_table(w),
        "the file reload changed the key table"
    );
}

/// The deciding row, through the real file reload: a key whose grant for
/// `alpha` the reload removes lists none of `alpha`'s tools and cannot call
/// them; a key that never had `alpha` is refused the same call.
#[cfg(feature = "spec-preview")]
#[tokio::test]
async fn file_reload_a_key_that_lost_a_backend_neither_lists_nor_calls_it() {
    let w = world().await;
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
    let kept = listed(&w, "k-deny", "kept-file").await;
    assert!(
        kept.iter().any(|n| n == "write"),
        "control: after the file reload a key that kept alpha still lists it: {kept:?}"
    );
    let _kept = w.legacy_owned("kept-call", "k-deny").await;
    let write = serde_json::json!({
        "name": "gateway_invoke",
        "arguments": { "server": "alpha", "tool": "write", "arguments": {} }
    });
    let kept_call = w.post_in("k-deny", "kept-call", "tools/call", write).await;
    assert!(
        succeeded(&kept_call),
        "control: after the file reload a key that kept alpha still calls it: {kept_call}"
    );
    let after = w.post_in("k-std", "std-call", "tools/call", invoke).await;
    assert!(
        !succeeded(&after),
        "after a file reload k-std still calls alpha: {after}"
    );
}

/// The status a `tools/list` request as `bearer` gets, outside any session.
async fn status_as(w: &World, bearer: &str) -> axum::http::StatusCode {
    use tower::ServiceExt as _;
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("authorization", format!("Bearer {bearer}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string(),
        ))
        .expect("a request");
    w.router
        .clone()
        .oneshot(request)
        .await
        .expect("served")
        .status()
}

/// Through the real file reload: a key the reload removes is refused on its
/// next request, and the GET stream it holds is sent nothing more for it.
#[tokio::test]
async fn file_reload_a_removed_key_gets_nothing_on_its_get_stream() {
    let w = world().await;
    w.store_shared("alpha", vec![tool("read", "r")]);
    w.settle().await;
    let (mut get, mut kept) = (w.sse("k-std").await, w.sse("k-deny").await);
    push(&w, "alpha").await;
    assert!(
        get.frames(&w).await.iter().any(|m| m == GET_NOTE),
        "premise: GET delivered"
    );
    assert!(
        kept.frames(&w).await.iter().any(|m| m == GET_NOTE),
        "premise: the kept key's GET delivered"
    );

    file_reload_k_std(&w, |_| false).await;
    assert_eq!(
        status_as(&w, "k-std").await,
        axum::http::StatusCode::UNAUTHORIZED,
        "premise: a request as the removed key is refused"
    );
    push(&w, "alpha").await;
    assert!(
        !get.frames(&w).await.iter().any(|m| m == GET_NOTE),
        "the GET stream still serves a key the file reload removed"
    );
    assert!(
        kept.frames(&w).await.iter().any(|m| m == GET_NOTE),
        "control: after the file reload a kept key's GET stream still delivers"
    );
}

/// Through the real file reload: a key the reload removes has its listen
/// stream ended at its next delivery, while a kept key's stays open.
#[tokio::test]
async fn file_reload_a_removed_key_ends_its_listen_stream() {
    let w = world().await;
    w.store_shared("alpha", vec![tool("read", "r")]);
    w.settle().await;
    let (mut listen, mut kept) = (w.listen("k-std").await, w.listen("k-deny").await);
    assert_eq!(listen.told(&w).await, 0, "premise: listen is open");

    file_reload_k_std(&w, |_| false).await;
    assert_eq!(
        status_as(&w, "k-std").await,
        axum::http::StatusCode::UNAUTHORIZED,
        "premise: a request as the removed key is refused"
    );
    assert!(
        listen.closed(&w).await,
        "listen still serves a key the file reload removed"
    );
    assert!(
        !kept.closed(&w).await,
        "control: after the file reload a kept key's listen stream ended"
    );
}
