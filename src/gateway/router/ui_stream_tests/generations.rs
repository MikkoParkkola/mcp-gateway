// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Generations in `hello` heads: they must not hide a reload, and a counts-only
//! stream must not feel admin-only change.

use super::*;

/// The number after `tag` in a frame's `head` string.
fn head_part(hello: &Frame, tag: char) -> u64 {
    let head = hello.json()["head"].as_str().unwrap_or_default().to_owned();
    head.split('.')
        .find_map(|p| p.strip_prefix(tag))
        .and_then(|n| n.parse().ok())
        .expect("the head names that part")
}

#[tokio::test]
async fn a_reload_with_no_stream_open_still_advances_the_generation() {
    let (state, _dir) = fixture().await;
    let hub = state.dashboard_bootstrap.stream_hub();
    let mut first = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    let before = head_part(&first.until("hello").await, 'r');
    first.until("status").await;
    drop(first);
    assert!(yield_until(|| !hub.watcher_running()).await);
    state
        .live_config
        .edit(|c| c.auth.public_paths.push("/gap".to_owned()));
    let mut second = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    let after = head_part(&second.until("hello").await, 'r');
    assert!(after > before, "{after} should follow {before}");
}

#[tokio::test]
async fn a_counts_only_stream_does_not_see_an_admin_only_change() {
    let (state, _dir) = fixture().await;
    let _ = state
        .backends
        .register(http_backend_at("gen-probe", "http://127.0.0.1:9/mcp"));
    let backend = state.backends.get("gen-probe").expect("registered");
    let mut admin = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    let a1 = head_part(&admin.until("hello").await, 's');
    admin.until("status").await;
    let mut low = open(&state, request(STREAM, Who::Bearer(KEY), None)).await;
    let low1 = head_part(&low.until("hello").await, 's');
    backend
        .shared_entry_for_test()
        .failsafe
        .record_success(Duration::from_millis(5));
    tokio::time::sleep(Duration::from_secs(2)).await;
    let moved = admin.until("status").await.part('s');
    assert_ne!(moved, Some(a1.to_string()), "the admin view did change");
    let mut again = open(&state, request(STREAM, Who::Bearer(KEY), None)).await;
    let low2 = head_part(&again.until("hello").await, 's');
    assert_eq!(low2, low1, "counts did not change, so neither did its id");
}

/// The generation in a `reload` frame.
fn generation(frame: &Frame) -> u64 {
    frame.json()["generation"].as_u64().expect("a generation")
}

#[tokio::test]
async fn a_watcher_that_died_under_open_streams_is_replaced_at_the_next_admission() {
    let (state, _dir) = fixture().await;
    let hub = state.dashboard_bootstrap.stream_hub();
    let mut a = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    let a0 = generation(&a.until("reload").await);
    let dead = hub.kill_watcher_for_test().expect("a watcher is running");
    assert!(yield_until(|| dead.is_finished()).await);
    let mut b = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    let b0 = generation(&b.until("reload").await);
    let began = tokio::time::Instant::now();
    state
        .live_config
        .edit(|c| c.auth.public_paths.push("/revived".to_owned()));
    assert!(generation(&a.until("reload").await) > a0);
    assert!(generation(&b.until("reload").await) > b0);
    assert!(
        began.elapsed() <= Duration::from_secs(3),
        "within the bound"
    );
}
