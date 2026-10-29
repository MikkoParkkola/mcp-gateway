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
    let (state, _dir) = fixture_unpaused().await;
    tokio::time::pause();
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
    let (state, _dir) = fixture_unpaused().await;
    tokio::time::pause();
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

#[tokio::test]
async fn an_open_stream_restarts_a_dead_watcher_without_a_new_admission() {
    let (state, _dir) = fixture_unpaused().await;
    tokio::time::pause();
    let hub = state.dashboard_bootstrap.stream_hub();
    let mut a = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    let a0 = generation(&a.until("reload").await);
    let dead = hub.kill_watcher_for_test().expect("a watcher is running");
    assert!(yield_until(|| dead.is_finished()).await);
    let began = tokio::time::Instant::now();
    state
        .live_config
        .edit(|c| c.auth.public_paths.push("/alone".to_owned()));
    assert!(generation(&a.until("reload").await) > a0);
    assert!(
        began.elapsed() <= Duration::from_secs(3),
        "within the bound"
    );
}

#[tokio::test]
async fn a_watcher_that_died_before_the_first_snapshot_is_replaced_by_the_waiting_stream() {
    let (state, _dir) = fixture_unpaused().await;
    tokio::time::pause();
    let hub = state.dashboard_bootstrap.stream_hub();
    let mut a = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    let dead = hub.kill_watcher_for_test().expect("a watcher is running");
    assert!(yield_until(|| dead.is_finished()).await);
    let began = tokio::time::Instant::now();
    a.until("hello").await;
    assert!(
        began.elapsed() <= Duration::from_secs(3),
        "within the bound"
    );
}

#[tokio::test]
async fn a_viewer_revoked_while_waiting_for_the_first_snapshot_ends_within_the_bound() {
    let (state, _dir) = fixture_unpaused().await;
    tokio::time::pause();
    let hub = state.dashboard_bootstrap.stream_hub();
    let h = issue(&state);
    let mut a = open(&state, request(STREAM, Who::Cookie(&h), None)).await;
    let dead = hub.kill_watcher_for_test().expect("a watcher is running");
    assert!(yield_until(|| dead.is_finished()).await);
    let out = Request::builder()
        .method("POST")
        .uri("/dashboard/logout")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={h}"))
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 52_346))))
        .body(Body::empty())
        .unwrap();
    let _ = create_router(Arc::clone(&state))
        .oneshot(out)
        .await
        .unwrap();
    assert!(a.ended_within(REVOKED_WITHIN).await);
}

#[tokio::test]
async fn a_stream_stuck_in_a_send_revives_a_dead_watcher() {
    let (state, _dir) = fixture_unpaused().await;
    tokio::time::pause();
    let hub = state.dashboard_bootstrap.stream_hub();
    // Nobody reads: `hello` fills the channel and the next frame is stuck.
    let _stuck = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    for _ in 0..100 {
        if hub.sends_awaiting_room() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(
        hub.sends_awaiting_room(),
        1,
        "the stream is stuck in a send"
    );
    let dead = hub.kill_watcher_for_test().expect("a watcher is running");
    assert!(yield_until(|| dead.is_finished()).await);
    let before = hub.probe().watchers_started();
    for _ in 0..3000 {
        if hub.probe().watchers_started() > before {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let started = hub.probe().watchers_started();
    assert_eq!(
        started,
        before + 1,
        "the send's upkeep started a new watcher"
    );
}

/// A little past the stream's one-hour lifetime.
const PAST_LIFETIME: Duration = Duration::from_secs(3601);

#[tokio::test]
async fn a_stream_still_waiting_for_its_first_snapshot_ends_at_its_lifetime() {
    let (state, _dir) = fixture_unpaused().await;
    tokio::time::pause();
    let hub = state.dashboard_bootstrap.stream_hub();
    // The watcher parks before it publishes, so no fresh snapshot ever lands.
    hub.probe().arm_park_forever();
    let _waiting = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    assert_eq!(hub.open_streams(), 1);
    tokio::time::sleep(PAST_LIFETIME).await;
    assert!(
        yield_until(|| hub.open_streams() == 0).await,
        "the lifetime ended it and its slot returned"
    );
}
