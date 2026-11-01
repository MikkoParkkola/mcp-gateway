// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The watcher handover: a replacement waits for the retiring watcher to
//! finish before it publishes. Real worker threads, ordered by counts and the
//! publish lock's wait signal, never by time.

use super::*;

/// Tries for a wait that must succeed.
const TRIES: u32 = 5_000_000;

/// Yield until `done`, giving up after `TRIES` yields.
async fn until(mut done: impl FnMut() -> bool) -> bool {
    for _ in 0..TRIES {
        if done() {
            return true;
        }
        tokio::task::yield_now().await;
    }
    done()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_successor_waits_for_the_publisher_even_after_a_waiting_replacement_is_cancelled() {
    let (state, _dir) = fixture_unpaused().await;
    let hub = state.dashboard_bootstrap.stream_hub();
    let probe = hub.probe();
    let (release, gate) = std::sync::mpsc::channel();
    probe.arm(gate);
    // A enters its publish step and parks there, uncancellable.
    let first = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    assert!(until(|| probe.entered()).await, "A parked");
    drop(first);
    assert!(until(|| hub.open_streams() == 0).await);
    // B starts and waits for A; then B is cancelled.
    let second = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    assert!(until(|| probe.watchers_started() == 2).await);
    drop(second);
    assert!(until(|| hub.open_streams() == 0).await);
    // C starts. While A is parked it must not publish.
    let _third = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    assert!(until(|| probe.watchers_started() == 3).await);
    assert!(
        until(|| probe.lock_waits() == 2).await,
        "B and C each queued behind A's lock"
    );
    assert_eq!(probe.observe_calls(), 1, "only A has begun a publish");
    assert_eq!(probe.publishes(), 0);
    // A finishes; only then does C publish.
    release.send(()).expect("the gate is open");
    assert!(until(|| probe.publishes() >= 2).await, "A then C published");
    assert_eq!(probe.watchers_started(), 3);
}

#[tokio::test]
async fn a_publisher_parked_forever_is_aborted_so_its_successor_still_publishes() {
    let (state, _dir) = fixture_unpaused().await;
    let hub = state.dashboard_bootstrap.stream_hub();
    let probe = hub.probe();
    probe.arm_park_forever();
    // A takes the lock and parks at an await point, never to publish.
    let first = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    assert!(until(|| probe.entered()).await, "A parked holding the lock");
    // The last stream goes: A is aborted, which frees the lock.
    drop(first);
    assert!(until(|| hub.open_streams() == 0).await);
    let _second = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    assert!(until(|| probe.publishes() >= 1).await, "C published");
}
