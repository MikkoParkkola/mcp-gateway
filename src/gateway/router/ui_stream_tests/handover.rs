// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The watcher handover: a replacement waits for the retiring watcher to
//! finish before it publishes. Real worker threads, ordered by counts and the
//! old task's `JoinHandle`, never by time.

use super::*;

/// Tries for a wait that must succeed, and for one that must not.
const TRIES: u32 = 5_000_000;
const NEGATIVE_TRIES: u32 = 200_000;

async fn until(done: impl FnMut() -> bool) -> bool {
    until_within(TRIES, done).await
}

/// Yield until `done`, giving up after `tries` yields.
async fn until_within(tries: u32, mut done: impl FnMut() -> bool) -> bool {
    for _ in 0..tries {
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
    let early = until_within(NEGATIVE_TRIES, || probe.observe_calls() >= 2).await;
    assert!(!early, "C began a publish while A was still parked");
    assert_eq!(probe.publishes(), 0);
    // A finishes; only then does C publish.
    release.send(()).expect("the gate is open");
    assert!(until(|| probe.publishes() >= 2).await, "A then C published");
    assert_eq!(probe.watchers_started(), 3);
}
