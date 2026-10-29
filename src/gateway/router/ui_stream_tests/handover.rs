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
async fn a_replacement_watcher_publishes_only_after_the_retiring_one_finished() {
    let (state, _dir) = fixture_unpaused().await;
    let hub = state.dashboard_bootstrap.stream_hub();
    let probe = hub.probe();
    let (release, gate) = std::sync::mpsc::channel();
    probe.arm(gate);
    // 1. The first watcher enters its publish step and parks there.
    let first = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    assert!(until(|| probe.entered()).await, "the old watcher parked");
    // 2. The last stream goes; a new one starts a replacement.
    drop(first);
    assert!(until(|| hub.open_streams() == 0).await);
    let _second = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    assert!(until(|| probe.watchers_started() == 2).await);
    // 3. Given every chance, the replacement still has not published.
    let more = until_within(NEGATIVE_TRIES, || probe.observe_calls() >= 2).await;
    assert!(
        !more,
        "the replacement began a publish while the old one ran"
    );
    assert_eq!(probe.publishes(), 0);
    // 4. The old watcher finishes; only then does the replacement publish.
    release.send(()).expect("the gate is open");
    assert!(until(|| probe.publishes() >= 2).await, "both publishes ran");
    assert_eq!(probe.watchers_started(), 2);
}
