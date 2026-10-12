// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202 P4a worker-settle rows that need seams base 6c62a0985 lacks, so
//! they are compile-red there: the r4.1 commit-attempt hook
//! (`TaskExecutor::commit_hook_for_test`) and `settle_cas`'s new `cancel_rx`
//! parameter. Their behaviour is pinned against design r4 "Worker settle: one
//! rule, bounded" and r4.1.
//!
//! The hook these rows assume (test-only, no public item):
//! - `TaskExecutor::commit_hook_for_test(&self) -> CommitAttemptHook`, a
//!   cloneable handle installed on the executor;
//! - `CommitAttemptHook::attempts(&self, id: &str) -> usize`: the
//!   `commit_transition` attempts made for `id` since the hook was taken;
//! - `CommitAttemptHook::inject_conflict_before(&self, id: &str, attempt: usize)`:
//!   immediately before attempt `attempt` (1-based) for `id`, commit one
//!   `StatusMessage` write at the record's current revision, dated at its
//!   current `last_updated_at` (no clock read), so that attempt loses its
//!   compare-and-set. May be called for several attempts.

use tokio::sync::watch;

#[cfg(feature = "metrics")]
use super::worker_clock_settle_tests::clock_waits;
use super::worker_clock_settle_tests::{created, dark, day_task, flip_when_waiting, flipped};
use super::worker_tests::{OWNER, complete, fixture_with};
use crate::gateway::task_service::TaskStatus;
use crate::test_wait::HANG_BOUND;

/// R2d (MIK-8202.AC.16, AC.2). r4 rule 1: after `Read(t)` the time source is
/// `Some(t)`, and a retry after a `RevisionConflict` keeps it. The clock goes
/// dark again right after the wait's one readable read, and the post-wait
/// commit (attempt 2) loses its compare-and-set to an injected write; the
/// re-read commit (attempt 3) is dated `flipped()`. Mutant M2b (a fresh read
/// instead of `at`) is killed by `readable_reads == 1` and the `Completed`
/// status (a fresh read is refused); a second wait by the wait count of 1.
#[tokio::test(flavor = "current_thread")]
async fn r2d_a_conflict_after_the_wait_retries_at_the_read_time() {
    #[cfg(feature = "metrics")]
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    #[cfg(feature = "metrics")]
    let metrics = recorder.handle();
    #[cfg(feature = "metrics")]
    let _guard = telemetry_metrics::set_default_local_recorder(&recorder);
    let fx = day_task("r2d-wait-conflict").await;
    let hook = fx.executor.commit_hook_for_test();
    hook.inject_conflict_before(&fx.id, 2);
    fx.service.store.set_clock_for_test(dark());
    let flip = flip_when_waiting(&fx, 1, Some(1), None);
    let (_tx, mut rx) = watch::channel(false);

    let delivered = fx
        .executor
        .settle_cas(OWNER, &fx.id, fx.revision, complete(), &mut rx)
        .await;
    flip.abort();

    let stored = fx.service.get(OWNER, &fx.id).expect("the owner reads it");
    assert_eq!(stored.task.status(), TaskStatus::Completed);
    assert!(delivered, "the original output was stored");
    assert_eq!(
        stored.task.last_updated_at(),
        flipped(),
        "the retry kept `at`"
    );
    assert_eq!(
        hook.attempts(&fx.id),
        3,
        "dark, conflict, then the stored retry"
    );
    assert_eq!(
        fx.service.store.readable_reads_for_test(),
        1,
        "only the wait read the clock; the dated commits never did"
    );
    #[cfg(feature = "metrics")]
    assert_eq!(clock_waits(&metrics.render()), 1, "{}", metrics.render());
}

/// The r4.1 worst case on a 1 ms TTL: attempt 1 reads a readable clock and
/// loses to an injected write, attempt 2 meets the dark clock, the one wait
/// expires, and `settle_dated_last_known` commits at `last_updated_at`
/// (attempts 3 and 4), each injected conflict in `conflicts_at` beating it.
async fn worst_case(
    key: &str,
    conflicts_at: &[usize],
) -> (bool, super::worker_tests::Fixture, usize) {
    let fx = fixture_with(key, created(), 1).await;
    let hook = fx.executor.commit_hook_for_test();
    for &attempt in conflicts_at {
        hook.inject_conflict_before(&fx.id, attempt);
    }
    fx.service.store.set_clock_for_test(Some(created()));
    fx.service.store.set_clock_unreadable_after_for_test(1);
    let (_tx, mut rx) = watch::channel(false);
    let delivered = tokio::time::timeout(
        HANG_BOUND,
        fx.executor
            .settle_cas(OWNER, &fx.id, fx.revision, complete(), &mut rx),
    )
    .await
    .expect("the worst case terminates within the hang bound");
    let attempts = hook.attempts(&fx.id);
    (delivered, fx, attempts)
}

/// R2f (MIK-8202.AC.16, AC.2; lead bound). r4 Bound and r4.1 "at most 4
/// commits": with BOTH fallback commits beaten, `settle_dated_last_known`
/// stops after exactly 2 fallback commits (4 in total), stores nothing and
/// gives no receipt; one wait. Mutant M2g (the fallback retries past one
/// re-read) is killed by `attempts == 4` (it makes a fifth).
#[tokio::test(flavor = "current_thread")]
async fn r2f_the_worst_case_stops_after_two_fallback_commits() {
    #[cfg(feature = "metrics")]
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    #[cfg(feature = "metrics")]
    let metrics = recorder.handle();
    #[cfg(feature = "metrics")]
    let _guard = telemetry_metrics::set_default_local_recorder(&recorder);

    let (delivered, fx, attempts) = worst_case("r2f-two-conflicts", &[1, 3, 4]).await;

    assert_eq!(attempts, 4, "2 main + 2 fallback commits, never a fifth");
    assert!(
        !delivered,
        "a second lost fallback compare-and-set stores nothing"
    );
    assert_eq!(fx.status(), TaskStatus::Working, "the injected writes won");
    #[cfg(feature = "metrics")]
    assert_eq!(clock_waits(&metrics.render()), 1, "{}", metrics.render());
}

/// R2f sibling (MIK-8202.AC.16, AC.2). r4 `settle_dated_last_known`: with ONE
/// fallback commit beaten, the re-read commit stores the ORIGINAL output dated
/// at `last_updated_at`. Mutant M2g's twin (no re-read after the first
/// fallback conflict) is killed by the `Completed` status; the bound by
/// `attempts == 4`.
#[tokio::test(flavor = "current_thread")]
async fn r2f_one_fallback_conflict_still_stores_the_output_at_last_updated_at() {
    let (delivered, fx, attempts) = worst_case("r2f-one-conflict", &[1, 3]).await;

    assert_eq!(attempts, 4, "2 main + 2 fallback commits");
    let stored = fx.service.get(OWNER, &fx.id).expect("the owner reads it");
    assert_eq!(stored.task.status(), TaskStatus::Completed);
    assert!(delivered, "the original output was stored");
    let result = stored.task.result().expect("a result").to_string();
    assert!(result.contains("done"), "the original output: {result}");
    assert_eq!(
        stored.task.last_updated_at(),
        created(),
        "its own last_updated_at"
    );
}
