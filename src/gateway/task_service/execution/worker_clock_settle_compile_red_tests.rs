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
//!
//! The loss-arm rows at the end pin one branch each of the three functions
//! the critical-coverage grade watches (MIK-8202 P4a). Every one needs the
//! hook or a settle entry base lacks, so all live here.

use std::ops::ControlFlow;
use std::sync::atomic::Ordering;

use tokio::sync::watch;

#[cfg(feature = "metrics")]
use super::worker_clock_settle_tests::clock_waits;
use super::worker_clock_settle_tests::{created, dark, day_task, flip_when_waiting, flipped};
use super::worker_tests::{Fixture, OWNER, complete, fixture_with};
use crate::gateway::gateway_writes::WriteRecord;
use crate::gateway::task_service::{ErrorAuthor, TaskStatus, TaskTransition};
use crate::test_wait::{HANG_BOUND, wait_until};

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

/// Once the store has refused `refusals` reads (the settle is waiting), set
/// the task's cancel flag. Bounded by `HANG_BOUND`: when the wait never
/// starts, the flag is never set and the caller aborts this.
fn stop_when_waiting(
    fx: &Fixture,
    refusals: usize,
    tx: watch::Sender<bool>,
) -> tokio::task::JoinHandle<()> {
    let service = std::sync::Arc::clone(&fx.service);
    tokio::spawn(async move {
        let waiting = wait_until(HANG_BOUND, || {
            let refused = service.store.refused_reads_for_test();
            async move {
                if refused >= refusals {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(format!("{refused} refused reads"))
                }
            }
        })
        .await;
        if waiting.is_err() {
            return;
        }
        let _ = tx.send(true);
    })
}

/// MIK-8202 P4a: `settle_cas_by`'s second-`RevisionConflict` arm. Two
/// injected conflicts beat both commits on a readable clock, so the outcome
/// is lost: `false`, the row stays working, and exactly two attempts ran.
#[tokio::test(flavor = "current_thread")]
async fn p4a_two_conflicts_lose_the_outcome_after_two_attempts() {
    let fx = day_task("p4a-two-conflicts").await;
    let hook = fx.executor.commit_hook_for_test();
    hook.inject_conflict_before(&fx.id, 1);
    hook.inject_conflict_before(&fx.id, 2);

    let (_tx, mut rx) = watch::channel(false);
    let delivered = fx
        .executor
        .settle_cas(OWNER, &fx.id, fx.revision, complete(), &mut rx)
        .await;

    assert!(!delivered, "a second lost compare-and-set stores nothing");
    assert_eq!(hook.attempts(&fx.id), 2, "one retry, then the loss arm");
    let stored = fx.service.get(OWNER, &fx.id).expect("the owner reads it");
    assert_eq!(
        stored.task.status(),
        TaskStatus::Working,
        "the injected writes won"
    );
    assert!(stored.task.result().is_none(), "no outcome was stored");
}

/// MIK-8202 P4a: `settle_cas_by`'s `ClockWait::Stopped` arm. The clock stays
/// dark while the task's cancel flag is set mid-wait, so the settle stops
/// with `false` and no commit follows the wait.
#[tokio::test(flavor = "current_thread")]
async fn p4a_a_cancel_set_during_the_wait_stops_the_settle() {
    let fx = day_task("p4a-stopped").await;
    fx.service.store.set_clock_for_test(dark());
    let hook = fx.executor.commit_hook_for_test();
    let (tx, mut rx) = watch::channel(false);
    let stop = stop_when_waiting(&fx, 1, tx);

    let delivered = tokio::time::timeout(
        HANG_BOUND,
        fx.executor
            .settle_cas(OWNER, &fx.id, fx.revision, complete(), &mut rx),
    )
    .await
    .expect("a stopped wait ends within the hang bound");
    stop.abort();

    assert!(!delivered, "a stopped settle stores nothing");
    assert_eq!(hook.attempts(&fx.id), 1, "no commit follows the wait");
    assert_eq!(fx.status(), TaskStatus::Working, "the row was not settled");
}

/// MIK-8202 P4a: `settle_cas_by`'s merged write-failure arm, through its
/// `Service` half. Every store write fails, so the first commit is a store
/// failure rather than a conflict: `false` after exactly one write attempt.
#[tokio::test(flavor = "current_thread")]
async fn p4a_a_failed_first_write_is_not_retried() {
    let fx = day_task("p4a-service-main").await;
    let hook = fx.executor.commit_hook_for_test();
    let writes = fx.fail_writes().await;

    let (_tx, mut rx) = watch::channel(false);
    let delivered = fx
        .executor
        .settle_cas(OWNER, &fx.id, fx.revision, complete(), &mut rx)
        .await;

    assert!(!delivered, "a failed write stores nothing");
    assert_eq!(
        hook.attempts(&fx.id),
        1,
        "a store failure is not a conflict"
    );
    assert_eq!(writes.load(Ordering::SeqCst), 1, "one write, and no retry");
    assert_eq!(fx.status(), TaskStatus::Working, "the row was not settled");
}

/// MIK-8202 P4a: `settle_dated_last_known`'s terminal re-read. The record is
/// cancelled by a direct store write on a dark clock, so the first attempt
/// meets `ClockUnreadable` (the clock is read before the revision is
/// checked), the 1 ms wait expires, and the fallback's first re-read finds
/// the terminal record: `false` with no fallback commit.
#[tokio::test(flavor = "current_thread")]
async fn p4a_an_expired_wait_finds_a_terminal_record_in_the_fallback() {
    let fx = fixture_with("p4a-terminal-fallback", created(), 1).await;
    fx.service.store.set_clock_for_test(dark());
    // Dated explicitly: this write never reads the dark clock.
    fx.service
        .store
        .transition(
            &fx.owner_digest,
            &fx.id,
            fx.revision,
            TaskTransition::Cancel,
            created(),
        )
        .await
        .expect("the direct cancel commits");
    let hook = fx.executor.commit_hook_for_test();

    let (_tx, mut rx) = watch::channel(false);
    let delivered = tokio::time::timeout(
        HANG_BOUND,
        fx.executor
            .settle_cas(OWNER, &fx.id, fx.revision, complete(), &mut rx),
    )
    .await
    .expect("an expired wait falls back without waiting again");

    assert!(!delivered, "no receipt for an outcome that was not stored");
    assert_eq!(
        hook.attempts(&fx.id),
        1,
        "no fallback commit after a terminal re-read"
    );
    assert!(
        fx.service.store.refused_reads_for_test() >= 1,
        "the first attempt met the dark clock"
    );
    let stored = fx.service.get(OWNER, &fx.id).expect("the owner reads it");
    assert_eq!(
        stored.task.status(),
        TaskStatus::Cancelled,
        "the cancel stands"
    );
    assert!(
        stored.task.result().is_none(),
        "no output was written over it"
    );
}

/// MIK-8202 P4a: `settle_dated_last_known`'s merged write-failure arm,
/// through its `Service` half. The 1 ms wait expires on the dark clock, and
/// the fallback's dated commit fails in the store: `false`, the row working.
#[tokio::test(flavor = "current_thread")]
async fn p4a_a_failed_fallback_write_stores_nothing() {
    let fx = fixture_with("p4a-service-fallback", created(), 1).await;
    fx.service.store.set_clock_for_test(dark());
    let hook = fx.executor.commit_hook_for_test();
    let writes = fx.fail_writes().await;

    let (_tx, mut rx) = watch::channel(false);
    let delivered = tokio::time::timeout(
        HANG_BOUND,
        fx.executor
            .settle_cas(OWNER, &fx.id, fx.revision, complete(), &mut rx),
    )
    .await
    .expect("an expired wait falls back without waiting again");

    assert!(!delivered, "a failed fallback write stores nothing");
    assert_eq!(
        hook.attempts(&fx.id),
        2,
        "the dark attempt, then the failed dated commit"
    );
    assert_eq!(
        writes.load(Ordering::SeqCst),
        1,
        "the dark attempt never reached the disk"
    );
    assert_eq!(fx.status(), TaskStatus::Working, "the row was not settled");
}

/// MIK-8202 P4a: `dated_reread`'s error branch. The fallback opens on an id
/// the store holds no record for, so the re-read fails and the outcome is
/// lost: `false` with no commit attempted.
#[tokio::test(flavor = "current_thread")]
async fn p4a_a_fallback_reread_that_fails_stores_nothing() {
    let fx = day_task("p4a-reread-fails").await;
    let hook = fx.executor.commit_hook_for_test();
    let missing = "task-00000000-0000-4000-8000-000000000000";

    let delivered = fx
        .executor
        .settle_dated_last_known(
            OWNER,
            missing,
            (
                complete(),
                crate::gateway::task_service::record::Provenance::default(),
            ),
            ErrorAuthor::Gateway,
            WriteRecord::default(),
        )
        .await;

    assert!(!delivered, "a failed re-read stores nothing");
    assert_eq!(
        hook.attempts(missing),
        0,
        "no commit without a record to date it at"
    );
}
