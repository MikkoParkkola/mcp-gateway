// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202 P4a: the worker settle on a store clock that reads before 1970
//! (design r4 "Worker settle: one rule, bounded", r4.1). These rows compile
//! against base 6c62a0985 and are red there by behaviour: base's
//! `transition_digest_write` dates a `None` settle at chrono's wall clock, never reading
//! the store clock, so no row below sees a refused read, a wait or the flip
//! time. Rows that need seams base lacks live in
//! `worker_clock_settle_compile_red_tests.rs`.
//!
//! Each `settle_cas` call passes a cancel receiver whose sender stays alive,
//! so a clock wait is never stopped by a dropped sender.

use std::ops::ControlFlow;

use chrono::{DateTime, Utc};
use tokio::sync::watch;

use super::worker_tests::{Fixture, OWNER, complete, fixture_with};
use crate::gateway::task_service::{ServiceError, TaskStatus, TaskTransition};
use crate::test_wait::{HANG_BOUND, wait_until};

/// The task's creation time: fixed and in the past, so a settle dated at
/// base's real now can never equal it.
pub(super) fn created() -> DateTime<Utc> {
    DateTime::from_timestamp(1_700_000_000, 0).expect("a valid instant")
}

/// The time the store clock reads once it is flipped readable.
pub(super) fn flipped() -> DateTime<Utc> {
    DateTime::from_timestamp(1_700_000_600, 0).expect("a valid instant")
}

/// The store clock before 1970.
pub(super) fn dark() -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(-1, 0)
}

/// A working row created at [`created`] with a 24 h TTL.
pub(super) async fn day_task(key: &str) -> Fixture {
    fixture_with(key, created(), 86_400_000).await
}

/// From a second task: once the store has refused `refusals` reads (the
/// settle is waiting), run `then` and flip the clock readable at
/// [`flipped`], with `unreadable_after` readable reads left before it goes
/// dark again (`None`: stays readable). Bounded by `HANG_BOUND`; on base the
/// refusal never comes, so the flip never happens and the caller aborts it.
pub(super) fn flip_when_waiting(
    fx: &Fixture,
    refusals: usize,
    unreadable_after: Option<usize>,
    then: Option<TaskTransition>,
) -> tokio::task::JoinHandle<()> {
    let service = std::sync::Arc::clone(&fx.service);
    let (owner, id, revision) = (fx.owner_digest.clone(), fx.id.clone(), fx.revision);
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
        if let Some(event) = then {
            // Dated explicitly: this write never reads the dark clock.
            service
                .store
                .transition(&owner, &id, revision, event, created())
                .await
                .expect("the concurrent write commits at the revision read");
        }
        if let Some(reads) = unreadable_after {
            service.store.set_clock_unreadable_after_for_test(reads);
        }
        service.store.set_clock_for_test(Some(flipped()));
    })
}

/// `mcp_task_clock_waits_total` from a local Prometheus render.
#[cfg(feature = "metrics")]
pub(super) fn clock_waits(rendered: &str) -> u64 {
    rendered
        .lines()
        .filter(|l| l.starts_with("mcp_task_clock_waits_total"))
        .filter_map(|l| l.rsplit(' ').next()?.parse::<u64>().ok())
        .sum()
}

/// R2 (MIK-8202.AC.16, AC.2). r4 rule 1: a commit dated `None` that meets
/// `ClockUnreadable` waits once in `readable_now`, then commits the SAME
/// outcome dated `Some(t)` at the first readable time. Mutant M2a (the worker
/// drops the outcome on `ClockUnreadable`) is killed by `delivered` and the
/// `Completed` status; M2b (the retry takes a fresh read instead of `at`) is
/// killed by `readable_reads == 1` and the `Completed` status: the clock goes
/// dark again right after the wait's one readable read, so a fresh read is
/// refused and the retry cannot commit.
/// Red on base: base settles at chrono's wall clock, so `last_updated_at != flipped()`.
#[tokio::test(flavor = "current_thread")]
async fn r2_a_settle_on_a_dark_clock_keeps_its_outcome_dated_at_the_first_readable_time() {
    #[cfg(feature = "metrics")]
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    #[cfg(feature = "metrics")]
    let metrics = recorder.handle();
    #[cfg(feature = "metrics")]
    let _guard = telemetry_metrics::set_default_local_recorder(&recorder);
    let fx = day_task("r2-dark-settle").await;
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
    assert!(
        delivered,
        "the backend's output was stored and is receipted"
    );
    let result = stored.task.result().expect("a result").to_string();
    assert!(result.contains("done"), "the backend's output: {result}");
    assert_eq!(
        stored.task.last_updated_at(),
        flipped(),
        "dated at the read"
    );
    let store = &fx.service.store;
    assert!(
        store.refused_reads_for_test() >= 1,
        "the settle met the dark clock"
    );
    assert_eq!(
        store.readable_reads_for_test(),
        1,
        "the wait's one read dates the commit; no fresh read follows it"
    );
    #[cfg(feature = "metrics")]
    assert_eq!(clock_waits(&metrics.render()), 1, "{}", metrics.render());
}

/// R2b, worker site (MIK-8202.AC.16, AC.2). r4 rule 1 `Expired` →
/// `settle_dated_last_known`: a clock that stays dark past the task's 1 ms TTL
/// ends the one wait, and the ORIGINAL outcome is committed dated at the
/// record's own `last_updated_at` (here its creation time), never 1969 or 0;
/// exactly one wait is counted. Mutant M2c (Expired waits again) is killed by
/// the `HANG_BOUND` timeout and the wait count of 1; M2e (Expired settles
/// `clock_expired` instead) by the `Completed` status and the output check.
/// Red on base: base settles at chrono's wall clock, so the date is not `created()`.
/// P2's input-round Expired site is not rowed here: `readable_or_fail` is
/// private to `input_round` and unreachable from this module.
#[tokio::test(flavor = "current_thread")]
async fn r2b_an_expired_wait_settles_the_original_outcome_at_last_updated_at() {
    #[cfg(feature = "metrics")]
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    #[cfg(feature = "metrics")]
    let metrics = recorder.handle();
    #[cfg(feature = "metrics")]
    let _guard = telemetry_metrics::set_default_local_recorder(&recorder);
    let fx = fixture_with("r2b-expired", created(), 1).await;
    fx.service.store.set_clock_for_test(dark());

    let (_tx, mut rx) = watch::channel(false);
    let delivered = tokio::time::timeout(
        HANG_BOUND,
        fx.executor
            .settle_cas(OWNER, &fx.id, fx.revision, complete(), &mut rx),
    )
    .await
    .expect("an expired wait settles without waiting again");

    let stored = fx.service.get(OWNER, &fx.id).expect("the owner reads it");
    assert_eq!(
        stored.task.status(),
        TaskStatus::Completed,
        "not clock_expired"
    );
    assert!(delivered, "the backend's output was stored");
    let result = stored.task.result().expect("a result").to_string();
    assert!(result.contains("done"), "the original output: {result}");
    assert_eq!(
        stored.task.last_updated_at(),
        created(),
        "its own last_updated_at"
    );
    assert!(
        fx.service.store.refused_reads_for_test() >= 1,
        "the clock was read"
    );
    #[cfg(feature = "metrics")]
    assert_eq!(clock_waits(&metrics.render()), 1, "{}", metrics.render());
}

/// R2c (MIK-8202.AC.16, AC.2). r3/r4 Typing: `ClockUnreadable` is mapped to
/// `ServiceError::Unavailable` only at `commit_to_service`, so a request-side
/// cancel on a dark clock answers Unavailable and leaves the task unchanged.
/// Mutant M2d (`ClockUnreadable` mapped to `RevisionConflict` inside
/// `transition_digest_write`) is killed by `refused_reads == 1`: a conflict
/// sends the cancel to `cancel_lost_the_revision`, whose retry reads the
/// clock a second time. Red on base: base cancels at chrono's wall clock.
#[tokio::test(flavor = "current_thread")]
async fn r2c_a_cancel_on_a_dark_clock_is_unavailable_and_changes_nothing() {
    let fx = day_task("r2c-cancel").await;
    fx.service.store.set_clock_for_test(dark());

    let cancelled = fx.executor.cancel(OWNER, &fx.id, fx.revision).await;

    assert!(
        matches!(cancelled, Err(ServiceError::Unavailable)),
        "a dark clock is unavailable: {cancelled:?}"
    );
    assert_eq!(fx.status(), TaskStatus::Working, "the task is unchanged");
    assert_eq!(fx.stored_revision(), fx.revision, "nothing was written");
    assert_eq!(
        fx.service.store.refused_reads_for_test(),
        1,
        "one refused read and no CancelRetry: a clock refusal, not a conflict"
    );
}

/// R2e (MIK-8202.AC.16, AC.2; lead). r4 rule 2 and r4.1 Precedence: every
/// attempt follows the one rule. The first commit reads a readable clock and
/// then loses its compare-and-set (`move_on`); the retry meets a dark clock
/// (`set_clock_unreadable_after_for_test(1)`), waits, and commits the original
/// output at the flip time. Mutant M2f (the second attempt's
/// `ClockUnreadable` falls into the catch-all) is killed by the `Completed`
/// status and `delivered`. Red on base: both attempts read chrono's wall clock, so the
/// date is not `flipped()`.
#[tokio::test(flavor = "current_thread")]
async fn r2e_a_retry_after_a_conflict_that_meets_a_dark_clock_keeps_the_output() {
    let fx = day_task("r2e-conflict-dark").await;
    // The concurrent write is dated at `created()`, not at the real clock
    // (`move_on`): a record keeps `max(last_updated_at, at)`, so a 2026 date
    // here would outrank the flip time the row asserts.
    fx.service
        .store
        .transition(
            &fx.owner_digest,
            &fx.id,
            fx.revision,
            TaskTransition::StatusMessage(Some("busy".into())),
            created(),
        )
        .await
        .expect("the row moves on at the revision read");
    fx.service.store.set_clock_for_test(Some(created()));
    fx.service.store.set_clock_unreadable_after_for_test(1);
    let flip = flip_when_waiting(&fx, 1, None, None);

    let (_tx, mut rx) = watch::channel(false);
    let delivered = fx
        .executor
        .settle_cas(OWNER, &fx.id, fx.revision, complete(), &mut rx)
        .await;
    flip.abort();

    let stored = fx.service.get(OWNER, &fx.id).expect("the owner reads it");
    assert_eq!(stored.task.status(), TaskStatus::Completed);
    assert!(delivered, "the original output was stored");
    let result = stored.task.result().expect("a result").to_string();
    assert!(result.contains("done"), "the original output: {result}");
    assert_eq!(
        stored.task.last_updated_at(),
        flipped(),
        "dated at the flip"
    );
    assert!(
        fx.service.store.refused_reads_for_test() >= 1,
        "the retry met the dark clock"
    );
}

/// R2g (MIK-8202.AC.16, AC.2; gpt). r4.1 Terminal guard: a cancel that lands
/// during the wait leaves the record terminal at the post-wait re-read, so
/// the settle returns `false` (no relay receipt) and the cancel stands.
/// Mutant M2h (the terminal guard after the post-wait re-read is removed) is
/// killed by `!delivered` and the `Cancelled` status. Red on base: base never
/// waits and completes the task at chrono's wall clock, returning `true`.
#[tokio::test(flavor = "current_thread")]
async fn r2g_a_cancel_during_the_wait_gives_no_receipt() {
    let fx = day_task("r2g-cancel-in-wait").await;
    fx.service.store.set_clock_for_test(dark());
    let flip = flip_when_waiting(&fx, 1, None, Some(TaskTransition::Cancel));

    let (_tx, mut rx) = watch::channel(false);
    let delivered = fx
        .executor
        .settle_cas(OWNER, &fx.id, fx.revision, complete(), &mut rx)
        .await;
    flip.abort();

    assert!(!delivered, "no receipt for an outcome that was not stored");
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
