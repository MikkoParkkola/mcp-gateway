// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Settle under the F20 bound (delta S1-S1''''): Refused only while no task
//! exists or before its first byte, Unconfirmed once a dispatched write is
//! not confirmed, and a repeat delivered at least once. The timing rows run
//! on a paused clock moved by hand, as the bounded rows do; the rest run on
//! the real clock with the default bound.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

#[cfg(feature = "webui")]
use serde_json::{Map, Value};

use super::rotation::WriteFault;
use super::rotation_tests::{cfg, log_path};
use super::settle::{FailSettle, Role, Unsettled};
use super::settle_tests::{on_disk, payload, records_of};
use super::*;

/// The F20 bound the timing rows set: a paused clock makes its size free.
const LIMIT: Duration = Duration::from_secs(5);
const TICK: Duration = Duration::from_millis(1);
/// One tick before a bound: the last moment a call must still be waiting.
const JUST_BEFORE: Duration = LIMIT
    .checked_sub(TICK)
    .expect("the bound is longer than a tick");

fn opened(dir: &tempfile::TempDir) -> (std::path::PathBuf, Arc<TransparencyLogger>) {
    let path = log_path(dir);
    let l = Arc::new(TransparencyLogger::open(cfg(&path, 12, false)).unwrap());
    (path, l)
}

async fn settle_once(
    l: &Arc<TransparencyLogger>,
    token: &str,
) -> Result<super::settle::Appended, Unsettled> {
    let own = l.log_id();
    l.settle(&own, token, Role::Outcome, payload()).await
}

/// Settle answers within twice its bound (10 s at the default); a real-clock
/// row gives up well past that, naming the call, so a hang fails the row.
const WATCHDOG: Duration = Duration::from_secs(30);

/// A real-clock settle of `token`, failing the row if `what` hangs.
async fn settle_watched(
    l: &Arc<TransparencyLogger>,
    token: &str,
    what: &str,
) -> Result<super::settle::Appended, Unsettled> {
    let own = l.log_id();
    settle_watched_as(l, &own, token, what).await
}

/// As [`settle_watched`], bound to `own` read beforehand: reading the id
/// takes the logger's lock, which a stalled write holds.
async fn settle_watched_as(
    l: &Arc<TransparencyLogger>,
    own: &super::identity::LogId,
    token: &str,
    what: &str,
) -> Result<super::settle::Appended, Unsettled> {
    tokio::time::timeout(WATCHDOG, l.settle(own, token, Role::Outcome, payload()))
        .await
        .unwrap_or_else(|_| panic!("{what} did not return within {WATCHDOG:?}"))
}

type Pending = tokio::task::JoinHandle<Result<super::settle::Appended, Unsettled>>;

/// Start a settle of `token` on the runtime, so the clock can move under it.
fn spawn_settle(l: &Arc<TransparencyLogger>, token: &'static str) -> Pending {
    let l = Arc::clone(l);
    tokio::spawn(async move { settle_once(&l, token).await })
}

/// Yield until `ready`, with real time only as a hang guard: the runtime is
/// never idle meanwhile, so the paused clock does not move by itself.
async fn until(what: &str, ready: impl Fn() -> bool) {
    let guard = std::time::Instant::now();
    while !ready() {
        assert!(
            guard.elapsed() < Duration::from_secs(60),
            "{what} never happened"
        );
        tokio::task::yield_now().await;
    }
}

/// Move the paused clock to a deadline, and require `call` to answer there,
/// with the clock held: a call still waiting on a later timer never answers
/// here, since the clock moves only when this row moves it.
async fn answers_at(call: &Pending, what: &str) {
    tokio::time::advance(TICK).await;
    until(what, || call.is_finished()).await;
}

/// Move the paused clock by `by`, and say whether `call` has answered.
async fn advance(call: &Pending, by: Duration) -> bool {
    tokio::time::advance(by).await;
    tokio::task::yield_now().await;
    call.is_finished()
}

fn tasks(l: &TransparencyLogger) -> usize {
    l.bound.closures_entered.load(Ordering::SeqCst)
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_settle_that_cannot_take_the_permit_is_refused_at_the_bound_with_no_task() {
    // GIVEN: the one append permit held by another append
    let dir = crate::test_dir_keep::kept_tempdir();
    let (path, l) = opened(&dir);
    *l.bound.limit.lock().unwrap() = LIMIT;
    let held = l.hold_append_permit_for_test().await;
    let (before, started) = (on_disk(&path), tasks(&l));

    // WHEN: it is settled, and the clock reaches the permit bound
    let waits = l.permit_waits_for_test();
    let call = spawn_settle(&l, "w-1");
    until("the permit wait", || l.permit_waits_for_test() > waits).await;
    assert!(
        !advance(&call, JUST_BEFORE).await,
        "gave up before the bound"
    );
    answers_at(&call, "an answer at the bound").await;
    let got = call.await.unwrap();

    // THEN: Refused as a timeout, no task ever ran, nothing appended
    let timed_out =
        matches!(&got, Err(Unsettled::Refused(e)) if e.kind() == std::io::ErrorKind::TimedOut);
    assert!(timed_out, "{got:?}");
    assert_eq!(tasks(&l), started);
    assert_eq!(on_disk(&path), before);
    drop(held);
}

#[tokio::test]
async fn a_settle_with_the_permit_closed_or_the_log_stalled_is_refused_at_once() {
    for refusal in ["closed", "stalled"] {
        // GIVEN: the permit closed, or a write stalled past its bound
        let dir = crate::test_dir_keep::kept_tempdir();
        let (path, l) = opened(&dir);
        let own = l.log_id();
        assert!(
            settle_watched(&l, "w-0", "the settle before the refusal")
                .await
                .is_ok()
        );
        let stall = (refusal == "stalled").then(|| {
            let stall = l.stall_next_write_for_test(Duration::from_millis(100));
            (stall, Arc::clone(&l))
        });
        if let Some((_, l)) = &stall {
            let got = settle_watched(l, "w-stuck", "the settle that stalls").await;
            assert!(matches!(got, Err(Unsettled::Unconfirmed(_))), "{got:?}");
            assert!(l.is_stalled());
        } else {
            l.close_append_permit_for_test();
        }
        let (before, started) = (on_disk(&path), tasks(&l));
        let waits = l.permit_waits_for_test();

        // WHEN: it is settled
        let got = settle_watched_as(&l, &own, "w-1", "the refused settle").await;

        // THEN: Refused, no task started, nothing appended
        assert!(
            matches!(got, Err(Unsettled::Refused(_))),
            "{refusal}: {got:?}"
        );
        assert_eq!(tasks(&l), started, "{refusal}");
        assert_eq!(on_disk(&path), before, "{refusal}");
        if refusal == "stalled" {
            // Refused at once: it never queued for the permit.
            assert_eq!(l.permit_waits_for_test(), waits, "{refusal}");
        }
        if let Some((stall, l)) = stall {
            l.release_and_drain(stall).await;
        }
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_settle_task_held_past_the_bound_is_unconfirmed_and_lands_once() {
    // GIVEN: settle's task held before it starts any work
    let dir = crate::test_dir_keep::kept_tempdir();
    let (path, l) = opened(&dir);
    *l.bound.limit.lock().unwrap() = LIMIT;
    let gate = l.hold_settle_task_for_test();

    // WHEN: it is settled, and the clock reaches the write bound
    let call = spawn_settle(&l, "w-1");
    until("the task start", || gate.is_entered()).await;
    assert!(
        !advance(&call, JUST_BEFORE).await,
        "gave up before the bound"
    );
    answers_at(&call, "an answer at the bound").await;
    let got = call.await.unwrap();

    // THEN: Unconfirmed (the task exists and may run); once let go and
    // drained, it has landed exactly once
    assert!(matches!(got, Err(Unsettled::Unconfirmed(_))), "{got:?}");
    l.release_and_drain(gate).await;
    assert_eq!(records_of(&path, "w-1").len(), 1);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_settle_answers_within_twice_the_bound() {
    // GIVEN: the permit held for most of its bound, then a write that stalls
    let dir = crate::test_dir_keep::kept_tempdir();
    let (_, l) = opened(&dir);
    let stall = l.stall_next_write_for_test(LIMIT);
    *l.bound.limit.lock().unwrap() = LIMIT;
    let held = l.hold_append_permit_for_test().await;
    let waits = l.permit_waits_for_test();
    let call = spawn_settle(&l, "w-1");
    until("the permit wait", || l.permit_waits_for_test() > waits).await;
    assert!(!advance(&call, JUST_BEFORE).await);

    // WHEN: the permit frees just inside its bound, and the write stalls
    drop(held);
    until("the stalled write", || stall.is_entered()).await;

    // THEN: still waiting one tick before the write bound, and Unconfirmed
    // at it: under twice the bound in all
    assert!(
        !advance(&call, JUST_BEFORE).await,
        "gave up before the bound"
    );
    answers_at(&call, "an answer at the bound").await;
    let got = call.await.unwrap();
    assert!(matches!(got, Err(Unsettled::Unconfirmed(_))), "{got:?}");
    l.release_and_drain(stall).await;
}

/// What a reader was told: the record's kind and its fields.
#[cfg(feature = "webui")]
type Told = Arc<std::sync::Mutex<Vec<(String, Map<String, Value>)>>>;

#[cfg(feature = "webui")]
#[tokio::test]
async fn a_stalled_write_is_unconfirmed_and_its_retry_is_delivered_twice() {
    // GIVEN: readers of `settle.save` and of plain `save`, and the next write
    // stalled past a short bound
    let dir = crate::test_dir_keep::kept_tempdir();
    let (path, l) = opened(&dir);
    let told: Told = Arc::default();
    for kind in ["save", "settle.save"] {
        let sink = Arc::clone(&told);
        l.subscribe(
            kind,
            Arc::new(move |f: &Map<String, Value>, _: &str, _: u64| {
                let kind = f
                    .get("kind")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                sink.lock().unwrap().push((kind, f.clone()));
            }),
        );
    }
    let stall = l.stall_next_write_for_test(Duration::from_millis(100));

    // WHEN: it is settled, the write released and drained, then retried
    let got = settle_watched(&l, "w-1", "the stalled settle").await;
    l.release_and_drain(stall).await;
    let landed = records_of(&path, "w-1").len();
    *l.bound.limit.lock().unwrap() = super::bounded::AUDIT_APPEND_TIMEOUT;
    let retried = settle_watched(&l, "w-1", "the retried settle").await;

    // THEN: Unconfirmed, landed once, then Appended; two records, and the
    // `settle.save` reader told twice with equal role, token and payload
    assert!(matches!(got, Err(Unsettled::Unconfirmed(_))), "{got:?}");
    assert_eq!(landed, 1);
    assert!(retried.is_ok(), "{retried:?}");
    assert_eq!(records_of(&path, "w-1").len(), 2);
    let told = told.lock().unwrap();
    assert_eq!(told.len(), 2, "plain `save` is told nothing");
    let given = payload();
    let equal = |f: &Map<String, Value>| {
        let keys = given
            .keys()
            .cloned()
            .chain(["event".into(), "token".into()]);
        keys.map(|k| f.get(&k).cloned()).collect::<Vec<_>>()
    };
    assert!(told.iter().all(|(kind, _)| kind == "settle.save"));
    assert_eq!(equal(&told[0].1), equal(&told[1].1));
}

#[tokio::test]
async fn a_failed_or_partial_write_or_sync_or_a_panic_is_unconfirmed() {
    for fault in ["sync", "partial", "panic"] {
        // GIVEN: a sync that fails, a write cut short, or a task that panics
        let dir = crate::test_dir_keep::kept_tempdir();
        let (path, l) = opened(&dir);
        assert!(
            settle_watched(&l, "w-0", "the settle before the fault")
                .await
                .is_ok()
        );
        let fired = l.write_faults_fired();
        match fault {
            "sync" => l.arm_write_fault(Some(WriteFault::SyncError)),
            "partial" => l.arm_write_fault(Some(WriteFault::FullForever)),
            _ => l.arm_settle_fault(FailSettle::PanicInTask),
        }

        // WHEN: it is settled
        let got = settle_watched(&l, "w-1", "the faulted settle").await;

        // THEN: the fault fired, and the result is Unconfirmed by it, not by
        // a timeout: the write was dispatched, its landing unproven
        let consumed = if fault == "panic" {
            l.hooks.settle_fault.lock().unwrap().is_none()
        } else {
            l.write_faults_fired() > fired
        };
        assert!(consumed, "{fault}: the fault never fired");
        let by_fault = matches!(&got, Err(Unsettled::Unconfirmed(e)) if e.kind() != std::io::ErrorKind::TimedOut);
        assert!(by_fault, "{fault}: {got:?}");
        l.arm_write_fault(None);
        assert!(records_of(&path, "w-1").len() <= 1, "{fault}");
    }
}

#[tokio::test]
async fn a_refresh_failure_is_refused_and_counted_like_a_failed_append() {
    // GIVEN: the active file replaced by one recovery cannot read
    let dir = crate::test_dir_keep::kept_tempdir();
    let (path, l) = opened(&dir);
    assert!(
        settle_watched(&l, "w-0", "the settle before the refresh failure")
            .await
            .is_ok()
    );
    let failures = l.append_failures();
    let swapped = path.with_extension("swap");
    std::fs::write(&swapped, "not a record\n").unwrap();
    std::fs::rename(&swapped, &path).unwrap();

    // WHEN: it is settled
    let got = settle_watched(&l, "w-1", "the settle after the refresh failure").await;

    // THEN: Refused before any byte, and the log's health counts it
    assert!(matches!(got, Err(Unsettled::Refused(_))), "{got:?}");
    assert_eq!(l.append_failures(), failures + 1);
}
