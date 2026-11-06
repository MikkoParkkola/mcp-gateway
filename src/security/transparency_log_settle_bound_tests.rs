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

use serde_json::{Map, Value};

use super::rotation::WriteFault;
use super::rotation_tests::{cfg, log_path};
use super::settle::{FailSettle, Role, Unsettled};
use super::settle_tests::{on_disk, payload, records_of};
use super::*;

/// The F20 bound the timing rows set: a paused clock makes its size free.
const LIMIT: Duration = Duration::from_secs(5);
const TICK: Duration = Duration::from_millis(1);

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
    let dir = tempfile::tempdir().unwrap();
    let (path, l) = opened(&dir);
    *l.bound.limit.lock().unwrap() = LIMIT;
    let held = l.hold_append_permit_for_test().await;
    let (before, started) = (on_disk(&path), tasks(&l));

    // WHEN: it is settled, and the clock reaches the permit bound
    let waits = l.permit_waits_for_test();
    let call = spawn_settle(&l, "w-1");
    until("the permit wait", || l.permit_waits_for_test() > waits).await;
    assert!(
        !advance(&call, LIMIT - TICK).await,
        "gave up before the bound"
    );
    advance(&call, TICK).await;
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
        let dir = tempfile::tempdir().unwrap();
        let (path, l) = opened(&dir);
        assert!(settle_once(&l, "w-0").await.is_ok());
        let stall = (refusal == "stalled").then(|| {
            let stall = l.stall_next_write_for_test(Duration::from_millis(100));
            (stall, Arc::clone(&l))
        });
        if let Some((_, l)) = &stall {
            let got = settle_once(l, "w-stuck").await;
            assert!(matches!(got, Err(Unsettled::Unconfirmed(_))), "{got:?}");
            assert!(l.is_stalled());
        } else {
            l.close_append_permit_for_test();
        }
        let (before, started) = (on_disk(&path), tasks(&l));

        // WHEN: it is settled
        let got = settle_once(&l, "w-1").await;

        // THEN: Refused, no task started, nothing appended
        assert!(
            matches!(got, Err(Unsettled::Refused(_))),
            "{refusal}: {got:?}"
        );
        assert_eq!(tasks(&l), started, "{refusal}");
        assert_eq!(on_disk(&path), before, "{refusal}");
        if let Some((stall, l)) = stall {
            l.release_and_drain(stall).await;
        }
    }
}
