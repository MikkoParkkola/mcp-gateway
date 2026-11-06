// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Settle under the F20 bound (delta S1-S1''''): Refused only while no task
//! exists or before its first byte, Unconfirmed once a dispatched write is
//! not confirmed, and a repeat delivered at least once.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Map, Value};

use super::rotation::WriteFault;
use super::rotation_tests::{cfg, log_path};
use super::settle::{FailSettle, Role, Unsettled};
use super::settle_tests::{on_disk, payload, records_of};
use super::*;

/// The F20 bound the rows run under: short, so a timeout costs little.
const LIMIT: Duration = Duration::from_millis(300);

/// Settle answers within twice the bound (S1'); this guards that bound with
/// a margin for a loaded runner, so only a wait on the stalled write trips it.
const WITHIN: Duration = Duration::from_secs(3);

fn opened(dir: &tempfile::TempDir) -> (std::path::PathBuf, Arc<TransparencyLogger>) {
    let path = log_path(dir);
    let l = Arc::new(TransparencyLogger::open(cfg(&path, 12, false)).unwrap());
    *l.bound.limit.lock().unwrap() = LIMIT;
    (path, l)
}

async fn settle_once(
    l: &Arc<TransparencyLogger>,
    token: &str,
) -> Result<super::settle::Appended, Unsettled> {
    let call = l.settle(&l.log_id(), token, Role::Outcome, payload());
    tokio::time::timeout(WITHIN, call)
        .await
        .expect("settle answers within twice the F20 bound")
}

/// Wait until `token` has `n` records, for at most the hang bound.
async fn records_reach(path: &std::path::Path, token: &str, n: usize) {
    let deadline = tokio::time::Instant::now() + crate::test_wait::HANG_BOUND;
    while records_of(path, token).len() < n {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{token} never reached {n}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_settle_that_cannot_take_the_permit_is_refused_and_starts_no_task() {
    // GIVEN: the one append permit held by another append
    let dir = tempfile::tempdir().unwrap();
    let (path, l) = opened(&dir);
    assert!(settle_once(&l, "w-0").await.is_ok());
    let held = l.hold_append_permit_for_test().await;
    let (before, tasks) = (
        on_disk(&path),
        l.bound
            .closures_entered
            .load(std::sync::atomic::Ordering::SeqCst),
    );

    // WHEN: it is settled
    let got = settle_once(&l, "w-1").await;

    // THEN: Refused as a timeout, no task ever ran, nothing appended; the
    // next settle lands once the permit is free
    assert!(
        matches!(&got, Err(Unsettled::Refused(e)) if e.kind() == std::io::ErrorKind::TimedOut),
        "{got:?}"
    );
    assert_eq!(
        l.bound
            .closures_entered
            .load(std::sync::atomic::Ordering::SeqCst),
        tasks
    );
    assert!(on_disk(&path) == before);
    drop(held);
    assert!(settle_once(&l, "w-2").await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_settle_task_queued_past_the_bound_is_unconfirmed_and_lands_once() {
    // GIVEN: settle's task held before it starts any work
    let dir = tempfile::tempdir().unwrap();
    let (path, l) = opened(&dir);
    let gate = l.hold_settle_task_for_test();

    // WHEN: it is settled, then the task is let go
    let got = settle_once(&l, "w-1").await;
    gate.release();

    // THEN: Unconfirmed (the task exists and may run), and it lands once
    assert!(matches!(got, Err(Unsettled::Unconfirmed(_))), "{got:?}");
    records_reach(&path, "w-1", 1).await;
    assert_eq!(records_of(&path, "w-1").len(), 1);
}
