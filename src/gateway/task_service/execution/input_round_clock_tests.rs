// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `readable_now`'s two stops on a clock before 1970 (MIK-8202): the task's
//! row is gone, and the cancel sender is dropped. Paused time; no wall clock.

use super::{ClockWait, readable_now};
use crate::gateway::task_service::StoreLimits;
use crate::gateway::task_service::TaskStore;
use tokio::sync::watch;

/// A store whose clock reads before 1970, holding no task.
async fn store_before_epoch() -> (TaskStore, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = TaskStore::open(&dir.path().join("tasks"), StoreLimits::default())
        .await
        .expect("an empty store opens");
    store.set_clock_for_test(chrono::DateTime::from_timestamp(-1, 0));
    (store, dir)
}

/// A wait for a task whose row has left the store stops at its next retry:
/// nothing is left to wait for. Mutant: the gone row read as no bound.
#[tokio::test(start_paused = true)]
async fn a_wait_for_a_row_that_is_gone_stops() {
    let (store, _dir) = store_before_epoch().await;
    let (_tx, mut rx) = watch::channel(false);
    let outcome = readable_now(&store, "task-gone", &mut rx).await;
    assert!(matches!(outcome, ClockWait::Stopped));
    assert!(
        store.refused_reads_for_test() >= 2,
        "it retried once before stopping"
    );
}

/// A wait whose cancel sender is gone stops at once: nothing can cancel it
/// any more. Mutant: a dropped sender read as a retry.
#[tokio::test(start_paused = true)]
async fn a_wait_whose_cancel_sender_is_dropped_stops() {
    let (store, _dir) = store_before_epoch().await;
    let (tx, mut rx) = watch::channel(false);
    drop(tx);
    let outcome = readable_now(&store, "task-gone", &mut rx).await;
    assert!(matches!(outcome, ClockWait::Stopped));
    assert_eq!(
        store.refused_reads_for_test(),
        1,
        "it stopped on its first wait"
    );
}
