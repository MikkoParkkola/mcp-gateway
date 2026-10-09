// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7839.CANCEL.3 (C2): once a store stops serving, no mutation is
//! admitted. The guard a dropped stdio session leaves behind calls it from
//! `Drop`, so it must refuse without waiting on the ordering lock or the disk.

use super::support::*;
use super::*;

#[tokio::test]
async fn a_store_that_stopped_serving_admits_no_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let task = task();
    store
        .create(PreparedTask::for_test(&task, OWNER, 1))
        .await
        .expect("a live store admits a create");
    let before = files(&path);

    store.stop_serving();

    let settled = store
        .transition(OWNER, task.id(), 1, TaskTransition::Cancel, at(1))
        .await;
    assert!(
        matches!(settled, Err(StoreError::Unavailable)),
        "a transition after stop_serving was admitted: {settled:?}"
    );
    let another = super::support::task();
    let created = store
        .create(PreparedTask::for_test(&another, OWNER, 2))
        .await;
    assert!(
        matches!(created, Err(StoreError::Unavailable)),
        "a create after stop_serving was admitted: {created:?}"
    );
    assert_eq!(files(&path), before, "a refused mutation changed the store");
}

/// The cutoff never waits on the ordering lock: with a mutation admitted and
/// paused mid-write (holding that lock), `stop_serving` still returns at once.
/// The admitted mutation then finishes, and the next one is refused.
#[tokio::test]
async fn stopping_does_not_wait_for_a_write_in_flight() {
    use std::sync::mpsc::channel;
    use std::time::Duration;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let task = task();
    store
        .create(PreparedTask::for_test(&task, OWNER, 1))
        .await
        .expect("a live store admits a create");
    let (reached_tx, reached) = channel();
    let (unpause, paused) = channel::<()>();
    let paused = std::sync::Mutex::new(paused);
    let hook: CommitHook = Arc::new(move |stage| {
        if stage == CommitStage::Write {
            let _ = reached_tx.send(());
            let _ = paused.lock().unwrap().recv_timeout(Duration::from_secs(10));
        }
        Ok(())
    });
    store.set_hook(Some(hook)).await;
    let writer = store.clone();
    let admitted = tokio::spawn(async move {
        writer
            .transition(OWNER, task.id(), 1, TaskTransition::Cancel, at(1))
            .await
    });
    tokio::task::spawn_blocking(move || reached.recv_timeout(Duration::from_secs(5)))
        .await
        .unwrap()
        .expect("the admitted write reached its commit, holding the ordering lock");

    let (cutoff_tx, cutoff_done) = channel();
    let cutoff_store = store.clone();
    std::thread::spawn(move || {
        cutoff_store.stop_serving();
        let _ = cutoff_tx.send(());
    });
    let returned =
        tokio::task::spawn_blocking(move || cutoff_done.recv_timeout(Duration::from_secs(1)))
            .await
            .unwrap();
    unpause.send(()).unwrap();
    assert!(
        returned.is_ok(),
        "stop_serving waited on the write in flight"
    );
    admitted
        .await
        .unwrap()
        .expect("a write admitted before the cutoff finishes");
    store.set_hook(None).await;
    let another = super::support::task();
    let created = store
        .create(PreparedTask::for_test(&another, OWNER, 2))
        .await;
    assert!(
        matches!(created, Err(StoreError::Unavailable)),
        "a create after stop_serving was admitted: {created:?}"
    );
}
