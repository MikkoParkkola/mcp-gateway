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
