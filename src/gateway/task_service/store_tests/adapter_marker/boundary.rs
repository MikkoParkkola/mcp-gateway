// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;

/// STORE-04's inclusive serialized cap applies to dispatch-marker rewrites too.
#[tokio::test]
async fn marker_07_repeated_marker_at_exact_record_cap_preserves_durable_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let (task, binding) = admitted(&store, &services(), "exact-marker-cap").await;
    let owner = binding.principal_digest().to_owned();
    store.mark_dispatched(&owner, task.id(), 1).await.unwrap();
    let before = fs::read(path.join(format!("{}.json", task.id()))).unwrap();
    let wire = serde_json::to_value(store.get(&owner, task.id()).unwrap().task.wire()).unwrap();
    store.close().await.unwrap();

    // Reopen an actual committed record at its exact inclusive maximum. The
    // loader and marker writer must agree; a legal loaded record cannot become
    // unwritable merely because the marker is already present.
    let store = TaskStore::open(
        &path,
        StoreLimits {
            record_bytes: before.len(),
            ..StoreLimits::default()
        },
    )
    .await
    .expect("the loader accepts a record exactly at the byte cap");
    store
        .mark_dispatched(&owner, task.id(), 1)
        .await
        .expect("the unchanged marker fits exactly at the inclusive cap");
    assert_eq!(
        fs::read(path.join(format!("{}.json", task.id()))).unwrap(),
        before
    );
    let after = store.get(&owner, task.id()).unwrap();
    assert_eq!(after.revision, 1);
    assert_eq!(serde_json::to_value(after.task.wire()).unwrap(), wire);
    store.close().await.unwrap();
}
