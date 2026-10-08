// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;
use crate::gateway::task_service::record::{MAX_UPSTREAM_HANDLE_BYTES, UpstreamRecord};

/// STORE-04's inclusive serialized cap applies to dispatch-marker rewrites too.
#[tokio::test]
async fn marker_07_repeated_marker_at_exact_record_cap_preserves_durable_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let (task, binding) = admitted_with(&store, &services(), "exact-marker-cap", padding()).await;
    let owner = binding.principal_digest().to_owned();
    store.mark_dispatched(&owner, task.id(), 1).await.unwrap();
    let before = fs::read(path.join(format!("{}.json", task.id()))).unwrap();
    let wire = serde_json::to_value(store.get(&owner, task.id()).unwrap().task.wire()).unwrap();
    store.close().await.unwrap();

    // Reopen an actual committed record at its exact inclusive maximum. The
    // loader and marker writer must agree; a legal loaded record cannot become
    // unwritable merely because the marker is already present.
    // The row carries a target its fallback drops, so the loader's fallback
    // room (MIK-7651) fits under this cap and the size check is what is pinned.
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

fn upstream_for(binding: &TaskBinding, handle: &str) -> UpstreamRecord {
    UpstreamRecord {
        handle: handle.into(),
        backend: "orders".into(),
        tool: "create".into(),
        arguments: json!({"sku": "x"}),
        operation_digest: binding.operation().to_owned(),
    }
}

/// Reopen the closed directory with the record cap set to the row's exact size.
/// The row must carry [`padding`], or the loader refuses it for fallback room
/// (MIK-7651) before the size check under test is reached.
async fn reopened_at_exact_cap(path: &Path, id: &str) -> TaskStore {
    let size = fs::read(path.join(format!("{id}.json"))).unwrap().len();
    TaskStore::open(
        path,
        StoreLimits {
            record_bytes: size,
            ..StoreLimits::default()
        },
    )
    .await
    .expect("the loader accepts a record exactly at the byte cap")
}

/// Mutant: any one of the owner, revision, status, digest or handle-length
/// refusals in `mark_upstream` removed.
#[expect(
    clippy::too_many_lines,
    reason = "one table of refusals beside its positive control"
)]
#[tokio::test]
async fn upstream_01_a_descriptor_is_attached_only_to_the_owners_live_matching_row() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let admission = services();
    let (moved, moved_binding) = admitted(&store, &admission, "up-moved").await;
    let (done, done_binding) = admitted(&store, &admission, "up-done").await;
    let (mine, binding) = admitted(&store, &admission, "up-mine").await;
    let owner = binding.principal_digest().to_owned();
    // `ALICE` owns all three, so one owner digest covers every row below.
    assert_eq!(moved_binding.principal_digest(), owner);
    assert_eq!(done_binding.principal_digest(), owner);
    store
        .transition(
            &owner,
            moved.id(),
            1,
            TaskTransition::StatusMessage(Some("working".into())),
            at(1),
        )
        .await
        .unwrap();
    store
        .transition(&owner, done.id(), 1, TaskTransition::Cancel, at(2))
        .await
        .unwrap();
    let before = files(&path);
    let good = upstream_for(&binding, "handle-1");

    let refusals = [
        (
            "foreign owner",
            OTHER,
            mine.id(),
            1,
            good.clone(),
            StoreError::NotFound,
        ),
        (
            "moved revision",
            owner.as_str(),
            moved.id(),
            1,
            upstream_for(&moved_binding, "h"),
            StoreError::RevisionConflict,
        ),
        (
            "terminal row",
            owner.as_str(),
            done.id(),
            2,
            upstream_for(&done_binding, "h"),
            StoreError::InvalidTransition,
        ),
        (
            "another operation's digest",
            owner.as_str(),
            mine.id(),
            1,
            UpstreamRecord {
                operation_digest: "c".repeat(64),
                ..good.clone()
            },
            StoreError::InvalidTransition,
        ),
        (
            "over-long handle",
            owner.as_str(),
            mine.id(),
            1,
            upstream_for(&binding, &"h".repeat(MAX_UPSTREAM_HANDLE_BYTES + 1)),
            StoreError::Capacity,
        ),
    ];
    for (why, who, id, revision, upstream, expected) in refusals {
        assert_eq!(
            store
                .mark_upstream(who, id, revision, upstream)
                .await
                .unwrap_err(),
            expected,
            "{why}"
        );
        assert_eq!(files(&path), before, "{why}: a refusal writes nothing");
    }
    assert_eq!(store.upstream_of(&owner, mine.id()).unwrap().0, None);

    // Positive control: the widest accepted handle attaches, raises the row to
    // the upstream version, and moves no revision.
    let widest = upstream_for(&binding, &"h".repeat(MAX_UPSTREAM_HANDLE_BYTES));
    store
        .mark_upstream(&owner, mine.id(), 1, widest.clone())
        .await
        .unwrap();
    let record = record_json(&path, mine.id());
    assert_eq!(record["version"], json!(3));
    assert_eq!(record["revision"], json!(1));
    let (held, revision, status) = store.upstream_of(&owner, mine.id()).unwrap();
    assert_eq!(
        (held, revision, status),
        (Some(widest), 1, TaskStatus::Working)
    );
    // The descriptor is the owner's alone: a foreign caller meets an absent task.
    assert_eq!(
        store.upstream_of(OTHER, mine.id()).unwrap_err(),
        StoreError::NotFound
    );
    assert_eq!(
        store.operation_digest_of(&owner, mine.id()).as_deref(),
        Some(binding.operation())
    );
    assert_eq!(store.operation_digest_of(OTHER, mine.id()), None);
    store.close().await.unwrap();
}

/// Mutant: the byte-cap check after the descriptor is attached is removed.
#[tokio::test]
async fn upstream_02_a_descriptor_that_overflows_the_record_cap_is_refused_unwritten() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let (task, binding) = admitted_with(&store, &services(), "up-cap", padding()).await;
    let owner = binding.principal_digest().to_owned();
    store.close().await.unwrap();

    let store = reopened_at_exact_cap(&path, task.id()).await;
    let before = files(&path);
    assert_eq!(
        store
            .mark_upstream(&owner, task.id(), 1, upstream_for(&binding, "handle-1"))
            .await
            .unwrap_err(),
        StoreError::Capacity
    );
    assert_eq!(
        files(&path),
        before,
        "a descriptor that does not fit is not written"
    );
    assert_eq!(store.upstream_of(&owner, task.id()).unwrap().0, None);
    store.close().await.unwrap();

    // Positive control: with room, the same descriptor is persisted.
    let store = open(&path).await;
    store
        .mark_upstream(&owner, task.id(), 1, upstream_for(&binding, "handle-1"))
        .await
        .unwrap();
    assert!(store.upstream_of(&owner, task.id()).unwrap().0.is_some());
    store.close().await.unwrap();
}

/// C6 killer (`TASKS_OWNERFILTER`): the descriptor-size probe is owner-scoped,
/// so a foreign owner learns only what an absent task would tell it.
#[tokio::test]
async fn upstream_02_the_descriptor_probe_answers_a_foreign_owner_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let (task, binding) = admitted(&store, &services(), "probe-owner").await;
    let owner = binding.principal_digest().to_owned();
    let args = json!({"sku": "x"});
    assert_eq!(
        store.admits_upstream_descriptor(&owner, task.id(), "orders", "create", &args),
        Ok(true),
        "positive control: the owner is answered"
    );
    assert_eq!(
        store.admits_upstream_descriptor(OTHER, task.id(), "orders", "create", &args),
        Err(StoreError::NotFound)
    );
    store.close().await.unwrap();
}

/// Every read and write entry point refuses a store that is not serving, and
/// writes nothing.
async fn assert_unserved(reader: &TaskStore, owner: &str, id: &str, binding: &TaskBinding) {
    let args = json!({"sku": "x"});
    assert_eq!(reader.get(owner, id).unwrap_err(), StoreError::Unavailable);
    assert_eq!(
        reader.upstream_of(owner, id).unwrap_err(),
        StoreError::Unavailable
    );
    assert_eq!(reader.operation_digest_of(owner, id), None);
    assert_eq!(
        reader.admits_upstream_descriptor(owner, id, "orders", "create", &args),
        Err(StoreError::Unavailable)
    );
    assert_eq!(
        reader.mark_dispatched(owner, id, 1).await.unwrap_err(),
        StoreError::Unavailable
    );
    assert_eq!(
        reader
            .mark_upstream(owner, id, 1, upstream_for(binding, "handle-1"))
            .await
            .unwrap_err(),
        StoreError::Unavailable
    );
}

/// Mutant: the readiness check removed from any store read or marker write.
#[tokio::test]
async fn closed_01_a_closed_store_answers_nothing_about_a_row_it_held() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let (task, binding) = admitted(&store, &services(), "closed").await;
    let owner = binding.principal_digest().to_owned();
    let id = task.id();
    let args = json!({"sku": "x"});
    // Positive control: every call below is answered while the store is open.
    assert!(store.get(&owner, id).is_ok());
    assert!(store.upstream_of(&owner, id).is_ok());
    assert_eq!(
        store.operation_digest_of(&owner, id).as_deref(),
        Some(binding.operation())
    );
    assert_eq!(
        store.admits_upstream_descriptor(&owner, id, "orders", "create", &args),
        Ok(true)
    );

    // Poisoned, with every row still in memory: each guard is exercised on its own.
    let (spare, spare_binding) = admitted(&store, &services(), "poisoner").await;
    poison(&store, spare_binding.principal_digest(), spare.id(), 1).await;
    assert_unserved(&store, &owner, id, &binding).await;

    let reader = store.clone();
    store.close().await.unwrap();
    assert_unserved(&reader, &owner, id, &binding).await;
    // Nothing was written by the refused calls.
    assert_eq!(record_json(&path, id)["dispatched"], json!(false));
    assert!(record_json(&path, id).get("upstream").is_none());
}
