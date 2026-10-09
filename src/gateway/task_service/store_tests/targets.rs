// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2450: the record's `targets` field, its version, and the loader range.
use super::super::record::Target;
use super::*;
use chrono::Utc;

fn target() -> Target {
    Target {
        server: "mock".into(),
        tool: "echo".into(),
    }
}

/// A closed store holding one row, and the file that holds it.
async fn one_row(dir: &std::path::Path) -> (std::path::PathBuf, String) {
    let path = dir.join("tasks");
    let store = open(&path).await;
    let task = task();
    store
        .create(PreparedTask::for_test(&task, OWNER, 1))
        .await
        .unwrap();
    let id = task.id().to_owned();
    store.close().await.unwrap();
    (path, id)
}

fn set_version(file: &std::path::Path, version: u32) -> Vec<u8> {
    let mut value: Value = serde_json::from_slice(&fs::read(file).unwrap()).unwrap();
    value["version"] = json!(version);
    let bytes = serde_json::to_vec(&value).unwrap();
    fs::write(file, &bytes).unwrap();
    bytes
}

#[tokio::test]
async fn a_version_5_row_with_targets_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let task = task();
    store
        .create(PreparedTask::for_test(&task, OWNER, 1))
        .await
        .unwrap();
    store
        .add_targets(OWNER, task.id(), 1, vec![target(), target()])
        .await
        .unwrap();
    store.close().await.unwrap();

    let file = path.join(format!("{}.json", task.id()));
    let value: Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    assert_eq!(value["version"], json!(5));
    assert_eq!(
        value["targets"],
        json!([{"server": "mock", "tool": "echo"}])
    );
    let reopened = open(&path).await;
    let read = reopened.get(OWNER, task.id()).unwrap();
    assert_eq!(read.targets, vec![target()]);
    assert!(read.targets_recorded);
    reopened.close().await.unwrap();
}

#[tokio::test]
async fn the_loader_accepts_versions_1_to_7_and_refuses_8() {
    // v7 is the upstream cancel claim (MIK-7642).
    for version in 1..=8_u32 {
        let dir = tempfile::tempdir().unwrap();
        let (path, id) = one_row(dir.path()).await;
        set_version(&path.join(format!("{id}.json")), version);
        let opened = TaskStore::open(&path, StoreLimits::default()).await;
        assert_eq!(opened.is_ok(), version <= 7, "version {version}");
        if let Ok(store) = opened {
            store.close().await.unwrap();
        }
    }
}

#[tokio::test]
async fn a_version_4_row_stays_byte_identical_and_has_no_targets() {
    let dir = tempfile::tempdir().unwrap();
    let (path, id) = one_row(dir.path()).await;
    let file = path.join(format!("{id}.json"));
    let before = set_version(&file, 4);

    let store = open(&path).await;
    let read = store.get(OWNER, &id).unwrap();
    assert!(read.targets.is_empty() && !read.targets_recorded);
    store.close().await.unwrap();

    assert_eq!(fs::read(&file).unwrap(), before, "loading never rewrites");
    assert!(!String::from_utf8(before).unwrap().contains("targets"));
}

#[tokio::test]
async fn targets_that_overflow_the_record_budget_are_refused_not_truncated() {
    let dir = tempfile::tempdir().unwrap();
    let store = TaskStore::open(
        &dir.path().join("tasks"),
        StoreLimits {
            record_bytes: 4 * 1024,
            ..StoreLimits::default()
        },
    )
    .await
    .unwrap();
    let task = task();
    store
        .create(PreparedTask::for_test(&task, OWNER, 1))
        .await
        .unwrap();
    let many = (0..256)
        .map(|n| Target {
            server: format!("server-{n}"),
            tool: "echo".into(),
        })
        .collect();
    let refused = store.add_targets(OWNER, task.id(), 1, many).await;
    assert!(matches!(refused, Err(StoreError::Capacity)), "{refused:?}");
    assert!(store.get(OWNER, task.id()).unwrap().targets.is_empty());
    store.close().await.unwrap();
}

#[tokio::test]
async fn a_settlement_that_overflows_beside_parked_targets_still_ends_failed() {
    let dir = tempfile::tempdir().unwrap();
    let store = TaskStore::open(
        &dir.path().join("tasks"),
        StoreLimits {
            record_bytes: 4 * 1024,
            ..StoreLimits::default()
        },
    )
    .await
    .unwrap();
    let task = task();
    store
        .create(PreparedTask::for_test(&task, OWNER, 1))
        .await
        .unwrap();
    let parked = (0..60)
        .map(|n| Target {
            server: format!("s{n:03}"),
            tool: "echo".into(),
        })
        .collect();
    store
        .add_targets(OWNER, task.id(), 1, parked)
        .await
        .unwrap();
    let big = json!({ "content": [{ "type": "text", "text": "q".repeat(3_000) }] });

    let settled = store
        .settle_bounded(
            OWNER,
            task.id(),
            1,
            (TaskTransition::Complete(big), Some(Vec::new())),
            at(1),
        )
        .await
        .unwrap();

    assert_eq!(settled.task.status(), TaskStatus::Failed);
    assert!(settled.output_free && settled.targets.is_empty());
    assert!(
        !serde_json::to_string(&settled.task.wire())
            .unwrap()
            .contains("qqqq")
    );
    store.close().await.unwrap();
}

/// Mutant: any one of the owner, revision or terminal-status refusals in
/// `add_targets`, or its readiness check, removed.
#[tokio::test]
async fn add_targets_refuses_a_foreign_owner_a_moved_row_a_settled_row_and_a_closed_store() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let (moved, settled, live) = (task(), task(), task());
    for (identity, task) in [(1, &moved), (2, &settled), (3, &live)] {
        store
            .create(PreparedTask::for_test(task, OWNER, identity))
            .await
            .unwrap();
    }
    store
        .transition(
            OWNER,
            moved.id(),
            1,
            TaskTransition::StatusMessage(Some("working".into())),
            at(1),
        )
        .await
        .unwrap();
    store
        .transition(OWNER, settled.id(), 1, TaskTransition::Cancel, at(2))
        .await
        .unwrap();
    let before = files(&path);

    for (why, owner, id, revision, expected) in [
        ("foreign owner", OTHER, live.id(), 1, StoreError::NotFound),
        (
            "moved revision",
            OWNER,
            moved.id(),
            1,
            StoreError::RevisionConflict,
        ),
        (
            "settled row",
            OWNER,
            settled.id(),
            2,
            StoreError::InvalidTransition,
        ),
    ] {
        assert_eq!(
            store
                .add_targets(owner, id, revision, vec![target()])
                .await
                .unwrap_err(),
            expected,
            "{why}"
        );
        assert_eq!(files(&path), before, "{why}: a refusal writes nothing");
    }

    // Positive control: the owner's live row at its revision takes the target.
    store
        .add_targets(OWNER, live.id(), 1, vec![target()])
        .await
        .unwrap();
    let file = path.join(format!("{}.json", live.id()));
    let value: Value = serde_json::from_slice(&fs::read(file).unwrap()).unwrap();
    assert_eq!(
        value["targets"],
        json!([{"server": "mock", "tool": "echo"}])
    );

    let reader = store.clone();
    store.close().await.unwrap();
    assert_eq!(
        reader
            .add_targets(OWNER, live.id(), 1, vec![target()])
            .await
            .unwrap_err(),
        StoreError::Unavailable
    );
}

/// C6 gap table rank 6 (tasks, `Shared::settle_bounded_blocking`): settling
/// another owner's live task is refused as not found and writes nothing. The
/// request path checks ownership first, which would hide this refusal failing
/// open; recovery passes the row's own owner.
#[tokio::test]
async fn settle_bounded_refuses_a_foreign_owner_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let live = task();
    store
        .create(PreparedTask::for_test(&live, OWNER, 1))
        .await
        .unwrap();
    let before = files(&path);

    let refused = store
        .settle_bounded(OTHER, live.id(), 1, (TaskTransition::Cancel, None), at(1))
        .await
        .unwrap_err();

    assert_eq!(refused, StoreError::NotFound);
    assert_eq!(files(&path), before, "a refusal writes nothing");
    // Positive control: the owner settles the same row at the same revision.
    let settled = store
        .settle_bounded(OWNER, live.id(), 1, (TaskTransition::Cancel, None), at(1))
        .await
        .unwrap();
    assert_eq!(settled.task.status(), TaskStatus::Cancelled);
    store.close().await.unwrap();
}

/// A peer-authored failure, settled on a fresh row's revision 1.
fn peer_failure() -> TaskTransition {
    TaskTransition::Fail(crate::protocol::JsonRpcError {
        code: -32042,
        message: "the peer's words".into(),
        data: None,
    })
}

/// MIK-7887.RECEIPT.1: a row that records its calls is raised to version 6 and
/// keeps them when its failure is recorded as the peer's.
#[tokio::test]
async fn a_peer_failure_on_a_row_with_calls_is_version_6() {
    use crate::gateway::task_service::ErrorAuthor;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let task = task();
    store
        .create(PreparedTask::for_test(&task, OWNER, 1))
        .await
        .unwrap();
    store
        .add_targets(OWNER, task.id(), 1, vec![target()])
        .await
        .unwrap();
    let settled = store
        .settle_bounded_by(
            OWNER,
            task.id(),
            1,
            (
                peer_failure(),
                None,
                crate::gateway::gateway_writes::WriteRecord::default(),
            ),
            ErrorAuthor::Peer,
            Utc::now(),
        )
        .await
        .unwrap();
    assert_eq!(settled.error_author, Some(ErrorAuthor::Peer));
    assert_eq!(settled.targets, vec![target()]);
    store.close().await.unwrap();
    let value: Value =
        serde_json::from_slice(&fs::read(path.join(format!("{}.json", task.id()))).unwrap())
            .unwrap();
    assert_eq!(value["version"], json!(6), "{value}");
    assert_eq!(value["errorAuthor"], json!("peer"), "{value}");
}

/// MIK-7887.RECEIPT.1 (fail closed): a legacy row that cannot name its calls
/// is not raised past the version that stores them. Its failure's authorship
/// is not recorded, so a read neither skips the delivery check nor receipts.
#[tokio::test]
async fn a_legacy_row_without_calls_records_no_peer_authorship() {
    use crate::gateway::task_service::ErrorAuthor;
    let dir = tempfile::tempdir().unwrap();
    let (path, id) = one_row(dir.path()).await;
    set_version(&path.join(format!("{id}.json")), 3);
    let store = open(&path).await;
    let settled = store
        .settle_bounded_by(
            OWNER,
            &id,
            1,
            (
                peer_failure(),
                None,
                crate::gateway::gateway_writes::WriteRecord::default(),
            ),
            ErrorAuthor::Peer,
            Utc::now(),
        )
        .await
        .unwrap();
    assert_eq!(settled.error_author, None);
    assert!(!settled.targets_recorded, "the row stays legacy");
    store.close().await.unwrap();
    let value: Value =
        serde_json::from_slice(&fs::read(path.join(format!("{id}.json"))).unwrap()).unwrap();
    assert_eq!(value["version"], json!(3), "{value}");
    assert!(value.get("errorAuthor").is_none(), "{value}");
}
