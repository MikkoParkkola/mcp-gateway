// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2450: the record's `targets` field, its version, and the loader range.
use super::super::record::Target;
use super::*;

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
async fn the_loader_accepts_versions_1_to_5_and_refuses_6() {
    for version in 1..=6_u32 {
        let dir = tempfile::tempdir().unwrap();
        let (path, id) = one_row(dir.path()).await;
        set_version(&path.join(format!("{id}.json")), version);
        let opened = TaskStore::open(&path, StoreLimits::default()).await;
        assert_eq!(opened.is_ok(), version <= 5, "version {version}");
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
