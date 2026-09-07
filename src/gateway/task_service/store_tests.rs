// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! STORE-01/03/04/06 and CANCEL-01 component prerequisites, not transport UAT.

use std::{
    fs,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use serde_json::{Value, json};

use super::{model::*, record::PreparedTask, store::*};
use crate::protocol::{JsonRpcError, mrtr::InputRequired};

const OWNER: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const OTHER: &str = "2222222222222222222222222222222222222222222222222222222222222222";
/// A well-formed task name that belongs to no fixture task.
const FOREIGN_NAME: &str = "task-00000000-0000-4000-8000-000000000000";

mod admission;
mod durability;
mod qualification;
mod support;
use support::*;

#[tokio::test]
async fn store_01_acknowledges_only_an_immediately_readable_durable_record() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let task = task();
    let expected = serde_json::to_value(task.wire()).unwrap();
    let created = store
        .create(PreparedTask::for_test(&task, OWNER, 1))
        .await
        .unwrap();
    assert_eq!(created.revision, 1);
    assert_eq!(
        serde_json::to_value(store.get(OWNER, task.id()).unwrap().task.wire()).unwrap(),
        expected
    );
    assert!(path.join(format!("{}.json", task.id())).is_file());
    assert!(store.ready());
    store.close().await.unwrap();
    let reopened = open(&path).await;
    assert_eq!(
        serde_json::to_value(reopened.get(OWNER, task.id()).unwrap().task.wire()).unwrap(),
        expected
    );
    reopened.close().await.unwrap();
}

#[tokio::test]
async fn store_03_each_terminal_and_consumed_input_history_survive_reopen() {
    for event in [
        TaskTransition::Complete(json!({"content":[],"isError":true})),
        TaskTransition::Fail(JsonRpcError {
            code: -32042,
            message: "failed".into(),
            data: Some(Value::Null),
        }),
        TaskTransition::Cancel,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tasks");
        let store = open(&path).await;
        let mut task = task();
        task.transition(
            TaskTransition::RequireInput(InputRequired {
                requests: vec![("consumed-key".into(), json!({"method":"roots/list"}))],
                request_state: None,
            }),
            at(1),
        )
        .unwrap();
        task.transition(
            TaskTransition::ProvideInput(json!({"consumed-key":{"roots":[]}})),
            at(2),
        )
        .unwrap();
        store
            .create(PreparedTask::for_test(&task, OWNER, 1))
            .await
            .unwrap();
        let terminal = store
            .transition(OWNER, task.id(), 1, event, at(3))
            .await
            .unwrap();
        let snapshot = serde_json::to_value(terminal.task.snapshot()).unwrap();
        store.close().await.unwrap();
        let reopened = open(&path).await;
        let restored = reopened.get(OWNER, task.id()).unwrap();
        assert_eq!(restored.revision, 2);
        assert_eq!(
            serde_json::to_value(restored.task.snapshot()).unwrap(),
            snapshot
        );
        assert_eq!(snapshot["issuedInputKeys"], json!(["consumed-key"]));
        reopened.close().await.unwrap();
    }
}

#[tokio::test]
async fn store_04_owner_and_revision_refusals_preserve_every_file_and_view() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let task = task();
    store
        .create(PreparedTask::for_test(&task, OWNER, 1))
        .await
        .unwrap();
    let before = files(&path);
    assert_eq!(
        store.get(OTHER, task.id()).unwrap_err(),
        StoreError::NotFound
    );
    assert_eq!(
        store
            .get(OWNER, "task-00000000-0000-4000-8000-000000000000")
            .unwrap_err(),
        StoreError::NotFound
    );
    assert_eq!(
        store
            .transition(OTHER, task.id(), 1, TaskTransition::Cancel, at(1))
            .await
            .unwrap_err(),
        StoreError::NotFound
    );
    assert_eq!(
        store
            .transition(OWNER, task.id(), 0, TaskTransition::Cancel, at(1))
            .await
            .unwrap_err(),
        StoreError::RevisionConflict
    );
    assert_eq!(files(&path), before);
    assert_eq!(
        store.get(OWNER, task.id()).unwrap().task.status(),
        TaskStatus::Working
    );
    store.close().await.unwrap();
}

#[tokio::test]
async fn cancel_01_first_terminal_commit_wins_in_both_orders_and_after_reopen() {
    for first in [
        TaskTransition::Cancel,
        TaskTransition::Complete(json!({"content":[]})),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tasks");
        let store = open(&path).await;
        let task = task();
        store
            .create(PreparedTask::for_test(&task, OWNER, 1))
            .await
            .unwrap();
        let initial = store
            .transition(OWNER, task.id(), 1, first, at(1))
            .await
            .unwrap();
        let before = files(&path);
        let expected = serde_json::to_value(initial.task.snapshot()).unwrap();
        for event in [
            TaskTransition::Cancel,
            TaskTransition::Complete(json!({"content":[{"type":"text","text":"late"}]})),
        ] {
            let late = store
                .transition(OWNER, task.id(), initial.revision, event, at(2))
                .await
                .unwrap();
            assert_eq!(late.revision, initial.revision);
            assert_eq!(
                serde_json::to_value(late.task.snapshot()).unwrap(),
                expected
            );
            assert_eq!(files(&path), before);
        }
        store.close().await.unwrap();
        let reopened = open(&path).await;
        assert_eq!(
            serde_json::to_value(reopened.get(OWNER, task.id()).unwrap().task.snapshot()).unwrap(),
            expected
        );
        reopened.close().await.unwrap();
    }
}

#[tokio::test]
async fn store_04_corrupt_rebound_or_unrestorable_records_refuse_without_reset() {
    for corruption in ["syntax", "version", "duplicate", "rebound", "snapshot"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tasks");
        let store = open(&path).await;
        let task = task();
        store
            .create(PreparedTask::for_test(&task, OWNER, 1))
            .await
            .unwrap();
        if corruption == "duplicate" {
            store
                .create(PreparedTask::for_test(&self::task(), OWNER, 2))
                .await
                .unwrap();
        }
        store.close().await.unwrap();
        let record = path.join(format!("{}.json", task.id()));
        if corruption == "syntax" {
            fs::write(&record, b"{broken").unwrap();
        } else if corruption == "rebound" {
            // Moving an intact record under another legal task name must not
            // rebind it to that name: the record carries its own identity.
            fs::rename(&record, path.join(format!("{FOREIGN_NAME}.json"))).unwrap();
        } else {
            let mut value: Value = serde_json::from_slice(&fs::read(&record).unwrap()).unwrap();
            if corruption == "version" {
                value["version"] = json!(999);
            } else if corruption == "snapshot" {
                // Settled before it was created: legal JSON the model refuses to
                // restore. The store must propagate that refusal, not accept it.
                value["model"]["task"]["lastUpdatedAt"] = json!("2026-09-06T00:00:00Z");
            } else {
                value["admission"]["identityDigest"] = json!(format!("{:064x}", 2));
            }
            fs::write(&record, serde_json::to_vec(&value).unwrap()).unwrap();
        }
        let before = files(&path);
        assert!(
            matches!(
                TaskStore::open(&path, StoreLimits::default()).await,
                Err(StoreError::CorruptRecord)
            ),
            "{corruption} must refuse readiness"
        );
        assert_eq!(
            files(&path),
            before,
            "{corruption} must preserve every file"
        );
    }
}

#[tokio::test]
async fn store_03_refused_events_never_reach_the_writer_or_change_the_committed_view() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let mut task = task();
    task.transition(
        TaskTransition::RequireInput(InputRequired {
            requests: vec![("live-key".into(), json!({"method":"roots/list"}))],
            request_state: None,
        }),
        at(1),
    )
    .unwrap();
    store
        .create(PreparedTask::for_test(&task, OWNER, 1))
        .await
        .unwrap();
    let before = files(&path);
    // Entering the writer at all breaks the contract, so the hook both counts and
    // refuses: a store that serialized before validating would answer Storage.
    let entered = Arc::new(AtomicUsize::new(0));
    let tripwire = entered.clone();
    store
        .set_hook(Some(Arc::new(move |_| {
            tripwire.fetch_add(1, Ordering::SeqCst);
            Err(std::io::Error::other("writer must not be entered"))
        })))
        .await;
    for refused in [
        TaskTransition::Complete(json!("not-an-object")),
        TaskTransition::RequireInput(InputRequired {
            requests: vec![("second-round".into(), json!({"method":"roots/list"}))],
            request_state: None,
        }),
        TaskTransition::ProvideInput(json!([])),
    ] {
        assert_eq!(
            store
                .transition(OWNER, task.id(), 1, refused, at(2))
                .await
                .unwrap_err(),
            StoreError::InvalidTransition,
            "a model refusal is reported as a refusal, never as a storage failure"
        );
    }
    // The contrast that makes the variant worth having: an answer to a key that is
    // not outstanding is a no-op, not a refusal, and it must not write either.
    let quiet = store
        .transition(
            OWNER,
            task.id(),
            1,
            TaskTransition::ProvideInput(json!({"absent-key":{}})),
            at(2),
        )
        .await
        .unwrap();
    assert_eq!(quiet.revision, 1);
    assert_eq!(quiet.task.status(), TaskStatus::InputRequired);
    assert_eq!(
        entered.load(Ordering::SeqCst),
        0,
        "no refused or ignored event reached the writer"
    );
    assert_eq!(files(&path), before);
    assert_eq!(store.get(OWNER, task.id()).unwrap().revision, 1);
    store.close().await.unwrap();
}

#[tokio::test]
async fn store_04_live_owner_excludes_second_open_and_close_releases_lease() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let second = tokio::time::timeout(
        Duration::from_secs(2),
        TaskStore::open(&path, StoreLimits::default()),
    )
    .await
    .expect("custody must refuse promptly");
    assert!(matches!(second, Err(StoreError::AlreadyOwned)));
    store.close().await.unwrap();
    open(&path).await.close().await.unwrap();
}

#[tokio::test]

async fn store_06_malformed_ids_never_derive_paths_or_change_storage() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let task = task();
    store
        .create(PreparedTask::for_test(&task, OWNER, 1))
        .await
        .unwrap();
    fs::create_dir(path.join("task-..")).unwrap();
    let absolute = dir.path().join("outside-absolute");
    let cases = [
        (
            "../outside-traversal".to_owned(),
            vec![dir.path().join("outside-traversal")],
        ),
        (absolute.to_str().unwrap().to_owned(), vec![absolute]),
        (
            "task-../outside-prefixed".to_owned(),
            vec![
                path.join("task-..").join("outside-prefixed"),
                dir.path().join("outside-prefixed"),
            ],
        ),
        (
            "%2e%2e%2foutside-encoded".to_owned(),
            vec![
                dir.path().join("outside-encoded"),
                path.join("%2e%2e%2foutside-encoded"),
            ],
        ),
        ("task-no-uuid".to_owned(), vec![path.join("task-no-uuid")]),
        (
            "task-00000000-0000-3000-8000-000000000000".to_owned(),
            vec![path.join("task-00000000-0000-3000-8000-000000000000")],
        ),
    ];
    for (index, (id, targets)) in cases.into_iter().enumerate() {
        let mut planted = self::task();
        planted.complete(
            json!({"content":[{"type":"text","text":format!("distinct outside payload {index}")}]}),
        );
        let bytes =
            serde_json::to_vec(&PreparedTask::for_test(&planted, OWNER, 42).record).unwrap();
        for target in targets {
            assert!(
                target.starts_with(dir.path()),
                "every adversarial target is fixture-owned"
            );
            seed_private(&target, &bytes);
            seed_private(
                &std::path::PathBuf::from(format!("{}.json", target.display())),
                &bytes,
            );
        }
        let before = manifest(dir.path());
        assert_eq!(
            store.get(OWNER, &id).unwrap_err(),
            StoreError::NotFound,
            "must not return planted valid Task payload"
        );
        assert_eq!(
            store
                .transition(OWNER, &id, 1, TaskTransition::Cancel, at(1))
                .await
                .unwrap_err(),
            StoreError::NotFound
        );
        assert_eq!(
            manifest(dir.path()),
            before,
            "no planted payload or store artifact changes"
        );
    }
    store.close().await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn store_06_private_modes_and_unsafe_sources_are_enforced() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    for unsafe_kind in [
        "directory-mode",
        "record-mode",
        "record-link",
        "lease-link",
        // A lease that IS a regular file and is NOT private. The link case
        // above cannot reach this: a symlink fails BOTH halves of the guard, so
        // it never proves the guard is a disjunction. Custody of a lease other
        // users can write is not custody.
        "lease-mode",
        "record-directory",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tasks");
        let store = open(&path).await;
        let lease = created_sidecar(&path);
        let task = task();
        store
            .create(PreparedTask::for_test(&task, OWNER, 1))
            .await
            .unwrap();
        store.close().await.unwrap();
        let record = path.join(format!("{}.json", task.id()));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&record).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let outside = dir.path().join("outside");
        fs::write(&outside, b"untouched").unwrap();
        match unsafe_kind {
            "directory-mode" => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            }
            "record-mode" => {
                fs::set_permissions(&record, fs::Permissions::from_mode(0o644)).unwrap();
            }
            "record-link" => {
                fs::remove_file(&record).unwrap();
                symlink(&outside, &record).unwrap();
            }
            "lease-link" => {
                fs::remove_file(&lease).unwrap();
                symlink(&outside, &lease).unwrap();
            }
            "lease-mode" => {
                fs::set_permissions(&lease, fs::Permissions::from_mode(0o644)).unwrap();
            }
            _ => {
                fs::remove_file(&record).unwrap();
                fs::create_dir(&record).unwrap();
            }
        }
        let before = manifest(dir.path());
        assert!(matches!(
            TaskStore::open(&path, StoreLimits::default()).await,
            Err(StoreError::UnsafeStore)
        ));
        assert_eq!(
            manifest(dir.path()),
            before,
            "failed readiness preserves types, inode, modes, links and bytes"
        );
        assert_eq!(fs::read(&outside).unwrap(), b"untouched");
    }
}

#[tokio::test]
async fn store_01_io_faults_never_publish_uncommitted_acceptance() {
    for stage in [
        CommitStage::Write,
        CommitStage::Flush,
        CommitStage::FileSync,
        CommitStage::Rename,
        CommitStage::DirectorySync,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tasks");
        let store = open(&path).await;
        let lease = created_sidecar(&path);
        let task = task();
        let prepared = PreparedTask::for_test(&task, OWNER, 1);
        let expected = serde_json::to_value(&prepared.record).unwrap();
        let captured = Arc::new(std::sync::Mutex::new(None));
        let image = captured.clone();
        let hook_path = path.clone();
        store
            .set_hook(Some(Arc::new(move |point| {
                if point == stage {
                    *image.lock().unwrap() = Some(manifest(&hook_path));
                    Err(std::io::Error::other("injected store failure"))
                } else {
                    Ok(())
                }
            })))
            .await;
        assert_eq!(
            store.create(prepared).await.unwrap_err(),
            StoreError::Storage
        );
        assert_stage_layout(
            captured
                .lock()
                .unwrap()
                .as_ref()
                .expect("real requested stage reached"),
            &lease,
            task.id(),
            stage,
            &expected,
        );
        if stage == CommitStage::DirectorySync {
            assert!(!store.ready());
            assert_eq!(
                store.get(OWNER, task.id()).unwrap_err(),
                StoreError::Unavailable
            );
            store.close().await.unwrap();
        } else {
            assert!(store.ready());
            assert_eq!(
                store.get(OWNER, task.id()).unwrap_err(),
                StoreError::NotFound
            );
            assert!(
                !path.join(format!("{}.json", task.id())).exists(),
                "pre-rename failure has no final task record"
            );
            store.close().await.unwrap();
            let reopened = open(&path).await;
            assert_eq!(
                reopened.get(OWNER, task.id()).unwrap_err(),
                StoreError::NotFound,
                "failed creation must not reappear on reopen"
            );
            reopened
                .create(PreparedTask::for_test(&task, OWNER, 1))
                .await
                .unwrap();
            reopened.close().await.unwrap();
        }
    }
}

#[tokio::test]
async fn store_03_failed_settlement_preserves_committed_view_or_poisons_readiness() {
    for stage in [
        CommitStage::Write,
        CommitStage::Flush,
        CommitStage::FileSync,
        CommitStage::Rename,
        CommitStage::DirectorySync,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tasks");
        let store = open(&path).await;
        let task = task();
        store
            .create(PreparedTask::for_test(&task, OWNER, 1))
            .await
            .unwrap();
        let record = path.join(format!("{}.json", task.id()));
        let before = fs::read(&record).unwrap();
        store
            .set_hook(Some(Arc::new(move |point| {
                if point == stage {
                    Err(std::io::Error::other("injected settlement failure"))
                } else {
                    Ok(())
                }
            })))
            .await;
        assert_eq!(
            store
                .transition(OWNER, task.id(), 1, TaskTransition::Cancel, at(1))
                .await
                .unwrap_err(),
            StoreError::Storage
        );
        if stage == CommitStage::DirectorySync {
            assert!(!store.ready());
            assert_eq!(
                store.get(OWNER, task.id()).unwrap_err(),
                StoreError::Unavailable
            );
        } else {
            assert_eq!(fs::read(&record).unwrap(), before);
            let retained = store.get(OWNER, task.id()).unwrap();
            assert_eq!(retained.revision, 1);
            assert_eq!(retained.task.status(), TaskStatus::Working);
            assert_eq!(
                serde_json::to_value(retained.task.snapshot()).unwrap(),
                serde_json::to_value(task.snapshot()).unwrap()
            );
        }
        store.close().await.unwrap();
    }
}

#[tokio::test]
async fn store_01_paused_directory_sync_keeps_handle_and_view_unpublished() {
    for paused in [CommitStage::Write, CommitStage::DirectorySync] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tasks");
        let store = open(&path).await;
        let task = task();
        let lease = created_sidecar(&path);
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let receiver = std::sync::Mutex::new(release_rx);
        store
            .set_hook(Some(Arc::new(move |stage| {
                if stage == paused {
                    entered_tx.send(()).unwrap();
                    receiver
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(3))
                        .map_err(std::io::Error::other)?;
                }
                Ok(())
            })))
            .await;
        let owned = store.clone();
        let prepared = PreparedTask::for_test(&task, OWNER, 1);
        let expected = serde_json::to_value(&prepared.record).unwrap();
        let pending = tokio::spawn(async move { owned.create(prepared).await });
        tokio::task::spawn_blocking(move || entered_rx.recv_timeout(Duration::from_secs(3)))
            .await
            .unwrap()
            .expect("reach actual temp-create/final-sync boundary");
        let published = pending.is_finished();
        let observed = store.get(OWNER, task.id());
        let image = manifest(&path);
        release_tx.send(()).unwrap();
        let committed = pending.await.unwrap().unwrap();
        assert!(!published, "acknowledgement preceded final durability");
        assert_eq!(observed.unwrap_err(), StoreError::NotFound);
        assert_stage_layout(&image, &lease, task.id(), paused, &expected);
        assert_eq!(committed.task.id(), task.id());
        assert_eq!(store.get(OWNER, task.id()).unwrap().revision, 1);
        store.close().await.unwrap();
    }
}

#[tokio::test]
async fn store_04_count_and_byte_reservations_reject_before_write() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = TaskStore::open(
        &path,
        StoreLimits {
            records: 2,
            per_principal: 1,
            record_bytes: 4096,
            logical_bytes: 16384,
        },
    )
    .await
    .unwrap();
    let first = task();
    store
        .create(PreparedTask::for_test(&first, OWNER, 1))
        .await
        .unwrap();
    let before = files(&path);
    assert_eq!(
        store
            .create(PreparedTask::for_test(&task(), OWNER, 2))
            .await
            .unwrap_err(),
        StoreError::Capacity
    );
    assert_eq!(files(&path), before);
    let mut large = task();
    large.complete(json!({"content":[{"text":"x".repeat(8192)}]}));
    assert_eq!(
        store
            .create(PreparedTask::for_test(&large, OTHER, 3))
            .await
            .unwrap_err(),
        StoreError::Capacity
    );
    assert_eq!(files(&path), before);
    store
        .create(PreparedTask::for_test(&task(), OTHER, 4))
        .await
        .unwrap();
    let full = files(&path);
    assert_eq!(
        store
            .create(PreparedTask::for_test(&task(), &"3".repeat(64), 5))
            .await
            .unwrap_err(),
        StoreError::Capacity
    );
    assert_eq!(files(&path), full);
    store.close().await.unwrap();

    let logical_path = dir.path().join("logical-budget");
    let logical = TaskStore::open(
        &logical_path,
        StoreLimits {
            records: 4,
            per_principal: 4,
            record_bytes: 4096,
            logical_bytes: 4096,
        },
    )
    .await
    .unwrap();
    logical
        .create(PreparedTask::for_test(&task(), OWNER, 1))
        .await
        .unwrap();
    let one_record = files(&logical_path);
    assert_eq!(
        logical
            .create(PreparedTask::for_test(&task(), OTHER, 2))
            .await
            .unwrap_err(),
        StoreError::Capacity
    );
    assert_eq!(
        files(&logical_path),
        one_record,
        "logical capacity must refuse while count/principal limits still have room"
    );
    logical.close().await.unwrap();
}
