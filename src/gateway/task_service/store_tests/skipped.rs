// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8023: one unreadable record no longer stops the store from opening.
//! A row that cannot be read is skipped in place, never moved or rewritten;
//! the refusals that guard the trust boundary stay fatal.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use super::super::record::PreparedTask;
use super::super::store::{StoreError, StoreLimits, TaskStore};
use super::support::*;
use super::{FOREIGN_NAME, OTHER, OWNER};

/// Two committed tasks; returns the path, the record to damage and the id of
/// the task that stays intact.
async fn two_tasks(root: &Path) -> (PathBuf, PathBuf, String) {
    let path = root.join("tasks");
    let store = open(&path).await;
    let (damaged, kept) = (task(), task());
    for (one, n) in [(&damaged, 1), (&kept, 2)] {
        store
            .create(PreparedTask::for_test(one, OWNER, n))
            .await
            .unwrap();
    }
    store.close().await.unwrap();
    let record = path.join(format!("{}.json", damaged.id()));
    (path, record, kept.id().to_owned())
}

fn rewrite(record: &Path, edit: impl FnOnce(&mut Value)) {
    let mut value: Value = serde_json::from_slice(&fs::read(record).unwrap()).unwrap();
    edit(&mut value);
    fs::write(record, serde_json::to_vec(&value).unwrap()).unwrap();
}

/// Cut the record off `offset` bytes into the member named `member`, as a
/// write that stopped part way would.
fn truncate_inside(record: &Path, member: &str, offset: usize) {
    let bytes = fs::read(record).unwrap();
    let at = String::from_utf8_lossy(&bytes)
        .find(&format!("\"{member}\""))
        .unwrap();
    fs::write(record, &bytes[..at + offset]).unwrap();
}

/// Append a second, later copy of a top-level member, as damage could: the
/// strict parse refuses the duplicate, and the member walk must not lose a
/// value it read earlier to the later copy.
fn append_duplicate(record: &Path, member: &str, value: &str) {
    let mut bytes = fs::read(record).unwrap();
    assert_eq!(bytes.pop(), Some(b'}'), "the record ends with its brace");
    bytes.extend_from_slice(format!(",\"{member}\":{value}}}").as_bytes());
    fs::write(record, bytes).unwrap();
}

/// Opens, keeps the intact task readable and leaves every file as it was.
async fn assert_skipped(path: &Path, kept: &str, case: &str) -> TaskStore {
    let before = files(path);
    let store = match TaskStore::open(path, StoreLimits::default()).await {
        Ok(store) => store,
        Err(error) => panic!("{case}: one unreadable record stopped the store: {error:?}"),
    };
    assert!(store.get(OWNER, kept).is_ok(), "{case}: the intact task");
    assert_eq!(files(path), before, "{case}: the store must move nothing");
    store
}

#[tokio::test]
async fn an_unparseable_record_is_skipped_and_the_rest_load() {
    for case in ["syntax", "no_admission", "cut_in_admission"] {
        let dir = tempfile::tempdir().unwrap();
        let (path, record, kept) = two_tasks(dir.path()).await;
        match case {
            "syntax" => fs::write(&record, b"{broken").unwrap(),
            "cut_in_admission" => truncate_inside(&record, "admission", 20),
            _ => rewrite(&record, |v| {
                v.as_object_mut().unwrap().remove("admission");
            }),
        }
        let store = assert_skipped(&path, &kept, case).await;
        assert_eq!(
            store.restored_bindings().len(),
            1,
            "{case}: no identity to keep"
        );
        store.close().await.unwrap();
    }
}

/// A row whose admission block still reads keeps its binding even when the
/// task inside it does not restore, so its idempotency key stays taken.
#[tokio::test]
async fn an_unrestorable_record_keeps_its_binding() {
    for case in [
        "snapshot",
        "model",
        "version_zero",
        "truncated",
        "trailing",
        "duplicate_model",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let (path, record, kept) = two_tasks(dir.path()).await;
        let identity: String = {
            let value: Value = serde_json::from_slice(&fs::read(&record).unwrap()).unwrap();
            value["admission"]["identityDigest"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        // A duplicated admission block no longer keeps a key: either copy could
        // be the writer's, so it seals (store_tests/admission.rs, MIK-8052).
        if case == "duplicate_model" {
            // A later model naming another task must not rebind the key to it.
            append_duplicate(&record, "model", r#"{"task":{"taskId":"another"}}"#);
        } else if case == "trailing" {
            // Whole and valid, then bytes after its closing brace: the strict
            // parse refuses it, the member walk still reads the key.
            let mut bytes = fs::read(&record).unwrap();
            bytes.extend_from_slice(b" trailing");
            fs::write(&record, bytes).unwrap();
        } else if case == "truncated" {
            // A write cut off inside `model`, which the record serializes
            // after `admission`: the key read before the damage is kept.
            truncate_inside(&record, "model", 12);
        } else {
            rewrite(&record, |v| match case {
                "snapshot" => v["model"]["task"]["lastUpdatedAt"] = json!("2026-09-06T00:00:00Z"),
                "model" => v["model"] = json!("not a task"),
                _ => v["version"] = json!(0),
            });
        }
        let store = assert_skipped(&path, &kept, case).await;
        let bindings = store.restored_bindings();
        assert_eq!(bindings.len(), 2, "{case}: both bindings, one reserved");
        let damaged_id = record.file_stem().unwrap().to_str().unwrap();
        assert!(
            bindings
                .iter()
                .any(|(b, id)| b.identity == identity && id == damaged_id),
            "{case}: the damaged row's key stays taken, bound to its own task id"
        );
        assert!(
            matches!(store.get(OWNER, damaged_id), Err(StoreError::NotFound)),
            "{case}: a reserved key, never a restored task"
        );
        store.close().await.unwrap();
    }
}

/// Still fatal: a newer build's row (a downgrade, not damage), and a damaged
/// row whose name or identity is not its own.
#[tokio::test]
async fn a_newer_or_rebound_record_still_refuses() {
    for case in [
        "newer",
        "newer_broken_model",
        "newer_truncated",
        "newer_then_null_version",
        "current_then_newer_version",
        "rebound_broken",
        "duplicate_broken",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let (path, record, _) = two_tasks(dir.path()).await;
        if case == "newer_truncated" {
            // In the bytes as written (version first, model last), so the cut
            // cannot reorder anything: the version must still be read.
            let text = String::from_utf8(fs::read(&record).unwrap()).unwrap();
            let version: Value = serde_json::from_str::<Value>(&text).unwrap()["version"].clone();
            let newer = text.replacen(&format!("\"version\":{version}"), "\"version\":999", 1);
            assert_ne!(newer, text, "the version was rewritten in place");
            fs::write(&record, newer).unwrap();
            truncate_inside(&record, "model", 12);
        } else if case == "newer_then_null_version" {
            // A later junk copy must not hide the newer version read first.
            rewrite(&record, |v| v["version"] = json!(999));
            append_duplicate(&record, "version", "null");
        } else if case == "current_then_newer_version" {
            // A newer copy after a readable current one is still a newer
            // build's row: the walk keeps the highest version it reads.
            append_duplicate(&record, "version", "999");
        } else if case.starts_with("newer") {
            rewrite(&record, |v| {
                v["version"] = json!(999);
                v["aFieldFromTheFuture"] = json!(true);
                // A malformed sibling must not hide the version (MIK-8023 r2).
                if case == "newer_broken_model" {
                    v["model"] = json!("not a task");
                }
            });
        } else if case == "rebound_broken" {
            unrestorable(&record);
            fs::rename(&record, path.join(format!("{FOREIGN_NAME}.json"))).unwrap();
        } else {
            // A skipped row that claims the intact row's identity.
            let other = fs::read_dir(&path)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|file| *file != record && file.extension().is_some_and(|x| x == "json"))
                .unwrap();
            let theirs: Value = serde_json::from_slice(&fs::read(other).unwrap()).unwrap();
            rewrite(&record, |v| {
                v["admission"]["identityDigest"] = theirs["admission"]["identityDigest"].clone();
                v["model"]["task"]["lastUpdatedAt"] = json!("2026-09-06T00:00:00Z");
            });
        }
        let before = files(&path);
        assert!(
            matches!(
                TaskStore::open(&path, StoreLimits::default()).await,
                Err(StoreError::CorruptRecord)
            ),
            "{case} must refuse readiness"
        );
        assert_eq!(files(&path), before, "{case} must preserve every file");
    }
}

fn unrestorable(record: &Path) {
    rewrite(record, |v| {
        v["model"]["task"]["lastUpdatedAt"] = json!("2026-09-06T00:00:00Z");
    });
}

/// Expiry reads only the loaded tasks: a skipped row is never a candidate,
/// so its file and its kept key outlive every sweep.
#[tokio::test]
async fn expiry_never_reaches_a_skipped_row() {
    let dir = tempfile::tempdir().unwrap();
    let (path, record, kept) = two_tasks(dir.path()).await;
    unrestorable(&record);
    let skipped_id = record.file_stem().unwrap().to_str().unwrap().to_owned();
    let store = assert_skipped(&path, &kept, "expiry").await;
    let later = chrono::Utc::now() + chrono::Duration::days(3650);
    assert!(
        store
            .expired_candidates(later)
            .iter()
            .all(|(id, _)| *id != skipped_id),
        "a skipped row must never be offered to expiry"
    );
    store.close().await.unwrap();
    assert!(record.is_file(), "the skipped row's file stays");
}

/// A skipped row with a kept key still holds its owner's place: with a cap of
/// two, the owner of one loaded and one reserved row cannot add a third.
#[tokio::test]
async fn a_kept_row_still_counts_against_its_owners_cap() {
    let dir = tempfile::tempdir().unwrap();
    let (path, record, _) = two_tasks(dir.path()).await;
    unrestorable(&record);
    let limits = StoreLimits {
        per_principal: 2,
        ..StoreLimits::default()
    };
    let store = TaskStore::open(&path, limits)
        .await
        .expect("one unrestorable row no longer stops the store");
    assert!(matches!(
        store
            .create(PreparedTask::for_test(&task(), OWNER, 3))
            .await,
        Err(StoreError::Capacity)
    ));
    store.close().await.unwrap();
}

/// An unreadable row still takes its place in the record count.
#[tokio::test]
async fn an_unreadable_row_still_counts_against_the_record_cap() {
    let dir = tempfile::tempdir().unwrap();
    let (path, record, _) = two_tasks(dir.path()).await;
    fs::write(&record, b"{broken").unwrap();
    let limits = StoreLimits {
        records: 2,
        ..StoreLimits::default()
    };
    let store = TaskStore::open(&path, limits)
        .await
        .expect("one unreadable row no longer stops the store");
    assert!(matches!(
        store
            .create(PreparedTask::for_test(&task(), OTHER, 3))
            .await,
        Err(StoreError::Capacity)
    ));
    store.close().await.unwrap();
}

/// The open reports what it skipped on the operator's gauge, by class.
#[cfg(feature = "metrics")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn skipped_rows_are_reported_by_class() {
    let dir = tempfile::tempdir().unwrap();
    let (path, record, _) = two_tasks(dir.path()).await;
    unrestorable(&record);
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    telemetry_metrics::with_local_recorder(&recorder, || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let store = TaskStore::open(&path, StoreLimits::default())
                    .await
                    .unwrap();
                store.close().await.unwrap();
            });
        });
    });
    let rendered = handle.render();
    for (class, count) in [("reserved", " 1"), ("sealed", " 0")] {
        assert!(
            rendered.lines().any(|line| line.starts_with(&format!(
                "mcp_task_store_skipped_records{{class=\"{class}\"}}"
            )) && line.ends_with(count)),
            "{class}: {rendered}"
        );
    }
}

/// `MIK-8052.AC4`: a FIFO wearing a record's name is refused as unsafe, and
/// opening it never waits for a writer. The open runs on its own thread so a
/// hang fails the bound instead of the suite; a writer is then attached so the
/// stuck open, if any, returns.
#[cfg(unix)]
#[test]
fn a_fifo_record_is_refused_without_waiting_for_a_writer() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async { open(&path).await.close().await.unwrap() });
    let fifo = path.join("task-00000000-0000-4000-8000-000000000000.json");
    crate::test_fifo::make_fifo(&fifo);

    let (done, opened) = std::sync::mpsc::channel();
    let store_path = path.clone();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let outcome = runtime.block_on(TaskStore::open(&store_path, StoreLimits::default()));
        let _ = done.send(outcome.map(|_| ()).err());
    });
    let outcome = opened.recv_timeout(std::time::Duration::from_secs(5));
    if outcome.is_err() {
        // Release the open blocked on the FIFO before failing.
        let _ = fs::OpenOptions::new().write(true).open(&fifo);
    }
    assert_eq!(
        outcome.ok(),
        Some(Some(StoreError::UnsafeStore)),
        "the open must refuse the FIFO at once"
    );
}
