// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Store-level Windows rows for the task store (test plan §3). Each decisive
//! assertion starts `WT-ASSERT <row>`.

use super::*;
use crate::private_fs::test_support::{assert_owner_only, icacls};
use std::path::Path;

const RECORD: &str = "task-00000000-0000-4000-8000-000000000000.json";

async fn opened_then_closed(dir: &Path) {
    let store = open(dir).await;
    store.close().await.expect("clean close");
}

// W-T1 (task store): the directory and lease it creates are owner-only.
#[tokio::test]
async fn wt1_task_store_objects_are_owner_only() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("tasks");
    opened_then_closed(&dir).await;
    assert_owner_only("W-T1/task-dir", &dir, true);
    assert_owner_only("W-T1/task-lease", &dir.join("store.lease"), false);
}

async fn open_err(dir: &Path) -> Option<StoreError> {
    TaskStore::open(dir, StoreLimits::default()).await.err()
}

// W-T4 (task store): a foreign ACE on the directory, the lease or a record.
#[tokio::test]
async fn wt4_task_dir() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("tasks");
    opened_then_closed(&dir).await;
    icacls("W-T4/task-dir", &dir, &["/grant", "*S-1-1-0:R"]);
    assert_eq!(
        open_err(&dir).await,
        Some(StoreError::UnsafeStore),
        "WT-ASSERT W-T4/task-dir"
    );
}

#[tokio::test]
async fn wt4_task_lease() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("tasks");
    opened_then_closed(&dir).await;
    icacls(
        "W-T4/task-lease",
        &dir.join("store.lease"),
        &["/grant", "*S-1-1-0:R"],
    );
    assert_eq!(
        open_err(&dir).await,
        Some(StoreError::UnsafeStore),
        "WT-ASSERT W-T4/task-lease"
    );
}

// The planted record does not parse, so a store that skips the privacy check
// reports CorruptRecord; only the privacy check answers UnsafeStore first.
#[tokio::test]
async fn wt4_task_record() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("tasks");
    opened_then_closed(&dir).await;
    let record = dir.join(RECORD);
    let mut file =
        crate::private_fs::create_file_private(&record, crate::private_fs::Share::Exclusive)
            .expect("create the planted record");
    std::io::Write::write_all(&mut file, b"not a record").unwrap();
    drop(file);
    icacls("W-T4/task-record", &record, &["/grant", "*S-1-1-0:R"]);
    assert_eq!(
        open_err(&dir).await,
        Some(StoreError::UnsafeStore),
        "WT-ASSERT W-T4/task-record"
    );
}

// W-T9: custody. In-process rather than a child process: the lock lives on
// each handle (probe E4), so a second open in this process meets it exactly as
// another process would; dropping the holder releases it.
#[tokio::test]
async fn wt9_custody_is_exclusive_and_released() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("tasks");
    let holder = open(&dir).await;
    assert_eq!(
        open_err(&dir).await,
        Some(StoreError::AlreadyOwned),
        "WT-ASSERT W-T9"
    );
    holder.close().await.expect("clean close");
    assert_eq!(
        open_err(&dir).await,
        None,
        "WT-ASSERT W-T9: not reacquired after release"
    );
}

// W-T5 (task store): a directory the store creates is judged like an existing
// one, so creating it through a junction refuses.
#[tokio::test]
async fn wt5_task_fresh_dir_under_junction_refuses() {
    let root = tempfile::tempdir().unwrap();
    let real = root.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = root.path().join("j");
    let made = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&link)
        .arg(&real)
        .status();
    if !made.is_ok_and(|s| s.success()) {
        crate::private_fs::test_support::fixture_fail("W-T5/task", "mklink /J failed");
    }
    assert_eq!(
        open_err(&link.join("tasks")).await,
        Some(StoreError::UnsafeStore),
        "WT-ASSERT W-T5/task"
    );
}
