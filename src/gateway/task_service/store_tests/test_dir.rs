// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A store holding a share of its temporary directory keeps it until its last
//! write: a worker's write landing while a test removed the directory left the
//! folder behind in the shared temp directory.

use super::support::*;
use super::*;

#[tokio::test]
async fn a_planted_late_write_after_test_end_leaves_no_folder() {
    let root = Arc::new(tempfile::tempdir().unwrap());
    let root_path = root.path().to_owned();
    let store = open(&root_path.join("tasks")).await;
    store.keep_test_dir(Arc::clone(&root));
    // The test body ends: its own share of the directory goes first.
    drop(root);
    // A worker's handle outlives the test body and writes after it ends.
    let worker = store.clone();
    drop(store);
    let task = task();
    worker
        .create(PreparedTask::for_test(&task, OWNER, 1))
        .await
        .expect("the late write lands in the still-owned directory");
    assert!(
        root_path
            .join("tasks")
            .join(format!("{}.json", task.id()))
            .is_file()
    );

    drop(worker);

    assert!(
        !root_path.exists(),
        "the store's directory outlived its last handle"
    );
}
