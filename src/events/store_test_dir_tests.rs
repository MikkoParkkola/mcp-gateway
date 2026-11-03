// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An events store holding a share of its temporary directory keeps it until
//! its last write: a delivery worker's write landing while a test removed the
//! directory left the store's folders behind in the shared temp directory.

use std::sync::Arc;

use chrono::Utc;

use super::*;

#[test]
fn a_late_write_after_the_test_ends_lands_and_leaves_no_folder() {
    let root = Arc::new(tempfile::tempdir().expect("a store root"));
    let root_path = root.path().to_owned();
    let now = Utc::now();
    let tail = TailPolicy {
        ttl: std::time::Duration::from_secs(3600),
        max: 3,
        max_per_principal: 2,
    };
    let store = Arc::new(Store::open(&root_path, Ok(now), tail).expect("open"));
    store.keep_test_dir(Arc::clone(&root));
    // The test body ends: its own share of the directory goes first.
    drop(root);
    // A worker's handle outlives the test body and writes after it ends.
    let worker = Arc::clone(&store);
    drop(store);
    let sub = tests::sub("p", "https://h/a", now);
    let admitted = worker.admit(
        sub.clone(),
        true,
        tests::CAPS,
        crate::duration_bound::delta!(minutes, 10),
        now,
        tail,
    );
    assert!(
        matches!(admitted, Ok(Ok(_))),
        "the late write lands in the still-owned directory: {admitted:?}"
    );

    drop(worker);

    assert!(
        !root_path.exists(),
        "the store's directory outlived its last handle"
    );
}
