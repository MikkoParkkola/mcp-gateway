// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The refusal arms of the Windows custody helpers, driven on real
//! directories and files with a planted foreign ACE.

use super::super::StoreError;
use super::{create_private_dir, judge_store_dir, open_new_private, open_record};
use crate::private_fs::test_support::icacls;

#[test]
fn judge_store_dir_refuses_an_absent_path_and_a_shared_directory() {
    let root = tempfile::tempdir().unwrap();
    assert_eq!(
        judge_store_dir(&root.path().join("absent")).err(),
        Some(StoreError::UnsafeStore)
    );

    let store = root.path().join("store");
    create_private_dir(&store).unwrap();
    assert!(judge_store_dir(&store).is_ok(), "a private store passes");

    icacls("T1/shared", &store, &["/grant", "*S-1-1-0:R"]);
    assert_eq!(judge_store_dir(&store).err(), Some(StoreError::UnsafeStore));
}

#[test]
fn open_record_refuses_an_absent_record_and_a_shared_one() {
    let root = tempfile::tempdir().unwrap();
    let record = root.path().join("record.json");
    assert_eq!(
        open_record(&record).err(),
        Some(StoreError::UnsafeStore),
        "absent"
    );

    drop(open_new_private(&record).unwrap());
    assert!(open_record(&record).is_ok(), "a private record opens");

    icacls("T3/shared", &record, &["/grant", "*S-1-1-0:R"]);
    assert_eq!(
        open_record(&record).err(),
        Some(StoreError::UnsafeStore),
        "shared"
    );
}
