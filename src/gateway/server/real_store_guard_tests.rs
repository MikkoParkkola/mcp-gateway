// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::task_runtime::is_under;

#[cfg(unix)]
#[test]
fn a_store_under_a_symlinked_ancestor_is_refused() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let real = tmp.path().join("real/store");
    std::fs::create_dir_all(&real).expect("real store directory");
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(tmp.path().join("real"), &link).expect("symlink ancestor");
    let dir = link.join("store/x");

    assert!(!dir.starts_with(&real));
    assert!(is_under(&dir, &real));
}

#[test]
fn a_sibling_directory_is_not_under_the_store() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let real = tmp.path().join("real/store");
    std::fs::create_dir_all(&real).expect("real store directory");
    let sibling = tmp.path().join("real/store-sibling");
    std::fs::create_dir_all(&sibling).expect("sibling directory");

    assert!(!is_under(&sibling, &real));
}
