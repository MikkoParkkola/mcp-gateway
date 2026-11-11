// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! ownership acquired before opening a gateway store.

use super::*;

#[test]
fn registered_lookup_holds_every_nested_directory() {
    let outer = kept_tempdir();
    let inner = kept_tempdir_in(outer.path());
    let outer_path = outer.path().to_owned();
    let inner_path = inner.path().to_owned();
    let found = registered_for(&inner_path.join("tasks"));
    assert!(found.holds_anything());
    assert!(found.dirs.iter().any(|dir| Arc::ptr_eq(dir, &outer)));
    assert!(found.dirs.iter().any(|dir| Arc::ptr_eq(dir, &inner)));
    drop(inner);
    drop(outer);
    assert!(inner_path.is_dir());
    drop(found);
    assert!(!inner_path.exists());
    assert!(!outer_path.exists());
}

#[cfg(unix)]
#[test]
fn registered_lookup_matches_a_symlinked_temp_path() {
    let dir = kept_tempdir();
    let root = dir.path().to_owned();
    let aliases = tempfile::tempdir().expect("an unregistered alias directory");
    let alias = aliases.path().join("alias");
    std::os::unix::fs::symlink(&root, &alias).expect("a symlink");
    let found = registered_for(&alias.join("tasks"));
    assert!(found.dirs.iter().any(|kept| Arc::ptr_eq(kept, &dir)));
    drop(dir);
    assert!(alias.is_dir());
    drop(found);
    assert!(!root.exists());
}

#[test]
#[should_panic(expected = "started on a store whose test never kept its directory")]
fn registered_lookup_of_an_unowned_path_does_not_keep_a_store() {
    let dir = tempfile::tempdir().expect("an unregistered directory");
    let found = registered_for_in(&dir.path().join("tasks"), &[]);
    assert!(!found.holds_anything());
    let keep = TestDirKeep::default();
    keep.attach_registered(found);
    keep.assert_kept("an unowned-path worker");
}

#[test]
fn registered_attachment_and_a_later_explicit_keep_coexist() {
    let outer = kept_tempdir();
    // Explicit keep owns a different, unregistered child, so replacing either
    // attachment is observable independently of the other.
    let inner = Arc::new(tempfile::tempdir_in(outer.path()).expect("an explicit directory"));
    let path = inner.path().join("tasks");
    let keep = TestDirKeep::default();
    keep.attach_registered(registered_for(&path));
    keep.assert_kept("an automatically kept worker");
    keep.keep(Arc::clone(&inner), &path);
    keep.assert_kept("an explicitly kept worker");
    assert!(Arc::ptr_eq(keep.dir.get().expect("explicit keep"), &inner));
    let attached = keep.registered.get().expect("registered attachment");
    assert!(attached.dirs.iter().any(|dir| Arc::ptr_eq(dir, &outer)));
    let outer_weak = Arc::downgrade(&outer);
    let inner_weak = Arc::downgrade(&inner);
    drop(outer);
    drop(inner);
    assert!(outer_weak.upgrade().is_some());
    assert!(inner_weak.upgrade().is_some());
    drop(keep);
    assert!(outer_weak.upgrade().is_none());
    assert!(inner_weak.upgrade().is_none());
}

#[test]
fn registered_lookup_honours_only_the_explicit_parent_kept_list() {
    let world = tempfile::tempdir().expect("an unregistered fixture world");
    let root = world.path().join("temp-root");
    let parent = world.path().join("parent-kept");
    let outside = world.path().join("outside").join("tasks");
    std::fs::create_dir(&root).expect("a temp root");
    std::fs::create_dir(&parent).expect("a parent-kept directory");
    let _root = temp_root_for_test(&root);
    // This is MCP_GATEWAY_TEST_KEPT_DIRS's format, parsed at each lookup;
    // neither the process env nor the cached is_external is involved.
    let list = std::env::join_paths([&parent]).expect("a joinable parent list");
    let external = parse_external(&list);
    let path = parent.join("tasks");
    assert!(is_external_in(&external, &path));
    let found = registered_for_in(&path, &external);
    assert!(found.dirs.is_empty());
    assert!(found.parent_kept);
    assert!(found.holds_anything());
    let keep = TestDirKeep::default();
    keep.attach_registered(found);
    keep.assert_kept("a parent-kept worker");
    assert!(!registered_for_in(&path, &[]).holds_anything());
    assert!(!under_temp_root(&outside));
    assert!(!is_external_in(&external, &outside));
    assert!(!registered_for_in(&outside, &external).holds_anything());
}

#[test]
#[should_panic(expected = "started on a store whose test never kept its directory")]
fn registered_empty_attachment_never_satisfies_the_worker_guard() {
    let found = Found {
        dirs: Vec::new(),
        parent_kept: false,
    };
    assert!(!found.holds_anything());
    let keep = TestDirKeep::default();
    keep.attach_registered(found);
    keep.assert_kept("an empty-attachment worker");
}

#[test]
fn registered_lookup_holds_a_weak_across_a_simulated_open() {
    let dir = kept_tempdir();
    let root = dir.path().to_owned();
    let weak = Arc::downgrade(&dir);
    let found = registered_for(&root.join("tasks"));
    // The test's last share goes away between lookup and the store open.
    drop(dir);
    assert!(weak.upgrade().is_some());
    assert!(
        root.is_dir(),
        "the original directory survives the open window"
    );
    drop(found);
    assert!(weak.upgrade().is_none());
    assert!(!root.exists(), "the registry itself owns no directory");
}

/// A registered directory that merely holds a symlink to an unregistered one owns the link, not the
/// store behind it: the store's own directory could be deleted while the store is alive.
#[cfg(unix)]
#[test]
fn registered_lookup_through_a_symlink_into_an_unregistered_directory_keeps_nothing() {
    let registered = kept_tempdir();
    let outside = tempfile::tempdir().expect("an unregistered directory");
    std::os::unix::fs::symlink(outside.path(), registered.path().join("link")).expect("a symlink");
    let found = registered_for(&registered.path().join("link").join("store"));
    assert!(
        found.dirs.iter().any(|kept| Arc::ptr_eq(kept, &registered)),
        "the directory holding the link is still held"
    );
    assert!(
        !found.holds_anything(),
        "but it does not stand in for the store's own directory"
    );
}
