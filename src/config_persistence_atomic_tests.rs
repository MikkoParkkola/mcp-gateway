// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `write_atomic` mode and symlink tests (MIK-8664).

use std::os::unix::fs::PermissionsExt as _;

use super::AclPresence::PresentOrUnknown;
use super::GidMatch::{Matched, Unmatched};
use super::{FileMode, Symlink, inherit_mode, write_atomic, write_atomic_observed};

fn mode_of(path: &std::path::Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn private_gives_owner_only() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret");
    write_atomic(&path, b"shh", FileMode::Private, Symlink::Replace).unwrap();
    assert_eq!(mode_of(&path), 0o600);
    // And over an existing wider file: owner-only whatever the target had.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    write_atomic(&path, b"shh", FileMode::Private, Symlink::Replace).unwrap();
    assert_eq!(mode_of(&path), 0o600);
}

#[test]
fn inherit_without_a_target_matches_plain_create() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    write_atomic(&path, b"{}", FileMode::Inherit, Symlink::Replace).unwrap();
    let sibling = dir.path().join("sibling.json");
    std::fs::File::create(&sibling).unwrap();
    assert_eq!(mode_of(&path), mode_of(&sibling));
}

#[test]
fn inherit_mode_never_widens() {
    // The `Absent` rows are Linux-only, in `config_persistence_acl_tests.rs`.
    assert_eq!(inherit_mode(0o644, Matched, PresentOrUnknown), 0o600);
    assert_eq!(inherit_mode(0o640, Unmatched, PresentOrUnknown), 0o600);
}

#[test]
fn inherit_observes_a_private_scratch() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    std::fs::write(&path, b"old").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    // The bytes are never in a wider file: the scratch is still 0600 when
    // the observer sees it after `sync_all`, before the mode step.
    let seen = std::cell::Cell::new(0o777);
    write_atomic_observed(
        &path,
        b"new",
        FileMode::Inherit,
        Symlink::Replace,
        |scratch| {
            let mode = scratch.metadata().unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
            seen.set(mode);
        },
    )
    .unwrap();
    assert_eq!(seen.get(), 0o600);
    assert_eq!(std::fs::read(&path).unwrap(), b"new");
}

#[test]
fn replace_over_a_symlink_replaces_the_link() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    std::fs::write(&target, b"old").unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    write_atomic(&link, b"new", FileMode::Inherit, Symlink::Replace).unwrap();
    assert!(
        !std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(std::fs::read(&link).unwrap(), b"new");
    assert_eq!(std::fs::read(&target).unwrap(), b"old");
}

#[test]
fn follow_writes_through_the_link() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    std::fs::write(&target, b"old").unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    write_atomic(&link, b"new", FileMode::Inherit, Symlink::Follow).unwrap();
    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(std::fs::read(&target).unwrap(), b"new");
}

#[test]
fn inherit_replace_over_a_symlink_takes_sibling_mode() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    std::fs::write(&target, b"old").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    write_atomic(&link, b"new", FileMode::Inherit, Symlink::Replace).unwrap();
    // No target (a link is not one), so the umask mode — never the link's
    // own 0777 placeholder bits.
    let sibling = dir.path().join("sibling");
    std::fs::File::create(&sibling).unwrap();
    assert_eq!(mode_of(&link), mode_of(&sibling));
    assert_ne!(mode_of(&link), 0o777);
}

/// Off Linux there is no ACL probe, so a group-readable target narrows to
/// its owner bits.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
#[test]
fn inherit_without_acl_probe_keeps_owner_bits_only() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    std::fs::write(&path, b"old").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    write_atomic(&path, b"new", FileMode::Inherit, Symlink::Replace).unwrap();
    assert_eq!(mode_of(&path), 0o600);
}
