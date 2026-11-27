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
    // The bytes are never in an open file: the scratch is still mode 0000
    // when the observer sees it after `sync_all`, before its access settles.
    let seen = std::cell::Cell::new(0o777);
    write_atomic_observed(
        &path,
        b"new",
        FileMode::Inherit,
        Symlink::Replace,
        |scratch| {
            let mode = scratch.metadata().unwrap().permissions().mode() & 0o777;
            seen.set(mode);
        },
        || Ok(()),
    )
    .unwrap();
    assert_eq!(seen.get(), 0o000);
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

/// Review r1 (gpt): a refused save's scratch that cannot be removed returns
/// the removal error, so the refusal is never read as "nothing left behind".
/// Gone or removed, the refusal itself is returned.
#[test]
fn a_scratch_that_stays_replaces_the_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let refusal = || std::io::Error::other("refused");
    let stays = dir.path().join("stays");
    std::fs::create_dir(&stays).unwrap();
    let kept = super::drop_scratch(&stays, refusal());
    assert_ne!(kept.to_string(), "refused", "{kept}");
    assert!(stays.exists(), "a directory is not removed as a file");
    let removed = dir.path().join("removed");
    std::fs::write(&removed, b"scratch").unwrap();
    assert_eq!(
        super::drop_scratch(&removed, refusal()).to_string(),
        "refused"
    );
    assert!(!removed.exists());
    let gone = dir.path().join("gone");
    assert_eq!(super::drop_scratch(&gone, refusal()).to_string(), "refused");
}

/// Review r2 (gpt): through the writer, a refused save whose scratch cannot
/// be removed (the folder made read-only after the fill) answers the removal
/// error, which is no writer refusal, and the target keeps its bytes.
#[test]
fn a_refusal_that_leaves_its_scratch_is_not_a_writer_refusal() {
    use super::unix::seams::{self, Seams};
    // Root deletes from a read-only folder; the row needs permissions to bind
    // (the repo's pattern, as in serve_session_tests and reader_lock_tests).
    if rustix::process::geteuid().is_root() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    std::fs::write(&path, b"old").unwrap();
    let folder = dir.path().to_path_buf();
    let armed = seams::arm(
        dir.path(),
        Seams {
            refuse: Some("target-changed"),
            before_verify: Some(Box::new(move |_target, _scratch| {
                std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o500))
                    .expect("read-only folder");
            })),
            ..Seams::default()
        },
    );
    let result = write_atomic(&path, b"new", FileMode::Inherit, Symlink::Replace);
    drop(armed);
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let error = result.expect_err("the save refuses");
    assert!(super::writer_refusal(&error).is_none(), "{error}");
    assert_eq!(std::fs::read(&path).unwrap(), b"old");
    // The removal really failed: a scratch stands beside the target.
    let left = std::fs::read_dir(dir.path()).unwrap().count();
    assert!(
        left > 1,
        "the scratch was removed after all ({left} entries)"
    );
}
