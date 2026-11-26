// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8664 (DUPC-7.PR7.7): an ACL on the target, or one the scratch inherits from
//! its directory, can widen access past the mode bits, so `FileMode::Inherit`
//! keeps the owner bits only. The ACL is written here in the kernel's binary
//! format, so no `setfacl` is needed; a filesystem that refuses ACLs FAILS the
//! test unless `MCP_TEST_NO_ACL_FS=1` names such a host.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use super::{FileMode, Symlink, write_atomic};

/// `user::rw- user:65534:--- group::r-- mask::r-- other::r--`, as the kernel
/// stores it: a version-2 header, then {tag u16, perm u16, id u32} entries.
fn acl_with_a_denied_user() -> Vec<u8> {
    let mut v = 2u32.to_le_bytes().to_vec();
    for (tag, perm, id) in [
        (0x01u16, 6u16, u32::MAX),
        (0x02, 0, 65534),
        (0x04, 4, u32::MAX),
        (0x10, 4, u32::MAX),
        (0x20, 4, u32::MAX),
    ] {
        v.extend(tag.to_le_bytes());
        v.extend(perm.to_le_bytes());
        v.extend(id.to_le_bytes());
    }
    v
}

/// Sets `name` on `path`; returns false only on a host marked as ACL-less.
fn set_acl(path: &Path, name: &str) -> bool {
    let file = std::fs::File::open(path).unwrap();
    match rustix::fs::fsetxattr(
        &file,
        name,
        &acl_with_a_denied_user(),
        rustix::fs::XattrFlags::empty(),
    ) {
        Ok(()) => true,
        Err(e)
            if e == rustix::io::Errno::NOTSUP
                && std::env::var_os("MCP_TEST_NO_ACL_FS").is_some() =>
        {
            println!("ACL test not run: MCP_TEST_NO_ACL_FS set and the filesystem refuses ACLs");
            false
        }
        Err(e) => panic!(
            "the filesystem refused {name} ({e}); set MCP_TEST_NO_ACL_FS=1 only on a host that cannot hold ACLs"
        ),
    }
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn an_acl_on_the_target_keeps_only_the_owner_bits() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    std::fs::write(&path, "{}").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    if !set_acl(&path, "system.posix_acl_access") {
        return;
    }
    write_atomic(&path, b"{}", FileMode::Inherit, Symlink::Replace).unwrap();
    assert_eq!(
        mode(&path),
        0o600,
        "an ACL'd target must not hand its group bits on"
    );
}

/// The target has no ACL; the DIRECTORY's default ACL is inherited by the
/// scratch. WRITER.6: a replacement drops that inherited ACL, so the target's
/// own mode is kept (it was narrowed to 0600 while the ACL stayed on).
#[test]
fn a1_a_replacement_drops_the_acl_its_scratch_inherits() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    std::fs::write(&path, "{}").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    if !set_acl(dir.path(), "system.posix_acl_default") {
        return;
    }
    write_atomic(&path, b"{}", FileMode::Inherit, Symlink::Replace).unwrap();
    assert!(!has_access_acl(&path), "A1: the inherited ACL is gone");
    assert_eq!(mode(&path), 0o640, "A1: the target's own mode is kept");
}

/// Whether `path` carries an access ACL.
fn has_access_acl(path: &Path) -> bool {
    let file = std::fs::File::open(path).unwrap();
    match rustix::fs::fgetxattr(&file, "system.posix_acl_access", &mut [0u8; 0][..]) {
        Err(e) if e == rustix::io::Errno::NODATA => false,
        Ok(_) => true,
        Err(e) => panic!("reading the access ACL of {}: {e}", path.display()),
    }
}

/// A2: a `Private` save of a new file drops the folder's inherited ACL.
#[test]
fn a2_a_private_new_file_drops_the_inherited_acl() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret.json");
    if !set_acl(dir.path(), "system.posix_acl_default") {
        return;
    }
    write_atomic(&path, b"{}", FileMode::Private, Symlink::Replace).unwrap();
    assert!(!has_access_acl(&path), "A2: no inherited ACL");
    assert_eq!(mode(&path), 0o600, "A2: owner-only");
}

/// A3: an `Inherit` save of a NEW file keeps what the folder gives it.
#[test]
fn a3_an_inherit_new_file_keeps_the_folders_acl() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    if !set_acl(dir.path(), "system.posix_acl_default") {
        return;
    }
    write_atomic(&path, b"{}", FileMode::Inherit, Symlink::Replace).unwrap();
    assert!(has_access_acl(&path), "A3: the folder's ACL stays");
}

/// A4: a backup keeps the owner-bits rule when its folder has a default ACL:
/// the ACL is not stripped from a backup.
#[test]
fn a4_a_backup_keeps_the_owner_bits_under_a_folder_acl() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("state.json");
    std::fs::write(&source, "{}").unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o640)).unwrap();
    if !set_acl(dir.path(), "system.posix_acl_default") {
        return;
    }
    let backup = dir.path().join("state.json.bak");
    super::copy_keeping_access(&source, &backup).unwrap();
    assert!(has_access_acl(&backup), "A4: not stripped");
    assert_eq!(mode(&backup), 0o600, "A4: owner bits only");
}

/// Linux only: `Absent` exists only where the probe can prove it.
#[test]
fn inherit_mode_keeps_the_full_mode_only_with_the_group_and_no_acl() {
    use super::AclPresence::Absent;
    use super::GidMatch::{Matched, Unmatched};
    use super::inherit_mode;
    assert_eq!(inherit_mode(0o640, Matched, Absent), 0o640);
    assert_eq!(inherit_mode(0o640, Unmatched, Absent), 0o600);
    assert_eq!(inherit_mode(0o604, Unmatched, Absent), 0o600);
}
