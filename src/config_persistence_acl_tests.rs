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

/// The target has no ACL; the DIRECTORY's default ACL is inherited by the scratch.
#[test]
fn an_acl_the_scratch_inherits_keeps_only_the_owner_bits() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    std::fs::write(&path, "{}").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    if !set_acl(dir.path(), "system.posix_acl_default") {
        return;
    }
    write_atomic(&path, b"{}", FileMode::Inherit, Symlink::Replace).unwrap();
    assert_eq!(
        mode(&path),
        0o600,
        "an inherited ACL must not survive a group-readable chmod"
    );
}
