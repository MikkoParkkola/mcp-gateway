// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The shared atomic writer on unix: how a replacement takes the target's
//! group and mode.

use std::path::Path;

/// Whether the scratch ended up in the target's group.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum GidMatch {
    /// `fchown` to the target's gid succeeded.
    Matched,
    /// `fchown` was refused; the mode keeps the owner bits only.
    Unmatched,
}

/// Whether an ACL can widen the group bits past the mode.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AclPresence {
    /// Neither file carries an access ACL. Only the Linux probe can prove it.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    Absent,
    /// An ACL is present, or the probe could not tell.
    PresentOrUnknown,
}

#[cfg(unix)]
impl AclPresence {
    /// Only a proven-absent ACL lets the full mode through; off Linux nothing
    /// can be proven, so the answer is always no.
    fn allows_full_mode(self) -> bool {
        match self {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::Absent => true,
            Self::PresentOrUnknown => false,
        }
    }
}

/// Never wider than the target: the full mode only when the group is the
/// target's and no ACL can widen it; otherwise the owner bits only.
#[cfg(unix)]
pub(super) fn inherit_mode(target_mode: u32, gid: GidMatch, acl: AclPresence) -> u32 {
    if gid == GidMatch::Matched && acl.allows_full_mode() {
        target_mode
    } else {
        target_mode & 0o700
    }
}

/// Narrow the open scratch to the target's mode, never wider (unix,
/// `Inherit` over an existing target only). Runs after the bytes are written
/// and synced: the scratch was created private, so the bytes are never in a
/// wider file. Order is fixed: `fchown` first, then `chmod`, never the other
/// way round — the mode is only meaningful once the group is settled.
#[cfg(unix)]
pub(super) fn apply_inherited_mode(
    scratch: &std::fs::File,
    target: &Path,
    target_meta: &std::fs::Metadata,
) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::PermissionsExt as _;
    // Take the target's group when the process may; a refusal only narrows
    // what the chmod below keeps, and is never an error of the write.
    let gid = match std::os::unix::fs::fchown(scratch, None, Some(target_meta.gid())) {
        Ok(()) => GidMatch::Matched,
        Err(_) => GidMatch::Unmatched,
    };
    // An ACL on either file can widen the group bits past the mode; a target
    // that cannot be opened for the probe counts as widened.
    // Only a regular file is opened for the probe, and without waiting: a path
    // swapped for a FIFO after the stat must not block the save.
    let acl = if target_meta.is_file() {
        match crate::open_nonblocking::open_nonblocking(target) {
            Ok(target) => acl_presence(&target, scratch),
            Err(_) => AclPresence::PresentOrUnknown,
        }
    } else {
        AclPresence::PresentOrUnknown
    };
    scratch.set_permissions(std::fs::Permissions::from_mode(inherit_mode(
        target_meta.mode() & 0o7777,
        gid,
        acl,
    )))
}

/// Whether either file carries an access ACL that can widen the group bits
/// past the mode. Both fds are probed: the target's ACL widens what the mode
/// means, and the scratch's own (inherited from the directory) survives the
/// chmod below.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn acl_presence(target: &std::fs::File, scratch: &std::fs::File) -> AclPresence {
    // An empty read asks only whether the attribute exists: `NODATA` means no
    // ACL, anything else (present, or an error that hides the answer) counts
    // as one.
    fn absent(file: &std::fs::File) -> bool {
        matches!(
            rustix::fs::fgetxattr(file, "system.posix_acl_access", &mut [0u8; 0][..]),
            Err(e) if e == rustix::io::Errno::NODATA
        )
    }
    if absent(target) && absent(scratch) {
        AclPresence::Absent
    } else {
        AclPresence::PresentOrUnknown
    }
}

/// Without the Linux probe there is no way to tell, so every target counts
/// as widened and keeps the owner bits only.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
fn acl_presence(_target: &std::fs::File, _scratch: &std::fs::File) -> AclPresence {
    AclPresence::PresentOrUnknown
}
