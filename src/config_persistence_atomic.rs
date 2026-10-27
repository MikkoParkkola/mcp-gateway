// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The shared atomic writer.

use std::io::Write;
use std::path::{Path, PathBuf};

/// The mode a replaced file gets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileMode {
    /// Owner-only (0600 / owner-only DACL), whatever the target had.
    Private,
    /// Never wider than the existing target; see `inherit_mode`.
    Inherit,
}

/// What a symlink at `path` means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Symlink {
    /// Write through to the link's target, keeping the link (MIK-8153).
    Follow,
    /// Replace the link itself, as a plain rename over `path` does.
    Replace,
}

/// Replace `path` with `bytes` atomically. A failure before the rename leaves the
/// old file untouched and removes the scratch. NO directory fsync: a failure after
/// the rename would report a committed write as failed (MIK-8664 AC PR7.8).
pub fn write_atomic(
    path: &Path,
    bytes: &[u8],
    mode: FileMode,
    link: Symlink,
) -> std::io::Result<()> {
    write_atomic_observed(path, bytes, mode, link, |_| {})
}

/// [`write_atomic_observed`] for tests outside this module (lead ruling
/// 2026-10-26): the capability writer's tests inject a failure at the rename
/// through it. Test builds with the web UI only (the writer's only
/// build), so production code cannot reach the observed variant.
#[cfg(all(test, feature = "webui"))]
pub(crate) fn write_atomic_observed_for_test(
    path: &Path,
    bytes: &[u8],
    mode: FileMode,
    link: Symlink,
    observe: impl FnOnce(&std::fs::File),
) -> std::io::Result<()> {
    write_atomic_observed(path, bytes, mode, link, observe)
}

/// `write_atomic` with `observe` called on the open scratch after `sync_all` and
/// before the mode step: the test seam that pins "private while the bytes are in it".
fn write_atomic_observed(
    path: &Path,
    bytes: &[u8],
    mode: FileMode,
    link: Symlink,
    observe: impl FnOnce(&std::fs::File),
) -> std::io::Result<()> {
    // The rename destination: through the link (MIK-8153) or onto it.
    let target: PathBuf = match link {
        Symlink::Follow => crate::identity_grants::journal::resolved(path),
        Symlink::Replace => path.to_path_buf(),
    };
    // The target's metadata, when there is a file to inherit from. A symlink
    // at the destination is not one: the rename swaps the link itself away,
    // so there is no mode to keep. Absence reads as absent; any other stat
    // failure under `Inherit` is returned before any scratch is created, so a
    // target we could not stat is never replaced by a wider default-mode file,
    // while a `Private` write never needed the stat.
    let target_meta = match std::fs::symlink_metadata(&target) {
        Ok(meta) if !meta.file_type().is_symlink() => Some(meta),
        Ok(_) => None,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            if matches!(mode, FileMode::Inherit) {
                return Err(e);
            }
            None
        }
    };
    let (mut file, scratch) = create_scratch(
        &target,
        super::next_scratch_seed(),
        scratch_create_for(mode, target_meta.as_ref()),
    )?;
    // Leave no debris behind on any failure before the rename. The scratch
    // name is unique per call, so without cleanup each failure would strand
    // one more file next to the target.
    let cleanup = |leftover: &Path| {
        let _ = std::fs::remove_file(leftover);
    };
    // Write through the handle the exclusive create returned. Reopening by
    // path would reopen the gap the exclusive create just closed.
    if let Err(e) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        // Close before cleanup: Windows cannot delete a file held open
        // without delete sharing.
        drop(file);
        cleanup(&scratch);
        return Err(e);
    }
    observe(&file);
    #[cfg(unix)]
    if matches!(mode, FileMode::Inherit)
        && let Some(meta) = target_meta.as_ref()
        && let Err(e) = apply_inherited_mode(&file, &target, meta)
    {
        drop(file);
        cleanup(&scratch);
        return Err(e);
    }
    // Closed before the rename: Windows renames only a closed file.
    drop(file);
    if let Err(e) = super::rename_with_retry(&scratch, &target) {
        cleanup(&scratch);
        return Err(e);
    }
    Ok(())
}

/// How a scratch file is created.
#[derive(Clone, Copy)]
enum ScratchCreate {
    /// Owner-only from creation, via [`create_new_private`].
    Private,
    /// Default creation: the umask mode on unix, the directory's inherited
    /// ACL on Windows.
    Default,
}

/// How the scratch for a (`mode`, `target`) write is created: private
/// from creation whenever the bytes must never sit in a wider file.
fn scratch_create_for(mode: FileMode, target: Option<&std::fs::Metadata>) -> ScratchCreate {
    match mode {
        FileMode::Private => ScratchCreate::Private,
        // Unix only: the mode step narrows the scratch after the sync, so the
        // bytes sit in a private file until then. A Windows `Inherit` takes
        // the directory's ACL from creation instead, with or without a target.
        FileMode::Inherit if target.is_some() && cfg!(unix) => ScratchCreate::Private,
        FileMode::Inherit => ScratchCreate::Default,
    }
}

/// Claim a scratch file next to `path` that no other writer holds, created
/// per `create`, through the parent's one candidate loop
/// ([`super::claim_scratch`]), with `io::Error`s for the shared atomic writer.
///
/// # Errors
///
/// Returns an error when every candidate name is taken, or on any I/O failure
/// other than a collision.
fn create_scratch(
    path: &Path,
    first: u64,
    create: ScratchCreate,
) -> std::io::Result<(std::fs::File, PathBuf)> {
    super::claim_scratch(path, first, |candidate| match create {
        ScratchCreate::Private => super::create_new_private(candidate),
        ScratchCreate::Default => std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(candidate),
    })
    .map_err(|e| match e {
        super::ScratchClaimError::AllTaken => std::io::Error::other(format!(
            "{} scratch names next to {} were all in use",
            super::SCRATCH_ATTEMPTS,
            path.display()
        )),
        super::ScratchClaimError::Io(e) => e,
    })
}

/// Whether the scratch ended up in the target's group.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GidMatch {
    /// `fchown` to the target's gid succeeded.
    Matched,
    /// `fchown` was refused; the mode keeps the owner bits only.
    Unmatched,
}

/// Whether an ACL can widen the group bits past the mode.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AclPresence {
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
fn inherit_mode(target_mode: u32, gid: GidMatch, acl: AclPresence) -> u32 {
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
fn apply_inherited_mode(
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

#[cfg(all(test, unix))]
#[path = "config_persistence_atomic_tests.rs"]
mod atomic_tests;

// Linux only: writes POSIX ACL xattrs, which only the Linux probe reads.
#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
#[path = "config_persistence_acl_tests.rs"]
mod acl_tests;
