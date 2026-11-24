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
    write_atomic_observed(path, bytes, mode, link, |_| {}, || Ok(()))
}

/// [`write_atomic`] with `check` run after the scratch is written, synced and
/// closed, and before the rename: an `Err` from it removes the scratch and
/// leaves `path` untouched. Config history's save checks there that its
/// record is still the store's newest (design D-2), so a save past its
/// deadline never renames over newer history.
pub(crate) fn write_atomic_checked(
    path: &Path,
    bytes: &[u8],
    mode: FileMode,
    link: Symlink,
    check: impl FnOnce() -> std::io::Result<()>,
) -> std::io::Result<()> {
    write_atomic_observed(path, bytes, mode, link, |_| {}, check)
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
    write_atomic_observed(path, bytes, mode, link, observe, || Ok(()))
}

/// `write_atomic` with `observe` called on the open scratch after `sync_all` and
/// before the mode step: the test seam that pins "private while the bytes are in it".
/// `check` runs once the scratch is closed, just before the rename.
fn write_atomic_observed(
    path: &Path,
    bytes: &[u8],
    mode: FileMode,
    link: Symlink,
    observe: impl FnOnce(&std::fs::File),
    check: impl FnOnce() -> std::io::Result<()>,
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
    #[cfg(test)]
    let staged = super::crash_fs::stage(&target, &scratch, bytes);
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
    if let Err(e) = check() {
        cleanup(&scratch);
        return Err(e);
    }
    if let Err(e) = super::rename_with_retry(&scratch, &target) {
        cleanup(&scratch);
        return Err(e);
    }
    #[cfg(test)]
    if let Some(staged) = staged {
        super::crash_fs::bind(&target, staged);
    }
    Ok(())
}

// Windows `Inherit` keeps the target's access list.
#[cfg(windows)]
#[path = "config_persistence_atomic_windows.rs"]
mod windows;

// Unix: how a replacement takes the target's group and mode.
#[cfg(unix)]
#[path = "config_persistence_atomic_unix.rs"]
mod unix;
#[cfg(unix)]
use unix::apply_inherited_mode;
#[cfg(all(test, unix))]
use unix::{AclPresence, GidMatch, inherit_mode};

/// How a scratch file is created.
#[derive(Clone, Copy)]
enum ScratchCreate {
    /// Owner-only from creation, via [`create_new_private`].
    Private,
    /// Default creation: the umask mode on unix, the directory's inherited
    /// ACL on Windows.
    Default,
    /// Windows `Inherit` over an existing target: the target's access list,
    /// checked before any byte is written.
    #[cfg(windows)]
    KeepTarget,
}

/// How the scratch for a (`mode`, `target`) write is created: private
/// from creation whenever the bytes must never sit in a wider file.
fn scratch_create_for(mode: FileMode, target: Option<&std::fs::Metadata>) -> ScratchCreate {
    match mode {
        FileMode::Private => ScratchCreate::Private,
        // Unix: the mode step narrows the scratch after the sync, so the bytes
        // sit in a private file until then. Windows: the scratch is created
        // with the target's access list and checked before the write.
        FileMode::Inherit if target.is_some() && cfg!(unix) => ScratchCreate::Private,
        #[cfg(windows)]
        FileMode::Inherit if target.is_some() => ScratchCreate::KeepTarget,
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
        #[cfg(windows)]
        ScratchCreate::KeepTarget => create_kept(path, candidate),
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

/// The Windows `KeepTarget` scratch: the target's list when it is protected,
/// else a default create checked against the target. Refused before any byte
/// is written, with no scratch left.
#[cfg(windows)]
fn create_kept(target: &Path, candidate: &Path) -> std::io::Result<std::fs::File> {
    finish_kept(windows::prepare(target, candidate)?, target, candidate)
}

/// Turn the Windows decision into the scratch file: the kept one, or a
/// default create, checked when the volume keeps lists.
#[cfg(windows)]
fn finish_kept(
    decision: windows::KeptScratch,
    target: &Path,
    candidate: &Path,
) -> std::io::Result<std::fs::File> {
    use windows::KeptScratch;
    match decision {
        KeptScratch::Kept(file) => Ok(file),
        KeptScratch::NoAcls => std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(candidate),
        KeptScratch::Default(source) => {
            // The owner alone: the folder supplies the inherited list, and
            // the target's owner is kept (or the create is refused).
            let file = windows::create_like(
                candidate,
                &source,
                crate::win_acl::CopyWith::OwnerOnly,
                target,
            )?;
            if let Err(e) = windows::verify(&file, &source, target) {
                drop(file);
                let _ = std::fs::remove_file(candidate);
                return Err(e);
            }
            Ok(file)
        }
    }
}

/// Copy `src` to `dst` (a backup), keeping `src`'s access: on unix
/// `std::fs::copy`, which keeps the mode; on Windows, where a copy takes the
/// folder's list instead, the bytes are written to a scratch created with
/// `src`'s list (checked as an `Inherit` save is) and renamed over `dst`.
///
/// # Errors
///
/// Returns the copy's I/O error, or on Windows a refusal when `src`'s list
/// cannot be copied exactly; `dst` is then left as it was.
pub fn copy_keeping_access(src: &Path, dst: &Path) -> std::io::Result<()> {
    #[cfg(not(windows))]
    {
        std::fs::copy(src, dst).map(|_| ())
    }
    #[cfg(windows)]
    {
        use std::io::Read as _;
        // One handle, following links, for both the bytes and the access
        // list: nothing swapped in by name between the two reads can pair
        // these bytes with another file's list. Plain read access carries
        // READ_CONTROL.
        let mut source = std::fs::File::open(src)?;
        let mut bytes = Vec::new();
        source.read_to_end(&mut bytes)?;
        let (mut file, scratch) =
            super::claim_scratch(dst, super::next_scratch_seed(), |candidate| {
                finish_kept(
                    windows::prepare_from(&source, src, candidate)?,
                    src,
                    candidate,
                )
            })
            .map_err(|e| match e {
                super::ScratchClaimError::AllTaken => std::io::Error::other(format!(
                    "{} scratch names next to {} were all in use",
                    super::SCRATCH_ATTEMPTS,
                    dst.display()
                )),
                super::ScratchClaimError::Io(e) => e,
            })?;
        if let Err(e) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
            drop(file);
            let _ = std::fs::remove_file(&scratch);
            return Err(e);
        }
        drop(file);
        super::rename_with_retry(&scratch, dst).inspect_err(|_| {
            let _ = std::fs::remove_file(&scratch);
        })
    }
}

#[cfg(tp3)]
#[cfg(all(test, unix))]
#[path = "config_persistence_atomic_tests.rs"]
mod atomic_tests;

// Linux only: writes POSIX ACL xattrs, which only the Linux probe reads.
#[cfg(tp3)]
#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
#[path = "config_persistence_acl_tests.rs"]
mod acl_tests;

// Windows: an `Inherit` save keeps the target's access list on Windows.
#[cfg(tp3)]
#[cfg(all(test, windows))]
#[path = "config_persistence_winacl_tests.rs"]
mod winacl_tests;

// The same, through each runtime state caller.
#[cfg(tp3)]
#[cfg(all(test, windows))]
#[path = "config_persistence_winacl_callers_tests.rs"]
mod winacl_callers_tests;
