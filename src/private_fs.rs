// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Owner-only file custody for the task store and the personal-account store
//! on Windows (design `docs/design/2026-09-26-windows-owner-only-stores.md`).
//!
//! The unix stores keep their mode-based bodies where they are; this module is
//! the Windows side of the same rules. Safe code only: every Win32 call goes
//! through `crate::win_acl` (ADR-016).

use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt as _;
use std::path::{Component, Path};

use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY,
    FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL,
};

pub(crate) use crate::win_acl::Share;

/// Why an object is not private (design §2.2). Tests assert the reason, so one
/// check cannot mask another.
#[derive(Clone, Debug, Eq, PartialEq)]
#[expect(dead_code, reason = "red stage: the stub judges construct no refusal")]
pub(crate) enum PrivacyRefusal {
    /// P1: a NULL DACL grants everyone.
    NullDacl,
    /// P2: an allow ACE for someone other than the current user.
    ForeignSid(String),
    /// P2: an ACE type other than plain allow/deny.
    OtherAceType(u8),
    /// P3: no ACE grants the user read and write.
    NoReadWrite,
    /// P4: owned by someone else.
    ForeignOwner(String),
    /// P5: the DACL inherits.
    NotProtected,
    /// Symlink, junction or other reparse point.
    ReparsePoint,
    /// Network drive, or a volume that keeps no ACLs.
    NotLocal,
    /// The opened directory is not the configured path.
    PathMismatch,
    /// Not a regular file (or not a directory, where one is required).
    NotRegular,
    /// The security information could not be read.
    Unreadable,
}

/// Lexical acceptance of a leading path component on Windows (design §2.3 R3).
pub(crate) fn prefix_allowed(component: &Component<'_>) -> bool {
    matches!(component, Component::Prefix(_))
}

/// Open a directory for judging and pinning: no reparse following, data access
/// so the missing delete-share binds (design R3-1), no delete sharing.
pub(crate) fn open_dir(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

/// Open a record or manifest for reading: no reparse following; directories
/// open too, so they can be refused as `NotRegular` rather than as a raw error.
pub(crate) fn open_file_read(path: &Path) -> io::Result<File> {
    hook(Hook::BeforeRecordOpen, path);
    OpenOptions::new()
        .access_mode(GENERIC_READ | READ_CONTROL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

/// Judge an open directory handle against P1-P5, reparse, locality and the
/// configured path.
pub(crate) fn judge_dir(_dir: &File, _configured: &Path) -> Result<(), PrivacyRefusal> {
    Ok(())
}

/// Judge an open file handle against P1-P5, reparse and regular-file.
pub(crate) fn judge_file(_file: &File) -> Result<(), PrivacyRefusal> {
    Ok(())
}

/// Create a store directory that is private from its first instant.
pub(crate) fn create_dir_private(path: &Path) -> io::Result<()> {
    std::fs::create_dir(path)?;
    crate::win_acl::after_create(path, None);
    Ok(())
}

/// Create a store file that is private from its first instant.
pub(crate) fn create_file_private(path: &Path, _share: Share) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)?;
    crate::win_acl::after_create(path, Some(&file));
    Ok(file)
}

/// Flush a file's data and metadata.
pub(crate) fn sync_file(file: &File) -> io::Result<()> {
    let result = file.sync_all();
    trace(Trace::SyncFile(result.is_ok()));
    result
}

/// Flush a directory after a rename inside it (probe E1: needs write access).
pub(crate) fn sync_dir(path: &Path) -> io::Result<()> {
    let result = OpenOptions::new()
        .access_mode(GENERIC_WRITE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .and_then(|dir| dir.sync_all());
    trace(Trace::SyncDir(result.is_ok()));
    result
}

/// Replace `dest` with `tmp`, durably.
/// Takes `AsRef<Path>` like `std::fs::rename`, so call sites are shared.
pub(crate) fn replace(tmp: impl AsRef<Path>, dest: impl AsRef<Path>) -> io::Result<()> {
    attempt();
    trace(Trace::Replace {
        write_through: false,
    });
    std::fs::rename(tmp, dest)
}

/// Fired by the store open between the path walk and the directory open.
pub(crate) fn after_path_walk(path: &Path) {
    hook(Hook::AfterPathWalk, path);
}

// ---- test instrumentation, shared unchanged by red and fix bodies ----

/// Named observation points (test plan W-T18, W-T24).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Hook {
    AfterPathWalk,
    BeforeRecordOpen,
}

/// Durability calls, in order (test plan W-T22).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Trace {
    SyncFile(bool),
    SyncDir(bool),
    Replace { write_through: bool },
}

#[cfg(test)]
use instrument::{attempt, hook, trace};

#[cfg(not(test))]
fn hook(_which: Hook, _path: &Path) {}
#[cfg(not(test))]
fn trace(_event: Trace) {}
#[cfg(not(test))]
fn attempt() {}

#[cfg(test)]
pub(crate) mod instrument {
    use super::{Hook, Trace};
    use std::path::Path;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, Ordering};

    type HookFn = Box<dyn Fn(Hook, &Path) + Send + Sync>;
    pub(crate) static HOOK: Mutex<Option<HookFn>> = Mutex::new(None);
    pub(crate) static TRACE: Mutex<Vec<Trace>> = Mutex::new(Vec::new());
    pub(crate) static REPLACE_ATTEMPTS: AtomicU32 = AtomicU32::new(0);

    pub(super) fn hook(which: Hook, path: &Path) {
        if let Some(f) = HOOK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            f(which, path);
        }
    }

    pub(super) fn trace(event: Trace) {
        TRACE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(event);
    }

    pub(super) fn attempt() {
        REPLACE_ATTEMPTS.fetch_add(1, Ordering::SeqCst);
    }
}
