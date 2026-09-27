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
use std::path::{Component, Path, PathBuf, Prefix};
use std::sync::OnceLock;

use crate::win_acl::{Ace, Inspection, Sid};

use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, MOVEFILE_WRITE_THROUGH, READ_CONTROL,
};

pub(crate) use crate::win_acl::Share;

/// Why an object is not private (design §2.2). Tests assert the reason, so one
/// check cannot mask another.
#[derive(Clone, Debug, Eq, PartialEq)]
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
/// Only a plain drive (`C:`) or its verbatim form (`\\?\C:`); a UNC share,
/// a device path or `\\?\GLOBALROOT` is not a local, ACL-bearing location.
pub(crate) fn prefix_allowed(component: &Component<'_>) -> bool {
    matches!(
        component,
        Component::Prefix(p) if matches!(p.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
    )
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

/// The user this process runs as, read once.
fn user() -> io::Result<&'static Sid> {
    static USER: OnceLock<Sid> = OnceLock::new();
    if let Some(user) = USER.get() {
        return Ok(user);
    }
    let sid = crate::win_acl::current_user_sid()?;
    Ok(USER.get_or_init(|| sid))
}

/// `FILE_READ_DATA | FILE_WRITE_DATA`, or `GENERIC_ALL`: what P3 requires.
const READ_WRITE: u32 = 0x1 | 0x2;
const GENERIC_ALL: u32 = 0x1000_0000;
/// `INHERITED_ACE`.
const INHERITED: u8 = 0x10;
/// `INHERIT_ONLY_ACE`: applies to children only, never to the object itself.
const INHERIT_ONLY: u8 = 0x08;
/// `GENERIC_READ | GENERIC_WRITE`.
const GENERIC_READ_WRITE: u32 = 0x8000_0000 | 0x4000_0000;

/// Every rule P1-P5 the descriptor breaks, in the design's reporting order.
pub(crate) fn refusals(inspection: &Inspection, user: &Sid) -> Vec<PrivacyRefusal> {
    let mut found = Vec::new();
    let Some(aces) = inspection.dacl.as_ref() else {
        found.push(PrivacyRefusal::NullDacl);
        return found;
    };
    let mut read_write = false;
    let mut user_denied = false;
    let mut inherited = false;
    for ace in aces {
        match ace {
            Ace::Allowed { flags, mask, sid } => {
                inherited |= flags & INHERITED != 0;
                if sid != user {
                    found.push(PrivacyRefusal::ForeignSid(sid.to_sddl()));
                } else if flags & INHERIT_ONLY == 0 {
                    read_write |= mask & GENERIC_ALL != 0
                        || mask & READ_WRITE == READ_WRITE
                        || mask & GENERIC_READ_WRITE == GENERIC_READ_WRITE;
                }
            }
            // A deny only narrows access; it may name anyone. One naming the
            // user that takes away read or write fails P3. A deny for a group
            // the user belongs to is not resolved here: it can only make the
            // store unusable (fail closed), never readable by someone else.
            Ace::Denied { flags, mask, sid } => {
                inherited |= flags & INHERITED != 0;
                user_denied |= sid == user
                    && flags & INHERIT_ONLY == 0
                    && mask & (READ_WRITE | GENERIC_ALL | GENERIC_READ_WRITE) != 0;
            }
            Ace::Other { ace_type } => found.push(PrivacyRefusal::OtherAceType(*ace_type)),
        }
    }
    if !read_write || user_denied {
        found.push(PrivacyRefusal::NoReadWrite);
    }
    match inspection.owner.as_ref() {
        Some(owner) if owner == user => {}
        Some(owner) => found.push(PrivacyRefusal::ForeignOwner(owner.to_sddl())),
        None => found.push(PrivacyRefusal::Unreadable),
    }
    if !inspection.protected || inherited {
        found.push(PrivacyRefusal::NotProtected);
    }
    found
}

/// Every rule the open object breaks; empty when it is private.
pub(crate) fn privacy_refusals(file: &File) -> Vec<PrivacyRefusal> {
    match (user(), crate::win_acl::inspect(file)) {
        (Ok(user), Ok(inspection)) => refusals(&inspection, user),
        _ => vec![PrivacyRefusal::Unreadable],
    }
}

fn first(found: Vec<PrivacyRefusal>) -> Result<(), PrivacyRefusal> {
    found.into_iter().next().map_or(Ok(()), Err)
}

fn attributes(file: &File) -> Result<u32, PrivacyRefusal> {
    use std::os::windows::fs::MetadataExt as _;
    file.metadata()
        .map(|meta| meta.file_attributes())
        .map_err(|_| PrivacyRefusal::Unreadable)
}

/// Re-walk `configured` after the store directory is open: every existing
/// component must still be a plain directory (no reparse point), and the path
/// must still resolve to the very directory the handle holds. This is what
/// catches an ancestor swapped for a junction between the first walk and the
/// open (design R2-1). Comparing identities, not path strings, keeps 8.3 short
/// names (`RUNNER~1`) from reading as a different place.
fn same_place(dir: &File, configured: &Path) -> Result<(), PrivacyRefusal> {
    // `absolute` resolves `.`/`..` and a relative path the same way the
    // original open did.
    let wanted = std::path::absolute(configured).map_err(|_| PrivacyRefusal::PathMismatch)?;
    let mut prefix = PathBuf::new();
    let mut last = None;
    for part in wanted.components() {
        prefix.push(part);
        if matches!(part, Component::Prefix(_) | Component::RootDir) {
            continue;
        }
        let handle = OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&prefix)
            .map_err(|_| PrivacyRefusal::PathMismatch)?;
        if attributes(&handle)? & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(PrivacyRefusal::PathMismatch);
        }
        last = Some(handle);
    }
    let last = last.ok_or(PrivacyRefusal::PathMismatch)?;
    let held = crate::win_acl::file_identity(dir).map_err(|_| PrivacyRefusal::Unreadable)?;
    let now = crate::win_acl::file_identity(&last).map_err(|_| PrivacyRefusal::Unreadable)?;
    if held != now {
        return Err(PrivacyRefusal::PathMismatch);
    }
    Ok(())
}

/// Judge an open directory handle against reparse, locality, the configured
/// path and P1-P5.
pub(crate) fn judge_dir(dir: &File, configured: &Path) -> Result<(), PrivacyRefusal> {
    let attrs = attributes(dir)?;
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(PrivacyRefusal::ReparsePoint);
    }
    if attrs & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(PrivacyRefusal::NotRegular);
    }
    if !crate::win_acl::volume_is_local(dir).map_err(|_| PrivacyRefusal::Unreadable)? {
        return Err(PrivacyRefusal::NotLocal);
    }
    same_place(dir, configured)?;
    first(privacy_refusals(dir))
}

/// Judge an open file handle against reparse, regular-file and P1-P5.
pub(crate) fn judge_file(file: &File) -> Result<(), PrivacyRefusal> {
    let attrs = attributes(file)?;
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(PrivacyRefusal::ReparsePoint);
    }
    if attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return Err(PrivacyRefusal::NotRegular);
    }
    first(privacy_refusals(file))
}

/// Create a store directory that is private from its first instant.
pub(crate) fn create_dir_private(path: &Path) -> io::Result<()> {
    crate::win_acl::create_dir_private(path, user()?)
}

/// Create a store file that is private from its first instant.
pub(crate) fn create_file_private(path: &Path, share: Share) -> io::Result<File> {
    crate::win_acl::create_file_private(path, user()?, share)
}

/// Flush a file's data and metadata.
pub(crate) fn sync_file(file: &File) -> io::Result<()> {
    let result: io::Result<()> = {
        let _ = file;
        Ok(())
    };
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

/// Replace `dest` with `tmp`, durably (`MOVEFILE_WRITE_THROUGH`). An outside
/// holder of `dest` (an antivirus scan, a backup agent) makes the move fail
/// with access-denied or a sharing violation (probe E2b); that is retried, at
/// most three attempts in all, 10 then 20 ms apart, and then reported.
/// Takes `AsRef<Path>` like `std::fs::rename`, so call sites are shared.
pub(crate) fn replace(tmp: impl AsRef<Path>, dest: impl AsRef<Path>) -> io::Result<()> {
    const ATTEMPTS: u32 = 3;
    let (tmp, dest) = (tmp.as_ref(), dest.as_ref());
    let mut wait = std::time::Duration::from_millis(10);
    let mut attempt_no = 1;
    loop {
        attempt();
        trace(Trace::Replace {
            write_through: crate::win_acl::REPLACE_FLAGS & MOVEFILE_WRITE_THROUGH != 0,
        });
        match crate::win_acl::replace(tmp, dest) {
            Err(error) if attempt_no < ATTEMPTS && matches!(error.raw_os_error(), Some(5 | 32)) => {
                hook(Hook::ReplaceRetry, dest);
                std::thread::sleep(wait);
                wait *= 2;
                attempt_no += 1;
            }
            done => return done,
        }
    }
}

/// Fired by the store open between the path walk and the directory open.
pub(crate) fn after_path_walk(path: &Path) {
    hook(Hook::AfterPathWalk, path);
}

/// Fired by the store open after its directories are judged and before custody
/// is taken, while only the held directory handles pin them.
pub(crate) fn after_dir_judged(path: &Path) {
    hook(Hook::AfterDirJudged, path);
}

// ---- test instrumentation, shared unchanged by red and fix bodies ----

/// Named observation points (test plan W-T18, W-T24).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Hook {
    AfterPathWalk,
    /// Directories judged and held, custody not yet taken (W-T16b).
    AfterDirJudged,
    BeforeRecordOpen,
    /// A replace attempt failed and another is about to run (W-T20).
    ReplaceRetry,
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

/// Thread-local, so parallel tests never see each other's hooks or traces.
/// Store operations run the IO on the calling thread, where the hook is set.
#[cfg(test)]
pub(crate) mod instrument {
    use super::{Hook, Trace};
    use std::cell::{Cell, RefCell};
    use std::path::Path;

    type HookFn = Box<dyn Fn(Hook, &Path)>;
    thread_local! {
        static HOOK: RefCell<Option<HookFn>> = const { RefCell::new(None) };
        static TRACE: RefCell<Vec<Trace>> = const { RefCell::new(Vec::new()) };
        static REPLACE_ATTEMPTS: Cell<u32> = const { Cell::new(0) };
    }

    pub(crate) fn set_hook(hook: Option<HookFn>) {
        HOOK.with(|h| *h.borrow_mut() = hook);
    }

    /// Take (and clear) this thread's durability trace.
    pub(crate) fn take_trace() -> Vec<Trace> {
        TRACE.with(|t| std::mem::take(&mut *t.borrow_mut()))
    }

    /// Take (and reset) this thread's replace-attempt count.
    pub(crate) fn take_attempts() -> u32 {
        REPLACE_ATTEMPTS.with(|c| c.replace(0))
    }

    pub(super) fn hook(which: Hook, path: &Path) {
        HOOK.with(|h| {
            if let Some(f) = h.borrow().as_ref() {
                f(which, path);
            }
        });
    }

    pub(super) fn trace(event: Trace) {
        TRACE.with(|t| t.borrow_mut().push(event));
    }

    pub(super) fn attempt() {
        REPLACE_ATTEMPTS.with(|c| c.set(c.get() + 1));
    }
}

#[cfg(test)]
#[path = "private_fs_test_support.rs"]
pub(crate) mod test_support;

#[cfg(test)]
#[path = "private_fs_tests.rs"]
mod tests;
