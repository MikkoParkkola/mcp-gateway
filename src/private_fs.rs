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
    /// P5: the stored DACL lacks `SE_DACL_PROTECTED` (an old-style DACL
    /// included) or holds an inherited entry.
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

/// The gateway account's SID in `S-1-...` form, for messages that must name it.
pub(crate) fn user_sid_string() -> Option<String> {
    user().ok().map(Sid::to_sddl)
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
        // A NULL DACL grants everyone everything, so nothing else about the
        // DACL matters; the owner still does, because the repair must fix it.
        found.push(PrivacyRefusal::NullDacl);
        match inspection.owner.as_ref() {
            Some(owner) if owner == user => {}
            Some(owner) => found.push(PrivacyRefusal::ForeignOwner(owner.to_sddl())),
            None => found.push(PrivacyRefusal::Unreadable),
        }
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

/// Every rule the descriptor breaks for a file of class `what`.
pub(crate) fn refusals_for(
    inspection: &Inspection,
    user: &Sid,
    what: crate::config::Protects,
) -> Vec<PrivacyRefusal> {
    use crate::config::Protects;
    if what == Protects::Secrecy {
        return refusals(inspection, user);
    }
    // Integrity: others may read, never change; SYSTEM and Administrators are
    // trusted as unix trusts root (#1718 design, owner ruling 2026-09-29).
    let trusted = |sid: &Sid| sid == user || is_system_or_admins(sid);
    let mut found = Vec::new();
    match inspection.dacl.as_ref() {
        None => found.push(PrivacyRefusal::NullDacl),
        Some(aces) => {
            for ace in aces {
                match ace {
                    Ace::Allowed { flags, mask, sid } => {
                        if !trusted(sid) && flags & INHERIT_ONLY == 0 && mask & WRITE_BITS != 0 {
                            found.push(PrivacyRefusal::ForeignSid(sid.to_sddl()));
                        }
                    }
                    Ace::Denied { .. } => {}
                    Ace::Other { ace_type } => {
                        found.push(PrivacyRefusal::OtherAceType(*ace_type));
                    }
                }
            }
        }
    }
    match inspection.owner.as_ref() {
        Some(owner) if trusted(owner) => {}
        Some(owner) => found.push(PrivacyRefusal::ForeignOwner(owner.to_sddl())),
        None => found.push(PrivacyRefusal::Unreadable),
    }
    found
}

/// Every right that lets a foreign ACE change an Integrity file.
const WRITE_BITS: u32 = windows_sys::Win32::Storage::FileSystem::FILE_WRITE_DATA
    | windows_sys::Win32::Storage::FileSystem::FILE_APPEND_DATA
    | windows_sys::Win32::Storage::FileSystem::FILE_WRITE_EA
    | windows_sys::Win32::Storage::FileSystem::FILE_WRITE_ATTRIBUTES
    | windows_sys::Win32::Storage::FileSystem::DELETE
    | windows_sys::Win32::Storage::FileSystem::WRITE_DAC
    | windows_sys::Win32::Storage::FileSystem::WRITE_OWNER
    | GENERIC_WRITE
    | GENERIC_ALL;

/// `S-1-5-18` (SYSTEM) or `S-1-5-32-544` (Administrators).
fn is_system_or_admins(sid: &Sid) -> bool {
    // Compared by value against SIDs built once: no string per owner or ACE.
    static TRUSTED: OnceLock<[Sid; 2]> = OnceLock::new();
    TRUSTED
        .get_or_init(|| [Sid::from_parts(5, &[18]), Sid::from_parts(5, &[32, 544])])
        .contains(sid)
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
    // A pipe or device has no attributes worth judging: only a disk object is
    // a regular file or directory (UPGRADING-4.0 item 99).
    if !crate::win_acl::is_disk_object(file) {
        return Err(PrivacyRefusal::NotRegular);
    }
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

/// Every rule an open file breaks for class `what`: a link or a non-regular
/// file is refused alone (there is no DACL worth judging on it), otherwise
/// [`refusals_for`] on the handle's own descriptor.
pub(crate) fn file_refusals_for(file: &File, what: crate::config::Protects) -> Vec<PrivacyRefusal> {
    let attrs = match attributes(file) {
        Ok(attrs) => attrs,
        Err(refusal) => return vec![refusal],
    };
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return vec![PrivacyRefusal::ReparsePoint];
    }
    if attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return vec![PrivacyRefusal::NotRegular];
    }
    match (user(), crate::win_acl::inspect(file)) {
        (Ok(user), Ok(inspection)) => refusals_for(&inspection, user, what),
        _ => vec![PrivacyRefusal::Unreadable],
    }
}

/// Which rules failed, and the PowerShell lines that repair them, one per
/// line. Paths are PowerShell single-quoted literals (no expansion), with every
/// single-quote character PowerShell recognises doubled, so no path can end
/// the literal. The gateway account is named by its SID, which stays right in
/// an elevated prompt run as another account. The DACL is replaced in ONE
/// write with a protected DACL holding only the gateway account's grant, so no
/// intermediate state exposes the file. With a foreign owner the lines need an
/// administrator prompt: take ownership, write the DACL as owner, then give
/// ownership to the gateway account. The SDDL depends on the file's class:
/// a secret is owner-only, a trust file also grants SYSTEM and Administrators
/// full control and Everyone read (a superset of any prior reader, so the
/// repair cuts off no legitimate reader and removes every foreign write).
pub(crate) fn windows_remediation(
    path: &str,
    found: &[PrivacyRefusal],
    what: crate::config::Protects,
) -> String {
    use PrivacyRefusal as P;
    use std::fmt::Write as _;
    let Some(me) = user_sid_string() else {
        // Ends in a line break, as every other branch does: a caller appends.
        return format!(
            " ({found:?}). The gateway account could not be resolved, so no repair command is printed.\n"
        );
    };
    let literal: String = path
        .chars()
        .flat_map(|c| {
            let quote = matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}');
            std::iter::once(c).chain(quote.then_some(c))
        })
        .collect();
    let foreign_owner = found.iter().any(|r| matches!(r, P::ForeignOwner(_)));
    // Allowlist first: a line an administrator runs elevated is printed only
    // for a path made of characters that can never end or escape a literal.
    // The quote doubling above is the second layer, not the gate.
    if !runnable_path(path) {
        let mut out = format!(
            " ({found:?}). The path holds characters outside letters, digits, space and \
             \\ : . _ - ( ), so no command is printed for it. To repair it"
        );
        if foreign_owner {
            let _ = write!(
                out,
                ", as an administrator, make the account with SID {me} its owner, then"
            );
        }
        let _ = match what {
            crate::config::Protects::Secrecy => write!(
                out,
                " open its Security settings, disable inheritance and remove every entry, \
                 and grant Full control to the account with SID {me} alone."
            ),
            crate::config::Protects::Integrity => write!(
                out,
                " open its Security settings, disable inheritance, remove write, delete, \
                 change-permissions and take-ownership rights from every account except \
                 SYSTEM, Administrators and the account with SID {me}, keep read access for \
                 the others, and grant Full control to the account with SID {me}."
            ),
        };
        // Ends in a line break, as the runnable branch does: a caller appends.
        out.push('\n');
        return out;
    }
    let sddl = match what {
        crate::config::Protects::Secrecy => format!("D:P(A;;FA;;;{me})"),
        crate::config::Protects::Integrity => {
            format!("D:P(A;;FA;;;{me})(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;WD)")
        }
    };
    let mut out = format!(" ({found:?}). To repair it, run these lines in Windows PowerShell");
    if foreign_owner {
        out.push_str(" as an administrator, because the file has another owner");
    }
    out.push_str(":\n");
    // With a foreign owner, the elevated account first takes ownership itself
    // (an owner may always write the DACL), writes the DACL, and only then
    // hands ownership to the gateway account. Handing it over first could
    // leave the elevated account with no right to write the DACL.
    if foreign_owner {
        let _ = writeln!(out, "takeown /F '{literal}'");
    }
    let _ = writeln!(
        out,
        "$acl = New-Object System.Security.AccessControl.FileSecurity; \
         $acl.SetSecurityDescriptorSddlForm('{sddl}', 'Access'); \
         (Get-Item -LiteralPath '{literal}').SetAccessControl($acl)"
    );
    if foreign_owner {
        let _ = writeln!(out, "icacls '{literal}' /setowner '*{me}'");
    }
    out
}

/// What follows a refusal head for a file of class `what`: the broken rules
/// and the repair for that class (or the not-a-regular-file advice). One text
/// for every guarded reader and writer of a trust or secret file.
pub(crate) fn refusal_detail(
    shown: &str,
    found: &[PrivacyRefusal],
    what: crate::config::Protects,
) -> String {
    if found
        .iter()
        .any(|r| matches!(r, PrivacyRefusal::ReparsePoint | PrivacyRefusal::NotRegular))
    {
        return format!(
            " ({found:?}): it is not a regular file. Write the content, then replace the file."
        );
    }
    let mut text = windows_remediation(shown, found, what);
    if what == crate::config::Protects::Integrity {
        text.push_str(
            "This file may be read by others, so the repair keeps them as readers; \
             an owner-only repair would also lock out legitimate readers.\n",
        );
    }
    text
}

/// The characters a printed, runnable repair line may carry in its path.
fn runnable_path(path: &str) -> bool {
    path.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, ' ' | '\\' | ':' | '.' | '_' | '-' | '(' | ')')
    })
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

#[cfg(test)]
#[path = "private_fs_class_tests.rs"]
mod class_tests;
