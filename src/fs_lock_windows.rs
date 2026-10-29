// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The Windows half of [`super::ExclusiveFileLock`]'s `acquire`, `try_lease`
//! (and through it `lease` and `acquire_until`): the lock directory is judged
//! and pinned, the sidecar is created owner-only, and an existing sidecar is
//! used only once it judges private.
//!
//! A sidecar that does not (an older build created it with its directory's
//! inherited ACL, or another account planted it) is replaced. Never by name:
//! an older build shares delete, so a delete by name succeeds under a holder,
//! who then keeps locking the unlinked file while the next process locks the
//! new one. It is replaced only through a handle opened with no sharing at
//! all, which exists only when no other handle to the file does, and closing
//! that handle deletes the file. A sidecar still open elsewhere is refused, and
//! the caller's own deadline bounds how long that is waited out.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt as _;
use std::path::Path;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_FLAG_DELETE_ON_CLOSE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
    FILE_SHARE_WRITE, READ_CONTROL,
};

use super::{Attempt, DirPin, ExclusiveFileLock};
use crate::private_fs::{PrivacyRefusal, Share, create_file_private, judge_file, judge_lock_dir};

const ACCESS_DENIED: i32 = 5;
const SHARING_VIOLATION: i32 = 32;

/// How long `acquire`, which has no deadline of its own, waits for a sidecar
/// it can use. Past it the refusal is returned; a legitimate holder of an
/// owner-only sidecar is still waited for without a bound, as before.
const HEAL_LIMIT: Duration = Duration::from_secs(30);
const HEAL_POLL: Duration = Duration::from_millis(25);

/// One attempt, never waiting: `Err` only for the errors a lock file open has
/// always returned (a missing or read-only directory); a refused directory or
/// sidecar is `Refused`.
pub(super) fn probe(lock_path: &Path) -> io::Result<Attempt> {
    // A refused directory is a refusal like a refused sidecar, so a caller
    // that keeps refusals on its busy path (the grant journal) never reads it
    // as an unreadable file.
    let pin = match lock_dir(lock_path) {
        Ok(pin) => pin,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            return Ok(Attempt::Refused(error));
        }
        Err(error) => return Err(error),
    };
    let sidecar = sidecar(lock_path)?;
    // Held from the judgement to the sidecar's open only.
    drop(pin);
    Ok(match sidecar {
        Sidecar::Private(file) => match file.try_lock() {
            Ok(()) => Attempt::Taken(ExclusiveFileLock::held(file)),
            Err(std::fs::TryLockError::WouldBlock) => Attempt::Held,
            Err(std::fs::TryLockError::Error(error)) => return Err(error),
        },
        Sidecar::Held => Attempt::Held,
        Sidecar::Refused(error) => Attempt::Refused(error),
    })
}

/// Block until the lock is taken. Only the search for a usable sidecar is
/// bounded (`HEAL_LIMIT`); the wait for a holder of an owner-only one is not.
pub(super) fn acquire(lock_path: &Path) -> io::Result<ExclusiveFileLock> {
    let deadline = Instant::now() + HEAL_LIMIT;
    loop {
        let pin = lock_dir(lock_path)?;
        let sidecar = sidecar(lock_path)?;
        // Held from the judgement to the sidecar's open only, never across a
        // wait for a holder.
        drop(pin);
        let refused = match sidecar {
            Sidecar::Private(file) => {
                super::lock_exclusive(&file)?;
                return Ok(ExclusiveFileLock::held(file));
            }
            Sidecar::Held => None,
            Sidecar::Refused(error) => Some(error),
        };
        let now = Instant::now();
        if now >= deadline {
            return Err(refused.unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "lock file {} could not be opened owner-only within {} s",
                        lock_path.display(),
                        HEAL_LIMIT.as_secs()
                    ),
                )
            }));
        }
        std::thread::sleep(HEAL_POLL.min(deadline - now));
    }
}

/// The directory a lock path names: its parent, or the current directory for
/// a bare file name.
fn parent_of(lock_path: &Path) -> &Path {
    lock_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// Open and judge the lock's directory. The handle is held while the
/// sidecar is opened, so the directory judged is the one the sidecar is in.
/// A directory only broad local groups may write proceeds with one warning.
fn lock_dir(lock_path: &Path) -> io::Result<DirPin> {
    let configured = std::path::absolute(parent_of(lock_path))?;
    let dir = crate::private_fs::open_dir(&configured)?;
    let found = judge_lock_dir(&dir, &configured);
    if found.is_empty() {
        return Ok(DirPin(dir));
    }
    match broad_groups(&found) {
        Some(groups) => {
            warn_once(&configured, &groups);
            Ok(DirPin(dir))
        }
        None => Err(directory_refusal(&configured, &found)),
    }
}

/// The local groups every account on the host belongs to. A lock directory
/// that lets only these (beside the user, SYSTEM and Administrators) write is
/// common outside the profile (another drive, `ProgramData`), so refusing it
/// would stop the gateway starting after an upgrade; it is warned about
/// instead. Everyone, Anonymous and any specific account are still refused.
const BROAD_GROUPS: [(&str, &str); 2] = [
    ("S-1-5-32-545", "BUILTIN\\Users"),
    ("S-1-5-11", "Authenticated Users"),
];

/// The broad groups behind `found`, when every rule broken is one of their
/// writes; `None` when anything else is refused.
fn broad_groups(found: &[PrivacyRefusal]) -> Option<Vec<&'static str>> {
    let mut groups = found
        .iter()
        .map(|refusal| match refusal {
            PrivacyRefusal::ForeignSid(sid) => BROAD_GROUPS
                .iter()
                .find(|(group, _)| group == sid)
                .map(|(_, name)| *name),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    groups.sort_unstable();
    groups.dedup();
    (!groups.is_empty()).then_some(groups)
}

/// One warning per directory per process.
fn warn_once(dir: &Path, groups: &[&str]) {
    static WARNED: parking_lot::Mutex<Vec<std::path::PathBuf>> =
        parking_lot::Mutex::new(Vec::new());
    {
        let mut warned = WARNED.lock();
        if warned.iter().any(|seen| seen == dir) {
            return;
        }
        warned.push(dir.to_path_buf());
    }
    let text = broad_warning(dir, groups);
    tracing::warn!(directory = %dir.display(), "{text}");
}

/// What `doctor` reports for `dir` as a lock directory: the warning for one
/// only broad local groups may write, the refusal for one that is refused,
/// why it could not be judged, or `None` when it is fine or does not exist.
pub(super) fn lock_directory_finding(dir: &Path) -> Option<String> {
    let configured = match std::path::absolute(dir) {
        Ok(configured) => configured,
        Err(error) => {
            return Some(format!(
                "lock directory {} cannot be resolved: {error}",
                dir.display()
            ));
        }
    };
    let handle = match crate::private_fs::open_dir(&configured) {
        Ok(handle) => handle,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return None,
        Err(error) => {
            return Some(format!(
                "lock directory {} cannot be opened to judge it: {error}",
                configured.display()
            ));
        }
    };
    let found = judge_lock_dir(&handle, &configured);
    if found.is_empty() {
        return None;
    }
    Some(match broad_groups(&found) {
        Some(groups) => broad_warning(&configured, &groups),
        None => directory_refusal(&configured, &found).to_string(),
    })
}

/// The warning text, with the repair in prose: a command built from a path
/// quotes differently in each shell, and getting it wrong can cut this
/// account's own access. The steps first keep this account's access, so
/// removing the groups never removes it.
fn broad_warning(dir: &Path, groups: &[&str]) -> String {
    let groups = groups.join(" and ");
    format!(
        "lock directory {} lets {groups} create files in it, so another local account could \
         hold a lock file there and stall the gateway's writes; the gateway proceeds. To close \
         it, in the folder's Security settings disable inheritance (copying the entries), give \
         this account Full control, and remove {groups}",
        dir.display()
    )
}

enum Sidecar {
    /// Judged owner-only; not yet locked.
    Private(File),
    /// Open elsewhere in a way that is ordinary contention, or mid-replace.
    Held,
    /// Not owner-only and cannot be replaced now.
    Refused(io::Error),
}

fn sidecar(path: &Path) -> io::Result<Sidecar> {
    match create_file_private(path, Share::LockSidecar) {
        Ok(file) => return Ok(Sidecar::Private(file)),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) if error.raw_os_error() == Some(SHARING_VIOLATION) => return Ok(Sidecar::Held),
        // A name still in place but refused a create is delete-pending: a
        // healer's delete-on-close replace met another open handle (an
        // indexer, an antivirus scan), and the name frees once that closes.
        Err(error) if error.raw_os_error() == Some(ACCESS_DENIED) => match denied_create(path) {
            Denied::Pending => return Ok(Sidecar::Held),
            Denied::Directory => {}
            Denied::Created(file) => return Ok(Sidecar::Private(file)),
            Denied::Unwritable => return Err(error),
        },
        // A directory this account may not create in is an error, as it
        // always was: the grant journal reads it as an unreadable file.
        Err(error) => return Err(error),
    }
    // Something other than a file in the way is an error at once, never a
    // sidecar to wait out or replace.
    if std::fs::symlink_metadata(path).is_ok_and(|meta| meta.is_dir()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("lock file {} is a directory", path.display()),
        ));
    }
    let reason = match open_existing(path) {
        Ok(file) => match judge_file(&file) {
            Ok(()) => return Ok(Sidecar::Private(file)),
            Err(reason) => format!("{reason:?}"),
        },
        Err(error) if error.raw_os_error() == Some(SHARING_VIOLATION) => return Ok(Sidecar::Held),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Sidecar::Held),
        Err(error) if error.raw_os_error() == Some(ACCESS_DENIED) => {
            "this account cannot open it".to_owned()
        }
        Err(error) => return Err(error),
    };
    #[cfg(test)]
    after_judge();
    match open_exclusive(path) {
        // The only handle: closing it deletes the file.
        Ok(only) => {
            drop(only);
            Ok(match create_file_private(path, Share::LockSidecar) {
                Ok(file) => Sidecar::Private(file),
                // Another healer recreated it first, or the name is still
                // settling: the next attempt judges whatever is there.
                Err(_) => Sidecar::Held,
            })
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Sidecar::Held),
        // Open elsewhere: a healer's owner-only replacement is contention; the
        // original, still open, is the refusal.
        Err(error) if error.raw_os_error() == Some(SHARING_VIOLATION) => {
            Ok(match open_existing(path) {
                Ok(file) if judge_file(&file).is_ok() => Sidecar::Held,
                Ok(_) => Sidecar::Refused(held_refusal(path, &reason)),
                Err(error) if error.raw_os_error() == Some(ACCESS_DENIED) => {
                    Sidecar::Refused(held_refusal(path, &reason))
                }
                Err(_) => Sidecar::Held,
            })
        }
        // Never "remove it": whether another process still has it open is not
        // known here, and removing a file something holds splits the lock.
        Err(error) => Ok(Sidecar::Refused(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "lock file {} is not owner-only ({reason}) and cannot be replaced ({error}). Stop \
                 any process that may have it open and give this account the right to replace \
                 files in that folder; the gateway then replaces the file itself",
                path.display()
            ),
        ))),
    }
}

/// What a create refused with `ERROR_ACCESS_DENIED` met.
enum Denied {
    /// The name is still in place: delete-pending, contention to wait out.
    Pending,
    /// A directory holds the name: the caller's directory error follows.
    Directory,
    /// The delete finished in between, and a second create took the name.
    Created(File),
    /// The name is absent and a create is still refused: this account may
    /// not create in the directory.
    Unwritable,
}

/// Tell a delete-pending name (whose metadata reads, or is itself refused)
/// from a directory this account may not create in (no such name). One more
/// create covers a delete that finished between the two reads.
fn denied_create(path: &Path) -> Denied {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => Denied::Directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match create_file_private(path, Share::LockSidecar) {
                Ok(file) => Denied::Created(file),
                Err(again)
                    if again.raw_os_error() == Some(ACCESS_DENIED)
                        && std::fs::symlink_metadata(path)
                            .is_err_and(|e| e.kind() == io::ErrorKind::NotFound) =>
                {
                    Denied::Unwritable
                }
                Err(_) => Denied::Pending,
            }
        }
        _ => Denied::Pending,
    }
}

/// The open `try_acquire` judges with: read and write, sharing read and write
/// (never delete), not following a link.
fn open_existing(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(GENERIC_READ | GENERIC_WRITE | READ_CONTROL)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

/// Delete access, no sharing: succeeds only when no other handle exists, and
/// deletes the file (a link itself, never its target) when closed.
fn open_exclusive(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(DELETE)
        .share_mode(0)
        .custom_flags(FILE_FLAG_DELETE_ON_CLOSE | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

fn held_refusal(path: &Path, reason: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "lock file {} is not owner-only ({reason}) and another process holds it open, so it \
             cannot be replaced yet. Stop that process (another gateway, perhaps an older \
             version); the gateway then replaces the file itself",
            path.display()
        ),
    )
}

/// Prose, never a command: a command built from a path is an injection risk
/// when pasted, and a blanket removal can cut this account's own access.
fn directory_refusal(dir: &Path, found: &[PrivacyRefusal]) -> io::Error {
    use PrivacyRefusal as P;
    let mut others: Vec<&str> = found
        .iter()
        .filter_map(|refusal| match refusal {
            P::ForeignSid(sid) => Some(sid.as_str()),
            _ => None,
        })
        .collect();
    others.sort_unstable();
    others.dedup();
    let mut why = Vec::new();
    if !others.is_empty() {
        why.push(format!(
            "lets {} add, delete or change files in it, or change its permissions",
            others.join(", ")
        ));
    }
    for refusal in found {
        match refusal {
            P::ForeignSid(_) => {}
            P::NullDacl => why.push("has no access list, so every account has full access".into()),
            P::OtherAceType(kind) => why.push(format!(
                "holds an access entry of a type the gateway cannot judge (type {kind})"
            )),
            P::ForeignOwner(owner) => why.push(format!("is owned by {owner}")),
            P::ReparsePoint | P::PathMismatch => {
                why.push("is a link, or a link sits in its path".into());
            }
            P::NotLocal => {
                why.push("is on a network volume, or one that keeps no access lists".into());
            }
            P::NotRegular => why.push("is not a directory".into()),
            other => why.push(format!("fails {other:?}")),
        }
    }
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "lock directory {} {}. In the folder's Security settings remove other accounts' rights \
             to add, delete or change anything in it (an inherited entry needs inheritance \
             disabled first), keeping this account's own access; a link or a network location \
             needs the data directory moved to a local folder",
            dir.display(),
            why.join("; ")
        ),
    )
}

#[cfg(test)]
thread_local! {
    static AFTER_JUDGE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Test seam: run `hook` once, on this thread, after the next probe judged an
/// existing sidecar not owner-only and before it tries to replace it.
#[cfg(test)]
pub(super) fn after_judge_once(hook: impl FnOnce() + 'static) {
    AFTER_JUDGE.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn after_judge() {
    if let Some(hook) = AFTER_JUDGE.with(|slot| slot.borrow_mut().take()) {
        hook();
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    #[test]
    fn a_bare_file_name_locks_in_the_current_directory() {
        assert_eq!(super::parent_of(Path::new("x.lock")), Path::new("."));
        assert_eq!(super::parent_of(Path::new("d\\x.lock")), Path::new("d"));
    }
}
