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
    Ok(match sidecar(lock_path)? {
        Sidecar::Private(file) => match file.try_lock() {
            Ok(()) => Attempt::Taken(ExclusiveFileLock::held(file).pinning(pin)),
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
        let refused = match sidecar(lock_path)? {
            Sidecar::Private(file) => {
                super::lock_exclusive(&file)?;
                return Ok(ExclusiveFileLock::held(file).pinning(pin));
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
        drop(pin);
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

/// Open and judge the lock's directory; the handle is held for the lock's
/// lifetime so the directory cannot be renamed or swapped under it.
fn lock_dir(lock_path: &Path) -> io::Result<DirPin> {
    let configured = std::path::absolute(parent_of(lock_path))?;
    let dir = crate::private_fs::open_dir(&configured)?;
    let found = judge_lock_dir(&dir, &configured);
    if found.is_empty() {
        Ok(DirPin(dir))
    } else {
        Err(directory_refusal(&configured, &found))
    }
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
