// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Primitive A: replace the config with bytes and prove they are durable, or
//! prove what is on disk without writing. A [`CommitToken`] exists only after
//! the directory sync, the file flush and a matching read-back of the target,
//! in that order; nothing else builds one.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "the config writer, a later step, calls A")
)]

use std::io;
use std::path::Path;

#[cfg(test)]
use super::journal::fault::{self, Fault, HookAt};
use super::lock::Locked;
use super::{FileMode, Symlink, write_atomic};

/// The SHA-256 of a file's bytes, lowercase hex: the revision a diff or a
/// history view was made from. Not `config_revision`, which also covers the
/// process environment and `file:` secrets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FileRevision(String);

impl FileRevision {
    /// The revision of `bytes`.
    #[must_use]
    pub(crate) fn of(bytes: &[u8]) -> Self {
        Self(crate::hashing::sha256_hex(bytes))
    }

    /// The revision of everything `reader` yields, read in fixed chunks:
    /// equal to [`Self::of`] over the same bytes.
    ///
    /// # Errors
    ///
    /// The read error; never a revision of a partial read.
    pub(crate) fn of_reader(reader: impl std::io::Read) -> std::io::Result<Self> {
        crate::hashing::sha256_hex_reader(reader).map(Self)
    }

    /// The hex digest.
    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Proof that the target holds `revision`'s bytes durably: the token exists
/// only after the directory sync, the file flush and a matching read-back,
/// in that order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommitToken {
    revision: FileRevision,
}

impl CommitToken {
    /// The revision the target was proven to hold.
    pub(crate) fn revision(&self) -> &FileRevision {
        &self.revision
    }
}

/// Which write a commit makes. A behaves the same for both; the seam and the
/// writer's journal fact tell them apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Action {
    /// The new bytes.
    Forward,
    /// The original, put back.
    Restore,
}

/// Which A call a directory sync belongs to, so a test seam can fail one
/// call's sync and not another's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SyncKey {
    /// A commit's sync after its rename.
    Commit(Action),
    /// A verify's sync.
    Verify,
}

/// What the read-back found at the target.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Found {
    /// No file there.
    Missing,
    /// A FIFO, device or directory: never hashed.
    NotAFile,
    /// A regular file with these bytes.
    Bytes(FileRevision),
}

/// Why a configured path refused the write.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The configured path no longer names the locked target.
    Moved,
    /// Any other refusal, in `Locked`'s own words; never parsed.
    Other(String),
}

/// Why no token was issued.
#[derive(Debug)]
pub(crate) enum NotDurable {
    /// No rename happened: the target is unchanged.
    Write(io::Error),
    /// Renamed, durability unproven: the directory sync or the read-back
    /// failed.
    Sync(io::Error),
    /// The payload is not at the target as a regular file.
    NotOnDisk { found: Found },
    /// Refused before any write.
    Refused(Refusal),
    /// Refused after the rename: the new bytes stand on the old target.
    Repointed(Refusal),
}

/// Write `bytes` over the locked target, sync its directory, read it back.
///
/// # Errors
///
/// [`NotDurable`], naming whether the rename happened.
pub(crate) fn commit(
    locked: &Locked,
    configured: &Path,
    action: Action,
    bytes: &[u8],
) -> Result<CommitToken, NotDurable> {
    if let Some(why) = refusal(locked, configured) {
        return Err(NotDurable::Refused(why));
    }
    #[cfg(test)]
    if fault::fires(&locked.target, |f| matches!(f, Fault::FailWrite)).is_some() {
        return Err(NotDurable::Write(io::Error::other(
            "injected write failure",
        )));
    }
    write_atomic(&locked.target, bytes, FileMode::Private, Symlink::Replace)
        .map_err(NotDurable::Write)?;
    // From here the rename happened: every failure leaves the new bytes.
    super::sync_dir_for(&locked.target, Some(SyncKey::Commit(action))).map_err(NotDurable::Sync)?;
    let revision = FileRevision::of(bytes);
    #[cfg(test)]
    hook(&locked.target, HookAt::BeforeReadBack);
    read_back(&locked.target, &revision)?;
    #[cfg(test)]
    hook(&locked.target, HookAt::BeforeRecheck);
    if let Some(why) = refusal(locked, configured) {
        return Err(NotDurable::Repointed(why));
    }
    Ok(CommitToken { revision })
}

/// Prove the target holds `expected` without writing: sync its directory,
/// read it back.
///
/// # Errors
///
/// [`NotDurable`]; never `Write` or `Repointed`, since nothing is written.
pub(crate) fn verify(
    locked: &Locked,
    configured: &Path,
    expected: &FileRevision,
) -> Result<CommitToken, NotDurable> {
    if let Some(why) = refusal(locked, configured) {
        return Err(NotDurable::Refused(why));
    }
    super::sync_dir_for(&locked.target, Some(SyncKey::Verify)).map_err(NotDurable::Sync)?;
    #[cfg(test)]
    hook(&locked.target, HookAt::BeforeReadBack);
    read_back(&locked.target, expected)?;
    #[cfg(test)]
    hook(&locked.target, HookAt::BeforeRecheck);
    if let Some(why) = refusal(locked, configured) {
        return Err(NotDurable::Refused(why));
    }
    Ok(CommitToken {
        revision: expected.clone(),
    })
}

/// Whether the configured path refuses a write now. `may_write` speaks in
/// sentences; whether the path moved is asked of `still_named_by`, never read
/// from the sentence.
fn refusal(locked: &Locked, configured: &Path) -> Option<Refusal> {
    let text = locked.may_write(configured).err()?;
    Some(if locked.still_named_by(configured).is_err() {
        Refusal::Moved
    } else {
        Refusal::Other(text)
    })
}

/// Read the target back and compare its digest with `expected`. Only a
/// regular file is hashed: a FIFO or device is opened without waiting on it
/// and refused. A read error proves nothing, so it is `Sync`.
fn read_back(target: &Path, expected: &FileRevision) -> Result<(), NotDurable> {
    let mut file = match open_target(target) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(NotDurable::NotOnDisk {
                found: Found::Missing,
            });
        }
        Err(e) => return Err(NotDurable::Sync(e)),
    };
    if !file.metadata().map_err(NotDurable::Sync)?.is_file() {
        return Err(NotDurable::NotOnDisk {
            found: Found::NotAFile,
        });
    }
    // A directory sync makes the name durable, not the data: flush the file
    // too, so a match read from the page cache proves bytes on disk.
    flush(&mut file, target).map_err(NotDurable::Sync)?;
    let found = FileRevision::of_reader(&mut file).map_err(NotDurable::Sync)?;
    if &found == expected {
        return Ok(());
    }
    Err(NotDurable::NotOnDisk {
        found: Found::Bytes(found),
    })
}

/// Open one handle for the flush and the hash, without waiting on a FIFO.
#[cfg(unix)]
fn open_target(target: &Path) -> io::Result<std::fs::File> {
    crate::open_nonblocking::open_nonblocking(target)
}

/// Windows needs write access to flush. Deny write and delete sharing so
/// the file cannot be changed or replaced between the flush and the hash.
#[cfg(not(unix))]
fn open_target(target: &Path) -> io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;

    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ)
        .open(target)
}

/// Flush the same file whose bytes are then hashed.
fn flush(file: &mut std::fs::File, target: &Path) -> io::Result<()> {
    #[cfg(test)]
    if fault::fires(target, |f| matches!(f, Fault::FailFileSync)).is_some() {
        return Err(io::Error::other("injected file-sync failure"));
    }
    #[cfg(not(test))]
    let _ = target;
    file.sync_all()?;
    #[cfg(test)]
    super::crash_fs::note_flushed(target, file)?;
    Ok(())
}

/// Run a row's hook armed for `target` at `at`.
#[cfg(test)]
fn hook(target: &Path, at: HookAt) {
    if let Some(Fault::Hook(_, run)) =
        fault::fires(target, |f| matches!(f, Fault::Hook(a, _) if *a == at))
    {
        run(target);
    }
}

/// The Windows read-back handle denies write and delete sharing: while it is
/// held nothing can change or replace the file; once dropped, both work.
#[cfg(all(test, windows))]
mod windows_share_tests {
    /// A26 (register 1168): red oracle: each blocked operation reports its
    /// exact code, not just any unrelated I/O failure: the write
    /// `ERROR_SHARING_VIOLATION` (32), the rename onto the held file
    /// `ERROR_ACCESS_DENIED` (5).
    #[test]
    fn the_read_back_handle_blocks_writes_and_replacement_while_held() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("gateway.yaml");
        let other = dir.path().join("other.yaml");
        std::fs::write(&target, b"a").expect("seed");
        std::fs::write(&other, b"b").expect("seed");
        let held = super::open_target(&target).expect("open");
        let write_error = std::fs::OpenOptions::new()
            .write(true)
            .open(&target)
            .expect_err("write while held");
        assert_eq!(write_error.raw_os_error(), Some(32), "write while held");
        let rename_error = std::fs::rename(&other, &target).expect_err("replace while held");
        assert_eq!(rename_error.raw_os_error(), Some(5), "replace while held");
        drop(held);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&target)
            .expect("write after drop");
        std::fs::rename(&other, &target).expect("replace after drop");
    }
}
