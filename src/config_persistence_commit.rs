// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Primitive A: replace the config with bytes and prove they are durable, or
//! prove what is on disk without writing. A [`CommitToken`] exists only after
//! the directory sync succeeded and a read-back of the target matched, in that
//! order; nothing else builds one.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "the config writer, a later step, calls A")
)]

use std::io;
use std::path::Path;

use super::lock::Locked;
use crate::config_reload::FileRevision;

/// Proof that the target holds `revision`'s bytes durably: the directory was
/// synced after the rename, then the bytes read back matched.
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
    let _ = (locked, configured, action, bytes);
    Err(NotDurable::Write(io::Error::other("not built yet")))
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
    let _ = (locked, configured, expected);
    Err(NotDurable::Write(io::Error::other("not built yet")))
}
