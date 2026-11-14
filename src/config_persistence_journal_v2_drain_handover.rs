// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Hand a journal's frozen records over to the framed abandoned file: preflight proves the file
//! acceptable, then the flag, the frames, the syncs and the journal's removal follow in order.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use super::super::JournalSession;
use super::super::abandoned::{Placement, against_donor, frames_of, marked};
use super::super::abandoned::{TornProof, encode_frame};
use super::DrainSession;
use super::fault::{self, At};
use crate::config_persistence::sync_dir_of;
use crate::security::transparency_log::rotation::file_id;

/// Why a handover did not complete. The donor is byte-identical after `Foreign`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HandoverError {
    Journal,
    Write,
    Sync,
    Finish,
    Foreign,
}

/// `<config>.abandoned`, beside the resolved config, in the journal's own directory.
pub(crate) fn abandoned_path(target: &Path) -> PathBuf {
    let mut name = std::ffi::OsString::from(target.file_name().unwrap_or_default());
    name.push(".abandoned");
    target.with_file_name(name)
}

/// Open an existing abandoned file for the whole call: no symlink follow, no waiting on a
/// FIFO, then the opened handle must be a private regular file of this user with one link.
/// `Ok(None)` when there is no file.
fn open_existing(path: &Path, bound: usize) -> Result<Option<(File, Vec<u8>)>, HandoverError> {
    let file = match open_guarded(path, false) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(HandoverError::Foreign),
    };
    if checked(&file)?.len() > bound as u64 {
        return Err(HandoverError::Foreign);
    }
    let mut bytes = Vec::new();
    (&file)
        .take(bound as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| HandoverError::Foreign)?;
    Ok(Some((file, bytes)))
}

/// The check every read of the file is behind: the OPENED handle is a regular file that is
/// private to this user and has one link.
fn checked(file: &File) -> Result<std::fs::Metadata, HandoverError> {
    let meta = file.metadata().map_err(|_| HandoverError::Foreign)?;
    if meta.is_file() && private_to_us(&meta) {
        Ok(meta)
    } else {
        Err(HandoverError::Foreign)
    }
}

#[cfg(unix)]
fn open_guarded(path: &Path, create: bool) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let flags =
        rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::NOCTTY;
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .write(true)
        .custom_flags(flags.bits().cast_signed());
    if create {
        options.create_new(true).mode(0o600);
    }
    options.open(path)
}

#[cfg(not(unix))]
fn open_guarded(path: &Path, create: bool) -> std::io::Result<File> {
    // ponytail: no reparse-point or owner checks off Unix yet; they come with the startup caller.
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true);
    if create {
        options.create_new(true);
    }
    options.open(path)
}

#[cfg(unix)]
fn private_to_us(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    meta.uid() == rustix::process::getuid().as_raw()
        && meta.nlink() == 1
        // No group or other permission bit: the low six bits are all zero.
        && meta.mode().trailing_zeros() >= 6
}

/// Fails closed off Unix: no owner check exists there yet, so no file counts as private to this
/// user. The Windows owner check through `win_acl` is a tracked precondition of the startup
/// caller; until then a handover refuses on those platforms.
#[cfg(not(unix))]
fn private_to_us(_meta: &std::fs::Metadata) -> bool {
    false
}

pub(crate) fn hand_over(session: &mut DrainSession) -> Result<(), HandoverError> {
    // Refuse before anything is written: off Unix the file cannot be proven private to this user.
    if !cfg!(unix) {
        return Err(HandoverError::Foreign);
    }
    let journal = session.journal.as_mut().ok_or(HandoverError::Journal)?;
    let donor = marked(&journal.state);
    donor.binding.as_ref().ok_or(HandoverError::Foreign)?;
    donor.finish_ready().map_err(|_| HandoverError::Journal)?;
    let frames: Vec<Vec<u8>> = frames_of(&donor)
        .ok_or(HandoverError::Foreign)?
        .iter()
        .map(encode_frame)
        .collect::<Result<_, _>>()
        .map_err(|_| HandoverError::Journal)?;
    let total: usize = frames.iter().map(Vec::len).sum();
    let path = abandoned_path(&journal.target);
    let existing = open_existing(&path, total)?;
    let bytes = existing.as_ref().map_or(&[][..], |(_, bytes)| bytes);
    let placement = against_donor(bytes, &donor);
    if placement == Placement::Foreign {
        return Err(HandoverError::Foreign);
    }
    let target = journal.target.clone();
    commit(
        journal,
        donor,
        &path,
        existing.map(|(file, _)| file),
        placement,
        &frames,
    )?;
    super::finish(session).map_err(|_| HandoverError::Finish)?;
    seam(&target, At::HandoverFinished)
}

/// A crash-test boundary: only a fired fault does anything, and only in a test build.
fn seam(target: &Path, at: At) -> Result<(), HandoverError> {
    fault::hit(target, at).map_err(|_| HandoverError::Journal)
}

/// The first writes: flag the donor, write what the file lacks, sync the file and then its
/// directory, and check the sealed file is the one at the path.
fn commit(
    journal: &mut JournalSession,
    donor: super::super::JournalV2,
    path: &Path,
    file: Option<File>,
    placement: Placement,
    frames: &[Vec<u8>],
) -> Result<(), HandoverError> {
    // Never append donor frames onto bytes the donor does not prove, whoever the caller is.
    if placement == Placement::Foreign {
        return Err(HandoverError::Foreign);
    }
    journal.state = donor;
    journal.persist().map_err(|_| HandoverError::Journal)?;
    seam(&journal.target, At::HandoverFlagged)?;
    let mut file = match file {
        Some(file) => file,
        None => open_guarded(path, true).map_err(|_| HandoverError::Write)?,
    };
    // A file this call created passes by construction; the same check runs on every path so no
    // read, including the seal's, is ever behind a handle that was not checked.
    checked(&file).map_err(|_| HandoverError::Write)?;
    let from = match placement {
        Placement::Whole => frames.len(),
        Placement::Torn { complete, proof } => {
            truncate_to(&file, &proof)?;
            complete
        }
        Placement::Missing { complete } => complete,
        Placement::Absent => 0,
        // Refused above; if that guard is ever removed this fails loudly instead of appending.
        Placement::Foreign => return Err(HandoverError::Foreign),
    };
    file.seek(SeekFrom::End(0))
        .map_err(|_| HandoverError::Write)?;
    for frame in &frames[from..] {
        file.write_all(frame).map_err(|_| HandoverError::Write)?;
    }
    seam(&journal.target, At::AbandonFileAppended)?;
    file.sync_all().map_err(|_| HandoverError::Sync)?;
    crate::config_persistence::crash_fs::note_flushed(&journal.target, &mut file)
        .map_err(|_| HandoverError::Sync)?;
    seam(&journal.target, At::AbandonFileDataSynced)?;
    sync_dir_of(path).map_err(|_| HandoverError::Sync)?;
    seam(&journal.target, At::AbandonFileSynced)?;
    seal(&mut file, path, frames)
}

/// The only shortening of the file: to the start of a torn frame a donor-backed placement proved.
fn truncate_to(file: &File, proof: &TornProof) -> Result<(), HandoverError> {
    file.set_len(proof.start() as u64)
        .map_err(|_| HandoverError::Write)
}

/// Re-read the file through the same handle: it must now be exactly the donor's frames, and
/// the path must still name that file.
fn seal(file: &mut File, path: &Path, frames: &[Vec<u8>]) -> Result<(), HandoverError> {
    let want: Vec<u8> = frames.concat();
    file.seek(SeekFrom::Start(0))
        .map_err(|_| HandoverError::Write)?;
    let mut have = Vec::new();
    file.read_to_end(&mut have)
        .map_err(|_| HandoverError::Write)?;
    if have != want {
        return Err(HandoverError::Write);
    }
    // Identity only, never read; a replaced path must not make the open wait.
    let at_path =
        crate::open_nonblocking::open_nonblocking(path).map_err(|_| HandoverError::Write)?;
    match (file_id(file), file_id(&at_path)) {
        (Ok(ours), Ok(theirs)) if ours == theirs => Ok(()),
        _ => Err(HandoverError::Write),
    }
}

// The success-path rows need a file that passes the owner check, which only exists on Unix.
#[cfg(all(test, unix))]
#[path = "config_persistence_journal_v2_drain_handover_crash_tests.rs"]
mod crash_tests;
#[cfg(all(test, unix))]
#[path = "config_persistence_journal_v2_drain_handover_tests.rs"]
mod tests;
#[cfg(all(test, not(unix)))]
#[path = "config_persistence_journal_v2_drain_handover_windows_tests.rs"]
mod windows_tests;
