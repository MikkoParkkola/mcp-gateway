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
    let meta = file.metadata().map_err(|_| HandoverError::Foreign)?;
    if !meta.is_file() || !private_to_us(&meta) || meta.len() > bound as u64 {
        return Err(HandoverError::Foreign);
    }
    let mut bytes = Vec::new();
    (&file)
        .take(bound as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| HandoverError::Foreign)?;
    Ok(Some((file, bytes)))
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
        && meta.mode() & 0o077 == 0
}

#[cfg(not(unix))]
fn private_to_us(_meta: &std::fs::Metadata) -> bool {
    true
}

pub(crate) fn hand_over(session: &mut DrainSession) -> Result<(), HandoverError> {
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
    commit(
        journal,
        donor,
        &path,
        existing.map(|(file, _)| file),
        placement,
        &frames,
    )?;
    super::finish(session).map_err(|_| HandoverError::Finish)
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
    journal.state = donor;
    journal.persist().map_err(|_| HandoverError::Journal)?;
    let mut file = match file {
        Some(file) => file,
        None => open_guarded(path, true).map_err(|_| HandoverError::Write)?,
    };
    let from = match placement {
        Placement::Whole => frames.len(),
        Placement::Torn {
            complete, proof, ..
        } => {
            truncate_to(&file, &proof)?;
            complete
        }
        Placement::Missing { complete } => complete,
        Placement::Absent | Placement::Foreign => 0,
    };
    file.seek(SeekFrom::End(0))
        .map_err(|_| HandoverError::Write)?;
    for frame in &frames[from..] {
        file.write_all(frame).map_err(|_| HandoverError::Write)?;
    }
    file.sync_all().map_err(|_| HandoverError::Sync)?;
    crate::config_persistence::crash_fs::note_flushed(&journal.target, &mut file)
        .map_err(|_| HandoverError::Sync)?;
    sync_dir_of(path).map_err(|_| HandoverError::Sync)?;
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
    let at_path = File::open(path).map_err(|_| HandoverError::Write)?;
    match (file_id(file), file_id(&at_path)) {
        (Ok(ours), Ok(theirs)) if ours == theirs => Ok(()),
        _ => Err(HandoverError::Write),
    }
}

#[cfg(test)]
#[path = "config_persistence_journal_v2_drain_handover_tests.rs"]
mod tests;
