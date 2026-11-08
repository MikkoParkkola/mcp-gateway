// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test-only power-loss overlay for one armed config directory. For a
//! symlinked target, arm the target's own directory. DropAll restores the
//! last synced namespace and durable generation data; KeepAll keeps the
//! observed directory; KeepRenameDropData keeps observed names and synced
//! data, but tears unsynced tails at seed % unsynced_len.
//!
//! Only file names and bytes are modelled, not mode or mtime durability.
//! A file never data-synced or snapshotted is absent under DropAll. Arming
//! treats existing bytes as durable. A new, unhooked file at a directory
//! snapshot is assumed data-synced, as the crate's other writers are.
//!
//! Generations use handle identity: (dev, ino) on Unix and
//! win_acl::file_identity (volume serial, 128-bit file id) on Windows.
//! The model keeps an open File for each generation until disarming to
//! prevent identity reuse after unlink. Those handles allow delete sharing
//! on Windows and must not block replacement. A flush updates the handle's
//! generation, even if the path has since been replaced. Reading flushed
//! bytes rewinds, reads sequentially, then rewinds again for the hash.
//!
//! Trust boundary: durability comes from notifications. An in-process test
//! cannot detect removal of sync_all if its notification remains. The real
//! flush notification belongs immediately after successful sync_all; the
//! atomic-write notification follows successful scratch sync and rename.
#![cfg(test)]

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{self, Read, Seek};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::security::transparency_log::rotation::{FileId, file_id, path_id};

#[derive(Clone, Copy, Debug)]
pub(crate) enum Mode {
    DropAll,
    KeepAll,
    KeepRenameDropData { seed: u64 },
}

/// Durable state; rows can construct independent projection inputs.
#[derive(Default)]
pub(crate) struct Overlay {
    /// Name -> generation as of the last directory sync (what DropAll keeps).
    pub(crate) names: BTreeMap<String, FileId>,
    /// Name -> generation now: a rename binds a new generation here at once,
    /// before any directory sync makes it durable (what the keep modes see).
    pub(crate) current: BTreeMap<String, FileId>,
    pub(crate) data: BTreeMap<FileId, Vec<u8>>,
    pub(crate) held: BTreeMap<FileId, File>,
}

static ARMED: Mutex<Option<HashMap<PathBuf, Overlay>>> = Mutex::new(None);

pub(crate) struct Armed(PathBuf);

impl Drop for Armed {
    fn drop(&mut self) {
        let mut armed = ARMED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(dirs) = armed.as_mut() {
            dirs.remove(&key(&self.0));
        }
    }
}

fn key(dir: &Path) -> PathBuf {
    std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf())
}

fn read_bytes(mut file: &File) -> io::Result<Vec<u8>> {
    file.rewind()?;
    let mut bytes = Vec::new();
    let read = file.read_to_end(&mut bytes);
    file.rewind()?;
    read?;
    Ok(bytes)
}

pub(crate) fn arm(dir: &Path) -> Armed {
    let dir = key(dir);
    let mut overlay = Overlay::default();
    for entry in std::fs::read_dir(&dir).expect("crash_fs: read directory") {
        let entry = entry.expect("crash_fs: read entry");
        if !entry.file_type().expect("crash_fs: file type").is_file() {
            continue;
        }
        let name = entry
            .file_name()
            .into_string()
            .expect("crash_fs: UTF-8 name");
        let file = File::open(entry.path()).expect("crash_fs: open file");
        let generation = file_id(&file).expect("crash_fs: file identity");
        let bytes = read_bytes(&file).expect("crash_fs: read file");
        overlay.names.insert(name.clone(), generation);
        overlay.current.insert(name.clone(), generation);
        overlay.data.insert(generation, bytes);
        overlay.held.insert(generation, file);
    }
    ARMED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get_or_insert_with(HashMap::new)
        .insert(dir.clone(), overlay);
    Armed(dir)
}

pub(crate) fn cut(dir: &Path, mode: Mode) {
    let dir = key(dir);
    let mut armed = ARMED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let durable = armed.as_mut().and_then(|dirs| dirs.get_mut(&dir));
    let durable = durable.unwrap_or_else(|| {
        panic!("crash_fs: directory not armed: {}", dir.display());
    });
    let mut observed = BTreeMap::new();
    for entry in std::fs::read_dir(&dir).expect("crash_fs: read directory") {
        let entry = entry.expect("crash_fs: read entry");
        if entry.file_type().expect("crash_fs: file type").is_file() {
            let name = entry
                .file_name()
                .into_string()
                .expect("crash_fs: UTF-8 name");
            let file = File::open(entry.path()).expect("crash_fs: open file");
            let generation = file_id(&file).expect("crash_fs: file identity");
            let bytes = read_bytes(&file).expect("crash_fs: read file");
            durable.current.insert(name.clone(), generation);
            observed.insert(name, bytes);
        }
    }
    let want = project(durable, &observed, mode);
    for name in observed.keys() {
        if !want.contains_key(name) {
            std::fs::remove_file(dir.join(name)).expect("crash_fs: remove file");
        }
    }
    for (name, bytes) in want {
        if observed.get(&name) != Some(&bytes) {
            std::fs::write(dir.join(name), bytes).expect("crash_fs: restore file");
        }
    }
}

pub(crate) fn project(
    durable: &Overlay,
    observed: &BTreeMap<String, Vec<u8>>,
    mode: Mode,
) -> BTreeMap<String, Vec<u8>> {
    match mode {
        Mode::DropAll => durable
            .names
            .iter()
            .map(|(name, generation)| (name.clone(), durable.data[generation].clone()))
            .collect(),
        Mode::KeepAll => observed.clone(),
        Mode::KeepRenameDropData { seed } => observed
            .iter()
            .map(|(name, obs)| {
                let data = durable.current.get(name).and_then(|g| durable.data.get(g));
                let bytes = match data {
                    Some(data) if data == obs => obs.clone(),
                    Some(data) if obs.starts_with(data) && data.len() < obs.len() => {
                        let tail = (seed % (obs.len() - data.len()) as u64) as usize;
                        obs[..data.len() + tail].to_vec()
                    }
                    Some(data) => data.clone(),
                    None => obs[..(seed % obs.len().max(1) as u64) as usize].to_vec(),
                };
                (name.clone(), bytes)
            })
            .collect(),
    }
}

pub(super) fn note_dir_synced(dir: &Path) {
    let dir = key(dir);
    let mut armed = ARMED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(overlay) = armed.as_mut().and_then(|dirs| dirs.get_mut(&dir)) else {
        return;
    };
    let mut names = BTreeMap::new();
    for entry in std::fs::read_dir(&dir).expect("crash_fs: read directory") {
        let entry = entry.expect("crash_fs: read entry");
        if !entry.file_type().expect("crash_fs: file type").is_file() {
            continue;
        }
        let name = entry
            .file_name()
            .into_string()
            .expect("crash_fs: UTF-8 name");
        let file = File::open(entry.path()).expect("crash_fs: open file");
        let generation = file_id(&file).expect("crash_fs: file identity");
        if let std::collections::btree_map::Entry::Vacant(entry) = overlay.data.entry(generation) {
            entry.insert(read_bytes(&file).expect("crash_fs: read file"));
            overlay.held.insert(generation, file);
        }
        names.insert(name, generation);
    }
    overlay.current = names.clone();
    overlay.names = names;
}

pub(super) struct Staged {
    generation: FileId,
    bytes: Vec<u8>,
    // The synced scratch, held from staging on (default sharing, so the
    // rename still works) so its identity cannot be reused before bind.
    held: File,
}

/// The synced scratch's identity, taken by path (nothing else touches the
/// scratch), and the exact bytes write_atomic wrote and synced into it.
pub(super) fn stage(target: &Path, scratch: &Path, bytes: &[u8]) -> Option<Staged> {
    let dir = key(target.parent()?);
    let mut armed = ARMED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let overlay = armed.as_mut()?.get_mut(&dir)?;
    let held = File::open(scratch).expect("crash_fs: hold scratch");
    let generation = file_id(&held).expect("crash_fs: scratch identity");
    // The scratch's bytes were synced before this call: durable now, under
    // its own generation, whatever happens to its name later.
    overlay.data.insert(generation, bytes.to_vec());
    Some(Staged {
        generation,
        bytes: bytes.to_vec(),
        held,
    })
}

pub(super) fn bind(target: &Path, staged: Staged) {
    let mut armed = ARMED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(overlay) = target
        .parent()
        .map(key)
        .and_then(|dir| armed.as_mut().and_then(|dirs| dirs.get_mut(&dir)))
    else {
        return;
    };
    overlay.held.insert(staged.generation, staged.held);
    // Bind the name only if the file now at the target is the staged one.
    let Ok(now) = File::open(target).and_then(|f| file_id(&f)) else {
        return;
    };
    if now != staged.generation {
        return;
    }
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .expect("crash_fs: UTF-8 name");
    overlay.data.insert(now, staged.bytes);
    overlay.current.insert(name.to_owned(), now);
}

/// Trust boundary: this notification follows the real sync_all in flush;
/// it cannot prove that sync happened if that call is removed.
/// Read this handle and rewind before and after reading.
pub(super) fn note_flushed(target: &Path, file: &mut File) -> io::Result<()> {
    let mut armed = ARMED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(overlay) = target
        .parent()
        .map(key)
        .and_then(|dir| armed.as_mut().and_then(|dirs| dirs.get_mut(&dir)))
    else {
        return Ok(());
    };
    let generation = file_id(file)?;
    // Hold the generation before recording it. Unix: a clone of the flushed
    // handle. Windows: the read-back handle denies delete sharing (holding a
    // clone would block later renames), and it also stops the file being
    // replaced while held, so a fresh default-sharing handle is this file.
    #[cfg(unix)]
    let held = file.try_clone()?;
    #[cfg(not(unix))]
    let held = {
        let fresh = File::open(target)?;
        if file_id(&fresh)? != generation {
            return Err(io::Error::other("crash_fs: flushed file was replaced"));
        }
        fresh
    };
    let bytes = read_bytes(file)?;
    overlay.held.insert(generation, held);
    overlay.data.insert(generation, bytes);
    Ok(())
}
