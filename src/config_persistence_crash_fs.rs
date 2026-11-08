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

#[derive(Clone, Copy, Debug)]
pub(crate) enum Mode {
    DropAll,
    KeepAll,
    KeepRenameDropData { seed: u64 },
}

/// Identity components, with room for the Windows 128-bit file id.
pub(crate) type Generation = (u64, u128);

/// Durable state; rows can construct independent projection inputs.
#[derive(Default)]
pub(crate) struct Overlay {
    /// Name -> generation as of the last directory sync (what DropAll keeps).
    pub(crate) names: BTreeMap<String, Generation>,
    /// Name -> generation now: a rename binds a new generation here at once,
    /// before any directory sync makes it durable (what the keep modes see).
    pub(crate) current: BTreeMap<String, Generation>,
    pub(crate) data: BTreeMap<Generation, Vec<u8>>,
    // Immutable after arming; never reconstructed from later durable data.
    pub(crate) arming: BTreeMap<String, Vec<u8>>,
    pub(crate) held: BTreeMap<Generation, File>,
}

static ARMED: Mutex<Option<HashMap<PathBuf, Overlay>>> = Mutex::new(None);

pub(crate) struct Armed(PathBuf);

impl Drop for Armed {
    fn drop(&mut self) {
        let mut armed = ARMED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(dirs) = armed.as_mut() {
            dirs.remove(&self.0);
        }
    }
}

fn identity(file: &File) -> io::Result<Generation> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        Ok((metadata.dev(), u128::from(metadata.ino())))
    }
    #[cfg(windows)]
    {
        crate::win_acl::file_identity(file)
    }
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
    let mut overlay = Overlay::default();
    for entry in std::fs::read_dir(dir).expect("crash_fs: read directory") {
        let entry = entry.expect("crash_fs: read entry");
        if !entry.file_type().expect("crash_fs: file type").is_file() {
            continue;
        }
        let name = entry
            .file_name()
            .into_string()
            .expect("crash_fs: UTF-8 name");
        let file = File::open(entry.path()).expect("crash_fs: open file");
        let generation = identity(&file).expect("crash_fs: file identity");
        let bytes = read_bytes(&file).expect("crash_fs: read file");
        overlay.names.insert(name.clone(), generation);
        overlay.current.insert(name.clone(), generation);
        overlay.arming.insert(name, bytes.clone());
        overlay.data.insert(generation, bytes);
        overlay.held.insert(generation, file);
    }
    ARMED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get_or_insert_with(HashMap::new)
        .insert(dir.to_path_buf(), overlay);
    Armed(dir.to_path_buf())
}

pub(crate) fn cut(dir: &Path, mode: Mode) {
    let armed = ARMED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let durable = armed.as_ref().and_then(|dirs| dirs.get(dir));
    let durable = durable.unwrap_or_else(|| {
        panic!("crash_fs: directory not armed: {}", dir.display());
    });
    let mut observed = BTreeMap::new();
    for entry in std::fs::read_dir(dir).expect("crash_fs: read directory") {
        let entry = entry.expect("crash_fs: read entry");
        if entry.file_type().expect("crash_fs: file type").is_file() {
            let name = entry
                .file_name()
                .into_string()
                .expect("crash_fs: UTF-8 name");
            observed.insert(
                name,
                std::fs::read(entry.path()).expect("crash_fs: read file"),
            );
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
    let mut armed = ARMED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(overlay) = armed.as_mut().and_then(|dirs| dirs.get_mut(dir)) else {
        return;
    };
    let mut names = BTreeMap::new();
    for entry in std::fs::read_dir(dir).expect("crash_fs: read directory") {
        let entry = entry.expect("crash_fs: read entry");
        if !entry.file_type().expect("crash_fs: file type").is_file() {
            continue;
        }
        let name = entry
            .file_name()
            .into_string()
            .expect("crash_fs: UTF-8 name");
        let file = File::open(entry.path()).expect("crash_fs: open file");
        let generation = identity(&file).expect("crash_fs: file identity");
        if let std::collections::btree_map::Entry::Vacant(entry) = overlay.data.entry(generation) {
            entry.insert(read_bytes(&file).expect("crash_fs: read file"));
            overlay.held.insert(generation, file);
        }
        names.insert(name, generation);
    }
    overlay.current = names.clone();
    overlay.names = names;
}

pub(super) fn note_data_durable(target: &Path, file: &File) {
    let mut armed = ARMED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(overlay) = target
        .parent()
        .and_then(|dir| armed.as_mut().and_then(|dirs| dirs.get_mut(dir)))
    else {
        return;
    };
    let generation = identity(file).expect("crash_fs: file identity");
    let bytes = read_bytes(file).expect("crash_fs: read durable file");
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .expect("crash_fs: UTF-8 name");
    overlay.data.insert(generation, bytes);
    overlay.current.insert(name.to_owned(), generation);
    overlay
        .held
        .insert(generation, file.try_clone().expect("crash_fs: hold file"));
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
        .and_then(|dir| armed.as_mut().and_then(|dirs| dirs.get_mut(dir)))
    else {
        return Ok(());
    };
    let generation = identity(file)?;
    let bytes = read_bytes(file)?;
    overlay.data.insert(generation, bytes);
    Ok(())
}
