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
//! This first commit deliberately supplies only stubs, not that model.
#![cfg(test)]

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io;
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

// Only membership matters in this stub. No snapshot is captured.
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

pub(crate) fn arm(dir: &Path) -> Armed {
    ARMED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get_or_insert_with(HashMap::new)
        .insert(dir.to_path_buf(), Overlay::default());
    Armed(dir.to_path_buf())
}

pub(crate) fn cut(dir: &Path, _mode: Mode) {
    let armed = ARMED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(
        armed.as_ref().is_some_and(|dirs| dirs.contains_key(dir)),
        "crash_fs: directory not armed: {}",
        dir.display()
    );
}

pub(crate) fn project(
    _durable: &Overlay,
    observed: &BTreeMap<String, Vec<u8>>,
    _mode: Mode,
) -> BTreeMap<String, Vec<u8>> {
    observed.clone()
}

pub(super) fn note_dir_synced(_dir: &Path) {}

pub(super) fn note_data_durable(_target: &Path, _file: &File) {}

/// Trust boundary: the eventual notification must follow the real sync_all
/// in flush; it cannot prove that sync happened if that call is removed.
/// The eventual read uses this handle and rewinds before and after reading.
pub(super) fn note_flushed(_target: &Path, _file: &mut File) -> io::Result<()> {
    Ok(())
}
