// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The Windows side of the task store's custody rules (design §2.3, T1-T7).
//! Same names and signatures as the unix helpers in `store.rs`, so the store
//! body is shared; every privacy decision is `crate::private_fs`'s.

use std::fs;
use std::io;
use std::path::Path;

use super::StoreError;
use crate::private_fs::{self, Share};

pub(super) use crate::private_fs::{replace as rename, sync_dir, sync_file};

/// A directory's identity. The store's directory is pinned open without delete
/// sharing for its whole custody, so it cannot be renamed or swapped: present
/// is enough.
pub(super) type DirId = ();

/// `Some` when a directory is at `dir`.
pub(super) fn dir_identity(dir: &Path) -> Option<DirId> {
    fs::symlink_metadata(dir)
        .ok()
        .filter(fs::Metadata::is_dir)
        .map(|_| ())
}

/// T1/T2: the store directory and lease are judged on an open handle.
pub(super) fn has_mode(_meta: &fs::Metadata, _expected: u32) -> bool {
    true
}

/// T1: judge the store directory on an open handle (DACL, reparse, locality,
/// final path), the Windows side of the unix `0700` check.
/// Returns the judged handle, which the caller holds for the custody lifetime.
pub(super) fn judge_store_dir(dir: &Path) -> Result<crate::fs_lock::DirPin, StoreError> {
    private_fs::after_path_walk(dir);
    let handle = private_fs::open_dir(dir).map_err(|_| StoreError::UnsafeStore)?;
    private_fs::judge_dir(&handle, dir).map_err(|reason| {
        let shown_path = dir.display();
        tracing::warn!(?reason, path = %shown_path, "task store directory is not private");
        StoreError::UnsafeStore
    })?;
    Ok(crate::fs_lock::DirPin(handle))
}

/// T5: create the store directory, and each missing ancestor, private from its
/// first instant, as unix creates them all `0700`.
pub(super) fn create_private_dir(dir: &Path) -> Result<(), StoreError> {
    // A relative path's last ancestor is the empty path: never created.
    let missing: Vec<&Path> = dir
        .ancestors()
        .take_while(|p| !p.as_os_str().is_empty() && !p.exists())
        .collect();
    for path in missing.into_iter().rev() {
        match private_fs::create_dir_private(path) {
            Err(error) if error.kind() != io::ErrorKind::AlreadyExists => {
                tracing::warn!(%error, path = %path.display(), "task store directory not created");
                return Err(StoreError::Unavailable);
            }
            _ => {}
        }
    }
    Ok(())
}

/// T4: a scratch record, private from creation, no sharing.
pub(super) fn open_new_private(path: &Path) -> io::Result<fs::File> {
    private_fs::create_file_private(path, Share::Exclusive)
}

/// T3: open without following a reparse point, then judge the handle.
pub(super) fn open_record(path: &Path) -> Result<fs::File, StoreError> {
    let file = private_fs::open_file_read(path).map_err(|error| {
        let shown_path = path.display();
        tracing::warn!(%error, path = %shown_path, "task record could not be opened");
        StoreError::UnsafeStore
    })?;
    private_fs::judge_file(&file).map_err(|reason| {
        let shown_path = path.display();
        tracing::warn!(?reason, path = %shown_path, "task record is not private");
        StoreError::UnsafeStore
    })?;
    Ok(file)
}

#[cfg(test)]
#[path = "store_windows_tests.rs"]
mod tests;
