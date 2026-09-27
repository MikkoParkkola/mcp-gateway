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

/// T1/T2: the store directory and lease are judged on an open handle.
pub(super) fn has_mode(_meta: &fs::Metadata, _expected: u32) -> bool {
    true
}

/// T1: judge the store directory on an open handle (DACL, reparse, locality,
/// final path), the Windows side of the unix `0700` check.
pub(super) fn judge_store_dir(dir: &Path) -> Result<(), StoreError> {
    private_fs::after_path_walk(dir);
    let handle = private_fs::open_dir(dir).map_err(|_| StoreError::UnsafeStore)?;
    private_fs::judge_dir(&handle, dir).map_err(|reason| {
        tracing::warn!(?reason, path = %dir.display(), "task store directory is not private");
        StoreError::UnsafeStore
    })
}

/// T5: create the store directory private from its first instant. Missing
/// ancestors are created plainly; they are outside the model, as on unix.
pub(super) fn create_private_dir(dir: &Path) -> Result<(), StoreError> {
    if let Some(parent) = dir.parent() {
        fs::create_dir_all(parent).map_err(|_| StoreError::Unavailable)?;
    }
    private_fs::create_dir_private(dir).map_err(|error| {
        tracing::warn!(%error, path = %dir.display(), "task store directory not created");
        StoreError::Unavailable
    })
}

/// T4: a scratch record, private from creation, no sharing.
pub(super) fn open_new_private(path: &Path) -> io::Result<fs::File> {
    private_fs::create_file_private(path, Share::Exclusive)
}

/// T3: open without following a reparse point, then judge the handle.
pub(super) fn open_record(path: &Path) -> Result<fs::File, StoreError> {
    let file = private_fs::open_file_read(path).map_err(|error| {
        tracing::warn!(%error, path = %path.display(), "task record could not be opened");
        StoreError::UnsafeStore
    })?;
    private_fs::judge_file(&file).map_err(|reason| {
        tracing::warn!(?reason, path = %path.display(), "task record is not private");
        StoreError::UnsafeStore
    })?;
    Ok(file)
}
