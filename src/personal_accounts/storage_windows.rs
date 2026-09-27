// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The Windows side of the personal-account store's custody rules (design
//! §2.3, R1-R6). Same names and signatures as the unix helpers in
//! `storage.rs`; every privacy decision is `crate::private_fs`'s.

use std::fs::{self, File, Metadata};
use std::io;
use std::path::Path;

use super::AccountError;
use crate::private_fs;

pub(super) use crate::private_fs::prefix_allowed;

/// R1: a store directory is judged on an open handle to it.
/// Returns the judged handle; `open`/`initialize` hold it for the custody
/// lifetime (design §2.2).
pub(super) fn private_directory(path: &Path) -> Result<crate::fs_lock::DirPin, AccountError> {
    private_fs::after_path_walk(path);
    let dir = private_fs::open_dir(path).map_err(|_| AccountError::StorageUnavailable)?;
    let metadata = dir
        .metadata()
        .map_err(|_| AccountError::StorageUnavailable)?;
    if !metadata.is_dir() {
        return Err(AccountError::InvalidConfiguration);
    }
    private_fs::judge_dir(&dir, path).map_err(|reason| {
        tracing::warn!(?reason, path = %path.display(), "account store directory is not private");
        AccountError::InvalidConfiguration
    })?;
    Ok(crate::fs_lock::DirPin(dir))
}

/// R2: create each missing component private from its first instant, as the
/// unix body creates each with `0700`.
pub(super) fn create_directory(path: &Path) -> Result<(), AccountError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => return Ok(()),
        Ok(_) => return Err(AccountError::InvalidConfiguration),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(AccountError::StorageUnavailable),
    }
    let parent = path.parent().ok_or(AccountError::InvalidConfiguration)?;
    create_directory(parent)?;
    if let Err(error) = private_fs::create_dir_private(path)
        && error.kind() != io::ErrorKind::AlreadyExists
    {
        return Err(AccountError::StorageUnavailable);
    }
    drop(private_directory(path)?);
    sync_directory(parent)
}

/// R7: flush a directory after a rename inside it (probe E1).
pub(super) fn sync_directory(path: &Path) -> Result<(), AccountError> {
    private_fs::sync_dir(path).map_err(|_| AccountError::StorageUnavailable)
}

/// R5/R6: open without following a reparse point.
pub(super) fn open_nofollow(path: &Path) -> io::Result<File> {
    private_fs::open_file_read(path).inspect(|f| {
        if let Ok(c) = f.try_clone() {
            std::mem::forget(c);
        }
    })
}

/// R5/R6: not a regular file, or not private by its DACL, judged on the open
/// handle.
pub(super) fn not_private(file: &File, metadata: &Metadata) -> bool {
    !metadata.is_file() || private_fs::judge_file(file).is_err()
}

// W-T7 (lexical): the path rule alone, with no filesystem behind it, so a
// later layer (locality, the no-follow re-walk) cannot stand in for it.
#[cfg(test)]
#[path = "storage_windows_tests.rs"]
mod tests;
