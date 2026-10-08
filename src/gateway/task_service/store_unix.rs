// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The unix side of the task store's custody rules: mode checks and durable file
//! operations. Same names and signatures as the Windows helpers in
//! `store_windows.rs`, so the store body is shared.

use std::fs;
use std::io;
use std::path::Path;

use super::{RECORD_MODE, STORE_MODE, StoreError};
use crate::fs_lock::DirPin;

pub(super) use std::fs::rename;

/// A directory's identity: its device and inode.
pub(super) type DirId = (u64, u64);

/// The identity of the directory at `dir`, or `None` when nothing is there.
pub(super) fn dir_identity(dir: &Path) -> Option<DirId> {
    use std::os::unix::fs::MetadataExt as _;
    fs::symlink_metadata(dir)
        .ok()
        .filter(fs::Metadata::is_dir)
        .map(|meta| (meta.dev(), meta.ino()))
}

/// Open a record without following a symlink, so the thing judged and the thing
/// read are the same file. Non-blocking, so a FIFO wearing a record's name is
/// judged and refused instead of waiting for a writer (`MIK-8052.AC4`); the flag
/// has no effect on reading a regular file.
#[cfg(unix)]
pub(super) fn open_record(path: &Path) -> Result<fs::File, StoreError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let shown_path = path.display();
    let flags = rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags.bits().cast_signed())
        .open(path)
        .map_err(|error| {
            tracing::warn!(%error, path = %shown_path, "task record could not be opened as a private regular file");
            StoreError::UnsafeStore
        })
}

#[cfg(unix)]
#[expect(
    clippy::unnecessary_wraps,
    reason = "unix judges by mode; nothing to hold"
)]
pub(super) fn judge_store_dir(_dir: &Path) -> Result<DirPin, StoreError> {
    Ok(DirPin())
}

#[cfg(unix)]
pub(super) fn has_mode(meta: &fs::Metadata, expected: u32) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    meta.mode() & 0o7777 == expected
}

#[cfg(unix)]
pub(super) fn create_private_dir(dir: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    fs::DirBuilder::new()
        .recursive(true)
        .mode(STORE_MODE)
        .create(dir)
        .and_then(|()| fs::set_permissions(dir, fs::Permissions::from_mode(STORE_MODE)))
        .map_err(|error| {
            tracing::warn!(%error, path = %dir.display(), "task store directory not created");
            StoreError::Unavailable
        })
}

/// A scratch record: `mode` is masked by the process umask, so the record is
/// forced private regardless of how the surrounding process was configured.
#[cfg(unix)]
pub(super) fn open_new_private(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(RECORD_MODE)
        .open(path)?;
    force_owner_only(&file)?;
    Ok(file)
}

#[cfg(unix)]
pub(super) fn sync_file(file: &fs::File) -> io::Result<()> {
    file.sync_all()
}

#[cfg(unix)]
pub(super) fn force_owner_only(file: &fs::File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    file.set_permissions(fs::Permissions::from_mode(RECORD_MODE))
}

/// Make the rename itself durable. Opening a directory as a file is not portable,
/// and the durability target for this store is Linux and macOS.
#[cfg(unix)]
pub(super) fn sync_dir(dir: &Path) -> io::Result<()> {
    fs::File::open(dir)?.sync_all()
}
