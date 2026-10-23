// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Open a file without waiting on it, for the mode-checked readers.

use std::path::Path;

/// Opens `path` for reading without waiting on it: on Unix with
/// `O_NONBLOCK | O_NOCTTY`, following a symlink, so a FIFO is refused
/// downstream as not a regular file rather than blocking for a writer.
#[cfg(unix)]
pub(crate) fn open_nonblocking(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(
            (rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::NOCTTY)
                .bits()
                .cast_signed(),
        )
        .open(path)
}

#[cfg(not(unix))]
pub(crate) fn open_nonblocking(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}
