// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Read a config file the way the gateway's own reader opens it, for the
//! commands that read it a second time (`doctor`, `upgrade`).

use std::io::Read as _;
use std::path::Path;

/// The text of the regular file at `path`.
///
/// Opens on Unix with `O_NONBLOCK | O_NOCTTY`, following a symlink (a
/// Kubernetes `ConfigMap` mount is one), and refuses anything the opened
/// handle does not report as a regular file, so a FIFO or a device is refused
/// at once instead of blocking or reading without end. Like the gateway's
/// reader, it sets no size limit on a regular file.
///
/// # Errors
///
/// The open or read error, or `InvalidInput` for a path that is not a
/// regular file.
pub(super) fn read_regular_text(path: &Path) -> std::io::Result<String> {
    let mut file = open_nonblocking(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    Ok(text)
}

#[cfg(unix)]
fn open_nonblocking(path: &Path) -> std::io::Result<std::fs::File> {
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
fn open_nonblocking(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}
