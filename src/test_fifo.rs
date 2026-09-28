// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Create a named pipe (FIFO) as a test fixture, on every unix target.
//!
//! `rustix::fs::mkfifoat` and `mknodat` are not provided on Apple targets, so a
//! fixture calling them breaks the whole test build on macOS. POSIX
//! `mkfifo(1)` is on every Linux and macOS host, needs no new dependency and
//! no `unsafe`.

use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
use std::path::Path;

/// Create an owner-only (0600) FIFO at `path`, and check that one was made.
pub(crate) fn make_fifo(path: &Path) {
    let status = std::process::Command::new("mkfifo")
        .args(["-m", "600"])
        .arg(path)
        .status()
        .expect("run mkfifo(1) for the FIFO fixture");
    assert!(status.success(), "mkfifo(1) failed for {}", path.display());
    let meta = std::fs::symlink_metadata(path).expect("stat the FIFO fixture");
    assert!(
        meta.file_type().is_fifo(),
        "{} is not a FIFO",
        path.display()
    );
    assert_eq!(
        meta.permissions().mode() & 0o777,
        0o600,
        "FIFO fixture mode"
    );
}
