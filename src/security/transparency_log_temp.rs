// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A transparency log path for tests, inside its own temporary directory.

use std::path::{Path, PathBuf};

/// An empty log file inside its own temporary directory.
///
/// The log writes sidecars beside its path (`<path>.hwm`, `<path>.lock`), and
/// a bare `NamedTempFile` removes only the log file itself, so every test run
/// left the sidecars behind. Dropping this removes the directory and all of
/// them. Keep it alive until the logger is dropped: declare it after the
/// field holding the logger, since fields drop in declaration order and a
/// directory with an open `.lock` inside cannot be removed on Windows.
pub(crate) struct TempLog {
    path: PathBuf,
    _dir: tempfile::TempDir,
}

impl TempLog {
    /// A new, empty log file, as `NamedTempFile::new` would create.
    pub(crate) fn new() -> Self {
        let dir = tempfile::tempdir().expect("log tempdir");
        let path = dir.path().join("audit.jsonl");
        std::fs::File::create(&path).expect("log file");
        Self { path, _dir: dir }
    }

    /// The log file's path.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}
