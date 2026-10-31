// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A temporary directory whose path a path check accepts as normalised.
//!
//! The Windows runner's TEMP is an 8.3 path (`C:\Users\RUNNER~1\...`), and
//! the allowed-folder check refuses a short-name segment as `not_normalised`
//! on purpose (W18). On Windows the directory goes under the working
//! directory, which has long names; elsewhere it is a plain `tempdir()`.

/// A fresh temporary directory with no 8.3 short name in its path.
pub(crate) fn tempdir() -> tempfile::TempDir {
    #[cfg(windows)]
    let dir = std::env::current_dir().and_then(tempfile::tempdir_in);
    #[cfg(not(windows))]
    let dir = tempfile::tempdir();
    dir.expect("tempdir")
}
