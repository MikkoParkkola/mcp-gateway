// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Create a symlink as a test fixture, on unix and on Windows.
//!
//! The Windows CI job enables Developer Mode before the tests run (`ci.yml`,
//! "Allow symlink creation"), so a non-elevated token may create symlinks.

use std::io;
use std::path::Path;

/// Link `link` to `target`. On Windows the kind follows what `target` is now;
/// a dangling target becomes a file link.
pub(crate) fn symlink(target: impl AsRef<Path>, link: impl AsRef<Path>) -> io::Result<()> {
    let (target, link) = (target.as_ref(), link.as_ref());
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)
    }
    #[cfg(windows)]
    {
        // A relative target is relative to the link's directory, not the cwd.
        let resolved = link
            .parent()
            .map_or_else(|| target.to_path_buf(), |dir| dir.join(target));
        if resolved.is_dir() {
            std::os::windows::fs::symlink_dir(target, link)
        } else {
            std::os::windows::fs::symlink_file(target, link)
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (target, link);
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}
