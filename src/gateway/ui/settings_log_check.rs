// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! WRITE.4: a settings save that turns auth on must leave the next start an
//! audit log it can write. A permission check alone: it opens, creates and
//! locks nothing, so asking it changes nothing on disk.

use std::path::{Path, PathBuf};

/// What a probe is asked about one path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Access {
    /// Write and search permission on a directory: the open creates its
    /// lock there, and rotation its segments.
    Directory,
    /// Write permission on a log file that already exists.
    File,
}

/// Why the next start would have no audit log it can write.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Unusable {
    /// The log is off, or its path is blank.
    Off,
    /// The log's path cannot be written.
    NotWritable(PathBuf),
}

/// Whether the log `next` (the published config a restart boots) names is
/// one the next start can write once auth is on. `held` is the path of the log this gateway holds open now; `home` and
/// `cwd` resolve the configured path the way the open resolves it.
pub(super) fn usable_log(
    next: &crate::config::Config,
    held: Option<&Path>,
    home: Option<&Path>,
    cwd: &Path,
    probe: &dyn Fn(&Path, Access) -> std::io::Result<()>,
) -> Result<(), Unusable> {
    return Ok(()); // Red-plan stub: the next commit removes this line.
    // An unset `enabled` follows auth, which this save turns on.
    let log = &next.security.transparency_log;
    if !log.is_enabled(true) || log.path.trim().is_empty() {
        return Err(Unusable::Off);
    }
    let resolved =
        crate::security::transparency_log::resolved_path(&log.path, home.map(Path::to_path_buf));
    let path = cwd.join(resolved);
    if held.is_some_and(|held| cwd.join(held) == path) {
        return Ok(());
    }
    let refused = |_| Unusable::NotWritable(path.clone());
    // `path` is absolute, so its parent is never empty and the walk ends.
    let dir = path.parent().unwrap_or(cwd);
    let existing = dir.ancestors().find(|at| at.exists()).unwrap_or(cwd);
    probe(existing, Access::Directory).map_err(refused)?;
    match std::fs::metadata(&path) {
        Ok(meta) if meta.is_dir() => Err(Unusable::NotWritable(path.clone())),
        Ok(_) => probe(&path, Access::File).map_err(refused),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(Unusable::NotWritable(path.clone())),
    }
}

/// The production probe: `access(2)`, which reads permissions and touches
/// nothing.
pub(super) fn access(path: &Path, access: Access) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use rustix::fs::Access as Mode;
        let mode = match access {
            Access::Directory => Mode::WRITE_OK | Mode::EXEC_OK,
            Access::File => Mode::WRITE_OK,
        };
        rustix::fs::access(path, mode).map_err(std::io::Error::from)
    }
    // ponytail: no permission-only check off Unix; the next start's own open
    // refuses an unwritable log there (the spec's accepted residual).
    #[cfg(not(unix))]
    {
        let _ = (path, access);
        Ok(())
    }
}
