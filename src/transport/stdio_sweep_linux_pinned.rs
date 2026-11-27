// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A walked process's `/proc/<pid>` directory, held open for its walk, so
//! that every read of the walk names that process and no later one.

use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStringExt as _;

use rustix::fs::{Mode, OFlags};

/// One walked process's `/proc/<pid>` directory, held open for its whole walk
/// (design delta D5'''' option A, code review r1). Every file of the walk is
/// opened through `fd`. Once that process is reaped every such open fails with
/// `ESRCH` (probe t9477fa, kernel 6.17), so a later process given the same pid
/// is never read through it; while it is a zombie the reads still answer.
pub(super) struct Pinned {
    fd: OwnedFd,
    /// Test only: where the directory was opened, so the sabotage job can make
    /// the walk read by path instead (mutant M10). Unmutated code never reads it.
    #[cfg(test)]
    #[allow(dead_code)]
    base: std::path::PathBuf,
}

impl Pinned {
    pub(super) fn open(base: &std::path::Path) -> std::io::Result<Self> {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
        Ok(Self {
            fd: rustix::fs::open(base, flags, Mode::empty())?,
            #[cfg(test)]
            base: base.to_path_buf(),
        })
    }

    /// Open `rel` beneath the pinned directory.
    fn open_at(&self, rel: &std::path::Path, dir: bool) -> std::io::Result<OwnedFd> {
        let kind = if dir {
            OFlags::DIRECTORY
        } else {
            OFlags::empty()
        };
        let flags = OFlags::RDONLY | OFlags::CLOEXEC | kind;
        Ok(rustix::fs::openat(&self.fd, rel, flags, Mode::empty())?)
    }

    pub(super) fn read(&self, rel: &std::path::Path) -> std::io::Result<String> {
        let mut text = String::new();
        std::fs::File::from(self.open_at(rel, false)?).read_to_string(&mut text)?;
        Ok(text)
    }

    /// The entry names of directory `rel`, without `.` and `..`.
    pub(super) fn list(&self, rel: &std::path::Path) -> std::io::Result<Vec<std::ffi::OsString>> {
        let mut names = Vec::new();
        for entry in rustix::fs::Dir::read_from(self.open_at(rel, true)?)? {
            let name = entry?.file_name().to_bytes().to_vec();
            if name != b"." && name != b".." {
                names.push(std::ffi::OsString::from_vec(name));
            }
        }
        Ok(names)
    }
}
