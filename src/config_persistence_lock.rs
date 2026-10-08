// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The cross-process lock every `gateway.yaml` writer holds from its load to
//! its write (MIK-8042).
//!
//! A writer that loads, edits and writes without it can be overtaken: another
//! process writes in between, and the slower writer's stale copy erases that
//! change while both report success. Holding one lock across the whole
//! read-modify-write makes the second writer edit the first one's result.
//!
//! The lock is an exclusive lock on a sidecar next to the config,
//! `.<file name>.lock`. Next to the file because the config path is the one
//! thing every writer agrees on (a lock under the data directory would miss a
//! writer started with another `--data-dir`). The sidecar is never deleted:
//! removing it would let a writer lock a fresh file while another still holds
//! the old one.
//!
//! The config file itself cannot carry the lock: every write replaces it by
//! rename, so a lock on it would stay on the old inode.

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::fs_lock::ExclusiveFileLock;

/// How often a waiting writer tries the lock again.
const POLL: Duration = Duration::from_millis(25);

/// The lock sidecar for `config`: `.<file name>.lock` in the same directory.
pub(crate) fn lock_path(config: &Path) -> PathBuf {
    let name = config
        .file_name()
        .map_or_else(|| "config".into(), |name| name.to_string_lossy());
    config.with_file_name(format!(".{name}.lock"))
}

/// Why a writer does not hold the config lock.
#[derive(Debug)]
pub(crate) enum NotLocked {
    /// Another writer held it until the deadline. Nothing was read or
    /// written, so the same write can simply be retried.
    Busy,
    /// The lock cannot be taken at all (a directory or a symlink where the
    /// sidecar goes, a read-only directory, no file locking on this
    /// platform). Writing anyway would be the unlocked write the lock
    /// exists to prevent, so the write is refused.
    Failed(String),
}

/// One attempt. `Ok(None)` means another writer holds the lock.
///
/// `try_acquire` is the only constructor used: it refuses a symlink
/// (`O_NOFOLLOW`) or anything but a regular file, judges the file's privacy
/// on Windows, and refuses on platforms with no file locking. The sidecar
/// sits in a directory the user chose, so a planted link must not be
/// followed.
fn try_once(lock: &Path) -> Result<Option<ExclusiveFileLock>, NotLocked> {
    match ExclusiveFileLock::try_acquire(lock) {
        Ok(held) => Ok(Some(held)),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(error) => Err(NotLocked::Failed(format!(
            "cannot lock {}: {error}",
            lock.display()
        ))),
    }
}

/// Take the lock for `config`, waiting until `deadline` while another writer
/// holds it. For async callers: the wait is an async sleep, never a thread
/// blocked on an executor worker.
pub(crate) async fn lock_config(
    config: &Path,
    deadline: Instant,
) -> Result<ExclusiveFileLock, NotLocked> {
    let lock = lock_path(config);
    loop {
        if let Some(held) = try_once(&lock)? {
            return Ok(held);
        }
        if Instant::now() >= deadline {
            return Err(NotLocked::Busy);
        }
        tokio::time::sleep(POLL).await;
    }
}

/// [`lock_config`] for a synchronous caller (the CLI), which may block its
/// own thread. `on_wait` runs once, the first time the lock is found held,
/// so the caller can say what it is waiting for.
pub(crate) fn lock_config_blocking(
    config: &Path,
    deadline: Instant,
    on_wait: impl FnOnce(&Path),
) -> Result<ExclusiveFileLock, NotLocked> {
    let lock = lock_path(config);
    let mut on_wait = Some(on_wait);
    loop {
        if let Some(held) = try_once(&lock)? {
            return Ok(held);
        }
        if let Some(say) = on_wait.take() {
            say(&lock);
        }
        if Instant::now() >= deadline {
            return Err(NotLocked::Busy);
        }
        std::thread::sleep(POLL);
    }
}

#[cfg(test)]
mod tests {
    use super::lock_path;
    use std::path::Path;

    #[test]
    fn the_sidecar_sits_next_to_the_config() {
        assert_eq!(
            lock_path(Path::new("/etc/mcp/gateway.yaml")),
            Path::new("/etc/mcp/.gateway.yaml.lock")
        );
        assert_eq!(
            lock_path(Path::new("gateway.yaml")),
            Path::new(".gateway.yaml.lock")
        );
    }
}
