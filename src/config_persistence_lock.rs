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
/// A failure names `config` first: that is the file the user selected, and
/// the sidecar is a detail of how it is locked.
fn try_once(config: &Path, lock: &Path) -> Result<Option<ExclusiveFileLock>, NotLocked> {
    #[cfg(any(unix, windows))]
    keep_private(lock).map_err(|error| {
        NotLocked::Failed(format!(
            "cannot lock {} (lock file {}): {error}",
            config.display(),
            lock.display()
        ))
    })?;
    match ExclusiveFileLock::try_acquire(lock) {
        Ok(held) => Ok(Some(held)),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(error) => Err(NotLocked::Failed(format!(
            "cannot lock {} (lock file {}): {error}",
            config.display(),
            lock.display()
        ))),
    }
}

/// Unix: make an existing sidecar owner-only before it is locked.
///
/// Any account that can open the sidecar can lock it, and so stall every
/// config write; `try_acquire` creates it owner-only, but one checked out by
/// git or copied in can be `0644`. One this user owns is tightened in place
/// (through the opened handle, never the path, so a swapped-in link is not
/// followed); one another account owns is refused, except for root, which
/// may write a user's config. A holder that opened it while it was readable
/// keeps its handle: closing that would mean replacing the file, which the
/// never-delete rule forbids.
#[cfg(unix)]
fn keep_private(lock: &Path) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
    let file = match std::fs::OpenOptions::new()
        .read(true)
        // Non-blocking, so a FIFO in its place cannot hang the open.
        .custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK)
                .bits()
                .cast_signed(),
        )
        .open(lock)
    {
        Ok(file) => file,
        // Missing: `try_acquire` creates it owner-only. Any other failure
        // (a link, no access) refuses the write here.
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let meta = file.metadata()?;
    let me = rustix::process::geteuid().as_raw();
    let shared = meta.mode() & 0o077 != 0;
    if !meta.is_file() || !shared {
        return Ok(());
    }
    if meta.uid() != me && me != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "it belongs to another user and others can open it; stop every gateway and CLI command using this config, then remove it",
        ));
    }
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
}

/// Windows: refuse an existing sidecar other accounts can open, saying how to
/// repair it.
///
/// The gateway creates the sidecar owner-only; one copied in, restored or
/// checked out by git inherits its directory's ACL, which `try_acquire`
/// refuses with only the rule it broke. This refusal carries the repair
/// (an owner-only DACL, the same command the gateway prints for a secret
/// file), so the user is never left with an error they cannot act on. An
/// open that fails (a holder sharing less, a link) is left to `try_acquire`.
#[cfg(windows)]
fn keep_private(lock: &Path) -> io::Result<()> {
    let Ok(file) = crate::private_fs::open_file_read(lock) else {
        return Ok(());
    };
    let found = crate::private_fs::privacy_refusals(&file);
    if found.is_empty() {
        return Ok(());
    }
    let repair = crate::private_fs::windows_remediation(
        &lock.display().to_string(),
        &found,
        crate::config::Protects::Secrecy,
    );
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("other accounts can open it{}", repair.trim_end()),
    ))
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
        if let Some(held) = try_once(config, &lock)? {
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
        if let Some(held) = try_once(config, &lock)? {
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

    /// MIK-8132: a sidecar with an inherited ACL (copied in, or checked out
    /// by git) is refused with the repair to run, never with only the rule it
    /// broke.
    #[cfg(windows)]
    #[test]
    fn a_shared_sidecar_is_refused_with_its_repair() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = dir.path().join("gateway.yaml");
        let lock = lock_path(&config);
        std::fs::write(&lock, "").expect("sidecar with an inherited ACL");

        let refused = super::lock_config_blocking(&config, std::time::Instant::now(), |_| {});

        let Err(super::NotLocked::Failed(message)) = refused else {
            panic!("a shared sidecar must refuse the lock");
        };
        assert!(
            message.contains("To repair it") && message.contains(".gateway.yaml.lock"),
            "{message}"
        );
    }

    /// MIK-8153: a config named through a symlink and through its target is
    /// one config, so both spellings meet one lock.
    #[cfg(unix)]
    #[test]
    fn a_symlink_and_its_target_share_one_lock() {
        let real = tempfile::tempdir().expect("real dir");
        let other = tempfile::tempdir().expect("link dir");
        let target = real.path().join("gateway.yaml");
        std::fs::write(&target, "backends: {}\n").expect("config");
        let link = other.path().join("gateway.yaml");
        std::os::unix::fs::symlink(&target, &link).expect("link");

        let now = std::time::Instant::now;
        let held = super::lock_config_blocking(&target, now(), |_| {}).expect("lock via target");
        let second = super::lock_config_blocking(&link, now(), |_| {});

        assert!(
            matches!(second, Err(super::NotLocked::Busy)),
            "the link spelling must meet the target's lock"
        );
        drop(held);
    }

    /// A sidecar other accounts can open (a `0644` one checked out by git,
    /// say) is one they can lock, stalling every config write. One this
    /// user owns is made owner-only before it is locked.
    #[cfg(unix)]
    #[test]
    fn a_readable_sidecar_is_made_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let config = dir.path().join("gateway.yaml");
        let lock = lock_path(&config);
        std::fs::write(&lock, "").expect("sidecar");
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o644)).expect("chmod");

        let held = super::lock_config_blocking(&config, std::time::Instant::now(), |_| {});

        assert!(held.is_ok(), "the lock is taken");
        let mode = std::fs::metadata(&lock).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "mode {mode:o}");
    }
}
