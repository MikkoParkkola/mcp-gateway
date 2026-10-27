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

use super::journal::Recovered;
use crate::fs_lock::ExclusiveFileLock;
use crate::identity_grants::journal::resolved;

/// How often a waiting writer tries the lock again.
const POLL: Duration = Duration::from_millis(25);

/// The lock sidecar for `config`: `.<file name>.lock` in the same directory.
/// Callers pass the resolved config ([`resolved`]), so every spelling of one
/// config (a symlink, relative against absolute) meets one lock (MIK-8153).
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
fn try_once(
    config: &Path,
    lock: &Path,
    owners: Owners,
) -> Result<Option<ExclusiveFileLock>, NotLocked> {
    #[cfg(any(unix, windows))]
    keep_private(lock, owners).map_err(|error| {
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
/// Whose sidecar a lock accepts.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Owners {
    /// A config lock: root may tighten a user's sidecar, since root may write
    /// that user's config.
    UserOrRoot,
    /// A per-user lock (the vault): only the effective user's own sidecar,
    /// whatever its mode, with no exception for root.
    UserOnly,
}

/// A per-user sidecar must belong to `expected_uid`, the effective user,
/// whatever its mode and with no exception for root. Pure, so it is tested
/// without a second account.
#[cfg(unix)]
fn judge_owner(file_uid: u32, expected_uid: u32) -> io::Result<()> {
    if file_uid == expected_uid {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "it belongs to another user; remove it so the gateway recreates it as yours",
    ))
}

/// The uid a per-user sidecar must belong to: the effective user. A test
/// can name another, to show the lock path really asks.
#[cfg(unix)]
fn expected_owner_uid() -> u32 {
    #[cfg(test)]
    if let Some(uid) = EXPECTED_OWNER.with(std::cell::Cell::get) {
        return uid;
    }
    rustix::process::geteuid().as_raw()
}

#[cfg(all(test, unix))]
thread_local! {
    static EXPECTED_OWNER: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
}

#[cfg(unix)]
fn keep_private(lock: &Path, owners: Owners) -> io::Result<()> {
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
    if owners == Owners::UserOnly && meta.is_file() {
        judge_owner(meta.uid(), expected_owner_uid())?;
    }
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
fn keep_private(lock: &Path, _owners: Owners) -> io::Result<()> {
    // Windows already refuses any sidecar not private to this user, owner
    // included, so both owner rules are the same here.
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
///
/// A replace journal left beside the config is recovered before this
/// returns, so no holder ever reads a half-replaced file
/// ([`super::journal`]).
pub(crate) async fn lock_config(
    config: &Path,
    deadline: Instant,
) -> Result<ExclusiveFileLock, NotLocked> {
    lock_config_recovering(config, deadline)
        .await
        .map(|(held, _)| held)
}

/// [`lock_config`], also saying what recovery did, for a holder with a live
/// gateway: after [`Recovered::RolledBack`] the running config is on bytes
/// that are no longer on disk, and it owes a reload.
pub(crate) async fn lock_config_recovering(
    config: &Path,
    deadline: Instant,
) -> Result<(ExclusiveFileLock, Recovered), NotLocked> {
    // Resolved once: the lock and the recovery are about the same file, even
    // if a symlink is re-pointed meanwhile.
    let target = resolved(config);
    let lock = lock_path(&target);
    loop {
        if let Some(held) = try_once(config, &lock, Owners::UserOrRoot)? {
            // Recovery reads, writes and fsyncs: off the async workers. The
            // lock moves into the task, so a caller cancelled while waiting
            // here never leaves recovery running unlocked.
            let target = target.clone();
            return tokio::task::spawn_blocking(move || recovered(&target, held))
                .await
                .map_err(|e| {
                    NotLocked::Failed(format!("recovering the replace journal failed: {e}"))
                })?;
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
    let target = resolved(config);
    let lock = lock_path(&target);
    let held = poll_blocking(config, &lock, Owners::UserOrRoot, deadline, Some(on_wait))?;
    recovered(&target, held).map(|(held, _)| held)
}

/// The one blocking wait both synchronous locks share: one attempt per
/// `POLL` until `deadline`, with `on_wait` told once when the lock is held.
fn poll_blocking(
    config: &Path,
    lock: &Path,
    owners: Owners,
    deadline: Instant,
    mut on_wait: Option<impl FnOnce(&Path)>,
) -> Result<ExclusiveFileLock, NotLocked> {
    loop {
        if let Some(held) = try_once(config, lock, owners)? {
            return Ok(held);
        }
        if let Some(say) = on_wait.take() {
            say(lock);
        }
        // Never sleep past the deadline: a lock released after it is not
        // taken late.
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(NotLocked::Busy);
        }
        std::thread::sleep(POLL.min(left));
    }
}

/// Recover a replace journal beside the resolved `target` under `held`; an
/// unusable one releases the lock and refuses, naming what to do by hand.
fn recovered(
    target: &Path,
    held: ExclusiveFileLock,
) -> Result<(ExclusiveFileLock, Recovered), NotLocked> {
    match super::journal::recover(target) {
        Ok(recovered) => Ok((held, recovered)),
        Err(message) => Err(NotLocked::Failed(message)),
    }
}

/// Take the lock file `lock` itself, blocking until `deadline`: the same
/// owner-only sidecar and the same attempt as the config lock, for a lock
/// that is not beside a config (ADR-028's per-user vault lock). Only the
/// effective user's own sidecar is accepted, with no exception for root.
pub(crate) fn lock_file_blocking(
    lock: &Path,
    deadline: Instant,
) -> Result<ExclusiveFileLock, NotLocked> {
    // Named for what it guards; the path follows in the refusal.
    let subject = Path::new("the secret vault");
    poll_blocking(subject, lock, Owners::UserOnly, deadline, None::<fn(&Path)>)
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

    /// The per-user owner rule, without a second account: a sidecar owned by
    /// another uid is refused, the user's own is accepted.
    #[cfg(unix)]
    #[test]
    fn a_per_user_lock_accepts_only_the_users_own_sidecar() {
        let refused = super::judge_owner(1000, 1001).expect_err("another user's sidecar");
        assert_eq!(refused.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(refused.to_string().contains("belongs to another user"));
        super::judge_owner(1001, 1001).expect("the user's own sidecar");
    }

    /// The vault lock passes the real effective uid: a sidecar this user
    /// created, then loosened, is accepted and tightened, never refused.
    #[cfg(unix)]
    #[test]
    fn the_vault_lock_passes_the_real_uid() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let lock = dir.path().join("vault.lock");
        std::fs::write(&lock, "").expect("write");
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let held = super::lock_file_blocking(&lock, std::time::Instant::now());
        assert!(held.is_ok(), "the user's own sidecar was refused");
        let mode = std::fs::metadata(&lock).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "mode {mode:o}");
    }

    /// The lock path itself asks the owner rule: with another uid expected,
    /// a private sidecar this user owns is refused. Skipping the check, or
    /// moving it below the early return for a private file, turns this green
    /// into a pass and so fails it.
    #[cfg(unix)]
    #[test]
    fn the_vault_lock_refuses_a_sidecar_owned_by_anyone_else() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let lock = dir.path().join("vault.lock");
        std::fs::write(&lock, "").expect("write");
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let me = rustix::process::geteuid().as_raw();
        super::EXPECTED_OWNER.with(|uid| uid.set(Some(me + 1)));
        let refused = super::lock_file_blocking(&lock, std::time::Instant::now());
        super::EXPECTED_OWNER.with(|uid| uid.set(None));
        match refused {
            Err(super::NotLocked::Failed(why)) => {
                assert!(why.contains("belongs to another user"), "{why}");
            }
            other => panic!("not refused: {:?}", other.is_ok()),
        }
    }
}
