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
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering::SeqCst};
use std::time::{Duration, Instant};

use super::journal::Recovered;
use crate::fs_lock::ExclusiveFileLock;
use crate::identity_grants::journal::resolved;

/// How often a waiting writer tries the lock again.
const POLL: Duration = Duration::from_millis(25);

/// The sidecar for resolved `config`, shared by every spelling of its path.
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
    /// The lock was taken, but the pending recovery it runs first found a
    /// replace journal or staged original the config guard refuses; nothing
    /// was restored. The text names no path.
    Refused(String),
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

/// A held config lock and the file it was taken for: the config resolved
/// once, so the holder's load, write and reload reach the file it locked even
/// if a symlink at the configured path is re-pointed meanwhile.
pub(crate) struct Locked {
    /// The resolved config.
    pub(crate) target: PathBuf,
    /// The lock; released on drop.
    pub(crate) held: ExclusiveFileLock,
    /// What recovery did. After [`Recovered::RolledBack`] the running config
    /// is on bytes that are no longer on disk, and a live gateway owes a
    /// reload.
    pub(crate) recovered: Recovered,
    /// A replace journal was left beside the config and is not yet
    /// recovered: only [`lock_config_deferred`] leaves one.
    pub(crate) journal_pending: bool,
    /// The configured path was a symlink to a missing target when it was
    /// resolved: damage, not absence (GH462).
    dangling: bool,
    /// The target existed once the lock was held, so its disappearance
    /// before the write is a deletion, not a config still to be created.
    existed: bool,
}

impl Locked {
    /// Whether there is no config to load: the target is missing, and the
    /// configured path is no dangling link to it. A dangling link refuses:
    /// its target is never created from defaults (GH462). It counts if it
    /// dangled when the path was resolved and the target is still missing,
    /// or dangles now because the target was deleted while the writer
    /// waited. A path that moved refuses first ([`Self::still_named_by`]),
    /// so the link judged here is the one that names the target.
    ///
    /// # Errors
    ///
    /// A moved path, a dangling link, or a target whose metadata cannot be
    /// read.
    pub(crate) fn absent(&self, config: &Path) -> Result<bool, String> {
        self.still_named_by(config)?;
        match std::fs::symlink_metadata(&self.target) {
            Ok(_) => Ok(false),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let links =
                    std::fs::symlink_metadata(config).is_ok_and(|m| m.file_type().is_symlink());
                if self.dangling || links {
                    return Err(format!(
                        "{} is a symlink to {}, which does not exist",
                        config.display(),
                        self.target.display()
                    ));
                }
                Ok(true)
            }
            Err(e) => Err(format!(
                "Cannot inspect config file {}: {e}",
                self.target.display()
            )),
        }
    }

    /// Whether the holder may write the target now: the path still names it,
    /// it is no dangling link's missing target, and it was not deleted since
    /// the lock was held. Checked before the write, so a config deleted while
    /// the writer worked is not recreated from its copy.
    ///
    /// # Errors
    ///
    /// As [`Self::absent`].
    pub(crate) fn may_write(&self, config: &Path) -> Result<(), String> {
        if self.absent(config)? && self.existed {
            return Err(format!(
                "Not saved: {} was deleted during the write; nothing was written",
                config.display()
            ));
        }
        Ok(())
    }

    /// Refuse a write whose configured path no longer names the target this
    /// lock holds: the link was re-pointed while the writer waited or
    /// worked, and writing the old target would report success for a file
    /// the path no longer names.
    ///
    /// # Errors
    ///
    /// The path moved; nothing may be written.
    pub(crate) fn still_named_by(&self, config: &Path) -> Result<(), String> {
        if resolved(config) == self.target {
            return Ok(());
        }
        Err(format!(
            "Not saved: {} moved during the write (it no longer names {}); nothing was written, retry",
            config.display(),
            self.target.display()
        ))
    }
}

/// Take the lock for `config`, waiting until `deadline` while another writer
/// holds it. For async callers.
///
/// A replace journal left beside the config is recovered before this
/// returns, so no holder ever reads a half-replaced file
/// ([`super::journal`]).
///
/// All of it runs on one thread off the async workers: resolving the path,
/// opening the sidecar and recovery each touch the filesystem, and on a
/// stalled NFS or FUSE mount any of them blocks (#1808). The lock stays with
/// that thread until it returns, so a caller cancelled meanwhile never
/// leaves recovery running unlocked, and the thread stops waiting within one
/// poll of the cancel.
pub(crate) async fn lock_config(config: &Path, deadline: Instant) -> Result<Locked, NotLocked> {
    match lock_with(config, deadline, Preflight::None, Recovery::OnAcquire).await {
        Ok(locked) => locked,
        // Preflight::None loads nothing, so it refuses nothing.
        Err(e) => Err(NotLocked::Failed(e.to_string())),
    }
}

/// [`lock_config`] that leaves a pending replace journal where it is and
/// reports it ([`Locked::journal_pending`]): an audited writer appends its
/// recovery intent first, then recovers ([`super::journal::recover`]). A
/// refused acquisition recovers nothing.
pub(crate) async fn lock_config_deferred(
    config: &Path,
    deadline: Instant,
) -> Result<Locked, NotLocked> {
    match lock_with(config, deadline, Preflight::None, Recovery::Deferred).await {
        Ok(locked) => locked,
        // Preflight::None loads nothing, so it refuses nothing.
        Err(e) => Err(NotLocked::Failed(e.to_string())),
    }
}

/// [`lock_config`] for a writer that loads the config under the lock: the
/// config must load first (the outer `Err`, the load's own error), so a
/// file that does not is refused with no lock file made (GH462). Skipped
/// while a replace journal is pending: the file may be a refused candidate,
/// which the lock recovers before the holder's own load.
///
/// The check runs on the lock thread, not the async worker. It reads bytes
/// another writer can still change before the lock is held, so the holder's
/// load under the lock is the one that decides; a file broken in that gap
/// is refused after the lock file exists, the one exception to GH462.
pub(crate) async fn lock_config_loading(
    config: &Path,
    deadline: Instant,
) -> crate::Result<Result<Locked, NotLocked>> {
    lock_with(config, deadline, Preflight::Loads, Recovery::OnAcquire).await
}

/// When a pending replace journal is recovered.
#[derive(Clone, Copy)]
enum Recovery {
    /// Before the lock is handed over.
    OnAcquire,
    /// By the holder, after its own audit intent.
    Deferred,
}

/// What the lock thread checks before it opens the sidecar.
#[derive(Clone, Copy)]
enum Preflight {
    None,
    /// The config loads, or is absent, unless a replace journal is pending.
    Loads,
}

async fn lock_with(
    config: &Path,
    deadline: Instant,
    preflight: Preflight,
    recovery: Recovery,
) -> crate::Result<Result<Locked, NotLocked>> {
    let config = config.to_path_buf();
    let waiting = Arc::new(AtomicBool::new(true));
    let _cancel = StopWaiting(Arc::clone(&waiting));
    off_runtime(move || {
        if matches!(preflight, Preflight::Loads) && !super::journal::exists(&config) {
            super::load_existing_or_default(&config)?;
        }
        Ok(acquire(&config, deadline, recovery, &|| waiting.load(SeqCst), |_| {}))
    })
    .await
    .unwrap_or_else(|why| {
        Ok(match why {
            // Retryable, as a lock held past the wait is.
            NoResult::Stalled => Err(NotLocked::Busy),
            NoResult::Lost => Err(NotLocked::Failed(
                "taking the config lock failed: its thread could not start or ended without a result"
                    .to_owned(),
            )),
        })
    })
}

/// Tells the locking thread to stop waiting once its caller is gone.
struct StopWaiting(Arc<AtomicBool>);

impl Drop for StopWaiting {
    fn drop(&mut self) {
        self.0.store(false, SeqCst);
    }
}

/// The wait itself, on a thread that may block. Gives up as at the deadline
/// once `waiting` turns false. `on_wait` runs once, the first time the lock
/// is found held.
fn acquire(
    config: &Path,
    deadline: Instant,
    recovery: Recovery,
    waiting: &dyn Fn() -> bool,
    on_wait: impl FnOnce(&Path),
) -> Result<Locked, NotLocked> {
    // Resolved once: the lock, the recovery and the holder's work are about
    // the same file, even if a symlink is re-pointed meanwhile.
    let target = resolved(config);
    let dangling = std::fs::symlink_metadata(config).is_ok_and(|m| m.file_type().is_symlink())
        && std::fs::metadata(config).is_err_and(|e| e.kind() == io::ErrorKind::NotFound);
    let lock = lock_path(&target);
    let mut on_wait = Some(on_wait);
    // Test-only: counts this caller as a waiter once it finds the lock held.
    #[cfg(test)]
    let mut counted = Waiting::default();
    loop {
        if let Some(held) = try_once(config, &lock, Owners::UserOrRoot)? {
            let mut locked = Locked {
                target,
                held,
                recovered: Recovered::Nothing,
                journal_pending: false,
                dangling,
                existed: false,
            };
            match recovery {
                Recovery::OnAcquire => {
                    refuse_pending_v2(&locked)?;
                    locked.recovered =
                        super::journal::recover(&locked.target).map_err(|error| match error {
                            super::journal::NotRecovered::Refused(why) => NotLocked::Refused(why),
                            super::journal::NotRecovered::Failed(why) => NotLocked::Failed(why),
                        })?;
                }
                Recovery::Deferred => {
                    locked.journal_pending = super::journal::exists(&locked.target);
                }
            }
            locked.existed = std::fs::symlink_metadata(&locked.target).is_ok();
            return Ok(locked);
        }
        if let Some(say) = on_wait.take() {
            say(&lock);
        }
        #[cfg(test)]
        counted.start(&lock);
        if !waiting() || Instant::now() >= deadline {
            return Err(NotLocked::Busy);
        }
        std::thread::sleep(POLL);
    }
}

/// Why [`off_runtime`] has no result.
#[derive(Debug, PartialEq)]
enum NoResult {
    /// Not started: [`MAX_ABANDONED`] earlier threads are still stuck.
    Stalled,
    /// The thread could not start, or ended without a result.
    Lost,
}

// ponytail: a cap of 4 abandoned threads, not a per-mount bound. A thread
// stalled on a dead NFS or FUSE mount stays stalled whatever its caller
// does, so each retry against that mount would leave one more behind; a
// few cover a mount that recovers, and past them every lock attempt
// refuses until one returns. Threads whose caller is still waiting are not
// counted: their callers already bound them, and counting them would turn
// writers that only wait on each other into refusals.
const MAX_ABANDONED: usize = 4;

/// Threads [`off_runtime`] started whose caller gave up before they
/// returned.
struct Abandoned(AtomicUsize);

static ABANDONED: Abandoned = Abandoned(AtomicUsize::new(0));

/// A thread's state, shared by it and its caller.
const RUNNING: u8 = 0;
const RETURNED: u8 = 1;
const LEFT: u8 = 2;

/// Run `work` on a detached thread of its own and await its result: a
/// detached thread, not `spawn_blocking`, so filesystem work stalled on an
/// NFS or FUSE mount never holds the runtime's shutdown (as the reload's own
/// load does, #1808). Whatever `work` owns (a held lock) stays with it until
/// it finishes, even if the awaiting caller is dropped.
async fn off_runtime<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, NoResult> {
    off_runtime_in(&ABANDONED, work).await
}

async fn off_runtime_in<T: Send + 'static>(
    abandoned: &'static Abandoned,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, NoResult> {
    if abandoned.0.load(SeqCst) >= MAX_ABANDONED {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            tracing::warn!(
                stuck = MAX_ABANDONED,
                "config lock work refused: earlier threads are still stuck in the filesystem; check the mount holding gateway.yaml"
            );
        });
        return Err(NoResult::Stalled);
    }
    let state = Arc::new(AtomicU8::new(RUNNING));
    let (done, result) = tokio::sync::oneshot::channel();
    let ended = Returned {
        state: Arc::clone(&state),
        abandoned,
    };
    std::thread::Builder::new()
        .name("config-lock".into())
        .spawn(move || {
            let out = work();
            // A result nobody received (a held lock) is dropped before the
            // thread counts as returned: closing it can stall on the same
            // mount. A panic marks it returned too, as the guard drops.
            if let Err(out) = done.send(out) {
                drop(out);
            }
            drop(ended);
        })
        .map_err(|_| NoResult::Lost)?;
    let mut caller = Left {
        state,
        abandoned,
        armed: true,
    };
    let out = result.await;
    // Received: the thread's send succeeded and it is returning.
    caller.armed = out.is_err();
    out.map_err(|_| NoResult::Lost)
}

/// Held by the thread: marks it returned, and uncounts it if its caller
/// had already left.
struct Returned {
    state: Arc<AtomicU8>,
    abandoned: &'static Abandoned,
}

impl Drop for Returned {
    fn drop(&mut self) {
        if self.state.swap(RETURNED, SeqCst) == LEFT {
            self.abandoned.0.fetch_sub(1, SeqCst);
        }
    }
}

/// Held by the caller: counts the thread as abandoned if the caller leaves
/// before receiving its result. Counted before the state turns, so the
/// thread's uncount can never run ahead of it.
struct Left {
    state: Arc<AtomicU8>,
    abandoned: &'static Abandoned,
    /// Cleared once the result is received.
    armed: bool,
}

impl Drop for Left {
    fn drop(&mut self) {
        if !self.armed || self.state.load(SeqCst) == RETURNED {
            return;
        }
        self.abandoned.0.fetch_add(1, SeqCst);
        if self
            .state
            .compare_exchange(RUNNING, LEFT, SeqCst, SeqCst)
            .is_err()
        {
            self.abandoned.0.fetch_sub(1, SeqCst);
        }
    }
}

#[cfg(test)]
#[path = "config_persistence_lock_waiters_tests.rs"]
mod waiter_support;
#[cfg(test)]
use waiter_support::Waiting;
#[cfg(all(test, feature = "webui"))]
pub(crate) use waiter_support::waiters_for_test;

/// [`lock_config`] for a synchronous caller (the CLI), which may block its
/// own thread. `on_wait` runs once, the first time the lock is found held,
/// so the caller can say what it is waiting for.
pub(crate) fn lock_config_blocking(
    config: &Path,
    deadline: Instant,
    on_wait: impl FnOnce(&Path),
) -> Result<Locked, NotLocked> {
    acquire(config, deadline, Recovery::OnAcquire, &|| true, on_wait)
}

/// [`lock_config_deferred`] for a synchronous caller (the CLI): a pending
/// journal is left where it is and reported in [`Locked::journal_pending`],
/// for a caller that may not recover it unaudited.
pub(crate) fn lock_config_blocking_deferred(
    config: &Path,
    deadline: Instant,
    on_wait: impl FnOnce(&Path),
) -> Result<Locked, NotLocked> {
    acquire(config, deadline, Recovery::Deferred, &|| true, on_wait)
}

#[path = "config_persistence_lock_reader.rs"]
mod reader;
#[cfg(test)]
use reader::creation_blocked;
pub(crate) use reader::{
    ReaderLock, journal_pending, no_writer_possible, reader_lock, reader_lock_deferred,
};

/// The vault lock's blocking wait: one attempt per `POLL` until `deadline`,
/// with `on_wait` told once when the lock is held. The config locks wait in
/// [`acquire`], which also recovers the journal.
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

/// Take the lock file `lock` itself, blocking until `deadline`: the same
/// owner-only sidecar rules apply. Only the effective user's own sidecar is
/// accepted, with no exception for root. `subject` names what the lock
/// guards; the path follows it in a refusal.
pub(crate) fn lock_file_blocking(
    lock: &Path,
    subject: &str,
    deadline: Instant,
) -> Result<ExclusiveFileLock, NotLocked> {
    poll_blocking(
        Path::new(subject),
        lock,
        Owners::UserOnly,
        deadline,
        None::<fn(&Path)>,
    )
}

#[cfg(test)]
#[path = "config_persistence_lock_tests.rs"]
mod tests;

/// Dispatch an already held lock without recursively acquiring it.
pub(crate) fn dispatch_journal(
    locked: &Locked,
) -> Result<Option<super::journal::v2::OpenJournal>, super::journal::v2::JournalError> {
    super::journal::v2::open(locked)
}

/// Refuse exposing a writer while a v2 owner still owes settlement; any
/// other journal is left to the legacy recovery that follows.
pub(crate) fn refuse_pending_v2(locked: &Locked) -> Result<(), NotLocked> {
    use super::journal::v2::OpenJournal;

    match dispatch_journal(locked) {
        Ok(None) => Ok(()),
        Ok(Some(OpenJournal::Legacy(legacy))) => {
            drop(legacy);
            Ok(())
        }
        Ok(Some(OpenJournal::Current(state))) => {
            drop(state);
            Err(NotLocked::Refused(
                super::journal::SETTLEMENT_PENDING.to_owned(),
            ))
        }
        // Not a journal this can classify: legacy recovery refuses it with
        // its reviewed step, and never acts on anything but a v1 journal.
        Err(_) => Ok(()),
    }
}
