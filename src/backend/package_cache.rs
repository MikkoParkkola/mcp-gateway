// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Repairing the package cache a stdio backend installs into.
//!
//! A package manager reports an unusable install on the child's stderr, and the
//! child dies before it can answer the handshake — so the reason exists only
//! where the child is read, and no caller can see it in the error alone.
//!
//! The repair lives here rather than in the transport because every start of a
//! backend funnels through this one call: a client's request, warm-start, and
//! the health probe's restart all reach it, so a cache that cannot install is
//! cleared wherever a backend starts, not only where it was spawned.

use std::collections::HashMap;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use tracing::warn;

use crate::Error;
use crate::transport::StdioTransport;

/// Text a package manager prints when its install tree cannot be used.
///
/// `ENOENT` is absent because a missing binary renders as `Failed to spawn: No
/// such file or directory (os error 2)` — the literal never appears on its own,
/// and as a substring it matches too much else to be a signal. `EALLOWGIT` is
/// absent because it is a policy refusal: a fresh install is refused exactly the
/// same way, so clearing the cache cannot fix it and only costs a reinstall.
const NEEDLES: [&str; 3] = [
    "Cannot find module",
    "ERR_MODULE_NOT_FOUND",
    "MODULE_NOT_FOUND",
];

/// Caches already cleared since their last successful start.
///
/// Keyed by the cache directory, which identifies the backend across the
/// transports a restart replaces. Without this, a backend that cannot install
/// has its cache wiped on every restart — an install per boot, forever, for a
/// failure no install fixes.
fn repaired_since_success() -> &'static Mutex<HashSet<PathBuf>> {
    static REPAIRED: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    REPAIRED.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Records a repair, returning false when this cache was already repaired
/// since its last successful start.
fn mark_repaired(dir: &Path) -> bool {
    repaired_since_success()
        .lock()
        .is_ok_and(|mut set| set.insert(dir.to_path_buf()))
}

/// Arms the next repair after a start that succeeded, or after a repair that
/// did not happen.
fn arm_again(dir: &Path) {
    if let Ok(mut set) = repaired_since_success().lock() {
        set.remove(dir);
    }
}

/// One mutex per cache directory, held across a whole start of a backend that
/// uses it: the first attempt, the repair and the retry.
///
/// Two starts of one backend can both fail and both decide to repair, and the
/// retry one of them runs installs into exactly the tree the other would
/// delete. A start that is not repairing installs into that tree too, so the
/// lock covers every start of the cache, not only the repairing ones; starts of
/// one backend's cache run one at a time. Entries are never removed: there is one per cache path, and the
/// paths are the backends the configuration names.
fn repair_locks() -> &'static Mutex<HashMap<PathBuf, Arc<tokio::sync::Mutex<()>>>> {
    static LOCKS: OnceLock<Mutex<HashMap<PathBuf, Arc<tokio::sync::Mutex<()>>>>> = OnceLock::new();
    LOCKS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The longest one start can hold its backend's cache lock, from the backend's
/// request timeout `t`. Both the hold and the wait are derived from here, so
/// they cannot drift apart.
///
/// The sum of the steps the lock covers: a failed first attempt
/// ([`attempt_bound`]), moving the cache aside ([`rename_bound`]), and the single
/// retry (another attempt): 2 * (2t + 2s) + t = 5t + 4s.
fn lock_hold_bound(t: std::time::Duration) -> std::time::Duration {
    attempt_bound(t) * 2 + rename_bound(t)
}

/// One start attempt: `initialize` is at most two requests of `t` each (one
/// version renegotiation), plus about 2 s of settling and draining the child.
fn attempt_bound(t: std::time::Duration) -> std::time::Duration {
    t * 2 + std::time::Duration::from_secs(2)
}

/// Moving the cache aside, which the repair gives up on after this.
fn rename_bound(t: std::time::Duration) -> std::time::Duration {
    t
}

/// A held cache lock, owned so it can travel into the blocking rename.
type CacheGuard = tokio::sync::OwnedMutexGuard<()>;

fn repair_lock(dir: &Path) -> Arc<tokio::sync::Mutex<()>> {
    let mut locks = repair_locks()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Arc::clone(locks.entry(dir.to_path_buf()).or_default())
}

/// Starts a stdio backend, clearing its package cache and retrying once when
/// the failure is one a fresh install can repair.
///
/// The cache cleared is the one the gateway assigned, read from the transport
/// rather than from its environment: `assigned_package_cache_dir` answers
/// `None` for a backend that runs no package manager and for one whose
/// configuration names a cache of its own, and a path the operator wrote is
/// not the gateway's to delete however much it looks like one.
///
/// The retry is bounded to one, and the cache is cleared at most once per
/// successful start. A backend whose install genuinely cannot be repaired fails
/// the second attempt too, and what happens after that is the caller's retry
/// policy — warm-start's loop, the health probe — not this function's.
pub(crate) async fn start_with_repair(transport: &Arc<StdioTransport>) -> crate::Result<()> {
    start_reporting(transport).await.0
}

/// What a failed start's repair did.
///
/// The latch is the whole of it: exactly one of two repairs of one cache
/// clears, and the other finds the first one's mark. A caller that only wants
/// the start's result uses [`start_with_repair`]; this is for the tests that
/// have to see which of the two they are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Repair {
    /// This call cleared the cache and retried the start.
    Cleared,
    /// A repair of this cache had already run since its last successful start.
    AlreadyRepaired,
    /// The failure is not one a fresh install repairs, or the cache is not the
    /// gateway's to clear.
    NotRepaired,
}

/// [`start_with_repair`], reporting what the repair did.
pub(crate) async fn start_reporting(
    transport: &Arc<StdioTransport>,
) -> (crate::Result<()>, Repair) {
    start_reporting_with(transport, discard_tombstone).await
}

/// [`start_reporting`], handing a moved-aside cache to `discard`, so a test can
/// hold its deletion open and show that nothing waits on it.
async fn start_reporting_with(
    transport: &Arc<StdioTransport>,
    discard: fn(PathBuf),
) -> (crate::Result<()>, Repair) {
    if let Some(root) = transport
        .assigned_package_cache_dir()
        .and_then(Path::parent)
    {
        sweep_tombstones_once(root);
    }
    // Held from the first spawn to the end of any retry: see `repair_lock`.
    // The cache is per backend (its name is hashed into the path), so only
    // other starts of this same backend wait. In the normal case a start holds
    // it for at most `lock_hold_bound` (5T + 4s, T being the request timeout);
    // deleting the moved tree holds nothing. Writes to the child's stdin and
    // reaping it carry no timeout of their own.
    let lock = transport.assigned_package_cache_dir().map(repair_lock);
    // A start waits out one full repair, the same bound, so a start arriving
    // mid-repair succeeds after it instead of failing. Past that it fails as
    // unavailable rather than queue forever behind, say, a rename stuck on a
    // wedged filesystem, which keeps the lock (see `retire_cache_dir`).
    let held = match lock {
        Some(lock) => {
            let wait = lock_hold_bound(transport.request_timeout());
            let Ok(held) = tokio::time::timeout(wait, lock.lock_owned()).await else {
                let error = Error::BackendUnavailable(format!(
                    "stdio backend {}: its package cache is still locked by another start or \
                     a rename after {:?}",
                    transport.diagnostic_command(),
                    wait
                ));
                return (Err(error), Repair::NotRepaired);
            };
            Some(held)
        }
        None => None,
    };
    let Err(error) = transport.start().await else {
        if let Some(dir) = transport.assigned_package_cache_dir() {
            arm_again(dir);
        }
        return (Ok(()), Repair::NotRepaired);
    };

    let needle = install_failure_needle(&error, &transport.stderr_tail());
    warn!(
        command = %transport.diagnostic_command(),
        needle = needle.unwrap_or("none"),
        exit_status = %exit_status_text(transport.exit_status()),
        "start failed; reporting how the child ended, not what it printed"
    );
    let Some(needle) = needle else {
        return (Err(error), Repair::NotRepaired);
    };
    let Some(dir) = assigned_cache_to_clear(transport) else {
        warn!(
            command = %transport.diagnostic_command(),
            "the package cache was not assigned by this gateway; leaving it alone"
        );
        return (Err(error), Repair::NotRepaired);
    };

    // `dir` came from the same assignment the lock was taken for, so the lock
    // is held here; without it there is no repair.
    let Some(held) = held else {
        return (Err(error), Repair::NotRepaired);
    };
    repair_while_locked(transport, &dir, needle, error, held, discard).await
}

/// The section the cache's lock guards: latch, remove, retry.
///
/// One function so the exclusion is a unit a second repair of the same backend
/// cannot interleave with.
async fn repair_while_locked(
    transport: &Arc<StdioTransport>,
    dir: &Path,
    needle: &'static str,
    error: Error,
    held: CacheGuard,
    discard: fn(PathBuf),
) -> (crate::Result<()>, Repair) {
    if !mark_repaired(dir) {
        warn!(
            path = %dir.display(),
            "package cache already repaired since the last successful start"
        );
        return (Err(error), Repair::AlreadyRepaired);
    }
    // Kept to the end of the retry. If this future is dropped mid-rename, the
    // guard is still inside the blocking task, which Tokio cannot abort.
    let limit = rename_bound(transport.request_timeout());
    let Ok((retired, _held)) = retire_within(dir, held, retire_now, discard, limit).await else {
        warn!(path = %dir.display(), "moving the package cache aside did not finish in time; abandoning the repair");
        let error = Error::BackendUnavailable(format!(
            "stdio backend {}: moving its package cache aside did not finish within {limit:?}; \
             the backend cannot start until it does",
            transport.diagnostic_command()
        ));
        return (Err(error), Repair::NotRepaired);
    };
    // The tombstone's deletion and the latch reset already happened inside
    // the rename's task (see `retire_cache_dir`).
    if retired == Retired::Refused {
        warn!(path = %dir.display(), "could not clear package cache");
        return (Err(error), Repair::NotRepaired);
    }
    warn!(
        command = %transport.diagnostic_command(),
        needle = needle,
        path = %dir.display(),
        "package cache cleared after a failed start; retrying once"
    );
    let retry = transport.start().await;
    if retry.is_ok() {
        arm_again(dir);
    }
    (retry, Repair::Cleared)
}

/// The assigned cache, when the child is actually running with it.
///
/// An assignment the transport carries but the child never received is not a
/// directory this gateway created, so both halves have to agree before the
/// removal walks it.
fn assigned_cache_to_clear(transport: &StdioTransport) -> Option<PathBuf> {
    let dir = transport.assigned_package_cache_dir()?.to_path_buf();
    (transport.package_cache_dir().as_deref() == Some(dir.as_path())).then_some(dir)
}

/// Which known install failure a failed start matches, if any.
///
/// The child's stderr is the half that matters: the text naming an unusable
/// install is printed there, and judging the transport's error alone means
/// never seeing the failure this exists for. The needle comes back rather than
/// the text because the text is the child's to print — it may carry a token,
/// a PEM block or a JSON body holding a key — and the needle is what a log can
/// be told about it.
pub(crate) fn install_failure_needle(error: &Error, stderr: &str) -> Option<&'static str> {
    let mut text = error.to_string();
    text.push('\n');
    text.push_str(stderr);
    NEEDLES
        .iter()
        .copied()
        .find(|needle| text.contains(*needle))
}

/// How the child ended, as a log field.
fn exit_status_text(status: Option<std::process::ExitStatus>) -> String {
    status.map_or_else(|| "running".to_string(), |status| status.to_string())
}

/// What moving a cache aside did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Retired {
    /// The cache now sits at this tombstone, to be deleted with no lock held.
    Moved(PathBuf),
    /// There was no cache to move.
    AlreadyGone,
    /// The path is not a tree this gateway may touch, or the rename failed.
    Refused,
}

/// Marks a tombstone's name. A cache directory's own name never holds a `.`
/// (see `cache_component`), so this cannot match a live cache.
const TOMBSTONE_MARK: &str = ".tombstone-";

/// [`retire_cache_dir`], given up on after `limit`.
///
/// Giving up drops only the wait. The blocking rename cannot be stopped, so its
/// thread is orphaned until the filesystem answers, and it keeps the cache's
/// lock until then: later starts fail fast as busy instead of installing into
/// a tree that is still being moved.
async fn retire_within<F>(
    dir: &Path,
    held: CacheGuard,
    retire: F,
    discard: fn(PathBuf),
    limit: std::time::Duration,
) -> Result<(Retired, Option<CacheGuard>), tokio::time::error::Elapsed>
where
    F: FnOnce(&Path) -> Retired + Send + 'static,
{
    tokio::time::timeout(limit, retire_cache_dir(dir, held, retire, discard)).await
}

/// Moves a cache aside to a tombstone on the blocking pool.
///
/// The cache's lock travels into the blocking task and comes back with the
/// result. A started blocking task cannot be aborted, so if the start awaiting
/// it is cancelled, the rename still finishes, and it keeps every other start
/// of this backend out until it has.
///
/// What follows the rename happens in the same task, before the guard is let
/// go, so it happens even when no caller is left to see the result: a moved
/// tree is handed to `discard`, and a refused rename re-arms the latch, since
/// that start never got its repair and a later start may try again.
async fn retire_cache_dir<F>(
    dir: &Path,
    held: CacheGuard,
    retire: F,
    discard: fn(PathBuf),
) -> (Retired, Option<CacheGuard>)
where
    F: FnOnce(&Path) -> Retired + Send + 'static,
{
    let target = dir.to_path_buf();
    let renamed = tokio::task::spawn_blocking(move || {
        let retired = retire(&target);
        match &retired {
            Retired::Moved(tombstone) => discard(tombstone.clone()),
            Retired::Refused => arm_again(&target),
            Retired::AlreadyGone => {}
        }
        (retired, held)
    });
    match renamed.await {
        Ok((retired, held)) => (retired, Some(held)),
        Err(error) => {
            warn!(%error, "package cache rename task failed");
            (Retired::Refused, None)
        }
    }
}

/// Renames the cache to a sibling tombstone: one atomic step on one filesystem,
/// however large the tree, so the next start installs into a fresh directory.
fn retire_now(dir: &Path) -> Retired {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);

    if !is_a_tree_to_walk(dir) {
        return Retired::Refused;
    }
    let (Some(parent), Some(leaf)) = (dir.parent(), dir.file_name()) else {
        return Retired::Refused;
    };
    let tombstone = parent.join(format!(
        "{}{TOMBSTONE_MARK}{}-{}",
        leaf.to_string_lossy(),
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    match std::fs::rename(dir, &tombstone) {
        Ok(()) => Retired::Moved(tombstone),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Retired::AlreadyGone,
        Err(error) => {
            warn!(%error, "could not move the package cache aside");
            Retired::Refused
        }
    }
}

/// Deletes a tombstone in the background, holding no lock: how long a large or
/// slow tree takes no longer blocks any start.
fn discard_tombstone(tombstone: PathBuf) {
    drop(tokio::task::spawn_blocking(move || {
        if !remove_now(&tombstone) {
            warn!(path = %tombstone.display(), "could not delete a package cache tombstone");
        }
    }));
}

/// Deletes tombstones a previous run left under `root`, once per root per
/// process: the first repair-capable start of a backend is the sweep's startup.
fn sweep_tombstones_once(root: &Path) {
    static SWEPT: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    let first = SWEPT
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .is_ok_and(|mut swept| swept.insert(root.to_path_buf()));
    if !first {
        return;
    }
    let root = root.to_path_buf();
    drop(tokio::task::spawn_blocking(move || {
        let Ok(entries) = std::fs::read_dir(&root) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if entry.file_name().to_string_lossy().contains(TOMBSTONE_MARK) && !remove_now(&path) {
                warn!(path = %path.display(), "could not delete a package cache tombstone");
            }
        }
    }));
}

fn remove_now(dir: &Path) -> bool {
    if !is_a_tree_to_walk(dir) {
        return false;
    }
    match std::fs::remove_dir_all(dir) {
        Ok(()) => true,
        Err(error) => error.kind() == std::io::ErrorKind::NotFound,
    }
}

/// Whether the path holds the kind of tree the removal is allowed to walk.
///
/// A trailing separator is refused because the OS resolves the final component
/// before the walk begins, so a symlink there is followed and the walk lands in
/// the link's target rather than in the cache. A final component that is itself
/// a symlink is refused for that same reason: the gateway creates a directory
/// there, and a link is not the tree this is clearing. "Already gone" passes,
/// because a cache the first spawn never created is not a failure to clear.
fn is_a_tree_to_walk(dir: &Path) -> bool {
    if has_trailing_separator(dir) {
        return false;
    }
    match std::fs::symlink_metadata(dir) {
        Ok(metadata) => metadata.file_type().is_dir(),
        Err(error) => error.kind() == std::io::ErrorKind::NotFound,
    }
}

/// Whether the path ends in a separator.
///
/// `Path` iterates and compares components as if it did not, which is the whole
/// reason this is checked on the text: `remove_dir_all` is handed the text.
fn has_trailing_separator(dir: &Path) -> bool {
    let text = dir.as_os_str().to_string_lossy();
    text.ends_with('/') || text.ends_with(std::path::MAIN_SEPARATOR)
}

#[cfg(test)]
#[path = "package_cache_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "package_cache_retry_tests.rs"]
mod retry_tests;
