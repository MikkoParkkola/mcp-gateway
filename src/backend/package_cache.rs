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

/// One mutex per cache directory, held across a repair.
///
/// Two starts of one backend can both fail and both decide to repair, and the
/// retry one of them runs installs into exactly the tree the other would
/// delete. Entries are never removed: there is one per cache path, and the
/// paths are the backends the configuration names.
fn repair_locks() -> &'static Mutex<HashMap<PathBuf, Arc<tokio::sync::Mutex<()>>>> {
    static LOCKS: OnceLock<Mutex<HashMap<PathBuf, Arc<tokio::sync::Mutex<()>>>>> = OnceLock::new();
    LOCKS.get_or_init(|| Mutex::new(HashMap::new()))
}

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

    // Held across the retry: the retry installs into the tree a second repair
    // of this backend would otherwise delete underneath it.
    let lock = repair_lock(&dir);
    let _repairing = lock.lock().await;
    repair_while_locked(transport, &dir, needle, error).await
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
) -> (crate::Result<()>, Repair) {
    if !mark_repaired(dir) {
        warn!(
            path = %dir.display(),
            "package cache already repaired since the last successful start"
        );
        return (Err(error), Repair::AlreadyRepaired);
    }
    if !remove_cache_dir(dir).await {
        // The start never got its repair, so the latch is not spent: a later
        // start can try the same cache again.
        arm_again(dir);
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

/// Removes a directory tree, treating "already gone" as success.
///
/// The tree is being removed because it is damaged, and it is the largest state
/// a backend has, so the delete runs on the blocking pool rather than parking an
/// async worker on it.
async fn remove_cache_dir(dir: &Path) -> bool {
    let target = dir.to_path_buf();
    match tokio::task::spawn_blocking(move || remove_now(&target)).await {
        Ok(removed) => removed,
        Err(error) => {
            warn!(%error, "package cache removal task failed");
            false
        }
    }
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
