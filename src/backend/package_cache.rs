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

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};
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

/// Arms the next repair after a start that succeeded.
fn arm_again(dir: &Path) {
    if let Ok(mut set) = repaired_since_success().lock() {
        set.remove(dir);
    }
}

/// Starts a stdio backend, clearing its package cache and retrying once when
/// the failure is one a fresh install can repair.
///
/// The retry is bounded to one, and the cache is cleared at most once per
/// successful start. A backend whose install genuinely cannot be repaired fails
/// the second attempt too, and what happens after that is the caller's retry
/// policy — warm-start's loop, the health probe — not this function's.
pub(crate) async fn start_with_repair(transport: &Arc<StdioTransport>) -> crate::Result<()> {
    start_with_repair_under(transport, &owned_root()).await
}

/// [`start_with_repair`], with the directory the gateway owns injected.
///
/// Tests pass a temporary root, so no test touches the running gateway's state.
pub(crate) async fn start_with_repair_under(
    transport: &Arc<StdioTransport>,
    owned_root: &Path,
) -> crate::Result<()> {
    let cache = transport.package_cache_dir();
    match transport.start().await {
        Ok(()) => {
            if let Some(dir) = cache {
                arm_again(&dir);
            }
            Ok(())
        }
        Err(error) => {
            let stderr = transport.stderr_tail();
            if !stderr.is_empty() {
                warn!(
                    command = %transport.diagnostic_command(),
                    stderr = %stderr,
                    "start failed with the backend's last output on stderr"
                );
            }
            if !cache_shaped(&error, &stderr) {
                return Err(error);
            }
            let Some(dir) = cache else {
                return Err(error);
            };
            if !owned_cache_dir(&dir, owned_root) {
                warn!(
                    path = %dir.display(),
                    "not clearing a package cache outside the gateway data directory"
                );
                return Err(error);
            }
            if !mark_repaired(&dir) {
                warn!(
                    path = %dir.display(),
                    "package cache already repaired since the last successful start"
                );
                return Err(error);
            }
            if !remove_cache_dir(&dir).await {
                warn!(path = %dir.display(), "could not clear package cache");
                return Err(error);
            }
            warn!(
                command = %transport.diagnostic_command(),
                path = %dir.display(),
                "package cache cleared after a failed start; retrying once"
            );
            let retry = transport.start().await;
            if retry.is_ok() {
                arm_again(&dir);
            }
            retry
        }
    }
}

/// Whether a failed start is one a fresh package install can fix.
///
/// The child's stderr is the half that matters: the text naming an unusable
/// install is printed there, and judging the transport's error alone means
/// never seeing the failure this exists for.
pub(crate) fn cache_shaped(error: &Error, stderr: &str) -> bool {
    let mut text = error.to_string();
    text.push('\n');
    text.push_str(stderr);
    NEEDLES.iter().any(|needle| text.contains(needle))
}

/// The directory every per-backend cache is created under.
fn owned_root() -> PathBuf {
    crate::config_persistence::gateway_data_dir().join("pkg-cache")
}

/// Whether `dir` is a cache the gateway created: exactly one plain path
/// component below the root it owns.
///
/// One component, because that is what `isolated_package_manager_env` builds —
/// and nothing else. The root itself is not a backend cache, a `..` component
/// would escape, and a deeper path was not created by that function. Deleting
/// is irreversible, so the test is on the shape of the path rather than on
/// where it happens to resolve.
fn owned_cache_dir(dir: &Path, root: &Path) -> bool {
    let Ok(relative) = dir.strip_prefix(root) else {
        return false;
    };
    let mut components = relative.components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
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
    match std::fs::remove_dir_all(dir) {
        Ok(()) => true,
        Err(error) => error.kind() == std::io::ErrorKind::NotFound,
    }
}

#[cfg(test)]
#[path = "package_cache_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "package_cache_retry_tests.rs"]
mod retry_tests;
