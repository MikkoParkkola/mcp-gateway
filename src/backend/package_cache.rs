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

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tracing::warn;

use crate::Error;
use crate::transport::StdioTransport;

/// Text a package manager prints when its install tree cannot be used.
///
/// `ENOENT` is deliberately absent: a missing binary renders as `Failed to
/// spawn: No such file or directory (os error 2)`, so the literal never appears
/// on its own, and as a substring it matches too much else to be a signal.
const NEEDLES: [&str; 4] = [
    "Cannot find module",
    "ERR_MODULE_NOT_FOUND",
    "MODULE_NOT_FOUND",
    "EALLOWGIT",
];

/// Starts a stdio backend, clearing its package cache and retrying once when
/// the failure is one a fresh install can repair.
///
/// The retry is bounded to one. A backend whose install cannot be repaired
/// fails the second attempt too, and what happens after that is the caller's
/// retry policy — warm-start's loop, the health probe — not this function's.
pub(crate) async fn start_with_repair(transport: &Arc<StdioTransport>) -> crate::Result<()> {
    match transport.start().await {
        Ok(()) => Ok(()),
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
            let Some(dir) = transport.package_cache_dir() else {
                return Err(error);
            };
            if !owned_cache_dir(&dir, &owned_root()) {
                warn!(
                    path = %dir.display(),
                    "not clearing a package cache outside the gateway data directory"
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
            transport.start().await
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

/// Whether `dir` is one of the per-backend caches the gateway created.
///
/// Lexical containment is enough: the only paths below `pkg-cache` are the ones
/// `isolated_package_manager_env` builds, and `remove_dir_all` unlinks a symlink
/// rather than following it. A cache an operator pointed the backend at by hand
/// is left where it is.
fn owned_cache_dir(dir: &Path, root: &Path) -> bool {
    dir.starts_with(root)
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
