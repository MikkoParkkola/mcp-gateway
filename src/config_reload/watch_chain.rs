// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Keeping the config watcher on the directories the config's link chain
//! actually runs through (#453).
//!
//! A config named through symlinks is read from wherever the chain ends, and
//! the chain can change under a running gateway: a deploy retargets the link to
//! a release in another directory, and a Kubernetes `ConfigMap` update swaps its
//! `..data` directory link. Watches registered once at startup keep watching
//! the directories the chain has left.
//!
//! The notify callback runs on notify's own event thread, and the inotify
//! backend serves `watch`/`unwatch` on that same thread, so the callback must
//! never call either. It only wakes the task here, which recomputes the chain
//! itself and reconciles the watches.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::Mutex;
use tracing::{info, warn};

use super::{ReloadTrigger, absolute_watch_path, watch_dir_of};

/// Hops followed before a chain is treated as a loop, as the kernel's `ELOOP`.
const MAX_HOPS: usize = 40;

/// The directories a config's link chain runs through, each canonical, and
/// where it ends.
///
/// Every hop's parent directory is included, not only the first and the last:
/// a retarget of a link in the middle of the chain happens in that link's own
/// directory, and nothing else hears it. A hop through a directory link (a
/// `ConfigMap`'s `..data`) is resolved by canonicalizing the parent, so the set
/// names real directories and never the link.
///
/// # Errors
///
/// Returns the I/O error of a hop that cannot be read, or `FilesystemLoop`
/// past [`MAX_HOPS`]. A caller keeps its last good set on error: mid-update
/// (the old directory being deleted) a hop can briefly fail to resolve.
pub(super) fn chain_dirs(named: &Path) -> std::io::Result<(BTreeSet<PathBuf>, PathBuf)> {
    let mut dirs = BTreeSet::new();
    let mut hop = absolute_watch_path(named.to_path_buf());
    for _ in 0..MAX_HOPS {
        dirs.insert(std::fs::canonicalize(watch_dir_of(&hop))?);
        match std::fs::read_link(&hop) {
            Ok(target) => {
                let base = watch_dir_of(&hop);
                hop = absolute_watch_path(if target.is_absolute() {
                    target
                } else {
                    base.join(target)
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {
                // Not a link: the chain ends here.
                let end = std::fs::canonicalize(&hop)?;
                dirs.insert(watch_dir_of(&end));
                return Ok((dirs, end));
            }
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other(
        "config symlink chain exceeds 40 hops",
    ))
}

/// The watcher and the directories it has actually been told to watch.
///
/// The ledger records a directory only after `watch()` succeeded and drops it
/// only after `unwatch()` did, so it is evidence of what is watched rather than
/// of what was wanted. A failed `watch()` leaves the directory out, and the
/// next wake tries it again.
pub(super) struct ChainWatch {
    pub(super) watcher: Mutex<Option<RecommendedWatcher>>,
    pub(super) ledger: Mutex<BTreeSet<PathBuf>>,
    /// Env-file directories, watched outside the chain and never unwatched here.
    protected: BTreeSet<PathBuf>,
    /// Wakes the rewatch task has finished handling (tests wait on it).
    #[cfg(test)]
    pub(super) wakes_handled: std::sync::atomic::AtomicUsize,
    /// `watch()` failures that were logged.
    #[cfg(test)]
    pub(super) watch_warnings: std::sync::atomic::AtomicUsize,
}

impl ChainWatch {
    pub(super) fn new(watcher: RecommendedWatcher, protected: BTreeSet<PathBuf>) -> Arc<Self> {
        Arc::new(Self {
            watcher: Mutex::new(Some(watcher)),
            ledger: Mutex::new(BTreeSet::new()),
            protected,
            #[cfg(test)]
            wakes_handled: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            watch_warnings: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// Watch `wanted`, and stop watching what the ledger holds beyond it.
    /// Returns whether the ledger changed.
    pub(super) fn reconcile(&self, wanted: &BTreeSet<PathBuf>) -> bool {
        let mut guard = self.watcher.lock();
        let Some(watcher) = guard.as_mut() else {
            return false;
        };
        let mut ledger = self.ledger.lock();
        let before = ledger.clone();
        for dir in wanted
            .difference(&before)
            .filter(|dir| !self.protected.contains(*dir))
        {
            match watcher.watch(dir, RecursiveMode::NonRecursive) {
                Ok(()) => {
                    ledger.insert(dir.clone());
                }
                Err(e) => {
                    warn!(dir = %dir.display(), error = %e, "Config watcher: cannot watch");
                    #[cfg(test)]
                    self.watch_warnings
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }
        }
        for dir in before
            .difference(wanted)
            .filter(|dir| !self.protected.contains(*dir))
        {
            // A directory already deleted (the old `ConfigMap` generation) has
            // lost its watch with it; either way it is no longer watched.
            if let Err(e) = watcher.unwatch(dir) {
                info!(dir = %dir.display(), error = %e, "Config watcher: unwatch of a gone directory");
            }
            ledger.remove(dir);
        }
        *ledger != before
    }

    /// The ledger: the directories actually watched.
    pub(super) fn watched_now(&self) -> BTreeSet<PathBuf> {
        self.ledger.lock().clone()
    }

    #[cfg(test)]
    pub(super) fn watched(&self) -> BTreeSet<PathBuf> {
        self.watched_now()
    }
}

/// Recompute the chain on every wake and follow it.
///
/// A changed chain is itself a config change (the link now names another
/// file), so it triggers a reload, and only after the new directories are
/// watched: a write to the new target in between is then read by that reload.
pub(super) fn spawn_rewatch_task(
    named: PathBuf,
    chain: Arc<ChainWatch>,
    mut wake: tokio::sync::watch::Receiver<()>,
    reload: tokio::sync::mpsc::Sender<ReloadTrigger>,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut last_end = chain_dirs(&named).ok().map(|(_, end)| end);
        loop {
            tokio::select! {
                changed = wake.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
                _ = shutdown.recv() => break,
            }
            let Ok((wanted, end)) = chain_dirs(&named) else {
                #[cfg(test)]
                chain
                    .wakes_handled
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                continue; // keep the last good set; the next event retries
            };
            let rewatched = chain.reconcile(&wanted);
            #[cfg(test)]
            chain
                .wakes_handled
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if rewatched || last_end.as_ref() != Some(&end) {
                last_end = Some(end);
                let _ = reload.try_send(ReloadTrigger::ConfigFile);
            }
        }
        // Drop the watcher so its thread and watches end with the task.
        chain.watcher.lock().take();
    })
}

/// Watch each env file's parent directory once, `NonRecursive`, as before #453.
/// Returns the set, which the chain reconcile must never unwatch.
pub(super) fn watch_env_dirs(
    watcher: &mut RecommendedWatcher,
    env_file_paths: &[PathBuf],
) -> BTreeSet<PathBuf> {
    let mut env_dirs = BTreeSet::new();
    for env_path in env_file_paths {
        let dir = watch_dir_of(env_path);
        if !env_dirs.insert(dir.clone()) {
            continue;
        }
        if !dir.exists() {
            warn!(dir = %dir.display(), "Config watcher: env-file directory does not exist, skipping");
            continue;
        }
        match watcher.watch(&dir, RecursiveMode::NonRecursive) {
            Ok(()) => {
                info!(dir = %dir.display(), "Config watcher: watching env-file directory");
            }
            Err(e) => warn!(
                dir = %dir.display(),
                error = %e,
                "Config watcher: failed to watch env-file directory"
            ),
        }
    }
    env_dirs
}

#[cfg(all(test, unix))]
#[path = "watch_chain_tests.rs"]
mod tests;
