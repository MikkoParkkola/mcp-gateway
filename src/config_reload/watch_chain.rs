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

use super::{ReloadTrigger, watch_dir_of};

/// Hops followed before a chain is treated as a loop, as the kernel's `ELOOP`.
const MAX_HOPS: usize = 40;

/// How often a chain that cannot be resolved is tried again without an event.
pub(super) const CHAIN_RETRY: std::time::Duration = std::time::Duration::from_secs(2);

/// A resolved chain: the directories to watch, the file it ends at, and the
/// paths whose change can move it.
pub(super) struct Chain {
    pub(super) dirs: BTreeSet<PathBuf>,
    pub(super) end: PathBuf,
    /// Each hop's file and each followed directory link, under its canonical
    /// directory: the paths notify reports for a write, rename or retarget
    /// that moves the chain (MIK-8013).
    pub(super) names: BTreeSet<PathBuf>,
}

/// The directories a config's link chain runs through, each canonical, and
/// where it ends. See [`resolve_chain`].
///
/// # Errors
///
/// As [`resolve_chain`].
pub(super) fn chain_dirs(named: &Path) -> std::io::Result<(BTreeSet<PathBuf>, PathBuf)> {
    resolve_chain(named).map(|chain| (chain.dirs, chain.end))
}

/// The directories a config's link chain runs through, each canonical, where
/// it ends, and the paths on it.
///
/// `named` is the path as the operator gave it, made absolute but with its
/// links intact: canonicalizing it first would erase a release link such as
/// Capistrano's `current` before it could be seen.
///
/// Each hop is a file path. A directory link that is the hop's immediate
/// parent (`current`, a `ConfigMap`'s `..data`) is followed, chain and all,
/// and the directory holding it is recorded: its retarget is heard there. Then
/// the hop's real directory is recorded, where writes to the file are heard,
/// and if the file is itself a link its target is the next hop. A directory
/// link higher in the path is resolved by `canonicalize` and not watched, so
/// nothing as high as `/` joins the set.
///
/// # Errors
///
/// Returns the I/O error of a hop that cannot be resolved, or an error past
/// [`MAX_HOPS`] link expansions. A caller keeps its last good set on error:
/// mid-update (the old directory being deleted) a hop can briefly fail.
pub(super) fn resolve_chain(named: &Path) -> std::io::Result<Chain> {
    let mut dirs = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut hop = std::path::absolute(named)?;
    let mut steps = 0;
    let mut expand = || {
        steps += 1;
        if steps > MAX_HOPS {
            Err(std::io::Error::other(format!(
                "config symlink chain exceeds {MAX_HOPS} links at {}",
                named.display()
            )))
        } else {
            Ok(())
        }
    };
    loop {
        let name = hop
            .file_name()
            .ok_or_else(|| std::io::Error::other(format!("{} names no file", hop.display())))?
            .to_os_string();
        let mut dir = watch_dir_of(&hop);
        while std::fs::symlink_metadata(&dir)?.file_type().is_symlink() {
            expand()?;
            let holder = watch_dir_of(&dir);
            let holder_real = std::fs::canonicalize(&holder)?;
            let target = std::fs::read_link(&dir)?;
            // A link is never named `..`, so it always has a file name.
            if let Some(link) = dir.file_name() {
                names.insert(holder_real.join(link));
            }
            dirs.insert(holder_real);
            dir = if target.is_absolute() {
                target
            } else {
                holder.join(target)
            };
        }
        let real_dir = std::fs::canonicalize(&dir)?;
        let file = real_dir.join(&name);
        dirs.insert(real_dir);
        names.insert(file.clone());
        // Ask for the file type first: `read_link` on a plain file is
        // `InvalidInput` on unix but os error 4390 (not a reparse point) on
        // Windows, so its error kind cannot tell "not a link" from a fault.
        match std::fs::symlink_metadata(&file).and_then(|meta| {
            if meta.file_type().is_symlink() {
                std::fs::read_link(&file).map(Some)
            } else {
                Ok(None)
            }
        }) {
            Ok(Some(target)) => {
                expand()?;
                hop = if target.is_absolute() {
                    target
                } else {
                    watch_dir_of(&file).join(target)
                };
            }
            // Not a link: the chain ends at this file.
            Ok(None) => {
                return Ok(Chain {
                    dirs,
                    end: file,
                    names,
                });
            }
            Err(e) => {
                return Err(std::io::Error::new(
                    e.kind(),
                    format!("{}: {e}", file.display()),
                ));
            }
        }
    }
}

/// The config path as the operator named it, made absolute without resolving
/// any link in it. The watcher, the rewatch task and the reload all use this
/// one path: resolving the parent here would pin a Capistrano `current` to the
/// release it named at startup, and every reload would read that release.
/// Only per-event matching resolves links (`config_watch_paths`).
pub(super) fn named_config_path(path: PathBuf) -> PathBuf {
    std::path::absolute(&path).unwrap_or(path)
}

/// The directories to watch at startup. A chain that cannot be resolved yet
/// (a target missing mid-update) watches the named file's own directory, and
/// the rewatch task resolves it again on its first wake, on a timer and on
/// every event.
pub(super) fn startup_dirs(named: &Path) -> BTreeSet<PathBuf> {
    chain_dirs(named).map_or_else(
        |e| {
            // The rewatch task warns once if the chain stays broken.
            info!(error = %e, "Config watcher: cannot resolve the config's link chain yet");
            BTreeSet::from([watch_dir_of(named)])
        },
        |(wanted, _)| wanted,
    )
}

/// The paths an event must touch to wake the rewatch task (MIK-8013).
///
/// Each wake re-resolves the whole chain, so a writer beside the config would
/// otherwise cost a resolve per write. The notify callback reads this; the
/// rewatch task replaces it after each resolve. `None` (no chain resolved yet,
/// or the last resolve failed) wakes on every event, as before.
#[derive(Default)]
pub(super) struct ChainNames {
    names: Mutex<Option<BTreeSet<PathBuf>>>,
    /// The paths of every event that passed (tests read it).
    #[cfg(test)]
    pub(super) passed: Mutex<Vec<Vec<PathBuf>>>,
}

impl ChainNames {
    /// Whether `event` can concern the config: a rescan (events were lost),
    /// or [`ChainNames::may_move_chain`] on its paths.
    pub(super) fn concerns(&self, event: &notify::Event) -> bool {
        let concerns = event.need_rescan() || self.may_move_chain(&event.paths);
        #[cfg(test)]
        if concerns {
            self.passed.lock().push(event.paths.clone());
        }
        concerns
    }

    /// Whether an event on `paths` can have moved the chain: one of them is a
    /// hop, a followed directory link or a watched directory, or there is no
    /// path or no resolved chain to judge by.
    pub(super) fn may_move_chain(&self, paths: &[PathBuf]) -> bool {
        paths.is_empty()
            || self.names.lock().as_ref().is_none_or(|names| {
                paths
                    .iter()
                    .any(|path| names.iter().any(|name| same_entry(path, name)))
            })
    }

    fn set(&self, names: Option<BTreeSet<PathBuf>>) {
        *self.names.lock() = names;
    }
}

/// Whether two paths name the same directory entry. Names are spelled as the
/// operator wrote them, which a case-insensitive file system (the macOS and
/// Windows defaults) may report in another case; ignoring case there costs at
/// most a spare resolve on a case-sensitive volume.
fn same_entry(a: &Path, b: &Path) -> bool {
    if cfg!(any(windows, target_os = "macos")) {
        a.as_os_str().eq_ignore_ascii_case(b.as_os_str())
    } else {
        a == b
    }
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
    /// Directories whose failed `watch()` was already logged, so a retry on
    /// every wake does not repeat it. Cleared on success, and pruned when the
    /// directory leaves the chain.
    warned: Mutex<BTreeSet<PathBuf>>,
    /// Shared with the notify callback, which wakes the task only for these.
    pub(super) names: Arc<ChainNames>,
    /// Wakes the rewatch task has finished handling (tests wait on it).
    #[cfg(test)]
    pub(super) wakes_handled: std::sync::atomic::AtomicUsize,
    /// `watch()` failures that were logged.
    #[cfg(test)]
    pub(super) watch_warnings: std::sync::atomic::AtomicUsize,
}

impl ChainWatch {
    /// The watch ledger for `watcher`, sharing `names` with its callback.
    pub(super) fn with_names(watcher: RecommendedWatcher, names: Arc<ChainNames>) -> Arc<Self> {
        Arc::new(Self {
            watcher: Mutex::new(Some(watcher)),
            ledger: Mutex::new(BTreeSet::new()),
            warned: Mutex::new(BTreeSet::new()),
            names,
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
        let mut warned = self.warned.lock();
        let before = ledger.clone();
        for dir in wanted.difference(&before) {
            match watcher.watch(dir, RecursiveMode::NonRecursive) {
                Ok(()) => {
                    ledger.insert(dir.clone());
                    warned.remove(dir);
                }
                Err(e) => {
                    if warned.insert(dir.clone()) {
                        warn!(dir = %dir.display(), error = %e, "Config watcher: cannot watch");
                        #[cfg(test)]
                        self.watch_warnings
                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                }
            }
        }
        for dir in before.difference(wanted) {
            // A directory already deleted (the old `ConfigMap` generation) has
            // lost its watch with it; either way it is no longer watched.
            if let Err(e) = watcher.unwatch(dir) {
                info!(dir = %dir.display(), error = %e, "Config watcher: unwatch of a gone directory");
            }
            ledger.remove(dir);
        }
        warned.retain(|dir| wanted.contains(dir));
        *ledger != before
    }

    /// The ledger: the directories actually watched.
    pub(super) fn watched_now(&self) -> BTreeSet<PathBuf> {
        self.ledger.lock().clone()
    }

    // Linux-only (W-L9): the real-watcher rows run on inotify (see `watch_chain_tests.rs`).
    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn watched(&self) -> BTreeSet<PathBuf> {
        self.watched_now()
    }
}

/// Recompute the chain on every wake and follow it.
///
/// A changed chain is itself a config change (the link now names another
/// file), so it triggers a reload, and only after the new directories are
/// watched: a write to the new target in between is then read by that reload.
/// The first resolve always triggers one: the config was read before the
/// watches existed, and a retarget in between would otherwise go unheard.
#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_rewatch_task(
    named: PathBuf,
    chain: Arc<ChainWatch>,
    mut wake: tokio::sync::watch::Receiver<()>,
    reload: tokio::sync::mpsc::Sender<ReloadTrigger>,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
    retry_every: std::time::Duration,
    mut poller: super::env_poll::EnvPoller,
    env_poll_every: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut last_end: Option<PathBuf> = None;
        // While the chain cannot be resolved, its missing part may appear in a
        // directory nobody watches yet, so the task also retries on a timer.
        // An interval's first tick completes at once: entering the broken
        // state retries once immediately, then every `retry_every`.
        let mut broken = false;
        let mut retry = tokio::time::interval(retry_every);
        retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Env files are polled by content, never watched (#1286): a watch
        // goes stale when a link in the path is retargeted.
        let mut env_poll = tokio::time::interval(env_poll_every);
        env_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = shutdown.recv() => break,
                changed = wake.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
                _ = retry.tick(), if broken => {}
                _ = env_poll.tick() => {
                    // No memo: a file that differs is re-triggered every tick
                    // until a reload succeeds; the debounce coalesces them.
                    if let Some(trigger) = poller.tick(env_poll_every).await {
                        let _ = reload.try_send(trigger);
                    }
                    // After a stalled read the interval is ready again at once
                    // and select picks at random, so shutdown is checked here:
                    // a stalled read then delays it by at most one poll wait.
                    // Not `biased`, which would let constant directory wakes
                    // starve the poll.
                    if !matches!(
                        shutdown.try_recv(),
                        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
                    ) {
                        break;
                    }
                    continue;
                }
            }
            let (wanted, end) = match resolve_chain(&named) {
                Ok(Chain {
                    dirs,
                    end,
                    mut names,
                }) => {
                    // Before the watches change: a new directory's events
                    // cannot arrive before its watch, so they meet these names.
                    // A watched directory itself (deleted, moved) wakes too.
                    names.extend(dirs.iter().cloned());
                    chain.names.set(Some(names));
                    (dirs, end)
                }
                Err(e) => {
                    // Without a chain nothing says which events matter.
                    chain.names.set(None);
                    if !broken {
                        warn!(error = %e, "Config watcher: cannot resolve the config's link chain; keeping the last watches");
                    }
                    broken = true;
                    #[cfg(test)]
                    chain
                        .wakes_handled
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    continue; // keep the last good set; the timer and the next event retry
                }
            };
            broken = false;
            let rewatched = chain.reconcile(&wanted);
            #[cfg(test)]
            chain
                .wakes_handled
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if rewatched || last_end.as_ref() != Some(&end) {
                info!(
                    end = %end.display(),
                    directories = wanted.len(),
                    "Config watcher: following the config's link chain"
                );
                last_end = Some(end);
                let _ = reload.try_send(ReloadTrigger::ConfigFile);
            }
        }
        // Drop the watcher so its thread and watches end with the task.
        chain.watcher.lock().take();
    })
}

#[cfg(test)]
#[path = "watch_chain_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "watch_chain_filter_tests.rs"]
mod filter_tests;

#[cfg(test)]
mod plain_file_tests {
    /// A regular file ends the chain on every platform (#1142: on Windows the
    /// chain failed on os error 4390 and hot-reload never followed the file).
    #[test]
    fn a_regular_file_ends_the_chain() {
        let root = tempfile::tempdir().expect("root");
        let cfg = root.path().join("gateway.yaml");
        std::fs::write(&cfg, "a: 1\n").expect("config");

        let (dirs, end) = super::chain_dirs(&cfg).expect("a plain file resolves");
        let real = std::fs::canonicalize(&cfg).expect("canonical");
        assert_eq!(end, real);
        assert_eq!(dirs.len(), 1);
        assert!(dirs.contains(real.parent().expect("parent")));
    }
}
