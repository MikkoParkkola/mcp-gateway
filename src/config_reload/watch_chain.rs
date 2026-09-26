// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Keeping the config watcher on the directories the config's link chain
//! actually runs through (#453).
//!
//! Red-first: signatures only. The chain is not walked, nothing is rewatched,
//! and the watcher keeps the directories it watched at startup.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use notify::RecommendedWatcher;
use parking_lot::Mutex;

use super::ReloadTrigger;

/// The directories a config's link chain runs through, and where it ends.
///
/// # Errors
///
/// Never, yet.
#[cfg_attr(not(test), expect(dead_code, reason = "red-first stub"))]
pub(super) fn chain_dirs(named: &Path) -> std::io::Result<(BTreeSet<PathBuf>, PathBuf)> {
    Ok((BTreeSet::new(), named.to_path_buf()))
}

/// The watcher, kept alive; no ledger of watched directories yet.
pub(super) struct ChainWatch {
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "held to keep the watcher alive")
    )]
    pub(super) watcher: Mutex<Option<RecommendedWatcher>>,
}

impl ChainWatch {
    pub(super) fn new(watcher: RecommendedWatcher, _protected: BTreeSet<PathBuf>) -> Arc<Self> {
        Arc::new(Self {
            watcher: Mutex::new(Some(watcher)),
        })
    }

    #[cfg(test)]
    pub(super) fn watched(&self) -> BTreeSet<PathBuf> {
        BTreeSet::new()
    }
}

/// Returns at once: nothing follows the chain yet.
pub(super) fn spawn_rewatch_task(
    _named: PathBuf,
    _chain: Arc<ChainWatch>,
    _wake: tokio::sync::watch::Receiver<()>,
    _reload: tokio::sync::mpsc::Sender<ReloadTrigger>,
    _shutdown: tokio::sync::broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async {})
}

#[cfg(all(test, unix))]
#[path = "watch_chain_tests.rs"]
mod tests;
