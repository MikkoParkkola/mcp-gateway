// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What the capability backend lists, and the one place a change of it is
//! announced: a reload's env overlay, or a login that expired (MIK-7940).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::CapabilityBackend;
use crate::backend::BackendRegistry;

/// A stored token can change on disk without a notice: the watch looks again
/// at least this often.
const RECHECK: Duration = Duration::from_secs(300);

impl CapabilityBackend {
    /// The names clients are shown now, sorted. A change between two calls is
    /// a change of what `tools/list` answers.
    pub fn listed_names(&self) -> Vec<String> {
        let mut seen = HashMap::new();
        let mut names: Vec<String> = self
            .capabilities
            .read()
            .entries
            .iter()
            .filter(|entry| {
                self.executor
                    .missing_credential(&entry.auth, &mut seen)
                    .is_none()
            })
            .map(|entry| entry.name.clone())
            .collect();
        names.sort();
        names
    }

    /// Run `change` (for example publishing a new env overlay) and announce
    /// `tools/list_changed` when what is listed now differs from what was last
    /// announced. One lock covers the comparison, `change` and the record, so a
    /// transition seen by two observers is announced once.
    pub(crate) fn announce_listing_change(
        &self,
        registry: &BackendRegistry,
        change: impl FnOnce(),
    ) -> bool {
        let mut last = self.listing.lock();
        let before = last.take().unwrap_or_else(|| self.listed_names());
        change();
        let now = self.listed_names();
        let changed = now != before;
        *last = Some(now);
        if changed {
            registry.nudge_catalogue(&self.name);
        }
        changed
    }

    /// The catalogue changed (a load, reload or removal): what is listed now is
    /// what clients are told next, so it is the baseline, and the watch plans
    /// again for the new entries' expiries. The change itself is announced by
    /// its path: the watcher after a reload (a quarantine unload is followed by
    /// one), [`Self::finish_initial_scan`] for the startup scan.
    pub(super) fn catalogue_changed(&self) {
        *self.listing.lock() = Some(self.listed_names());
        self.listing_wake.notify_one();
    }

    /// The startup scan loaded every directory. A client served while it ran
    /// may have listed part of it, even a tool a later directory hid again, and
    /// no reload announces its loads: mark the scan complete (readiness,
    /// MIK-7268), then announce once.
    pub(crate) fn finish_initial_scan(&self, registry: &BackendRegistry) {
        self.mark_initial_scan_complete();
        registry.nudge_catalogue_scanned(&self.name);
    }

    /// When the earliest listed `oauth:` login stops counting, if any.
    fn next_listing_expiry(&self) -> Option<u64> {
        self.capabilities
            .read()
            .entries
            .iter()
            .filter_map(|entry| self.executor.listing_expires_at(&entry.auth))
            .min()
    }

    /// Watch for logins that expire with no reload, which change the listing
    /// as surely as a key edit does (MIK-7940 #1), until `shutdown` fires.
    pub(crate) fn spawn_listing_watch(
        self: &Arc<Self>,
        registry: Arc<BackendRegistry>,
        mut shutdown: tokio::sync::broadcast::Receiver<()>,
    ) {
        let backend = Arc::clone(self);
        // The baseline an expiry is compared with: what is listed now.
        backend
            .listing
            .lock()
            .get_or_insert_with(|| backend.listed_names());
        tokio::spawn(async move {
            loop {
                let wait = backend.next_listing_expiry().map_or(RECHECK, |at| {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    // One second past the flip, so it has happened.
                    Duration::from_secs(at.saturating_sub(now) + 1).min(RECHECK)
                });
                tokio::select! {
                    _ = shutdown.recv() => return,
                    // A new entry may expire sooner: plan again.
                    () = backend.listing_wake.notified() => continue,
                    () = tokio::time::sleep(wait) => {}
                }
                if backend.announce_listing_change(&registry, || {}) {
                    tracing::info!(
                        backend = %backend.name,
                        "capability listing changed with no reload (a login expired)"
                    );
                }
            }
        });
    }
}

#[cfg(test)]
#[path = "backend_listing_tests.rs"]
mod tests;
