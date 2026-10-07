// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What each capability directory's last read proved (MIK-8050).
//!
//! A directory that failed to read, or in which a capability file failed to
//! load, proves nothing about what it holds: its capabilities are kept as
//! unread, so their event subscriptions survive. Only a capability absent
//! from a directory that read cleanly is proven deleted. Reads and their
//! publication are serialized by `load_order`, so the published catalogue
//! and this state always describe the same reads, in order.

use std::collections::{BTreeMap, BTreeSet};

use tracing::{info, warn};

use super::{CapabilityBackend, CapabilityDefinition, CapabilityLoader, definition_changed};
use crate::Result;
use crate::capability::validate_capability_account_binding;

/// One directory's last read.
#[derive(Debug, Default)]
pub(crate) struct DirState {
    /// The capabilities its last read admitted. A read that failed leaves it
    /// as it was; a read in which a file failed adds to it.
    last_read: BTreeSet<String>,
    /// Whether its latest read failed, or a file in it failed to load.
    failed: bool,
    /// Whether any read of it has been clean (every file loaded) in this
    /// process.
    ever_loaded: bool,
}

/// What the current catalogue proves, read with it under one lock.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct LoadState {
    /// No directory failed.
    pub(crate) complete: bool,
    /// The capabilities of failed directories, as their last reads saw them.
    pub(crate) unread: BTreeSet<String>,
    /// A failed directory has never loaded: what it holds is unknown.
    pub(crate) never_loaded: bool,
}

impl LoadState {
    /// Whether a stored subscription to the unoffered event type `name` is
    /// kept: its capability may still exist in a directory this load could
    /// not read.
    pub(crate) fn keeps(&self, name: &str) -> bool {
        self.never_loaded
            || self
                .unread
                .iter()
                .any(|cap| name.starts_with(&format!("webhook.{cap}.")))
    }
}

/// One directory's read: its admitted capabilities and whether a file failed,
/// or `None` when the directory could not be read.
type Read = Option<(Vec<CapabilityDefinition>, BTreeSet<String>, bool)>;

impl CapabilityBackend {
    /// Record a read of `dir`. Called with the catalogue the read produced
    /// already published.
    pub(super) fn record_read(&self, dir: &str, read: Option<(BTreeSet<String>, bool)>) {
        let mut dirs = self.dirs_loaded.lock();
        let state = dirs.entry(dir.to_owned()).or_default();
        match read {
            Some((names, false)) => {
                state.last_read = names;
                state.failed = false;
                state.ever_loaded = true;
            }
            // Not a clean read: what the failed file holds is not known, so
            // a directory never read cleanly keeps every absent capability.
            Some((names, true)) => {
                state.last_read.extend(names);
                state.failed = true;
            }
            None => state.failed = true,
        }
    }

    /// What the current catalogue proves. A registered directory with no
    /// read yet counts as failed and never loaded.
    pub(crate) fn load_state(&self) -> LoadState {
        let registered = self.directories.read().clone();
        let dirs = self.dirs_loaded.lock();
        let mut state = LoadState {
            complete: true,
            ..LoadState::default()
        };
        for dir in &registered {
            match dirs.get(dir) {
                Some(read) if !read.failed => {}
                Some(read) => {
                    state.complete = false;
                    state.unread.extend(read.last_read.iter().cloned());
                    state.never_loaded |= !read.ever_loaded;
                }
                None => {
                    state.complete = false;
                    state.never_loaded = true;
                }
            }
        }
        state
    }

    /// The capabilities and what they prove, read under one lock, so a reload
    /// cannot change one without the other (MIK-8028, MIK-8050).
    pub(crate) fn catalogue_snapshot(&self) -> (Vec<CapabilityDefinition>, LoadState) {
        let caps = self.capabilities.read();
        (caps.entries.clone(), self.load_state())
    }

    /// Called once the startup scan has read every directory, before its
    /// routes are registered. A reload that published while the scan ran was
    /// followed by the scan's upserts, which cannot remove what the reload
    /// published and the scan then found deleted; one full reload replaces
    /// the catalogue wholesale (MIK-8050).
    pub(crate) async fn reload_if_reloaded_during_scan(&self) {
        if self.take_reloaded_during_scan()
            && let Err(error) = self.reload().await
        {
            warn!(backend = %self.name, %error, "the reload that ends the startup scan failed");
        }
    }

    /// Reload all capabilities from registered directories
    ///
    /// This is the hot-reload entry point. It re-reads all capability
    /// files from the registered directories and updates the registry.
    ///
    /// # Errors
    ///
    /// Returns an error if reloading fails for all directories.
    pub async fn reload(&self) -> Result<usize> {
        let _order = self.load_order.lock().await;
        let dirs: Vec<String> = self.directories.read().clone();

        if dirs.is_empty() {
            tracing::debug!(backend = %self.name, "No directories to reload");
            return Ok(0);
        }

        let mut reads: Vec<(String, Read)> = Vec::with_capacity(dirs.len());
        for dir in &dirs {
            match CapabilityLoader::load_directory_reporting(dir).await {
                Ok((loaded, file_failed)) => {
                    // Every parsed name, refused or not: a refused capability
                    // is not proven deleted (MIK-8050).
                    let names = loaded.iter().map(|c| c.name.clone()).collect();
                    let (admitted, failed) = self.admit(loaded, file_failed);
                    reads.push((dir.clone(), Some((admitted, names, failed))));
                }
                Err(e) => {
                    warn!(backend = %self.name, directory = %dir, error = %e, "Failed to reload directory");
                    reads.push((dir.clone(), None));
                }
            }
        }
        let admitted: Vec<CapabilityDefinition> = reads
            .iter()
            .filter_map(|(_, read)| read.as_ref())
            .flat_map(|(caps, _, _)| caps.iter().cloned())
            .collect();
        let total = admitted.len();

        // Atomic swap: rebuild index and tool cache in one write lock, then
        // bump the shared policy epoch while that lock is still held.
        {
            let mut caps = self.capabilities.write();
            let incoming: std::collections::HashMap<&str, &CapabilityDefinition> =
                admitted.iter().map(|c| (c.name.as_str(), c)).collect();
            // Revoke the in-flight calls of a capability that is gone OR edited,
            // and stop its children: a call holding the old definition must not
            // start or replace a child under the new one (MIK-7870, MIK-7925).
            let mut revoked = std::collections::HashSet::new();
            for (name, &pos) in &caps.index {
                if incoming
                    .get(name.as_str())
                    .is_none_or(|new| definition_changed(&caps.entries[pos], new))
                {
                    self.executor.bump_mcp_generation(name);
                    revoked.insert(name.clone());
                }
            }
            caps.replace_all(admitted);
            // With the swap, under the same lock: `catalogue_snapshot` never
            // sees one without the other.
            for (dir, read) in reads {
                self.record_read(&dir, read.map(|(_, names, failed)| (names, failed)));
            }
            self.note_reload_during_scan();
            self.executor.bump_policy_epoch();
            self.executor.stop_unloaded_mcp(&|name| {
                !revoked.contains(name) && caps.index.contains_key(name)
            });
        }

        info!(backend = %self.name, count = total, directories = dirs.len(), "Hot-reloaded capabilities");
        if let Some(notice) = self.reload_notice.get() {
            let _ = notice.send(self.name.clone());
        }
        Ok(total)
    }

    /// Where every successful reload announces itself; set once, by the
    /// capability watcher.
    pub(crate) fn set_reload_notice(&self, notice: tokio::sync::mpsc::UnboundedSender<String>) {
        let _ = self.reload_notice.set(notice);
    }

    /// The same admission gate the initial load applies, per directory: a
    /// refused capability is not proven deleted, so its directory reads as
    /// failed for the keep rule (MIK-8050).
    fn admit(
        &self,
        loaded: Vec<CapabilityDefinition>,
        file_failed: bool,
    ) -> (Vec<CapabilityDefinition>, bool) {
        let mut failed = file_failed;
        let mut admitted = Vec::with_capacity(loaded.len());
        for cap in loaded {
            match validate_capability_account_binding(&cap, self.executor.account_strategies()) {
                Ok(()) => admitted.push(cap),
                Err(error) => {
                    failed = true;
                    warn!(
                        backend = %self.name,
                        capability = %cap.name,
                        error = %error,
                        "Capability refused on reload: its account binding does not resolve"
                    );
                }
            }
        }
        (admitted, failed)
    }
}

/// The directory map type the backend holds.
pub(super) type DirsLoaded = parking_lot::Mutex<BTreeMap<String, DirState>>;
