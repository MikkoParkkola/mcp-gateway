// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Loading capability definitions from directories, and reloading them all.

use super::{
    CapabilityBackend, CapabilityDefinition, CapabilityLoader, DirectoryLoad, HashMap, Result,
    debug, definition_changed, info, validate_capability_account_binding, warn,
};

impl CapabilityBackend {
    /// Pre-register watched directories without loading any capability YAMLs.
    ///
    /// Used at startup so the file watcher (`CapabilityWatcher::start`) can
    /// see the configured directory list synchronously, before the async
    /// `load_from_directory` task has had a chance to push paths via
    /// the loader path. Without this, the watcher races the loader and
    /// logs "No capability directories to watch" because the spawned
    /// loader has not yet populated `self.directories`.
    ///
    /// Duplicates are skipped; safe to call repeatedly.
    pub fn register_directories(&self, paths: &[String]) {
        let mut dirs = self.directories.write();
        for path in paths {
            if !dirs.contains(path) {
                dirs.push(path.clone());
            }
        }
    }

    /// Load capabilities from a directory
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be loaded.
    pub async fn load_from_directory(&self, path: &str) -> Result<usize> {
        Ok(self.load_from_directory_reporting(path).await?.admitted)
    }

    /// Load a directory and REPORT, rather than only log, every capability the
    /// account admission gate refused.
    ///
    /// `load_from_directory` keeps its log-and-drop behaviour for the hot-reload
    /// and account-less paths. Startup uses this variant so an invalid
    /// `auth.account` binding present in the INITIAL catalogue can be turned
    /// into a startup failure instead of a warning behind a serving listener.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory itself cannot be loaded. A refused
    /// capability is not an error here — it is reported in
    /// [`DirectoryLoad::rejected`] so the caller decides.
    pub async fn load_from_directory_reporting(&self, path: &str) -> Result<DirectoryLoad> {
        let loaded = CapabilityLoader::load_directory_with_paths(path).await?;
        let mut report = DirectoryLoad {
            admitted: loaded.len(),
            rejected: Vec::new(),
        };

        // Register directory for future hot-reloads.
        {
            let mut dirs = self.directories.write();
            if !dirs.contains(&path.to_string()) {
                dirs.push(path.to_string());
            }
        }

        // Upsert each capability into the indexed store, through the account
        // admission gate. A refused capability is LOGGED and dropped rather
        // than published: the operator gets a named error, and no caller gets a
        // tool whose account reference cannot resolve.
        for (file, cap) in loaded {
            let capability = cap.name.clone();
            if let Err(error) = self.admit_from(file, cap) {
                warn!(
                    backend = %self.name,
                    capability = %capability,
                    error = %error,
                    "Capability refused: its account binding does not resolve"
                );
                report.admitted -= 1;
                self.note_refused(&capability);
                report.rejected.push(format!("{capability}: {error}"));
            }
            tokio::task::yield_now().await;
        }

        info!(backend = %self.name, count = report.admitted, path = path, "Loaded capabilities");
        Ok(report)
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
        let dirs: Vec<String> = self.directories.read().clone();

        if dirs.is_empty() {
            debug!(backend = %self.name, "No directories to reload");
            return Ok(0);
        }

        let mut paths = Vec::new();
        let mut total = 0;
        // A directory that could not be read leaves the catalogue partial:
        // its capabilities are missing from this load, not deleted.
        let mut partial = false;

        for dir in &dirs {
            match CapabilityLoader::load_directory_with_paths(dir).await {
                Ok(loaded) => {
                    total += loaded.len();
                    paths.extend(loaded);
                }
                Err(e) => {
                    partial = true;
                    warn!(backend = %self.name, directory = %dir, error = %e, "Failed to reload directory");
                }
            }
        }

        // The same admission gate the initial load applies.
        let (mut admitted, mut trusted) = (Vec::with_capacity(paths.len()), Vec::new());
        let mut refused = std::collections::HashSet::new();
        for (file, cap) in paths {
            match validate_capability_account_binding(&cap, self.executor.account_strategies()) {
                Ok(()) => {
                    trusted.push((file, cap.name.clone()));
                    admitted.push(cap);
                }
                Err(error) => {
                    total -= 1;
                    refused.insert(cap.name.clone());
                    warn!(
                        backend = %self.name,
                        capability = %cap.name,
                        error = %error,
                        "Capability refused on reload: its account binding does not resolve"
                    );
                }
            }
        }

        // Atomic swap: rebuild index and tool cache in one write lock, then
        // bump the shared policy epoch while that lock is still held.
        {
            let mut caps = self.capabilities.write();
            let incoming: HashMap<&str, &CapabilityDefinition> =
                admitted.iter().map(|c| (c.name.as_str(), c)).collect();
            // Revoke the in-flight calls of a capability that is gone OR edited,
            // and stop its children: a call holding the old definition must not
            // start or replace a child under the new one.
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
            caps.settle_absent(refused);
            // With the swap, under the same lock: `catalogue_snapshot` never
            // sees one without the other.
            self.set_catalogue_partial(partial);
            self.bump_catalogue_generation(&caps);
            self.executor.bump_policy_epoch();
            self.executor.stop_unloaded_mcp(&|name| {
                !revoked.contains(name) && caps.index.contains_key(name)
            });
        }
        self.catalogue_changed();
        self.note_admitted(trusted, !partial);

        info!(backend = %self.name, count = total, directories = dirs.len(), "Hot-reloaded capabilities");
        Ok(total)
    }
}
