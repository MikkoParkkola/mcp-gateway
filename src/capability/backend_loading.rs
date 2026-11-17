// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Loading capability definitions from directories, and reloading them all.

use super::{
    CapabilityBackend, CapabilityDefinition, CapabilityLoader, DirectoryLoad, HashMap, Result,
    debug, definition_changed, info, part_from, validate_capability_account_binding, warn,
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
            admitted: loaded.files.len(),
            rejected: Vec::new(),
            unreadable: loaded
                .failures
                .iter()
                .map(|failure| failure.path.clone())
                .collect(),
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
        // A GraphQL or JSON-RPC provider on a paced host fails loading, like a
        // file the loader refuses: judged on the whole catalogue these files
        // join, so the order they are read in decides nothing.
        let intervals = {
            let caps = self.capabilities.read();
            crate::capability::pacing::declared_intervals(
                caps.entries
                    .iter()
                    .chain(loaded.files.iter().map(|file| &file.definition)),
            )
        };
        for file in loaded.files {
            let capability = file.definition.name.clone();
            if let Some(reason) =
                crate::capability::pacing::unpaced_protocol_refusal(&file.definition, &intervals)
            {
                warn!(backend = %self.name, capability = %capability, error = %reason, "Failed to load capability");
                report.admitted -= 1;
                report.unreadable.push(file.path.clone());
                continue;
            }
            // Digest outside the catalogue lock. The bytes are not stored.
            let source = self.source_of(&file.path, &file.bytes);
            if let Err(error) = self.admit_from(file.path, file.definition, Some(source)) {
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
        // Held through the publish; this reload's log lines are written after
        // it is released, so a blocked log write never holds up the next
        // catalogue operation.
        let operation = self.lock_operation().await;
        let dirs: Vec<String> = self.directories.read().clone();
        let mut failed_dirs: Vec<(String, String)> = Vec::new();

        // Before any note, so this reload's set is not the one still stored
        // on the catalogue. Install below is what stores it. An empty
        // directory list still installs: the fresh set replaces a partial
        // one left by an earlier operation.
        self.begin_reload_coverage();

        let mut loaded_files = Vec::new();
        let mut total = 0;
        // A directory that could not be read leaves the catalogue partial:
        // its capabilities are missing from this load, not deleted.
        // A file that could not be read does not: the directory was listed,
        // and that file is simply not served. Coverage hears both.
        let mut partial = false;

        for dir in &dirs {
            match CapabilityLoader::load_directory_with_paths(dir).await {
                Ok(loaded) => {
                    total += loaded.files.len();
                    for failure in &loaded.failures {
                        self.note_unreadable(&failure.path);
                    }
                    loaded_files.extend(loaded.files);
                }
                Err(e) => {
                    partial = true;
                    self.note_unreadable(dir);
                    failed_dirs.push((dir.clone(), e.to_string()));
                }
            }
        }

        // The same admission gate the initial load applies.
        let Admission {
            admitted,
            trusted,
            refused,
            refused_logs,
        } = self.admit_reloaded(loaded_files, &mut total);

        // Atomic swap: rebuild index and tool cache in one write lock, then
        // bump the shared policy epoch while that lock is still held.
        // The seq and the snapshot are taken here, after install, and the
        // publish below runs only once this guard has dropped.
        let (seq, part) = {
            let mut caps = self.capabilities.write();
            let incoming: HashMap<&str, &CapabilityDefinition> = admitted
                .iter()
                .map(|(cap, _)| (cap.name.as_str(), cap))
                .collect();
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
            // A row holds the swap here, before the catalogue is replaced,
            // while this write lock is still held.
            #[cfg(test)]
            super::super::op_gate::reach(super::super::op_gate::Step::Swap);
            caps.install(admitted);
            caps.settle_absent(refused);
            crate::capability::pacing::seed_from(&caps.entries);
            // With the entries, under the same lock: the part names this
            // catalogue and the coverage of the operation that wrote it.
            caps.unread = self.recording.lock().clone();
            // With the swap, under the same lock: `catalogue_snapshot` never
            // sees one without the other.
            self.set_catalogue_partial(partial);
            self.bump_catalogue_generation(&caps);
            self.executor.bump_policy_epoch();
            self.executor.stop_unloaded_mcp(&|name| {
                !revoked.contains(name) && caps.index.contains_key(name)
            });
            // After install, still under this lock: the seq and the part name
            // the catalogue this swap wrote, not the one it replaced.
            let seq = self.alloc_seq();
            let part = part_from(&caps);
            (seq, part)
        };
        // The catalogue lock is released. A row holds this gap. The publish
        // runs with that lock free; the operation lock is still held.
        #[cfg(test)]
        super::super::op_gate::reach(super::super::op_gate::Step::BeforePublish);
        self.publish_revision(seq, part);
        self.catalogue_changed();
        self.note_admitted(trusted, !partial);
        drop(operation);

        if dirs.is_empty() {
            debug!(backend = %self.name, "No directories to reload");
        }
        for (dir, error) in &failed_dirs {
            warn!(backend = %self.name, directory = %dir, error = %error, "Failed to reload directory");
        }
        for (capability, error) in &refused_logs {
            warn!(
                backend = %self.name,
                capability = %capability,
                error = %error,
                "Capability refused on reload: its account binding does not resolve"
            );
        }
        info!(backend = %self.name, count = total, directories = dirs.len(), "Hot-reloaded capabilities");
        Ok(total)
    }
}

/// What a reload's admission gate let through, and what it refused.
struct Admission {
    admitted: Vec<(CapabilityDefinition, Option<super::indexed::ServedSource>)>,
    /// Each admitted file's path and capability name.
    trusted: Vec<(String, String)>,
    refused: std::collections::HashSet<String>,
    /// Each account-binding refusal's capability and error, logged after the
    /// catalogue lock is released.
    refused_logs: Vec<(String, String)>,
}

impl CapabilityBackend {
    /// The admission gate the initial load applies, on a reload's files:
    /// GraphQL and JSON-RPC providers on a paced host, then account bindings.
    /// `total` drops by one for each file refused.
    fn admit_reloaded(
        &self,
        mut files: Vec<crate::capability::loader::LoadedCapability>,
        total: &mut usize,
    ) -> Admission {
        let mut gate = Admission {
            admitted: Vec::with_capacity(files.len()),
            trusted: Vec::new(),
            refused: std::collections::HashSet::new(),
            refused_logs: Vec::new(),
        };
        *total -= self.drop_unpaced_protocols(&mut files, &mut gate.refused);
        for file in files {
            match validate_capability_account_binding(
                &file.definition,
                self.executor.account_strategies(),
            ) {
                Ok(()) => {
                    let source = self.source_of(&file.path, &file.bytes);
                    gate.trusted.push((file.path, file.definition.name.clone()));
                    gate.admitted.push((file.definition, Some(source)));
                }
                Err(error) => {
                    *total -= 1;
                    gate.refused.insert(file.definition.name.clone());
                    gate.refused_logs
                        .push((file.definition.name.clone(), error.to_string()));
                }
            }
        }
        gate
    }

    /// Take out of `files` every capability that puts a GraphQL or JSON-RPC
    /// provider on a host the new catalogue paces, logging each at WARN and
    /// adding its name to `refused`; return how many. Judged on the whole
    /// catalogue, so file order decides nothing.
    fn drop_unpaced_protocols(
        &self,
        files: &mut Vec<crate::capability::loader::LoadedCapability>,
        refused: &mut std::collections::HashSet<String>,
    ) -> usize {
        let intervals = crate::capability::pacing::declared_intervals(
            files.iter().map(|file| &file.definition),
        );
        let before = files.len();
        files.retain(|file| {
            let Some(reason) =
                crate::capability::pacing::unpaced_protocol_refusal(&file.definition, &intervals)
            else {
                return true;
            };
            warn!(
                backend = %self.name,
                capability = %file.definition.name,
                error = %reason,
                "Capability refused on reload"
            );
            refused.insert(file.definition.name.clone());
            false
        });
        before - files.len()
    }
}
