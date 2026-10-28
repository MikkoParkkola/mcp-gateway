// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rug-pull detection for the capability backend (split from `backend.rs`).

use tracing::warn;

use super::{CapabilityBackend, RugPullRecord, compute_capability_hash};

impl CapabilityBackend {
    /// Scan every watched directory for capability YAMLs whose embedded
    /// `sha256:` pin no longer matches the on-disk content, and quarantine
    /// any mismatches as rug-pull events.
    ///
    /// Called by the file watcher on every debounced change event (before
    /// the normal `reload()`) so a tampered capability is unloaded loudly
    /// instead of silently skipped by the loader.
    ///
    /// Returns the list of newly-detected rug-pull records.
    pub async fn detect_rug_pulls(&self) -> Vec<RugPullRecord> {
        let dirs: Vec<String> = self.directories.read().clone();
        let mut detected = Vec::new();

        for dir in &dirs {
            detect_rug_pulls_in_dir(Path::new(dir), &mut detected).await;
        }

        // The name each file was trusted as comes from its path, which the
        // changed bytes cannot choose: never from the pin they still declare.
        // A reload drops a refused file from the map, so a later change to
        // it keeps the name its earlier record took from the same path.
        for record in &mut detected {
            let loaded = self.loaded_from.read().get(&record.file).cloned();
            record.loaded_as = loaded.or_else(|| {
                let state = self.rug_pull_state.read();
                state
                    .get(&record.file)
                    .and_then(|old| old.loaded_as.clone())
            });
        }
        for record in &detected {
            // The changed bytes chose `capability` and `expected`, so neither
            // is logged. The trusted name passed the loader's name rule; the
            // path is escaped; `actual` is the gateway's own hash.
            warn!(
                backend = %self.name,
                trusted = ?record.loaded_as,
                file = ?record.file,
                actual = %record.actual,
                "RUG-PULL DETECTED: capability YAML sha256 pin mismatch — unloading",
            );
            // Only the capability this file was trusted as is unloaded: a file
            // never loaded holds nothing, and its declared name could be any
            // other capability's.
            if let Some(trusted) = record.loaded_as.as_deref() {
                self.unload_capability(trusted);
            }
            self.mark_rug_pull(record.clone());
        }

        detected
    }

    /// Clear the record for `file` only if its observed hash is still
    /// `actual`, so a newer mismatch found meanwhile is never dropped.
    /// Returns whether a record was cleared.
    pub fn clear_rug_pull_if(&self, file: &str, actual: &str) -> bool {
        let mut state = self.rug_pull_state.write();
        let current = state
            .get(file)
            .is_some_and(|record| record.actual == actual);
        if current {
            state.remove(file);
        }
        current
    }

    /// Each pin mismatch still on disk, with its bytes read once and their
    /// hash. A file that is gone, or whose bytes match their pin again, has
    /// its record cleared (only while that record is the one read) and is
    /// left out. Blocking: call it off the async workers.
    pub(crate) fn current_mismatches(&self) -> Vec<(RugPullRecord, String, String)> {
        let mut mismatches = Vec::new();
        for record in self.rug_pull_records() {
            let Ok(content) = std::fs::read_to_string(&record.file) else {
                self.clear_rug_pull_if(&record.file, &record.actual);
                continue;
            };
            let actual = compute_capability_hash(&content);
            if actual.eq_ignore_ascii_case(&record.expected) {
                self.clear_rug_pull_if(&record.file, &record.actual);
                continue;
            }
            mismatches.push((record, content, actual));
        }
        mismatches
    }

    /// Record the name each loaded file holds, its pin having matched, and
    /// hand the capabilities on. A full reload replaces the map; a single
    /// directory or a partial reload only adds, keeping what it did not read.
    pub(super) fn note_loaded(
        &self,
        loaded: Vec<(String, super::CapabilityDefinition)>,
        replace: bool,
    ) -> Vec<super::CapabilityDefinition> {
        let mut names = self.loaded_from.write();
        if replace {
            names.clear();
        }
        loaded
            .into_iter()
            .map(|(path, capability)| {
                names.insert(path, capability.name.clone());
                capability
            })
            .collect()
    }
}

#[cfg(test)]
#[path = "backend_rug_pull_tests.rs"]
mod tests;

use std::path::Path;

/// Recursively walk a directory and report any YAML file whose embedded
/// `sha256:` pin does not match the file's current content.
async fn detect_rug_pulls_in_dir(dir: &Path, out: &mut Vec<RugPullRecord>) {
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
        return;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if path
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with('.'))
        {
            continue;
        }
        if path.is_dir() {
            Box::pin(detect_rug_pulls_in_dir(&path, out)).await;
            continue;
        }
        if !path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
            continue;
        }
        let Ok(content) = tokio::fs::read_to_string(&path).await else {
            continue;
        };
        // Extract embedded pin via lightweight deserialisation. A parse error
        // here is not a rug-pull (the loader will surface it); we only care
        // about files that self-declare a pin that no longer matches.
        let pinned: Option<String> = crate::yaml::from_str::<crate::yaml::Value>(&content)
            .ok()
            .and_then(|v| {
                v.get("sha256")
                    .and_then(crate::yaml::Value::as_str)
                    .map(str::to_string)
            });
        let Some(expected) = pinned else { continue };
        let actual = compute_capability_hash(&content);
        if !expected.eq_ignore_ascii_case(&actual) {
            // Recover the capability name the same way parse_capability_file does.
            let name = crate::yaml::from_str::<crate::yaml::Value>(&content)
                .ok()
                .and_then(|v| {
                    v.get("name")
                        .and_then(crate::yaml::Value::as_str)
                        .map(str::to_string)
                })
                .or_else(|| path.file_stem().map(|s| s.to_string_lossy().into_owned()))
                .unwrap_or_default();
            out.push(RugPullRecord {
                capability: name,
                file: path.display().to_string(),
                expected,
                actual,
                loaded_as: None,
            });
        }
    }
}
