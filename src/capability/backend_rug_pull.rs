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

        // Before anything unloads: the name each file was trusted as is the
        // loaded capability its still-declared pin verified, kept across a
        // later change to the same file.
        for record in &mut detected {
            record.loaded_as = self.trusted_name(&record.expected).or_else(|| {
                let state = self.rug_pull_state.read();
                state
                    .get(&record.file)
                    .and_then(|old| old.loaded_as.clone())
            });
        }
        for record in &detected {
            // The changed bytes chose `capability` and `expected`: neither is
            // logged raw. The trusted name passed the loader's name rule.
            warn!(
                backend = %self.name,
                trusted = ?record.loaded_as,
                file = ?record.file,
                expected = ?record.expected,
                actual = %record.actual,
                "RUG-PULL DETECTED: capability YAML sha256 pin mismatch — unloading",
            );
            self.unload_capability(record.loaded_as.as_deref().unwrap_or(&record.capability));
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

    /// The loaded capability whose own pin is `expected`.
    fn trusted_name(&self, expected: &str) -> Option<String> {
        let caps = self.capabilities.read();
        caps.entries
            .iter()
            .find(|cap| {
                cap.sha256
                    .as_deref()
                    .is_some_and(|pin| pin.eq_ignore_ascii_case(expected))
            })
            .map(|cap| cap.name.clone())
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
