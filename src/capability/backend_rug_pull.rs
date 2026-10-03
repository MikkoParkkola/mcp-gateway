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

        for record in &detected {
            warn!(
                backend = %self.name,
                capability = %record.capability,
                file = %record.file,
                expected = %record.expected,
                actual = %record.actual,
                "RUG-PULL DETECTED: capability YAML sha256 pin mismatch — unloading",
            );
            self.unload_capability(&record.capability);
            self.mark_rug_pull(record.clone());
        }

        detected
    }
}

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
        let pinned: Option<String> = serde_yaml::from_str::<serde_yaml::Value>(&content)
            .ok()
            .and_then(|v| {
                v.get("sha256")
                    .and_then(serde_yaml::Value::as_str)
                    .map(str::to_string)
            });
        let Some(expected) = pinned else { continue };
        let actual = compute_capability_hash(&content);
        if !expected.eq_ignore_ascii_case(&actual) {
            // Recover the capability name the same way parse_capability_file does.
            let name = serde_yaml::from_str::<serde_yaml::Value>(&content)
                .ok()
                .and_then(|v| {
                    v.get("name")
                        .and_then(serde_yaml::Value::as_str)
                        .map(str::to_string)
                })
                .or_else(|| path.file_stem().map(|s| s.to_string_lossy().into_owned()))
                .unwrap_or_default();
            out.push(RugPullRecord {
                capability: name,
                file: path.display().to_string(),
                expected,
                actual,
            });
        }
    }
}
