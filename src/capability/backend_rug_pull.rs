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
        // it keeps the name its earlier record took from the same path, for
        // display only: another file may have been admitted under it since.
        let mut admitted = Vec::with_capacity(detected.len());
        for record in &mut detected {
            // Only an admitted file is recorded: its path, not a name some
            // other file may also hold, is what is trusted.
            let loaded = self.loaded_from.read().get(&record.file).cloned();
            admitted.push(loaded.clone());
            record.loaded_as = loaded.or_else(|| {
                let state = self.rug_pull_state.read();
                state
                    .get(&record.file)
                    .and_then(|old| old.loaded_as.clone())
            });
        }
        for (record, admitted) in detected.iter().zip(&admitted) {
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
            // Only the capability this file is admitted as now is unloaded: a
            // file not admitted holds nothing, and its declared name, or the
            // name an earlier record kept, could be another file's now.
            if let Some(trusted) = admitted.as_deref() {
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
    #[cfg(feature = "webui")]
    pub(crate) fn current_mismatches(&self) -> Mismatches {
        let mut mismatches = Mismatches::default();
        for record in self.rug_pull_records() {
            let content = match std::fs::read_to_string(&record.file) {
                Ok(content) => content,
                // Gone: nothing is left to decide about.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    self.clear_rug_pull_if(&record.file, &record.actual);
                    continue;
                }
                // Unreadable is not resolved: the record stays, and the
                // list is incomplete until the file reads again.
                Err(_) => {
                    mismatches.incomplete = true;
                    continue;
                }
            };
            let actual = compute_capability_hash(&content);
            // Matching the pin these bytes declare (restored, or re-pinned
            // by an admin) or declaring none resolves it; the pin recorded
            // at detection is the changed bytes' own and decides nothing.
            match declared_pin(&content) {
                Ok(pin)
                    if pin
                        .as_deref()
                        .is_none_or(|p| p.eq_ignore_ascii_case(&actual)) =>
                {
                    self.clear_rug_pull_if(&record.file, &record.actual);
                    continue;
                }
                Ok(_) => {}
                // Garbled bytes resolve nothing: the record stays, and its
                // summary cannot be built, so the list is incomplete.
                Err(()) => {
                    mismatches.incomplete = true;
                    continue;
                }
            }
            mismatches.changes.push((record, content, actual));
        }
        mismatches
    }

    /// Admit `capability`, loaded from `file`, and on success record the
    /// file as the one it was loaded from: only an admitted file is trusted.
    pub(super) fn admit_from(
        &self,
        file: String,
        capability: super::CapabilityDefinition,
    ) -> crate::Result<()> {
        let name = capability.name.clone();
        self.register_capability(capability)?;
        self.loaded_from.write().insert(file, name);
        Ok(())
    }

    /// Record a reload's admitted files. A full reload replaces the map; a
    /// partial one only adds, keeping what it did not read.
    pub(super) fn note_admitted(&self, admitted: Vec<(String, String)>, replace: bool) {
        let mut names = self.loaded_from.write();
        if replace {
            names.clear();
        }
        names.extend(admitted);
    }
}

#[cfg(test)]
#[path = "backend_rug_pull_tests.rs"]
mod tests;

use std::path::Path;

/// What reconciling the pin mismatches found.
#[cfg(feature = "webui")]
#[derive(Debug, Default)]
pub(crate) struct Mismatches {
    /// Each mismatch still on disk: its record, the bytes read and their hash.
    pub(crate) changes: Vec<(RugPullRecord, String, String)>,
    /// A recorded file could not be read: the list is missing it.
    pub(crate) incomplete: bool,
}

/// The `sha256:` pin a capability file declares: `Ok(None)` for none,
/// `Err(())` when the bytes do not parse or the pin is not a string, which
/// says nothing either way.
fn declared_pin(content: &str) -> Result<Option<String>, ()> {
    let parsed = crate::yaml::from_str::<crate::yaml::Value>(content).map_err(|_| ())?;
    match parsed.get("sha256") {
        // A pin spelled so the key reads differently (a tag, say) is not "no
        // pin": none only when the text never names one.
        None if !content.contains("sha256") => Ok(None),
        None => Err(()),
        Some(pin) => pin.as_str().map(|pin| Some(pin.to_string())).ok_or(()),
    }
}

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
        let Ok(Some(expected)) = declared_pin(&content) else {
            continue;
        };
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
