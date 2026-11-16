// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Recorded config versions and the reload events that produced them.

#![allow(
    dead_code,
    reason = "callers arrive in a later slice; the store is not wired yet"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::config_reload::revision::RawInputs;

/// Where a reload event came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Source {
    Start,
    File,
    Ui { who: String },
    Restore { who: String },
}

/// Whether the reload was applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Outcome {
    Applied,
    Refused,
}

/// One file as it stood in a stored version. `bytes` is `None` when that version had no such file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StoredFile {
    pub path: String,
    pub bytes: Option<Vec<u8>>,
}

/// One kept version of the config files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Snapshot {
    pub revision: String,
    pub at: u64,
    pub files: Vec<StoredFile>,
    pub pending_restart: Vec<String>,
}

/// A revision that is still the one the process is running.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StillRunning {
    pub revision: String,
    pub since: u64,
}

/// One reload attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Event {
    pub at: u64,
    pub source: Source,
    pub outcome: Outcome,
    pub revision: Option<String>,
    pub unchanged: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub still_running: Option<StillRunning>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<u64>,
    #[serde(default)]
    pub attempted_diff: Option<String>,
}

/// How much history `open` is willing to keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Bounds {
    pub snapshots: usize,
    pub snapshot_bytes: usize,
    pub events: usize,
    pub event_bytes: usize,
    pub max_age_secs: u64,
}

impl Default for Bounds {
    fn default() -> Self {
        Self {
            snapshots: 100,
            snapshot_bytes: 64 * 1024 * 1024,
            events: 2_000,
            event_bytes: 8 * 1024 * 1024,
            max_age_secs: 60 * 24 * 3600,
        }
    }
}

/// What `lookup` found for a revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Lookup {
    Kept(Snapshot),
    NoLongerKept,
    Unknown,
}

#[derive(Debug, Default, Serialize)]
struct State {
    snapshots: Vec<Snapshot>,
    events: Vec<Event>,
}

/// In-memory history of config versions. The file under `data_dir` is not touched.
pub(crate) struct ConfigHistory {
    data_dir: PathBuf,
    bounds: Bounds,
    inner: parking_lot::Mutex<State>,
}

impl ConfigHistory {
    pub(crate) const FILE: &'static str = "config-history.json";

    /// Start a store for `data_dir`. Any file already there is left unread.
    pub(crate) fn open(data_dir: &Path, bounds: Bounds, now: u64) -> Self {
        let _ = now;
        Self {
            data_dir: data_dir.to_path_buf(),
            bounds,
            inner: parking_lot::Mutex::new(State::default()),
        }
    }

    /// Remember `event` and, when present, `snapshot`, unless a kept version
    /// already holds the same files. Old snapshots fall away by age alone.
    pub(crate) fn record(&self, event: Event, snapshot: Option<Snapshot>, running: &str, now: u64) {
        let _ = (running, &self.data_dir);
        let mut state = self.inner.lock();
        if let Some(snapshot) = snapshot
            && !state
                .snapshots
                .iter()
                .any(|kept| kept.files == snapshot.files)
        {
            state.snapshots.push(snapshot);
        }
        state.events.push(event);
        let max_age = self.bounds.max_age_secs;
        state
            .snapshots
            .retain(|snapshot| now.saturating_sub(snapshot.at) <= max_age);
    }

    pub(crate) fn events(&self) -> Vec<Event> {
        self.inner.lock().events.clone()
    }

    /// Kept versions, oldest first.
    pub(crate) fn snapshots(&self) -> Vec<Snapshot> {
        self.inner.lock().snapshots.clone()
    }

    /// `Kept` when `revision` is still in memory. Anything else is `Unknown`.
    pub(crate) fn lookup(&self, revision: &str) -> Lookup {
        let state = self.inner.lock();
        if let Some(snapshot) = state
            .snapshots
            .iter()
            .find(|snapshot| snapshot.revision == revision)
        {
            return Lookup::Kept(snapshot.clone());
        }
        Lookup::Unknown
    }

    /// Write the whole store to `data_dir` as it stands: in place, with the
    /// process's default mode.
    fn save_as_is(&self) {
        let state = self.inner.lock();
        if let Ok(json) = serde_json::to_vec(&*state) {
            let _ = std::fs::write(self.data_dir.join(Self::FILE), json);
        }
    }
}

/// The store a `LiveConfig` records its publishes into, with the paths of the
/// files a version holds (the publish carries their bytes, not their names).
pub(crate) struct HistoryHook {
    pub store: Arc<ConfigHistory>,
    pub config_path: String,
    pub grants_path: Option<String>,
}

impl HistoryHook {
    /// Record one applied publish under `revision` and save the store. The
    /// stub records every publish as a file reload, keeps gateway.yaml and
    /// every value the load consumed, and no restart fields.
    pub(crate) fn on_publish(&self, raw: &RawInputs, revision: &str, now: u64) {
        let snapshot = Snapshot {
            revision: revision.to_string(),
            at: now,
            files: std::iter::once(StoredFile {
                path: self.config_path.clone(),
                bytes: Some(raw.gateway_yaml.clone()),
            })
            .chain(raw.consumed.iter().map(|input| StoredFile {
                path: input.name.clone(),
                bytes: Some(input.value.clone()),
            }))
            .collect(),
            pending_restart: Vec::new(),
        };
        let event = Event {
            at: now,
            source: Source::File,
            outcome: Outcome::Applied,
            revision: Some(revision.to_string()),
            unchanged: false,
            still_running: None,
            location: None,
            attempted_diff: None,
        };
        self.store.record(event, Some(snapshot), revision, now);
        self.store.save_as_is();
    }
}

#[cfg(test)]
#[path = "history_record_tests.rs"]
mod record_tests;
#[cfg(test)]
#[path = "history_tests.rs"]
mod tests;
