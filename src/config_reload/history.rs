// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Recorded config versions and the reload events that produced them.

#![allow(
    dead_code,
    reason = "callers arrive in a later slice; the store is not wired yet"
)]

use std::cell::RefCell;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

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

#[derive(Debug, Default)]
struct State {
    snapshots: Vec<Snapshot>,
    events: Vec<Event>,
}

/// In-memory history of config versions. The file under `data_dir` is not touched.
pub(crate) struct ConfigHistory {
    data_dir: PathBuf,
    bounds: Bounds,
    inner: RefCell<State>,
}

impl ConfigHistory {
    pub(crate) const FILE: &'static str = "config-history.json";

    /// Start a store for `data_dir`. Any file already there is left unread.
    pub(crate) fn open(data_dir: &Path, bounds: Bounds, now: u64) -> Self {
        let _ = now;
        Self {
            data_dir: data_dir.to_path_buf(),
            bounds,
            inner: RefCell::new(State::default()),
        }
    }

    /// Remember `event` and, when present, `snapshot`. Old snapshots fall away by age alone.
    pub(crate) fn record(&self, event: Event, snapshot: Option<Snapshot>, running: &str, now: u64) {
        let _ = (running, &self.data_dir);
        let mut state = self.inner.borrow_mut();
        if let Some(snapshot) = snapshot {
            state.snapshots.push(snapshot);
        }
        state.events.push(event);
        let max_age = self.bounds.max_age_secs;
        state
            .snapshots
            .retain(|snapshot| now.saturating_sub(snapshot.at) <= max_age);
    }

    pub(crate) fn events(&self) -> Vec<Event> {
        self.inner.borrow().events.clone()
    }

    /// Kept versions, oldest first.
    pub(crate) fn snapshots(&self) -> Vec<Snapshot> {
        self.inner.borrow().snapshots.clone()
    }

    /// `Kept` when `revision` is still in memory. Anything else is `Unknown`.
    pub(crate) fn lookup(&self, revision: &str) -> Lookup {
        let state = self.inner.borrow();
        if let Some(snapshot) = state
            .snapshots
            .iter()
            .find(|snapshot| snapshot.revision == revision)
        {
            return Lookup::Kept(snapshot.clone());
        }
        Lookup::Unknown
    }
}

#[cfg(test)]
#[path = "history_tests.rs"]
mod tests;
