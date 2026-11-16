// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Recorded config versions and the reload events that produced them.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::config_persistence::{FileMode, Symlink, write_atomic};
use crate::config_reload::revision::RawInputs;

/// Where a reload event came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Source {
    Start,
    File,
    Ui { who: String },
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
            snapshots: 50,
            snapshot_bytes: 32 * 1024 * 1024,
            events: 1_000,
            event_bytes: 4 * 1024 * 1024,
            max_age_secs: 30 * 24 * 3600,
        }
    }
}

/// What `lookup` found for a revision.
#[cfg_attr(
    not(test),
    allow(dead_code, reason = "read by the history page, a later slice")
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Lookup {
    Kept(Snapshot),
    NoLongerKept,
    Unknown,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    snapshots: Vec<Snapshot>,
    events: Vec<Event>,
}

/// In-memory history of config versions, persisted as `data_dir/config-history.json`.
pub(crate) struct ConfigHistory {
    data_dir: PathBuf,
    bounds: Bounds,
    /// False when a file on disk could not be read or moved aside: a save
    /// would replace history this process never loaded.
    saves: bool,
    inner: parking_lot::Mutex<State>,
}

impl ConfigHistory {
    pub(crate) const FILE: &'static str = "config-history.json";

    /// Start a store for `data_dir`. A missing file is an empty store. A file
    /// that does not parse is moved aside and the store starts empty. A file
    /// that is refused (a link, not owner-only, another account's) or cannot
    /// be read or moved aside is left as it is, said once, and this store
    /// keeps its history in memory only.
    pub(crate) fn open(data_dir: &Path, bounds: Bounds, now: u64) -> Self {
        let path = data_dir.join(Self::FILE);
        let (state, saves) = match read_stored(&path) {
            Ok(None) => (State::default(), true),
            Err(reason) => {
                tracing::warn!(%reason, "config history kept in memory only; its file is left as it is");
                (State::default(), false)
            }
            Ok(Some(text)) => match serde_json::from_str::<State>(&text) {
                Ok(state) => (state, true),
                Err(error) => match crate::counters::persist::quarantine(&path, now) {
                    Ok(_) => (State::default(), true),
                    Err(quarantine_error) => {
                        tracing::warn!(
                            parse = %error,
                            error = %quarantine_error,
                            "config history could not be moved aside; not saving over it"
                        );
                        (State::default(), false)
                    }
                },
            },
        };
        Self {
            data_dir: data_dir.to_path_buf(),
            bounds,
            saves,
            inner: parking_lot::Mutex::new(state),
        }
    }

    /// Remember `event` and, when present, `snapshot`. Evict, then save.
    /// `running` is the revision a snapshot eviction must not drop.
    pub(crate) fn record(&self, event: Event, snapshot: Option<Snapshot>, running: &str, now: u64) {
        let path = self.data_dir.join(Self::FILE);
        let failed = {
            let mut state = self.inner.lock();
            if let Some(snapshot) = snapshot {
                state.snapshots.push(snapshot);
            }
            state.events.push(event);
            evict_snapshots(&mut state.snapshots, self.bounds, running, now);
            evict_events(&mut state.events, self.bounds);
            // Written under the lock, so the file never ends on an older state
            // than a record that raced this one.
            if self.saves {
                serde_json::to_vec(&*state)
                    .map_err(std::io::Error::from)
                    .and_then(|bytes| {
                        write_atomic(&path, &bytes, FileMode::Private, Symlink::Replace)
                    })
                    .err()
            } else {
                None
            }
        };
        if let Some(error) = failed {
            tracing::warn!(%error, "config history could not be saved");
        }
    }

    /// The bytes `path` had in the newest kept version, when it has that file.
    fn newest_file_bytes(&self, path: &str) -> Option<Vec<u8>> {
        let state = self.inner.lock();
        let file = state
            .snapshots
            .last()?
            .files
            .iter()
            .find(|file| file.path == path)?;
        file.bytes.clone()
    }

    /// When the newest kept version named `revision` was stored.
    fn stored_at(&self, revision: &str) -> Option<u64> {
        let state = self.inner.lock();
        state
            .snapshots
            .iter()
            .rev()
            .find(|snapshot| snapshot.revision == revision)
            .map(|snapshot| snapshot.at)
    }

    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "read by the history page, a later slice")
    )]
    pub(crate) fn events(&self) -> Vec<Event> {
        self.inner.lock().events.clone()
    }

    /// Kept versions, oldest first.
    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "read by the history page, a later slice")
    )]
    pub(crate) fn snapshots(&self) -> Vec<Snapshot> {
        self.inner.lock().snapshots.clone()
    }

    /// `Kept` when `revision` is still stored. `NoLongerKept` when a held
    /// event names it. Otherwise `Unknown`.
    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "read by the history page, a later slice")
    )]
    pub(crate) fn lookup(&self, revision: &str) -> Lookup {
        let state = self.inner.lock();
        if let Some(snapshot) = state
            .snapshots
            .iter()
            .find(|snapshot| snapshot.revision == revision)
        {
            return Lookup::Kept(snapshot.clone());
        }
        if state
            .events
            .iter()
            .any(|event| event.revision.as_deref() == Some(revision))
        {
            return Lookup::NoLongerKept;
        }
        Lookup::Unknown
    }
}

/// The store a `LiveConfig` records its publishes into, with the paths of the
/// files a version holds (the publish carries their bytes, not their names).
pub(crate) struct HistoryHook {
    pub store: Arc<ConfigHistory>,
    pub config_path: String,
    pub grants_path: Option<String>,
}

/// The hook a serving gateway attaches when it has a config file.
pub(crate) fn hook_for(
    data_dir: &Path,
    config_path: &Path,
    grants_path: Option<String>,
) -> HistoryHook {
    HistoryHook {
        store: Arc::new(ConfigHistory::open(
            data_dir,
            Bounds::default(),
            crate::clock::unix_secs().unwrap_or(0),
        )),
        config_path: config_path.display().to_string(),
        grants_path,
    }
}

impl HistoryHook {
    /// Record one applied publish under `revision`. `previous == Some(revision)`
    /// is an unchanged reload: an event and no new version.
    pub(crate) fn on_publish(
        &self,
        raw: &RawInputs,
        revision: &str,
        pending_restart: &[&str],
        previous: Option<&str>,
        source: Source,
        now: u64,
    ) {
        if previous == Some(revision) {
            self.store.record(
                applied_event(now, source, revision, true),
                None,
                revision,
                now,
            );
            return;
        }
        let snapshot = Snapshot {
            revision: revision.to_string(),
            at: now,
            pending_restart: pending_restart
                .iter()
                .copied()
                .map(str::to_string)
                .collect(),
            files: self.version_files(raw),
        };
        self.store.record(
            applied_event(now, source, revision, false),
            Some(snapshot),
            revision,
            now,
        );
    }

    /// Record a refused reload. No version is stored. `served` is the revision
    /// still published, when there is one.
    pub(crate) fn on_refused(
        &self,
        source: Source,
        served: Option<&str>,
        _line: Option<u32>,
        now: u64,
    ) {
        let still_running = served.map(|revision| StillRunning {
            revision: revision.to_string(),
            since: self.store.stored_at(revision).unwrap_or(now),
        });
        self.store.record(
            Event {
                at: now,
                source,
                outcome: Outcome::Refused,
                revision: None,
                unchanged: false,
                still_running,
                location: None,
                attempted_diff: None,
            },
            None,
            served.unwrap_or(""),
            now,
        );
    }

    /// gateway.yaml, then each env file, then the grants file when this hook has one.
    fn version_files(&self, raw: &RawInputs) -> Vec<StoredFile> {
        let mut files = Vec::with_capacity(raw.env_files.len() + 2);
        files.push(StoredFile {
            path: self.config_path.clone(),
            bytes: Some(raw.gateway_yaml.clone()),
        });
        files.extend(raw.env_files.iter().map(|(path, bytes)| StoredFile {
            path: path.clone(),
            bytes: bytes.clone(),
        }));
        if let Some(path) = &self.grants_path {
            let bytes = match &raw.grants {
                Some(grants) => Some(grants.clone()),
                None => self.store.newest_file_bytes(path),
            };
            files.push(StoredFile {
                path: path.clone(),
                bytes,
            });
        }
        files
    }
}

/// The stored history, read as the secret file it is (it holds env-file
/// bytes): `None` when there is none, the refusal or read error otherwise.
fn read_stored(path: &Path) -> Result<Option<String>, String> {
    // The guarded read follows links, so a link is refused first. The check
    // and the open are two calls: swapping the file between them takes write
    // access to the data directory, which only the gateway's own user has.
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(format!(
                "Refusing to load config history file {}: it is a symbolic link, and the \
                 history is read only from the file the gateway writes.",
                path.display()
            ));
        }
        _ => {}
    }
    match crate::config::read_checked_file(path, crate::config::CheckedFile::ConfigHistory) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

fn applied_event(at: u64, source: Source, revision: &str, unchanged: bool) -> Event {
    Event {
        at,
        source,
        outcome: Outcome::Applied,
        revision: Some(revision.to_string()),
        unchanged,
        still_running: None,
        location: None,
        attempted_diff: None,
    }
}

fn file_bytes(snapshot: &Snapshot) -> usize {
    snapshot.files.iter().fold(0_usize, |sum, file| {
        sum.saturating_add(file.bytes.as_ref().map_or(0, Vec::len))
    })
}

fn snapshot_total(snapshots: &[Snapshot]) -> usize {
    snapshots.iter().fold(0_usize, |sum, snapshot| {
        sum.saturating_add(file_bytes(snapshot))
    })
}

/// Drop non-running versions past `max_age_secs`, then the oldest non-running
/// version until the count and the byte total both fit. `running` stays.
fn evict_snapshots(snapshots: &mut Vec<Snapshot>, bounds: Bounds, running: &str, now: u64) {
    snapshots.retain(|snapshot| {
        snapshot.revision == running || now.saturating_sub(snapshot.at) <= bounds.max_age_secs
    });
    while snapshots.len() > bounds.snapshots || snapshot_total(snapshots) > bounds.snapshot_bytes {
        let Some(index) = snapshots
            .iter()
            .position(|snapshot| snapshot.revision != running)
        else {
            break;
        };
        snapshots.remove(index);
    }
}

fn event_json_len(event: &Event) -> usize {
    serde_json::to_vec(event).map_or(usize::MAX, |bytes| bytes.len())
}

/// Drop the oldest event until the count and the serialized-byte total both fit.
fn evict_events(events: &mut Vec<Event>, bounds: Bounds) {
    let mut sizes: Vec<usize> = events.iter().map(event_json_len).collect();
    let mut total = sizes
        .iter()
        .fold(0_usize, |sum, size| sum.saturating_add(*size));
    while events.len() > bounds.events || total > bounds.event_bytes {
        if events.is_empty() {
            break;
        }
        events.remove(0);
        total = total.saturating_sub(sizes.remove(0));
    }
}

#[cfg(test)]
#[path = "history_record_tests.rs"]
mod record_tests;
#[cfg(test)]
#[path = "history_reload_tests.rs"]
mod reload_tests;
#[cfg(test)]
#[path = "history_tests.rs"]
mod tests;
