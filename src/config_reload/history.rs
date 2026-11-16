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

impl Drop for StoredFile {
    fn drop(&mut self) {
        // Every parsed copy of a version's bytes. Wiped here, the same
        // zeroize `WipedBytes` uses, so dropping the parse does not leave
        // the secret in the allocator's free list. A field of this value
        // cannot be moved out; clone the bytes instead.
        if let Some(bytes) = self.bytes.as_mut() {
            zeroize::Zeroize::zeroize(bytes);
        }
    }
}

/// One kept version of the config files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Snapshot {
    pub revision: String,
    pub at: u64,
    /// Where the publish that stored this version came from. Absent in a
    /// file written before the field existed: those load as a file reload.
    #[serde(default = "file_source")]
    pub source: Source,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
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

/// What `lookup` found for a revision. Test-only until the history page
/// reads it.
#[cfg(test)]
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

/// Where this store's history lives. Disk mode holds no version bodies: each
/// record reads the file, evicts, writes it back and drops the bytes (wiped).
/// Memory-only is the refused-file mode of the 2026-11-16 ruling.
enum StoreMode {
    Disk { path: PathBuf },
    MemoryOnly { state: State },
}

/// Config versions and reload events, persisted as `data_dir/config-history.json`
/// unless that file is refused, when this store keeps them in memory only.
pub(crate) struct ConfigHistory {
    bounds: Bounds,
    mode: parking_lot::Mutex<StoreMode>,
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
        // A parsed file is not kept: disk mode re-reads it on each call, and
        // the parse is wiped when it drops.
        let mode = match read_stored(&path) {
            Ok(None) => StoreMode::Disk { path },
            Err(reason) => {
                tracing::warn!(%reason, "config history kept in memory only; its file is left as it is");
                StoreMode::MemoryOnly {
                    state: State::default(),
                }
            }
            Ok(Some(text)) => match serde_json::from_slice::<State>(text.as_bytes()) {
                Ok(parsed) => {
                    drop(parsed);
                    StoreMode::Disk { path }
                }
                Err(error) => match crate::counters::persist::quarantine(&path, now) {
                    Ok(_) => StoreMode::Disk { path },
                    Err(quarantine_error) => {
                        tracing::warn!(
                            parse = %error,
                            error = %quarantine_error,
                            "config history could not be moved aside; not saving over it"
                        );
                        StoreMode::MemoryOnly {
                            state: State::default(),
                        }
                    }
                },
            },
        };
        Self {
            bounds,
            mode: parking_lot::Mutex::new(mode),
        }
    }

    /// Remember `event` and, when present, `snapshot`. Evict, then save.
    /// `running` is the revision a snapshot eviction must not drop. A disk
    /// read that is refused or fails switches this store to memory-only,
    /// starting from the event being recorded, and does not write.
    pub(crate) fn record(&self, event: Event, snapshot: Option<Snapshot>, running: &str, now: u64) {
        let noted = {
            let mut mode = self.mode.lock();
            record_in(&mut mode, self.bounds, event, snapshot, running, now)
        };
        match noted {
            None => {}
            Some(Noted::Write(error)) => {
                tracing::warn!(%error, "config history could not be saved");
            }
            Some(Noted::Read(reason)) => {
                tracing::warn!(%reason, "config history kept in memory only; its file is left as it is");
            }
        }
    }

    /// The bytes `path` had in the newest kept version, when it has that file.
    fn newest_file_bytes(&self, path: &str) -> Option<Vec<u8>> {
        self.with_state(|state| {
            let file = state
                .snapshots
                .last()?
                .files
                .iter()
                .find(|file| file.path == path)?;
            file.bytes.clone()
        })
    }

    /// When the newest kept version named `revision` was stored.
    fn stored_at(&self, revision: &str) -> Option<u64> {
        self.with_state(|state| {
            state
                .snapshots
                .iter()
                .rev()
                .find(|snapshot| snapshot.revision == revision)
                .map(|snapshot| snapshot.at)
        })
    }

    /// Held events, oldest first. Test-only until the history page reads it.
    #[cfg(test)]
    pub(crate) fn events(&self) -> Vec<Event> {
        self.with_state(|state| state.events.clone())
    }

    /// Kept versions, oldest first.
    pub(crate) fn snapshots(&self) -> Vec<Snapshot> {
        self.with_state(|state| state.snapshots.clone())
    }

    /// `Kept` when `revision` is still stored. `NoLongerKept` when a held
    /// event names it. Otherwise `Unknown`. Test-only until the history page
    /// reads it.
    #[cfg(test)]
    pub(crate) fn lookup(&self, revision: &str) -> Lookup {
        self.with_state(|state| {
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
        })
    }

    /// Disk reads and parses the file. Memory-only reads the held state.
    /// A disk read that fails answers as an empty store and does not change mode.
    fn with_state<T>(&self, read: impl FnOnce(&State) -> T) -> T {
        let mode = self.mode.lock();
        match &*mode {
            StoreMode::MemoryOnly { state } => read(state),
            StoreMode::Disk { path } => {
                let state = load_state(path).unwrap_or_default();
                read(&state)
            }
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
            source: source.clone(),
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
        line: Option<u32>,
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
                location: line.map(u64::from),
                attempted_diff: None,
            },
            None,
            served.unwrap_or(""),
            now,
        );
    }

    /// A grants publish is its own version. The grants come from their file,
    /// so the source is `File`. Nothing is recorded when this hook has no
    /// grants path. `previous == Some(revision)` is an unchanged event.
    /// Otherwise the version is the newest held version's files with the
    /// grants entry set to `grants` (`None` when there are none), appended
    /// when that version has no grants entry; with no held version, only
    /// the grants entry.
    pub(crate) fn on_grants(
        &self,
        grants: Option<&[u8]>,
        revision: &str,
        pending_restart: &[&str],
        previous: Option<&str>,
        now: u64,
    ) {
        let Some(grants_path) = self.grants_path.clone() else {
            return;
        };
        if previous == Some(revision) {
            self.store.record(
                applied_event(now, Source::File, revision, true),
                None,
                revision,
                now,
            );
            return;
        }
        let bytes = grants.map(<[u8]>::to_vec);
        let mut files = self
            .store
            .snapshots()
            .pop()
            .map(|newest| newest.files.clone())
            .unwrap_or_default();
        if let Some(file) = files.iter_mut().find(|file| file.path == grants_path) {
            if let Some(old) = file.bytes.as_mut() {
                zeroize::Zeroize::zeroize(old);
            }
            file.bytes = bytes;
        } else {
            files.push(StoredFile {
                path: grants_path,
                bytes,
            });
        }
        let snapshot = Snapshot {
            revision: revision.to_string(),
            at: now,
            source: Source::File,
            pending_restart: pending_restart
                .iter()
                .copied()
                .map(str::to_string)
                .collect(),
            files,
        };
        self.store.record(
            applied_event(now, Source::File, revision, false),
            Some(snapshot),
            revision,
            now,
        );
    }

    /// gateway.yaml, then each env file, then the grants file when this hook has one.
    fn version_files(&self, raw: &RawInputs) -> Vec<StoredFile> {
        let mut files = Vec::with_capacity(raw.env_files.len() + 2);
        // m10: the version rereads gateway.yaml from disk, not the published bytes.
        files.push(StoredFile {
            path: self.config_path.clone(),
            bytes: Some(mutant!(
                "m10",
                std::fs::read(&self.config_path).unwrap_or_default(),
                raw.gateway_yaml.clone()
            )),
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
        // m6: the consumed values (env, overrides, secret files) are stored too.
        files.extend(mutant!(
            "m6",
            raw.consumed
                .iter()
                .map(|input| StoredFile {
                    path: input.name.clone(),
                    bytes: Some(input.value.clone()),
                })
                .collect::<Vec<_>>(),
            Vec::<StoredFile>::new()
        ));
        // m5: a version keeps gateway.yaml only.
        mutant!("m5", files.into_iter().take(1).collect(), files)
    }
}

/// The stored history, read as the secret file it is (it holds env-file
/// bytes): `None` when there is none, the refusal or read error otherwise.
fn read_stored(path: &Path) -> Result<Option<crate::wiped_bytes::WipedBytes>, String> {
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
        Ok(text) => Ok(Some(crate::wiped_bytes::WipedBytes::new(text.into_bytes()))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

/// A disk read refused or failed while recording, or a save that did not land.
enum Noted {
    Write(std::io::Error),
    Read(String),
}

fn record_in(
    mode: &mut StoreMode,
    bounds: Bounds,
    event: Event,
    snapshot: Option<Snapshot>,
    running: &str,
    now: u64,
) -> Option<Noted> {
    let path = match mode {
        StoreMode::MemoryOnly { state } => {
            remember(state, event, snapshot, bounds, running, now);
            return None;
        }
        StoreMode::Disk { path } => path.clone(),
    };
    // The path clone ended the borrow of `mode`, so a failed read can switch it.
    match load_state(&path) {
        Ok(mut state) => {
            remember(&mut state, event, snapshot, bounds, running, now);
            // Written under the mode lock, so the file never ends on an older
            // state than a record that raced this one. The bytes are wiped
            // when `save_state` drops them.
            save_state(&path, &state).err().map(Noted::Write)
        }
        Err(reason) => {
            let mut state = State::default();
            remember(&mut state, event, snapshot, bounds, running, now);
            *mode = StoreMode::MemoryOnly { state };
            Some(Noted::Read(reason))
        }
    }
}

fn remember(
    state: &mut State,
    event: Event,
    snapshot: Option<Snapshot>,
    bounds: Bounds,
    running: &str,
    now: u64,
) {
    if let Some(snapshot) = snapshot {
        // m7: a held version with the same files is re-keyed to the new id.
        mutant!(
            "m7",
            {
                for held in state
                    .snapshots
                    .iter_mut()
                    .filter(|held| held.files == snapshot.files)
                {
                    held.revision.clone_from(&snapshot.revision);
                }
            },
            ()
        );
        state.snapshots.push(snapshot);
    }
    state.events.push(event);
    evict_snapshots(&mut state.snapshots, bounds, running, now);
    evict_events(&mut state.events, bounds);
}

/// The file, parsed. Absent is an empty store. The read text is wiped when
/// `read_stored`'s buffer drops, and the parsed copy when `State` drops.
fn load_state(path: &Path) -> Result<State, String> {
    let Some(text) = read_stored(path)? else {
        return Ok(State::default());
    };
    serde_json::from_slice(text.as_bytes()).map_err(|error| error.to_string())
}

fn save_state(path: &Path, state: &State) -> Result<(), std::io::Error> {
    let bytes = serde_json::to_vec(state).map_err(std::io::Error::from)?;
    let bytes = crate::wiped_bytes::WipedBytes::new(bytes);
    write_atomic(path, bytes.as_bytes(), FileMode::Private, Symlink::Replace)
}

/// A stored version written before `source` existed is a file reload.
fn file_source() -> Source {
    Source::File
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
#[path = "history_route_tests.rs"]
mod route_tests;
#[cfg(test)]
#[path = "history_tests.rs"]
mod tests;
