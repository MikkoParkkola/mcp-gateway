// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Recorded config versions and the reload events that produced them.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::config_reload::revision::RawInputs;

/// The whole-save deadline: a record's save, its sidecar wait and the
/// startup worker's open all end within it (design D-1, D-2).
pub(crate) const SAVE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

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
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StoredFile {
    pub path: String,
    pub bytes: Option<Vec<u8>>,
}

/// The path and the byte count, never the bytes: a version holds env-file
/// secrets (I2).
impl std::fmt::Debug for StoredFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredFile")
            .field("path", &self.path)
            .field("bytes", &self.bytes.as_ref().map(Vec::len))
            .finish()
    }
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

/// What `lookup` found for a revision.
#[cfg(any(test, feature = "webui"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Lookup {
    Kept(Snapshot),
    NoLongerKept,
    Unknown,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct State {
    snapshots: Vec<Snapshot>,
    events: Vec<Event>,
}

/// Where this store's history lives. Disk mode holds no version bodies: each
/// record reads the file, evicts, writes it back and drops the bytes (wiped).
/// Memory-only is the refused-file mode of the 2026-11-16 ruling.
enum StoreMode {
    /// Not read yet: `open_now` reads it; until then reads go to the file.
    Unopened {
        now: u64,
    },
    Disk,
    MemoryOnly {
        state: State,
    },
}

/// Config versions and reload events, persisted as `data_dir/config-history.json`
/// unless that file is refused, when this store keeps them in memory only.
pub(crate) struct ConfigHistory {
    bounds: Bounds,
    mode: parking_lot::Mutex<StoreMode>,
    /// The directory the history file lives in, kept in either mode.
    data_dir: PathBuf,
    /// Serializes records in the order reloads take it: a reload takes it
    /// under `lock_reload`, before anything changes, and its record task
    /// holds it until the record is done (design D-1). Never taken with a
    /// swap lock held, never by anything else.
    record_guard: Arc<tokio::sync::Mutex<()>>,
    /// Raised when a save is abandoned at its deadline; a save renames only
    /// while this still equals the ticket it took (design D-2).
    generation: std::sync::atomic::AtomicU64,
    /// Test-only: every registered temp dir containing this history, taken
    /// at open (`crate::test_dir_keep`). A save its test left running (a
    /// watched reload's record) then lands before the dir goes, never while
    /// it is being removed, where its sidecar open would leave the dir behind.
    /// Declared last, so the store's other fields drop first.
    #[cfg(test)]
    _kept_dirs: Vec<Arc<tempfile::TempDir>>,
}

impl ConfigHistory {
    pub(crate) const FILE: &'static str = "config-history.json";

    /// Start a store for `data_dir`. A missing file is an empty store. A file
    /// that does not parse is moved aside and the store starts empty. A file
    /// that is refused (a link, not owner-only, another account's) or cannot
    /// be read or moved aside is left as it is, said once, and this store
    /// keeps its history in memory only.
    pub(crate) fn open(data_dir: &Path, bounds: Bounds, now: u64) -> Self {
        // No I/O here: the file is read by `open_now`, which startup runs on
        // its worker under the startup deadline (gpt G1).
        Self {
            bounds,
            mode: parking_lot::Mutex::new(StoreMode::Unopened { now }),
            data_dir: data_dir.to_path_buf(),
            record_guard: Arc::new(tokio::sync::Mutex::new(())),
            generation: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            _kept_dirs: crate::test_dir_keep::kept_dirs_for(data_dir),
        }
    }

    /// The guard a reload takes before anything changes (design D-1).
    pub(crate) fn record_guard(&self) -> Arc<tokio::sync::Mutex<()>> {
        Arc::clone(&self.record_guard)
    }

    /// The history file's path, in either mode.
    pub(crate) fn file(&self) -> PathBuf {
        self.data_dir.join(Self::FILE)
    }

    /// Remember `event` and, when present, `snapshot`, saved on this thread
    /// (design D-2); `running` is the revision an eviction must not drop.
    #[cfg(test)]
    pub(crate) fn record(&self, event: Event, snapshot: Option<Snapshot>, running: &str, now: u64) {
        self.save_inline(Record {
            event,
            snapshot,
            running: running.to_string(),
            served: None,
            now,
        });
    }

    /// Held events, oldest first. Test-only until the history page reads it.
    #[cfg(test)]
    pub(crate) fn events(&self) -> Vec<Event> {
        self.with_state(|state| state.events.clone())
    }

    /// Kept versions, oldest first. Test-only until the history page reads it.
    #[cfg(test)]
    pub(crate) fn snapshots(&self) -> Vec<Snapshot> {
        self.with_state(|state| state.snapshots.clone())
    }

    /// What `revision` resolves to in one read of the store (see `resolve`).
    /// A file that cannot be read or parsed is the caller's error, never an
    /// empty store and never `Unknown`. The routes read through
    /// `lookup_against` and `contents`; this is the rows' single lookup.
    #[cfg(test)]
    pub(crate) fn lookup(&self, revision: &str) -> Result<Lookup, String> {
        self.read_state().map(|state| resolve(&state, revision))
    }

    /// For a restore, from one read: what `revision` resolves to, and the
    /// newest kept copy of the served revision, the version it is compared
    /// against. `served` is asked after the read, so the baseline is judged
    /// by the revision served when the read was taken, never an earlier one.
    #[cfg(feature = "webui")]
    pub(crate) fn lookup_against(
        &self,
        revision: &str,
        served: impl FnOnce() -> Option<String>,
    ) -> Result<(Lookup, Option<Snapshot>), String> {
        let state = self.read_state()?;
        let baseline = served().and_then(|served| newest(&state, &served).cloned());
        Ok((resolve(&state, revision), baseline))
    }

    /// Every kept version and held event, oldest first, from one read.
    #[cfg(feature = "webui")]
    pub(crate) fn contents(&self) -> Result<(Vec<Snapshot>, Vec<Event>), String> {
        self.read_state()
            .map(|state| (state.snapshots, state.events))
    }

    /// Memory-only reads the held state; otherwise the file. Test-only. A
    /// failed read is never taken as an empty store: it fails the reader
    /// with the read error (design D-2).
    #[cfg(test)]
    fn with_state<T>(&self, read: impl FnOnce(&State) -> T) -> T {
        let state = self
            .read_state()
            .unwrap_or_else(|error| panic!("the history file does not read: {error}"));
        read(&state)
    }

    /// The production read: memory-only answers the held state, otherwise
    /// the file is read and parsed now. Its error goes to the caller.
    #[cfg(any(test, feature = "webui"))]
    fn read_state(&self) -> Result<State, String> {
        let mode = self.mode.lock();
        match &*mode {
            StoreMode::MemoryOnly { state } => Ok(state.clone()),
            StoreMode::Disk | StoreMode::Unopened { .. } => load_state(&self.file()),
        }
    }
}

/// The newest kept copy of `revision`: the copy eviction pins.
#[cfg(any(test, feature = "webui"))]
fn newest<'a>(state: &'a State, revision: &str) -> Option<&'a Snapshot> {
    state
        .snapshots
        .iter()
        .rev()
        .find(|kept| kept.revision == revision)
}

/// `Kept` with the newest copy when `revision` is still stored,
/// `NoLongerKept` when only a held event names it, else `Unknown`.
#[cfg(any(test, feature = "webui"))]
fn resolve(state: &State, revision: &str) -> Lookup {
    if let Some(kept) = newest(state, revision) {
        return Lookup::Kept(kept.clone());
    }
    let named = state
        .events
        .iter()
        .any(|event| event.revision.as_deref() == Some(revision));
    if named {
        Lookup::NoLongerKept
    } else {
        Lookup::Unknown
    }
}

/// The store a `LiveConfig` records its publishes into, with the paths of the
/// files a version holds (the publish carries their bytes, not their names).
pub(crate) struct HistoryHook {
    pub store: Arc<ConfigHistory>,
    pub config_path: String,
}

/// The hook a serving gateway attaches when it has a config file.
pub(crate) fn hook_for(data_dir: &Path, config_path: &Path) -> HistoryHook {
    HistoryHook {
        store: Arc::new(ConfigHistory::open(
            data_dir,
            Bounds::default(),
            crate::clock::unix_secs().unwrap_or(0),
        )),
        config_path: config_path.display().to_string(),
    }
}

impl HistoryHook {
    /// The record `pending` stands for, built from the publish's own inputs
    /// only (gateway.yaml and the env files): no version depends on another
    /// record or on state read back from the store (design D-1).
    pub(crate) fn build(&self, pending: PendingRecord, now: u64) -> Record {
        match pending {
            PendingRecord::Publish {
                raw,
                revision,
                pending_restart,
                previous,
                pin,
                source,
            } => self.publish_record(
                &raw,
                (&revision, previous.as_deref()),
                &pending_restart,
                &pin,
                source,
                now,
            ),
            PendingRecord::Refused {
                source,
                served,
                line,
            } => Record {
                event: Event {
                    at: now,
                    source,
                    outcome: Outcome::Refused,
                    revision: None,
                    unchanged: false,
                    still_running: None,
                    location: line.map(u64::from),
                    attempted_diff: None,
                },
                snapshot: None,
                running: served.clone().unwrap_or_default(),
                served,
                now,
            },
        }
    }

    /// Build and save one pending record on this thread. Test-only: a reload
    /// saves through the record task, startup through `ConfigHistory::start`.
    #[cfg(test)]
    pub(crate) fn run(&self, pending: PendingRecord, now: u64) {
        self.store.save_inline(self.build(pending, now));
    }

    /// The files a version of `raw` holds, as the swap observer logs them.
    #[cfg(test)]
    pub(crate) fn observed_files(&self, raw: &RawInputs) -> Vec<(String, Option<Vec<u8>>)> {
        self.version_files(raw)
            .into_iter()
            .map(|file| (file.path.clone(), file.bytes.clone()))
            .collect()
    }

    /// `(revision, previous)`: the published revision and the one it replaced.
    /// `pin` is the served version after this publish, the one eviction keeps.
    fn publish_record(
        &self,
        raw: &RawInputs,
        (revision, previous): (&str, Option<&str>),
        pending_restart: &[&str],
        pin: &str,
        source: Source,
        now: u64,
    ) -> Record {
        let unchanged = !records_a_version(previous, revision);
        let snapshot = (!unchanged).then(|| Snapshot {
            revision: revision.to_string(),
            at: now,
            source: source.clone(),
            pending_restart: pending_restart
                .iter()
                .copied()
                .map(str::to_string)
                .collect(),
            files: self.version_files(raw),
        });
        Record {
            event: applied_event(now, source, revision, unchanged),
            snapshot,
            // Not `revision`: after a part-only publish an unchanged event's
            // revision names no kept version, and the served one must stay.
            running: pin.to_string(),
            served: None,
            now,
        }
    }

    /// gateway.yaml, then each env file (design D-3 M6: the grants file is
    /// not part of a config version; grants versions are recorded separately).
    fn version_files(&self, raw: &RawInputs) -> Vec<StoredFile> {
        let mut files = Vec::with_capacity(raw.env_files.len() + 1);
        files.push(StoredFile {
            path: self.config_path.clone(),
            bytes: Some(raw.gateway_yaml.clone()),
        });
        files.extend(raw.env_files.iter().map(|(path, bytes)| StoredFile {
            path: path.clone(),
            bytes: bytes.clone(),
        }));
        files
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

fn remember(
    state: &mut State,
    event: Event,
    snapshot: Option<Snapshot>,
    bounds: Bounds,
    running: &str,
    now: u64,
) {
    if let Some(snapshot) = snapshot {
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

/// A stored version written before `source` existed is a file reload.
fn file_source() -> Source {
    Source::File
}

/// Whether a full publish from `previous` to `revision` stores a version: only
/// when the revision moved. The live config moves its recorded (served)
/// revision by this same rule ([`recorded_after`]), so the two cannot drift.
fn records_a_version(previous: Option<&str>, revision: &str) -> bool {
    previous != Some(revision)
}

/// What the live config should hold as its recorded revision once a full
/// publish replaced `before` with `now`: `now` if that publish stores a
/// version, otherwise `kept` unchanged. Nothing published, nothing held.
pub(super) fn recorded_after(
    before: Option<&str>,
    now: Option<&str>,
    kept: Option<&str>,
) -> Option<String> {
    let now = now?;
    let stored = records_a_version(before, now);
    Some(if stored { now } else { kept? }.to_owned())
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
    // Only the newest copy of the running revision is pinned (t12): an older
    // copy of the same revision ages and counts out like any other.
    let mut pinned = snapshots
        .iter()
        .rposition(|snapshot| snapshot.revision == running);
    let mut index = 0;
    snapshots.retain(|snapshot| {
        let keep = Some(index) == pinned || now.saturating_sub(snapshot.at) <= bounds.max_age_secs;
        index += 1;
        keep
    });
    pinned = snapshots
        .iter()
        .rposition(|snapshot| snapshot.revision == running);
    while snapshots.len() > bounds.snapshots || snapshot_total(snapshots) > bounds.snapshot_bytes {
        let Some(oldest) = (0..snapshots.len()).find(|i| Some(*i) != pinned) else {
            break;
        };
        snapshots.remove(oldest);
        pinned = pinned.map(|p| if p > oldest { p - 1 } else { p });
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

#[cfg(tp3)]
#[cfg(test)]
#[path = "history_deadline_tests.rs"]
mod deadline_tests;
#[cfg(tp3)]
#[cfg(test)]
#[path = "history_order_tests.rs"]
mod order_tests;
#[cfg(tp3)]
#[cfg(test)]
#[path = "history_read_tests.rs"]
mod read_tests;
#[cfg(tp3)]
#[cfg(test)]
#[path = "history_record_tests.rs"]
mod record_tests;
#[cfg(tp3)]
#[cfg(test)]
#[path = "history_reload_tests.rs"]
mod reload_tests;
#[cfg(tp3)]
#[cfg(test)]
#[path = "history_route_tests.rs"]
mod route_tests;
#[path = "history_save.rs"]
mod save;
#[cfg(tp3)]
#[cfg(test)]
#[path = "history_save_tests.rs"]
mod save_tests;
pub(crate) use save::Record;
#[path = "history_task.rs"]
mod task;
pub(crate) use task::{PendingRecord, RecordSlot};
#[cfg(test)]
#[path = "history_seams.rs"]
pub(crate) mod seams;
#[cfg(tp3)]
#[cfg(test)]
#[path = "history_startup_tests.rs"]
mod startup_tests;
#[cfg(tp3)]
#[cfg(test)]
#[path = "history_tests.rs"]
mod tests;
