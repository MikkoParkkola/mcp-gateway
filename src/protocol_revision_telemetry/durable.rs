// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The stdio side of the restart-safe window, and the file helpers the v2
//! window (`window.rs`) shares. Stdio writes only its own transport's counts
//! into the v2 `stdio` slice: reported, never certified.

use std::collections::BTreeMap;
#[cfg(unix)]
use std::fs::File;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::window::{read_or_create, read_window_v2, validate_window_v2, window_paths};
use super::{
    DURABLE_TELEMETRY_DIR, DURABLE_WINDOW_FILE, Registry, Snapshot, Transport, empty_shadow_counts,
    global,
};
use crate::fs_lock::ExclusiveFileLock;

/// Cross-process sink used by stdio servers.
///
/// Each process contributes only the delta since its preceding write. A shared
/// advisory lock serializes the aggregate update across gateway processes.
#[derive(Debug)]
pub struct DurableTelemetrySink {
    window_path: PathBuf,
    lock_path: PathBuf,
    previous_snapshot: Snapshot,
    previous_shadow: BTreeMap<String, u64>,
    previous_agents: BTreeMap<String, u64>,
    parent_sync_pending: bool,
    #[cfg(test)]
    created_by: crate::test_late_write::Creator,
}

/// What one stdio persist adds: this process's stdio counts, its list
/// shadow and its missing-revision agents, all cumulative.
pub(super) struct StdioCounts {
    pub(super) snapshot: Snapshot,
    pub(super) shadow: BTreeMap<String, u64>,
    pub(super) agents: BTreeMap<String, u64>,
}

impl StdioCounts {
    fn of(registry: &Registry) -> Self {
        Self {
            snapshot: registry.transport_snapshot(Transport::Stdio),
            shadow: registry.shadow_snapshot(),
            agents: registry.missing_revision_agents(Transport::Stdio),
        }
    }
}

impl DurableTelemetrySink {
    /// Open or create the durable measurement window below `data_dir`.
    ///
    /// A v1 window is refused with the archive instruction, never converted.
    pub fn open(data_dir: &Path) -> io::Result<Self> {
        let directory = data_dir.join(DURABLE_TELEMETRY_DIR);
        std::fs::create_dir_all(&directory)?;
        force_directory_owner_only(&directory)?;
        let (window_path, lock_path) = window_paths(data_dir);
        {
            let _lock = ExclusiveFileLock::acquire(&lock_path)?;
            read_or_create(&window_path, unix_seconds()?)?;
        }
        Ok(Self {
            window_path,
            lock_path,
            previous_snapshot: Snapshot::default(),
            previous_shadow: empty_shadow_counts(),
            previous_agents: BTreeMap::new(),
            parent_sync_pending: false,
            #[cfg(test)]
            created_by: crate::test_late_write::Creator::default(),
        })
    }

    /// Add counters observed since this sink's preceding successful write.
    pub fn persist_registry(&mut self, registry: &Registry) -> io::Result<()> {
        self.persist(StdioCounts::of(registry), unix_seconds()?)
    }

    /// Persist the current process-global counters.
    pub fn persist_global(&mut self) -> io::Result<()> {
        let counts = StdioCounts::of(
            &global()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        self.persist(counts, unix_seconds()?)
    }

    fn persist(&mut self, current: StdioCounts, now: u64) -> io::Result<()> {
        self.persist_with_parent_sync(current, now, sync_parent_directory)
    }

    pub(super) fn persist_with_parent_sync(
        &mut self,
        current: StdioCounts,
        now: u64,
        sync_parent: impl FnOnce(&Path) -> io::Result<()>,
    ) -> io::Result<()> {
        let snapshot_delta = snapshot_delta(&current.snapshot, &self.previous_snapshot);
        let shadow_delta = map_delta(&current.shadow, &self.previous_shadow);
        let agents_delta = map_delta(&current.agents, &self.previous_agents);
        if snapshot_delta.total == 0 && shadow_delta.values().all(|count| *count == 0) {
            if self.parent_sync_pending {
                sync_parent(&self.window_path)?;
                self.parent_sync_pending = false;
            }
            return Ok(());
        }

        #[cfg(test)]
        self.created_by
            .witness("telemetry window", &self.window_path);
        let _lock = ExclusiveFileLock::acquire(&self.lock_path)?;
        let mut window = read_window_v2(&self.window_path)?;
        add_snapshot(&mut window.stdio, &snapshot_delta)?;
        add_map(&mut window.tools_list_shadow, &shadow_delta)?;
        add_map(&mut window.missing_revision_agents, &agents_delta)?;
        window.updated_at_unix_seconds = window.updated_at_unix_seconds.max(now);
        validate_window_v2(&window)?;
        write_json_atomic(&self.window_path, &window)?;
        self.previous_snapshot = current.snapshot;
        self.previous_shadow = current.shadow;
        self.previous_agents = current.agents;
        self.parent_sync_pending = true;
        sync_parent(&self.window_path)?;
        self.parent_sync_pending = false;
        Ok(())
    }
}

/// Location of the restart-safe aggregate below a gateway data directory.
pub fn durable_window_path(data_dir: &Path) -> PathBuf {
    data_dir
        .join(DURABLE_TELEMETRY_DIR)
        .join(DURABLE_WINDOW_FILE)
}

fn snapshot_delta(current: &Snapshot, previous: &Snapshot) -> Snapshot {
    Snapshot {
        by_revision: map_delta(&current.by_revision, &previous.by_revision),
        by_client: map_delta(&current.by_client, &previous.by_client),
        by_transport: map_delta(&current.by_transport, &previous.by_transport),
        unattributed: counter_delta(current.unattributed, previous.unattributed),
        total: counter_delta(current.total, previous.total),
    }
}

fn map_delta(
    current: &BTreeMap<String, u64>,
    previous: &BTreeMap<String, u64>,
) -> BTreeMap<String, u64> {
    current
        .iter()
        .map(|(key, value)| {
            let prior = previous.get(key).copied().unwrap_or(0);
            (key.clone(), counter_delta(*value, prior))
        })
        .collect()
}

fn counter_delta(current: u64, previous: u64) -> u64 {
    current.checked_sub(previous).unwrap_or(current)
}

fn add_snapshot(target: &mut Snapshot, delta: &Snapshot) -> io::Result<()> {
    add_map(&mut target.by_revision, &delta.by_revision)?;
    add_map(&mut target.by_client, &delta.by_client)?;
    add_map(&mut target.by_transport, &delta.by_transport)?;
    target.unattributed = checked_counter_add(target.unattributed, delta.unattributed)?;
    target.total = checked_counter_add(target.total, delta.total)?;
    Ok(())
}

pub(super) fn add_map(
    target: &mut BTreeMap<String, u64>,
    delta: &BTreeMap<String, u64>,
) -> io::Result<()> {
    for (key, increment) in delta {
        let value = target.entry(key.clone()).or_insert(0);
        *value = checked_counter_add(*value, *increment)?;
    }
    Ok(())
}

pub(super) fn checked_counter_add(current: u64, increment: u64) -> io::Result<u64> {
    current
        .checked_add(increment)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "telemetry counter overflow"))
}

pub(super) fn validate_bounded_keys<'a>(
    values: &BTreeMap<String, u64>,
    allowed: impl Iterator<Item = &'a str>,
    label: &str,
) -> io::Result<()> {
    let allowed = allowed.collect::<std::collections::BTreeSet<_>>();
    if let Some(unbounded) = values.keys().find(|key| !allowed.contains(key.as_str())) {
        return Err(invalid_window(&format!(
            "unbounded {label} label in durable telemetry: {unbounded}"
        )));
    }
    Ok(())
}

pub(super) fn invalid_window(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(super) fn checked_counter_sum(mut values: impl Iterator<Item = u64>) -> io::Result<u64> {
    values.try_fold(0, checked_counter_add)
}

fn unix_seconds() -> io::Result<u64> {
    crate::clock::unix_secs().map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

/// Write `value` to a private temporary file, fsync it, and rename it over `path`.
// Not `config_persistence::write_atomic`: fixed `json.tmp` under its own lock, plus a directory sync after the baseline advances.
pub(super) fn write_json_atomic(path: &Path, value: &impl Serialize) -> io::Result<()> {
    #[cfg(test)]
    write_seam::record(path);
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let temporary = path.with_extension("json.tmp");
    {
        let mut file = crate::config_persistence::create_private_replacing(&temporary)?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    }
    std::fs::rename(&temporary, path)?;
    Ok(())
}

#[cfg(unix)]
pub(super) fn sync_parent_directory(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "window has no parent"))?;
    File::open(parent)?.sync_all()
}

#[cfg(unix)]
pub(super) fn force_directory_owner_only(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

// The non-unix no-ops keep the unix signatures; they live beside this file.
#[cfg(not(unix))]
#[path = "nonunix.rs"]
mod nonunix;
#[cfg(not(unix))]
pub(super) use nonunix::{force_directory_owner_only, sync_parent_directory};

/// Test support: window writes counted per window file (MIK-8364), so a row
/// can assert that a request path wrote nothing. Keyed by path, so parallel
/// tests with their own data directories never see each other's writes.
#[cfg(test)]
pub(crate) mod write_seam {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, PoisonError};

    static WRITES: Mutex<Option<HashMap<PathBuf, usize>>> = Mutex::new(None);

    pub(super) fn record(path: &Path) {
        let mut writes = WRITES.lock().unwrap_or_else(PoisonError::into_inner);
        *writes
            .get_or_insert_with(HashMap::new)
            .entry(path.to_path_buf())
            .or_insert(0) += 1;
    }

    /// Window writes to `path` so far.
    pub(crate) fn writes(path: &Path) -> usize {
        WRITES
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .and_then(|writes| writes.get(path).copied())
            .unwrap_or(0)
    }
}

#[cfg(test)]
#[path = "durable_tests.rs"]
mod tests;
