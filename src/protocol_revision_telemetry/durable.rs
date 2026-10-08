// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Restart-safe durable window: the on-disk aggregate stdio servers share.

use std::collections::BTreeMap;
#[cfg(unix)]
use std::fs::File;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::{
    DURABLE_TELEMETRY_DIR, DURABLE_WINDOW_FILE, DURABLE_WINDOW_SCHEMA, MEASURED_CLIENTS,
    MEASURED_REVISIONS, MEASURED_TRANSPORTS, OTHER_REVISION, Registry, RetirementBlocked, Snapshot,
    empty_shadow_counts, global, retire_revisions,
};
use crate::fs_lock::ExclusiveFileLock;

/// Restart-safe aggregate for a production measurement window.
///
/// The file contains bounded labels only. It never stores raw client names,
/// session identifiers, request bodies, or tool arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableWindow {
    /// Stable on-disk schema identifier.
    pub schema_version: String,
    /// Unix timestamp when this window started.
    pub started_at_unix_seconds: u64,
    /// Most recent successful aggregate update, recorded as Unix seconds for operator inspection
    /// after the seven-day window.
    pub updated_at_unix_seconds: u64,
    /// Cross-process request counters accumulated since `started_at_unix_seconds`.
    pub snapshot: Snapshot,
    /// All 16 bounded `tools/list` filter combinations, including zeroes.
    pub tools_list_shadow: BTreeMap<String, u64>,
}

impl DurableWindow {
    fn empty(now: u64) -> Self {
        Self {
            schema_version: DURABLE_WINDOW_SCHEMA.to_string(),
            started_at_unix_seconds: now,
            updated_at_unix_seconds: now,
            snapshot: Snapshot::default(),
            tools_list_shadow: empty_shadow_counts(),
        }
    }

    /// Evaluate the persisted counters using the durable start timestamp.
    pub fn retirement_decision_at(
        &self,
        now_unix_seconds: u64,
    ) -> Result<Vec<String>, RetirementBlocked> {
        let elapsed =
            Duration::from_secs(now_unix_seconds.saturating_sub(self.started_at_unix_seconds));
        retire_revisions(&self.snapshot, elapsed)
    }
}

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
    parent_sync_pending: bool,
}

impl DurableTelemetrySink {
    /// Open or create the durable measurement window below `data_dir`.
    pub fn open(data_dir: &Path) -> io::Result<Self> {
        let directory = data_dir.join(DURABLE_TELEMETRY_DIR);
        std::fs::create_dir_all(&directory)?;
        force_directory_owner_only(&directory)?;
        let window_path = directory.join(DURABLE_WINDOW_FILE);
        let lock_path = directory.join(".window.lock");
        {
            let _lock = ExclusiveFileLock::acquire(&lock_path)?;
            if window_path.exists() {
                read_window_file(&window_path)?;
            } else {
                write_window_atomic(&window_path, &DurableWindow::empty(unix_seconds()?))?;
                sync_parent_directory(&window_path)?;
            }
        }
        Ok(Self {
            window_path,
            lock_path,
            previous_snapshot: Snapshot::default(),
            previous_shadow: empty_shadow_counts(),
            parent_sync_pending: false,
        })
    }

    /// Add counters observed since this sink's preceding successful write.
    pub fn persist_registry(&mut self, registry: &Registry) -> io::Result<()> {
        self.persist(
            registry.snapshot(),
            registry.shadow_snapshot(),
            unix_seconds()?,
        )
    }

    /// Persist the current process-global counters.
    pub fn persist_global(&mut self) -> io::Result<()> {
        let (snapshot, shadow) = {
            let registry = global()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (registry.snapshot(), registry.shadow_snapshot())
        };
        self.persist(snapshot, shadow, unix_seconds()?)
    }

    fn persist(
        &mut self,
        current: Snapshot,
        current_shadow: BTreeMap<String, u64>,
        now: u64,
    ) -> io::Result<()> {
        self.persist_with_parent_sync(current, current_shadow, now, sync_parent_directory)
    }

    fn persist_with_parent_sync(
        &mut self,
        current: Snapshot,
        current_shadow: BTreeMap<String, u64>,
        now: u64,
        sync_parent: impl FnOnce(&Path) -> io::Result<()>,
    ) -> io::Result<()> {
        let snapshot_delta = snapshot_delta(&current, &self.previous_snapshot);
        let shadow_delta = map_delta(&current_shadow, &self.previous_shadow);
        if snapshot_delta.total == 0 && shadow_delta.values().all(|count| *count == 0) {
            if self.parent_sync_pending {
                sync_parent(&self.window_path)?;
                self.parent_sync_pending = false;
            }
            return Ok(());
        }

        let _lock = ExclusiveFileLock::acquire(&self.lock_path)?;
        let mut window = read_window_file(&self.window_path)?;
        add_snapshot(&mut window.snapshot, &snapshot_delta)?;
        add_map(&mut window.tools_list_shadow, &shadow_delta)?;
        window.updated_at_unix_seconds = window.updated_at_unix_seconds.max(now);
        validate_window(&window)?;
        write_window_atomic(&self.window_path, &window)?;
        self.previous_snapshot = current;
        self.previous_shadow = current_shadow;
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

/// Load and validate the operator-readable production window.
pub fn load_durable_window(data_dir: &Path) -> io::Result<DurableWindow> {
    read_window_file(&durable_window_path(data_dir))
}

/// Evaluate the production decision from exact-window HTTP and stdio evidence.
///
/// HTTP observations live in Prometheus while stdio observations live in the
/// durable window. A revision is eligible only when both independent sources
/// mark it below the threshold for the same window.
pub fn production_retirement_decision(
    data_dir: &Path,
    http_snapshot: &Snapshot,
    http_started_at_unix_seconds: u64,
) -> io::Result<Result<Vec<String>, RetirementBlocked>> {
    production_retirement_decision_at(
        data_dir,
        http_snapshot,
        http_started_at_unix_seconds,
        unix_seconds()?,
    )
}

/// Time-injected production decision used by deterministic tests and offline exports.
pub fn production_retirement_decision_at(
    data_dir: &Path,
    http_snapshot: &Snapshot,
    http_started_at_unix_seconds: u64,
    ended_at_unix_seconds: u64,
) -> io::Result<Result<Vec<String>, RetirementBlocked>> {
    let window = load_durable_window(data_dir)?;
    if http_started_at_unix_seconds != window.started_at_unix_seconds {
        return Ok(Err(RetirementBlocked::WindowMisaligned));
    }
    let elapsed =
        Duration::from_secs(ended_at_unix_seconds.saturating_sub(http_started_at_unix_seconds));
    let stdio_candidates = match window.retirement_decision_at(ended_at_unix_seconds) {
        Ok(candidates) => candidates,
        Err(blocked) => return Ok(Err(blocked)),
    };
    let http_candidates = match retire_revisions(http_snapshot, elapsed) {
        Ok(candidates) => candidates,
        Err(blocked) => return Ok(Err(blocked)),
    };
    Ok(Ok(stdio_candidates
        .into_iter()
        .filter(|candidate| http_candidates.contains(candidate))
        .collect()))
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

fn add_map(target: &mut BTreeMap<String, u64>, delta: &BTreeMap<String, u64>) -> io::Result<()> {
    for (key, increment) in delta {
        let value = target.entry(key.clone()).or_insert(0);
        *value = checked_counter_add(*value, *increment)?;
    }
    Ok(())
}

fn checked_counter_add(current: u64, increment: u64) -> io::Result<u64> {
    current
        .checked_add(increment)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "telemetry counter overflow"))
}

fn read_window_file(path: &Path) -> io::Result<DurableWindow> {
    let bytes = std::fs::read(path)?;
    let window: DurableWindow = serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    validate_window(&window)?;
    Ok(window)
}

fn validate_window(window: &DurableWindow) -> io::Result<()> {
    if window.schema_version != DURABLE_WINDOW_SCHEMA {
        return Err(invalid_window("unsupported durable telemetry schema"));
    }
    if window.updated_at_unix_seconds < window.started_at_unix_seconds {
        return Err(invalid_window("window update precedes its start"));
    }
    validate_bounded_keys(
        &window.snapshot.by_revision,
        MEASURED_REVISIONS
            .iter()
            .copied()
            .chain(std::iter::once(OTHER_REVISION)),
        "revision",
    )?;
    validate_bounded_keys(
        &window.snapshot.by_client,
        MEASURED_CLIENTS.iter().copied(),
        "client",
    )?;
    validate_bounded_keys(
        &window.snapshot.by_transport,
        MEASURED_TRANSPORTS
            .iter()
            .map(|transport| transport.as_str()),
        "transport",
    )?;
    if checked_counter_sum(window.snapshot.by_revision.values().copied())?
        .checked_add(window.snapshot.unattributed)
        != Some(window.snapshot.total)
    {
        return Err(invalid_window("revision counters do not equal total"));
    }
    if checked_counter_sum(window.snapshot.by_client.values().copied())? != window.snapshot.total {
        return Err(invalid_window("client counters do not equal total"));
    }
    if checked_counter_sum(window.snapshot.by_transport.values().copied())? != window.snapshot.total
    {
        return Err(invalid_window("transport counters do not equal total"));
    }
    let expected_shadow = empty_shadow_counts();
    if window.tools_list_shadow.keys().ne(expected_shadow.keys()) {
        return Err(invalid_window("tools/list shadow labels are incomplete"));
    }
    Ok(())
}

fn validate_bounded_keys<'a>(
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

fn invalid_window(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn checked_counter_sum(mut values: impl Iterator<Item = u64>) -> io::Result<u64> {
    values.try_fold(0, checked_counter_add)
}

fn unix_seconds() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn write_window_atomic(path: &Path, window: &DurableWindow) -> io::Result<()> {
    let bytes = serde_json::to_vec_pretty(window)
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
fn sync_parent_directory(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "window has no parent"))?;
    File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn force_directory_owner_only(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn force_directory_owner_only(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
#[path = "durable_tests.rs"]
mod tests;
