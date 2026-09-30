// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! U1 v2 measurement window: per-transport counts, one segment per HTTP
//! process, and a decision that reads only sealed evidence.
//!
//! Design: `docs/design/2026-09-30-u1-durable-per-transport-window.md`.
//!
//! The decision half (`decide`, `parse_declaration`) runs only under the
//! operator's ignored test, so outside `cfg(test)` it is unreferenced.
#![cfg_attr(not(test), allow(dead_code))]

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{
    DURABLE_TELEMETRY_DIR, DURABLE_WINDOW_FILE, MEASURED_CLIENTS, MEASURED_REVISIONS, NAMED_CLIENTS,
    OTHER_REVISION, Snapshot, Transport, USER_AGENT_FAMILIES, checked_counter_sum,
    empty_shadow_counts, invalid_window, validate_bounded_keys,
};
use crate::fs_lock::ExclusiveFileLock;

/// Schema identifier of the v2 window.
pub(crate) const WINDOW_SCHEMA_V2: &str = "mcp_protocol_revision_window.v2";
/// The v1 identifier, refused on open and never converted.
const WINDOW_SCHEMA_V1: &str = "mcp_protocol_revision_window.v1";

/// One HTTP `serve` process's contribution, written cumulatively.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Segment {
    pub listen: String,
    pub exe: String,
    pub process_started_at: u64,
    pub opened_at: u64,
    pub last_checkpoint_at: u64,
    pub closed_cleanly: bool,
    /// Set at open, under the lock, when the previous segment was not closed:
    /// that writer crashed or is still serving.
    pub opened_while_another_was_open: bool,
    pub snapshot: Snapshot,
    pub missing_revision_agents: BTreeMap<String, u64>,
    pub tools_list_shadow: BTreeMap<String, u64>,
}

/// The v2 window file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct WindowV2 {
    pub schema_version: String,
    pub created_at_unix_seconds: u64,
    pub updated_at_unix_seconds: u64,
    /// Stdio counts, merged by delta from every stdio child. Reported only.
    pub stdio: Snapshot,
    pub missing_revision_agents: BTreeMap<String, u64>,
    pub tools_list_shadow: BTreeMap<String, u64>,
    pub http_segments: Vec<Segment>,
}

impl WindowV2 {
    pub(crate) fn empty(now: u64) -> Self {
        Self {
            schema_version: WINDOW_SCHEMA_V2.to_string(),
            created_at_unix_seconds: now,
            updated_at_unix_seconds: now,
            stdio: Snapshot::default(),
            missing_revision_agents: BTreeMap::new(),
            tools_list_shadow: empty_shadow_counts(),
            http_segments: Vec::new(),
        }
    }
}

pub(crate) fn window_paths(data_dir: &Path) -> (PathBuf, PathBuf) {
    let directory = data_dir.join(DURABLE_TELEMETRY_DIR);
    (
        directory.join(DURABLE_WINDOW_FILE),
        directory.join(".window.lock"),
    )
}

/// Read and validate a v2 window. A v1 file is refused with the archive
/// instruction: converting it would claim HTTP coverage it never had.
pub(crate) fn read_window_v2(path: &Path) -> io::Result<WindowV2> {
    let bytes = std::fs::read(path)?;
    let schema = serde_json::from_slice::<serde_json::Value>(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    if schema.as_deref() == Some(WINDOW_SCHEMA_V1) {
        return Err(invalid_window(&format!(
            "v1 protocol-revision window at {}: archive (move) its directory, then restart; it is never converted",
            path.display()
        )));
    }
    let window: WindowV2 = serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    validate_window_v2(&window)?;
    Ok(window)
}

pub(crate) fn validate_window_v2(window: &WindowV2) -> io::Result<()> {
    if window.schema_version != WINDOW_SCHEMA_V2 {
        return Err(invalid_window("unsupported durable telemetry schema"));
    }
    if window.updated_at_unix_seconds < window.created_at_unix_seconds {
        return Err(invalid_window("window update precedes its creation"));
    }
    validate_snapshot(&window.stdio, Transport::Stdio)?;
    validate_agents(&window.missing_revision_agents)?;
    validate_shadow(&window.tools_list_shadow)?;
    for segment in &window.http_segments {
        if segment.last_checkpoint_at < segment.opened_at {
            return Err(invalid_window("segment checkpoint precedes its open"));
        }
        validate_snapshot(&segment.snapshot, Transport::Http)?;
        validate_agents(&segment.missing_revision_agents)?;
        validate_shadow(&segment.tools_list_shadow)?;
    }
    Ok(())
}

fn validate_snapshot(snapshot: &Snapshot, transport: Transport) -> io::Result<()> {
    validate_bounded_keys(
        &snapshot.by_revision,
        MEASURED_REVISIONS
            .iter()
            .copied()
            .chain(std::iter::once(OTHER_REVISION)),
        "revision",
    )?;
    validate_bounded_keys(&snapshot.by_client, MEASURED_CLIENTS.iter().copied(), "client")?;
    validate_bounded_keys(
        &snapshot.by_transport,
        std::iter::once(transport.as_str()),
        "transport",
    )?;
    let total = Some(snapshot.total);
    if checked_counter_sum(snapshot.by_revision.values().copied())?
        .checked_add(snapshot.unattributed)
        != total
    {
        return Err(invalid_window("revision counters do not equal total"));
    }
    if Some(checked_counter_sum(snapshot.by_client.values().copied())?) != total {
        return Err(invalid_window("client counters do not equal total"));
    }
    if Some(checked_counter_sum(snapshot.by_transport.values().copied())?) != total {
        return Err(invalid_window("transport counters do not equal total"));
    }
    Ok(())
}

fn validate_agents(agents: &BTreeMap<String, u64>) -> io::Result<()> {
    validate_bounded_keys(
        agents,
        NAMED_CLIENTS
            .iter()
            .chain(USER_AGENT_FAMILIES.iter())
            .copied(),
        "missing-revision agent",
    )
}

fn validate_shadow(shadow: &BTreeMap<String, u64>) -> io::Result<()> {
    if shadow.keys().ne(empty_shadow_counts().keys()) {
        return Err(invalid_window("tools/list shadow labels are incomplete"));
    }
    Ok(())
}

/// Write-then-rename under the caller's lock, then sync the directory.
pub(crate) fn write_window_v2(path: &Path, window: &WindowV2) -> io::Result<()> {
    validate_window_v2(window)?;
    super::write_json_atomic(path, window)?;
    super::sync_parent_directory(path)
}

/// Read the window, creating an empty one when absent. Caller holds the lock.
pub(crate) fn read_or_create(path: &Path, now: u64) -> io::Result<WindowV2> {
    match read_window_v2(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let window = WindowV2::empty(now);
            write_window_v2(path, &window)?;
            Ok(window)
        }
        other => other,
    }
}

pub(crate) fn lock(lock_path: &Path) -> io::Result<ExclusiveFileLock> {
    ExclusiveFileLock::acquire(lock_path)
}

/// Who an HTTP segment claims to be. Checked against the operator's
/// declaration at decision time, never trusted from the file alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WriterIdentity {
    pub listen: String,
    pub exe: String,
    pub process_started_at: u64,
}

/// One HTTP process's segment in the shared window.
#[derive(Debug)]
pub(crate) struct HttpSegmentSink {
    window_path: PathBuf,
    lock_path: PathBuf,
    index: usize,
    identity: WriterIdentity,
}

/// Counts an HTTP segment writes: cumulative for this process.
#[derive(Debug, Clone, Default)]
pub(crate) struct SegmentCounts {
    pub snapshot: Snapshot,
    pub missing_revision_agents: BTreeMap<String, u64>,
    pub tools_list_shadow: BTreeMap<String, u64>,
}

impl HttpSegmentSink {
    /// Append this process's segment. Under the lock, a previous segment that
    /// is not closed marks the new one as opened alongside another writer.
    pub(crate) fn open(data_dir: &Path, identity: WriterIdentity, now: u64) -> io::Result<Self> {
        let (window_path, lock_path) = window_paths(data_dir);
        let directory = data_dir.join(DURABLE_TELEMETRY_DIR);
        std::fs::create_dir_all(&directory)?;
        super::force_directory_owner_only(&directory)?;
        let _lock = lock(&lock_path)?;
        let mut window = read_or_create(&window_path, now)?;
        let opened_while_another_was_open = false; // RED STUB
        window.http_segments.push(Segment {
            listen: identity.listen.clone(),
            exe: identity.exe.clone(),
            process_started_at: identity.process_started_at,
            opened_at: now,
            last_checkpoint_at: now,
            closed_cleanly: false,
            opened_while_another_was_open,
            snapshot: Snapshot::default(),
            missing_revision_agents: BTreeMap::new(),
            tools_list_shadow: empty_shadow_counts(),
        });
        window.updated_at_unix_seconds = window.updated_at_unix_seconds.max(now);
        let index = window.http_segments.len() - 1;
        write_window_v2(&window_path, &window)?;
        Ok(Self {
            window_path,
            lock_path,
            index,
            identity,
        })
    }

    /// Rewrite this segment's cumulative counts. `close` seals it. A failed
    /// write loses nothing: the next one carries the same cumulative counts.
    pub(crate) fn checkpoint(&mut self, counts: &SegmentCounts, now: u64, close: bool) -> io::Result<()> {
        let _lock = lock(&self.lock_path)?;
        let mut window = read_window_v2(&self.window_path)?;
        let segment = window
            .http_segments
            .get_mut(self.index)
            .filter(|segment| {
                segment.exe == self.identity.exe
                    && segment.process_started_at == self.identity.process_started_at
            })
            .ok_or_else(|| invalid_window("this process's segment is missing from the window"))?;
        segment.snapshot = counts.snapshot.clone();
        segment.missing_revision_agents = counts.missing_revision_agents.clone();
        segment.tools_list_shadow = counts.tools_list_shadow.clone();
        segment.last_checkpoint_at = segment.last_checkpoint_at.max(now);
        segment.closed_cleanly = close;
        window.updated_at_unix_seconds = window.updated_at_unix_seconds.max(now);
        write_window_v2(&self.window_path, &window)
    }
}

/// Seconds allowed between one segment's close and the next process's start.
pub(crate) const RESTART_BUDGET_SECONDS: u64 = 300;

/// The operator's declaration. Provenance comes from here, never the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Declaration {
    pub population: Vec<Transport>,
    pub listen: String,
    pub exe_prefix: String,
}

/// Why the v2 window cannot certify a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WindowBlocked {
    Retirement(super::RetirementBlocked),
    PopulationMismatch,
    UncleanSegment,
    ConcurrentHttpWriters,
    ForeignWriter,
    CoverageGap,
    NoSealedSegment,
}

/// The sealed span a decision was computed over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SealedSpan {
    pub started_at: u64,
    pub ended_at: u64,
    pub segments: usize,
    pub snapshot: Snapshot,
}

/// Evaluate the sealed prefix of clean HTTP segments against the declaration.
pub(crate) fn decide(
    window: &WindowV2,
    declaration: &Declaration,
) -> (Option<SealedSpan>, Result<Vec<String>, WindowBlocked>) {
    let span = sealed_span(window);
    let outcome = gate(window, declaration, span.as_ref());
    (span, outcome)
}

fn sealed_span(window: &WindowV2) -> Option<SealedSpan> {
    let sealed: Vec<&Segment> = window
        .http_segments
        .iter()
        .take_while(|segment| segment.closed_cleanly)
        .collect();
    let (first, last) = (sealed.first()?, sealed.last()?);
    let mut snapshot = Snapshot::default();
    for segment in &sealed {
        // Validated on read: every counter sum is checked, so saturating here
        // only guards arithmetic that validation already bounded.
        add_saturating(&mut snapshot, &segment.snapshot);
    }
    Some(SealedSpan {
        started_at: first.opened_at,
        ended_at: last.last_checkpoint_at,
        segments: sealed.len(),
        snapshot,
    })
}

fn gate(
    window: &WindowV2,
    declaration: &Declaration,
    span: Option<&SealedSpan>,
) -> Result<Vec<String>, WindowBlocked> {
    // RED STUB: certifies everything; replaced by the implementation commit.
    let _ = (window, declaration, span, RESTART_BUDGET_SECONDS);
    let _ = [WindowBlocked::ConcurrentHttpWriters, WindowBlocked::NoSealedSegment];
    Ok(Vec::new())
}

fn add_saturating(target: &mut Snapshot, delta: &Snapshot) {
    for (into, from) in [
        (&mut target.by_revision, &delta.by_revision),
        (&mut target.by_client, &delta.by_client),
        (&mut target.by_transport, &delta.by_transport),
    ] {
        for (key, value) in from {
            let entry = into.entry(key.clone()).or_insert(0);
            *entry = entry.saturating_add(*value);
        }
    }
    target.unattributed = target.unattributed.saturating_add(delta.unattributed);
    target.total = target.total.saturating_add(delta.total);
}

/// Parse the operator's declaration. Every value is required; `~` is not
/// expanded, so the prefix must be absolute.
pub(crate) fn parse_declaration(
    population: Option<&str>,
    listen: Option<&str>,
    exe_prefix: Option<&str>,
) -> io::Result<Declaration> {
    let required = |value: Option<&str>, name: &str| {
        value
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("{name} is required")))
    };
    let population = match required(population, "U1_POPULATION")?.as_str() {
        "http" => vec![Transport::Http],
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("U1_POPULATION={other}: only `http` can be certified"),
            ));
        }
    };
    let listen = required(listen, "U1_LISTEN")?;
    listen
        .parse::<std::net::SocketAddr>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, format!("U1_LISTEN: {error}")))?;
    let exe_prefix = required(exe_prefix, "U1_EXE_PREFIX")?;
    if !Path::new(&exe_prefix).is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "U1_EXE_PREFIX must be an absolute path",
        ));
    }
    Ok(Declaration {
        population,
        listen,
        exe_prefix,
    })
}

#[cfg(test)]
#[path = "protocol_revision_telemetry_window_tests.rs"]
mod tests;
