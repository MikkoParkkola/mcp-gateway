// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! U1 v2 measurement window: per-transport counts and one segment per HTTP
//! `serve` process. The decision half is `window_decide` (test-only).
//!
//! Design: `docs/design/2026-10-17-u1-window-v2-release-line.md`.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::agents::{NAMED_CLIENTS, USER_AGENT_FAMILIES};
use super::durable::{checked_counter_sum, invalid_window, validate_bounded_keys};
use super::{
    DURABLE_TELEMETRY_DIR, DURABLE_WINDOW_FILE, MEASURED_CLIENTS, MEASURED_REVISIONS,
    OTHER_REVISION, Snapshot, Transport, empty_shadow_counts,
};

/// Schema identifier of the v2 window.
pub(crate) const WINDOW_SCHEMA_V2: &str = "mcp_protocol_revision_window.v2";
/// The v1 identifier: refused on open, never converted.
const WINDOW_SCHEMA_V1: &str = "mcp_protocol_revision_window.v1";

/// One HTTP `serve` process's contribution, written cumulatively.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Segment {
    pub(crate) listen: String,
    pub(crate) exe: String,
    pub(crate) process_started_at_ms: u64,
    pub(crate) opened_at: u64,
    pub(crate) last_checkpoint_at: u64,
    /// The clock read at the seal itself; present exactly when closed.
    pub(crate) sealed_at_ms: Option<u64>,
    /// True only in the same write as the sealed counts.
    pub(crate) closed_cleanly: bool,
    pub(crate) snapshot: Snapshot,
    pub(crate) missing_revision_agents: BTreeMap<String, u64>,
    pub(crate) tools_list_shadow: BTreeMap<String, u64>,
}

/// The v2 window file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct WindowV2 {
    pub(crate) schema_version: String,
    pub(crate) created_at_unix_seconds: u64,
    pub(crate) updated_at_unix_seconds: u64,
    /// Stdio counts, merged by delta from every stdio child. Reported only.
    pub(crate) stdio: Snapshot,
    pub(crate) missing_revision_agents: BTreeMap<String, u64>,
    pub(crate) tools_list_shadow: BTreeMap<String, u64>,
    pub(crate) http_segments: Vec<Segment>,
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

/// `(window.json, .window.lock)` below a data directory.
pub(crate) fn window_paths(data_dir: &Path) -> (PathBuf, PathBuf) {
    let directory = data_dir.join(DURABLE_TELEMETRY_DIR);
    (
        directory.join(DURABLE_WINDOW_FILE),
        directory.join(".window.lock"),
    )
}

/// Read and validate the v2 window below `data_dir` (tests and the operator
/// command read it; the writers go through their own locked read).
#[cfg(test)]
pub(crate) fn load(data_dir: &Path) -> io::Result<WindowV2> {
    read_window_v2(&window_paths(data_dir).0)
}

/// [`load`] by file path. A v1 file is refused with the archive
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
            "v1 protocol-revision window at {}: archive (move) its directory, then restart; \
             it is never converted",
            path.display()
        )));
    }
    let window: WindowV2 = serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    validate_window_v2(&window)?;
    Ok(window)
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

/// Validate, write-then-rename, then sync the directory. Caller holds the lock.
pub(crate) fn write_window_v2(path: &Path, window: &WindowV2) -> io::Result<()> {
    validate_window_v2(window)?;
    super::durable::write_json_atomic(path, window)?;
    super::durable::sync_parent_directory(path)
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
        if segment.closed_cleanly != segment.sealed_at_ms.is_some() {
            return Err(invalid_window("a segment's seal time and close disagree"));
        }
        validate_snapshot(&segment.snapshot, Transport::Http)?;
        validate_agents(&segment.missing_revision_agents)?;
        validate_shadow(&segment.tools_list_shadow)?;
    }
    Ok(())
}

fn validate_snapshot(snapshot: &Snapshot, transport: Transport) -> io::Result<()> {
    let revisions = MEASURED_REVISIONS
        .iter()
        .copied()
        .chain(std::iter::once(OTHER_REVISION));
    validate_bounded_keys(&snapshot.by_revision, revisions, "revision")?;
    validate_bounded_keys(
        &snapshot.by_client,
        MEASURED_CLIENTS.iter().copied(),
        "client",
    )?;
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
    if Some(checked_counter_sum(
        snapshot.by_transport.values().copied(),
    )?) != total
    {
        return Err(invalid_window("transport counters do not equal total"));
    }
    Ok(())
}

fn validate_agents(agents: &BTreeMap<String, u64>) -> io::Result<()> {
    let allowed = NAMED_CLIENTS.iter().chain(USER_AGENT_FAMILIES).copied();
    validate_bounded_keys(agents, allowed, "missing-revision agent")
}

fn validate_shadow(shadow: &BTreeMap<String, u64>) -> io::Result<()> {
    if shadow.keys().ne(empty_shadow_counts().keys()) {
        return Err(invalid_window("tools/list shadow labels are incomplete"));
    }
    Ok(())
}

#[path = "window_sink.rs"]
mod sink;
#[cfg(test)]
pub(crate) use sink::stall_seam;
pub(crate) use sink::{HttpSegmentSink, SegmentCounts, WriterIdentity, global_segment_counts};

#[cfg(test)]
#[path = "window_tests.rs"]
mod tests;
