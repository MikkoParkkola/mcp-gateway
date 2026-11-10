// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The process-level health metrics: active sessions, start time and, on
//! Linux, resident memory.

use chrono::{DateTime, Utc};

/// Sessions the notification multiplexer holds.
pub(crate) const SESSIONS: &str = "mcp_gateway_sessions_active";
/// When the process started, as Unix seconds.
pub(crate) const START_TIME: &str = "process_start_time_seconds";
/// Resident set size; not a recorder gauge, see [`resident_memory_exposition`].
const RESIDENT: &str = "process_resident_memory_bytes";
/// The help text the scrape carries for [`RESIDENT`].
const RESIDENT_HELP: &str =
    "Resident set size. Linux only (read from /proc/self/statm); absent on other systems.";

/// Set the active-session gauge to `count`, at scrape time.
#[allow(clippy::cast_precision_loss)] // session counts are far below 2^53
pub(crate) fn record_sessions(count: usize) {
    telemetry_metrics::gauge!(SESSIONS).set(count as f64);
}

/// Set the start-time gauge from the process start; unset when the host clock
/// could not be read at start.
#[allow(clippy::cast_precision_loss)] // Unix seconds stay below 2^53 until year 285 million
pub(crate) fn record_start_time(wall: Option<DateTime<Utc>>) {
    if let Some(wall) = wall {
        telemetry_metrics::gauge!(START_TIME).set(wall.timestamp() as f64);
    }
}

/// Help text for the gauges this module sets.
pub(crate) fn register() {
    telemetry_metrics::describe_gauge!(
        SESSIONS,
        "Client sessions the gateway holds right now, read at scrape time."
    );
    telemetry_metrics::describe_gauge!(
        START_TIME,
        telemetry_metrics::Unit::Seconds,
        "When the gateway process started, in Unix seconds."
    );
}

/// The resident-memory sample for one scrape, as exposition text, or an empty
/// string when it cannot be read or the system is not Linux. A recorder gauge
/// would keep the last good value after a failed read; text appended per
/// scrape shows nothing instead.
pub(crate) fn resident_memory_exposition() -> String {
    super::memory::resident_memory_bytes().map_or_else(String::new, exposition_of)
}

/// [`resident_memory_exposition`] reading `statm` at `path`, pages of `page` bytes.
#[cfg(test)]
pub(super) fn exposition_from(path: &std::path::Path, page: u64) -> String {
    super::memory::bytes_from(path, page).map_or_else(String::new, exposition_of)
}

/// The exposition text for `bytes` of resident memory.
fn exposition_of(bytes: u64) -> String {
    format!("# HELP {RESIDENT} {RESIDENT_HELP}\n# TYPE {RESIDENT} gauge\n{RESIDENT} {bytes}\n")
}
