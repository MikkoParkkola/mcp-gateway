// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The gateway's own health over time (decision D10, Gateway Status): added
//! latency, gateway errors, memory and sessions per half-hour, and the
//! restarts and coverage behind the 7-day uptime strip, kept in a bounded
//! `health.json` that survives restart. Every stored value is a number the
//! gateway measured itself; no caller input or label is kept.
//!
//! A separate file from `counters.json` so an older binary, which rejects
//! unknown kinds there, simply ignores it.

use std::collections::VecDeque;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

/// One half-hour bucket, in seconds.
pub(crate) const HALF: u64 = 1_800;
/// One uptime-strip block, in seconds.
pub(crate) const BLOCK: u64 = 21_600;
/// Half-hours kept: 16 complete ones for the sparklines and the current one.
const HALVES_KEPT: usize = 17;
/// Blocks kept: 28 complete ones for the strip and the current one.
const BLOCKS_KEPT: usize = 29;
/// Restart details kept; the block rollups count every restart regardless.
pub(crate) const MAX_RESTARTS: usize = 256;
/// Intervals the gateway cannot account for, kept.
const MAX_GAPS: usize = 32;
/// Latency buckets: the histogram's finite bounds plus one overflow bucket.
const LATENCY_SLOTS: usize = 12;

/// How a restart's downtime is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DowntimeSource {
    /// From a clean stop's recorded time to the next start.
    Measured,
    /// From the last save (the last moment known alive) to the next start: a
    /// conservative upper estimate.
    Estimated,
}

/// One restart of the gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Restart {
    pub(crate) stopped_at: u64,
    pub(crate) started_at: u64,
    pub(crate) downtime_source: DowntimeSource,
}

/// The 95th percentile of added latency over a span.
// Read by the Gateway Status route (the next change); built for tests now.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum P95 {
    /// The upper bound of the bucket holding the 95th percentile, in ms.
    Ms(f64),
    /// Above the largest finite bound, in ms.
    AboveMs(f64),
    /// No call in the span.
    NoData,
}

/// One half-hour of measurements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Half {
    pub(crate) start: u64,
    latency: [u64; LATENCY_SLOTS],
    errors: [u64; 4],
    pub(crate) memory_max: Option<u64>,
    pub(crate) sessions_max: Option<u64>,
}

/// One six-hour block of the uptime strip.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Block {
    pub(crate) start: u64,
    pub(crate) running_seconds: u64,
    pub(crate) down_seconds: u64,
    pub(crate) restarts: u32,
    /// Some downtime in this block is estimated.
    pub(crate) estimated: bool,
}

/// Uptime over a span of blocks.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Uptime {
    pub(crate) running_seconds: u64,
    pub(crate) down_seconds: u64,
    pub(crate) covered_seconds: u64,
    /// running / covered in percent; `None` when nothing is covered.
    pub(crate) percent: Option<f64>,
    pub(crate) coverage_complete: bool,
}

/// counters.json's count of restores (this start's included), as the
/// health history reads it to tell a run it did not record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Restores {
    /// Counted without a break since the file had the count.
    Counted(u64),
    /// The count started again this start: the file was last written by a
    /// binary that does not keep it, so a run went unrecorded.
    Restarted(u64),
}

/// What a start found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Started {
    /// No previous history: a first start, claiming no downtime.
    pub(crate) fresh: bool,
    /// A previous file did not decode; it was set aside.
    pub(crate) set_aside: bool,
    /// A run the history did not record happened since its last save.
    pub(crate) missed_run: bool,
    pub(crate) restart: Option<Restart>,
}

/// The persisted state.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Inner {
    v: u32,
    observed_since: u64,
    /// counters.json's Restart markers known at the last start.
    counters_seen: u64,
    started_at: u64,
    last_tick: u64,
    saved_at: u64,
    clean_stop: Option<u64>,
    halves: VecDeque<Half>,
    blocks: VecDeque<Block>,
    restarts: VecDeque<Restart>,
    /// The start of the newest restart detail dropped by the cap.
    dropped_newest: Option<u64>,
    gaps: VecDeque<(u64, u64)>,
    /// The end of the newest gap the cap dropped: time before it may hold
    /// an interval the gateway cannot account for.
    #[serde(default)]
    gaps_dropped_to: Option<u64>,
    #[serde(skip)]
    incomplete: bool,
}

/// The health history, shared by the recorders, the saver and the route.
pub(crate) struct HealthHistory(Mutex<Inner>);

pub(crate) mod file;
// The readers serve the Gateway Status route (the next change); built for
// tests until then.
#[cfg(test)]
mod read;
mod write;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
