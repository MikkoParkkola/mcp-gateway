// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The recent-write sample: how many potentially-writing dispatches left the
//! gateway in the current second and the 60 complete seconds before it, read
//! by the restart warning. Over-counting is the safe side of every ambiguous
//! case: only a call its tool declares read-only goes uncounted.
#![allow(
    dead_code,
    clippy::unused_self,
    reason = "red-phase: remove when the counting points land"
)]

use std::time::Instant;

use crate::security::decision_record::Effect;

/// Seconds a sample covers besides the current partial one.
pub(crate) const WINDOW_SECS: u64 = 60;

/// One read of the counter, taken under its lock. `Copy`, so a bound sample
/// never changes after it is taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WriteSample {
    /// Writes in the current partial second and the 60 complete ones before it.
    pub(crate) count: u64,
    /// Complete seconds covered: whole seconds since start, at most 60. Under
    /// 60 in the first minute (incomplete coverage).
    pub(crate) complete_secs: u8,
    /// When the sample was taken, on the monotonic clock.
    pub(crate) taken_at_mono: Instant,
    /// Every counted write since start; never decreases.
    pub(crate) writes_total: u64,
}

/// 61 stamp-tagged one-second buckets and the running total, under one lock.
pub(crate) struct RecentWrites {
    start: Instant,
    ring: parking_lot::Mutex<Ring>,
}

/// Each bucket keeps the whole second (from start) it counts.
struct Ring {
    buckets: [(u64, u64); 61],
    writes_total: u64,
}

impl RecentWrites {
    /// A counter whose seconds are counted from `start`.
    pub(crate) fn new(start: Instant) -> Self {
        Self {
            start,
            ring: parking_lot::Mutex::new(Ring {
                buckets: [(0, 0); 61],
                writes_total: 0,
            }),
        }
    }

    /// Count one write at `now`.
    pub(crate) fn note(&self, _now: Instant) {}

    /// The window as of `now`.
    pub(crate) fn sample(&self, now: Instant) -> WriteSample {
        WriteSample {
            count: 0,
            complete_secs: 0,
            taken_at_mono: now,
            writes_total: 0,
        }
    }
}

/// The one rule: a dispatch counts unless its tool declared it read-only.
pub(crate) fn counts_as_write(_effect: Option<Effect>) -> bool {
    false
}

/// Whether a direct-route forward of `method` counts: `tools/call` by its
/// slot's declared `effect`; every other method counts unless it is on the
/// read list (initialize, ping and the list and read methods).
pub(crate) fn direct_method_counts(_method: &str, _effect: Option<Effect>) -> bool {
    false
}

#[cfg(test)]
#[path = "recent_writes_tests.rs"]
mod tests;
