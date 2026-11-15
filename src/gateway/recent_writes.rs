// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The recent-write sample: how many potentially-writing dispatches left the
//! gateway in the current second and the 60 complete seconds before it, read
//! by the restart warning. Over-counting is the safe side of every ambiguous
//! case: only a call its tool declares read-only goes uncounted.
use std::time::Instant;

use crate::security::decision_record::Effect;

/// Seconds a sample covers besides the current partial one.
#[allow(
    dead_code,
    reason = "only the web UI restart GET reads the sample; without the web UI nothing does"
)]
pub(crate) const WINDOW_SECS: u64 = 60;

/// One read of the counter, taken under its lock. `Copy`, so a bound sample
/// never changes after it is taken.
#[allow(
    dead_code,
    reason = "only the web UI restart GET reads the sample; without the web UI nothing does"
)]
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

/// Buckets in the ring: the current partial second and the 60 before it.
const BUCKETS: usize = 61;

/// 61 stamp-tagged one-second buckets and the running total, under one lock.
pub(crate) struct RecentWrites {
    start: Instant,
    ring: parking_lot::Mutex<Ring>,
}

/// Each bucket is (the whole second from start it counts, its count).
struct Ring {
    buckets: [(u64, u64); BUCKETS],
    writes_total: u64,
}

impl RecentWrites {
    /// A counter whose seconds are counted from `start`.
    pub(crate) fn new(start: Instant) -> Self {
        Self {
            start,
            ring: parking_lot::Mutex::new(Ring {
                buckets: [(0, 0); BUCKETS],
                writes_total: 0,
            }),
        }
    }

    /// Whole seconds from start to `at`; an instant before start reads 0.
    fn second(&self, at: Instant) -> u64 {
        at.saturating_duration_since(self.start).as_secs()
    }

    /// Count one write at `now`. A bucket still holding an older second
    /// restarts at this one.
    pub(crate) fn note(&self, now: Instant) {
        let second = self.second(now);
        let mut ring = self.ring.lock();
        let bucket = &mut ring.buckets[slot(second)];
        if bucket.0 != second {
            *bucket = (second, 0);
        }
        bucket.1 += 1;
        ring.writes_total += 1;
    }

    /// The window as of `now`: every bucket whose second is `now`'s or one of
    /// the 60 before it. A bucket stamped later than `now` (a note racing the
    /// sample) is outside it.
    #[allow(
        dead_code,
        reason = "only the web UI restart GET reads the sample; without the web UI nothing does"
    )]
    pub(crate) fn sample(&self, now: Instant) -> WriteSample {
        let second = self.second(now);
        let ring = self.ring.lock();
        let count = ring
            .buckets
            .iter()
            .filter(|(stamp, _)| {
                second
                    .checked_sub(*stamp)
                    .is_some_and(|age| age <= WINDOW_SECS)
            })
            .map(|(_, n)| n)
            .sum();
        WriteSample {
            count,
            complete_secs: u8::try_from(second.min(WINDOW_SECS)).unwrap_or(u8::MAX),
            taken_at_mono: now,
            writes_total: ring.writes_total,
        }
    }
}

/// The ring slot of a whole second.
fn slot(second: u64) -> usize {
    // The remainder is below 61, so it fits every usize.
    usize::try_from(second % BUCKETS as u64).unwrap_or(0)
}

/// The one rule: a dispatch counts unless its tool declared it read-only.
pub(crate) fn counts_as_write(effect: Option<Effect>) -> bool {
    effect != Some(Effect::ReadOnly)
}

/// Whether a direct-route forward of `method` counts: `tools/call` by its
/// slot's declared `effect`; every other method counts unless it is on the
/// read list (initialize, ping and the list and read methods).
pub(crate) fn direct_method_counts(method: &str, effect: Option<Effect>) -> bool {
    match method {
        "tools/call" => counts_as_write(effect),
        "initialize"
        | "ping"
        | "tools/list"
        | "resources/list"
        | "resources/read"
        | "resources/templates/list"
        | "prompts/list"
        | "prompts/get" => false,
        _ => true,
    }
}

#[cfg(test)]
#[path = "recent_writes_tests.rs"]
mod tests;
