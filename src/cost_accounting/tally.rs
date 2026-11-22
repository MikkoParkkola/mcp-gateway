// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Bounded cost counters (MIK-8000).
//!
//! Spend used to be kept as one record per answered call, and nothing trimmed
//! it: a caller with no credential grew the gateway's memory once per request.
//! These hold running sums instead, so what a key, session or caller keeps
//! depends on the catalog and the clock, never on how often it calls.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::NaiveDate;

use super::{BackendCost, ToolCost};

/// Distinct `(backend, tool)` rows one tally keeps. Later pairs add into one
/// `(other)` row: tool names are bounded by the catalog only while R2 refuses
/// absent tools, and a backend can switch R2 off.
pub(crate) const MAX_TOOL_ROWS: usize = 256;

/// The row overflowed pairs are reported under.
pub(crate) const OTHER: &str = "(other)";

/// Hours of spend a key keeps: the 30-day window plus its partial cutoff hour.
pub(crate) const BUCKET_HOURS: u64 = 720;

/// Longest `backend` plus `tool` name, in bytes, that gets its own row; a
/// longer pair counts in `(other)`. With R2 off a caller picks the tool name,
/// so the row cap alone would bound rows but not bytes.
pub(crate) const MAX_ROW_NAME_BYTES: usize = 256;

/// `[calls, tokens, micro-USD]` per `(backend, tool)`, capped at
/// [`MAX_TOOL_ROWS`] rows plus one overflow row.
#[derive(Debug, Default)]
pub(crate) struct ToolTally {
    rows: HashMap<(String, String), [u64; 3]>,
    overflow: [u64; 3],
}

impl ToolTally {
    /// Add one call on `backend`/`tool`.
    pub(crate) fn add(&mut self, backend: &str, tool: &str, tokens: u64, micro: u64) {
        let counts = [1, tokens, micro];
        // An over-long pair never has a row, so it needs no lookup or copy.
        if backend.len() + tool.len() <= MAX_ROW_NAME_BYTES {
            let key = (backend.to_string(), tool.to_string());
            if self.rows.contains_key(&key) || self.rows.len() < MAX_TOOL_ROWS {
                let row = self.rows.entry(key).or_default();
                for (total, add) in row.iter_mut().zip(counts) {
                    *total += add;
                }
                return;
            }
        }
        // Once per tally, on its first overflowed call. No name is logged:
        // with R2 off the caller chooses the tool name.
        if self.overflow[0] == 0 {
            tracing::warn!(
                max_rows = MAX_TOOL_ROWS,
                max_name_bytes = MAX_ROW_NAME_BYTES,
                "A cost breakdown reached its row or name-size limit; further tools in it are counted under (other)"
            );
        }
        for (total, add) in self.overflow.iter_mut().zip(counts) {
            *total += add;
        }
    }

    /// Rows held, the overflow row counted once it has a call.
    pub(crate) fn len(&self) -> usize {
        self.rows.len() + usize::from(self.overflow[0] > 0)
    }

    /// Per-backend and per-tool rows, and `[calls, tokens, micro]` totals.
    pub(crate) fn breakdown(&self) -> (Vec<BackendCost>, Vec<ToolCost>, [u64; 3]) {
        // The overflow row is told apart by position, never by name: a real
        // backend and tool may both be called "(other)".
        let overflow = (self.overflow[0] > 0).then(|| (OTHER, OTHER.to_string(), &self.overflow));
        let rows = self
            .rows
            .iter()
            .map(|((backend, tool), counters)| {
                (backend.as_str(), format!("{backend}:{tool}"), counters)
            })
            .chain(overflow);
        let mut by_backend: HashMap<&str, BackendCost> = HashMap::new();
        let mut by_tool = Vec::with_capacity(self.len());
        let mut totals = [0u64; 3];
        for (backend, tool_key, &[calls, tokens, micro]) in rows {
            let cost = usd(micro);
            by_tool.push(ToolCost {
                tool_key,
                call_count: calls,
                token_count: tokens,
                cost_usd: cost,
            });
            let row = by_backend.entry(backend).or_insert_with(|| BackendCost {
                backend: backend.to_string(),
                call_count: 0,
                token_count: 0,
                cost_usd: 0.0,
            });
            row.call_count += calls;
            row.token_count += tokens;
            row.cost_usd += cost;
            for (total, add) in totals.iter_mut().zip([calls, tokens, micro]) {
                *total += add;
            }
        }
        (by_backend.into_values().collect(), by_tool, totals)
    }
}

/// Local dates of spend a series keeps: today and the 29 before it (ADR-017).
pub(crate) const KEPT_DAYS: i64 = 30;

/// Where a bucket sits, an hour number or a local date, and when it has aged
/// out of a window whose newest slot is `newest`.
pub(crate) trait Slot: Copy + Ord {
    fn expired(self, newest: Self) -> bool;
}

impl Slot for u64 {
    /// Kept while no more than [`BUCKET_HOURS`] hours older than the newest.
    fn expired(self, newest: u64) -> bool {
        self + BUCKET_HOURS < newest
    }
}

impl Slot for NaiveDate {
    /// Kept while one of the [`KEPT_DAYS`] dates ending at the newest:
    /// counted in calendar dates, so a 23- or 25-hour day is one.
    fn expired(self, newest: NaiveDate) -> bool {
        (newest - self).num_days() >= KEPT_DAYS
    }
}

/// `(slot, tokens, micro-USD)` per slot that has spend, oldest first.
#[derive(Debug, Clone)]
pub(crate) struct Buckets<S>(VecDeque<(S, u64, u64)>);

impl<S> Default for Buckets<S> {
    fn default() -> Self {
        Self(VecDeque::new())
    }
}

/// Spend per hour number: at most [`BUCKET_HOURS`] + 1 of them, so a 30-day
/// window keeps its partial first hour.
pub(crate) type HourBuckets = Buckets<u64>;

/// Spend per local date in the host's zone (ADR-026): at most [`KEPT_DAYS`].
pub(crate) type DayTotals = Buckets<NaiveDate>;

/// Unix second `secs` as a date in the host's zone, the way the budget
/// dates its days (ADR-026).
pub(crate) fn local_date(secs: u64) -> NaiveDate {
    crate::local_day::local_day(&crate::local_day::host_zone(), secs).date
}

impl<S: Slot> Buckets<S> {
    /// Add spend in `slot`. The newest of `floor`, `slot` and what is held
    /// ends the window: a clock that steps back cannot widen it.
    pub(crate) fn add_slot(&mut self, slot: S, floor: S, tokens: u64, micro: u64) {
        let newest = self
            .newest()
            .map_or(floor, |held| held.max(floor))
            .max(slot);
        // Past the window: nothing kept. Counted in the all-time tally.
        if slot.expired(newest) {
            return;
        }
        // A clock that stepped back lands in its own slot, in order.
        let at_or_before = self.0.iter().rposition(|(s, ..)| *s <= slot);
        match at_or_before {
            Some(i) if self.0[i].0 == slot => {
                // Saturating: a restored file's numbers are not trusted.
                self.0[i].1 = self.0[i].1.saturating_add(tokens);
                self.0[i].2 = self.0[i].2.saturating_add(micro);
            }
            Some(i) => self.0.insert(i + 1, (slot, tokens, micro)),
            None => self.0.push_front((slot, tokens, micro)),
        }
        while self.0.front().is_some_and(|(s, ..)| s.expired(newest)) {
            self.0.pop_front();
        }
    }

    /// The newest slot with spend, if any.
    pub(crate) fn newest(&self) -> Option<S> {
        self.0.back().map(|(s, ..)| *s)
    }

    /// Buckets held.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    /// Every `(slot, tokens, micro-USD)` held, oldest first.
    #[cfg(any(test, feature = "cost-governance"))]
    pub(crate) fn rows(&self) -> Vec<(S, u64, u64)> {
        self.0.iter().copied().collect()
    }

    /// End the window at `newest`: a slot dated after it is counted in
    /// `newest`'s own slot, amounts summed, and the slots the window no
    /// longer holds are dropped. Afterwards no slot is dated after `newest`.
    pub(crate) fn settle(&mut self, newest: S) {
        for (slot, tokens, micro) in std::mem::take(&mut self.0) {
            self.add_slot(slot.min(newest), newest, tokens, micro);
        }
    }

    /// The micro-USD summed over every slot held.
    #[cfg(feature = "cost-governance")]
    pub(crate) fn micro_total(&self) -> u64 {
        self.0
            .iter()
            .fold(0, |sum, (.., micro)| sum.saturating_add(*micro))
    }
}

impl HourBuckets {
    /// Add spend at unix second `at`; the window ends no earlier than `now`.
    pub(crate) fn add(&mut self, at: u64, now: u64, tokens: u64, micro: u64) {
        self.add_slot(at / 3600, now / 3600, tokens, micro);
    }

    /// Tokens and USD from the hour holding `now - window_secs` onward.
    pub(crate) fn totals(&self, now: u64, window_secs: u64) -> (u64, f64) {
        let from = now.saturating_sub(window_secs) / 3600;
        let (tokens, micro) = self
            .0
            .iter()
            .filter(|(h, ..)| *h >= from)
            // Saturating: a restored file can hold any numbers.
            .fold((0u64, 0u64), |(t, m), (_, tok, mic)| {
                (t.saturating_add(*tok), m.saturating_add(*mic))
            });
        (tokens, usd(micro))
    }
}

/// One spend series: its hours, for the rolling windows, and its local days.
#[derive(Debug, Clone, Default)]
pub(crate) struct Series {
    pub(crate) hours: HourBuckets,
    pub(crate) days: DayTotals,
}

impl Series {
    /// Add spend at unix second `at`, the windows ending no earlier than `now`.
    pub(crate) fn add(&mut self, at: u64, now: u64, tokens: u64, micro: u64) {
        // Recorded spend is never dropped. A record so far behind the newest
        // held hour or date that a window ending there would not keep it (a
        // clock that stepped back past the window) settles the series at
        // `now` first: the held later slots count in `now`'s own slots, and
        // the record lands in its window. Any other record, a race across a
        // boundary or a smaller step back, goes in as it comes, every slot
        // keeping its date.
        let (hour, date) = (at / 3600, local_date(at));
        let past_hours = self.hours.newest().is_some_and(|held| hour.expired(held));
        let past_dates = self.days.newest().is_some_and(|held| date.expired(held));
        if past_hours || past_dates {
            self.settle(now / 3600, local_date(now));
        }
        self.hours.add(at, now, tokens, micro);
        self.days.add_slot(date, local_date(now), tokens, micro);
    }

    /// End the hours at `hour` and the dates at `date`: see
    /// [`Buckets::settle`].
    pub(crate) fn settle(&mut self, hour: u64, date: NaiveDate) {
        self.hours.settle(hour);
        self.days.settle(date);
    }

    /// Add each of `other`'s rows into this series' row for the same hour or
    /// date, so a sum of series is bounded like one series. Both series must
    /// be settled at one instant first: the window here ends at the newest
    /// slot either holds, so a slot past the other's window would age the
    /// other's rows out of the sum.
    #[cfg(any(test, feature = "cost-governance"))]
    pub(crate) fn merge(&mut self, other: &Self) {
        for &(hour, tokens, micro) in &other.hours.0 {
            self.hours.add_slot(hour, hour, tokens, micro);
        }
        for &(date, tokens, micro) in &other.days.0 {
            self.days.add_slot(date, date, tokens, micro);
        }
    }
}

/// Minimum seconds between two idle sweeps of one map.
pub(crate) const SWEEP_EVERY: u64 = 60;

/// True for exactly one caller once `next` is due, which re-arms it
/// [`SWEEP_EVERY`] ahead: an opportunistic sweep needs no background task.
pub(crate) fn sweep_due(next: &AtomicU64, now: u64) -> bool {
    let due = next.load(Ordering::Relaxed);
    now >= due
        && next
            .compare_exchange(due, now + SWEEP_EVERY, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
}

/// `usd` as whole micro-USD, the unit every total is kept in. A positive cost
/// rounds up, so a budget never counts a call for less than its price
/// (MIK-8081). A price that is a whole number of micro-USD keeps that number
/// even when the product picks up float noise: 0.07 is 70000, not 70001.
/// Zero, negative and `NaN` read as 0.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub(crate) fn micro(usd: f64) -> u64 {
    if usd.is_nan() || usd <= 0.0 {
        return 0;
    }
    let whole = (usd * 1_000_000.0).round();
    // A price above the whole micro-USD it rounds to has a fraction left,
    // even one the multiplication lost; it counts as one more.
    (whole as u64).saturating_add(u64::from(usd > whole / 1_000_000.0))
}

#[allow(clippy::cast_precision_loss)]
fn usd(micro: u64) -> f64 {
    micro as f64 / 1_000_000.0
}

#[cfg(tp2)]
#[cfg(test)]
#[path = "tally_tests.rs"]
mod tests;
