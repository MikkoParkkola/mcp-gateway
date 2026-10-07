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
        let key = (backend.to_string(), tool.to_string());
        let fits = backend.len() + tool.len() <= MAX_ROW_NAME_BYTES;
        let row = if self.rows.contains_key(&key) || (fits && self.rows.len() < MAX_TOOL_ROWS) {
            self.rows.entry(key).or_default()
        } else {
            &mut self.overflow
        };
        for (total, add) in row.iter_mut().zip([1, tokens, micro]) {
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

/// `(hour, tokens, micro-USD)` per hour with spend, oldest first: at most
/// [`BUCKET_HOURS`] + 1, the cutoff hour of a 30-day window included.
#[derive(Debug, Default)]
pub(crate) struct HourBuckets(VecDeque<(u64, u64, u64)>);

impl HourBuckets {
    /// Add spend at unix second `at`. The window ends at the latest of `now`,
    /// `at` and the newest bucket held, so a clock stepping back never widens it.
    pub(crate) fn add(&mut self, at: u64, now: u64, tokens: u64, micro: u64) {
        let hour = at / 3600;
        let newest = (now / 3600).max(hour).max(self.newest_hour().unwrap_or(0));
        // Past the window: nothing kept. Counted in the all-time tally.
        if hour + BUCKET_HOURS < newest {
            return;
        }
        // A clock that stepped back lands in its own hour, in order.
        let at_or_before = self.0.iter().rposition(|(h, ..)| *h <= hour);
        match at_or_before {
            Some(i) if self.0[i].0 == hour => {
                self.0[i].1 += tokens;
                self.0[i].2 += micro;
            }
            Some(i) => self.0.insert(i + 1, (hour, tokens, micro)),
            None => self.0.push_front((hour, tokens, micro)),
        }
        while self
            .0
            .front()
            .is_some_and(|(h, ..)| h + BUCKET_HOURS < newest)
        {
            self.0.pop_front();
        }
    }

    /// Tokens and USD from the hour holding `now - window_secs` onward.
    pub(crate) fn totals(&self, now: u64, window_secs: u64) -> (u64, f64) {
        let from = now.saturating_sub(window_secs) / 3600;
        let (tokens, micro) = self
            .0
            .iter()
            .filter(|(h, ..)| *h >= from)
            .fold((0, 0), |(t, m), (_, tok, mic)| (t + tok, m + mic));
        (tokens, usd(micro))
    }

    /// Buckets held.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    /// The newest hour with spend, if any.
    pub(crate) fn newest_hour(&self) -> Option<u64> {
        self.0.back().map(|(h, ..)| *h)
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

/// `usd` as whole micro-USD, truncated: the unit every total is kept in.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub(crate) fn micro(usd: f64) -> u64 {
    (usd * 1_000_000.0) as u64
}

#[allow(clippy::cast_precision_loss)]
fn usd(micro: u64) -> f64 {
    micro as f64 / 1_000_000.0
}

#[cfg(test)]
#[path = "tally_tests.rs"]
mod tests;
