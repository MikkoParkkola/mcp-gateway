// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Per-caller spend for calls that carry no session (MIK-7653).
//!
//! A 2026-07-28 request has no session, so its spend had no per-caller home
//! and its caller's report was always empty. Keyed on the router's caller key,
//! never on a label keyless callers share. Running counters only: an entry holds
//! at most `tally::MAX_TOOL_ROWS` rows plus `(other)`, and is dropped by the
//! opportunistic sweep [`CALLER_COST_IDLE`] after its last spend.

use std::sync::atomic::AtomicU64;
use std::time::Duration;

use dashmap::DashMap;

use super::tally::{self, ToolTally};
use super::{CostRecord, SessionCostSnapshot};

/// How long a caller's breakdown outlives its last spend: the per-key
/// budget's default day window, so a report covers at least a working day.
pub const CALLER_COST_IDLE: Duration = Duration::from_secs(24 * 60 * 60);

/// One caller's counters: `(backend, tool)` -> `[calls, tokens, micro-USD]`.
struct CallerCost {
    first_spend: u64,
    last_spend: u64,
    by_tool: ToolTally,
}

impl CallerCost {
    fn new(now: u64) -> Self {
        Self {
            first_spend: now,
            last_spend: now,
            by_tool: ToolTally::default(),
        }
    }

    fn expired(&self, now: u64) -> bool {
        self.last_spend + CALLER_COST_IDLE.as_secs() <= now
    }
}

/// Every session-less caller's spend.
#[derive(Default)]
pub(crate) struct CallerCosts {
    by_caller: DashMap<String, CallerCost>,
    next_sweep: AtomicU64,
}

impl CallerCosts {
    /// Add `rec` to `key`'s counters. An empty key is no identity: not kept.
    pub(crate) fn record(&self, key: &str, rec: &CostRecord, now: u64) {
        if key.is_empty() {
            return;
        }
        let micro = tally::micro(rec.estimated_cost_usd);
        {
            let mut entry = self
                .by_caller
                .entry(key.to_string())
                .or_insert_with(|| CallerCost::new(now));
            // A caller returning after the idle window starts over, as if swept.
            if entry.expired(now) {
                *entry = CallerCost::new(now);
            }
            entry
                .by_tool
                .add(&rec.backend, &rec.tool, rec.token_count, micro);
            entry.last_spend = now;
        }
        // The shard guard is dropped above: `retain` takes every shard lock,
        // and a held guard would deadlock it.
        if tally::sweep_due(&self.next_sweep, now) {
            self.by_caller.retain(|_, cost| !cost.expired(now));
        }
    }

    /// `key`'s breakdown, or `None` for an empty key, no spend, or an entry
    /// past its idle window (reading never extends it). The snapshot's
    /// session id is empty: the caller key embeds the principal.
    pub(crate) fn snapshot(&self, key: &str, now: u64) -> Option<SessionCostSnapshot> {
        if key.is_empty() {
            return None;
        }
        let cost = self.by_caller.get(key)?;
        if cost.expired(now) {
            return None;
        }
        let (by_backend, by_tool, totals) = cost.by_tool.breakdown();
        #[allow(clippy::cast_precision_loss)]
        let total_cost_usd = totals[2] as f64 / 1_000_000.0;
        Some(SessionCostSnapshot {
            session_id: String::new(),
            api_key_name: None,
            started_at: cost.first_spend,
            call_count: totals[0],
            total_tokens: totals[1],
            total_cost_usd,
            by_backend,
            by_tool,
        })
    }
}

#[cfg(test)]
#[path = "caller_tests.rs"]
mod tests;
