// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Per-caller spend for calls that carry no session (MIK-7653).
//!
//! A 2026-07-28 request has no session, so its spend had no per-caller home
//! and its caller's report was always empty. Keyed on the router's caller key,
//! never on a label keyless callers share. Running counters only: an entry is
//! bounded by its distinct `(backend, tool)` pairs, and is dropped by the
//! opportunistic sweep [`CALLER_COST_IDLE`] after its last spend.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use dashmap::DashMap;

use super::{BackendCost, CostRecord, SessionCostSnapshot, ToolCost};

/// How long a caller's breakdown outlives its last spend: the per-key
/// budget's default day window, so a report covers at least a working day.
pub const CALLER_COST_IDLE: Duration = Duration::from_secs(24 * 60 * 60);

/// Minimum seconds between two sweeps.
const SWEEP_EVERY: u64 = 60;

/// One caller's counters: `(backend, tool)` -> `[calls, tokens, micro-USD]`.
struct CallerCost {
    first_spend: u64,
    last_spend: u64,
    by_tool: HashMap<(String, String), [u64; 3]>,
}

impl CallerCost {
    fn new(now: u64) -> Self {
        Self {
            first_spend: now,
            last_spend: now,
            by_tool: HashMap::new(),
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
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let micro = (rec.estimated_cost_usd * 1_000_000.0) as u64;
        {
            let mut entry = self
                .by_caller
                .entry(key.to_string())
                .or_insert_with(|| CallerCost::new(now));
            // A caller returning after the idle window starts over, as if swept.
            if entry.expired(now) {
                *entry = CallerCost::new(now);
            }
            let row = entry
                .by_tool
                .entry((rec.backend.clone(), rec.tool.clone()))
                .or_default();
            for (total, add) in row.iter_mut().zip([1, rec.token_count, micro]) {
                *total += add;
            }
            entry.last_spend = now;
        }
        // The shard guard is dropped above: `retain` takes every shard lock,
        // and a held guard would deadlock it.
        let due = self.next_sweep.load(Ordering::Relaxed);
        if now >= due
            && self
                .next_sweep
                .compare_exchange(due, now + SWEEP_EVERY, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
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
        let mut by_backend: HashMap<&str, BackendCost> = HashMap::new();
        let mut by_tool = Vec::with_capacity(cost.by_tool.len());
        let mut totals = [0u64; 3];
        for ((backend, tool), counters) in &cost.by_tool {
            let [calls, tokens, micro] = *counters;
            #[allow(clippy::cast_precision_loss)]
            let usd = micro as f64 / 1_000_000.0;
            by_tool.push(ToolCost {
                tool_key: format!("{backend}:{tool}"),
                call_count: calls,
                token_count: tokens,
                cost_usd: usd,
            });
            let row = by_backend
                .entry(backend.as_str())
                .or_insert_with(|| BackendCost {
                    backend: backend.clone(),
                    call_count: 0,
                    token_count: 0,
                    cost_usd: 0.0,
                });
            row.call_count += calls;
            row.token_count += tokens;
            row.cost_usd += usd;
            for (total, add) in totals.iter_mut().zip(counters) {
                *total += add;
            }
        }
        #[allow(clippy::cast_precision_loss)]
        let total_cost_usd = totals[2] as f64 / 1_000_000.0;
        Some(SessionCostSnapshot {
            session_id: String::new(),
            api_key_name: None,
            started_at: cost.first_spend,
            call_count: totals[0],
            total_tokens: totals[1],
            total_cost_usd,
            by_backend: by_backend.into_values().collect(),
            by_tool,
        })
    }
}

#[cfg(test)]
#[path = "caller_tests.rs"]
mod tests;
