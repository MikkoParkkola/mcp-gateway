// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Pre-invoke budget enforcement.
//!
//! `BudgetEnforcer::check()` is called BEFORE every tool dispatch.
//! It must complete in <0.1 ms: one `DashMap` lookup + ≤3 short uncontended
//! locks, no allocations on the hot path when the tool is free. A paid tool also
//! takes the reservation lock and allocates its hold (MIK-7763).
//!
//! # Day-boundary reset
//!
//! `DailyAccumulator` keeps (`day_number`, `micro_usd`) under one lock. Each
//! `add()` compares the current day to the stored day and, on a rollover,
//! publishes the new day and clears the total in the same critical section,
//! so no add can land between the two and be erased (MIK-7880).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use super::config::{AlertAction, CostGovernanceConfig};
use super::registry::CostRegistry;

#[cfg(feature = "cost-governance")]
#[path = "enforcer_crossings.rs"]
pub(crate) mod crossings;

// ── DailyAccumulator ─────────────────────────────────────────────────────────

/// Daily spend accumulator with automatic day-boundary reset.
///
/// One lock holds both halves, so a reset and an add never interleave:
/// - `.0`: days since UNIX epoch (UTC).  Detects day rollovers.
/// - `.1`: accumulated spend in micro-USD (1 USD = `1_000_000`).
#[cfg(feature = "cost-governance")]
pub struct DailyAccumulator {
    state: Mutex<(u64, u64)>,
}

#[cfg(feature = "cost-governance")]
impl Default for DailyAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "cost-governance")]
impl DailyAccumulator {
    /// Create a new accumulator initialised to today / zero spend.
    pub fn new() -> Self {
        Self {
            state: Mutex::new((current_day(), 0)),
        }
    }

    fn lock(&self) -> MutexGuard<'_, (u64, u64)> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Add `micro` micro-USD of spend.  Auto-resets on day boundary.
    ///
    /// Returns the new running total **after** the add.
    ///
    /// Race-safety: the rollover check, the clear and the add share one
    /// critical section, so an add on the new day cannot be erased by the
    /// reset (MIK-7880). A rollover only moves forward: an add that read the
    /// clock before midnight but locked after a later add rolled over counts
    /// on the newer day instead of resetting it backward.
    pub fn add(&self, micro: u64) -> u64 {
        let today = current_day();
        let mut state = self.lock();
        if today > state.0 {
            state.0 = today;
            #[cfg(test)]
            fire_after_day_publish();
            state.1 = 0;
        }
        state.1 = state.1.saturating_add(micro);
        state.1
    }

    /// Current daily spend in micro-USD.
    ///
    /// Returns 0 if the stored day is before today (stale — caller treats as
    /// fresh day). A stored day ahead of this read's clock is still counted.
    pub fn current(&self) -> u64 {
        let state = self.lock();
        if state.0 >= current_day() { state.1 } else { 0 }
    }

    /// False once the stored day is before today: [`Self::current`] reads 0.
    fn is_current(&self) -> bool {
        self.lock().0 >= current_day()
    }
}

#[cfg(test)]
thread_local! {
    /// Runs once on this thread after a rollover publishes the new day and
    /// before the counter is cleared: a test lands an add there (MIK-7880).
    static AFTER_DAY_PUBLISH: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn fire_after_day_publish() {
    let taken = AFTER_DAY_PUBLISH.with(|hook| hook.borrow_mut().take());
    if let Some(f) = taken {
        f();
    }
}

#[cfg(all(test, feature = "cost-governance"))]
impl DailyAccumulator {
    /// An accumulator still on `day` holding `micro` of that day's spend.
    fn stale(day: u64, micro: u64) -> Self {
        Self {
            state: Mutex::new((day, micro)),
        }
    }
}

/// Micro-USD as USD.
#[cfg(feature = "cost-governance")]
#[allow(clippy::cast_precision_loss)]
fn usd(micro: u64) -> f64 {
    micro as f64 / 1_000_000.0
}

fn current_day() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
        / 86_400
}

/// Unbudgeted names one day map keeps entries for; later names add into
/// `(other)`. A check reads only budgeted names, so with R2 off and a non-zero
/// `default_cost` the caller would otherwise choose how many entries exist.
#[cfg(feature = "cost-governance")]
const MAX_UNBUDGETED_ROWS: usize = 256;

/// Add `micro` to `name`'s entry and return that entry's running total. A
/// budgeted name always has its own. Any other name has one only while `map`
/// holds fewer than [`MAX_UNBUDGETED_ROWS`] unbudgeted entries, and only if it is no longer than the cost tracker's row-name limit; past
/// either, its spend goes to `overflow`, which no budget check ever reads, so
/// a budget whose name happens to be `(other)` keeps its own total.
/// ponytail: a soft cap; racing first inserts can pass it by the caller count.
#[cfg(feature = "cost-governance")]
fn add_capped(
    (map, overflow): (&DashMap<String, DailyAccumulator>, &DailyAccumulator),
    name: &str,
    limits: &HashMap<String, f64>,
    micro: u64,
) -> u64 {
    // Budgeted entries never count against the cap, present or not, so the map
    // holds at most every budgeted name plus MAX_UNBUDGETED_ROWS others.
    let unbudgeted = || {
        let budgeted = limits.keys().filter(|k| map.contains_key(*k)).count();
        // A sweep may remove entries between the two reads.
        map.len().saturating_sub(budgeted)
    };
    let own = limits.contains_key(name)
        || map.contains_key(name)
        || (name.len() <= super::tally::MAX_ROW_NAME_BYTES && unbudgeted() < MAX_UNBUDGETED_ROWS);
    if own {
        map.entry(name.to_string()).or_default().add(micro)
    } else {
        overflow.add(micro)
    }
}

// ── EnforcementResult ────────────────────────────────────────────────────────

/// Result of a pre-invoke budget check.
#[cfg(feature = "cost-governance")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementResult {
    /// Whether the tool call should proceed.
    pub allowed: bool,
    /// Per-invocation cost in USD (0.0 if free or governance disabled).
    pub cost_usd: f64,
    /// Warning messages to inject into the response (non-empty at ≥80% threshold).
    pub warnings: Vec<String>,
    /// Block reason, set only when `allowed == false`.
    pub block_reason: Option<String>,
    /// The allowance this call reserved while it is in flight (MIK-7763).
    /// Shared by clones, released when the last one drops; never serialized.
    #[serde(skip)]
    pub(crate) hold: Option<Arc<SpendHold>>,
}

// ── Reservations ─────────────────────────────────────────────────────────────

/// Spend that admitted, unsettled calls have reserved, in micro-USD.
///
/// It counts toward every later check, so concurrent calls cannot all pass
/// against the same remaining allowance. It is not day-scoped and the
/// day-boundary reset never touches it.
#[cfg(feature = "cost-governance")]
#[derive(Default)]
struct Pending {
    global: u64,
    tools: HashMap<String, u64>,
    keys: HashMap<String, u64>,
}

#[cfg(feature = "cost-governance")]
impl Pending {
    fn add(&mut self, tool: &str, key: Option<&str>, micro: u64) {
        self.global = self.global.saturating_add(micro);
        let slot = self.tools.entry(tool.to_string()).or_default();
        *slot = slot.saturating_add(micro);
        if let Some(key) = key {
            let slot = self.keys.entry(key.to_string()).or_default();
            *slot = slot.saturating_add(micro);
        }
    }

    fn release(&mut self, tool: &str, key: Option<&str>, micro: u64) {
        self.global = self.global.saturating_sub(micro);
        Self::take(&mut self.tools, tool, micro);
        if let Some(key) = key {
            Self::take(&mut self.keys, key, micro);
        }
    }

    fn take(map: &mut HashMap<String, u64>, name: &str, micro: u64) {
        if let Some(slot) = map.get_mut(name) {
            *slot = slot.saturating_sub(micro);
            if *slot == 0 {
                map.remove(name);
            }
        }
    }

    fn tool(&self, name: &str) -> u64 {
        self.tools.get(name).copied().unwrap_or(0)
    }

    fn key(&self, name: &str) -> u64 {
        self.keys.get(name).copied().unwrap_or(0)
    }
}

/// The reservation ledger. One lock makes a check and its reservation a single
/// step, and a release wait for any check in progress.
#[cfg(feature = "cost-governance")]
type Ledger = Mutex<Pending>;

#[cfg(feature = "cost-governance")]
fn locked(ledger: &Ledger) -> MutexGuard<'_, Pending> {
    // The ledger holds plain counters: a poisoned lock still holds a usable value.
    ledger.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One admitted call's reservation. Dropping it gives the allowance back, so a
/// call that fails without spend, is refused later or is cancelled keeps
/// nothing. The caller records the spend first and drops the hold after:
/// a check then never sees the spend missing from both places.
#[cfg(feature = "cost-governance")]
#[must_use = "dropping a hold gives the reservation back"]
pub(crate) struct SpendHold {
    ledger: Arc<Ledger>,
    tool: String,
    key: Option<String>,
    micro: u64,
}

#[cfg(feature = "cost-governance")]
impl Drop for SpendHold {
    fn drop(&mut self) {
        locked(&self.ledger).release(&self.tool, self.key.as_deref(), self.micro);
    }
}

#[cfg(feature = "cost-governance")]
impl std::fmt::Debug for SpendHold {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpendHold")
            .field("micro", &self.micro)
            .finish_non_exhaustive()
    }
}

/// A `Log` alert recorded under the lock and emitted after it is released.
#[cfg(feature = "cost-governance")]
enum DeferredLog {
    Tool {
        tool: String,
        spent: f64,
        limit: f64,
    },
    Global {
        spent: f64,
        limit: f64,
    },
    Key {
        key: String,
        spent: f64,
        limit: f64,
    },
}

#[cfg(feature = "cost-governance")]
impl DeferredLog {
    fn emit(self) {
        match self {
            Self::Tool { tool, spent, limit } => tracing::warn!(
                tool = tool.as_str(),
                spent,
                limit,
                "Tool approaching daily budget limit"
            ),
            Self::Global { spent, limit } => {
                tracing::warn!(spent, limit, "Global daily spend approaching limit");
            }
            Self::Key { key, spent, limit } => tracing::warn!(
                key = key.as_str(),
                spent,
                limit,
                "API key approaching daily budget limit"
            ),
        }
    }
}

// ── EnforcerSnapshot ─────────────────────────────────────────────────────────

/// Serializable snapshot of current enforcer state (for persistence and stats).
#[cfg(feature = "cost-governance")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcerSnapshot {
    /// Today's global spend in USD.
    pub global_daily_usd: f64,
    /// Configured global daily limit (None = unlimited).
    pub global_daily_limit: Option<f64>,
    /// Per-tool today's spend (`tool_name` -> USD).
    pub tool_daily: HashMap<String, f64>,
    /// Configured per-tool daily limits.
    pub tool_limits: HashMap<String, f64>,
    /// Per-key today's spend (`key_name` -> USD).
    pub key_daily: HashMap<String, f64>,
    /// Configured per-key daily limits.
    pub key_limits: HashMap<String, f64>,
    /// Unix seconds read before the accumulators. A snapshot that straddles
    /// UTC midnight then dates its spend to the earlier day, never the later.
    pub taken_at: u64,
    /// Today's spend of unbudgeted tools past the per-tool map's cap (USD).
    #[serde(default)]
    pub tool_overflow_usd: f64,
    /// Today's spend of unbudgeted keys past the per-key map's cap (USD).
    #[serde(default)]
    pub key_overflow_usd: f64,
}

// ── BudgetEnforcer ───────────────────────────────────────────────────────────

/// Pre-invoke budget enforcement engine.
///
/// Wrap in `Arc` and share via `MetaMcp`.  Free tools and a disabled
/// governance take no lock; a check of a paid tool takes one short mutex
/// (the reservation ledger) and allocates its hold. Spend recording, snapshots
/// and each daily read take one short accumulator lock (MIK-7880).
#[cfg(feature = "cost-governance")]
pub struct BudgetEnforcer {
    pub(crate) config: CostGovernanceConfig,
    pub(crate) registry: Arc<CostRegistry>,
    /// Per-tool daily accumulators.
    tool_daily: DashMap<String, DailyAccumulator>,
    /// Global daily accumulator.
    global_daily: DailyAccumulator,
    /// Per-API-key daily accumulators.
    key_daily: DashMap<String, DailyAccumulator>,
    /// Spend reserved by in-flight admitted calls (MIK-7763).
    ledger: Arc<Ledger>,
    /// Told when committed spend crosses 50, 80 or 100 % of a daily budget.
    observer: crate::observer::Observer<crossings::BudgetCrossing>,
    /// When the next sweep of earlier days' entries may run (MIK-8015).
    next_sweep: std::sync::atomic::AtomicU64,
    /// The latest UTC day a sweep ran on: a new day sweeps at once, whatever
    /// the minute throttle says, so yesterday's rows never fill today's cap.
    swept_day: std::sync::atomic::AtomicU64,
    /// Spend of unbudgeted tool and key names past the day maps' cap.
    tool_overflow: DailyAccumulator,
    key_overflow: DailyAccumulator,
}

#[cfg(feature = "cost-governance")]
impl BudgetEnforcer {
    /// Create a new `BudgetEnforcer` from config and a shared cost registry.
    pub fn new(config: CostGovernanceConfig, registry: Arc<CostRegistry>) -> Self {
        Self {
            config,
            registry,
            tool_daily: DashMap::new(),
            global_daily: DailyAccumulator::new(),
            key_daily: DashMap::new(),
            ledger: Arc::default(),
            observer: crate::observer::Observer::default(),
            next_sweep: std::sync::atomic::AtomicU64::new(0),
            swept_day: std::sync::atomic::AtomicU64::new(0),
            tool_overflow: DailyAccumulator::new(),
            key_overflow: DailyAccumulator::new(),
        }
    }

    /// Pre-invoke budget check, and reservation of the allowance it admits.
    ///
    /// An allowed result carries a hold on the call's cost; later checks count
    /// it until the hold drops, so concurrent calls cannot all pass against the
    /// same remaining allowance. Keep the result (or the hold) until the spend
    /// is recorded. Refusals, warnings and reasons are those of a check with
    /// nothing in flight.
    ///
    /// Hot path: single `DashMap` lookup + ≤3 short accumulator locks.  No allocation
    /// when the tool is free or governance is disabled.
    #[allow(clippy::too_many_lines)]
    pub fn check(&self, tool_name: &str, api_key_name: Option<&str>) -> EnforcementResult {
        if !self.config.enabled {
            return EnforcementResult {
                allowed: true,
                cost_usd: 0.0,
                warnings: Vec::new(),
                block_reason: None,
                hold: None,
            };
        }

        let cost = self.registry.cost_for(tool_name);
        if cost == 0.0 {
            // Free tools skip all budget checks
            return EnforcementResult {
                allowed: true,
                cost_usd: 0.0,
                warnings: Vec::new(),
                block_reason: None,
                hold: None,
            };
        }

        // The same conversion `record_spend` applies to this cost.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let cost_micro = (cost * 1_000_000.0) as u64;

        // One step from here to the reservation below. Nothing in it waits or
        // writes a log: alerts are recorded and emitted after the lock is gone.
        let mut pending = locked(&self.ledger);
        let mut logs: Vec<DeferredLog> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();
        let mut blocked = false;
        let mut block_reason: Option<String> = None;

        // Check 1: per-tool daily limit
        if let Some(&limit) = self.config.budgets.per_tool.get(tool_name) {
            let acc = self.tool_daily.entry(tool_name.to_string()).or_default();
            #[allow(clippy::cast_precision_loss)]
            let current_usd = (acc.current() + pending.tool(tool_name)) as f64 / 1_000_000.0;
            let projected = current_usd + cost;

            if let Some(action) = self.evaluate_alerts(projected, limit) {
                match action {
                    AlertAction::Log => logs.push(DeferredLog::Tool {
                        tool: tool_name.to_string(),
                        spent: projected,
                        limit,
                    }),
                    AlertAction::Notify => {
                        warnings.push(format!(
                            "Tool '{tool_name}' daily spend ${projected:.4} approaching limit ${limit:.2}"
                        ));
                    }
                    AlertAction::Block => {
                        blocked = true;
                        block_reason = Some(format!(
                            "Tool '{tool_name}' daily budget exceeded: ${projected:.4} >= ${limit:.2}"
                        ));
                    }
                }
            }
        }

        // Check 2: global daily limit
        if !blocked && let Some(limit) = self.config.budgets.daily {
            #[allow(clippy::cast_precision_loss)]
            let current_usd = (self.global_daily.current() + pending.global) as f64 / 1_000_000.0;
            let projected = current_usd + cost;

            if let Some(action) = self.evaluate_alerts(projected, limit) {
                match action {
                    AlertAction::Log => logs.push(DeferredLog::Global {
                        spent: projected,
                        limit,
                    }),
                    AlertAction::Notify => {
                        warnings.push(format!(
                            "Global daily spend ${projected:.4} approaching limit ${limit:.2}"
                        ));
                    }
                    AlertAction::Block => {
                        blocked = true;
                        block_reason = Some(format!(
                            "Global daily budget exceeded: ${projected:.4} >= ${limit:.2}"
                        ));
                    }
                }
            }
        }

        // Check 3: per-key daily limit
        if !blocked
            && let Some(key_name) = api_key_name
            && let Some(&limit) = self.config.budgets.per_key.get(key_name)
        {
            let acc = self.key_daily.entry(key_name.to_string()).or_default();
            #[allow(clippy::cast_precision_loss)]
            let current_usd = (acc.current() + pending.key(key_name)) as f64 / 1_000_000.0;
            let projected = current_usd + cost;

            if let Some(action) = self.evaluate_alerts(projected, limit) {
                match action {
                    AlertAction::Log => logs.push(DeferredLog::Key {
                        key: key_name.to_string(),
                        spent: projected,
                        limit,
                    }),
                    AlertAction::Notify => {
                        warnings.push(format!(
                                    "API key '{key_name}' daily spend ${projected:.4} approaching limit ${limit:.2}"
                                ));
                    }
                    AlertAction::Block => {
                        blocked = true;
                        block_reason = Some(format!(
                            "API key '{key_name}' daily budget exceeded: ${projected:.4} >= ${limit:.2}"
                        ));
                    }
                }
            }
        }

        let hold = (!blocked).then(|| {
            pending.add(tool_name, api_key_name, cost_micro);
            Arc::new(SpendHold {
                ledger: Arc::clone(&self.ledger),
                tool: tool_name.to_string(),
                key: api_key_name.map(str::to_string),
                micro: cost_micro,
            })
        });
        drop(pending);
        for log in logs {
            log.emit();
        }

        EnforcementResult {
            allowed: !blocked,
            cost_usd: cost,
            warnings,
            block_reason,
            hold,
        }
    }

    /// Record actual spend after a successful invocation.
    ///
    /// Must be called AFTER the tool dispatch completes (post-invoke).
    pub fn record_spend(&self, tool_name: &str, api_key_name: Option<&str>, cost_usd: f64) {
        if cost_usd == 0.0 {
            return;
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let micro = (cost_usd * 1_000_000.0) as u64;

        let budgets = &self.config.budgets;
        // Before the adds, so the first spend of a day never finds yesterday's
        // rows filling the cap. No entry guard is held: `retain` takes every
        // shard lock.
        let today = current_day();
        let new_day = self
            .swept_day
            .fetch_max(today, std::sync::atomic::Ordering::Relaxed)
            < today;
        if new_day || super::tally::sweep_due(&self.next_sweep, super::persistence::now_secs()) {
            for (map, limits) in [
                (&self.tool_daily, &budgets.per_tool),
                (&self.key_daily, &budgets.per_key),
            ] {
                map.retain(|name, day| limits.contains_key(name) || day.is_current());
            }
        }
        let global = self.global_daily.add(micro);
        let tool = add_capped(self.tool_maps(), tool_name, &budgets.per_tool, micro);
        let key = api_key_name.map(|key| add_capped(self.key_maps(), key, &budgets.per_key, micro));
        if self.observer.is_set() {
            self.report_crossings(
                tool_name,
                api_key_name,
                micro,
                [global, tool, key.unwrap_or(0)],
            );
        }
    }

    /// Re-apply today's spend from a persisted snapshot, so a restart keeps
    /// counting against the budgets instead of starting them at zero.
    ///
    /// A snapshot saved on an earlier UTC day is ignored: the daily budgets it
    /// counted have already reset. The global total is the sum of the per-tool
    /// totals, because every recorded spend lands in both.
    pub fn restore(&self, persisted: &super::persistence::PersistedCosts) {
        if persisted.saved_at / 86_400 != current_day() {
            tracing::info!(
                saved_at = persisted.saved_at,
                "Persisted cost data is from an earlier UTC day; budgets start at zero"
            );
            return;
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let micro = |usd: f64| (usd.max(0.0) * 1_000_000.0).round() as u64;
        // Through the cap: a snapshot saved before the cap existed may hold
        // more names than it allows.
        let budgets = &self.config.budgets;
        // A zero row (a name saved after midnight before it spent again) is
        // not restored: it would take a place in the cap and read 0 anyway.
        for (tool, total) in &persisted.tool_totals {
            let spent = micro(total.total_cost_usd);
            if spent > 0 {
                self.global_daily.add(spent);
                add_capped(self.tool_maps(), tool, &budgets.per_tool, spent);
            }
        }
        for (key, &usd) in &persisted.key_totals {
            if micro(usd) > 0 {
                add_capped(self.key_maps(), key, &budgets.per_key, micro(usd));
            }
        }
        let tool_overflow = micro(persisted.tool_overflow_usd);
        self.global_daily.add(tool_overflow);
        self.tool_overflow.add(tool_overflow);
        self.key_overflow.add(micro(persisted.key_overflow_usd));
    }

    /// The per-tool day map and its overflow accumulator.
    fn tool_maps(&self) -> (&DashMap<String, DailyAccumulator>, &DailyAccumulator) {
        (&self.tool_daily, &self.tool_overflow)
    }

    /// The per-key day map and its overflow accumulator.
    fn key_maps(&self) -> (&DashMap<String, DailyAccumulator>, &DailyAccumulator) {
        (&self.key_daily, &self.key_overflow)
    }

    /// Snapshot current accumulator state for persistence and the UI endpoint.
    #[must_use]
    pub fn snapshot(&self) -> EnforcerSnapshot {
        let taken_at = super::persistence::now_secs();
        #[allow(clippy::cast_precision_loss)]
        let global_daily_usd = self.global_daily.current() as f64 / 1_000_000.0;

        let tool_daily: HashMap<String, f64> = self
            .tool_daily
            .iter()
            .map(|e| {
                #[allow(clippy::cast_precision_loss)]
                (e.key().clone(), e.value().current() as f64 / 1_000_000.0)
            })
            .collect();

        let key_daily: HashMap<String, f64> = self
            .key_daily
            .iter()
            .map(|e| {
                #[allow(clippy::cast_precision_loss)]
                (e.key().clone(), e.value().current() as f64 / 1_000_000.0)
            })
            .collect();

        EnforcerSnapshot {
            global_daily_usd,
            global_daily_limit: self.config.budgets.daily,
            tool_daily,
            tool_limits: self.config.budgets.per_tool.clone(),
            taken_at,
            key_daily,
            key_limits: self.config.budgets.per_key.clone(),
            tool_overflow_usd: usd(self.tool_overflow.current()),
            key_overflow_usd: usd(self.key_overflow.current()),
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Find the highest-threshold alert rule whose `at_percent` threshold
    /// is satisfied by `spend / limit * 100`.
    ///
    /// Uses `f64` comparison to avoid integer truncation errors near thresholds
    /// (e.g. 99.7 % must not be cast to 99 and miss the 100 % block rule).
    fn evaluate_alerts(&self, spend: f64, limit: f64) -> Option<AlertAction> {
        if limit <= 0.0 {
            return None;
        }
        let percent = spend / limit * 100.0;
        let mut best: Option<AlertAction> = None;
        let mut best_threshold = 0.0_f64;

        for rule in &self.config.alerts {
            let threshold = f64::from(rule.at_percent);
            if percent >= threshold && threshold >= best_threshold {
                best = Some(rule.action);
                best_threshold = threshold;
            }
        }

        best
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "enforcer_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "enforcer_atomic_tests.rs"]
mod atomic_tests;
