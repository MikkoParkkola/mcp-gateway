//! Pre-invoke budget enforcement.
//!
//! `BudgetEnforcer::check()` is called BEFORE every tool dispatch.
//! It must complete in <0.1 ms: one `DashMap` lookup + ≤3 atomic comparisons,
//! no allocations on the hot path when the tool is free.
//!
//! # Day-boundary reset
//!
//! `DailyAccumulator` stores (`day_number`, `micro_usd`) as separate atomics.
//! On each `add()` call the current day is compared to the stored day:
//! - If equal: `fetch_add` on the counter.
//! - If different: `compare_exchange` to win the reset race, then `swap(0)`
//!   + `fetch_add`.  Losers of the CAS fall through to `fetch_add` on the
//!     already-reset counter — no spend is lost.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use super::config::{AlertAction, CostGovernanceConfig};
use super::registry::CostRegistry;

// ── DailyAccumulator ─────────────────────────────────────────────────────────

/// Atomic daily spend accumulator with automatic day-boundary reset.
///
/// Uses two independent `AtomicU64` fields:
/// - `day`: days since UNIX epoch (UTC).  Detects day rollovers.
/// - `micro_usd`: accumulated spend in micro-USD (1 USD = `1_000_000`).
#[cfg(feature = "cost-governance")]
pub struct DailyAccumulator {
    day: AtomicU64,
    micro_usd: AtomicU64,
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
            day: AtomicU64::new(current_day()),
            micro_usd: AtomicU64::new(0),
        }
    }

    /// Add `micro` micro-USD of spend.  Auto-resets on day boundary.
    ///
    /// Returns the new running total **after** the add.
    ///
    /// Race-safety: `compare_exchange` ensures only one winner resets the
    /// counter.  The winner uses `swap(0)` then `fetch_add(micro)` so any
    /// concurrent `fetch_add` calls that arrive between the swap and our add
    /// are preserved.  Losers of the CAS simply `fetch_add` on the
    /// already-reset accumulator.
    pub fn add(&self, micro: u64) -> u64 {
        let today = current_day();
        let stored = self.day.load(Ordering::Acquire);
        if stored != today {
            // Attempt to win the reset race
            if self
                .day
                .compare_exchange(stored, today, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                // Won: zero the counter, then add our spend
                self.micro_usd.swap(0, Ordering::AcqRel);
                return self.micro_usd.fetch_add(micro, Ordering::AcqRel) + micro;
            }
            // Lost: another thread already reset — fall through to fetch_add
        }
        self.micro_usd.fetch_add(micro, Ordering::AcqRel) + micro
    }

    /// Current daily spend in micro-USD.
    ///
    /// Returns 0 if the stored day is not today (stale — caller treats as fresh day).
    pub fn current(&self) -> u64 {
        let today = current_day();
        if self.day.load(Ordering::Relaxed) != today {
            return 0;
        }
        self.micro_usd.load(Ordering::Relaxed)
    }
}

fn current_day() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
        / 86_400
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
}

// ── EnforcerSnapshot ─────────────────────────────────────────────────────────

/// Serializable snapshot of current enforcer state (for `/ui/api/costs` and stats).
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
}

// ── BudgetEnforcer ───────────────────────────────────────────────────────────

/// Pre-invoke budget enforcement engine.
///
/// Wrap in `Arc` and share via `MetaMcp`.  All operations are lock-free
/// in the common case (no day rollover, no limit exceeded).
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
        }
    }

    /// Pre-invoke budget check.
    ///
    /// Hot path: single `DashMap` lookup + ≤3 atomic loads.  No allocation
    /// when the tool is free or governance is disabled.
    #[allow(clippy::too_many_lines)]
    pub fn check(&self, tool_name: &str, api_key_name: Option<&str>) -> EnforcementResult {
        if !self.config.enabled {
            return EnforcementResult {
                allowed: true,
                cost_usd: 0.0,
                warnings: Vec::new(),
                block_reason: None,
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
            };
        }

        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::no_effect_underscore_binding
        )]
        let _cost_micro = (cost * 1_000_000.0) as u64;

        let mut warnings: Vec<String> = Vec::new();
        let mut blocked = false;
        let mut block_reason: Option<String> = None;

        // Check 1: per-tool daily limit
        if let Some(&limit) = self.config.budgets.per_tool.get(tool_name) {
            let acc = self.tool_daily.entry(tool_name.to_string()).or_default();
            #[allow(clippy::cast_precision_loss)]
            let current_usd = acc.current() as f64 / 1_000_000.0;
            let projected = current_usd + cost;

            if let Some(action) = self.evaluate_alerts(projected, limit) {
                match action {
                    AlertAction::Log => {
                        tracing::warn!(
                            tool = tool_name,
                            spent = projected,
                            limit = limit,
                            "Tool approaching daily budget limit"
                        );
                    }
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
            let current_usd = self.global_daily.current() as f64 / 1_000_000.0;
            let projected = current_usd + cost;

            if let Some(action) = self.evaluate_alerts(projected, limit) {
                match action {
                    AlertAction::Log => {
                        tracing::warn!(
                            spent = projected,
                            limit = limit,
                            "Global daily spend approaching limit"
                        );
                    }
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
            let current_usd = acc.current() as f64 / 1_000_000.0;
            let projected = current_usd + cost;

            if let Some(action) = self.evaluate_alerts(projected, limit) {
                match action {
                    AlertAction::Log => {
                        tracing::warn!(
                            key = key_name,
                            spent = projected,
                            limit = limit,
                            "API key approaching daily budget limit"
                        );
                    }
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

        EnforcementResult {
            allowed: !blocked,
            cost_usd: cost,
            warnings,
            block_reason,
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

        self.global_daily.add(micro);

        self.tool_daily
            .entry(tool_name.to_string())
            .or_default()
            .add(micro);

        if let Some(key) = api_key_name {
            self.key_daily
                .entry(key.to_string())
                .or_default()
                .add(micro);
        }
    }

    /// Snapshot current accumulator state for persistence and the UI endpoint.
    #[must_use]
    pub fn snapshot(&self) -> EnforcerSnapshot {
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
            key_daily,
            key_limits: self.config.budgets.per_key.clone(),
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
mod tests {
    use super::*;
    use crate::cost_accounting::config::{BudgetLimits, CostGovernanceConfig};
    use crate::cost_accounting::registry::CostRegistry;

    fn enforcer_with(
        enabled: bool,
        daily: Option<f64>,
        per_tool: &[(&str, f64)],
        per_key: &[(&str, f64)],
        tool_costs: &[(&str, f64)],
    ) -> BudgetEnforcer {
        let mut cfg = CostGovernanceConfig {
            enabled,
            budgets: BudgetLimits {
                daily,
                per_tool: per_tool.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
                per_key: per_key.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
            },
            ..CostGovernanceConfig::default()
        };
        for (name, cost) in tool_costs {
            cfg.tool_costs.insert(name.to_string(), *cost);
        }
        let registry = Arc::new(CostRegistry::new(&cfg));
        BudgetEnforcer::new(cfg, registry)
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn enforcer_disabled_allows_all() {
        let e = enforcer_with(false, Some(0.001), &[], &[], &[("paid_tool", 0.01)]);
        let result = e.check("paid_tool", None);
        assert!(result.allowed);
        assert_eq!(result.cost_usd, 0.0);
        assert!(result.warnings.is_empty());
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn enforcer_free_tool_skips_checks() {
        let e = enforcer_with(true, Some(0.001), &[], &[], &[("free_tool", 0.0)]);
        let result = e.check("free_tool", None);
        assert!(result.allowed);
        assert_eq!(result.cost_usd, 0.0);
        assert!(result.block_reason.is_none());
    }

    #[test]
    fn enforcer_per_tool_block_when_exceeded() {
        // limit = $0.005; cost = $0.01 → projected = $0.01 > limit → block
        let e = enforcer_with(
            true,
            None,
            &[("expensive_tool", 0.005)],
            &[],
            &[("expensive_tool", 0.01)],
        );
        // Pre-fill $0.004 (80% of limit)
        e.record_spend("expensive_tool", None, 0.004);
        // Next call costs $0.01 → $0.014 total → exceeds $0.005
        let result = e.check("expensive_tool", None);
        assert!(!result.allowed);
        assert!(result.block_reason.is_some());
    }

    #[test]
    fn enforcer_global_block_when_exceeded() {
        let e = enforcer_with(true, Some(0.01), &[], &[], &[("tool", 0.006)]);
        // Spend $0.006, then try another $0.006 → $0.012 > $0.01
        e.record_spend("tool", None, 0.006);
        let result = e.check("tool", None);
        assert!(!result.allowed);
        assert!(result.block_reason.as_deref().unwrap().contains("Global"));
    }

    #[test]
    fn enforcer_per_key_block_when_exceeded() {
        let e = enforcer_with(true, None, &[], &[("dev_key", 0.01)], &[("tool", 0.008)]);
        e.record_spend("tool", Some("dev_key"), 0.008);
        let result = e.check("tool", Some("dev_key"));
        assert!(!result.allowed);
        assert!(result.block_reason.as_deref().unwrap().contains("dev_key"));
    }

    #[test]
    fn enforcer_notify_warning_at_80_percent() {
        // limit = $0.01, cost = $0.009 → 90% → Notify
        let e = enforcer_with(true, Some(0.01), &[], &[], &[("tool", 0.009)]);
        let result = e.check("tool", None);
        assert!(result.allowed, "Should be allowed at 90% (not 100%)");
        assert!(!result.warnings.is_empty(), "Should have a warning at 90%");
    }

    #[test]
    fn enforcer_log_at_50_percent_no_response_warning() {
        // limit = $0.10, cost = $0.06 → 60% → Log only, no Notify
        let e = enforcer_with(true, Some(0.10), &[], &[], &[("tool", 0.06)]);
        let result = e.check("tool", None);
        assert!(result.allowed);
        // At 60%: Log fires but NOT Notify, so warnings vec stays empty
        assert!(
            result.warnings.is_empty(),
            "Log-only tier must NOT inject response warnings"
        );
    }

    #[test]
    fn enforcer_record_spend_accumulates() {
        let e = enforcer_with(true, Some(1.0), &[], &[], &[("tool", 0.01)]);
        e.record_spend("tool", Some("k1"), 0.30);
        e.record_spend("tool", Some("k1"), 0.20);
        let snap = e.snapshot();
        assert!((snap.global_daily_usd - 0.50).abs() < 1e-6);
        assert!((snap.tool_daily["tool"] - 0.50).abs() < 1e-6);
        assert!((snap.key_daily["k1"] - 0.50).abs() < 1e-6);
    }

    #[test]
    fn enforcer_check_performance_under_100us() {
        // 10,000 checks must complete in under 1 second total (<0.1ms each)
        let e = enforcer_with(true, Some(100.0), &[], &[], &[("tool", 0.001)]);
        let start = std::time::Instant::now();
        for _ in 0..10_000 {
            let _ = e.check("tool", Some("key"));
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_secs() < 1,
            "10,000 checks took {elapsed:?} (must be < 1s)"
        );
    }

    #[test]
    fn daily_accumulator_add_increases_current() {
        let acc = DailyAccumulator::new();
        acc.add(500_000); // $0.50
        acc.add(300_000); // $0.30
        assert_eq!(acc.current(), 800_000);
    }

    #[test]
    fn evaluate_alerts_selects_highest_matching_threshold() {
        // spend=0.09, limit=0.10 → 90% → highest rule that fires is Notify(80)
        let e = enforcer_with(true, Some(0.10), &[], &[], &[]);
        let action = e.evaluate_alerts(0.09, 0.10);
        assert_eq!(action, Some(AlertAction::Notify));
    }

    #[test]
    fn evaluate_alerts_returns_block_at_100_percent() {
        let e = enforcer_with(true, Some(0.10), &[], &[], &[]);
        let action = e.evaluate_alerts(0.10, 0.10);
        assert_eq!(action, Some(AlertAction::Block));
    }

    #[test]
    fn evaluate_alerts_returns_none_below_50_percent() {
        let e = enforcer_with(true, Some(1.0), &[], &[], &[]);
        let action = e.evaluate_alerts(0.40, 1.0);
        assert_eq!(action, None);
    }
}
