// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Saving and restoring the enforcer's spend: the snapshots a save writes,
//! the restore at start-up, and the alert levels a snapshot reports.

use std::collections::HashMap;

use dashmap::DashMap;

use super::super::config::{AlertRule, CostGovernanceConfig};
use super::super::persistence::EnforcerSaveSnapshot;
use super::{
    AlertAction, BudgetEnforcer, DailyAccumulator, EnforcerSnapshot, add_capped, rows, usd,
};

impl BudgetEnforcer {
    /// Re-apply today's spend from a persisted snapshot, so a restart keeps
    /// counting against the budgets instead of starting them at zero.
    ///
    /// A snapshot saved on an earlier day is ignored: the daily budgets it
    /// counted have already reset. A snapshot with `day_basis: "local"` was
    /// saved under local days and restores on the same local day. One without
    /// it was saved under UTC days (before ADR-026): it restores on the same
    /// UTC day, and that day stays open until UTC midnight, so its budgets
    /// reset once there and count local days after. The global total is the
    /// sum of the per-tool totals, because every recorded spend lands in both.
    pub fn restore(&self, persisted: &super::super::persistence::PersistedCosts) {
        let Some(day) = self.restore_day(persisted) else {
            return;
        };
        // Accumulators built before this restore hold the local day; filed
        // under the older legacy day, their spend would count on the local
        // day and miss the UTC reset. None holds spend yet at start-up.
        for acc in [&self.global_daily, &self.tool_overflow, &self.key_overflow] {
            acc.redate_if_empty(day);
        }
        for map in [&self.tool_daily, &self.key_daily] {
            for acc in map {
                acc.redate_if_empty(day);
            }
        }
        let day = Some(day);
        // The overflow first, so a row restored after it records it as the
        // overflow at its creation; then the estimates, so an estimated name
        // owns its row before the rows go through the cap (ADR-023).
        let tool_overflow = saved_micro("overflow", "tool", persisted.tool_overflow_usd);
        self.global_daily.add_on(day, tool_overflow);
        self.tool_overflow.add_on(day, tool_overflow);
        let key_overflow = saved_micro("overflow", "key", persisted.key_overflow_usd);
        self.key_overflow.add_on(day, key_overflow);
        for (attribution, saved, kind) in [
            (
                &self.tool_attribution,
                &persisted.tool_estimate,
                "tool estimate",
            ),
            (
                &self.key_attribution,
                &persisted.key_estimate,
                "key estimate",
            ),
        ] {
            for (name, &usd_value) in saved {
                if let Some(micro) = saved_figure(kind, name, usd_value) {
                    attribution.set(name, micro, day);
                    attribution.own(name);
                }
            }
        }
        // Every name the saving process owned is owned again before the rows
        // go through the cap, so its row survives a full cap: ownership is
        // never released within a process, and a restart carries it on.
        for (attribution, saved) in [
            (&self.tool_attribution, &persisted.tool_owned),
            (&self.key_attribution, &persisted.key_owned),
        ] {
            for name in saved.iter().flatten() {
                attribution.own(name);
            }
        }
        // Through the cap: a snapshot saved before the cap existed may hold
        // more names than it allows. Filed under the snapshot's own day, so
        // spend restored on a clock before 1970 still counts once the clock
        // reads that day.
        let budgets = &self.config.budgets;
        // A zero row (a name saved after midnight before it spent again) is
        // not restored: it would take a place in the cap and read 0 anyway.
        for (tool, total) in &persisted.tool_totals {
            let spent = saved_micro("tool", tool, total.total_cost_usd);
            if spent > 0 {
                self.global_daily.add_on(day, spent);
                add_capped(self.tool_maps(), tool, &budgets.per_tool, spent, day);
            }
        }
        for (key, &usd) in &persisted.key_totals {
            let spent = saved_micro("key", key, usd);
            if spent > 0 {
                add_capped(self.key_maps(), key, &budgets.per_key, spent, day);
            }
        }
        self.restore_attribution(persisted, day, (tool_overflow, key_overflow));
    }

    /// After the rows: the saved creation figures, then the seed of each name
    /// the startup config budgets that the saving process did not own, taken
    /// as a reload would take it (RESTORE.7). The overflow figures are the
    /// saved ones, read before the rows could spill into the overflow.
    fn restore_attribution(
        &self,
        persisted: &super::super::persistence::PersistedCosts,
        day: Option<u64>,
        (tool_overflow, key_overflow): (u64, u64),
    ) {
        let scopes = [
            (
                &self.tool_attribution,
                &self.tool_daily,
                &persisted.tool_born,
                &persisted.tool_owned,
                &self.config.budgets.per_tool,
                tool_overflow,
                "tool born",
            ),
            (
                &self.key_attribution,
                &self.key_daily,
                &persisted.key_born,
                &persisted.key_owned,
                &self.config.budgets.per_key,
                key_overflow,
                "key born",
            ),
        ];
        for (attribution, rows, born, owned, budgets, overflow, kind) in scopes {
            // Each saved creation figure, validated; one that fails takes the
            // saved overflow, the upper bound, so corruption never charges
            // less. An absent map (a file saved before it existed) keeps the
            // figures the restore recorded, and charges the overflow below.
            let saved_born: Option<HashMap<String, u64>> = born.as_ref().map(|map| {
                map.iter()
                    .map(|(name, &usd)| {
                        let micro = saved_figure(kind, name, usd).unwrap_or(overflow);
                        (name.clone(), micro)
                    })
                    .collect()
            });
            if let Some(saved_born) = &saved_born {
                let figures: Vec<(String, u64)> =
                    saved_born.iter().map(|(n, &m)| (n.clone(), m)).collect();
                attribution.restore_born(&figures, day);
            }
            // A file saved before the owned names existed seeds nothing.
            let Some(owned) = owned else { continue };
            let owned: std::collections::HashSet<&str> = owned.iter().map(String::as_str).collect();
            for name in budgets.keys() {
                if owned.contains(name.as_str()) || attribution.has_estimate(name) {
                    continue;
                }
                let figure = match (&saved_born, rows.contains_key(name)) {
                    (Some(saved), true) => saved.get(name).copied().unwrap_or(0),
                    (None, true) | (_, false) => overflow,
                };
                attribution.set(name, figure, day);
            }
        }
    }
}

/// Find the highest-threshold alert rule whose `at_percent` threshold
/// is satisfied by `spend / limit * 100`.
///
/// Uses `f64` comparison to avoid integer truncation errors near thresholds
/// (e.g. 99.7 % must not be cast to 99 and miss the 100 % block rule).
pub(super) fn evaluate_alerts(alerts: &[AlertRule], spend: f64, limit: f64) -> Option<AlertAction> {
    if limit <= 0.0 {
        return None;
    }
    let percent = spend / limit * 100.0;
    let mut best: Option<AlertAction> = None;
    let mut best_threshold = 0.0_f64;

    for rule in alerts {
        let threshold = f64::from(rule.at_percent);
        if percent >= threshold && threshold >= best_threshold {
            best = Some(rule.action);
            best_threshold = threshold;
        }
    }

    best
}

fn in_usd(figures: Vec<(String, u64)>) -> HashMap<String, f64> {
    figures
        .into_iter()
        .map(|(name, micro)| (name, usd(micro)))
        .collect()
}

fn daily_usd(map: &DashMap<String, DailyAccumulator>, today: Option<u64>) -> HashMap<String, f64> {
    map.iter()
        .map(|e| (e.key().clone(), usd(e.value().current_on(today))))
        .collect()
}

/// A saved row's `usd` as micro-USD, or 0 with a warning for a value no run
/// could have saved: negative, NaN, infinite, or above what a saved
/// micro-USD count can reach. Such a value is corruption; saturating it would
/// make a cap that refuses every call until the day rolls, so the row
/// restores as zero. The ceiling is the save side's own conversion of
/// `u64::MAX`, so a counter that saturated legitimately restores saturated
/// (its USD value times 1e6 rounds to 2^64; the cast saturates it back).
fn saved_micro(kind: &str, row: &str, usd_value: f64) -> u64 {
    saved_figure(kind, row, usd_value).unwrap_or(0)
}

/// `usd_value` in micro-USD, or `None`, with a warning, for a value no run
/// could have saved: a refusal, told apart from a valid zero.
fn saved_figure(kind: &str, row: &str, usd_value: f64) -> Option<u64> {
    if usd_value.is_finite() && usd_value >= 0.0 && usd_value <= usd(u64::MAX) {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        return Some((usd_value * 1_000_000.0).round() as u64);
    }
    tracing::warn!(
        target: "mcp_gateway::cost_accounting::enforcer",
        file = "costs.json",
        kind,
        row,
        usd = usd_value,
        "Saved daily total is out of range; restoring it as zero"
    );
    None
}
