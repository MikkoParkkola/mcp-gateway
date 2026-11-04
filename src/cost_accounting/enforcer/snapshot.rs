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
            // A file saved before the field existed keeps the figures the
            // restore recorded (the restored overflow, an upper bound).
            let saved_born: Option<Vec<(String, u64)>> = born.as_ref().map(|map| {
                map.iter()
                    .filter_map(|(name, &usd)| {
                        saved_figure(kind, name, usd).map(|m| (name.clone(), m))
                    })
                    .collect()
            });
            if let Some(saved_born) = &saved_born {
                attribution.restore_born(saved_born, day);
            }
            // A file saved before the owned names existed seeds nothing.
            let Some(owned) = owned else { continue };
            for name in budgets.keys() {
                if owned.contains(name) || attribution.has_estimate(name) {
                    continue;
                }
                let figure = if rows.contains_key(name) {
                    saved_born
                        .iter()
                        .flatten()
                        .find(|(n, _)| n == name)
                        .map_or(0, |(_, micro)| *micro)
                } else {
                    overflow
                };
                attribution.set(name, figure, day);
            }
        }
    }

    /// The day key to file `persisted` under, or `None` when it is from an
    /// earlier day. A clock it cannot read keeps the saved spend counting
    /// instead: discarding it would restart the budgets at zero.
    fn restore_day(&self, persisted: &super::super::persistence::PersistedCosts) -> Option<u64> {
        let now = crate::clock::unix_secs();
        let saved = persisted.saved_at;
        let same_day = match persisted.day_basis.as_deref() {
            Some("local") => now.map(|now| self.day_key(now) == self.day_key(saved)),
            // A basis this build does not recognise counts as a pre-upgrade
            // UTC day: discarding it would restart the budgets at zero.
            basis => {
                if let Some(other) = basis {
                    tracing::warn!(
                        target: "mcp_gateway::cost_accounting::enforcer",
                        day_basis = other,
                        "Persisted cost data names a day basis this gateway does not recognise; restoring it as a UTC day"
                    );
                }
                let same = now.map(|now| now / 86_400 == saved / 86_400);
                if same != Ok(false) {
                    self.legacy_utc_day
                        .store(saved / 86_400 + 1, std::sync::atomic::Ordering::Relaxed);
                }
                same
            }
        };
        if same_day == Ok(false) {
            tracing::info!(
                // The pre-split module path, kept as the log target.
                target: "mcp_gateway::cost_accounting::enforcer",
                saved_at = saved,
                "Persisted cost data is from an earlier day; budgets start at zero"
            );
            return None;
        }
        Some(self.day_key(saved))
    }

    /// The per-tool day rows.
    pub(super) fn tool_maps(&self) -> rows::Rows<'_> {
        (
            &self.tool_daily,
            &self.tool_overflow,
            &self.tool_overflow_swept,
            &self.tool_attribution,
        )
    }

    /// The per-key day rows.
    pub(super) fn key_maps(&self) -> rows::Rows<'_> {
        (
            &self.key_daily,
            &self.key_overflow,
            &self.key_overflow_swept,
            &self.key_attribution,
        )
    }

    /// Snapshot current accumulator state for the UI endpoint.
    #[must_use]
    pub fn snapshot(&self) -> EnforcerSnapshot {
        self.snapshot_under(&self.config)
    }

    /// [`Self::snapshot`] reporting the limits of `governance`, the config one
    /// response is built from.
    #[must_use]
    pub(crate) fn snapshot_under(&self, governance: &CostGovernanceConfig) -> EnforcerSnapshot {
        self.snapshot_at(crate::clock::unix_secs().ok(), governance)
    }

    /// A snapshot to persist, stamped from the wall clock. On a clock before
    /// 1970 there is none (MIK-8202): a snapshot stamped 0 would read as an
    /// earlier day on the next boot, which would throw the day's spend away.
    pub(crate) fn snapshot_for_save(
        &self,
    ) -> Result<EnforcerSaveSnapshot, crate::clock::ClockBeforeEpoch> {
        let taken_at = crate::clock::unix_secs()?;
        // One hold of the ledger lock across every capture, the lock a seed
        // holds while it classifies, reads and owns: a save never records a
        // name as owned without the figure that seed gave it (ADR-023).
        let _ledger = super::locked(&self.ledger);
        let today = Some(self.day_key(taken_at));
        let mut save = EnforcerSaveSnapshot::from_snapshot(
            self.snapshot_at(Some(taken_at), &self.config),
            taken_at,
            self.day_basis_at(taken_at),
        );
        save.tool_owned = self.tool_attribution.owned_names();
        save.key_owned = self.key_attribution.owned_names();
        save.tool_born = in_usd(self.tool_attribution.born_on(today));
        save.key_born = in_usd(self.key_attribution.born_on(today));
        Ok(save)
    }

    fn snapshot_at(
        &self,
        taken_at: Option<u64>,
        governance: &CostGovernanceConfig,
    ) -> EnforcerSnapshot {
        let today = taken_at.map(|secs| self.day_key(secs));
        let global_daily_usd = usd(self.global_daily.current_on(today));

        let tool_daily = daily_usd(&self.tool_daily, today);

        let key_daily = daily_usd(&self.key_daily, today);

        EnforcerSnapshot {
            global_daily_usd,
            global_daily_limit: governance.budgets.daily,
            tool_daily,
            tool_limits: governance.budgets.per_tool.clone(),
            taken_at,
            key_daily,
            key_limits: governance.budgets.per_key.clone(),
            tool_overflow_usd: usd(self.tool_overflow.current_on(today)),
            key_overflow_usd: usd(self.key_overflow.current_on(today)),
            tool_estimate: in_usd(self.tool_attribution.estimates_on(today)),
            key_estimate: in_usd(self.key_attribution.estimates_on(today)),
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
