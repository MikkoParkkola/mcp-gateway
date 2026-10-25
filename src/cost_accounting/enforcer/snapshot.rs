// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Saving and restoring the enforcer's spend: the snapshots a save writes,
//! the restore at start-up, and the alert levels a snapshot reports.

use std::collections::HashMap;

use dashmap::DashMap;

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
            for acc in map.iter() {
                acc.redate_if_empty(day);
            }
        }
        let day = Some(day);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let micro = |usd: f64| (usd.max(0.0) * 1_000_000.0).round() as u64;
        // Through the cap: a snapshot saved before the cap existed may hold
        // more names than it allows. Filed under the snapshot's own day, so
        // spend restored on a clock before 1970 still counts once the clock
        // reads that day (MIK-8202).
        let budgets = &self.config.budgets;
        // A zero row (a name saved after midnight before it spent again) is
        // not restored: it would take a place in the cap and read 0 anyway.
        for (tool, total) in &persisted.tool_totals {
            let spent = micro(total.total_cost_usd);
            if spent > 0 {
                self.global_daily.add_on(day, spent);
                add_capped(self.tool_maps(), tool, &budgets.per_tool, spent, day);
            }
        }
        for (key, &usd) in &persisted.key_totals {
            if micro(usd) > 0 {
                add_capped(self.key_maps(), key, &budgets.per_key, micro(usd), day);
            }
        }
        let tool_overflow = micro(persisted.tool_overflow_usd);
        self.global_daily.add_on(day, tool_overflow);
        self.tool_overflow.add_on(day, tool_overflow);
        self.key_overflow
            .add_on(day, micro(persisted.key_overflow_usd));
    }

    /// The day key to file `persisted` under, or `None` when it is from an
    /// earlier day. A clock it cannot read keeps the saved spend counting
    /// (MIK-8202): discarding it would restart the budgets at zero.
    fn restore_day(&self, persisted: &super::super::persistence::PersistedCosts) -> Option<u64> {
        let now = crate::clock::unix_secs();
        let saved = persisted.saved_at;
        let same_day = match persisted.day_basis.as_deref() {
            Some("local") => now.map(|now| super::day_key(now) == super::day_key(saved)),
            None => {
                let same = now.map(|now| now / 86_400 == saved / 86_400);
                if same != Ok(false) {
                    super::set_legacy_utc_day(saved / 86_400);
                }
                same
            }
            Some(other) => {
                tracing::warn!(
                    target: "mcp_gateway::cost_accounting::enforcer",
                    day_basis = other,
                    "Persisted cost data names a day basis this gateway does not know; budgets start at zero"
                );
                return None;
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
        Some(super::day_key(saved))
    }

    /// The per-tool day rows.
    pub(super) fn tool_maps(&self) -> rows::Rows<'_> {
        (
            &self.tool_daily,
            &self.tool_overflow,
            &self.tool_overflow_swept,
        )
    }

    /// The per-key day rows.
    pub(super) fn key_maps(&self) -> rows::Rows<'_> {
        (
            &self.key_daily,
            &self.key_overflow,
            &self.key_overflow_swept,
        )
    }

    /// Snapshot current accumulator state for the UI endpoint.
    #[must_use]
    pub fn snapshot(&self) -> EnforcerSnapshot {
        self.snapshot_at(crate::clock::unix_secs().ok())
    }

    /// A snapshot to persist, stamped from the wall clock. On a clock before
    /// 1970 there is none (MIK-8202): a snapshot stamped 0 would read as an
    /// earlier day on the next boot, which would throw the day's spend away.
    pub(crate) fn snapshot_for_save(
        &self,
    ) -> Result<EnforcerSaveSnapshot, crate::clock::ClockBeforeEpoch> {
        let taken_at = crate::clock::unix_secs()?;
        Ok(EnforcerSaveSnapshot::from_snapshot(
            self.snapshot_at(Some(taken_at)),
            taken_at,
        ))
    }

    fn snapshot_at(&self, taken_at: Option<u64>) -> EnforcerSnapshot {
        let global_daily_usd = usd(self.global_daily.current());

        let tool_daily = daily_usd(&self.tool_daily);

        let key_daily = daily_usd(&self.key_daily);

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
    pub(super) fn evaluate_alerts(&self, spend: f64, limit: f64) -> Option<AlertAction> {
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

fn daily_usd(map: &DashMap<String, DailyAccumulator>) -> HashMap<String, f64> {
    map.iter()
        .map(|e| (e.key().clone(), usd(e.value().current())))
        .collect()
}
