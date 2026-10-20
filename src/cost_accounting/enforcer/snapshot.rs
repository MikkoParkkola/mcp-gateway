// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Saving and restoring the enforcer's spend: the snapshots a save writes,
//! the restore at start-up, and the alert levels a snapshot reports.

use std::collections::HashMap;

use super::super::persistence::EnforcerSaveSnapshot;
use super::{AlertAction, BudgetEnforcer, EnforcerSnapshot, add_capped, rows, usd};

impl BudgetEnforcer {
    /// Re-apply today's spend from a persisted snapshot, so a restart keeps
    /// counting against the budgets instead of starting them at zero.
    ///
    /// A snapshot saved on an earlier UTC day is ignored: the daily budgets it
    /// counted have already reset. The global total is the sum of the per-tool
    /// totals, because every recorded spend lands in both.
    pub fn restore(&self, persisted: &super::super::persistence::PersistedCosts) {
        // A clock it cannot read keeps the saved spend counting (MIK-8202):
        // discarding it would restart the budgets at zero.
        let today = crate::clock::unix_secs().map(|now| now / 86_400);
        if today.is_ok_and(|today| persisted.saved_at / 86_400 != today) {
            tracing::info!(
                // The pre-split module path, kept as the log target.
                target: "mcp_gateway::cost_accounting::enforcer",
                saved_at = persisted.saved_at,
                "Persisted cost data is from an earlier UTC day; budgets start at zero"
            );
            return;
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let micro = |usd: f64| (usd.max(0.0) * 1_000_000.0).round() as u64;
        // Through the cap: a snapshot saved before the cap existed may hold
        // more names than it allows. Filed under the snapshot's own UTC day,
        // so spend restored on a clock before 1970 still counts once the
        // clock reads that day (MIK-8202).
        let budgets = &self.config.budgets;
        let day = Some(persisted.saved_at / 86_400);
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

        let tool_daily: HashMap<String, f64> = self
            .tool_daily
            .iter()
            .map(|e| (e.key().clone(), usd(e.value().current())))
            .collect();

        let key_daily: HashMap<String, f64> = self
            .key_daily
            .iter()
            .map(|e| (e.key().clone(), usd(e.value().current())))
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
