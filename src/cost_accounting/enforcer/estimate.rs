// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which earlier spend a name budgeted by reload is charged with (ADR-023).
//!
//! Past the row cap, spend of unbudgeted names goes to one overflow total, so
//! a name a publication starts budgeting may have spent there today. Its
//! starting figure is an upper bound of that spend: the overflow total now
//! when it has no row, or the overflow total when its row was created today.
//! Once owned, a name's spend always lands in its own row, so it is never
//! charged again.

use dashmap::DashMap;

use super::DailyAccumulator;

/// One scope's (per tool or per key) attribution state.
#[derive(Default)]
pub(super) struct Attribution {
    /// Every name budgeted since startup, by the startup config or a
    /// published generation. Never removed: an owned name has a row of its
    /// own under any generation, on any day, budgeted or not.
    owned: DashMap<String, ()>,
    /// The starting figure taken for a name today (zero included).
    estimate: DashMap<String, DailyAccumulator>,
    /// The overflow total when an unowned name's row was created today.
    born: DashMap<String, DailyAccumulator>,
}

impl Attribution {
    /// State owning `names`, the startup budgets.
    pub(super) fn owning<'a>(names: impl IntoIterator<Item = &'a String>) -> Self {
        let state = Self::default();
        for name in names {
            state.owned.insert(name.clone(), ());
        }
        state
    }

    pub(super) fn owns(&self, name: &str) -> bool {
        self.owned.contains_key(name)
    }

    pub(super) fn own(&self, name: &str) {
        self.owned.entry(name.to_owned()).or_insert(());
    }

    /// The starting figure taken for `name` on `today`, in micro-USD.
    pub(super) fn estimate_on(&self, name: &str, today: Option<u64>) -> u64 {
        self.estimate
            .get(name)
            .map_or(0, |acc| acc.current_on(today))
    }

    /// Every figure taken on `today`, zeros included, in micro-USD.
    pub(super) fn estimates_on(&self, today: Option<u64>) -> Vec<(String, u64)> {
        self.estimate
            .iter()
            .filter(|entry| entry.is_current_on(today))
            .map(|entry| (entry.key().clone(), entry.current_on(today)))
            .collect()
    }

    /// Record that an unowned name's row is created now, with `overflow` in
    /// the overflow total. Nothing to record while the overflow is empty.
    pub(super) fn born(&self, name: &str, overflow: u64, day: Option<u64>) {
        if overflow > 0 && !self.owns(name) {
            let acc = DailyAccumulator::on(day);
            acc.add_on(day, overflow);
            self.born.insert(name.to_owned(), acc);
        }
    }

    /// Take `name`'s starting figure as a publication starts budgeting it,
    /// then own it. Classify, read and own in this order, under the caller's
    /// ledger lock, so no settle can own the name between them. An owned name
    /// keeps today's figure, if any: its spend since it was owned is in its row.
    pub(super) fn seed(&self, name: &str, has_row: bool, overflow: u64, day: Option<u64>) {
        let taken_today = self
            .estimate
            .get(name)
            .is_some_and(|acc| acc.is_current_on(day));
        if !self.owns(name) && !taken_today {
            let figure = if has_row {
                self.born.get(name).map_or(0, |acc| acc.current_on(day))
            } else {
                overflow
            };
            self.set(name, figure, day);
        }
        self.own(name);
    }

    /// Store `micro` as `name`'s figure on `day` (a restore, or a seed).
    pub(super) fn set(&self, name: &str, micro: u64, day: Option<u64>) {
        let acc = DailyAccumulator::on(day);
        acc.add_on(day, micro);
        self.estimate.insert(name.to_owned(), acc);
    }

    /// Drop the figures of days other than `today`. Ownership stays.
    pub(super) fn sweep(&self, today: Option<u64>) {
        self.estimate.retain(|_, acc| acc.is_current_on(today));
        self.born.retain(|_, acc| acc.is_current_on(today));
    }
}

impl super::BudgetEnforcer {
    /// A publication replacing `outgoing` budgets with `incoming` ones: each
    /// name `incoming` starts budgeting takes its starting figure, and every
    /// `incoming` name is owned from now on. One step under the ledger lock,
    /// the lock every check and settle takes first, so no settle lands
    /// between a name's classification and its owning.
    pub(crate) fn seed_estimates(
        &self,
        outgoing: &crate::cost_accounting::config::BudgetLimits,
        incoming: &crate::cost_accounting::config::BudgetLimits,
    ) {
        let today = self.today().ok();
        let _pending = super::locked(&self.ledger);
        let scopes = [
            (
                &self.tool_daily,
                &self.tool_overflow,
                &self.tool_attribution,
                &outgoing.per_tool,
                &incoming.per_tool,
            ),
            (
                &self.key_daily,
                &self.key_overflow,
                &self.key_attribution,
                &outgoing.per_key,
                &incoming.per_key,
            ),
        ];
        for (rows, overflow, attribution, before, after) in scopes {
            let overflow = overflow.current_on(today);
            for name in after.keys().filter(|name| !before.contains_key(*name)) {
                attribution.seed(name, rows.contains_key(name), overflow, today);
            }
            for name in after.keys() {
                attribution.own(name);
            }
        }
    }
}
