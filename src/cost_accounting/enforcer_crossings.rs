// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Budget crossings for the operational events source (MIK-7720): which of
//! 50, 80 and 100 % of a daily budget one committed spend crossed. Integer
//! math on the totals `record_spend` already has; nothing is allocated
//! unless a threshold was crossed.

use super::BudgetEnforcer;

/// The percentages of a daily budget that are reported.
const PERCENTS: [u64; 3] = [50, 80, 100];

/// Committed spend crossed `percent` of the daily budget named `scope`:
/// `global`, `tool:<name>` or `key:<API key name>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BudgetCrossing {
    pub scope: String,
    pub percent: u8,
}

/// The percentages a total moving from `after - spent` to `after` (micro-USD)
/// crossed against a daily limit of `limit_usd`.
fn crossed(after: u64, spent: u64, limit_usd: f64) -> impl Iterator<Item = u64> {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let limit = (limit_usd.max(0.0) * 1_000_000.0).round() as u64;
    let before = after.saturating_sub(spent);
    PERCENTS.into_iter().filter(move |percent| {
        let mark = limit.saturating_mul(*percent);
        limit > 0 && before.saturating_mul(100) < mark && mark <= after.saturating_mul(100)
    })
}

impl BudgetEnforcer {
    /// Attach the observer told of each crossing.
    pub(crate) fn observe(&self, observer: crate::observer::ObserverFn<BudgetCrossing>) {
        self.observer.set(observer);
    }

    /// Tell the observer of every crossing one spend of `spent` made.
    /// `totals` are the global, tool and key totals after it (the key's is
    /// unused without a key).
    pub(super) fn report_crossings(
        &self,
        tool: &str,
        key: Option<&str>,
        spent: u64,
        totals: [u64; 3],
    ) {
        let budgets = &self.config.budgets;
        let [global, tool_total, key_total] = totals;
        let scopes = [
            (budgets.daily, global, None),
            (
                budgets.per_tool.get(tool).copied(),
                tool_total,
                Some(("tool", tool)),
            ),
            (
                key.and_then(|k| budgets.per_key.get(k).copied()),
                key_total,
                key.map(|k| ("key", k)),
            ),
        ];
        for (limit, total, name) in scopes {
            let Some(limit) = limit else { continue };
            for percent in crossed(total, spent, limit) {
                self.observer.call(BudgetCrossing {
                    scope: name.map_or_else(
                        || "global".to_owned(),
                        |(kind, name)| format!("{kind}:{name}"),
                    ),
                    percent: u8::try_from(percent).unwrap_or(100),
                });
            }
        }
    }
}

#[cfg(test)]
#[path = "enforcer_crossings_tests.rs"]
mod tests;
