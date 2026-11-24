// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! What the Costs list reads of one key: its own limit, its spend today as a
//! check judges it, and the first refusal under that limit today.

use super::{BudgetEnforcer, CostGovernanceConfig};

/// A key's first refusal under its own daily limit on one day.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct KeyRefusal {
    /// The day key it fell on.
    pub(crate) day: u64,
    /// When, in unix seconds.
    pub(crate) at_secs: u64,
    /// The limit it was refused under, as the config gave it.
    pub(crate) limit: f64,
}

/// One key's figures, read in one short step. The Costs page reads this and
/// the methods below it, so a build without the web UI has no caller.
#[cfg_attr(not(feature = "webui"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct KeyStandingInputs {
    /// The key's own limit in `governance`; `None` without one.
    pub(crate) limit: Option<f64>,
    /// Its spend today as the check judges it, in USD.
    pub(crate) judged: f64,
    /// Today's first refusal under its own limit, if one is recorded.
    pub(crate) refusal: Option<KeyRefusal>,
    /// The day key of the read.
    pub(crate) today: u64,
}

impl BudgetEnforcer {
    /// Record that `key` was refused under its own `limit` at `now`. The test
    /// and the write are one step on the map's entry: on the same day and
    /// under the same limit the earlier time stays, whichever refusal lands
    /// first; another day or another limit replaces the record.
    pub(super) fn note_first_block(&self, key: &str, today: u64, now: u64, limit: f64) {
        let fresh = KeyRefusal {
            day: today,
            at_secs: now,
            limit,
        };
        // Keep this one entry step: a read and a separate insert would let a
        // later refusal land between them and overwrite the earlier time.
        self.key_refused
            .entry(key.to_owned())
            .and_modify(|held| {
                // The same config value, bit for bit: no margin is wanted.
                if held.day == today && held.limit.to_bits() == limit.to_bits() {
                    held.at_secs = held.at_secs.min(now);
                } else {
                    *held = fresh;
                }
            })
            .or_insert(fresh);
    }

    /// `key`'s standing figures at `now` under `governance`: the same row,
    /// reload charge and in-flight holds the check judges a call by.
    #[cfg_attr(not(feature = "webui"), allow(dead_code))]
    pub(crate) fn key_standing_inputs(
        &self,
        governance: &CostGovernanceConfig,
        key: &str,
        now: u64,
    ) -> KeyStandingInputs {
        let today = self.day_key(now);
        // The check's order: the ledger, then the map shard, then the row.
        let pending = super::locked(&self.ledger);
        let held = pending.key(key);
        let row = self
            .key_daily
            .get(key)
            .map_or(0, |acc| acc.current_on(Some(today)));
        let judged = super::usd(self.key_attribution.judged(key, row, held, Some(today)));
        drop(pending);
        KeyStandingInputs {
            limit: governance.budgets.per_key.get(key).copied(),
            judged,
            refusal: self
                .key_refused
                .get(key)
                .map(|held| *held)
                .filter(|held| held.day == today),
            today,
        }
    }

    /// The price of the cheapest priced call, as a check converts it.
    #[cfg_attr(not(feature = "webui"), allow(dead_code))]
    pub(crate) fn cheapest_price(&self) -> Option<f64> {
        self.registry
            .cheapest_price()
            .map(|price| super::usd(super::super::tally::micro(price)))
    }

    /// When daily limits next reset after `now`: the next local midnight, or
    /// the next UTC midnight while a legacy UTC day is still open.
    #[cfg_attr(not(feature = "webui"), allow(dead_code))]
    pub(crate) fn resets_at(&self, now: u64) -> u64 {
        crate::local_day::next_reset(
            &crate::local_day::host_zone(),
            now,
            self.on_legacy_utc_day(now),
        )
    }
}
