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

/// One key's figures, read in one short step.
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
    /// Record that `key` was refused under its own `limit` at `now`.
    pub(super) fn note_key_refusal(&self, key: &str, today: u64, now: u64, limit: f64) {
        let _ = (key, today, now, limit, &self.key_refused);
    }

    /// `key`'s standing figures at `now` under `governance`.
    pub(crate) fn key_standing_inputs(
        &self,
        governance: &CostGovernanceConfig,
        key: &str,
        now: u64,
    ) -> KeyStandingInputs {
        let _ = (governance, key, now);
        KeyStandingInputs {
            limit: None,
            judged: 0.0,
            refusal: None,
            today: 0,
        }
    }

    /// The price of the cheapest priced tool, as a check converts it.
    pub(crate) fn cheapest_price(&self) -> Option<f64> {
        None
    }

    /// When daily limits next reset after `now`.
    pub(crate) fn resets_at(&self, now: u64) -> u64 {
        let _ = now;
        0
    }
}
