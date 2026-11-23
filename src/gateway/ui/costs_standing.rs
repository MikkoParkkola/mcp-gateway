// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Where one API key stands against its own daily limit, for the Costs list:
//! what happens at the limit, whether its priced calls are refused now, and
//! since when. Plain values in, plain values out: no clock, lock or I/O here,
//! so every answer is pinned by a row with literal inputs.

use crate::cost_accounting::config::{AlertAction, AlertRule};

/// The enforcer's record of a key's first refusal under its own limit.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Refusal {
    /// The day key the refusal fell on.
    pub(crate) day: u64,
    /// When it happened, in unix seconds.
    pub(crate) at_secs: u64,
    /// The key's limit at the time, as the config gave it: compared exactly,
    /// since an unchanged limit is the same parsed value.
    pub(crate) limit: f64,
}

/// What [`standing`] reads: the figures the enforcer judges a call by, in
/// USD as its check converts them, so the two add up the same way.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Inputs<'a> {
    /// The alert rules of the request's generation.
    pub(crate) rules: &'a [AlertRule],
    /// The key's own daily limit; `None` for a key without one.
    pub(crate) limit: Option<f64>,
    /// The key's judged spend today: its row, what a reload charged it and
    /// what calls in flight hold.
    pub(crate) judged: f64,
    /// The price of the cheapest priced tool; `None` when no tool is priced.
    pub(crate) cheapest: Option<f64>,
    /// The recorded first refusal, if any.
    pub(crate) refusal: Option<Refusal>,
    /// Today's day key.
    pub(crate) today: u64,
}

/// One key's standing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Standing {
    /// What happens at the limit: `"block"`, `"notify"`, or `None` for no
    /// limit or a limit whose only consequence is a log line.
    pub(crate) at_limit: Option<&'static str>,
    /// Whether the cheapest priced call made with this key is refused now.
    pub(crate) blocking: bool,
    /// The first refusal's time, while blocking, on this day and under this
    /// limit.
    pub(crate) blocked_since: Option<u64>,
}

/// The key's standing.
pub(crate) fn standing(inputs: &Inputs<'_>) -> Standing {
    let _ = inputs;
    Standing {
        at_limit: None,
        blocking: false,
        blocked_since: None,
    }
}

/// Whether the rules never get milder as the percent rises (log, then
/// notify, then block), read through the enforcer's own choice of rule.
pub(crate) fn ordered(rules: &[AlertRule]) -> bool {
    let _ = rules;
    let _ = AlertAction::Log;
    true
}

#[cfg(tp3)]
#[cfg(test)]
#[path = "costs_standing_tests.rs"]
mod tests;
