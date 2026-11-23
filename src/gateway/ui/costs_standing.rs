// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Where one API key stands against its own daily limit, for the Costs list:
//! what happens at the limit, whether its priced calls are refused now, and
//! since when. Plain values in, plain values out: no clock, lock or I/O here,
//! so every answer is pinned by a row with literal inputs.

use crate::cost_accounting::config::{AlertAction, AlertRule};
use crate::cost_accounting::enforcer::evaluate_alerts;

/// The enforcer's record of a key's first refusal under its own limit.
pub(crate) use crate::cost_accounting::enforcer::standing::KeyRefusal as Refusal;

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
    let Some(limit) = inputs.limit else {
        return Standing {
            at_limit: None,
            blocking: false,
            blocked_since: None,
        };
    };
    // Spend exactly at the limit: the rule the enforcer applies there.
    let at_limit = match evaluate_alerts(inputs.rules, limit, limit) {
        Some(AlertAction::Block) => Some("block"),
        Some(AlertAction::Notify) => Some("notify"),
        Some(AlertAction::Log) | None => None,
    };
    // The check's own sum: judged spend plus the call's price, against the
    // limit, under the same rules.
    let blocking = inputs.cheapest.is_some_and(|cheapest| {
        evaluate_alerts(inputs.rules, inputs.judged + cheapest, limit) == Some(AlertAction::Block)
    });
    let blocked_since = inputs
        .refusal
        .filter(|refusal| blocking && refusal.day == inputs.today && refusal.limit == limit)
        .map(|refusal| refusal.at_secs);
    Standing {
        at_limit,
        blocking,
        blocked_since,
    }
}

/// Whether the rules never get milder as the percent rises (log, then
/// notify, then block), read through the enforcer's own choice of rule.
pub(crate) fn ordered(rules: &[AlertRule]) -> bool {
    let mut percents: Vec<u32> = rules.iter().map(|rule| rule.at_percent).collect();
    percents.sort_unstable();
    percents.dedup();
    // Half a percent past each rule's own: every rule at or below it is
    // reached and none above it, clear of the float noise an exact percent
    // would carry through the enforcer's spend / limit * 100.
    let severity = |percent: u32| match evaluate_alerts(rules, f64::from(percent) + 0.5, 100.0) {
        None => 0,
        Some(AlertAction::Log) => 1,
        Some(AlertAction::Notify) => 2,
        Some(AlertAction::Block) => 3,
    };
    percents
        .windows(2)
        .all(|pair| severity(pair[0]) <= severity(pair[1]))
}

#[cfg(tp3)]
#[cfg(test)]
#[path = "costs_standing_tests.rs"]
mod tests;

#[cfg(tp3)]
#[cfg(test)]
#[path = "costs_standing_enforcer_tests.rs"]
mod enforcer_tests;
