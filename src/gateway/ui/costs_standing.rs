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
    // The record's limit is the config value it was refused under, compared
    // bit for bit: a reload to any other limit drops it.
    let blocked_since = inputs
        .refusal
        .filter(|refusal| {
            blocking && refusal.day == inputs.today && refusal.limit.to_bits() == limit.to_bits()
        })
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

/// The percent of a limit at which the screens warn: the lowest Notify
/// rule's, and 80 when no rule notifies. One source for the overview's limit
/// rows, the Costs list and the per-key series, so no two of them disagree.
pub(crate) fn warn_at_percent(rules: &[AlertRule]) -> f64 {
    rules
        .iter()
        .filter(|rule| rule.action == AlertAction::Notify)
        .map(|rule| f64::from(rule.at_percent))
        .reduce(f64::min)
        .unwrap_or(80.0)
}

/// `spent` as a percent of `limit`; none for a limit of zero or less, which no
/// screen warns about.
pub(crate) fn percent_of_limit(spent: f64, limit: f64) -> Option<f64> {
    (limit > 0.0).then(|| spent / limit * 100.0)
}

/// The members a `GET /ui/api/costs` answer gains: on every key row its
/// standing, its rate, today's judged spend and its own limit; on the body
/// the next reset, the percent the screens warn at and, only when it
/// applies, that the rules are unordered.
/// With no enforcer every one is null; on a clock before 1970 the figures
/// that need a time are null and nothing reads as blocking.
pub(crate) fn add_members(
    body: &mut serde_json::Value,
    tracker: &crate::cost_accounting::CostTracker,
    read: Option<(
        &crate::cost_accounting::enforcer::BudgetEnforcer,
        &crate::cost_accounting::config::CostGovernanceConfig,
    )>,
    now: Option<u64>,
) {
    use serde_json::{Value, json};
    let cheapest = read.and_then(|(enforcer, _)| enforcer.cheapest_price());
    if let Some(rows) = body.get_mut("by_key").and_then(Value::as_array_mut) {
        for row in rows {
            let Some(fields) = row.as_object_mut() else {
                continue;
            };
            let key = fields
                .get("api_key_name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let rate = now.and_then(|now| tracker.key_rate_3h(&key, now));
            let members = match read {
                None => json!({
                    "at_limit": null, "blocking": null, "blocked_since": null,
                    "rate_3h_usd_per_hour": null, "today_usd": null, "daily_limit_usd": null,
                }),
                Some((enforcer, governance)) => {
                    let figures =
                        now.map(|now| enforcer.key_standing_inputs(governance, &key, now));
                    let got = standing(&Inputs {
                        rules: &governance.alerts,
                        limit: governance.budgets.per_key.get(&key).copied(),
                        judged: figures.map_or(0.0, |read| read.judged),
                        // No time, no day to judge in: nothing reads as blocking.
                        cheapest: cheapest.filter(|_| figures.is_some()),
                        refusal: figures.and_then(|read| read.refusal),
                        today: figures.map_or(0, |read| read.today),
                    });
                    json!({
                        "at_limit": got.at_limit,
                        "blocking": got.blocking,
                        "blocked_since": got.blocked_since,
                        "rate_3h_usd_per_hour": rate,
                        "today_usd": figures.map(|read| read.judged),
                        "daily_limit_usd": governance.budgets.per_key.get(&key),
                    })
                }
            };
            if let Value::Object(members) = members {
                fields.extend(members);
            }
        }
    }
    let Some(fields) = body.as_object_mut() else {
        return;
    };
    let resets_at = read
        .zip(now)
        .map(|((enforcer, _), now)| enforcer.resets_at(now));
    fields.insert("resets_at".to_owned(), json!(resets_at));
    let warn_at = read.map(|(_, governance)| warn_at_percent(&governance.alerts));
    fields.insert("warn_at_percent".to_owned(), json!(warn_at));
    if read.is_some_and(|(_, governance)| !ordered(&governance.alerts)) {
        fields.insert("alert_rules".to_owned(), json!("unordered"));
    }
}

#[cfg(tp3)]
#[cfg(test)]
#[path = "costs_standing_tests.rs"]
mod tests;

#[cfg(tp3)]
#[cfg(test)]
#[path = "costs_standing_enforcer_tests.rs"]
mod enforcer_tests;
