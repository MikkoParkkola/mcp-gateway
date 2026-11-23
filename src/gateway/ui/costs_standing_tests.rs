// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A key's standing, from literal inputs: no clock and no enforcer.

use super::{Inputs, Refusal, Standing, ordered, standing};
use crate::cost_accounting::config::{AlertAction, AlertRule};

fn rule(at_percent: u32, action: AlertAction) -> AlertRule {
    AlertRule { at_percent, action }
}

const TODAY: u64 = 20_000;
const LIMIT: f64 = 25.0;
const CHEAPEST: f64 = 0.01;

fn inputs(rules: &[AlertRule], judged: f64) -> Inputs<'_> {
    Inputs {
        rules,
        limit: Some(LIMIT),
        judged,
        cheapest: Some(CHEAPEST),
        refusal: None,
        today: TODAY,
    }
}

fn at_limit(rules: &[AlertRule], limit: Option<f64>) -> Option<&'static str> {
    standing(&Inputs {
        limit,
        ..inputs(rules, 0.0)
    })
    .at_limit
}

/// The action at exactly the limit is the highest rule reached there; a log
/// line, no rule or no limit is no action a person sees.
#[test]
fn s1_at_limit_reads_the_rule_at_100_percent() {
    use AlertAction::{Block, Log, Notify};
    assert_eq!(
        at_limit(&[rule(80, Notify), rule(100, Block)], Some(LIMIT)),
        Some("block")
    );
    assert_eq!(at_limit(&[rule(80, Notify)], Some(LIMIT)), Some("notify"));
    assert_eq!(at_limit(&[rule(100, Log)], Some(LIMIT)), None);
    assert_eq!(at_limit(&[], Some(LIMIT)), None);
    assert_eq!(at_limit(&[rule(80, Notify), rule(100, Block)], None), None);
}

/// Blocking is the cheapest priced call refused now: judged spend plus the
/// cheapest price reaches a block rule.
#[test]
fn s2_blocking_is_the_cheapest_call_refused() {
    use AlertAction::{Block, Notify};
    let block_at_100 = [rule(100, Block)];
    assert!(!standing(&inputs(&block_at_100, 24.98)).blocking);
    assert!(standing(&inputs(&block_at_100, 24.99)).blocking);
    assert!(!standing(&inputs(&[rule(100, Notify)], 24.99)).blocking);
    let block_at_90 = [rule(90, Block)];
    assert!(!standing(&inputs(&block_at_90, 22.48)).blocking);
    assert!(standing(&inputs(&block_at_90, 22.49)).blocking);
}

/// The pure half of s2f: severity never falls as the percent rises, judged
/// at each rule's percent by the action the enforcer would take there.
#[test]
fn s2f_unordered_rules_are_said_in_the_answer() {
    use AlertAction::{Block, Log, Notify};
    assert!(ordered(&[
        rule(50, Log),
        rule(80, Notify),
        rule(100, Block)
    ]));
    assert!(ordered(&[rule(100, Block)]));
    assert!(ordered(&[]));
    assert!(!ordered(&[rule(80, Block), rule(100, Notify)]));
    assert!(!ordered(&[rule(50, Notify), rule(80, Log)]));
    // Given out of percent order: the walk is by percent, not by position.
    assert!(ordered(&[rule(100, Block), rule(50, Log)]));
    // Two rules at one percent: the action the enforcer takes there decides.
    // It keeps the later of the two, so block then log at 80 reads log.
    assert!(!ordered(&[
        rule(50, Notify),
        rule(80, Block),
        rule(80, Log)
    ]));
    assert!(ordered(&[rule(50, Notify), rule(80, Log), rule(80, Block)]));
}

fn since(refusal: Refusal, judged: f64) -> Option<u64> {
    standing(&Inputs {
        refusal: Some(refusal),
        ..inputs(&[rule(100, AlertAction::Block)], judged)
    })
    .blocked_since
}

/// The record counts only while blocking, on this day and under this limit.
#[test]
fn s3_blocked_since_needs_blocking_today_and_the_same_limit() {
    let today = Refusal {
        day: TODAY,
        at_secs: 1_774_778_400,
        limit: LIMIT,
    };
    assert_eq!(since(today, 24.99), Some(1_774_778_400));
    let yesterday = Refusal {
        day: TODAY - 1,
        ..today
    };
    assert_eq!(since(yesterday, 24.99), None);
    let other_limit = Refusal {
        limit: 20.0,
        ..today
    };
    assert_eq!(since(other_limit, 24.99), None);
    assert_eq!(since(today, 20.0), None, "not blocking");
}

/// No priced tool: no call can be refused for spend.
#[test]
fn s4_no_priced_tool_never_blocks() {
    let got = standing(&Inputs {
        cheapest: None,
        ..inputs(&[rule(100, AlertAction::Block)], 25.0)
    });
    assert_eq!(
        got,
        Standing {
            at_limit: Some("block"),
            blocking: false,
            blocked_since: None,
        }
    );
}

/// The next reset is the next local midnight, exact on 23 and 25 hour days;
/// while the legacy UTC day is open, the next UTC midnight.
#[test]
fn s6_next_reset_is_the_next_local_midnight() {
    use crate::local_day::next_reset;
    use chrono_tz::Tz;
    assert_eq!(
        next_reset(&Tz::Europe__Amsterdam, 1_774_778_400, false),
        1_774_821_600
    );
    assert_eq!(
        next_reset(&Tz::Europe__Amsterdam, 1_792_926_000, false),
        1_792_969_200
    );
    assert_eq!(
        next_reset(&Tz::Asia__Kathmandu, 1_781_504_100, false),
        1_781_547_300
    );
    assert_eq!(
        next_reset(&Tz::Europe__Amsterdam, 1_774_778_400, true),
        1_774_828_800
    );
}
