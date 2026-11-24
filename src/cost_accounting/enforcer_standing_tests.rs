// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The first refusal a key meets under its own daily limit, on a fixed clock.

use super::standing::KeyRefusal;
use super::*;
use crate::clock::test_clock;
use crate::cost_accounting::config::{BudgetLimits, CostGovernanceConfig};
use crate::cost_accounting::registry::CostRegistry;

/// 2026-03-29 10:00 UTC; tests count days in UTC.
const T1: u64 = 1_774_778_400;
const T2: u64 = T1 + 60;
/// The next UTC midnight after `T1`.
const MIDNIGHT: u64 = 1_774_828_800;
const KEY: &str = "ci";

fn enforcer(daily: Option<f64>, key_limit: f64) -> BudgetEnforcer {
    let mut config = CostGovernanceConfig {
        enabled: true,
        budgets: BudgetLimits {
            daily,
            per_key: [(KEY.to_string(), key_limit)].into(),
            ..BudgetLimits::default()
        },
        ..CostGovernanceConfig::default()
    };
    config.tool_costs.insert("cheap".to_string(), 0.01);
    let registry = Arc::new(CostRegistry::new(&config));
    BudgetEnforcer::new(config, registry)
}

fn refusal(e: &BudgetEnforcer, now: u64) -> Option<KeyRefusal> {
    e.key_standing_inputs(&e.config, KEY, now).refusal
}

/// The first refusal under the key's own limit is recorded once; a later one
/// leaves it; a refusal by another limit records nothing for the key; the
/// next day carries none.
#[test]
fn s5_the_first_key_refusal_of_the_day_is_recorded_once() {
    let e = enforcer(None, 25.0);
    {
        let _clock = test_clock::at_secs(T1);
        e.record_spend("cheap", Some(KEY), 24.99);
        assert!(!e.check("cheap", Some(KEY)).allowed, "premise: refused");
    }
    let today = e.day_key(T1);
    let first = KeyRefusal {
        day: today,
        at_secs: T1,
        limit: 25.0,
    };
    assert_eq!(refusal(&e, T1), Some(first));
    {
        let _clock = test_clock::at_secs(T2);
        assert!(!e.check("cheap", Some(KEY)).allowed);
    }
    assert_eq!(refusal(&e, T2), Some(first), "a second refusal moved it");
    assert_eq!(
        refusal(&e, MIDNIGHT),
        None,
        "the next day carries no record"
    );

    let global = enforcer(Some(1.0), 25.0);
    {
        let _clock = test_clock::at_secs(T1);
        global.record_spend("cheap", Some(KEY), 1.0);
        let refused = global.check("cheap", Some(KEY));
        assert!(!refused.allowed, "premise: the global limit refuses");
        assert!(
            refused
                .block_reason
                .as_deref()
                .is_some_and(|r| r.contains("Global"))
        );
    }
    assert_eq!(refusal(&global, T1), None, "not the key's own limit");
}

/// The day sweep keeps a record from its own day, and one from a day that
/// began after the sweep read its day: a sweep paused across midnight must
/// not erase the new day's first refusal.
#[test]
fn s5d_a_day_sweep_keeps_records_of_its_day_and_later() {
    let today = enforcer(None, 25.0).day_key(T1);
    let held = KeyRefusal {
        day: today,
        at_secs: T1,
        limit: 25.0,
    };
    let e = enforcer(None, 25.0);
    e.note_first_block(KEY, today, T1, 25.0);
    {
        let _clock = test_clock::at_secs(T2);
        // The day's first spend sweeps, with `today` as its day.
        e.record_spend("cheap", Some(KEY), 0.01);
    }
    assert_eq!(refusal(&e, T2), Some(held), "the sweep's own day stays");

    let tomorrow = enforcer(None, 25.0).day_key(MIDNIGHT);
    let later = KeyRefusal {
        day: tomorrow,
        at_secs: MIDNIGHT + 60,
        limit: 25.0,
    };
    let e = enforcer(None, 25.0);
    // Recorded on the new day while a sweep that read the old day waits.
    e.note_first_block(KEY, tomorrow, MIDNIGHT + 60, 25.0);
    {
        let _clock = test_clock::at_secs(T1);
        e.record_spend("cheap", Some(KEY), 0.01);
    }
    assert_eq!(
        refusal(&e, MIDNIGHT + 120),
        Some(later),
        "a newer day's record stays"
    );
}

/// Many refusals at once, from 8 threads: the record ends at the smallest
/// time. A correct write cannot lose it under any schedule; a read followed
/// by a separate insert loses an update on practically every run.
#[test]
fn s5c_concurrent_refusals_keep_the_smallest_time() {
    const THREADS: u64 = 8;
    const EACH: u64 = 10_000;
    let e = enforcer(None, 25.0);
    let today = e.day_key(T1);
    std::thread::scope(|scope| {
        for thread in 0..THREADS {
            let e = &e;
            scope.spawn(move || {
                for i in 0..EACH {
                    // A fixed spread of times; the smallest, T1, is written
                    // once, mid-run, while every other thread still writes.
                    let offset = (thread * EACH + i).wrapping_mul(7_919) % 80_000;
                    let at = if thread == 0 && i == EACH / 2 {
                        T1
                    } else {
                        T1 + 1 + offset
                    };
                    e.note_first_block(KEY, today, at, 25.0);
                }
            });
        }
    });
    assert_eq!(refusal(&e, T1).map(|r| r.at_secs), Some(T1));
}

/// Two refusals at once keep the earlier time in either order of arrival; a
/// refusal under a changed limit replaces the record.
#[test]
fn s5b_two_refusals_at_once_keep_the_earlier_time() {
    let today = enforcer(None, 25.0).day_key(T1);
    let earlier = KeyRefusal {
        day: today,
        at_secs: T1,
        limit: 25.0,
    };
    for order in [[T1, T2], [T2, T1]] {
        let e = enforcer(None, 25.0);
        for at in order {
            e.note_first_block(KEY, today, at, 25.0);
        }
        assert_eq!(refusal(&e, T2), Some(earlier), "order {order:?}");
    }
    let e = enforcer(None, 30.0);
    e.note_first_block(KEY, today, T1, 25.0);
    e.note_first_block(KEY, today, T2, 30.0);
    assert_eq!(
        refusal(&e, T2),
        Some(KeyRefusal {
            day: today,
            at_secs: T2,
            limit: 30.0,
        }),
        "another limit replaces the record"
    );
}
