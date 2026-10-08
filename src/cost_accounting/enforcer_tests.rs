// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Budget enforcer checks, alerts and accumulators.

use super::*;
use crate::cost_accounting::config::{BudgetLimits, CostGovernanceConfig};
use crate::cost_accounting::registry::CostRegistry;

fn enforcer_with(
    enabled: bool,
    daily: Option<f64>,
    per_tool: &[(&str, f64)],
    per_key: &[(&str, f64)],
    tool_costs: &[(&str, f64)],
) -> BudgetEnforcer {
    let mut cfg = CostGovernanceConfig {
        enabled,
        budgets: BudgetLimits {
            daily,
            per_tool: per_tool.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
            per_key: per_key.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
        },
        ..CostGovernanceConfig::default()
    };
    for (name, cost) in tool_costs {
        cfg.tool_costs.insert(name.to_string(), *cost);
    }
    let registry = Arc::new(CostRegistry::new(&cfg));
    BudgetEnforcer::new(cfg, registry)
}

#[test]
#[allow(clippy::float_cmp)]
fn enforcer_disabled_allows_all() {
    let e = enforcer_with(false, Some(0.001), &[], &[], &[("paid_tool", 0.01)]);
    let result = e.check("paid_tool", None);
    assert!(result.allowed);
    assert_eq!(result.cost_usd, 0.0);
    assert!(result.warnings.is_empty());
}

#[test]
#[allow(clippy::float_cmp)]
fn enforcer_free_tool_skips_checks() {
    let e = enforcer_with(true, Some(0.001), &[], &[], &[("free_tool", 0.0)]);
    let result = e.check("free_tool", None);
    assert!(result.allowed);
    assert_eq!(result.cost_usd, 0.0);
    assert!(result.block_reason.is_none());
}

#[test]
fn enforcer_per_tool_block_when_exceeded() {
    // limit = $0.005; cost = $0.01 → projected = $0.01 > limit → block
    let e = enforcer_with(
        true,
        None,
        &[("expensive_tool", 0.005)],
        &[],
        &[("expensive_tool", 0.01)],
    );
    // Pre-fill $0.004 (80% of limit)
    e.record_spend("expensive_tool", None, 0.004);
    // Next call costs $0.01 → $0.014 total → exceeds $0.005
    let result = e.check("expensive_tool", None);
    assert!(!result.allowed);
    assert!(result.block_reason.is_some());
}

#[test]
fn enforcer_global_block_when_exceeded() {
    let e = enforcer_with(true, Some(0.01), &[], &[], &[("tool", 0.006)]);
    // Spend $0.006, then try another $0.006 → $0.012 > $0.01
    e.record_spend("tool", None, 0.006);
    let result = e.check("tool", None);
    assert!(!result.allowed);
    assert!(result.block_reason.as_deref().unwrap().contains("Global"));
}

#[test]
fn enforcer_per_key_block_when_exceeded() {
    let e = enforcer_with(true, None, &[], &[("dev_key", 0.01)], &[("tool", 0.008)]);
    e.record_spend("tool", Some("dev_key"), 0.008);
    let result = e.check("tool", Some("dev_key"));
    assert!(!result.allowed);
    assert!(result.block_reason.as_deref().unwrap().contains("dev_key"));
}

#[test]
fn enforcer_notify_warning_at_80_percent() {
    // limit = $0.01, cost = $0.009 → 90% → Notify
    let e = enforcer_with(true, Some(0.01), &[], &[], &[("tool", 0.009)]);
    let result = e.check("tool", None);
    assert!(result.allowed, "Should be allowed at 90% (not 100%)");
    assert!(!result.warnings.is_empty(), "Should have a warning at 90%");
}

#[test]
fn enforcer_log_at_50_percent_no_response_warning() {
    // limit = $0.10, cost = $0.06 → 60% → Log only, no Notify
    let e = enforcer_with(true, Some(0.10), &[], &[], &[("tool", 0.06)]);
    let result = e.check("tool", None);
    assert!(result.allowed);
    // At 60%: Log fires but NOT Notify, so warnings vec stays empty
    assert!(
        result.warnings.is_empty(),
        "Log-only tier must NOT inject response warnings"
    );
}

#[test]
fn enforcer_record_spend_accumulates() {
    let e = enforcer_with(true, Some(1.0), &[], &[], &[("tool", 0.01)]);
    e.record_spend("tool", Some("k1"), 0.30);
    e.record_spend("tool", Some("k1"), 0.20);
    let snap = e.snapshot();
    assert!((snap.global_daily_usd - 0.50).abs() < 1e-6);
    assert!((snap.tool_daily["tool"] - 0.50).abs() < 1e-6);
    assert!((snap.key_daily["k1"] - 0.50).abs() < 1e-6);
}

#[test]
fn enforcer_check_performance_under_100us() {
    // 10,000 checks must complete in under 1 second total (<0.1ms each)
    let e = enforcer_with(true, Some(100.0), &[], &[], &[("tool", 0.001)]);
    let start = std::time::Instant::now();
    for _ in 0..10_000 {
        let _ = e.check("tool", Some("key"));
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs() < 1,
        "10,000 checks took {elapsed:?} (must be < 1s)"
    );
}

#[test]
fn daily_accumulator_add_increases_current() {
    let acc = DailyAccumulator::new();
    acc.add(500_000); // $0.50
    acc.add(300_000); // $0.30
    assert_eq!(acc.current(), 800_000);
}

#[test]
fn evaluate_alerts_selects_highest_matching_threshold() {
    // spend=0.09, limit=0.10 → 90% → highest rule that fires is Notify(80)
    let e = enforcer_with(true, Some(0.10), &[], &[], &[]);
    let action = e.evaluate_alerts(0.09, 0.10);
    assert_eq!(action, Some(AlertAction::Notify));
}

#[test]
fn evaluate_alerts_returns_block_at_100_percent() {
    let e = enforcer_with(true, Some(0.10), &[], &[], &[]);
    let action = e.evaluate_alerts(0.10, 0.10);
    assert_eq!(action, Some(AlertAction::Block));
}

#[test]
fn evaluate_alerts_returns_none_below_50_percent() {
    let e = enforcer_with(true, Some(1.0), &[], &[], &[]);
    let action = e.evaluate_alerts(0.40, 1.0);
    assert_eq!(action, None);
}

// ── Day maps stay bounded (MIK-8015) ──────────────────────────────

#[test]
fn many_unbudgeted_tools_in_one_day_hold_a_bounded_number_of_entries() {
    // GIVEN: no per-tool budgets, and spend on 1000 distinct tool names today
    let e = enforcer_with(true, None, &[], &[], &[]);
    for i in 0..1_000 {
        e.record_spend(&format!("invented-{i}"), None, 0.01);
    }
    // THEN: the per-tool day map holds the cap plus one overflow entry, not 1000
    let held = e.tool_daily.len();
    assert!(held <= 257, "the per-tool day map holds {held} entries");
}

#[test]
fn a_spend_sweeps_unbudgeted_entries_from_an_earlier_day() {
    // GIVEN: entries left from two days ago for an unbudgeted tool and key, and
    // one for a key with a budget
    let e = enforcer_with(true, None, &[], &[("budgeted", 5.0)], &[]);
    let old = current_day() - 2;
    e.tool_daily
        .insert("old-tool".to_string(), DailyAccumulator::stale(old, 5));
    e.key_daily
        .insert("old-key".to_string(), DailyAccumulator::stale(old, 5));
    e.key_daily
        .insert("budgeted".to_string(), DailyAccumulator::stale(old, 5));
    // WHEN: a call spends today
    e.record_spend("t", Some("k"), 0.01);
    // THEN: the stale unbudgeted entries are gone; the budgeted key keeps its own
    assert!(!e.tool_daily.contains_key("old-tool"), "stale tool kept");
    assert!(!e.key_daily.contains_key("old-key"), "stale key kept");
    assert!(e.key_daily.contains_key("budgeted"));
}

#[test]
fn spend_past_the_cap_counts_in_other_and_a_budgeted_tool_still_blocks() {
    // GIVEN: a budgeted tool, and the unbudgeted cap already filled
    let e = enforcer_with(true, None, &[("paid", 0.005)], &[], &[("paid", 0.01)]);
    for i in 0..300 {
        e.record_spend(&format!("invented-{i}"), None, 0.01);
    }
    e.record_spend("paid", None, 0.004);
    // THEN: the overflow is all in its own total, and the budgeted tool kept its own
    // entry, so its check still blocks
    let snap = e.snapshot();
    // Exactly the cap of unbudgeted names got their own entries.
    let own = MAX_UNBUDGETED_ROWS;
    #[allow(clippy::cast_precision_loss)]
    let overflow = (300 - own) as f64 * 0.01;
    let other = snap.tool_overflow_usd;
    assert!(
        (other - overflow).abs() < 1e-9,
        "the overflow holds {other}"
    );
    assert!((snap.tool_daily["paid"] - 0.004).abs() < 1e-9);
    assert!(!e.check("paid", None).allowed);
}

#[test]
fn the_sweep_keeps_entries_from_today() {
    // GIVEN: spend today on an unbudgeted tool and key
    let e = enforcer_with(true, None, &[], &[], &[]);
    e.record_spend("today-tool", Some("today-key"), 0.01);
    // WHEN: a later spend runs a due sweep
    e.next_sweep.store(0, std::sync::atomic::Ordering::Relaxed);
    e.record_spend("t", None, 0.01);
    // THEN: today's entries are still there
    assert!(e.tool_daily.contains_key("today-tool"));
    assert!(e.key_daily.contains_key("today-key"));
}

#[test]
fn a_budget_named_other_never_sees_overflow_spend() {
    // GIVEN: a per-tool budget whose name is "(other)", and the cap filled
    let e = enforcer_with(true, None, &[("(other)", 1.0)], &[], &[("(other)", 0.01)]);
    for i in 0..400 {
        e.record_spend(&format!("invented-{i}"), None, 0.01);
    }
    // THEN: that budget's own total is untouched, so its check passes
    assert!(!e.snapshot().tool_daily.contains_key("(other)"));
    assert!(e.check("(other)", None).allowed);
}

#[test]
fn a_restore_applies_the_cap_and_keeps_the_saved_overflow() {
    use super::super::persistence::{PersistedCosts, ToolTotal, now_secs};
    // GIVEN: a same-day snapshot saved before the cap, with 400 tool names
    let mut saved = PersistedCosts {
        saved_at: now_secs(),
        tool_overflow_usd: 0.5,
        ..PersistedCosts::default()
    };
    for i in 0..400 {
        let total = ToolTotal {
            call_count: 1,
            total_cost_usd: 0.01,
            avg_cost_usd: 0.01,
        };
        saved.tool_totals.insert(format!("t{i}"), total);
    }
    // WHEN: it is restored
    let e = enforcer_with(true, None, &[], &[], &[]);
    e.restore(&saved);
    // THEN: the map holds the cap; nothing is lost from the day's spend
    assert_eq!(e.tool_daily.len(), MAX_UNBUDGETED_ROWS);
    let snap = e.snapshot();
    #[allow(clippy::cast_precision_loss)]
    let past_cap = (400 - MAX_UNBUDGETED_ROWS) as f64 * 0.01;
    assert!((snap.tool_overflow_usd - (0.5 + past_cap)).abs() < 1e-9);
    assert!((snap.global_daily_usd - (4.0 + 0.5)).abs() < 1e-9);
}

#[test]
fn budgeted_names_arriving_after_the_cap_do_not_widen_it() {
    // GIVEN: three budgeted keys that spend only after the cap is full
    let budgets = [("b1", 9.0), ("b2", 9.0), ("b3", 9.0)];
    let e = enforcer_with(true, None, &[], &budgets, &[]);
    for i in 0..300 {
        e.record_spend("t", Some(&format!("invented-{i}")), 0.01);
    }
    for (name, _) in budgets {
        e.record_spend("t", Some(name), 0.01);
    }
    // THEN: the key map holds the cap plus the budgeted names, and the
    // overflow holds the rest of the invented keys
    assert_eq!(e.key_daily.len(), MAX_UNBUDGETED_ROWS + budgets.len());
    #[allow(clippy::cast_precision_loss)]
    let overflow = (300 - MAX_UNBUDGETED_ROWS) as f64 * 0.01;
    assert!((e.snapshot().key_overflow_usd - overflow).abs() < 1e-9);
}

#[test]
fn an_over_long_unbudgeted_name_counts_as_overflow() {
    let e = enforcer_with(true, None, &[], &[], &[]);
    let long = "x".repeat(super::super::tally::MAX_ROW_NAME_BYTES + 1);
    e.record_spend(&long, None, 0.01);
    assert!(e.tool_daily.is_empty());
    assert!((e.snapshot().tool_overflow_usd - 0.01).abs() < 1e-9);
}

#[test]
fn budgeted_names_present_first_leave_the_full_unbudgeted_allowance() {
    // GIVEN: three budgeted keys that spend before any other key
    let budgets = [("b1", 9.0), ("b2", 9.0), ("b3", 9.0)];
    let e = enforcer_with(true, None, &[], &budgets, &[]);
    for (name, _) in budgets {
        e.record_spend("t", Some(name), 0.01);
    }
    for i in 0..300 {
        e.record_spend("t", Some(&format!("invented-{i}")), 0.01);
    }
    // THEN: the invented keys still get the whole cap of their own entries
    assert_eq!(e.key_daily.len(), budgets.len() + MAX_UNBUDGETED_ROWS);
}

#[test]
fn a_due_sweep_frees_the_cap_before_a_new_name_is_counted() {
    // GIVEN: the per-tool map full of unbudgeted entries from two days ago
    let e = enforcer_with(true, None, &[], &[], &[]);
    let old = current_day() - 2;
    for i in 0..MAX_UNBUDGETED_ROWS {
        e.tool_daily
            .insert(format!("old-{i}"), DailyAccumulator::stale(old, 5));
    }
    // WHEN: the first spend of the day, with a sweep due, uses a new name
    e.record_spend("new-today", None, 0.01);
    // THEN: the sweep ran first, so the new name has its own entry
    assert!(e.tool_daily.contains_key("new-today"));
    assert!(e.snapshot().tool_overflow_usd.abs() < 1e-12);
}

#[test]
fn the_first_spend_of_a_new_day_sweeps_whatever_the_minute_throttle_says() {
    // GIVEN: yesterday's map full of unbudgeted rows, and the minute throttle
    // armed far ahead, as if a sweep had just run before midnight
    let e = enforcer_with(true, None, &[], &[], &[]);
    let yesterday = current_day() - 1;
    for i in 0..MAX_UNBUDGETED_ROWS {
        e.tool_daily
            .insert(format!("old-{i}"), DailyAccumulator::stale(yesterday, 5));
    }
    e.swept_day
        .store(yesterday, std::sync::atomic::Ordering::Relaxed);
    e.next_sweep
        .store(u64::MAX, std::sync::atomic::Ordering::Relaxed);
    // WHEN: the first spend of today uses a new name
    e.record_spend("new-today", None, 0.01);
    // THEN: the new day swept first, so the name has its own entry
    assert!(e.tool_daily.contains_key("new-today"));
    assert!(e.snapshot().tool_overflow_usd.abs() < 1e-12);
}

#[test]
fn a_restore_skips_rows_that_hold_no_spend() {
    use super::super::persistence::{PersistedCosts, ToolTotal, now_secs};
    // GIVEN: a same-day save holding zero rows left from the day before
    let mut saved = PersistedCosts {
        saved_at: now_secs(),
        ..PersistedCosts::default()
    };
    for i in 0..300 {
        let zero = ToolTotal {
            call_count: 0,
            total_cost_usd: 0.0,
            avg_cost_usd: 0.0,
        };
        saved.tool_totals.insert(format!("idle-{i}"), zero);
        saved.key_totals.insert(format!("idle-key-{i}"), 0.0);
    }
    // AND: one tool and one key that did spend today
    let used = ToolTotal {
        call_count: 1,
        total_cost_usd: 0.02,
        avg_cost_usd: 0.02,
    };
    saved.tool_totals.insert("used".to_string(), used);
    saved.key_totals.insert("used-key".to_string(), 0.03);
    // WHEN: it is restored
    let e = enforcer_with(true, None, &[], &[], &[]);
    e.restore(&saved);
    // THEN: only the rows with spend are back; no zero row takes a cap place
    let snap = e.snapshot();
    assert_eq!(e.tool_daily.len(), 1);
    assert_eq!(e.key_daily.len(), 1);
    assert!((snap.tool_daily["used"] - 0.02).abs() < 1e-9);
    assert!((snap.key_daily["used-key"] - 0.03).abs() < 1e-9);
}

/// A map full of yesterday's unbudgeted rows, with today already marked swept
/// and the minute throttle armed: what a spend that read the day just before
/// midnight leaves for the first spend after it (MIK-8045).
fn swept_today_with_old_rows(
    rows: fn(&BudgetEnforcer) -> &DashMap<String, DailyAccumulator>,
) -> BudgetEnforcer {
    let e = enforcer_with(true, None, &[], &[], &[]);
    let yesterday = current_day() - 1;
    for i in 0..MAX_UNBUDGETED_ROWS {
        rows(&e).insert(format!("old-{i}"), DailyAccumulator::stale(yesterday, 5));
    }
    e.swept_day
        .store(current_day(), std::sync::atomic::Ordering::Relaxed);
    e.next_sweep
        .store(u64::MAX, std::sync::atomic::Ordering::Relaxed);
    e
}

/// `MIK-STRADDLE.1`: a new tool gets its own row although the day's sweep ran
/// before yesterday's rows went stale.
#[test]
fn a_new_tool_after_a_straddled_sweep_gets_its_own_row() {
    // GIVEN: the tool map at the cap with yesterday's rows, today marked swept
    let e = swept_today_with_old_rows(|e| &e.tool_daily);
    // WHEN: a new tool spends
    e.record_spend("new-today", None, 0.01);
    // THEN: it has its own row and nothing overflowed
    assert!(
        e.tool_daily.contains_key("new-today"),
        "the new tool's spend went to the overflow row"
    );
    let snap = e.snapshot();
    assert!((snap.tool_daily["new-today"] - 0.01).abs() < 1e-9);
    assert!(snap.tool_overflow_usd.abs() < 1e-12);
}

/// `MIK-STRADDLE.2`: the same for a new key.
#[test]
fn a_new_key_after_a_straddled_sweep_gets_its_own_row() {
    // GIVEN: the key map at the cap with yesterday's rows, today marked swept
    let e = swept_today_with_old_rows(|e| &e.key_daily);
    // WHEN: a new key spends
    e.record_spend("t", Some("new-key"), 0.01);
    // THEN: it has its own row and nothing overflowed
    assert!(
        e.key_daily.contains_key("new-key"),
        "the new key's spend went to the overflow row"
    );
    let snap = e.snapshot();
    assert!((snap.key_daily["new-key"] - 0.01).abs() < 1e-9);
    assert!(snap.key_overflow_usd.abs() < 1e-12);
}

/// `MIK-STRADDLE.3`: with the cap full of today's rows, overflowing spends do
/// not sweep the map each time; at most one sweep a day.
#[test]
fn overflowing_spends_sweep_at_most_once_a_day() {
    // GIVEN: the tool map at the cap with today's rows, and one spend past it
    let e = enforcer_with(true, None, &[], &[], &[]);
    for i in 0..MAX_UNBUDGETED_ROWS {
        e.record_spend(&format!("now-{i}"), None, 0.01);
    }
    e.record_spend("first-over", None, 0.01);
    // AND: a row gone stale since, with the minute throttle armed
    let yesterday = DailyAccumulator::stale(current_day() - 1, 5);
    e.tool_daily.insert("now-0".to_string(), yesterday);
    e.next_sweep
        .store(u64::MAX, std::sync::atomic::Ordering::Relaxed);
    // WHEN: another new tool spends past the cap
    e.record_spend("second-over", None, 0.01);
    // THEN: no second sweep ran that day
    assert!(
        e.tool_daily.contains_key("now-0"),
        "an overflowing spend swept the map again the same day"
    );
}

/// `MIK-8081.CEIL.2`: a tool priced below one micro-USD counts at least one
/// micro-USD per call, so N calls exhaust a budget that fits N, and the call
/// after them is refused.
#[test]
fn a_sub_micro_tool_exhausts_a_budget_of_n_micros() {
    const N: u32 = 5;
    // GIVEN: a tool priced at a tenth of a micro-USD, under a per-tool budget
    // that fits N micro-USD and refuses the next
    let limit = (f64::from(N) + 0.5) * 1e-6;
    let e = enforcer_with(true, None, &[("cheap", limit)], &[], &[("cheap", 1e-7)]);
    // WHEN: N calls are admitted and recorded
    for call in 0..N {
        let verdict = e.check("cheap", None);
        assert!(verdict.allowed, "call {call} of {N} is admitted");
        e.settle(verdict.hold.as_deref(), "cheap", None, verdict.cost_usd);
    }
    // THEN: the budget is spent, and the next call is refused
    assert!(
        !e.check("cheap", None).allowed,
        "a sub-micro tool was never counted against its budget"
    );
}
