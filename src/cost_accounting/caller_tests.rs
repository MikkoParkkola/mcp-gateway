// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7653 T7/T8: the per-caller store's idle reset, sweep and concurrency.

use std::sync::Arc;

use super::{CALLER_COST_IDLE, CallerCosts};
use crate::cost_accounting::CostRecord;

const IDLE: u64 = CALLER_COST_IDLE.as_secs();

fn rec(tool: &str) -> CostRecord {
    CostRecord::new("alpha", tool, 10, 1.0)
}

/// `(tool_key, call_count)` of `key`'s snapshot at `now`, sorted.
fn tools(costs: &CallerCosts, key: &str, now: u64) -> Option<Vec<(String, u64)>> {
    costs.snapshot(key, now).map(|s| {
        let mut rows: Vec<_> = s
            .by_tool
            .into_iter()
            .map(|t| (t.tool_key, t.call_count))
            .collect();
        rows.sort();
        rows
    })
}

#[test]
fn a_returning_caller_sees_only_its_new_spend() {
    let costs = CallerCosts::default();
    costs.record("k", &rec("read"), 1000);
    // No sweep runs, so only the reset on record can drop the old spend
    costs
        .next_sweep
        .store(u64::MAX, std::sync::atomic::Ordering::Relaxed);
    costs.record("k", &rec("write"), 1000 + IDLE);
    assert_eq!(
        tools(&costs, "k", 1000 + IDLE),
        Some(vec![("alpha:write".to_string(), 1)])
    );
    // The totals were reset with the breakdown, not only the tool rows
    let snap = costs.snapshot("k", 1000 + IDLE).expect("fresh spend");
    assert_eq!((snap.call_count, snap.total_tokens), (1, 10));
    assert!((snap.total_cost_usd - 0.000_01).abs() < 1e-12);
}

#[test]
fn an_idle_breakdown_is_not_reported_even_before_a_sweep() {
    let costs = CallerCosts::default();
    costs.record("k", &rec("read"), 1000);
    assert_eq!(
        tools(&costs, "k", 1000 + IDLE - 1),
        Some(vec![("alpha:read".to_string(), 1)])
    );
    assert_eq!(tools(&costs, "k", 1000 + IDLE), None);
}

#[test]
fn a_later_record_sweeps_idle_callers_and_keeps_fresh_ones() {
    let costs = CallerCosts::default();
    costs.record("old", &rec("read"), 1000);
    costs.record("fresh", &rec("read"), 1000 + IDLE - 10);
    costs.record("other", &rec("read"), 1000 + IDLE + 60);
    assert!(
        !costs.by_caller.contains_key("old"),
        "the idle caller was kept"
    );
    assert!(
        costs.by_caller.contains_key("fresh"),
        "a fresh caller was swept"
    );
}

#[test]
fn an_empty_key_keeps_nothing() {
    let costs = CallerCosts::default();
    costs.record("", &rec("read"), 1000);
    assert!(costs.by_caller.is_empty());
    assert_eq!(tools(&costs, "", 1000), None);
}

#[test]
fn recording_a_caller_leaves_the_aggregate_alone() {
    let tracker = crate::cost_accounting::CostTracker::new();
    tracker.record_caller("k", "alpha", "read", 10, 1.0);
    assert_eq!(tracker.aggregate().total_calls, 0);
    assert_eq!(tracker.aggregate().key_count, 0);
}

#[test]
fn concurrent_records_during_sweeps_finish_with_exact_totals() {
    let costs = Arc::new(CallerCosts::default());
    let threads: Vec<_> = (0..8)
        .map(|t| {
            let costs = Arc::clone(&costs);
            std::thread::spawn(move || {
                for i in 0..500u64 {
                    // Every call is sweep-eligible: `now` keeps moving past the due time
                    costs.record(
                        &format!("k{}", i % 16),
                        &rec("read"),
                        1000 + i * SWEEP_STEP + t,
                    );
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().expect("no worker panicked");
    }
    let calls: u64 = (0..16)
        .filter_map(|k| costs.snapshot(&format!("k{k}"), 1000 + 500 * SWEEP_STEP))
        .map(|s| s.call_count)
        .sum();
    assert_eq!(calls, 8 * 500);
}

/// Larger than the sweep interval, far smaller than the idle window.
const SWEEP_STEP: u64 = 61;
