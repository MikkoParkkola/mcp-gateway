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
