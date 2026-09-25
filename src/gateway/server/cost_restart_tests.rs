// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Cost budgets survive a restart.
//!
//! The boot path loads `costs.json` from the data directory. These cases boot
//! governance twice from one directory, with the shutdown save in between, and
//! read the second enforcer. A boot path that loads the file and drops the
//! result leaves the second enforcer at zero, and the first case fails.

use super::persistence::boot_cost_governance;
use super::support::build_persisted_costs;
use crate::cost_accounting::config::CostGovernanceConfig;
use crate::cost_accounting::persistence::{self as cost_persistence, PersistedCosts, ToolTotal};

/// Every call costs 0.6 against a 1.0 daily budget, so one call fits and a
/// second, counted with the first, reaches the default 100% `block` rule.
fn governed() -> CostGovernanceConfig {
    let mut cfg = CostGovernanceConfig {
        enabled: true,
        default_cost: 0.6,
        ..CostGovernanceConfig::default()
    };
    cfg.budgets.daily = Some(1.0);
    cfg
}

#[test]
fn spend_before_a_restart_still_counts_against_the_daily_budget() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = governed();

    let (_, first) = boot_cost_governance(&cfg, dir.path());
    let first = first.expect("enabled governance builds an enforcer");
    assert!(
        first.check("search", Some("dev")).allowed,
        "0.6 of a 1.0 budget must be allowed"
    );
    first.record_spend("search", Some("dev"), 0.6);
    cost_persistence::save(
        &dir.path().join("costs.json"),
        &build_persisted_costs(&first.snapshot()),
    )
    .expect("shutdown save");
    drop(first);

    let (_, second) = boot_cost_governance(&cfg, dir.path());
    let second = second.expect("enabled governance builds an enforcer");
    let snap = second.snapshot();
    assert!(
        (snap.global_daily_usd - 0.6).abs() < 1e-9,
        "the restart dropped the earlier global spend: {snap:?}"
    );
    assert!(
        (snap.tool_daily.get("search").copied().unwrap_or(0.0) - 0.6).abs() < 1e-9,
        "the restart dropped the earlier per-tool spend: {snap:?}"
    );
    assert!(
        (snap.key_daily.get("dev").copied().unwrap_or(0.0) - 0.6).abs() < 1e-9,
        "the restart dropped the earlier per-key spend: {snap:?}"
    );
    assert!(
        !second.check("search", Some("dev")).allowed,
        "a second 0.6 call after the restart must exceed the 1.0 budget"
    );
}

#[test]
fn spend_saved_on_an_earlier_day_does_not_count_today() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut persisted = PersistedCosts {
        saved_at: cost_persistence::now_secs() - 2 * 86_400,
        ..PersistedCosts::default()
    };
    persisted.tool_totals.insert(
        "search".to_string(),
        ToolTotal {
            call_count: 0,
            total_cost_usd: 0.9,
            avg_cost_usd: 0.0,
        },
    );
    persisted.key_totals.insert("dev".to_string(), 0.9);
    cost_persistence::save(&dir.path().join("costs.json"), &persisted).expect("save");

    let (_, enforcer) = boot_cost_governance(&governed(), dir.path());
    let snap = enforcer.expect("enforcer").snapshot();
    assert!(
        snap.global_daily_usd.abs() < 1e-12,
        "a snapshot from two days ago must not count against today: {snap:?}"
    );
}

#[test]
fn disabled_governance_builds_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (registry, enforcer) = boot_cost_governance(&CostGovernanceConfig::default(), dir.path());
    assert!(registry.is_none() && enforcer.is_none());
}
