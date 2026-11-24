// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A key's standing read from a real budget enforcer, on a fixed clock: the
//! answer agrees with what the enforcer's own check does.

use std::collections::HashMap;
use std::sync::Arc;

use super::{Inputs, Standing, standing};
use crate::clock::test_clock;
use crate::cost_accounting::config::{AlertAction, AlertRule, BudgetLimits, CostGovernanceConfig};
use crate::cost_accounting::enforcer::BudgetEnforcer;
use crate::cost_accounting::persistence::PersistedCosts;
use crate::cost_accounting::registry::CostRegistry;

/// 2026-03-29 10:00 UTC; tests count days in UTC.
const NOW: u64 = 1_774_778_400;
const KEY: &str = "ci";

fn rule(at_percent: u32, action: AlertAction) -> AlertRule {
    AlertRule { at_percent, action }
}

fn governance(
    limits: &[(&str, f64)],
    prices: &[(&str, f64)],
    alerts: Vec<AlertRule>,
) -> CostGovernanceConfig {
    let mut config = CostGovernanceConfig {
        enabled: true,
        alerts,
        budgets: BudgetLimits {
            per_key: limits.iter().map(|(k, v)| ((*k).to_string(), *v)).collect(),
            ..BudgetLimits::default()
        },
        ..CostGovernanceConfig::default()
    };
    for (tool, price) in prices {
        config.tool_costs.insert((*tool).to_string(), *price);
    }
    config
}

fn enforcer(config: CostGovernanceConfig) -> BudgetEnforcer {
    let registry = Arc::new(CostRegistry::new(&config));
    BudgetEnforcer::new(config, registry)
}

fn block_at_100() -> Vec<AlertRule> {
    vec![rule(100, AlertAction::Block)]
}

/// The key's standing under `governance`, read as the Costs route reads it.
fn standing_under(
    e: &BudgetEnforcer,
    governance: &CostGovernanceConfig,
    key: &str,
) -> (Standing, f64) {
    let read = e.key_standing_inputs(governance, key, NOW);
    let got = standing(&Inputs {
        rules: &governance.alerts,
        limit: read.limit,
        judged: read.judged,
        cheapest: e.cheapest_price(),
        refusal: read.refusal,
        today: read.today,
    });
    (got, read.judged)
}

fn close(got: f64, want: f64) {
    assert!((got - want).abs() < 1e-9, "{got} != {want}");
}

/// The declared gap: `blocking` reads the registry's cheapest price, so a key
/// that reaches only a dearer tool is refused a little before it reads true.
#[test]
fn s2b_blocking_uses_the_registry_wide_cheapest_price() {
    let _clock = test_clock::at_secs(NOW);
    let config = governance(
        &[(KEY, 25.0)],
        &[("cheap", 0.01), ("dear", 0.50)],
        block_at_100(),
    );
    let e = enforcer(config.clone());
    e.record_spend("dear", Some(KEY), 24.60);
    assert!(
        !e.check("dear", Some(KEY)).allowed,
        "premise: the key's own tool is refused"
    );
    assert!(!standing_under(&e, &config, KEY).0.blocking);
    e.record_spend("dear", Some(KEY), 0.39);
    assert!(standing_under(&e, &config, KEY).0.blocking);

    // The same gap when the cheapest call is the default price.
    let config = CostGovernanceConfig {
        default_cost: 0.01,
        ..governance(&[(KEY, 25.0)], &[("dear", 0.50)], block_at_100())
    };
    let e = enforcer(config.clone());
    e.record_spend("dear", Some(KEY), 24.60);
    assert!(
        !e.check("dear", Some(KEY)).allowed,
        "premise: the key's own tool is refused"
    );
    assert!(!standing_under(&e, &config, KEY).0.blocking);
    e.record_spend("dear", Some(KEY), 0.39);
    assert!(standing_under(&e, &config, KEY).0.blocking);
}

/// A tool that is not listed costs the default price, so with a default
/// above zero that is the cheapest call a key can make: `blocking` reads it.
#[test]
fn s4b_the_default_price_is_a_priced_call() {
    let _clock = test_clock::at_secs(NOW);
    let config = CostGovernanceConfig {
        default_cost: 0.005,
        ..governance(&[(KEY, 25.0)], &[("dear", 3.0)], block_at_100())
    };
    let e = enforcer(config.clone());
    e.record_spend("dear", Some(KEY), 24.995);
    assert!(
        !e.check("unlisted", Some(KEY)).allowed,
        "premise: an unlisted tool is refused"
    );
    assert!(standing_under(&e, &config, KEY).0.blocking);
}

/// Around the limit, `blocking` is exactly a real check of the cheapest tool
/// refused.
#[test]
fn s2c_blocking_agrees_with_a_real_check_of_the_cheapest_tool() {
    let _clock = test_clock::at_secs(NOW);
    for judged in [24.97, 24.98, 24.99, 25.00] {
        let config = governance(
            &[(KEY, 25.0)],
            &[("cheap", 0.01), ("dear", 3.0)],
            block_at_100(),
        );
        let e = enforcer(config.clone());
        e.record_spend("dear", Some(KEY), judged);
        let blocking = standing_under(&e, &config, KEY).0.blocking;
        let refused = !e.check("cheap", Some(KEY)).allowed;
        assert_eq!(blocking, refused, "judged {judged}");
    }
}

/// Unordered rules: `blocking` keeps its one meaning, the cheapest call is
/// refused, while a dearer call that reaches a milder rule is allowed.
#[test]
fn s2d_blocking_means_the_cheapest_call_under_rules_that_are_not_ordered() {
    let _clock = test_clock::at_secs(NOW);
    let rules = vec![rule(80, AlertAction::Block), rule(100, AlertAction::Notify)];
    let config = governance(&[(KEY, 25.0)], &[("cheap", 0.01), ("dear", 5.01)], rules);
    let e = enforcer(config.clone());
    e.record_spend("dear", Some(KEY), 19.99);
    assert!(standing_under(&e, &config, KEY).0.blocking);
    assert!(e.check("dear", Some(KEY)).allowed, "100 percent is notify");
    assert!(!e.check("cheap", Some(KEY)).allowed, "80 percent is block");
}

/// The judged figure counts spend held by a call in flight and what a reload
/// charged, beside the recorded row.
#[test]
fn s2e_judged_spend_counts_reservations_and_reload_charges() {
    let _clock = test_clock::at_secs(NOW);
    let keys = [("held", 25.0), ("charged", 25.0), ("plain", 25.0)];
    let config = governance(&keys, &[("cheap", 0.01), ("hold", 4.99)], block_at_100());
    let e = enforcer(config.clone());
    let names = || keys.iter().map(|(k, _)| (*k).to_string());
    e.restore(&PersistedCosts {
        saved_at: NOW,
        key_totals: names().map(|k| (k, 20.0)).collect(),
        key_estimate: HashMap::from([("charged".to_string(), 4.99)]),
        key_owned: Some(names().collect()),
        day_basis: Some("local".to_string()),
        ..PersistedCosts::default()
    });
    let in_flight = e.check("hold", Some("held"));
    assert!(in_flight.allowed, "premise: the hold is admitted");
    for (key, blocking, today) in [
        ("held", true, 24.99),
        ("charged", true, 24.99),
        ("plain", false, 20.0),
    ] {
        let (got, judged) = standing_under(&e, &config, key);
        assert_eq!(got.blocking, blocking, "{key}");
        close(judged, today);
    }
    drop(in_flight);
}

/// A reload that raises the limit clears both; a restore keeps no time.
#[test]
fn s8_a_reload_that_raises_the_limit_clears_blocking_and_a_restore_keeps_no_time() {
    let _clock = test_clock::at_secs(NOW);
    let config = governance(&[(KEY, 25.0)], &[("cheap", 0.01)], block_at_100());
    let e = enforcer(config.clone());
    e.record_spend("cheap", Some(KEY), 24.99);
    assert!(!e.check("cheap", Some(KEY)).allowed, "premise: refused");
    let before = standing_under(&e, &config, KEY).0;
    assert_eq!((before.blocking, before.blocked_since), (true, Some(NOW)));

    let raised = governance(&[(KEY, 30.0)], &[("cheap", 0.01)], block_at_100());
    let after = standing_under(&e, &raised, KEY).0;
    assert_eq!((after.blocking, after.blocked_since), (false, None));

    let restored = enforcer(config.clone());
    restored.restore(&PersistedCosts {
        saved_at: NOW,
        key_totals: HashMap::from([(KEY.to_string(), 24.99)]),
        key_owned: Some(vec![KEY.to_string()]),
        day_basis: Some("local".to_string()),
        ..PersistedCosts::default()
    });
    let back = standing_under(&restored, &config, KEY).0;
    assert_eq!((back.blocking, back.blocked_since), (true, None));
}
