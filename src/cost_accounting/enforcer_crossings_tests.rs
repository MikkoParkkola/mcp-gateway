// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The budget hook (MIK-7720): each threshold of each budget is reported
//! once, on the spend that crosses it.

use std::sync::Arc;

use super::super::BudgetEnforcer;
use super::BudgetCrossing;
use crate::cost_accounting::config::CostGovernanceConfig;
use crate::cost_accounting::registry::CostRegistry;

fn observed(
    cfg: CostGovernanceConfig,
) -> (BudgetEnforcer, Arc<parking_lot::Mutex<Vec<BudgetCrossing>>>) {
    let registry = Arc::new(CostRegistry::new(&cfg));
    let enforcer = BudgetEnforcer::new(cfg, registry);
    let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    enforcer.observe(Arc::new(move |crossing| sink.lock().push(crossing)));
    (enforcer, seen)
}

fn crossing(scope: &str, percent: u8) -> BudgetCrossing {
    BudgetCrossing {
        scope: scope.into(),
        percent,
    }
}

#[test]
fn each_threshold_is_reported_once_on_the_spend_that_crosses_it() {
    let mut cfg = CostGovernanceConfig {
        enabled: true,
        ..Default::default()
    };
    cfg.budgets.daily = Some(1.0);
    let (enforcer, seen) = observed(cfg);
    for usd in [0.4, 0.2, 0.3, 0.2, 0.5] {
        enforcer.record_spend("search", None, usd);
    }
    assert_eq!(
        *seen.lock(),
        [
            crossing("global", 50),
            crossing("global", 80),
            crossing("global", 100)
        ]
    );
}

#[test]
fn a_key_budget_names_its_key_and_one_spend_can_cross_every_threshold() {
    let mut cfg = CostGovernanceConfig {
        enabled: true,
        ..Default::default()
    };
    cfg.budgets.per_key.insert("dev".into(), 1.0);
    cfg.budgets.per_tool.insert("search".into(), 10.0);
    let (enforcer, seen) = observed(cfg);
    enforcer.record_spend("search", Some("ops"), 2.0);
    enforcer.record_spend("search", Some("dev"), 1.0);
    assert_eq!(
        *seen.lock(),
        [
            crossing("key:dev", 50),
            crossing("key:dev", 80),
            crossing("key:dev", 100)
        ]
    );
}
