// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The overflow estimate of a name budgeted by reload survives a restart
//! apart from real spend (ADR-023): saved in `tool_estimate` /
//! `key_estimate`, restored into the estimate, never into the totals.

use super::persistence::boot_cost_governance;
use super::support::build_persisted_costs;
use crate::clock::test_clock::at_secs;
use crate::cost_accounting::config::{BudgetLimits, CostGovernanceConfig};
use crate::cost_accounting::enforcer::BudgetEnforcer;
use crate::cost_accounting::persistence::{self as cost_persistence, PersistedCosts};

const T: u64 = 1_800_000_000;
/// Unbudgeted rows one day map keeps (`rows::MAX_UNBUDGETED_ROWS`).
const CAP: usize = 256;

#[derive(Clone, Copy, Debug)]
enum Scope {
    Tool,
    Key,
}

impl Scope {
    fn limits(self, budgets: &mut BudgetLimits) -> &mut std::collections::HashMap<String, f64> {
        match self {
            Self::Tool => &mut budgets.per_tool,
            Self::Key => &mut budgets.per_key,
        }
    }

    /// Spend `usd` on `name` in this scope.
    fn spend(self, enforcer: &BudgetEnforcer, name: &str, usd: f64) {
        match self {
            Self::Tool => enforcer.record_spend(name, None, usd),
            Self::Key => enforcer.record_spend("read", Some(name), usd),
        }
    }

    /// Whether a call priced 1.0 on `name` is admitted.
    fn admits(self, enforcer: &BudgetEnforcer, name: &str) -> bool {
        match self {
            Self::Tool => enforcer.check(name, None).allowed,
            Self::Key => enforcer.check("read", Some(name)).allowed,
        }
    }

    fn estimate(self, persisted: &PersistedCosts, name: &str) -> Option<f64> {
        match self {
            Self::Tool => persisted.tool_estimate.get(name).copied(),
            Self::Key => persisted.key_estimate.get(name).copied(),
        }
    }
}

/// Governance on, every call priced 1.0, `target` budgeted at `limit` in
/// `scope` when one is given.
fn governed(scope: Scope, limit: Option<f64>) -> CostGovernanceConfig {
    let mut cfg = CostGovernanceConfig {
        enabled: true,
        default_cost: 1.0,
        ..CostGovernanceConfig::default()
    };
    if let Some(limit) = limit {
        scope
            .limits(&mut cfg.budgets)
            .insert("target".to_owned(), limit);
    }
    cfg
}

/// A first process: the map full, $3 of `target`'s spend in the overflow,
/// a publication that budgets `target`, then $0.50 of real spend on it.
/// Returns what its shutdown save writes.
fn first_process(scope: Scope, dir: &std::path::Path) -> PersistedCosts {
    let (_, enforcer) = boot_cost_governance(&governed(scope, None), dir);
    let enforcer = enforcer.expect("enabled governance builds an enforcer");
    for i in 0..CAP {
        scope.spend(&enforcer, &format!("filler-{i}"), 0.01);
    }
    scope.spend(&enforcer, "target", 3.0);
    let incoming = governed(scope, Some(5.0)).budgets;
    enforcer.seed_estimates(&BudgetLimits::default(), &incoming);
    scope.spend(&enforcer, "target", 0.5);
    let persisted = build_persisted_costs(&enforcer.snapshot_for_save().expect("a readable clock"));
    cost_persistence::save(&dir.join("costs.json"), &persisted).expect("shutdown save");
    persisted
}

/// T8: the estimate is saved apart from real spend and restored apart, so
/// the judged figure is the estimate plus the real spend, once: $4.50 in
/// all ($3, $0.50 and the $1 call) fits a $5 budget (a double count reads
/// $7.50) and not a $4.40 one (a lost estimate reads $1.50). The global
/// total stays as saved.
#[test]
fn t8_the_estimate_is_kept_apart_through_save_and_restore() {
    for scope in [Scope::Tool, Scope::Key] {
        let _clock = at_secs(T);
        let dir = tempfile::tempdir().expect("tempdir");
        let saved = first_process(scope, dir.path());
        assert_eq!(scope.estimate(&saved, "target"), Some(3.0), "{scope:?}");
        let real = match scope {
            Scope::Tool => saved.tool_totals.get("target").map(|t| t.total_cost_usd),
            Scope::Key => saved.key_totals.get("target").copied(),
        };
        assert_eq!(real, Some(0.5), "{scope:?}: real spend saved apart");

        let (_, fits) = boot_cost_governance(&governed(scope, Some(5.0)), dir.path());
        let fits = fits.expect("armed");
        assert!(scope.admits(&fits, "target"), "{scope:?}: 3 + 0.5 + 1 < 5");
        let snap = fits.snapshot();
        assert!(
            (snap.global_daily_usd
                - saved
                    .tool_totals
                    .values()
                    .map(|t| t.total_cost_usd)
                    .sum::<f64>()
                - saved.tool_overflow_usd)
                .abs()
                < 1e-9,
            "{scope:?}: the estimate is not in the global total: {snap:?}"
        );
        let (_, tight) = boot_cost_governance(&governed(scope, Some(4.4)), dir.path());
        assert!(
            !scope.admits(&tight.expect("armed"), "target"),
            "{scope:?}: 4.5 > 4.4"
        );
    }
}

/// T8b: a negative or non-finite saved estimate restores as no estimate,
/// so the name is judged from its real spend alone.
#[test]
fn t8b_a_corrupt_saved_estimate_restores_nothing() {
    for scope in [Scope::Tool, Scope::Key] {
        for bad in [-1.0, f64::NAN, f64::INFINITY] {
            let _clock = at_secs(T);
            let dir = tempfile::tempdir().expect("tempdir");
            let mut saved = first_process(scope, dir.path());
            match scope {
                Scope::Tool => saved.tool_estimate.insert("target".to_owned(), bad),
                Scope::Key => saved.key_estimate.insert("target".to_owned(), bad),
            };
            cost_persistence::save(&dir.path().join("costs.json"), &saved).expect("save");
            let (_, restored) = boot_cost_governance(&governed(scope, Some(1.6)), dir.path());
            assert!(
                scope.admits(&restored.expect("armed"), "target"),
                "{scope:?} {bad}: 0.5 + 1 < 1.6 with no estimate"
            );
        }
    }
}

/// T8c: an estimated name keeps its restored row through a saturated cap,
/// though the restarted config does not budget it: the estimates are
/// restored before the rows, so the name owns its row. An owned name still
/// takes a place in the cap, so one filler's spend may restore into the
/// overflow instead; none is lost.
#[test]
fn t8c_an_estimated_name_keeps_its_row_through_a_full_cap() {
    for scope in [Scope::Tool, Scope::Key] {
        let _clock = at_secs(T);
        let dir = tempfile::tempdir().expect("tempdir");
        let saved = first_process(scope, dir.path());
        let (_, restored) = boot_cost_governance(&governed(scope, None), dir.path());
        let snap = restored.expect("armed").snapshot();
        let (rows, overflow, saved_rows, saved_overflow) = match scope {
            Scope::Tool => (
                snap.tool_daily,
                snap.tool_overflow_usd,
                saved
                    .tool_totals
                    .values()
                    .map(|t| t.total_cost_usd)
                    .sum::<f64>(),
                saved.tool_overflow_usd,
            ),
            Scope::Key => (
                snap.key_daily,
                snap.key_overflow_usd,
                saved.key_totals.values().sum::<f64>(),
                saved.key_overflow_usd,
            ),
        };
        assert_eq!(rows.get("target").copied(), Some(0.5), "{scope:?}: its row");
        let restored_sum = rows.values().sum::<f64>() + overflow;
        assert!(
            (restored_sum - (saved_rows + saved_overflow)).abs() < 1e-9,
            "{scope:?}: every saved dollar restored, in a row or the overflow"
        );
    }
}

/// T8d: a zero figure is saved and restored as taken: after a restart with
/// the budget removed, the name's spend lands in its own row, and budgeting
/// it again on the same day takes no figure from the overflow.
#[test]
fn t8d_a_zero_estimate_survives_a_restart() {
    for scope in [Scope::Tool, Scope::Key] {
        let _clock = at_secs(T);
        let dir = tempfile::tempdir().expect("tempdir");
        {
            let (_, first) = boot_cost_governance(&governed(scope, None), dir.path());
            let first = first.expect("armed");
            for i in 0..CAP {
                scope.spend(&first, &format!("filler-{i}"), 0.01);
            }
            // The overflow is empty: the figure taken is zero.
            first.seed_estimates(
                &BudgetLimits::default(),
                &governed(scope, Some(2.5)).budgets,
            );
            let persisted =
                build_persisted_costs(&first.snapshot_for_save().expect("a readable clock"));
            assert_eq!(scope.estimate(&persisted, "target"), Some(0.0), "{scope:?}");
            cost_persistence::save(&dir.path().join("costs.json"), &persisted).expect("save");
        }
        let (_, second) = boot_cost_governance(&governed(scope, None), dir.path());
        let second = second.expect("armed");
        scope.spend(&second, "unrelated", 2.0);
        scope.spend(&second, "target", 1.0);
        let rows = match scope {
            Scope::Tool => second.snapshot().tool_daily,
            Scope::Key => second.snapshot().key_daily,
        };
        assert_eq!(
            rows.get("target").copied(),
            Some(1.0),
            "{scope:?}: its own row"
        );
        second.seed_estimates(
            &BudgetLimits::default(),
            &governed(scope, Some(2.5)).budgets,
        );
        let budgeted = governed(scope, Some(2.5));
        assert!(
            second
                .check_under(
                    &budgeted,
                    if matches!(scope, Scope::Tool) {
                        "target"
                    } else {
                        "read"
                    },
                    matches!(scope, Scope::Key).then_some("target")
                )
                .allowed,
            "{scope:?}: 1 + 0 + 1 < 2.5; a re-taken figure reads 2 more"
        );
    }
}
