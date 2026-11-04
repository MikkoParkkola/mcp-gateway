// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which names are budgeted decides which have a day row of their own
//! (ADR-023): settlement reads that membership from the budgets the
//! call was admitted under, so a reload that budgets a name gives it a row
//! even when 256 unbudgeted rows already fill the map.

use super::direct_guards_fixture::Fx;
use super::live_budget_tests::{backend_call, fixture, governance, reload};
use crate::config_reload::Generation;
use crate::cost_accounting::config::CostGovernanceConfig;
use crate::gateway::meta_mcp::invoke::dispatch_guards::{Admission, BackendCall, DirectOutcome};

/// Unbudgeted rows one day map keeps (`rows::MAX_UNBUDGETED_ROWS`).
pub(super) const CAP: usize = 256;

#[derive(Clone, Copy, Debug)]
pub(super) enum Scope {
    Tool,
    Key,
}

impl Scope {
    pub(super) fn budget(self, cfg: &mut CostGovernanceConfig, name: &str) {
        let limits = match self {
            Self::Tool => &mut cfg.budgets.per_tool,
            Self::Key => &mut cfg.budgets.per_key,
        };
        limits.insert(name.to_owned(), 50.0);
    }

    /// The call that spends $1 on `name` in this scope.
    pub(super) fn call<'a>(self, name: &'a str, generation: &'a Generation) -> BackendCall<'a> {
        match self {
            Self::Tool => BackendCall {
                tool: name,
                ..backend_call(Some(generation))
            },
            Self::Key => BackendCall {
                cost_key: Some(name),
                ..backend_call(Some(generation))
            },
        }
    }

    /// This scope's day rows and its overflow total.
    pub(super) fn rows(self, fx: &Fx) -> (std::collections::HashMap<String, f64>, f64) {
        let enforcer = fx.state.meta_mcp.budget_enforcer.as_ref().expect("armed");
        let snapshot = enforcer.snapshot();
        match self {
            Self::Tool => (snapshot.tool_daily, snapshot.tool_overflow_usd),
            Self::Key => (snapshot.key_daily, snapshot.key_overflow_usd),
        }
    }

    /// Spend on `n` distinct unbudgeted names, filling the cap.
    pub(super) fn fill(self, fx: &Fx, n: usize) {
        let enforcer = fx.state.meta_mcp.budget_enforcer.as_ref().expect("armed");
        for i in 0..n {
            let name = format!("filler-{i}");
            match self {
                Self::Tool => enforcer.record_spend(&name, None, 0.01),
                Self::Key => enforcer.record_spend("filler", Some(&name), 0.01),
            }
        }
    }
}

/// An armed gateway whose `scope` rows are full, and prices for the names the
/// rows below spend on.
pub(super) async fn full_fixture(scope: Scope) -> Fx {
    let fx = fixture(&governance(|c| {
        for name in ["target", "fresh"] {
            c.tool_costs.insert(name.to_owned(), 1.0);
        }
    }))
    .await;
    scope.fill(&fx, CAP);
    fx
}

/// Settle one $1 call on `name` under the live generation.
pub(super) fn settle(fx: &Fx, scope: Scope, name: &str) {
    let generation = fx.state.live_config.generation();
    let call = scope.call(name, &generation);
    let meta = &fx.state.meta_mcp;
    meta.account_dispatch(
        &call,
        DirectOutcome::Success { spend: true },
        &Admission::default(),
    );
}

/// T18a: 256 unbudgeted rows fill the map; a reload budgets an untracked
/// name; its first spend lands in a row of its own, not in the overflow.
#[tokio::test]
async fn t18a_a_name_budgeted_by_reload_gets_its_own_row_when_the_map_is_full() {
    for scope in [Scope::Tool, Scope::Key] {
        crate::test_day::same_utc_day_async(|| async move {
            let fx = full_fixture(scope).await;
            reload(&fx, |c| scope.budget(c, "target"));
            let (before, overflow) = scope.rows(&fx);
            assert!(!before.contains_key("target"), "{scope:?}: no row yet");
            settle(&fx, scope, "target");
            let (after, overflow_after) = scope.rows(&fx);
            assert_eq!(
                after.get("target").copied(),
                Some(1.0),
                "{scope:?}: {after:?}"
            );
            assert!((overflow_after - overflow).abs() < 1e-9, "{scope:?}");
        })
        .await;
    }
}

/// T18b: a reload budgets one of the 256 unbudgeted names, so it no longer
/// counts toward the cap; a fresh unbudgeted name takes the freed place
/// instead of overflowing.
#[tokio::test]
async fn t18b_a_name_budgeted_by_reload_frees_a_place_in_the_cap() {
    for scope in [Scope::Tool, Scope::Key] {
        crate::test_day::same_utc_day_async(|| async move {
            let fx = full_fixture(scope).await;
            reload(&fx, |c| scope.budget(c, "filler-0"));
            let (_, overflow) = scope.rows(&fx);
            settle(&fx, scope, "fresh");
            let (after, overflow_after) = scope.rows(&fx);
            assert_eq!(after.get("fresh").copied(), Some(1.0), "{scope:?}");
            assert!((overflow_after - overflow).abs() < 1e-9, "{scope:?}");
        })
        .await;
    }
}
