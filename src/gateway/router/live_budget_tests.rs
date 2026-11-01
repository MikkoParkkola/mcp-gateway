// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Cost-governance budgets and alerts apply on reload (ADR-023, U19 PR3a):
//! the next call is judged by the published budgets, today's spend survives
//! the swap, and a request keeps the budgets it arrived with.

use std::sync::Arc;

use serde_json::{Value, json};

use super::direct_guards_fixture::{Answer, Fx, fixture_built, post_meta_invoke};
use crate::cost_accounting::config::{AlertAction, AlertRule, CostGovernanceConfig};
use crate::cost_accounting::enforcer::BudgetEnforcer;
use crate::cost_accounting::registry::CostRegistry;
use crate::gateway::meta_mcp::visible::seams;

const KEY: &str = "k-budget";

/// Governance on, `read` at 1.0 a call, the default alert tiers, and the
/// budgets `budgets` sets.
fn governance(budgets: impl FnOnce(&mut CostGovernanceConfig)) -> CostGovernanceConfig {
    let mut cfg = CostGovernanceConfig {
        enabled: true,
        ..Default::default()
    };
    cfg.tool_costs.insert("read".to_string(), 1.0);
    budgets(&mut cfg);
    cfg
}

/// A gateway started with `cfg`: the enforcer built from it, and the live
/// config publishing the same section, as startup does.
async fn fixture(cfg: &CostGovernanceConfig) -> Fx {
    let registry = Arc::new(CostRegistry::new(cfg));
    let enforcer = Arc::new(BudgetEnforcer::new(cfg.clone(), Arc::clone(&registry)));
    let fx = fixture_built(Answer::Ok, move |meta| {
        meta.with_cost_governance(enforcer, registry)
    })
    .await;
    let seeded = cfg.clone();
    fx.state
        .live_config
        .edit(move |c| c.cost_governance = seeded);
    fx
}

/// Publish an edit of `cost_governance`, as a reload would.
fn reload(fx: &Fx, edit: impl FnOnce(&mut CostGovernanceConfig)) {
    fx.state.live_config.edit(|c| edit(&mut c.cost_governance));
}

/// The same edit as a hook a seam runs mid-request.
fn reload_hook(
    fx: &Fx,
    edit: impl FnOnce(&mut CostGovernanceConfig) + 'static,
) -> impl FnOnce() + 'static {
    let live = Arc::clone(&fx.state.live_config);
    move || live.edit(|c| edit(&mut c.cost_governance))
}

async fn call(fx: &Fx) -> Value {
    post_meta_invoke(fx, KEY, "alpha", "read", json!({}), None, None)
        .await
        .1
}

/// Whether `body` is the budget refusal.
fn refused(body: &Value) -> bool {
    body.pointer("/error/code") == Some(&json!(-32003))
}

/// `KEY`'s spend today, as the enforcer counts it.
fn spent(fx: &Fx) -> f64 {
    let enforcer = fx.state.meta_mcp.budget_enforcer.as_ref().expect("armed");
    enforcer
        .snapshot()
        .key_daily
        .get(KEY)
        .copied()
        .unwrap_or(0.0)
}

/// `n` admitted calls; each must pass.
async fn spend(fx: &Fx, n: usize) {
    for i in 0..n {
        let body = call(fx).await;
        assert!(!refused(&body), "call {i} was refused: {body}");
    }
}

/// The edit `scope` makes to set its budget to `limit`.
#[derive(Clone, Copy, Debug)]
enum Scope {
    Key,
    Tool,
    Daily,
}

impl Scope {
    fn set(self, cfg: &mut CostGovernanceConfig, limit: Option<f64>) {
        let budgets = &mut cfg.budgets;
        match (self, limit) {
            (Self::Key, Some(l)) => {
                budgets.per_key.insert(KEY.to_string(), l);
            }
            (Self::Key, None) => {
                budgets.per_key.remove(KEY);
            }
            (Self::Tool, Some(l)) => {
                budgets.per_tool.insert("read".to_string(), l);
            }
            (Self::Tool, None) => {
                budgets.per_tool.remove("read");
            }
            (Self::Daily, limit) => budgets.daily = limit,
        }
    }
}

const SCOPES: [Scope; 3] = [Scope::Key, Scope::Tool, Scope::Daily];

/// T1: a lowered budget refuses the next call the old one allowed, in every
/// scope; today's spend survives the reload.
#[tokio::test]
async fn t1_a_lowered_budget_refuses_the_next_call() {
    for scope in SCOPES {
        crate::test_day::same_utc_day_async(|| async move {
            let fx = fixture(&governance(|c| scope.set(c, Some(10.0)))).await;
            spend(&fx, 6).await;
            reload(&fx, |c| scope.set(c, Some(5.0)));
            let body = call(&fx).await;
            assert!(
                refused(&body),
                "{scope:?}: the old budget of 10 allowed it: {body}"
            );
            assert!(
                (spent(&fx) - 6.0).abs() < 1e-9,
                "{scope:?}: spend {}",
                spent(&fx)
            );
        })
        .await;
    }
}

/// T2: a raised budget admits a call the old one refused.
#[tokio::test]
async fn t2_a_raised_budget_admits_the_next_call() {
    for scope in SCOPES {
        crate::test_day::same_utc_day_async(|| async move {
            let fx = fixture(&governance(|c| scope.set(c, Some(5.0)))).await;
            spend(&fx, 4).await;
            assert!(
                refused(&call(&fx).await),
                "{scope:?}: 5 of 5 projected is refused"
            );
            reload(&fx, |c| scope.set(c, Some(10.0)));
            let body = call(&fx).await;
            assert!(
                !refused(&body),
                "{scope:?}: the new budget of 10 admits it: {body}"
            );
        })
        .await;
    }
}

/// T4: a budget removed by reload no longer refuses.
#[tokio::test]
async fn t4_a_removed_budget_no_longer_refuses() {
    for scope in SCOPES {
        crate::test_day::same_utc_day_async(|| async move {
            let fx = fixture(&governance(|c| scope.set(c, Some(5.0)))).await;
            spend(&fx, 4).await;
            assert!(
                refused(&call(&fx).await),
                "{scope:?}: refused before the reload"
            );
            reload(&fx, |c| scope.set(c, None));
            let body = call(&fx).await;
            assert!(!refused(&body), "{scope:?}: no budget, no refusal: {body}");
        })
        .await;
    }
}

/// T5a: alert rules apply on the next check. $5 of a $10 budget spent, so
/// the next call projects 60 %: a Block rule lowered to 50 % refuses it and
/// the one after; raised to 70 % it returns no action.
#[tokio::test]
async fn t5a_reloaded_alert_rules_apply_on_the_next_check() {
    let block_at = |at_percent| {
        vec![AlertRule {
            at_percent,
            action: AlertAction::Block,
        }]
    };
    crate::test_day::same_utc_day_async(|| async move {
        let fx = fixture(&governance(|c| Scope::Key.set(c, Some(10.0)))).await;
        spend(&fx, 5).await;
        reload(&fx, |c| c.alerts = block_at(50));
        assert!(refused(&call(&fx).await), "Block at 50 % refuses 60 %");
        assert!(
            refused(&call(&fx).await),
            "and every qualifying call after it"
        );
        reload(&fx, |c| c.alerts = block_at(70));
        let body = call(&fx).await;
        assert!(!refused(&body), "Block at 70 % leaves 60 % alone: {body}");
    })
    .await;
}

/// T12a: a request that arrived under a budget of 10 keeps it when a reload
/// lowers it to 5 mid-request; the next request is judged by 5.
#[tokio::test]
async fn t12a_a_request_keeps_the_budget_it_arrived_with_lowered() {
    crate::test_day::same_utc_day_async(|| async move {
        let fx = fixture(&governance(|c| Scope::Key.set(c, Some(10.0)))).await;
        spend(&fx, 6).await;
        seams::after_intake(reload_hook(&fx, |c| Scope::Key.set(c, Some(5.0))));
        let held = call(&fx).await;
        assert!(
            !refused(&held),
            "judged by the budget it arrived with: {held}"
        );
        let next = call(&fx).await;
        assert!(refused(&next), "the next request is judged by 5: {next}");
    })
    .await;
}

/// T12b: the reverse: arrived under 5, raised to 10 mid-request; the held
/// request is refused, the next admitted.
#[tokio::test]
async fn t12b_a_request_keeps_the_budget_it_arrived_with_raised() {
    crate::test_day::same_utc_day_async(|| async move {
        let fx = fixture(&governance(|c| Scope::Key.set(c, Some(5.0)))).await;
        spend(&fx, 4).await;
        seams::after_intake(reload_hook(&fx, |c| Scope::Key.set(c, Some(10.0))));
        let held = call(&fx).await;
        assert!(
            refused(&held),
            "judged by the budget it arrived with: {held}"
        );
        let next = call(&fx).await;
        assert!(!refused(&next), "the next request is judged by 10: {next}");
    })
    .await;
}

/// T15 (regression control, green at the base): a gateway started with
/// governance off has no enforcer, and a reload turning it on judges
/// nothing until a restart.
#[tokio::test]
async fn t15_governance_turned_on_by_reload_judges_nothing() {
    let fx = fixture_built(Answer::Ok, |meta| meta).await;
    reload(&fx, |c| {
        *c = governance(|c| Scope::Key.set(c, Some(1.0)));
    });
    for i in 0..3 {
        let body = call(&fx).await;
        assert!(!refused(&body), "call {i}: no enforcer, no budget: {body}");
    }
}
