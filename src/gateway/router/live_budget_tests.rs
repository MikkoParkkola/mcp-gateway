// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Cost-governance budgets and alerts apply on reload (ADR-023, U19 PR3a):
//! the next call is judged by the published budgets, today's spend survives
//! the swap, and a request keeps the budgets it arrived with.

use std::sync::Arc;

use serde_json::{Value, json};

pub(super) use super::direct_guards_fixture::Fx;
use super::direct_guards_fixture::{Answer, fixture_built, post_meta_invoke};
use crate::cost_accounting::config::{AlertAction, AlertRule, CostGovernanceConfig};
use crate::cost_accounting::enforcer::BudgetEnforcer;
use crate::cost_accounting::enforcer::crossings::BudgetCrossing;
use crate::cost_accounting::registry::CostRegistry;
use crate::gateway::meta_mcp::invoke::dispatch_guards::{BackendCall, DirectOutcome};
use crate::gateway::meta_mcp::visible::seams;

pub(super) const KEY: &str = "k-budget";

/// Governance on, `read` at 1.0 a call, the default alert tiers, and the
/// budgets `budgets` sets.
pub(super) fn governance(budgets: impl FnOnce(&mut CostGovernanceConfig)) -> CostGovernanceConfig {
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
pub(super) async fn fixture(cfg: &CostGovernanceConfig) -> Fx {
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
pub(super) fn reload(fx: &Fx, edit: impl FnOnce(&mut CostGovernanceConfig)) {
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
pub(super) fn spent(fx: &Fx) -> f64 {
    let enforcer = fx.state.meta_mcp.budget_enforcer.as_ref().expect("armed");
    enforcer
        .snapshot()
        .key_daily
        .get(KEY)
        .copied()
        .unwrap_or(0.0)
}

/// `n` admitted calls; each must pass.
pub(super) async fn spend(fx: &Fx, n: usize) {
    for i in 0..n {
        let body = call(fx).await;
        assert!(!refused(&body), "call {i} was refused: {body}");
    }
}

/// The edit `scope` makes to set its budget to `limit`.
#[derive(Clone, Copy, Debug)]
pub(super) enum Scope {
    Key,
    Tool,
    Daily,
}

impl Scope {
    pub(super) fn set(self, cfg: &mut CostGovernanceConfig, limit: Option<f64>) {
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

/// A `Block` rule at `at_percent`, the only alert rule.
fn block_at(at_percent: u32) -> Vec<AlertRule> {
    vec![AlertRule {
        at_percent,
        action: AlertAction::Block,
    }]
}

/// T12c: only a `Block` rule differs between N and N+1. A request that
/// arrived with no rule keeps judging without one when a reload adds it
/// mid-request; the next request meets it.
#[tokio::test]
async fn t12c_a_request_keeps_the_alert_rules_it_arrived_with() {
    crate::test_day::same_utc_day_async(|| async move {
        let mut cfg = governance(|c| Scope::Key.set(c, Some(10.0)));
        cfg.alerts.clear();
        let fx = fixture(&cfg).await;
        spend(&fx, 5).await;
        seams::after_intake(reload_hook(&fx, |c| c.alerts = block_at(50)));
        let held = call(&fx).await;
        assert!(!refused(&held), "N has no Block rule: {held}");
        let next = call(&fx).await;
        assert!(refused(&next), "N+1 blocks at 50 %: {next}");
    })
    .await;
}

/// T12c, reversed: arrived under a `Block` at 50 %, the rule removed
/// mid-request; the held request is refused, the next admitted.
#[tokio::test]
async fn t12c_a_request_keeps_the_blocking_rule_it_arrived_with() {
    crate::test_day::same_utc_day_async(|| async move {
        let mut cfg = governance(|c| Scope::Key.set(c, Some(10.0)));
        cfg.alerts = block_at(50);
        let fx = fixture(&cfg).await;
        spend(&fx, 4).await;
        seams::after_intake(reload_hook(&fx, |c| c.alerts.clear()));
        let held = call(&fx).await;
        assert!(refused(&held), "N blocks at 50 %: {held}");
        let next = call(&fx).await;
        assert!(!refused(&next), "N+1 has no rule: {next}");
    })
    .await;
}

/// A `read` call as the direct route builds it, pinned to `generation`.
pub(super) fn backend_call(
    generation: Option<&crate::config_reload::Generation>,
) -> BackendCall<'_> {
    BackendCall {
        server: "alpha",
        tool: "read",
        session_id: None,
        api_key_name: None,
        cost_key: None,
        trace_id: "",
        caller_key: None,
        generation,
    }
}

/// Crossings the enforcer reports from now on, as `(scope, percent)`.
fn watch_crossings(fx: &Fx) -> Arc<std::sync::Mutex<Vec<(String, u8)>>> {
    let seen: Arc<std::sync::Mutex<Vec<(String, u8)>>> = Arc::default();
    let sink = Arc::clone(&seen);
    let enforcer = fx.state.meta_mcp.budget_enforcer.as_ref().expect("armed");
    enforcer.observe(Arc::new(move |c: BudgetCrossing| {
        sink.lock().unwrap().push((c.scope, c.percent));
    }));
    seen
}

/// T12d: $7.50 spent. A call admitted under N (daily budget 10) settles $1
/// after N+1 (daily budget 20) publishes. $8.50 crosses N's 80 % mark and no
/// mark of N+1's (42.5 %), and the crossing is N's alone.
#[tokio::test]
async fn t12d_a_delayed_settlement_reports_the_crossings_of_its_own_budget() {
    crate::test_day::same_utc_day_async(|| async move {
        let fx = fixture(&governance(|c| c.budgets.daily = Some(10.0))).await;
        let meta = &fx.state.meta_mcp;
        meta.budget_enforcer
            .as_ref()
            .expect("armed")
            .record_spend("other", None, 7.5);
        let seen = watch_crossings(&fx);
        let admitted_under = fx.state.live_config.generation();
        let call = backend_call(Some(&admitted_under));
        let admission = meta.admit_spend_for(&call).expect("fits under N");
        reload(&fx, |c| c.budgets.daily = Some(20.0));
        meta.account_dispatch(&call, DirectOutcome::Success { spend: true }, &admission);
        assert_eq!(*seen.lock().unwrap(), [("global".to_owned(), 80)]);
    })
    .await;
}

/// T17: spent $0; a held call reserves $4; a reload sets the daily budget to
/// 5; a competing $2 call is refused (6 > 5); settling the held call charges
/// $4 exactly once.
#[tokio::test]
async fn t17_a_reservation_survives_the_reload_and_settles_once() {
    crate::test_day::same_utc_day_async(|| async move {
        let cfg = governance(|c| {
            c.budgets.daily = Some(10.0);
            c.tool_costs.insert("read".to_owned(), 4.0);
            c.tool_costs.insert("write".to_owned(), 2.0);
        });
        let fx = fixture(&cfg).await;
        let meta = &fx.state.meta_mcp;
        let before = fx.state.live_config.generation();
        let held = backend_call(Some(&before));
        let admission = meta.admit_spend_for(&held).expect("4 fits under 10");
        reload(&fx, |c| c.budgets.daily = Some(5.0));
        let after = fx.state.live_config.generation();
        let competing = BackendCall {
            tool: "write",
            ..backend_call(Some(&after))
        };
        assert!(
            meta.admit_spend_for(&competing).is_err(),
            "the held 4 counts against the new budget: 4 + 2 > 5"
        );
        meta.account_dispatch(&held, DirectOutcome::Success { spend: true }, &admission);
        let enforcer = meta.budget_enforcer.as_ref().expect("armed");
        assert!((enforcer.snapshot().global_daily_usd - 4.0).abs() < 1e-9);
    })
    .await;
}

/// A call with no pin judges with the live config's current generation.
#[tokio::test]
async fn an_unpinned_call_judges_with_the_live_generation() {
    crate::test_day::same_utc_day_async(|| async move {
        let fx = fixture(&governance(|c| c.budgets.daily = Some(10.0))).await;
        let meta = &fx.state.meta_mcp;
        meta.set_live_config(Arc::clone(&fx.state.live_config));
        meta.budget_enforcer
            .as_ref()
            .expect("armed")
            .record_spend("other", None, 6.0);
        assert!(meta.admit_spend_for(&backend_call(None)).is_ok());
        reload(&fx, |c| c.budgets.daily = Some(5.0));
        assert!(
            meta.admit_spend_for(&backend_call(None)).is_err(),
            "7 of the live budget 5"
        );
    })
    .await;
}
