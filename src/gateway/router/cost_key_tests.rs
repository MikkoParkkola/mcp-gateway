// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8507: per-key spend and budgets belong to the API key, never to a
//! display name another credential happens to carry.
//!
//! `budgets.per_key` is "per-API-key" (config.rs), and the cost record names
//! its key "`None` for anonymous/bearer". The static bearer is named `bearer`,
//! so an API key named `bearer` would share its spend counter and budget.
//! Cost governance at 1.0 a `read`, the key `bearer` holding 1.5.

#![cfg(feature = "cost-governance")]

use serde_json::{Value, json};

use super::direct_guards_fixture::{
    Answer, BEARER_SECRET, Fx, fixture_with_bearer, post_direct, post_meta_invoke,
};
use crate::gateway::meta_mcp::MetaMcp;

fn budget(meta: MetaMcp) -> MetaMcp {
    use crate::cost_accounting::config::CostGovernanceConfig;
    let mut cfg = CostGovernanceConfig {
        enabled: true,
        ..Default::default()
    };
    cfg.tool_costs.insert("read".to_string(), 1.0);
    cfg.budgets.per_key.insert("bearer".to_string(), 1.5);
    let registry = std::sync::Arc::new(crate::cost_accounting::registry::CostRegistry::new(&cfg));
    let enforcer = std::sync::Arc::new(crate::cost_accounting::enforcer::BudgetEnforcer::new(
        cfg,
        std::sync::Arc::clone(&registry),
    ));
    meta.with_cost_governance(enforcer, registry)
}

/// The spend refusal itself (-32003, "daily budget exceeded"), so a refusal
/// for any other reason cannot pass for it.
fn refused_for_budget(body: &Value) -> bool {
    body.pointer("/error/code") == Some(&json!(-32003))
        && body
            .pointer("/error/message")
            .and_then(Value::as_str)
            .is_some_and(|m| m.contains("budget exceeded"))
}

/// Answered: no error, and not an `isError` tool result.
fn answered(body: &Value) -> bool {
    body.get("error").is_none() && body.pointer("/result/isError") != Some(&json!(true))
}

/// The two routes a call is charged on: the direct route and the meta route.
async fn read(fx: &Fx, route: &str, token: &str) -> Value {
    if route == "direct" {
        post_direct(fx, "alpha", token, "read", json!({}), None, None)
            .await
            .1
    } else {
        post_meta_invoke(fx, token, "alpha", "read", json!({}), None, None)
            .await
            .1
    }
}

/// The bearer's call is not charged to the key named `bearer`: after it, the
/// key still has its own 1.5, so its first call is paid and its second is
/// refused by its own budget.
#[tokio::test]
async fn the_bearer_does_not_spend_the_budget_of_a_key_named_bearer() {
    for route in ["direct", "meta"] {
        let fx = fixture_with_bearer(Answer::Ok, budget).await;
        let by_bearer = read(&fx, route, BEARER_SECRET).await;
        assert!(
            answered(&by_bearer),
            "{route}: the bearer's own call: {by_bearer}"
        );

        let first = read(&fx, route, "bearer").await;
        assert!(
            answered(&first),
            "{route}: the key's first call is within its own 1.5: {first}"
        );
        let second = read(&fx, route, "bearer").await;
        assert!(
            refused_for_budget(&second),
            "{route}: the key's second call exceeds its own 1.5: {second}"
        );
    }
}
