// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7597 DIRECT.8: every control meta dispatch runs is run by the
//! per-backend route too, through one shared implementation.
//!
//! Three parts: a parity table over `DISPATCH_CONTROLS` (both routes, same
//! outcome), a small already-shared table, and a structural source check that
//! no control primitive is called outside the shared stage methods.

use std::sync::atomic::Ordering;

use serde_json::{Value, json};

use super::direct_guards_fixture::{Answer, Fx, fixture, post_direct, post_meta_invoke};
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::invoke::dispatch_guards::DISPATCH_CONTROLS;

/// What one call observed: the JSON-RPC error code (if refused) and how many
/// calls reached the backend in total.
#[derive(Debug, PartialEq, Eq)]
struct Seen {
    refused: Option<i64>,
    calls: usize,
}

fn seen(fx: &Fx, body: &Value) -> Seen {
    Seen {
        refused: body["error"]["code"].as_i64(),
        calls: fx.calls.load(Ordering::SeqCst),
    }
}

/// One row: arm the control, then make one call on `route`.
async fn row(control: &str, direct: bool) -> Seen {
    let (answer, arm): (Answer, fn(&mut MetaMcp)) = match control {
        "kill_switch" => (Answer::Ok, |m| m.kill_switch().kill("alpha")),
        "capability_disable" => (Answer::Ok, |m| {
            let cfg = crate::kill_switch::budget::CapabilityErrorBudgetConfig::default();
            for _ in 0..cfg.window_size {
                m.kill_switch()
                    .record_capability_failure("alpha", "read", &cfg);
            }
        }),
        "session_profile" | "cost_budget" | "error_budget" | "response_gates" => {
            return armed_row(control, direct).await;
        }
        other => panic!("no parity row for control `{other}`"),
    };
    let fx = fixture(answer, arm).await;
    let body = call(&fx, direct, None).await;
    seen(&fx, &body)
}

async fn call(fx: &Fx, direct: bool, session: Option<&str>) -> Value {
    if direct {
        post_direct(fx, "alpha", "k-budget", "read", json!({}), None, session)
            .await
            .1
    } else {
        post_meta_invoke(fx, "k-budget", "alpha", "read", json!({}), None, session)
            .await
            .1
    }
}

/// Rows whose arming needs more than a `fn` pointer.
async fn armed_row(control: &str, direct: bool) -> Seen {
    match control {
        "session_profile" => {
            let fx = super::direct_guards_fixture::fixture_built(Answer::Ok, |meta| {
                let meta = meta.with_profile_registry(deny_read_profiles());
                meta.session_profiles()
                    .set_profile("sess-parity", "no-read");
                meta
            })
            .await;
            let body = call(&fx, direct, Some("sess-parity")).await;
            seen(&fx, &body)
        }
        "error_budget" => {
            use crate::kill_switch::budget::{CapabilityErrorBudgetConfig, ErrorBudgetConfig};
            let fx = fixture(Answer::RpcError(-32050), |meta| {
                meta.set_error_budget_config(ErrorBudgetConfig {
                    threshold: 0.5,
                    window_size: 10,
                    min_samples: 4,
                    ..ErrorBudgetConfig::default()
                });
                meta.set_capability_budget_config(CapabilityErrorBudgetConfig {
                    threshold: 2.0,
                    ..CapabilityErrorBudgetConfig::default()
                });
            })
            .await;
            for _ in 0..4 {
                call(&fx, direct, None).await;
            }
            let body = call(&fx, direct, None).await;
            seen(&fx, &body)
        }
        "response_gates" => {
            let fx = fixture(Answer::Ok, |meta| {
                meta.set_response_contract(crate::config::ResponseContractConfig {
                    enabled: true,
                    action_mode: true,
                    fail_closed: true,
                    ..Default::default()
                });
            })
            .await;
            let body = call(&fx, direct, None).await;
            Seen {
                refused: body.get("error").map(|_| 0),
                calls: fx.calls.load(Ordering::SeqCst),
            }
        }
        "cost_budget" => cost_row(direct).await,
        other => panic!("no parity row for control `{other}`"),
    }
}

#[cfg(feature = "cost-governance")]
async fn cost_row(direct: bool) -> Seen {
    use crate::cost_accounting::config::CostGovernanceConfig;
    let mut cfg = CostGovernanceConfig {
        enabled: true,
        ..Default::default()
    };
    cfg.tool_costs.insert("read".to_string(), 1.0);
    cfg.budgets.per_key.insert("k-budget".to_string(), 1.0);
    let registry = std::sync::Arc::new(crate::cost_accounting::registry::CostRegistry::new(&cfg));
    let enforcer = std::sync::Arc::new(crate::cost_accounting::enforcer::BudgetEnforcer::new(
        cfg,
        std::sync::Arc::clone(&registry),
    ));
    let fx = super::direct_guards_fixture::fixture_built(Answer::Ok, move |meta| {
        meta.with_cost_governance(enforcer, registry)
    })
    .await;
    let body = call(&fx, direct, None).await;
    seen(&fx, &body)
}

#[cfg(not(feature = "cost-governance"))]
async fn cost_row(_direct: bool) -> Seen {
    Seen {
        refused: Some(-32003),
        calls: 0,
    }
}

fn deny_read_profiles() -> crate::routing_profile::ProfileRegistry {
    use crate::routing_profile::RoutingProfileConfig;
    let mut configs = std::collections::HashMap::new();
    configs.insert("open".to_string(), RoutingProfileConfig::default());
    configs.insert(
        "no-read".to_string(),
        RoutingProfileConfig {
            deny_tools: Some(vec!["read".to_string()]),
            ..RoutingProfileConfig::default()
        },
    );
    crate::routing_profile::ProfileRegistry::from_config(&configs, "open")
}

/// T8, shared controls: each control in `DISPATCH_CONTROLS` refuses the same
/// way, with the same number of backend calls, on both routes.
#[tokio::test]
async fn t8_every_shared_control_behaves_the_same_on_both_routes() {
    let mut differing = Vec::new();
    for control in DISPATCH_CONTROLS {
        let meta = row(control, false).await;
        let direct = row(control, true).await;
        assert!(
            meta.refused.is_some(),
            "{control}: the meta route must refuse: {meta:?}"
        );
        if meta != direct {
            differing.push(format!("{control}: meta {meta:?}, direct {direct:?}"));
        }
    }
    assert!(
        differing.is_empty(),
        "controls differing between routes: {differing:#?}"
    );
}

/// T8, allowed baseline: with nothing armed, both routes dispatch once.
#[tokio::test]
async fn t8_allowed_baseline_dispatches_once_on_both_routes() {
    for direct in [false, true] {
        let fx = fixture(Answer::Ok, |_| {}).await;
        let body = call(&fx, direct, None).await;
        assert!(body.get("result").is_some(), "direct={direct}: {body}");
        assert_eq!(fx.calls.load(Ordering::SeqCst), 1, "direct={direct}");
    }
}

/// T8, already-shared controls (guard): a tool name the gateway refuses to
/// route is refused on both routes without reaching the backend.
#[tokio::test]
async fn t8_already_shared_tool_name_validation_matches() {
    for direct in [false, true] {
        let fx = fixture(Answer::Ok, |_| {}).await;
        let body = if direct {
            post_direct(&fx, "alpha", "k-std", "bad name;", json!({}), None, None)
                .await
                .1
        } else {
            post_meta_invoke(&fx, "k-std", "alpha", "bad name;", json!({}), None, None)
                .await
                .1
        };
        assert!(body.get("error").is_some(), "direct={direct}: {body}");
        assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "direct={direct}");
    }
}

/// Body of the first `fn <name>` in `src`, by brace matching from its opening
/// `{`. Good enough for the functions named below; panics if one is missing, so
/// a rename fails loudly instead of checking nothing.
fn fn_body<'a>(src: &'a str, name: &str) -> &'a str {
    let at = src
        .find(&format!("fn {name}("))
        .unwrap_or_else(|| panic!("fn {name} not found"));
    let open = at + src[at..].find('{').expect("fn has a body");
    let mut depth = 0usize;
    for (i, c) in src[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &src[open..=open + i];
                }
            }
            _ => {}
        }
    }
    panic!("fn {name} body is unbalanced")
}

/// Control primitives that may run only inside the shared stage methods.
const BANNED: &[&str] = &[
    "kill_switch.is_killed",
    "is_capability_disabled",
    "record_error_budget",
    "enforcer.check",
    "enforcer.record_spend",
    ".admit_spend(",
    "apply_response_gates",
];

/// `active_profile(` followed, across whitespace and newlines, by `.check`.
fn has_profile_check(body: &str) -> bool {
    body.match_indices("active_profile(").any(|(i, _)| {
        let rest = &body[i..];
        let close = rest.find(')').unwrap_or(0);
        rest[close + 1..].trim_start().starts_with(".check")
    })
}

/// T8, structure: no route calls a control primitive directly; each goes
/// through the one stage method. A control added inline on one route, or left
/// behind at its old site, fails here.
#[test]
fn t8_no_control_primitive_runs_outside_the_shared_stages() {
    let invoke = include_str!("../meta_mcp/invoke.rs");
    let handlers = include_str!("backend_handlers.rs");
    let guards = include_str!("direct_guards.rs");
    let sites = [
        ("invoke_tool_traced", fn_body(invoke, "invoke_tool_traced")),
        (
            "check_invocation_policy",
            fn_body(invoke, "check_invocation_policy"),
        ),
        ("accounted_dispatch", fn_body(invoke, "accounted_dispatch")),
        (
            "backend_handler_inner",
            fn_body(handlers, "backend_handler_inner"),
        ),
        ("direct_guards.rs", guards),
    ];
    let mut found = Vec::new();
    for (site, body) in sites {
        for primitive in BANNED {
            if body.contains(primitive) {
                found.push(format!("{site}: {primitive}"));
            }
        }
        if has_profile_check(body) {
            found.push(format!("{site}: active_profile(..).check"));
        }
    }
    assert!(
        found.is_empty(),
        "control primitives outside the shared stages: {found:#?}"
    );
}

/// T3c, source half: the bridged round admits spend through the shared stage,
/// not the old inline call.
#[test]
fn t3c_the_bridged_round_admits_spend_through_the_shared_stage() {
    let invoke = include_str!("../meta_mcp/invoke.rs");
    let at = invoke
        .find("impl crate::gateway::input_bridge::BackendInvoker for BridgeDispatcher")
        .expect("bridge dispatcher impl");
    let body = fn_body(&invoke[at..], "invoke");
    assert!(
        body.contains("admit_spend_for"),
        "bridged round skips admit_spend_for"
    );
    assert!(
        !body.contains(".admit_spend("),
        "bridged round still calls admit_spend"
    );
}
