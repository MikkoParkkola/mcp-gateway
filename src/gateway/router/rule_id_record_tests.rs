// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Each recording site names the configured rule that decided: the request
//! firewall at the route stage (`gateway_invoke`), at the dispatch rescan
//! (a continuation's retry) and on the direct route; the tool policy's
//! withheld refusal on the direct and meta routes. The delivered error never
//! carries the id.

use serde_json::json;

use super::{
    Answer, Fx, Logged, Outcome, Route, call, configured, fixture, injected,
    key_admits_policy_denies,
};
use crate::config::Config;
use crate::security::firewall::{FirewallAction, FirewallRule};
use crate::security::rule_id::RuleId;

/// The id `fx` records for `rule`: its serde bytes under the running key.
fn firewall_id(fx: &Fx, rule: &FirewallRule) -> RuleId {
    let key = fx
        .state
        .live_config
        .generation()
        .auth()
        .record_key()
        .rule_id_key();
    RuleId::of(
        "firewall",
        &key,
        &serde_json::to_vec(rule).expect("serialises"),
    )
}

fn tool_policy_id(fx: &Fx, list: &str, pattern: &str) -> RuleId {
    let key = fx
        .state
        .live_config
        .generation()
        .auth()
        .record_key()
        .rule_id_key();
    let bytes = serde_json::to_vec(&(list, pattern)).expect("serialises");
    RuleId::of("tool_policy", &key, &bytes)
}

/// The fixture's blocking rule preceded by one that cannot match this call,
/// so a site naming the wrong rule, or the first rule, is told apart.
fn two_rules(c: &mut Config) {
    let deciding = c
        .security
        .firewall
        .rules
        .first()
        .cloned()
        .expect("the fixture's rule");
    let mut other = deciding.clone();
    other.tool_match = "never_called".to_string();
    let mut deciding = deciding;
    deciding.action = FirewallAction::Block;
    c.security.firewall.rules = vec![other, deciding];
}

/// The answer's text, whole, as one string.
fn delivered(outcome: &Outcome) -> String {
    format!("{}{}", outcome.code, outcome.message)
}

async fn firewall_site(route: Route) {
    let fx: Logged = fixture(Answer::Ok, Some(FirewallAction::Block)).await;
    let config = configured(&fx, two_rules);
    let deciding = config.security.firewall.rules[1].clone();
    let got = call(&fx, (route, injected()), &config, &config).await;
    let expected = firewall_id(&fx, &deciding);
    assert!(got.refused && got.kind == "firewall", "{route:?}: {got:?}");
    assert_eq!(got.rule, json!(expected.as_str()), "{route:?}");
    let hex = expected.as_str().trim_start_matches("firewall:");
    assert!(
        !delivered(&got).contains(hex) && !delivered(&got).contains("rule_id"),
        "{route:?}: the delivered refusal names the rule: {got:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn the_route_stage_firewall_refusal_records_its_rule_id() {
    firewall_site(Route::MetaInvoke).await;
}

#[tokio::test(flavor = "current_thread")]
async fn the_dispatch_rescan_firewall_refusal_records_its_rule_id() {
    firewall_site(Route::MetaRetry).await;
}

#[tokio::test(flavor = "current_thread")]
async fn the_direct_route_firewall_refusal_records_its_rule_id() {
    firewall_site(Route::Direct).await;
}

async fn withheld_tool_policy(route: Route) {
    let fx = fixture(Answer::Ok, None).await;
    let config = configured(&fx, key_admits_policy_denies);
    let got = call(&fx, (route, json!({"cmd": "x"})), &config, &config).await;
    let expected = tool_policy_id(&fx, "deny", "alpha:read");
    assert!(
        got.refused && got.kind == "tool_policy",
        "{route:?}: {got:?}"
    );
    assert_eq!(got.rule, json!(expected.as_str()), "{route:?}");
    let hex = expected.as_str().trim_start_matches("tool_policy:");
    assert!(!delivered(&got).contains(hex), "{route:?}: {got:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn a_withheld_tool_policy_refusal_keeps_its_rule_id_on_the_direct_route() {
    withheld_tool_policy(Route::Direct).await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_withheld_tool_policy_refusal_keeps_its_rule_id_on_gateway_invoke() {
    withheld_tool_policy(Route::MetaInvoke).await;
}
