// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Each recording site names the configured rule that decided: the request
//! firewall at the route stage (`gateway_invoke`), at the dispatch rescan
//! (a continuation's retry) and on the direct route; the tool policy's
//! withheld refusal on the direct and meta routes. The delivered error never
//! carries the id.

use serde_json::json;

use super::{
    Answer, Fx, Logged, Outcome, Route, call, configured, fixture, injected, injected_answer,
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
    // The retry's injection rides in a question's answer, which only the
    // dispatch rescan reads; the backend must ask for there to be a retry.
    let (answer, args) = match route {
        Route::MetaRetry => (Answer::AskAlways, injected_answer()),
        Route::Direct | Route::MetaInvoke => (Answer::Ok, injected()),
    };
    let fx: Logged = fixture(answer, Some(FirewallAction::Block)).await;
    let config = configured(&fx, two_rules);
    let deciding = config.security.firewall.rules[1].clone();
    let got = call(&fx, (route, args), &config, &config).await;
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

/// A backend answer carrying a credential the response firewall finds, built
/// from pieces so no literal token sits in the source.
fn leaky_answer() -> serde_json::Value {
    let token = ["gh", "p_", "abcdefghijklmnopqrstuvwxyz1234567890"].concat();
    json!({"content": [{"type": "text", "text": format!("token {token}")}], "isError": false})
}

/// Two rules for `read`: `shell` scans the request for shell injection,
/// `credentials` scans the answer for credentials.
fn split_rules(c: &mut Config, shell: FirewallAction, credentials: FirewallAction) {
    let base = c
        .security
        .firewall
        .rules
        .first()
        .cloned()
        .expect("the fixture's rule");
    let with = |action, scan| FirewallRule {
        action,
        scan: vec![scan],
        ..base.clone()
    };
    c.security.firewall.rules = vec![
        with(shell, crate::security::firewall::ScanType::ShellInjection),
        with(
            credentials,
            crate::security::firewall::ScanType::Credentials,
        ),
    ];
}

/// The request's shell rule warns, so the call goes on; the answer's
/// credential rule blocks.
fn request_warns_answer_blocks(c: &mut Config) {
    split_rules(c, FirewallAction::Warn, FirewallAction::Block);
}

/// Both rules warn: neither side refuses.
fn both_warn(c: &mut Config) {
    split_rules(c, FirewallAction::Warn, FirewallAction::Warn);
}

/// The request's shell rule blocks: the control that the request carries a
/// finding a rule decides.
fn request_blocks(c: &mut Config) {
    split_rules(c, FirewallAction::Block, FirewallAction::Block);
}

/// A response-firewall block names no rule, though the request beside it had
/// a finding a configured rule decided: response attribution is not
/// recorded, so the response verdict cannot borrow the request rule's id.
/// Judged under one generation with no reload, and under a pinned generation
/// that differs from the published one (the stronger answer policy decides).
async fn response_block(route: Route) {
    let fx = fixture(Answer::Built(leaky_answer), Some(FirewallAction::Block)).await;
    let blocks = configured(&fx, request_warns_answer_blocks);
    let warns = configured(&fx, both_warn);
    // Control: the request's shell rule matches this request and is named
    // when it decides.
    let control = configured(&fx, request_blocks);
    let got = super::call_as(&fx, (route, injected()), &control, None).await;
    let shell = firewall_id(&fx, &control.security.firewall.rules[0]);
    assert!(got.refused && got.calls == 0, "{route:?}: control: {got:?}");
    assert_eq!(got.rule, json!(shell.as_str()), "{route:?}: control");
    let shell = firewall_id(&fx, &blocks.security.firewall.rules[0]);
    let cases = [
        (&blocks, None),
        (&blocks, Some(&warns)),
        (&warns, Some(&blocks)),
    ];
    for (pinned, current) in cases {
        let got = super::call_as(&fx, (route, injected()), pinned, current).await;
        let case = (route, current.is_some());
        assert!(
            got.refused && got.calls == 1 && got.kind == "firewall",
            "{case:?}: premise, the sent request's answer is blocked: {got:?}"
        );
        assert!(got.rule.is_null(), "{case:?}: {got:?}");
        let hex = shell.as_str().trim_start_matches("firewall:");
        assert!(!delivered(&got).contains(hex), "{case:?}: {got:?}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_response_firewall_block_records_no_rule_on_gateway_invoke() {
    response_block(Route::MetaInvoke).await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_response_firewall_block_records_no_rule_on_the_direct_route() {
    response_block(Route::Direct).await;
}

/// A stored task read back after a reload whose tool policy denies its tool
/// is refused at the `tasks/get` (register row 425's designed path): the
/// refusal's message carries no rule id, and the read's record names the
/// deny entry.
#[tokio::test(flavor = "current_thread")]
async fn a_task_refused_by_the_tool_policy_delivers_no_rule_id() {
    let fx = fixture(Answer::Ok, None).await;
    let denies = configured(&fx, key_admits_policy_denies);
    let (live, published) = (std::sync::Arc::clone(&fx.state.live_config), denies.clone());
    super::seams::before_task_dispatch(move || live.set(published));
    let got = super::task_with(&fx, "rule-id-task", json!({})).await;
    assert!(
        got.get("error").is_some() && got.get("result").is_none(),
        "premise: the tasks/get read is refused: {got}"
    );
    let expected = tool_policy_id(&fx, "deny", "alpha:read");
    let hex = expected.as_str().trim_start_matches("tool_policy:");
    assert!(!got.to_string().contains(hex), "{got}");
    // The read is the last request, so its record is the last one: a record
    // the worker's own refusal wrote cannot stand in for it.
    let recorded = super::invocations(&fx).await;
    let read = recorded.last().expect("the read's record");
    assert_eq!(
        (&read["decision"]["kind"], &read["decision"]["rule_id"]),
        (&json!("tool_policy"), &json!(expected.as_str())),
        "the read's record names the deny entry: {recorded:?}"
    );
}
