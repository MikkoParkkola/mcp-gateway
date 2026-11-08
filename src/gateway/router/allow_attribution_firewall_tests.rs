// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A call the firewall let through names the rule that did, on
//! `gateway_invoke`: a rule letting through a finding whose default blocks
//! wins over any other, whatever the enforcement verdict was, and only the
//! arguments' scan is read for it.

use serde_json::{Value, json};

use super::super::rule_ids::{firewall_id, tool_policy_id};
use super::super::{Answer, Logged, Route, fixture, injected, injected_answer, invocations};
use super::{delivered, edited, on};
use crate::config::Config;
use crate::gateway::router::direct_guards_fixture::send;
use crate::security::firewall::{FirewallAction, FirewallRule, ScanType};

/// The shell injection (High, blocks by default) beside a SQL injection
/// (Medium, warns by default) in one call's arguments.
fn shell_and_sql() -> Value {
    // One declared parameter carries both: the fixture tool takes only `cmd`.
    let mut args = injected();
    let cmd = format!("{} ' OR 1=1", args["cmd"].as_str().unwrap_or_default());
    args["cmd"] = json!(cmd);
    args
}

/// A rule on `read` with `action` for `scan`, cut from the fixture's rule.
fn read_rule(fx: &Logged, action: FirewallAction, scan: &[ScanType]) -> FirewallRule {
    let base = fx
        .state
        .live_config
        .get()
        .security
        .firewall
        .rules
        .first()
        .cloned()
        .expect("the fixture's rule");
    FirewallRule {
        tool_match: "read".to_owned(),
        action,
        scan: scan.to_vec(),
        ..base
    }
}

fn with_rules(fx: &Logged, rules: Vec<FirewallRule>) -> Config {
    edited(fx, |c| c.security.firewall.rules = rules)
}

/// `gateway_invoke` of `read` with `args` under `rules`: asserted delivered,
/// returns the recorded `(kind, rule_id)`.
async fn allowed_under(fx: &Logged, rules: Vec<FirewallRule>, args: Value) -> (Value, Value) {
    let config = with_rules(fx, rules);
    let got = on(fx, Route::MetaInvoke, args, &config).await;
    assert!(delivered(&got), "premise, delivered: {got:?}");
    (got.kind, got.rule)
}

fn by(fx: &Logged, rule: &FirewallRule) -> (Value, Value) {
    (json!("firewall"), json!(firewall_id(fx, rule).as_str()))
}

/// R5 (ATTR.2). The shell finding softened to allow beside an independent
/// SQL finding: the call warns (the SQL default) and the softener is named.
/// Kills M6 (provenance from the enforcement resolver).
#[tokio::test(flavor = "current_thread")]
async fn softener_with_independent_warn() {
    let fx = fixture(Answer::Ok, Some(FirewallAction::Warn)).await;
    let softener = read_rule(&fx, FirewallAction::Allow, &[ScanType::ShellInjection]);
    let got = allowed_under(&fx, vec![softener.clone()], shell_and_sql()).await;
    assert_eq!(got, by(&fx, &softener));
}

/// R6 (ATTR.2). A warn-to-allow rule listed before the softener: the
/// softener is named. Kills M6.
#[tokio::test(flavor = "current_thread")]
async fn warn_to_allow_listed_first() {
    let fx = fixture(Answer::Ok, Some(FirewallAction::Warn)).await;
    let warn_to_allow = read_rule(&fx, FirewallAction::Allow, &[ScanType::SqlInjection]);
    let softener = read_rule(&fx, FirewallAction::Allow, &[ScanType::ShellInjection]);
    let got = allowed_under(&fx, vec![warn_to_allow, softener.clone()], shell_and_sql()).await;
    assert_eq!(got, by(&fx, &softener));
}

/// R9 (ATTR.2). A block-to-warn rule alone: the call warns through and the
/// rule is named. Kills M5 (block-to-warn not attributed).
#[tokio::test(flavor = "current_thread")]
async fn block_to_warn_alone() {
    let fx = fixture(Answer::Ok, Some(FirewallAction::Warn)).await;
    let to_warn = read_rule(&fx, FirewallAction::Warn, &[ScanType::ShellInjection]);
    let got = allowed_under(&fx, vec![to_warn.clone()], injected()).await;
    assert_eq!(got, by(&fx, &to_warn));
}

/// R11 (ATTR.2). A SQL-only allow beside the shell finding's own block: the
/// call is refused by the firewall before the backend, and the allowing
/// rule is not named. A pin.
#[tokio::test(flavor = "current_thread")]
async fn independent_block_still_blocks() {
    let fx = fixture(Answer::Ok, Some(FirewallAction::Warn)).await;
    let sql_allow = read_rule(&fx, FirewallAction::Allow, &[ScanType::SqlInjection]);
    let config = with_rules(&fx, vec![sql_allow.clone()]);
    let got = on(&fx, Route::MetaInvoke, shell_and_sql(), &config).await;
    assert!(
        got.refused && got.calls == 0 && got.kind == "firewall",
        "{got:?}"
    );
    assert_ne!(got.rule, json!(firewall_id(&fx, &sql_allow).as_str()));
}

/// R12 (ATTR.1). Non-matching rules before and after the softener: the
/// matched one is named.
#[tokio::test(flavor = "current_thread")]
async fn firewall_rule_matched_not_first() {
    let fx = fixture(Answer::Ok, Some(FirewallAction::Warn)).await;
    let mut before = read_rule(&fx, FirewallAction::Allow, &[]);
    before.tool_match = "never_called".to_owned();
    let matched = read_rule(&fx, FirewallAction::Allow, &[ScanType::ShellInjection]);
    let after = read_rule(&fx, FirewallAction::Allow, &[ScanType::Credentials]);
    let got = allowed_under(&fx, vec![before, matched.clone(), after], injected()).await;
    assert_eq!(got, by(&fx, &matched));
}

/// R13 (ATTR.2). A bridge retry whose answers alone carry the softened
/// finding: provenance is read from the arguments' scan only, so the record
/// stays `default_allow`. Kills M7 (answers' scan read). The grant half of
/// the design's row needs a capability that asks a question, which no
/// fixture serves.
#[tokio::test(flavor = "current_thread")]
async fn answers_only_softener_names_nothing() {
    let fx = fixture(Answer::AskAlways, Some(FirewallAction::Warn)).await;
    let softener = read_rule(&fx, FirewallAction::Allow, &[ScanType::ShellInjection]);
    let config = with_rules(&fx, vec![softener]);
    let got = on(&fx, Route::MetaRetry, injected_answer(), &config).await;
    // The question's own call, then the retry's.
    assert!(
        !got.refused && got.calls == 2,
        "premise, delivered: {got:?}"
    );
    assert_eq!((got.kind, got.rule), (json!("default_allow"), Value::Null));
}

/// R20 (ATTR.1). Two `gateway_execute` chain steps on `read` with different
/// arguments: the allow entry admits the first, and the second also carries a
/// shell injection a firewall rule softens. Each step's record names its own
/// decider, so neither inherits the other's. Kills M11 (notes kept in a
/// request-wide cell).
#[tokio::test(flavor = "current_thread")]
async fn chain_steps_own_allow() {
    let fx = fixture(Answer::Ok, Some(FirewallAction::Warn)).await;
    let softener = read_rule(&fx, FirewallAction::Allow, &[ScanType::ShellInjection]);
    let config = edited(&fx, |c| {
        c.security.firewall.rules = vec![softener.clone()];
        c.security.tool_policy.enabled = true;
        c.security.tool_policy.allow = vec!["alpha:read".to_owned()];
    });
    fx.state.live_config.set(config);
    let (recorded, sent) = (
        invocations(&fx).await.len(),
        fx.calls.load(std::sync::atomic::Ordering::SeqCst),
    );
    let params = json!({"name": "gateway_execute", "arguments": {"chain": [
        {"tool": "alpha:read", "arguments": {"cmd": "x"}},
        {"tool": "alpha:read", "arguments": injected()},
    ]}});
    let (_, body) = send(&fx, "/mcp", "k-std", "tools/call", params, None).await;
    assert_eq!(
        fx.calls.load(std::sync::atomic::Ordering::SeqCst) - sent,
        2,
        "premise: both steps reached the backend: {body}"
    );
    let rows = invocations(&fx).await;
    let decided: Vec<(Value, Value)> = rows[recorded..]
        .iter()
        .map(|r| {
            (
                r["decision"]["kind"].clone(),
                r["decision"]["rule_id"].clone(),
            )
        })
        .collect();
    let entry = tool_policy_id(&fx, "allow", "alpha:read");
    assert_eq!(
        decided,
        vec![
            (json!("tool_policy"), json!(entry.as_str())),
            by(&fx, &softener),
        ],
        "one record per step, each naming its own decider: {body}"
    );
}
