// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An allowed call's record names the check that allowed it: the mTLS rule
//! that matched, the allow-list entry, the firewall rule that let a finding
//! through. Each row asserts the outcome first, then the kind and the exact
//! keyed id of the deciding rule, computed from that rule.

use serde_json::{Value, json};

use super::mtls_rule_ids::{call_cert, enabled, rule_key, with_policy};
use super::rule_ids::tool_policy_id;
use super::{Answer, Logged, Outcome, Route, call_as, fixture, invocations};
use crate::config::Config;
use crate::mtls::access_control::rule_id_tests::{mtls_id, rule};

#[path = "allow_attribution_firewall_tests.rs"]
mod firewall;
#[path = "allow_attribution_grant_tests.rs"]
mod grants;

/// The fixture's live config with `edit` applied.
fn edited(fx: &Logged, edit: impl FnOnce(&mut Config)) -> Config {
    let mut config = (*fx.state.live_config.get()).clone();
    edit(&mut config);
    config
}

/// `alpha:read` with `args` through `route`, under `config` and no reload.
async fn on(fx: &Logged, route: Route, args: Value, config: &Config) -> Outcome {
    Box::pin(call_as(fx, (route, args), config, None)).await
}

/// Delivered, with one backend call.
fn delivered(got: &Outcome) -> bool {
    !got.refused && got.calls == 1
}

/// Rules A (another subject), B and C (both `agent-a`, B first): only the
/// first rule matching the certificate decides.
fn agent_rules() -> Vec<crate::mtls::config::PolicyRuleConfig> {
    vec![
        rule("nobody", &["*"], &[]),
        rule("agent-a", &["read"], &[]),
        rule("agent-a", &["read", "write"], &[]),
    ]
}

async fn mtls_first_matching_rule(route: Route) {
    let rules = agent_rules();
    let fx = with_policy(enabled(rules.clone())).await;
    let expected = mtls_id(&rule_key(&fx), &rules[1]);
    assert_ne!(
        expected,
        mtls_id(&rule_key(&fx), &rules[2]),
        "premise: B and C have distinct ids"
    );
    let got = Box::pin(call_cert(&fx, route, "read", Some("agent-a"))).await;
    assert!(delivered(&got), "{route:?}: premise, allowed: {got:?}");
    assert_eq!(
        (got.kind, got.rule),
        (json!("mtls"), json!(expected.as_str())),
        "{route:?}"
    );
}

/// R3 (ATTR.1). The certificate matches B and C; B, the first, is named.
/// Kills a collector naming the last matching rule.
#[tokio::test(flavor = "current_thread")]
async fn mtls_first_matching_rule_on_gateway_invoke() {
    mtls_first_matching_rule(Route::MetaInvoke).await;
}

/// R28 (ATTR.1). R3 on the direct route.
#[tokio::test(flavor = "current_thread")]
async fn mtls_first_matching_rule_on_the_direct_route() {
    mtls_first_matching_rule(Route::Direct).await;
}

fn allow_entries(c: &mut Config) {
    c.security.tool_policy.enabled = true;
    c.security.tool_policy.allow = ["beta:other", "alpha:read", "alpha:*"]
        .map(str::to_owned)
        .to_vec();
}

async fn allow_entry_matched(route: Route) {
    let fx = fixture(Answer::Ok, None).await;
    let config = edited(&fx, allow_entries);
    let got = on(&fx, route, json!({"cmd": "x"}), &config).await;
    let expected = tool_policy_id(&fx, "allow", "alpha:read");
    assert!(delivered(&got), "{route:?}: premise, allowed: {got:?}");
    assert_eq!(
        (got.kind, got.rule),
        (json!("tool_policy"), json!(expected.as_str())),
        "{route:?}"
    );
}

/// R4 (ATTR.1). Three allow entries: the exact `alpha:read` decides, not the
/// first entry or the prefix after it.
#[tokio::test(flavor = "current_thread")]
async fn allow_entry_matched_on_gateway_invoke() {
    allow_entry_matched(Route::MetaInvoke).await;
}

/// R28 (ATTR.1). R4 on the direct route.
#[tokio::test(flavor = "current_thread")]
async fn allow_entry_matched_on_the_direct_route() {
    allow_entry_matched(Route::Direct).await;
}

/// R25 (ATTR.3). A disabled mTLS policy whose rule would match notes
/// nothing: `default_allow`, no rule. A pin.
#[tokio::test(flavor = "current_thread")]
async fn a_disabled_mtls_policy_records_default_allow() {
    let mut config = enabled(agent_rules());
    config.enabled = false;
    let fx = with_policy(config).await;
    for route in [Route::MetaInvoke, Route::Direct] {
        let got = Box::pin(call_cert(&fx, route, "read", Some("agent-a"))).await;
        assert!(delivered(&got), "{route:?}: {got:?}");
        assert_eq!(
            (got.kind, got.rule),
            (json!("default_allow"), Value::Null),
            "{route:?}"
        );
    }
}

/// R29 (ATTR.1). A default-action allow names no entry: `default_allow`.
/// A pin.
#[tokio::test(flavor = "current_thread")]
async fn a_default_action_allow_records_default_allow() {
    let fx = fixture(Answer::Ok, None).await;
    let config = edited(&fx, |c| {
        c.security.tool_policy.enabled = true;
        c.security.tool_policy.allow.clear();
        c.security.tool_policy.default_action = crate::security::policy::PolicyAction::Allow;
    });
    for route in [Route::MetaInvoke, Route::Direct] {
        let got = on(&fx, route, json!({"cmd": "x"}), &config).await;
        assert!(delivered(&got), "{route:?}: {got:?}");
        assert_eq!(
            (got.kind, got.rule),
            (json!("default_allow"), Value::Null),
            "{route:?}"
        );
    }
}

/// R21 (ATTR.1). A task queued, then dispatched by the worker under an
/// allow entry: the worker's one invocation record names the entry. Kills
/// M14 (notes inside the dispatch scope dropped).
#[tokio::test(flavor = "current_thread")]
async fn a_queued_task_names_its_allow_entry() {
    let fx = fixture(Answer::Ok, None).await;
    fx.state.live_config.set(edited(&fx, allow_entries));
    let settled = Box::pin(super::task_with(&fx, "allow-entry-task", json!({}))).await;
    assert!(
        settled.get("error").is_none(),
        "premise, settled: {settled}"
    );
    let expected = tool_policy_id(&fx, "allow", "alpha:read");
    let recorded = invocations(&fx).await;
    let [dispatch] = recorded.as_slice() else {
        panic!("wanted the worker's one invocation record: {recorded:?}");
    };
    assert_eq!(
        (&dispatch["tool"], &dispatch["decision"]["decided"]),
        (&json!("read"), &json!("fresh")),
        "{dispatch}"
    );
    assert_eq!(
        (
            &dispatch["decision"]["kind"],
            &dispatch["decision"]["rule_id"]
        ),
        (&json!("tool_policy"), &json!(expected.as_str())),
        "{dispatch}"
    );
}

/// R1 (ATTR.1), the ladder below the grant on `alpha:read`: an mTLS rule
/// over an allow entry, the entry over a warn-to-allow rule, that rule over
/// nothing, and nothing is `default_allow`. Kills M1.
#[tokio::test(flavor = "current_thread")]
async fn attribution_ladder_below_grant() {
    let rules = agent_rules();
    let fx = with_policy(enabled(rules.clone())).await;
    fx.state.live_config.set(edited(&fx, allow_entries));
    let got = Box::pin(call_cert(&fx, Route::MetaInvoke, "read", Some("agent-a"))).await;
    assert!(delivered(&got), "premise: {got:?}");
    let mtls = mtls_id(&rule_key(&fx), &rules[1]);
    assert_eq!((got.kind, got.rule), (json!("mtls"), json!(mtls.as_str())));

    let fx = fixture(
        Answer::Ok,
        Some(crate::security::firewall::FirewallAction::Warn),
    )
    .await;
    let base = fx.state.live_config.get().security.firewall.rules[0].clone();
    let warn_to_allow = crate::security::firewall::FirewallRule {
        action: crate::security::firewall::FirewallAction::Allow,
        scan: vec![crate::security::firewall::ScanType::SqlInjection],
        ..base
    };
    let sql = json!({"cmd": "' OR 1=1"});
    let rung = |entry: bool, rule: bool| {
        let warn_to_allow = warn_to_allow.clone();
        edited(&fx, move |c| {
            if entry {
                allow_entries(c);
            }
            c.security.firewall.rules = if rule { vec![warn_to_allow] } else { vec![] };
        })
    };
    let entry = tool_policy_id(&fx, "allow", "alpha:read");
    let rule = super::rule_ids::firewall_id(&fx, &warn_to_allow);
    let cases = [
        (
            "entry over rule",
            rung(true, true),
            json!("tool_policy"),
            json!(entry.as_str()),
        ),
        (
            "rule alone",
            rung(false, true),
            json!("firewall"),
            json!(rule.as_str()),
        ),
        (
            "nothing",
            rung(false, false),
            json!("default_allow"),
            Value::Null,
        ),
    ];
    for (case, config, kind, id) in cases {
        let got = on(&fx, Route::MetaInvoke, sql.clone(), &config).await;
        assert!(delivered(&got), "{case}: premise: {got:?}");
        assert_eq!((got.kind, got.rule), (kind, id), "{case}");
    }
}
