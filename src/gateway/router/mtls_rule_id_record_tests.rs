// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An mTLS refusal records the rule that decided it, by its keyed id, with
//! one decision record per refused call. A refusal no rule decided (no
//! certificate, no rule matched) names none, and a disabled policy notes
//! nothing. `gateway_invoke` reaches the route stage's withheld memo, which
//! carries the meta layer's noted refusal into the record.

use serde_json::{Value, json};
use std::sync::atomic::Ordering;

use super::{Logged, Outcome, Route, fixture, invocations, outcome};
use crate::mtls::MtlsConfig;
use crate::mtls::access_control::rule_id_tests::{deny_write_rules, mtls_id, read_only_rules};
use crate::mtls::config::PolicyRuleConfig;
use crate::security::rule_id::RuleKey;

fn rule_key(fx: &Logged) -> RuleKey {
    let generation = fx.state.live_config.generation();
    generation.auth().record_key().rule_id_key()
}

/// The fixture with `config` as its mTLS policy, keyed under the gateway's
/// rule key.
async fn with_policy(config: MtlsConfig) -> Logged {
    let mut logged = fixture(super::Answer::Ok, None).await;
    let key = rule_key(&logged);
    // The router holds the state; drop it to install the policy.
    logged.fx.router = axum::Router::new();
    std::sync::Arc::get_mut(&mut logged.fx.state)
        .expect("sole owner during setup")
        .mtls_policy =
        std::sync::Arc::new(crate::mtls::MtlsPolicy::from_config_keyed(&config, &key));
    logged.fx.router = super::super::create_router(std::sync::Arc::clone(&logged.fx.state));
    logged
}

fn enabled(policies: Vec<PolicyRuleConfig>) -> MtlsConfig {
    MtlsConfig {
        enabled: true,
        policies,
        ..MtlsConfig::default()
    }
}

/// `tool` on `alpha` as `k-std` through `route`, presenting a certificate
/// with common name `cn` when one is given. Asserts the call left exactly one
/// new decision record.
async fn call_cert(fx: &Logged, route: Route, tool: &str, cn: Option<&str>) -> Outcome {
    let (uri, params) = match route {
        Route::Direct => ("/mcp/alpha", json!({"name": tool, "arguments": {}})),
        Route::MetaInvoke | Route::MetaRetry => (
            "/mcp",
            json!({"name": "gateway_invoke",
                   "arguments": {"server": "alpha", "tool": tool, "arguments": {}}}),
        ),
    };
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", "Bearer k-std")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
                .to_string(),
        ))
        .expect("request");
    if let Some(cn) = cn {
        request
            .extensions_mut()
            .insert(crate::mtls::identity::CertIdentity::for_test(
                crate::mtls::identity::CertFields {
                    common_name: Some(cn.to_string()),
                    display_name: cn.to_string(),
                    ..Default::default()
                },
            ));
    }
    let recorded = invocations(fx).await.len();
    let before = fx.calls.load(Ordering::SeqCst);
    let response = tower::ServiceExt::oneshot(fx.router.clone(), request)
        .await
        .expect("response");
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let body: Value = serde_json::from_slice(&bytes).expect("json");
    let rows = invocations(fx).await;
    let [row] = &rows[recorded..] else {
        panic!(
            "{route:?} {tool}: wanted one new decision record, got {:?}",
            &rows[recorded..]
        );
    };
    let decided = (
        row["decision"]["kind"].clone(),
        row["decision"]["rule_id"].clone(),
    );
    outcome(&body, fx.calls.load(Ordering::SeqCst) - before, decided)
}

/// `write` as `agent-1` is refused by rule B, which the record names.
async fn refused_by_b(route: Route, rules: Vec<PolicyRuleConfig>) {
    let deciding = rules[1].clone();
    let fx = with_policy(enabled(rules)).await;
    let expected = mtls_id(&rule_key(&fx), &deciding);
    let got = call_cert(&fx, route, "write", Some("agent-1")).await;
    assert!(
        got.refused && got.calls == 0 && got.kind == "mtls",
        "{route:?}: premise, refused by mTLS: {got:?}"
    );
    assert_eq!(
        got.rule,
        json!(expected.as_str()),
        "{route:?}: expected rule_id {}, got {}",
        expected.as_str(),
        got.rule
    );
    let hex = expected.as_str().trim_start_matches("mtls:");
    let delivered = format!("{}{}", got.code, got.message);
    assert!(
        !delivered.contains(hex),
        "{route:?}: the refusal names the rule: {got:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn an_mtls_deny_rule_refusal_records_its_rule_id_on_gateway_invoke() {
    refused_by_b(Route::MetaInvoke, deny_write_rules()).await;
}

#[tokio::test(flavor = "current_thread")]
async fn an_mtls_deny_rule_refusal_records_its_rule_id_on_the_direct_route() {
    refused_by_b(Route::Direct, deny_write_rules()).await;
}

/// B allows only `read`: `write` is refused with B's id, and `read` with the
/// same certificate and backend is allowed.
async fn excluded_by_b(route: Route) {
    refused_by_b(route, read_only_rules()).await;
    let fx = with_policy(enabled(read_only_rules())).await;
    let got = call_cert(&fx, route, "read", Some("agent-1")).await;
    assert!(
        !got.refused && got.calls == 1 && got.kind != "mtls",
        "{route:?}: B allows read: {got:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn an_mtls_allow_list_exclusion_records_its_rule_id_on_gateway_invoke() {
    excluded_by_b(Route::MetaInvoke).await;
}

#[tokio::test(flavor = "current_thread")]
async fn an_mtls_allow_list_exclusion_records_its_rule_id_on_the_direct_route() {
    excluded_by_b(Route::Direct).await;
}

/// No certificate, and a certificate no rule matches: refused by mTLS, and
/// no rule is named. On `gateway_invoke` only: the direct route answers such
/// a caller as a backend that does not exist (the policy refuses the whole
/// backend by name), recorded as `not_found`.
#[tokio::test(flavor = "current_thread")]
async fn an_mtls_refusal_with_no_certificate_or_no_matching_rule_records_no_rule_id() {
    let fx = with_policy(enabled(deny_write_rules())).await;
    let route = Route::MetaInvoke;
    for cn in [None, Some("stranger")] {
        let got = call_cert(&fx, route, "read", cn).await;
        assert!(
            got.refused && got.kind == "mtls",
            "{route:?} {cn:?}: {got:?}"
        );
        assert!(
            got.rule.is_null(),
            "{route:?} {cn:?}: expected no rule_id: {got:?}"
        );
    }
}

/// A disabled policy, even one whose rule B would refuse `read`, notes
/// nothing: the call goes through.
#[tokio::test(flavor = "current_thread")]
async fn a_disabled_mtls_policy_notes_nothing() {
    let mut rules = deny_write_rules();
    rules[1].deny.tools = vec!["read".to_string()];
    let mut config = enabled(rules);
    config.enabled = false;
    let fx = with_policy(config).await;
    for route in [Route::MetaInvoke, Route::Direct] {
        let got = call_cert(&fx, route, "read", Some("agent-1")).await;
        assert!(
            !got.refused && got.calls == 1 && got.kind != "mtls" && got.rule.is_null(),
            "{route:?}: {got:?}"
        );
    }
}
