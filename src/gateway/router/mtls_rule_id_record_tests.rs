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

pub(super) fn rule_key(fx: &Logged) -> RuleKey {
    let generation = fx.state.live_config.generation();
    generation.auth().record_key().rule_id_key()
}

/// The fixture with `config` as its mTLS policy, keyed under the gateway's
/// rule key.
pub(super) async fn with_policy(config: MtlsConfig) -> Logged {
    let logged = fixture(super::Answer::Ok, None).await;
    let key = rule_key(&logged);
    let policy = crate::mtls::MtlsPolicy::from_config_keyed(&config, &key);
    installed(logged, std::sync::Arc::new(policy))
}

/// `logged` with `policy` as its mTLS policy.
pub(super) fn installed(
    mut logged: Logged,
    policy: std::sync::Arc<crate::mtls::MtlsPolicy>,
) -> Logged {
    // The router holds the state; drop it to install the policy.
    logged.fx.router = axum::Router::new();
    std::sync::Arc::get_mut(&mut logged.fx.state)
        .expect("sole owner during setup")
        .mtls_policy = policy;
    logged.fx.router = super::super::create_router(std::sync::Arc::clone(&logged.fx.state));
    logged
}

pub(super) fn enabled(policies: Vec<PolicyRuleConfig>) -> MtlsConfig {
    MtlsConfig {
        enabled: true,
        policies,
        ..MtlsConfig::default()
    }
}

/// `tool` on `alpha` as `k-std` through `route`, presenting a certificate
/// with common name `cn` when one is given. Asserts the call left exactly one
/// new decision record; returns the answer, that record and the backend
/// calls made.
pub(super) async fn send_cert(
    fx: &Logged,
    route: Route,
    tool: &str,
    cn: Option<&str>,
) -> (Value, Value, usize) {
    let (uri, params) = match route {
        Route::Direct => ("/mcp/alpha", json!({"name": tool, "arguments": {}})),
        // An mTLS refusal comes before dispatch, so no backend question is
        // asked and no continuation is minted: there is no retry to send.
        Route::MetaRetry => panic!("an mTLS refusal leaves no continuation to retry"),
        Route::MetaInvoke => (
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
    (body, row.clone(), fx.calls.load(Ordering::SeqCst) - before)
}

/// [`send_cert`], as the call's outcome and its record's deciding check.
pub(super) async fn call_cert(fx: &Logged, route: Route, tool: &str, cn: Option<&str>) -> Outcome {
    let (body, row, calls) = send_cert(fx, route, tool, cn).await;
    let decided = (
        row["decision"]["kind"].clone(),
        row["decision"]["rule_id"].clone(),
    );
    outcome(&body, calls, decided)
}

/// `write` as `agent-1` is refused by rule B, which the record names.
async fn refused_by_b(route: Route, rules: Vec<PolicyRuleConfig>) {
    let deciding = rules[1].clone();
    let fx = with_policy(enabled(rules)).await;
    let expected = mtls_id(&rule_key(&fx), &deciding);
    let (body, row, calls) = send_cert(&fx, route, "write", Some("agent-1")).await;
    let decided = (
        row["decision"]["kind"].clone(),
        row["decision"]["rule_id"].clone(),
    );
    let got = outcome(&body, calls, decided);
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
    // The whole answer, not only its code and message, names no rule.
    let delivered = body.to_string();
    let hex = expected.as_str().trim_start_matches("mtls:");
    assert!(
        !delivered.contains("mtls:") && !delivered.contains(hex),
        "{route:?}: the answer names the rule: {delivered}"
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
/// same certificate and backend is allowed, naming B as its allow.
async fn excluded_by_b(route: Route) {
    refused_by_b(route, read_only_rules()).await;
    let fx = with_policy(enabled(read_only_rules())).await;
    let got = call_cert(&fx, route, "read", Some("agent-1")).await;
    assert!(
        !got.refused && got.calls == 1,
        "{route:?}: B allows read: {got:?}"
    );
    let b = mtls_id(&rule_key(&fx), &read_only_rules()[1]);
    assert_eq!(
        (got.kind, got.rule),
        (json!("mtls"), json!(b.as_str())),
        "{route:?}: the allowed read names B"
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

/// The direct route hides a backend the policy refuses by name: a caller
/// with no certificate, or one no rule matches, is refused every tool on
/// `alpha`
/// (`caller_hiding.rs:151-159`, `refused_by_name` through
/// `mtls_policy.refuses_backend`), so the answer is the missing backend's,
/// recorded as `not_found` with no rule. Neither the answer nor the record
/// names a tool of the backend or says that certificate policy refused.
#[tokio::test(flavor = "current_thread")]
async fn a_direct_call_no_rule_admits_answers_backend_not_found() {
    let fx = with_policy(enabled(deny_write_rules())).await;
    for cn in [None, Some("stranger")] {
        hidden_backend(&fx, cn).await;
    }
}

async fn hidden_backend(fx: &Logged, cn: Option<&str>) {
    let (body, row, calls) = send_cert(fx, Route::Direct, "read", cn).await;
    assert_eq!(calls, 0, "{cn:?}: {body}");
    assert_eq!(
        body.pointer("/error/message"),
        Some(&json!("Backend not found: alpha")),
        "{body}"
    );
    assert_eq!(row["decision"]["kind"], json!("not_found"), "{row}");
    assert!(row["decision"].get("rule_id").is_none(), "{row}");
    // The record's `who` names a certificate caller by its authority
    // (`mtls`) and subject: that is who called, not why it was refused.
    let (answer, record) = (body.to_string(), row.to_string());
    let decision = row["decision"].to_string();
    for word in ["write", "mtls", "certificate"] {
        assert!(!answer.contains(word), "the answer says {word}: {answer}");
        assert!(
            !decision.contains(word),
            "the decision says {word}: {decision}"
        );
    }
    for word in ["write", "certificate"] {
        assert!(!record.contains(word), "the record says {word}: {record}");
    }
    assert!(
        !answer.contains("read"),
        "the answer names a tool: {answer}"
    );
}

/// The policy as the production builder compiles it from config, under that
/// gateway's own record key: a refusal names rule B by the id the gateway's
/// rule key gives it, so an unkeyed production build is seen.
#[tokio::test(flavor = "current_thread")]
async fn a_production_built_mtls_policy_records_its_rule_id() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let mut config = crate::config::Config {
        mtls: enabled(deny_write_rules()),
        ..crate::config::Config::default()
    };
    config.tasks.store_dir = dir.path().join("tasks").to_string_lossy().into_owned();
    let gateway = crate::gateway::Gateway::new(config)
        .await
        .expect("valid config");
    let (policy, key) = Box::pin(gateway.built_mtls_policy_for_test())
        .await
        .expect("the production builder runs");
    let fx = installed(fixture(super::Answer::Ok, None).await, policy);
    let expected = mtls_id(&key, &deny_write_rules()[1]);
    let got = call_cert(&fx, Route::MetaInvoke, "write", Some("agent-1")).await;
    assert!(
        got.refused && got.kind == "mtls",
        "premise, refused by mTLS: {got:?}"
    );
    assert_eq!(
        got.rule,
        json!(expected.as_str()),
        "expected rule_id {}, got {}",
        expected.as_str(),
        got.rule
    );
}
