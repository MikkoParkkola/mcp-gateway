// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The decision fixture table's mTLS allow row (A2), apart so the HTTP rows
//! stay under the size ceiling.

use super::*;

/// An enabled mTLS policy: a rule for CN `nobody`, then one that matches
/// certificate CN `cn` and allows `alpha`'s `read`; first match wins, and no match denies
/// (`access_control/mod.rs:99-112`).
/// Keyed under the unit-test record key, which the table's gateway keys
/// with (asserted where the id is read), so the matched rule has an id.
fn mtls_policy_for(cn: &str) -> Arc<crate::mtls::MtlsPolicy> {
    Arc::new(crate::mtls::MtlsPolicy::from_config_keyed(
        &mtls_config_for(cn),
        &crate::gateway::record_principal::test_record_key().rule_id_key(),
    ))
}

fn mtls_config_for(cn: &str) -> crate::mtls::MtlsConfig {
    use crate::mtls::config::{CertMatchConfig, MtlsConfig, PolicyRuleConfig, ToolScopeConfig};
    MtlsConfig {
        enabled: true,
        policies: vec![
            // A non-matching rule first, so a first-rule mutant is told apart
            // from the matched rule when the allowing rule is recorded.
            PolicyRuleConfig {
                match_criteria: CertMatchConfig {
                    cn: Some("nobody".to_string()),
                    ..CertMatchConfig::default()
                },
                allow: ToolScopeConfig {
                    backends: vec!["alpha".to_string()],
                    tools: vec!["read".to_string()],
                },
                ..PolicyRuleConfig::default()
            },
            PolicyRuleConfig {
                match_criteria: CertMatchConfig {
                    cn: Some(cn.to_string()),
                    ..CertMatchConfig::default()
                },
                allow: ToolScopeConfig {
                    backends: vec!["alpha".to_string()],
                    tools: vec!["read".to_string()],
                },
                ..PolicyRuleConfig::default()
            },
        ],
        ..MtlsConfig::default()
    }
}

/// A2: an mTLS rule allows the caller's certificate (CN `agent-a`, the
/// owner certificate `direct_effect_tests::call` presents) on `alpha`'s
/// `read`, on the direct route. Records the matched rule, the second one
/// (flipped by allow attribution). Control: the same enabled, non-empty policy, its rule matching
/// another CN, refuses the call: no rule matches, so the policy denies.
#[tokio::test]
async fn a2_mtls_rule_allow() {
    use super::super::direct_effect_tests::call;
    use super::super::direct_guards_fixture::with_mtls_policy;
    let dir = Arc::new(tempfile::tempdir().expect("a log directory"));
    let fx = with_mtls_policy(mtls_policy_for("agent-a"), Box::pin(table(&dir))).await;
    let alpha = fx.state.backends.get("alpha").expect("alpha");
    let read: crate::protocol::Tool = serde_json::from_value(json!({
        "name": "read",
        "inputSchema": {"type": "object"},
        "annotations": {"readOnlyHint": true},
    }))
    .expect("a tool");
    alpha.declare_slot_effects_for_test(None, vec![read]);
    let rule = &mtls_config_for("agent-a").policies[1];
    let matched = crate::mtls::access_control::rule_id_tests::mtls_id(
        &crate::gateway::record_principal::test_record_key().rule_id_key(),
        rule,
    );
    let gateway_key = fx
        .state
        .live_config
        .generation()
        .auth()
        .record_key()
        .rule_id_key();
    assert_eq!(
        crate::mtls::access_control::rule_id_tests::mtls_id(&gateway_key, rule),
        matched,
        "premise: the table's gateway keys rules with the unit-test record key"
    );
    let before = (
        records(&dir).len(),
        super::super::direct_continuation_tests::dispatched(&fx),
    );
    let body = call(&fx, "/mcp/alpha", "read", json!({})).await;
    assert!(
        body.get("result").is_some() && body["result"]["isError"] != true,
        "premise: delivered: {body}"
    );
    assert_eq!(
        super::super::direct_continuation_tests::dispatched(&fx),
        before.1 + 1,
        "premise: the backend was sent the call once"
    );
    let mut all = records(&dir);
    let new = all.split_off(before.0);
    let [record] = new.as_slice() else {
        panic!("premise: one new invocation record: {new:?}");
    };
    assert_eq!(record["outcome"], "ok", "{record}");
    // flipped by allow attribution
    let row = DecisionRow {
        name: "a2_mtls_rule_allow",
        kind: "mtls",
        rule_id: RuleId::named(matched.as_str()),
        grant_id: None,
        findings: Findings::NotRun,
        effect: Some(("read_only", "tool_annotation")),
        decided: "fresh",
    };
    assert_row(&record["decision"], &row);

    let dir = Arc::new(tempfile::tempdir().expect("a log directory"));
    let fx = with_mtls_policy(mtls_policy_for("agent-b"), Box::pin(table(&dir))).await;
    let sent = super::super::direct_continuation_tests::dispatched(&fx);
    let body = call(&fx, "/mcp/alpha", "read", json!({})).await;
    assert!(
        body.get("error").is_some() || body["result"]["isError"] == true,
        "control: a rule for another CN did not refuse: {body}"
    );
    assert_eq!(
        super::super::direct_continuation_tests::dispatched(&fx),
        sent,
        "control: the backend was sent the call"
    );
}
