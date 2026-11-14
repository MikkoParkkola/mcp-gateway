// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A tool-policy refusal on the meta route records the deny entry that made
//! it, by its keyed id, and the delivered error never carries the id.

use serde_json::json;

use super::{api_key_caller, context, meta, ok_result, records};
use crate::gateway::authz::ToolPolicyAuthorizer;
use crate::security::rule_id::RuleId;
use crate::security::{ToolPolicy, ToolPolicyConfig};

#[tokio::test]
async fn a_meta_tool_policy_refusal_records_its_rule_id() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let meta = meta(Ok(ok_result()), &dir);
    let key = crate::gateway::record_principal::test_record_key().rule_id_key();
    let policy = ToolPolicy::from_config_keyed(
        &ToolPolicyConfig {
            deny: vec!["alpha:read".to_string()],
            use_default_deny: false,
            ..ToolPolicyConfig::default()
        },
        &key,
    );
    let authorizer = ToolPolicyAuthorizer {
        tool_policy: &policy,
        generation: None,
    };
    let who = api_key_caller();
    let args = json!({"server": "alpha", "tool": "read", "arguments": {}});
    // A withheld tool answers as an absent one: an `isError` result.
    let answer = meta
        .invoke_tool(&args, None, &context(&authorizer, &who))
        .await;
    let delivered = format!("{answer:?}");
    let all = records(&dir);
    let [record] = all.as_slice() else {
        panic!("one record: {all:?}");
    };
    let bytes = serde_json::to_vec(&("deny", "alpha:read")).expect("serialises");
    let expected = RuleId::of("tool_policy", &key, &bytes);
    assert_eq!(record["decision"]["kind"], "tool_policy", "{record}");
    assert_eq!(record["decision"]["rule_id"], expected.as_str(), "{record}");
    let hex = expected.as_str().trim_start_matches("tool_policy:");
    assert!(!delivered.contains(hex), "{delivered}");
}

/// A call to a backend that does not exist records no rule.
#[tokio::test]
async fn a_not_found_refusal_records_no_rule() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let meta = meta(Ok(ok_result()), &dir);
    let who = api_key_caller();
    let args = json!({"server": "nowhere", "tool": "read", "arguments": {}});
    let _ = meta
        .invoke_tool(
            &args,
            None,
            &context(&crate::gateway::authz::AllowAll, &who),
        )
        .await;
    let all = records(&dir);
    let [record] = all.as_slice() else {
        panic!("one record: {all:?}");
    };
    assert!(record["decision"].get("rule_id").is_none(), "{record}");
}

/// A response-side block (the contract gate) records no rule: response
/// attribution is not recorded.
#[tokio::test]
async fn a_response_side_block_records_no_rule() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let mut meta = meta(Ok(ok_result()), &dir);
    meta.set_response_contract(crate::config::ResponseContractConfig {
        fail_closed: true,
        action_mode: true,
        ..crate::config::ResponseContractConfig::default()
    });
    let who = api_key_caller();
    let args = json!({"server": "alpha", "tool": "read", "arguments": {}});
    let _ = meta
        .invoke_tool(
            &args,
            None,
            &context(&crate::gateway::authz::AllowAll, &who),
        )
        .await
        .expect_err("premise: the call is refused");
    let all = records(&dir);
    let [record] = all.as_slice() else {
        panic!("one record: {all:?}");
    };
    assert_eq!(record["decision"]["kind"], "response_gate", "{record}");
    assert!(record["decision"].get("rule_id").is_none(), "{record}");
}
