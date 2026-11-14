// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A call to a backend the registry does not hold is the gateway's own
//! answer: its invocation record names `not_found` and a refusal, never
//! `default_allow`, and the caller's answer is what it always was. Each row
//! runs inside a request's visibility memo, as every route runs a call.

use serde_json::{Value, json};

use super::{api_key_caller, context, meta, ok_result, records};
use crate::gateway::authz::{AllowAll, ToolPolicyAuthorizer};
use crate::gateway::meta_mcp::visible::memo::with_visibility_memo;
use crate::security::{ToolPolicy, ToolPolicyConfig};

/// `server`'s `read` invoked by an API-key caller under `authorizer`, inside
/// one request memo: the answer as the caller sees it, and the one record.
async fn invoke(
    dir: &tempfile::TempDir,
    server: &str,
    authorizer: &(dyn crate::gateway::authz::ToolAuthorizer + Sync),
) -> (String, Value) {
    let meta = meta(Ok(ok_result()), dir);
    let who = api_key_caller();
    let args = json!({"server": server, "tool": "read", "arguments": {}});
    let answer =
        with_visibility_memo(meta.invoke_tool(&args, None, &context(authorizer, &who))).await;
    let all = records(dir);
    let [record] = all.as_slice() else {
        panic!("one record: {all:?}");
    };
    (format!("{answer:?}"), record.clone())
}

/// NOTFOUND.1 (red first): an unscoped caller's call to a backend that does
/// not exist records `not_found`, never `default_allow`.
#[tokio::test]
async fn a_call_to_a_nonexistent_backend_records_not_found() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (answer, record) = invoke(&dir, "nowhere", &AllowAll).await;
    assert_eq!(
        record["decision"]["kind"], "not_found",
        "answer {answer}; record {record}"
    );
    assert!(record["decision"].get("rule_id").is_none(), "{record}");
}

/// NOTFOUND.2 (red first): the record's outcome is the gateway's refusal,
/// with the miss's code, and the answer is the plain miss it always was.
#[tokio::test]
async fn a_call_to_a_nonexistent_backend_is_recorded_as_denied() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (answer, record) = invoke(&dir, "nowhere", &AllowAll).await;
    assert!(
        answer.contains("Backend not found: nowhere"),
        "the answer is the plain miss: {answer}"
    );
    assert_eq!(record["outcome"], json!("denied"), "{record}");
    assert_eq!(record["error_code"], json!(-32001), "{record}");
}

/// Control: a call to a registered backend under `AllowAll` keeps its
/// allow and its own outcome.
#[tokio::test]
async fn a_call_to_a_registered_backend_still_records_default_allow() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (answer, record) = invoke(&dir, "alpha", &AllowAll).await;
    assert_eq!(record["decision"]["kind"], "default_allow", "{record}");
    assert_eq!(record["outcome"], json!("ok"), "answer {answer}; {record}");
}

/// Control: a name the tool policy refuses that is also unregistered keeps
/// the policy's refusal: the first decision noted stands.
#[tokio::test]
async fn a_policy_refusal_of_an_unregistered_name_keeps_the_policy_kind() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let key = crate::gateway::record_principal::test_record_key().rule_id_key();
    let policy = ToolPolicy::from_config_keyed(
        &ToolPolicyConfig {
            deny: vec!["nowhere:read".to_string()],
            use_default_deny: false,
            ..ToolPolicyConfig::default()
        },
        &key,
    );
    let authorizer = ToolPolicyAuthorizer {
        tool_policy: &policy,
        generation: None,
    };
    let (_, record) = invoke(&dir, "nowhere", &authorizer).await;
    assert_eq!(record["decision"]["kind"], "tool_policy", "{record}");
}
