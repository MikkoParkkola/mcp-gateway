// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The decision fixture table, meta-route allow rows: one per allow source.
//!
//! What every allow row pins today, read at 01aa22f2cc:
//! - `kind` `default_allow` with `rule_id` absent: `Checks::allowed`
//!   (`decision_record.rs:231`) is the only writer of an allow attribution and
//!   its only caller is the not-redecided copy (`:193`), so a fresh allowed call
//!   records `default_allow` (`:268-272`) whichever check allowed it. Every row
//!   but A6a is marked `flipped by MIK-9205`, which records the allowing check.
//! - `grant_id` absent: nothing writes it (`decision_record.rs:304`).
//! - findings `NotRun`: no production writer of `request_findings` yet.
//! - effect (`undeclared`, `tool_annotation`): the fixture lists `read` with no
//!   read-only hint, and a listed tool whose every occurrence omits the hint
//!   declares nothing (`annotations.rs:231-233`).
//!
//! Each row also runs a control: the same call with only its allowing check
//! removed must be refused, so the fixture goes through that check.

use std::sync::atomic::Ordering;

use serde_json::{Value, json};

use super::fixture_rows::table_meta;
use super::{api_key_caller, context, records};
use crate::config::BackendConfig;
use crate::gateway::authz::{AllowAll, ToolAuthorizer, ToolPolicyAuthorizer};
use crate::gateway::meta_mcp::visible::memo::with_visibility_memo;
use crate::security::decision_fixture_table::{DecisionRow, Findings, RuleId, assert_row};
use crate::security::policy::PolicyAction;
use crate::security::{ToolPolicy, ToolPolicyConfig};

/// The allow row every source records today.
const fn allowed(name: &'static str, reason: &'static str) -> DecisionRow {
    DecisionRow {
        name,
        kind: "default_allow",
        rule_id: RuleId::Absent(reason),
        grant_id: None,
        findings: Findings::NotRun,
        effect: Some(("undeclared", "tool_annotation")),
        decided: "fresh",
    }
}

/// A tool policy under the test record key.
fn policy(config: &ToolPolicyConfig) -> ToolPolicy {
    ToolPolicy::from_config_keyed(
        config,
        &crate::gateway::record_principal::test_record_key().rule_id_key(),
    )
}

/// `alpha`'s `read` invoked under `authorizer` on a fresh gateway: whether
/// it was delivered, the calls `alpha` was sent, and the call's one record.
async fn call_under(authorizer: &(dyn ToolAuthorizer + Sync)) -> (bool, usize, Value) {
    let dir = tempfile::tempdir().expect("a log directory");
    let (meta, sent) = table_meta(&dir, BackendConfig::default());
    let who = api_key_caller();
    let args = json!({"server": "alpha", "tool": "read", "arguments": {}});
    let answer =
        with_visibility_memo(meta.invoke_tool(&args, None, &context(authorizer, &who))).await;
    let delivered = matches!(&answer, Ok(result) if result["isError"] != true);
    let all = records(&dir);
    let [record] = all.as_slice() else {
        panic!("premise: one invocation record: {all:?}; answer {answer:?}");
    };
    (delivered, sent.load(Ordering::SeqCst), record.clone())
}

/// An allowed call: delivered, sent once, recorded `ok`; returns its decision.
async fn delivered(authorizer: &(dyn ToolAuthorizer + Sync)) -> Value {
    let (delivered, sent, record) = call_under(authorizer).await;
    assert!(delivered, "premise: the call is delivered: {record}");
    assert_eq!(sent, 1, "premise: the backend was sent the call once");
    assert_eq!(record["outcome"], "ok", "{record}");
    record["decision"].clone()
}

/// A control call: refused, and the backend was sent nothing.
async fn refused_control(authorizer: &(dyn ToolAuthorizer + Sync), what: &str) {
    let (delivered, sent, record) = call_under(authorizer).await;
    assert!(
        !delivered,
        "control: {what} did not refuse the call: {record}"
    );
    assert_eq!(sent, 0, "control: {what}: the backend was sent the call");
    assert_ne!(record["outcome"], "ok", "control: {what}: {record}");
}

/// A1: a tool-policy allow-list entry admits the call over a default deny.
/// Control: without the entry, the default deny refuses it.
#[tokio::test]
async fn a1_allow_list_pattern() {
    let with_entry = policy(&ToolPolicyConfig {
        default_action: PolicyAction::Deny,
        allow: vec!["alpha:read".to_string()],
        use_default_deny: false,
        ..ToolPolicyConfig::default()
    });
    let decision = delivered(&ToolPolicyAuthorizer {
        tool_policy: &with_entry,
        generation: None,
    })
    .await;
    // flipped by MIK-9205
    assert_row(
        &decision,
        &allowed("a1_allow_list_pattern", "flipped by MIK-9205"),
    );
    let without = policy(&ToolPolicyConfig {
        default_action: PolicyAction::Deny,
        use_default_deny: false,
        ..ToolPolicyConfig::default()
    });
    refused_control(
        &ToolPolicyAuthorizer {
            tool_policy: &without,
            generation: None,
        },
        "removing the allow entry",
    )
    .await;
}

/// A5: only the tool policy's default rule (allow) admits the call.
/// Control: the default set to deny refuses it.
#[tokio::test]
async fn a5_tool_policy_default_rule() {
    let default_allow = policy(&ToolPolicyConfig {
        default_action: PolicyAction::Allow,
        use_default_deny: false,
        ..ToolPolicyConfig::default()
    });
    let decision = delivered(&ToolPolicyAuthorizer {
        tool_policy: &default_allow,
        generation: None,
    })
    .await;
    // flipped by MIK-9205
    assert_row(
        &decision,
        &allowed("a5_tool_policy_default_rule", "flipped by MIK-9205"),
    );
    let default_deny = policy(&ToolPolicyConfig {
        default_action: PolicyAction::Deny,
        use_default_deny: false,
        ..ToolPolicyConfig::default()
    });
    refused_control(
        &ToolPolicyAuthorizer {
            tool_policy: &default_deny,
            generation: None,
        },
        "the default set to deny",
    )
    .await;
}

/// A6a: nothing restricts the call (no tool policy). MIK-9205 does not flip
/// this row. Control: a deny entry for the tool refuses it.
#[tokio::test]
async fn a6a_meta_no_rule() {
    let decision = delivered(&AllowAll).await;
    assert_row(
        &decision,
        &allowed("a6a_meta_no_rule", "no rule restricted this call"),
    );
    let deny = policy(&ToolPolicyConfig {
        deny: vec!["alpha:read".to_string()],
        use_default_deny: false,
        ..ToolPolicyConfig::default()
    });
    refused_control(
        &ToolPolicyAuthorizer {
            tool_policy: &deny,
            generation: None,
        },
        "a deny entry for the tool",
    )
    .await;
}
