// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The decision fixture table, meta-route allow rows: one per allow source.
//!
//! What every allow row pins today, read at 01aa22f2cc:
//! - `kind` `default_allow` with `rule_id` absent: `Checks::allowed`
//!   (`decision_record.rs:231`) is the only writer of an allow attribution and
//!   its only caller is the not-redecided copy (`:193`), so a fresh allowed call
//!   records `default_allow` (`:268-272`) whichever check allowed it. Rows A1
//!   and A4 are marked `flipped by allow attribution`: they record the allowing
//!   check. A5 and A6a stay `default_allow`: no entry decided them.
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
    let dir = std::sync::Arc::new(tempfile::tempdir().expect("a log directory"));
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
    // Every control here is a tool-policy refusal: a refused name is withheld
    // as `Withholding::Refused`, whose kind is `tool_policy` (`Withholding::kind`).
    assert_eq!(
        record["decision"]["kind"], "tool_policy",
        "control: {what}: {record}"
    );
}

/// A1: a tool-policy allow-list entry admits the call over a default deny.
/// Control: without the entry, the default deny refuses it.
#[tokio::test]
async fn a1_allow_list_pattern() {
    let with_entry = policy(&ToolPolicyConfig {
        default_action: PolicyAction::Deny,
        // A non-matching entry first: when the matched entry is recorded, a
        // first-entry mutant is told apart from it.
        allow: vec!["beta:other".to_string(), "alpha:read".to_string()],
        use_default_deny: false,
        ..ToolPolicyConfig::default()
    });
    let decision = delivered(&ToolPolicyAuthorizer {
        tool_policy: &with_entry,
        generation: None,
    })
    .await;
    // flipped by allow attribution: the matched entry, not the decoy before it.
    let entry = crate::security::rule_id::RuleId::of(
        "tool_policy",
        &crate::gateway::record_principal::test_record_key().rule_id_key(),
        &serde_json::to_vec(&("allow", "alpha:read")).expect("serialises"),
    );
    assert_row(
        &decision,
        &DecisionRow {
            kind: "tool_policy",
            rule_id: RuleId::named(entry.as_str()),
            ..allowed("a1_allow_list_pattern", "")
        },
    );
    // Only the matching entry removed: the decoy stays, and cannot admit it.
    let without = policy(&ToolPolicyConfig {
        default_action: PolicyAction::Deny,
        allow: vec!["beta:other".to_string()],
        use_default_deny: false,
        ..ToolPolicyConfig::default()
    });
    refused_control(
        &ToolPolicyAuthorizer {
            tool_policy: &without,
            generation: None,
        },
        "removing the matching allow entry",
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
    // Not flipped: a default-action allow names no entry, so it records
    // `default_allow` like a call no rule restricted.
    assert_row(
        &decision,
        &allowed(
            "a5_tool_policy_default_rule",
            "a default-action allow names no entry",
        ),
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

/// A6a: nothing restricts the call (no tool policy). Allow attribution does not
/// flip this row. Control: a deny entry for the tool refuses it.
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

/// A gateway whose request firewall carries `rules`, and `alpha`'s `read`
/// invoked on it with a shell-injection argument, a High finding that the
/// severity fallback blocks (`verdict.rs:279`) unless a rule softens it:
/// whether the call was delivered, the calls `alpha` was sent, its record.
#[cfg(feature = "firewall")]
async fn shell_call_under(
    rules: Vec<crate::security::firewall::FirewallRule>,
) -> (bool, usize, Value, crate::security::rule_id::RuleKey) {
    use crate::security::firewall::{Firewall, FirewallConfig};
    let dir = std::sync::Arc::new(tempfile::tempdir().expect("a log directory"));
    let (mut meta, sent) = table_meta(&dir, BackendConfig::default());
    meta.set_firewall(Some(std::sync::Arc::new(
        Firewall::from_config(
            FirewallConfig {
                rules,
                ..FirewallConfig::default()
            },
            None,
        )
        .with_continuations(meta.continuation()),
    )));
    // A firewalled gateway serves relays from a published live config, as
    // `tenants.rs` seeds it (`relay_staging.rs:229` panics without one).
    crate::security::firewall::collusion_live_rig::seed_meta(
        &meta,
        &meta.firewall_for_test().expect("set above"),
    );
    let who = api_key_caller();
    // Split, as `allowed_root_rule_id_tests` builds it: the scanner sees the
    // whole command.
    let cmd = ["; rm -", "rf /"].concat();
    let args = json!({"server": "alpha", "tool": "read", "arguments": {"cmd": cmd}});
    let answer =
        with_visibility_memo(meta.invoke_tool(&args, None, &context(&AllowAll, &who))).await;
    let delivered = matches!(&answer, Ok(result) if result["isError"] != true);
    let all = records(&dir);
    let [record] = all.as_slice() else {
        panic!("premise: one invocation record: {all:?}; answer {answer:?}");
    };
    // The key the published generation names its firewall rules under.
    let key = meta
        .current_generation()
        .expect("premise: a generation is published")
        .auth()
        .record_key()
        .rule_id_key();
    (delivered, sent.load(Ordering::SeqCst), record.clone(), key)
}

/// A4: a firewall Allow rule softens the shell-injection finding that would
/// block the call. Records that rule as the allowing check (flipped by allow attribution); the
/// firewall found and allowed a High finding, but the decision keeps no trace
/// of it: the constructor's `request_findings: None` (`decision_record.rs:305`)
/// is the only production line that sets the field, so findings stay `NotRun`
/// (an audit gap, on the register; flipped when the request-findings writer
/// lands). Control: the same firewall with only the non-matching rule blocks
/// the call.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn a4_firewall_allow_rule() {
    use crate::security::firewall::{FirewallAction, FirewallRule, ScanType};
    let soften = FirewallRule {
        tool_match: "read".to_string(),
        action: FirewallAction::Allow,
        reason: None,
        scan: vec![ScanType::ShellInjection],
        servers: None,
        keys: None,
        except: None,
        allowed_roots: None,
        path_args: None,
    };
    // A non-matching rule first (another tool), so a first-rule mutant is told
    // apart from the matched rule when the allowing rule is recorded.
    let elsewhere = FirewallRule {
        tool_match: "write".to_string(),
        ..soften.clone()
    };
    let (delivered, sent, record, key) =
        shell_call_under(vec![elsewhere.clone(), soften.clone()]).await;
    assert!(
        delivered,
        "premise: the softened call is delivered: {record}"
    );
    assert_eq!(sent, 1, "premise: the backend was sent the call once");
    assert_eq!(record["outcome"], "ok", "{record}");
    // flipped by allow attribution: the softening rule, not the decoy before it.
    let rule = crate::security::rule_id::RuleId::of(
        "firewall",
        &key,
        &serde_json::to_vec(&soften).expect("serialises"),
    );
    assert_row(
        &record["decision"],
        &DecisionRow {
            kind: "firewall",
            rule_id: RuleId::named(rule.as_str()),
            ..allowed("a4_firewall_allow_rule", "")
        },
    );
    // Only the matching rule removed: the decoy stays, and cannot admit it.
    let (delivered, sent, record, _) = shell_call_under(vec![elsewhere]).await;
    assert!(
        !delivered,
        "control: no rule did not block the call: {record}"
    );
    assert_eq!(sent, 0, "control: the backend was sent the call");
    assert_eq!(record["decision"]["kind"], "firewall", "control: {record}");
}
