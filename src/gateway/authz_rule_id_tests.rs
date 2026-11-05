// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A tool-policy refusal names its rule for the decision record only: the
//! message every transport delivers carries no trace of the id.

use super::{ToolTarget, tool_policy_refusal};
use crate::security::{ToolPolicy, ToolPolicyConfig};

#[test]
fn a_tool_policy_refusal_message_carries_no_rule_id() {
    let policy = ToolPolicy::from_config_keyed(
        &ToolPolicyConfig {
            deny: vec!["s:write".to_string()],
            use_default_deny: false,
            ..ToolPolicyConfig::default()
        },
        &crate::gateway::record_principal::test_record_key().rule_id_key(),
    );
    let args = serde_json::json!({});
    let target = ToolTarget {
        server: "s",
        tool: "write",
        arguments: &args,
    };
    let refusal = tool_policy_refusal(&policy, target).expect_err("denied");
    let id = refusal.rule_id.clone().expect("the refusal names its rule");
    let hex = id.as_str().trim_start_matches("tool_policy:");
    assert!(!refusal.message.contains(hex), "{}", refusal.message);
    assert!(!format!("{refusal:?}").contains(hex), "{refusal:?}");
}
