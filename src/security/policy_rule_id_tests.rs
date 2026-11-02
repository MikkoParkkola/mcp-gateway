// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which tool-policy entry decided a call, by its keyed id.

use super::{PolicyAction, ToolPolicy, ToolPolicyConfig};
use crate::gateway::record_principal::test_record_key;
use crate::security::rule_id::RuleId;

/// The id of the entry `(list, pattern as written)`.
fn id(list: &str, pattern: &str) -> RuleId {
    let bytes = serde_json::to_vec(&(list, pattern)).expect("serialises");
    RuleId::of("tool_policy", &test_record_key().rule_id_key(), &bytes)
}

fn policy(allow: &[&str], deny: &[&str], default: PolicyAction, builtin: bool) -> ToolPolicy {
    let config = ToolPolicyConfig {
        enabled: true,
        default_action: default,
        allow: allow.iter().map(|s| (*s).to_string()).collect(),
        deny: deny.iter().map(|s| (*s).to_string()).collect(),
        use_default_deny: builtin,
        log_denied: false,
    };
    ToolPolicy::from_config_keyed(&config, &test_record_key().rule_id_key())
}

/// The id that refused `tool` on server `s`.
fn refused_by(p: &ToolPolicy, tool: &str) -> Option<RuleId> {
    p.check_explained("s", tool)
        .expect_err("refused")
        .1
        .cloned()
}

/// The id that explicitly allowed `tool` on server `s`.
fn allowed_by(p: &ToolPolicy, tool: &str) -> Option<RuleId> {
    p.check_explained("s", tool).expect("allowed").cloned()
}

#[test]
fn allow_and_deny_lists_give_different_ids() {
    assert_ne!(id("allow", "foo"), id("deny", "foo"));
    let p = policy(&["foo"], &["foo"], PolicyAction::Allow, false);
    assert_eq!(allowed_by(&p, "foo"), Some(id("allow", "foo")));
}

#[test]
fn an_exact_and_a_prefix_pattern_have_different_ids() {
    assert_ne!(id("deny", "foo"), id("deny", "foo*"));
    let exact = policy(&[], &["foo"], PolicyAction::Allow, false);
    let prefix = policy(&[], &["foo*"], PolicyAction::Allow, false);
    assert_eq!(refused_by(&exact, "foo"), Some(id("deny", "foo")));
    assert_eq!(refused_by(&prefix, "foo"), Some(id("deny", "foo*")));
}

#[test]
fn a_builtin_deny_and_a_configured_deny_have_different_ids() {
    let p = policy(&[], &["write_file"], PolicyAction::Allow, true);
    assert_ne!(id("deny", "write_file"), id("builtin_deny", "write_file"));
    assert_eq!(refused_by(&p, "write_file"), Some(id("deny", "write_file")));
    let builtin_only = policy(&[], &[], PolicyAction::Allow, true);
    assert_eq!(
        refused_by(&builtin_only, "write_file"),
        Some(id("builtin_deny", "write_file"))
    );
}

#[test]
fn a_configured_prefix_deny_is_named_over_a_builtin_exact() {
    let p = policy(&[], &["write*"], PolicyAction::Allow, true);
    assert_eq!(refused_by(&p, "write_file"), Some(id("deny", "write*")));
}

#[test]
fn tool_policy_ties_resolve_exact_then_longest_prefix_then_configured_order() {
    let exact_first = policy(&[], &["fo*", "foo"], PolicyAction::Allow, false);
    assert_eq!(refused_by(&exact_first, "foo"), Some(id("deny", "foo")));
    let longest = policy(&[], &["f*", "foo*", "fo*"], PolicyAction::Allow, false);
    assert_eq!(refused_by(&longest, "food"), Some(id("deny", "foo*")));
    // The tool name and the server-qualified name both match: configured order.
    let order = policy(&[], &["s:foo", "foo"], PolicyAction::Allow, false);
    assert_eq!(refused_by(&order, "foo"), Some(id("deny", "s:foo")));
}

#[test]
fn a_default_deny_records_the_default_action_id() {
    let p = policy(&[], &["x"], PolicyAction::Deny, true);
    let default = id("default_action", "deny");
    assert_eq!(refused_by(&p, "anything"), Some(default.clone()));
    assert_ne!(default, id("deny", "x"));
    assert_ne!(default, id("builtin_deny", "write_file"));
}

#[test]
fn a_default_allow_names_no_entry() {
    let p = policy(&[], &[], PolicyAction::Allow, false);
    assert_eq!(allowed_by(&p, "anything"), None);
}

#[test]
fn an_unkeyed_policy_names_no_entry() {
    let config = ToolPolicyConfig {
        deny: vec!["x".to_string()],
        ..ToolPolicyConfig::default()
    };
    let p = ToolPolicy::from_config(&config);
    assert!(
        p.check_explained("s", "x")
            .expect_err("refused")
            .1
            .is_none()
    );
    assert!(p.check("s", "x").is_err(), "the public check still refuses");
}

#[test]
fn tool_policy_entry_bytes_are_pinned() {
    let cases = [
        (("allow", "read_*"), r#"["allow","read_*"]"#),
        (("deny", "s:write"), r#"["deny","s:write"]"#),
        (
            ("builtin_deny", "write_file"),
            r#"["builtin_deny","write_file"]"#,
        ),
        (("default_action", "deny"), r#"["default_action","deny"]"#),
        (("default_action", "allow"), r#"["default_action","allow"]"#),
    ];
    for ((list, pattern), bytes) in cases {
        assert_eq!(
            serde_json::to_string(&(list, pattern)).expect("serialises"),
            bytes
        );
    }
    // The default action's pattern is its serde name.
    for action in [PolicyAction::Allow, PolicyAction::Deny] {
        let name = serde_json::to_value(action).expect("serialises");
        assert!(matches!(name.as_str(), Some("allow" | "deny")), "{name}");
    }
    assert_eq!(id("deny", "s:write").as_str(), PINNED_DENY_ID);
}

/// Pinned from the first green run; a change here rotates every recorded id.
const PINNED_DENY_ID: &str = "PIN-DENY-ID";

/// The generation compiles both policies keyed, never through the unkeyed
/// entry points, which name no rule.
#[test]
fn the_generation_compiles_only_keyed_policies() {
    let source = include_str!("../config_reload/generation.rs");
    let code: String = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !code.contains("FirewallPolicy::compile("),
        "an unkeyed firewall compile"
    );
    assert!(
        !code.contains("ToolPolicy::from_config("),
        "an unkeyed tool-policy compile"
    );
    assert!(code.contains("FirewallPolicy::compile_keyed("));
    assert!(code.contains("ToolPolicy::from_config_keyed("));
}
