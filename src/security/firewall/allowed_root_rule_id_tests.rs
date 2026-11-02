// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A folder rule's refusal names that rule; a content rule at the same
//! action is named before it.

use serde_json::{Value, json};

use super::super::*;
use super::tree::{Fx, root_rule};
use crate::gateway::record_principal::test_record_key;
use crate::security::firewall::{FirewallPolicy, FirewallRule, ScanType};
use crate::security::response_policy::{KeyOf, RuleTarget, ServerOf};
use crate::security::rule_id::RuleId;

fn id(rule: &FirewallRule) -> RuleId {
    let bytes = serde_json::to_vec(rule).expect("serialises");
    RuleId::of("firewall", &test_record_key().rule_id_key(), &bytes)
}

/// The rule the keyed policy names for `args`, and whether it refused.
fn decided(fx: &Fx, args: &Value) -> (bool, Option<RuleId>) {
    let policy =
        FirewallPolicy::compile_keyed(fx.fw.config_for_test(), &test_record_key().rule_id_key());
    let target = RuleTarget {
        server: ServerOf::Backend("fs"),
        tool: "read_file",
        key: KeyOf::NoKey,
    };
    let sender = fx.sender();
    let (verdict, rule) =
        fx.fw
            .check_request_attributed(&policy, "s1", target, args, "c", "id-1", sender.as_deref());
    (!verdict.allowed, rule.cloned())
}

#[test]
fn a_folder_only_refusal_names_the_folder_rule() {
    let fx = Fx::new(&["path"], FirewallAction::Block);
    let rule = fx.fw.config_for_test().rules[0].clone();
    let (refused, named) = decided(&fx, &json!({"path": fx.path("outside/f")}));
    assert!(refused);
    assert_eq!(named, Some(id(&rule)));
}

#[test]
fn a_forced_folder_refusal_names_the_folder_rule() {
    let fx = Fx::new(&["path"], FirewallAction::Block);
    let rule = fx.fw.config_for_test().rules[0].clone();
    // A path argument that is not a string cannot be checked: a forced block.
    let (refused, named) = decided(&fx, &json!({"path": 7}));
    assert!(refused);
    assert_eq!(named, Some(id(&rule)));
}

#[test]
fn a_content_and_a_folder_rule_at_block_name_the_content_rule() {
    let fx = Fx::with_rules(|safe| {
        let folder = root_rule("read_file", &[safe], &["path"], FirewallAction::Block);
        let mut content = root_rule("read_file", &[], &[], FirewallAction::Block);
        content.allowed_roots = None;
        content.path_args = None;
        content.scan = vec![ScanType::Credentials];
        vec![folder, content]
    });
    let content = fx.fw.config_for_test().rules[1].clone();
    let token = format!("ghp_{}", "abcdefghijklmnopqrstuvwxyz1234567890");
    let (refused, named) = decided(&fx, &json!({"path": fx.path("outside/f"), "note": token}));
    assert!(refused);
    assert_eq!(named, Some(id(&content)));
}
