// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Kani proofs for the firewall action defaults.

use super::*;

fn any_firewall_action() -> FirewallAction {
    match kani::any::<u8>() % 3 {
        0 => FirewallAction::Allow,
        1 => FirewallAction::Warn,
        _ => FirewallAction::Block,
    }
}

fn any_severity() -> Severity {
    match kani::any::<u8>() % 3 {
        0 => Severity::High,
        1 => Severity::Medium,
        _ => Severity::Low,
    }
}

#[kani::proof]
fn firewall_action_resolution_contract() {
    let has_findings: bool = kani::any();
    let has_matching_rule: bool = kani::any();

    let highest_severity = if has_findings {
        Some(any_severity())
    } else {
        None
    };
    let matching_rule_action = if has_matching_rule {
        Some(any_firewall_action())
    } else {
        None
    };

    let action = decide_firewall_action(matching_rule_action, highest_severity);

    match highest_severity {
        None => assert_eq!(action, FirewallAction::Allow),
        Some(severity) => {
            if let Some(rule_action) = matching_rule_action {
                assert_eq!(action, rule_action);
            } else {
                assert_eq!(action, default_action_for_severity(severity));
            }
        }
    }
}
