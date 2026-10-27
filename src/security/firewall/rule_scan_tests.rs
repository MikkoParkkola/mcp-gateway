// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A firewall rule's `scan` list scopes it to the finding types it names.
//!
//! The list used to be ignored: a rule matching the tool decided every
//! finding, so an `allow` rule written for credentials also allowed a shell
//! injection in the same call. Each finding is now resolved on its own, by
//! the first rule whose glob covers the tool and whose list holds the
//! finding's type (empty holds all), or else by its severity default; the
//! call takes the most restrictive result.

use super::*;
use crate::security::Severity;
use serde_json::json;

fn rule(tool_match: &str, scan: &[ScanType], action: FirewallAction) -> FirewallRule {
    FirewallRule {
        tool_match: tool_match.to_string(),
        action,
        reason: None,
        scan: scan.to_vec(),
        servers: None,
        keys: None,
        except: None,
    }
}

fn firewall(rules: Vec<FirewallRule>) -> Firewall {
    Firewall::from_config(
        FirewallConfig {
            rules,
            ..FirewallConfig::default()
        },
        None,
    )
}

fn finding(scan_type: ScanType, severity: Severity) -> Finding {
    Finding {
        scan_type,
        severity,
        description: "fixture".to_string(),
        matched: "fixture".to_string(),
        location: FindingLocation::RequestArgs,
    }
}

const CREDENTIAL: (ScanType, Severity) = (ScanType::Credentials, Severity::High);
const SHELL: (ScanType, Severity) = (ScanType::ShellInjection, Severity::High);

fn resolve(fw: &Firewall, tool: &str, found: &[(ScanType, Severity)]) -> FirewallAction {
    let findings: Vec<Finding> = found.iter().map(|&(t, s)| finding(t, s)).collect();
    let target = crate::security::response_policy::RuleTarget {
        server: crate::security::response_policy::ServerOf::Backend("s"),
        tool,
        key: crate::security::response_policy::KeyOf::NoKey,
    };
    fw.resolve_action(target, &findings)
}

/// The fail-open this fixes: a credentials `allow` must not carry a shell
/// injection through with it.
#[test]
fn a_credentials_allow_rule_does_not_allow_an_injection_beside_it() {
    let fw = firewall(vec![rule(
        "*",
        &[ScanType::Credentials],
        FirewallAction::Allow,
    )]);
    assert_eq!(
        resolve(&fw, "t", &[CREDENTIAL, SHELL]),
        FirewallAction::Block
    );
}

#[test]
fn a_credentials_allow_rule_allows_a_credential_alone() {
    let fw = firewall(vec![rule(
        "*",
        &[ScanType::Credentials],
        FirewallAction::Allow,
    )]);
    assert_eq!(resolve(&fw, "t", &[CREDENTIAL]), FirewallAction::Allow);
}

/// A scoped `block` rule decides its own type; the others keep their
/// severity default (medium SQL injection warns, it is not blocked).
#[test]
fn a_block_rule_scoped_to_one_type_leaves_the_others_at_their_default() {
    let fw = firewall(vec![rule("*", &[ScanType::Pii], FirewallAction::Block)]);
    let sql = (ScanType::SqlInjection, Severity::Medium);
    assert_eq!(resolve(&fw, "t", &[sql]), FirewallAction::Warn);
    let pii = (ScanType::Pii, Severity::Low);
    assert_eq!(resolve(&fw, "t", &[pii, sql]), FirewallAction::Block);
}

/// An empty list holds every type: the rule decides the whole call, as before.
#[test]
fn an_empty_scan_list_decides_every_finding_as_before() {
    let fw = firewall(vec![rule("*", &[], FirewallAction::Allow)]);
    assert_eq!(
        resolve(&fw, "t", &[CREDENTIAL, SHELL]),
        FirewallAction::Allow
    );
    let none = firewall(vec![]);
    assert_eq!(
        resolve(&none, "t", &[CREDENTIAL, SHELL]),
        FirewallAction::Block
    );
    assert_eq!(resolve(&none, "t", &[]), FirewallAction::Allow);
}

/// Per finding, the first rule covering both the tool and the type wins.
#[test]
fn each_finding_takes_the_first_rule_covering_its_tool_and_type() {
    let fw = firewall(vec![
        rule("exec_*", &[ScanType::ShellInjection], FirewallAction::Block),
        rule("*", &[], FirewallAction::Allow),
    ]);
    assert_eq!(resolve(&fw, "exec_run", &[SHELL]), FirewallAction::Block);
    assert_eq!(resolve(&fw, "read_file", &[SHELL]), FirewallAction::Allow);
    let pii = (ScanType::Pii, Severity::Low);
    assert_eq!(resolve(&fw, "exec_run", &[pii]), FirewallAction::Allow);
}

/// End to end: a path-traversal `allow` does not open a shell injection.
#[test]
fn a_scoped_allow_rule_does_not_let_a_shell_injection_through_a_request() {
    let fw = firewall(vec![rule(
        "*",
        &[ScanType::PathTraversal],
        FirewallAction::Allow,
    )]);
    let args = json!({ "cmd": "; rm -rf /", "path": "../../../etc/passwd" });
    let verdict = fw.check_request("s1", "srv", "shell_run", &args, "caller", "s1");
    assert!(!verdict.allowed, "{verdict:?}");
    let only_path = json!({ "path": "../../../etc/passwd" });
    let verdict = fw.check_request("s1", "srv", "read_file", &only_path, "caller", "s1");
    assert!(verdict.allowed, "{verdict:?}");
}
