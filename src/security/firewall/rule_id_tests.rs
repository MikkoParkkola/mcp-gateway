// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which configured rule decided a request verdict, by its keyed id. A
//! recorded rule always decided the action that refused; a verdict the
//! severity fallback decided names none.

use super::*;
use crate::gateway::record_principal::test_record_key;
use crate::security::Severity;
use crate::security::response_policy::{KeyOf, RuleTarget, ServerOf};
use crate::security::rule_id::RuleId;

fn rule(tool_match: &str, scan: &[ScanType], action: FirewallAction) -> FirewallRule {
    FirewallRule {
        tool_match: tool_match.to_string(),
        action,
        reason: None,
        scan: scan.to_vec(),
        servers: None,
        keys: None,
        except: None,
        allowed_roots: None,
        path_args: None,
    }
}

fn id(rule: &FirewallRule) -> RuleId {
    let bytes = serde_json::to_vec(rule).expect("serialises");
    RuleId::of("firewall", &test_record_key().rule_id_key(), &bytes)
}

fn policy(rules: &[FirewallRule]) -> FirewallPolicy {
    let config = FirewallConfig {
        rules: rules.to_vec(),
        ..FirewallConfig::default()
    };
    FirewallPolicy::compile_keyed(&config, &test_record_key().rule_id_key())
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

/// The action and the rule named for `found` on tool `t` under `key`.
fn resolve(
    rules: &[FirewallRule],
    key: KeyOf<'_>,
    found: &[(ScanType, Severity)],
) -> (FirewallAction, Option<RuleId>) {
    let policy = policy(rules);
    let findings: Vec<Finding> = found.iter().map(|&(t, s)| finding(t, s)).collect();
    let target = RuleTarget {
        server: ServerOf::Backend("s"),
        tool: "t",
        key,
    };
    let (action, named) = Firewall::resolve_attributed(&policy, target, &findings);
    (action, named.cloned())
}

#[test]
fn a_rule_block_records_its_rule_id() {
    let block = rule("t", &[ScanType::Credentials], FirewallAction::Block);
    assert_eq!(
        resolve(std::slice::from_ref(&block), KeyOf::NoKey, &[CREDENTIAL]),
        (FirewallAction::Block, Some(id(&block)))
    );
}

#[test]
fn severity_block_beside_a_rule_warn_records_no_rule() {
    let warn = rule("t", &[ScanType::Credentials], FirewallAction::Warn);
    // The shell finding has no rule: its High severity blocks.
    assert_eq!(
        resolve(&[warn], KeyOf::NoKey, &[CREDENTIAL, SHELL]),
        (FirewallAction::Block, None)
    );
}

#[test]
fn severity_block_beside_a_rule_block_records_the_rule() {
    let block = rule("t", &[ScanType::Credentials], FirewallAction::Block);
    assert_eq!(
        resolve(
            std::slice::from_ref(&block),
            KeyOf::NoKey,
            &[SHELL, CREDENTIAL]
        ),
        (FirewallAction::Block, Some(id(&block)))
    );
}

#[test]
fn two_rules_at_block_name_the_first_in_finding_order() {
    let on_credentials = rule("t", &[ScanType::Credentials], FirewallAction::Block);
    let on_shell = rule("t", &[ScanType::ShellInjection], FirewallAction::Block);
    let rules = [on_credentials.clone(), on_shell.clone()];
    assert_eq!(
        resolve(&rules, KeyOf::NoKey, &[SHELL, CREDENTIAL]),
        (FirewallAction::Block, Some(id(&on_shell)))
    );
    assert_eq!(
        resolve(&rules, KeyOf::NoKey, &[CREDENTIAL, SHELL]),
        (FirewallAction::Block, Some(id(&on_credentials)))
    );
}

#[test]
fn an_unlisted_key_names_its_strongest_candidate_keys_rule() {
    let mut for_a = rule("t", &[ScanType::Credentials], FirewallAction::Warn);
    for_a.keys = Some(vec!["a".to_string()]);
    let mut for_b = rule("t", &[ScanType::Credentials], FirewallAction::Block);
    for_b.keys = Some(vec!["b".to_string()]);
    assert_eq!(
        resolve(&[for_a, for_b.clone()], KeyOf::NotKnown, &[CREDENTIAL]),
        (FirewallAction::Block, Some(id(&for_b)))
    );
}

#[test]
fn a_malformed_firewall_rule_keeps_its_configured_rules_id() {
    let malformed = rule("[", &[ScanType::Credentials], FirewallAction::Allow);
    assert_eq!(
        resolve(
            std::slice::from_ref(&malformed),
            KeyOf::NoKey,
            &[CREDENTIAL]
        ),
        (FirewallAction::Block, Some(id(&malformed)))
    );
}

#[test]
fn minimal_firewall_rule_serialises_to_exactly() {
    let minimal = rule("t", &[], FirewallAction::Block);
    let value = serde_json::to_value(&minimal).expect("serialises");
    let mut keys: Vec<&str> = value
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["action", "match", "reason", "scan"]);
}

#[test]
fn firewall_rule_bytes_and_id_are_pinned() {
    let minimal = rule("t", &[], FirewallAction::Block);
    assert_eq!(
        serde_json::to_string(&minimal).expect("serialises"),
        r#"{"match":"t","action":"block","reason":null,"scan":[]}"#
    );
    let maximal = maximal();
    assert_eq!(
        serde_json::to_string(&maximal).expect("serialises"),
        MAXIMAL_BYTES
    );
    assert_eq!(id(&minimal).as_str(), MINIMAL_ID);
    assert_eq!(id(&maximal).as_str(), MAXIMAL_ID);
}

/// Derived outside the crate (HKDF-SHA-256 of the test record key, empty
/// salt, info `decision.rule_id.v1`; then HMAC-SHA-256 of the bytes): a
/// change here rotates every recorded id.
const MAXIMAL_BYTES: &str = r#"{"match":"fs_*","action":"warn","reason":"r","scan":["shell_injection","credentials"],"servers":["fs","db"],"keys":["k2","k1"],"except":[{"tool":"fs_write"},{"server":"db"}],"allowed_roots":["/srv","/data"],"path_args":["path","dest"]}"#;
const MINIMAL_ID: &str =
    "firewall:ed196f652ef860c0072a542e91275571c284aeb064c9f3f2e7a67c4afc13fccf";
const MAXIMAL_ID: &str =
    "firewall:dd797779ffb5891ea649dcffb8876078aef75aadbe112dcae1f2ce513ae20aa8";

#[test]
fn two_rules_on_one_key_and_finding_name_the_first_in_rule_order() {
    let first = rule("t", &[ScanType::Credentials], FirewallAction::Block);
    let mut second = first.clone();
    second.reason = Some("second".to_string());
    assert_eq!(
        resolve(&[first.clone(), second], KeyOf::NoKey, &[CREDENTIAL]),
        (FirewallAction::Block, Some(id(&first)))
    );
}

/// Only (key a, shell) and (key b, credential) are rule-decided Blocks, by two
/// different rules; key-major order meets (a, shell) first, finding-major
/// order would meet (b, credential) first.
#[test]
fn a_sparse_key_by_finding_grid_names_the_key_major_winner() {
    let mut a_shell = rule("t", &[ScanType::ShellInjection], FirewallAction::Block);
    a_shell.keys = Some(vec!["a".to_string()]);
    let mut b_credential = rule("t", &[ScanType::Credentials], FirewallAction::Block);
    b_credential.keys = Some(vec!["b".to_string()]);
    let low = |t| (t, Severity::Low);
    let (action, named) = resolve(
        &[a_shell.clone(), b_credential],
        KeyOf::NotKnown,
        &[low(ScanType::Credentials), low(ScanType::ShellInjection)],
    );
    assert_eq!(action, FirewallAction::Block);
    assert_eq!(named, Some(id(&a_shell)));
}

#[test]
fn reordering_a_list_changes_only_that_rules_id() {
    let base = maximal();
    let untouched = rule("other", &[], FirewallAction::Block);
    let mut reordered = base.clone();
    reordered.scan.reverse();
    assert_ne!(id(&base), id(&reordered));
    for edit in [
        |r: &mut FirewallRule| r.servers.as_mut().expect("servers").reverse(),
        |r: &mut FirewallRule| r.keys.as_mut().expect("keys").reverse(),
        |r: &mut FirewallRule| r.except.as_mut().expect("except").reverse(),
        |r: &mut FirewallRule| r.allowed_roots.as_mut().expect("roots").reverse(),
        |r: &mut FirewallRule| r.path_args.as_mut().expect("args").reverse(),
    ] {
        let mut edited = base.clone();
        edit(&mut edited);
        assert_ne!(id(&base), id(&edited));
    }
    assert_eq!(id(&untouched), id(&untouched.clone()));
}

/// Every list holds at least two entries, deliberately unsorted.
fn maximal() -> FirewallRule {
    FirewallRule {
        tool_match: "fs_*".to_string(),
        action: FirewallAction::Warn,
        reason: Some("r".to_string()),
        scan: vec![ScanType::ShellInjection, ScanType::Credentials],
        servers: Some(vec!["fs".to_string(), "db".to_string()]),
        keys: Some(vec!["k2".to_string(), "k1".to_string()]),
        except: Some(vec![
            RuleException {
                server: None,
                tool: Some("fs_write".to_string()),
                key: None,
            },
            RuleException {
                server: Some("db".to_string()),
                tool: None,
                key: None,
            },
        ]),
        allowed_roots: Some(vec!["/srv".to_string(), "/data".to_string()]),
        path_args: Some(vec!["path".to_string(), "dest".to_string()]),
    }
}

/// The startup policy, compiled without a key, names no rule: an unkeyed id
/// would let a reader of the log test guesses about a short rule.
#[test]
fn an_unkeyed_compile_names_no_rule() {
    let block = rule("t", &[ScanType::Credentials], FirewallAction::Block);
    let config = FirewallConfig {
        rules: vec![block],
        ..FirewallConfig::default()
    };
    let policy = FirewallPolicy::compile(&config);
    let target = RuleTarget {
        server: ServerOf::Backend("s"),
        tool: "t",
        key: KeyOf::NoKey,
    };
    let findings = [finding(CREDENTIAL.0, CREDENTIAL.1)];
    let (action, named) = Firewall::resolve_attributed(&policy, target, &findings);
    assert_eq!((action, named), (FirewallAction::Block, None));
}

/// The relay refusals come from the collusion detector, not a configured
/// rule: both sites note kind firewall with no rule.
#[test]
fn the_relay_refusals_note_no_rule() {
    for (file, source) in [
        (
            "meta_mcp/invoke/relay.rs",
            include_str!("../../gateway/meta_mcp/invoke/relay.rs"),
        ),
        (
            "router/backend_handlers/relay.rs",
            include_str!("../../gateway/router/backend_handlers/relay.rs"),
        ),
    ] {
        let flat: String = source.split_whitespace().collect();
        assert!(
            flat.contains("DecisionKind::Firewall,None"),
            "{file}: a relay refusal must note no rule"
        );
    }
}

#[path = "allow_provenance_tests.rs"]
mod allow_provenance;
