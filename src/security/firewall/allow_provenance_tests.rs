// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which firewall rule an allowed call names, kept apart from enforcement:
//! a rule letting through a finding whose default blocks ranks first, any
//! other letting-through rule last, and the lowest rank wins, then the first.

use super::super::{Finding, Firewall, FirewallAction, ScanType};
use super::{SHELL, finding, id, policy, rule};
use crate::security::Severity;
use crate::security::decision_record::{Allow, AllowRank};
use crate::security::firewall::FirewallRule;
use crate::security::response_policy::{KeyOf, RuleTarget, ServerOf};

const SQL: (ScanType, Severity) = (ScanType::SqlInjection, Severity::Medium);

type Root = (
    Finding,
    FirewallAction,
    Option<crate::security::rule_id::RuleId>,
);

/// The allow `rules` name for content `found` and decided root findings.
fn provenance(
    rules: &[FirewallRule],
    found: &[(ScanType, Severity)],
    roots: &[Root],
) -> Option<Allow> {
    let policy = policy(rules);
    let findings: Vec<Finding> = found.iter().map(|&(t, s)| finding(t, s)).collect();
    let target = RuleTarget {
        server: ServerOf::Backend("s"),
        tool: "t",
        key: KeyOf::NoKey,
    };
    Firewall::allow_provenance(&policy, target, &findings, roots)
}

fn softened(rule: &FirewallRule) -> Allow {
    Allow::by(AllowRank::FirewallSoftenedBlock, Some(id(rule)))
}

fn let_through(rule: &FirewallRule) -> Allow {
    Allow::by(AllowRank::FirewallAllow, Some(id(rule)))
}

/// R5 (ATTR.2). A suppressed High beside an independent Medium: enforcement
/// warns (the Medium's severity default), and the record names the
/// softener. Kills M6 (provenance taken from the enforcement resolver).
#[test]
fn a_softener_beside_an_independent_warn_is_named() {
    let softener = rule("t", &[ScanType::ShellInjection], FirewallAction::Allow);
    let rules = [softener.clone()];
    assert_eq!(
        super::resolve(&rules, KeyOf::NoKey, &[SHELL, SQL]).0,
        FirewallAction::Warn,
        "premise: the call warns"
    );
    assert_eq!(
        provenance(&rules, &[SHELL, SQL], &[]),
        Some(softened(&softener))
    );
}

/// R6 (ATTR.2). A warn-to-allow rule listed before a block-to-allow rule:
/// the block-to-allow rule is named. Kills M6.
#[test]
fn a_softener_listed_second_still_wins() {
    let warn_to_allow = rule("t", &[ScanType::SqlInjection], FirewallAction::Allow);
    let softener = rule("t", &[ScanType::ShellInjection], FirewallAction::Allow);
    let rules = [warn_to_allow, softener.clone()];
    assert_eq!(
        provenance(&rules, &[SQL, SHELL], &[]),
        Some(softened(&softener))
    );
}

/// R9 (ATTR.2). A block-to-warn rule alone is named at the last rank, not
/// the first. Kills M4 (ranked first) and M5 (not attributed).
#[test]
fn a_block_to_warn_rule_is_named_at_the_last_rank() {
    let to_warn = rule("t", &[ScanType::ShellInjection], FirewallAction::Warn);
    assert_eq!(
        provenance(std::slice::from_ref(&to_warn), &[SHELL], &[]),
        Some(let_through(&to_warn))
    );
}

/// R12 (ATTR.1). Non-matching rules before and after: the matched one is
/// named. Kills a collector that names the first or last rule.
#[test]
fn the_matched_rule_is_named_not_the_first() {
    let before = rule("never_called", &[], FirewallAction::Allow);
    let matched = rule("t", &[ScanType::ShellInjection], FirewallAction::Allow);
    let after = rule("t", &[ScanType::Credentials], FirewallAction::Allow);
    let rules = [before, matched.clone(), after];
    assert_eq!(provenance(&rules, &[SHELL], &[]), Some(softened(&matched)));
}

/// A clean call and a severity-only allow name nothing. A pin.
#[test]
fn no_rule_no_provenance() {
    let unrelated = rule("t", &[ScanType::Credentials], FirewallAction::Allow);
    let rules = [unrelated];
    assert_eq!(provenance(&rules, &[], &[]), None);
    assert_eq!(
        provenance(&rules, &[(ScanType::SqlInjection, Severity::Low)], &[]),
        None
    );
}

/// A root rule's own `PathOutsideRoot` finding, decided as `action`.
fn root(rule: &FirewallRule, action: FirewallAction) -> Root {
    (
        finding(ScanType::PathOutsideRoot, Severity::High),
        action,
        Some(id(rule)),
    )
}

fn root_rule(action: FirewallAction) -> FirewallRule {
    FirewallRule {
        allowed_roots: Some(vec!["/srv".to_owned()]),
        path_args: Some(vec!["path".to_owned()]),
        ..rule("t", &[], action)
    }
}

/// R14 (ATTR.2). A root finding softened to allow ranks first, over a
/// content warn-to-allow rule. Kills M8 (root findings skipped).
#[test]
fn a_root_block_to_allow_is_a_softener() {
    let softener = root_rule(FirewallAction::Allow);
    let warn_to_allow = rule("t", &[ScanType::SqlInjection], FirewallAction::Allow);
    let rules = [warn_to_allow, softener.clone()];
    let roots = [root(&softener, FirewallAction::Allow)];
    assert_eq!(
        provenance(&rules, &[SQL], &roots),
        Some(softened(&softener))
    );
}

/// R15 (ATTR.2). A root finding softened to warn is named at the last rank.
/// Kills M8.
#[test]
fn a_root_block_to_warn_is_named_at_the_last_rank() {
    let to_warn = root_rule(FirewallAction::Warn);
    let roots = [root(&to_warn, FirewallAction::Warn)];
    assert_eq!(
        provenance(std::slice::from_ref(&to_warn), &[], &roots),
        Some(let_through(&to_warn))
    );
}

/// R16 (ATTR.2). A path inside its root raises no finding, so the root rule
/// names nothing. A pin; the end-to-end form is the record row.
#[test]
fn a_root_rule_admitting_an_inside_path_names_nothing() {
    let covering = root_rule(FirewallAction::Block);
    assert_eq!(provenance(std::slice::from_ref(&covering), &[], &[]), None);
}
