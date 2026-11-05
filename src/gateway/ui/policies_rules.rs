// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The finding rules in the Policies read model: each rule as written, its
//! editability, the earlier rules that shadow it per scan type
//! (conservatively), and the surfaces where its scope applies differently.

use serde_json::{Value, json};

use crate::security::firewall::{FirewallAction, FirewallRule, OUTPUT_ONLY, ScanType};

/// Every scan type, in `ScanType` order. The match below fails to compile
/// when a type is added, so this list cannot fall behind.
const ALL: [ScanType; 13] = [
    ScanType::Credentials,
    ScanType::Pii,
    ScanType::PromptInjection,
    ScanType::ShellInjection,
    ScanType::PathTraversal,
    ScanType::SqlInjection,
    ScanType::SequenceAnomaly,
    ScanType::MemoryPoisoning,
    ScanType::CrossTenantReach,
    ScanType::BudgetExceeded,
    ScanType::CollusionRelay,
    ScanType::PathOutsideRoot,
    ScanType::RootRefused,
];

#[allow(dead_code)]
fn every_type_is_listed(t: ScanType) {
    match t {
        ScanType::Credentials
        | ScanType::Pii
        | ScanType::PromptInjection
        | ScanType::ShellInjection
        | ScanType::PathTraversal
        | ScanType::SqlInjection
        | ScanType::SequenceAnomaly
        | ScanType::MemoryPoisoning
        | ScanType::CrossTenantReach
        | ScanType::BudgetExceeded
        | ScanType::CollusionRelay
        | ScanType::PathOutsideRoot
        | ScanType::RootRefused => {}
    }
}

/// How the screen treats a scan type: whether it offers it (ADR-029's six)
/// and whether a rule decides it. Exhaustive, so a new type fails to compile
/// until it is classified for both.
const fn class(t: ScanType) -> (bool, bool) {
    match t {
        ScanType::Credentials
        | ScanType::PromptInjection
        | ScanType::ShellInjection
        | ScanType::PathTraversal
        | ScanType::SqlInjection
        | ScanType::MemoryPoisoning => (true, true),
        // Their ordinary findings pass through the rules (ADR-029 F1b).
        ScanType::SequenceAnomaly | ScanType::CrossTenantReach => (false, true),
        // No scanner produces `pii`; both budget outcomes force a block past
        // the rules; the relay gate alone decides a relay.
        ScanType::Pii | ScanType::BudgetExceeded | ScanType::CollusionRelay => (false, false),
        // Output-only: the folder check produces them and no rule lists them.
        ScanType::PathOutsideRoot | ScanType::RootRefused => (false, false),
    }
}

/// The scan types a rule's `scan` may list: every type but the loader's
/// output-only ones.
fn rule_listable() -> Vec<ScanType> {
    ALL.into_iter()
        .filter(|t| !OUTPUT_ONLY.contains(t))
        .collect()
}

/// The scan types the Policies screen offers, in `ScanType` order.
pub(super) fn offered() -> Vec<ScanType> {
    ALL.into_iter().filter(|t| class(*t).0).collect()
}

/// The scan types a rule decides, in `ScanType` order.
fn decided() -> Vec<ScanType> {
    rule_listable()
        .into_iter()
        .filter(|t| class(*t).1)
        .collect()
}

/// A scan type's config spelling.
pub(super) fn name(t: ScanType) -> String {
    serde_json::to_value(t)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// Where a rule scoped by key resolves its key as not known, and where a
/// rule scoped by server has its backend expanded over the registry. Each
/// label names one production site that builds `KeyOf::NotKnown` or
/// `TargetOrigin::NoBackend` and reaches rule resolution; a source pin keeps
/// the two lists and those sites in step.
pub(super) const KEY_NOT_KNOWN: [&str; 7] = [
    "event_delivery",
    "task_settlement",
    "outbound_rescan",
    "backend_error",
    "notification",
    "stored_task",
    "discovery",
];
pub(super) const BACKEND_EXPANDED: [&str; 4] = [
    "notification",
    "stored_task",
    "discovery",
    "aggregate_answer",
];

/// The types `rule` decides: those of its `scan` a rule decides, or every
/// such type when `scan` is empty; none for a root rule.
/// A root rule decides only its own findings, never a content finding.
pub(super) fn decides(rule: &FirewallRule) -> Vec<ScanType> {
    if is_root(rule) {
        return Vec::new();
    }
    let decided = decided();
    let mut types: Vec<ScanType> = if rule.scan.is_empty() {
        decided
    } else {
        rule.scan
            .iter()
            .copied()
            .filter(|t| decided.contains(t))
            .collect()
    };
    types.sort_by_key(|t| ALL.iter().position(|a| a == t));
    types.dedup();
    types
}

fn is_root(rule: &FirewallRule) -> bool {
    rule.allowed_roots.is_some() || rule.path_args.is_some()
}

/// Every finding rule, in order.
pub(super) fn finding_rules(rules: &[FirewallRule]) -> Value {
    let offered = offered();
    let out: Vec<Value> = rules
        .iter()
        .enumerate()
        .map(|(i, rule)| {
            let reasons = read_only_reasons(rule, &offered);
            json!({
                "path": format!("security.firewall.rules[{i}]"),
                "match": rule.tool_match,
                "servers": rule.servers,
                "keys": rule.keys,
                "except": rule.except.as_ref().map(|entries| entries
                    .iter()
                    .map(|e| json!({ "server": e.server, "tool": e.tool, "key": e.key }))
                    .collect::<Vec<_>>()),
                "scan": rule.scan.iter().map(|t| name(*t)).collect::<Vec<_>>(),
                "action": rule.action,
                "reason": rule.reason,
                "allowed_roots": rule.allowed_roots,
                "path_args": rule.path_args,
                "root": is_root(rule),
                "editable": reasons.is_empty(),
                "read_only_reasons": reasons,
                "shadowed": shadowed(rules, i),
                "scope_differs": scope_differs(rule),
            })
        })
        .collect();
    Value::Array(out)
}

/// Why `rule` is read-only, in vocabulary order: empty when the save path
/// can edit it. Every field is named here, so a new field fails to compile
/// until it is classified.
fn read_only_reasons(rule: &FirewallRule, offered: &[ScanType]) -> Vec<&'static str> {
    let FirewallRule {
        tool_match: _,
        action,
        reason,
        scan,
        servers,
        keys,
        except,
        allowed_roots,
        path_args,
    } = rule;
    let mut out = Vec::new();
    if *action == FirewallAction::Allow {
        out.push("allow");
    }
    if reason.is_some() {
        out.push("reason");
    }
    if scan.is_empty() {
        out.push("empty_scan");
    }
    if scan.iter().any(|t| !offered.contains(t)) {
        out.push("unoffered_type");
    }
    if servers.is_some() {
        out.push("servers");
    }
    if keys.is_some() {
        out.push("keys");
    }
    if except.is_some() {
        out.push("except");
    }
    if allowed_roots.is_some() || path_args.is_some() {
        out.push("root");
    }
    out
}

/// The earlier rules that shadow rule `i`, per type: an earlier rule with
/// `match: "*"` or the identical match, deciding the type, with no
/// `servers`, `keys` or `except` (present but empty counts as present).
fn shadowed(rules: &[FirewallRule], i: usize) -> Vec<Value> {
    let later = &rules[i];
    decides(later)
        .into_iter()
        .filter_map(|t| {
            let by: Vec<String> = rules[..i]
                .iter()
                .enumerate()
                .filter(|(_, a)| {
                    (a.tool_match == "*" || a.tool_match == later.tool_match)
                        && a.servers.is_none()
                        && a.keys.is_none()
                        && a.except.is_none()
                        && decides(a).contains(&t)
                })
                .map(|(j, _)| format!("security.firewall.rules[{j}]"))
                .collect();
            (!by.is_empty()).then(|| json!({ "scan_type": name(t), "by": by }))
        })
        .collect()
}

/// The surfaces where `rule`'s scope applies differently.
fn scope_differs(rule: &FirewallRule) -> Value {
    let except = rule.except.as_deref().unwrap_or_default();
    let keyed = rule.keys.is_some() || except.iter().any(|e| e.key.is_some());
    let served = rule.servers.is_some() || except.iter().any(|e| e.server.is_some());
    json!({
        "key_not_known": listed(keyed, &KEY_NOT_KNOWN),
        "backend_expanded": listed(served, &BACKEND_EXPANDED),
    })
}

/// `labels` when `on`, else none.
fn listed(on: bool, labels: &[&'static str]) -> Vec<&'static str> {
    if on { labels.to_vec() } else { Vec::new() }
}
