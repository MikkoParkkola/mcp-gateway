// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The folder check proper: which root rules cover a call, where it is sent,
//! and the path values it carries (design sections 2, 3 and 6).

use serde_json::Value;

use super::super::verdict::{candidate_keys, rule_applies};
use super::super::{Finding, FindingLocation, FirewallAction, ScanType};
use super::{CompiledRoot, Item, PathArg, RootOutcome, RootReason, RootRefusal, precheck};
use crate::security::Severity;
use crate::security::response_policy::{RuleTarget, ServerOf};

/// One covering root rule and the action that decides its findings.
struct Covering<'a> {
    root: &'a CompiledRoot,
    action: FirewallAction,
}

/// The folder check for one call: a forced refusal, or the root findings
/// each covering rule decided. Called first by both entry points.
pub(crate) fn root_check(
    firewall: &super::super::Firewall,
    target: RuleTarget<'_>,
    args: &Value,
    backend: Option<&crate::backend::Backend>,
) -> RootOutcome {
    // Native tools take no path argument (S3 pins it): never covered.
    let ServerOf::Backend(server) = target.server else {
        return RootOutcome::default();
    };
    let covering = covering(firewall, target);
    let Some(first) = covering.first() else {
        return RootOutcome::default();
    };
    let refuse = |root: &CompiledRoot, argument: Option<&str>, reason| RootOutcome {
        forced: Some(RootRefusal {
            rule: root.identity.clone(),
            argument: argument.map(str::to_string),
            reason,
        }),
        findings: Vec::new(),
    };
    if let Err(reason) = classify(firewall, server, backend) {
        return refuse(first.root, None, reason);
    }
    // Every value of every covering rule is extracted and prechecked first,
    // then judged together: one resolver slot and one deadline per call.
    let mut items = Vec::new();
    let mut owners = Vec::new();
    for rule in &covering {
        let Some(args_of_rule) = &rule.root.args else {
            return refuse(rule.root, None, RootReason::RootUnresolvable);
        };
        for arg in args_of_rule {
            let name = arg_name(arg);
            let values = match extract(args, arg) {
                Ok(values) => values,
                Err(reason) => return refuse(rule.root, Some(&name), reason),
            };
            if let Some(reason) = values.iter().find_map(|v| precheck(v)) {
                return refuse(rule.root, Some(&name), reason);
            }
            if values.is_empty() {
                continue;
            }
            items.push(Item {
                roots: rule.root.roots.clone(),
                values: values.into_iter().map(str::to_string).collect(),
            });
            owners.push((rule, name));
        }
    }
    let inside = match super::judge(firewall, items) {
        Ok(inside) => inside,
        Err((at, reason)) => {
            let (rule, name) = owners
                .get(at)
                .map_or((first, None), |(r, n)| (*r, Some(n.as_str())));
            return refuse(rule.root, name, reason);
        }
    };
    let findings = owners
        .iter()
        .zip(inside)
        .filter(|(_, inside)| !inside)
        .map(|((rule, name), _)| (outside_finding(rule.root, name), rule.action))
        .collect();
    RootOutcome {
        forced: None,
        findings,
    }
}

/// The refusal for a call whose secret injection would rewrite what the
/// folder check judged: a covering root rule declares an argument whose
/// top-level key a matching secret rule owns (`a` over a declared `a.b`).
/// Keyed on ownership, not on what is written: injection drops the
/// caller's value for an owned key even when the credential is empty.
pub(crate) fn injection_refusal(
    firewall: &super::super::Firewall,
    target: RuleTarget<'_>,
    owned: &[String],
) -> Option<String> {
    covering(firewall, target).into_iter().find_map(|rule| {
        let argument = match &rule.root.args {
            None => None,
            Some(args) => Some(args.iter().find(|a| owned.contains(&a.segments[0]))?),
        };
        let argument = argument.map_or_else(String::new, |a| format!(", argument {}", arg_name(a)));
        Some(format!(
            "injected_path_argument: rule {}{argument}",
            rule.root.identity
        ))
    })
}

/// The root rules that apply to `target` under any candidate key, each
/// once, in rule order: the branch's own coverage, restated nowhere.
fn covering<'a>(firewall: &'a super::super::Firewall, target: RuleTarget<'a>) -> Vec<Covering<'a>> {
    let keys = candidate_keys(&firewall.rules, target);
    firewall
        .rules
        .iter()
        .filter_map(|rule| {
            let root = rule.root.as_ref()?;
            keys.iter()
                .any(|key| rule_applies(rule, target, *key))
                .then_some(Covering {
                    root,
                    action: rule.action,
                })
        })
        .collect()
}

/// Where the call is sent, read live: a capability backend of that name
/// cannot be checked (and is ambiguous beside a config backend of the same
/// name); a config backend must be a local process. The sending instance,
/// when the caller holds it, is classified, never a fresh lookup.
fn classify(
    firewall: &super::super::Firewall,
    server: &str,
    sending: Option<&crate::backend::Backend>,
) -> Result<(), RootReason> {
    let registries = &firewall.registries;
    let Some(backends) = &registries.backends else {
        return Err(RootReason::UnknownBackend);
    };
    let capability = registries
        .capabilities
        .as_ref()
        .is_some_and(|slot| slot.read().as_ref().is_some_and(|caps| caps.name == server));
    if capability {
        return Err(if backends.get(server).is_some() {
            RootReason::AmbiguousBackend
        } else {
            RootReason::CapabilityNotCheckable
        });
    }
    let local = match sending {
        Some(instance) => instance.is_local_process(),
        None => match backends.get(server) {
            Some(live) => live.is_local_process(),
            None => return Err(RootReason::UnknownBackend),
        },
    };
    if local {
        Ok(())
    } else {
        Err(RootReason::RemoteBackend)
    }
}

/// The entry as written in `path_args`, for refusals and findings.
fn arg_name(arg: &PathArg) -> String {
    format!(
        "{}{}",
        arg.segments.join("."),
        if arg.array { "[]" } else { "" }
    )
}

/// The string values `arg` names in `args`: none when an optional argument
/// is omitted; a refusal when a required one is, or when a value has the
/// wrong type on the way or at the leaf.
fn extract<'v>(args: &'v Value, arg: &PathArg) -> Result<Vec<&'v str>, RootReason> {
    let mut at = args;
    for segment in &arg.segments {
        let Some(object) = at.as_object() else {
            return Err(RootReason::WrongType);
        };
        match object.get(segment) {
            Some(next) => at = next,
            None if arg.optional => return Ok(Vec::new()),
            None => return Err(RootReason::MissingArgument),
        }
    }
    if !arg.array {
        return at.as_str().map(|s| vec![s]).ok_or(RootReason::WrongType);
    }
    let items = at.as_array().ok_or(RootReason::WrongType)?;
    items
        .iter()
        .map(|item| item.as_str().ok_or(RootReason::WrongType))
        .collect()
}

fn outside_finding(root: &CompiledRoot, name: &str) -> Finding {
    Finding {
        scan_type: ScanType::PathOutsideRoot,
        severity: Severity::High,
        description: format!("path_outside_root: rule {}, argument {name}", root.identity),
        matched: name.to_string(),
        location: FindingLocation::RequestArgs,
    }
}

/// Fold a folder outcome into the content action: a forced refusal blocks,
/// whatever any rule says; otherwise the most restrictive of the content
/// action and each root finding's own rule action.
pub(crate) fn apply_roots(
    outcome: RootOutcome,
    content_action: FirewallAction,
) -> (FirewallAction, Vec<Finding>) {
    if let Some(refusal) = outcome.forced {
        let code = serde_json::to_value(refusal.reason)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        let argument = refusal
            .argument
            .map_or_else(String::new, |a| format!(", argument {a}"));
        let finding = Finding {
            scan_type: ScanType::RootRefused,
            severity: Severity::Critical,
            description: format!("{code}: rule {}{argument}", refusal.rule),
            matched: String::new(),
            location: FindingLocation::RequestArgs,
        };
        return (FirewallAction::Block, vec![finding]);
    }
    let rank = |a: FirewallAction| match a {
        FirewallAction::Allow => 0,
        FirewallAction::Warn => 1,
        FirewallAction::Block => 2,
    };
    let action = outcome
        .findings
        .iter()
        .map(|(_, action)| *action)
        .fold(content_action, |a, b| if rank(b) > rank(a) { b } else { a });
    (
        action,
        outcome.findings.into_iter().map(|(f, _)| f).collect(),
    )
}
