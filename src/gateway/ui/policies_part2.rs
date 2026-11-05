// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The Policies read model, part 2: the offered scan types with their sides
//! and preconditions, the guards, the credentials pair and the relay. Every
//! setting is reported with the file's value (the published generation) and
//! the value the gateway enforces: the generation for the fields a reload
//! applies, the running config for the restart-only ones, and the
//! generation's compiled relay view for the relay's live fields.

use serde_json::{Value, json};

use super::policies::Sources;
use super::policies_rules::{decides, name, offered};
use crate::security::firewall::memory_scanner::MemoryScanner;
use crate::security::firewall::tenant_guard::CrossTenantReads;
use crate::security::firewall::{
    CollusionAction, CollusionView, FirewallAction, FirewallConfig, FirewallRule,
    SENSITIVE_CLASSES, ScanType,
};
use crate::security::posture::SecurityPosture;

const FW: &str = "security.firewall";

/// One setting: its path, the file's value, the enforced value and whether
/// they differ (the screen says "takes effect after restart").
fn setting(path: &str, file: Value, enforced: Value) -> Value {
    let pending = file != enforced;
    setting_pending(path, file, enforced, pending)
}

fn setting_pending(path: &str, file: Value, enforced: Value, pending: bool) -> Value {
    let mut s = serde_json::Map::new();
    s.insert("path".to_owned(), Value::from(path));
    s.insert("file".to_owned(), file);
    s.insert("enforced".to_owned(), enforced);
    s.insert("pending_restart".to_owned(), Value::Bool(pending));
    Value::Object(s)
}

/// A switch, `on` when its enforced value is.
fn switch(path: &str, file: bool, enforced: bool) -> Value {
    let mut s = setting(path, json!(file), json!(enforced));
    s["on"] = json!(enforced);
    s
}

fn fw_path(field: &str) -> String {
    format!("{FW}.{field}")
}

/// The four firewall-dependent sections of the read model.
pub(super) fn sections(sources: &Sources<'_>) -> [(&'static str, Value); 4] {
    let file = &sources.generation.config().security.firewall;
    let run = &sources.running.security.firewall;
    let posture = sources.running.security.posture;
    [
        ("scan_types", scan_types(file, run)),
        ("guards", guards(file, run, posture)),
        ("credentials", credentials(file, run)),
        (
            "relay",
            relay(file, run, sources.generation.collusion_view()),
        ),
    ]
}

/// Each offered type with its side and preconditions; produced when every
/// precondition's enforced value is on.
fn scan_types(file: &FirewallConfig, run: &FirewallConfig) -> Value {
    let types: Vec<Value> = offered()
        .into_iter()
        .map(|t| {
            let firewall = switch(&fw_path("enabled"), file.enabled, run.enabled);
            let (side, mut pre) = match t {
                ScanType::Credentials | ScanType::PromptInjection => (
                    "answer",
                    vec![
                        firewall,
                        switch(
                            &fw_path("scan_responses"),
                            file.scan_responses,
                            run.scan_responses,
                        ),
                    ],
                ),
                _ => (
                    "call",
                    vec![
                        firewall,
                        switch(
                            &fw_path("scan_requests"),
                            file.scan_requests,
                            run.scan_requests,
                        ),
                    ],
                ),
            };
            match t {
                // Live: applied through the generation.
                ScanType::Credentials => pre.push(switch(
                    &fw_path("credential_redaction"),
                    file.credential_redaction,
                    file.credential_redaction,
                )),
                ScanType::PromptInjection => pre.push(switch(
                    &fw_path("prompt_injection_detection"),
                    file.prompt_injection_detection,
                    run.prompt_injection_detection,
                )),
                ScanType::MemoryPoisoning => {
                    let (f, r) = (&file.memory_poisoning, &run.memory_poisoning);
                    pre.push(switch(
                        &fw_path("memory_poisoning.enabled"),
                        f.enabled,
                        r.enabled,
                    ));
                    pre.push(tool_list(f.scan_tools.clone(), r));
                }
                _ => {}
            }
            let produced = pre.iter().all(|p| p["on"] == json!(true));
            json!({ "type": name(t), "sides": [side], "preconditions": pre, "produced": produced })
        })
        .collect();
    Value::Array(types)
}

/// The memory scanner's tool list. It is on when some entry can match a
/// tool, as the scanner itself judges it: a tool named like the entry is
/// matched only when the entry can match at all.
fn tool_list(
    file: Vec<String>,
    run: &crate::security::firewall::memory_scanner::MemoryPoisoningConfig,
) -> Value {
    let scanner = MemoryScanner::new(run.clone());
    let on = run
        .scan_tools
        .iter()
        .any(|e| scanner.is_memory_write_tool(e));
    let mut s = setting(
        &fw_path("memory_poisoning.scan_tools"),
        Value::from(file),
        json!(run.scan_tools),
    );
    s["on"] = json!(on);
    s
}

/// The anomaly, tenant and budget guards and the cross-tenant read verdict,
/// all restart-only, so enforced from the running config.
fn guards(file: &FirewallConfig, run: &FirewallConfig, posture: SecurityPosture) -> Value {
    let s = |field: &str, f: Value, r: Value| setting(&fw_path(field), f, r);
    let mut anomaly_proof = vec!["blind_no_identity"];
    if posture == SecurityPosture::Hardened {
        anomaly_proof.push("blind_map_full");
    }
    if run.anomaly_block_threshold.is_some() {
        anomaly_proof.push("forced_block");
    }
    let (ft, rt) = (&file.tenant_guard, &run.tenant_guard);
    let (fb, rb) = (&file.budget, &run.budget);
    let reads_effect = match rt.cross_tenant_reads {
        CrossTenantReads::Off => "checks_nothing",
        CrossTenantReads::Observe => "flags_and_delivers",
        CrossTenantReads::Block => "withholds_frame",
    };
    json!({
        "anomaly": {
            "running": run.enabled && run.anomaly_detection,
            "settings": [
                s("anomaly_detection", json!(file.anomaly_detection), json!(run.anomaly_detection)),
                s("anomaly_threshold", json!(file.anomaly_threshold), json!(run.anomaly_threshold)),
                s("anomaly_block_threshold", json!(file.anomaly_block_threshold), json!(run.anomaly_block_threshold)),
                s("anomaly_min_observations", json!(file.anomaly_min_observations), json!(run.anomaly_min_observations)),
            ],
            "rule_proof": anomaly_proof,
            "rule_decidable": ["low_anomaly"],
        },
        "tenant": {
            "running": run.enabled && rt.enabled,
            "settings": [
                s("tenant_guard.enabled", json!(ft.enabled), json!(rt.enabled)),
                s("tenant_guard.max_tenants_per_window", json!(ft.max_tenants_per_window), json!(rt.max_tenants_per_window)),
                s("tenant_guard.window_secs", json!(ft.window_secs), json!(rt.window_secs)),
                s("tenant_guard.arg_keys", json!(ft.arg_keys), json!(rt.arg_keys)),
            ],
            "rule_proof": ["unattributable_read"],
            "rule_decidable": ["tenant_limit"],
        },
        "budget": {
            "running": run.enabled && rb.enabled,
            "settings": [
                s("budget.enabled", json!(fb.enabled), json!(rb.enabled)),
                s("budget.max_calls_per_window", json!(fb.max_calls_per_window), json!(rb.max_calls_per_window)),
                s("budget.window_secs", json!(fb.window_secs), json!(rb.window_secs)),
            ],
            "rule_proof": ["budget_limit", "budget_unattributable"],
            "rule_decidable": [],
        },
        // It reads no firewall switch: it judges whenever `arg_keys`
        // attributes tenants and its mode is not `off`
        // (`outbound/judge.rs` `judging`).
        "tenant_reads": {
            "running": !rt.arg_keys.is_empty() && rt.cross_tenant_reads != CrossTenantReads::Off,
            "mode": s("tenant_guard.cross_tenant_reads", json!(ft.cross_tenant_reads), json!(rt.cross_tenant_reads)),
            "effect": reads_effect,
            "rule_proof": ["cross_tenant_read"],
        },
    })
}

/// Exactly `{match: "*", scan: [credentials], action: warn}` and nothing
/// else: the rule the screen writes, so saving again is idempotent.
fn is_pinned(rule: &FirewallRule) -> bool {
    let FirewallRule {
        tool_match,
        action,
        reason,
        scan,
        servers,
        keys,
        except,
        allowed_roots,
        path_args,
    } = rule;
    tool_match == "*"
        && *action == FirewallAction::Warn
        && scan.as_slice() == [ScanType::Credentials]
        && reason.is_none()
        && servers.is_none()
        && keys.is_none()
        && except.is_none()
        && allowed_roots.is_none()
        && path_args.is_none()
}

/// An `except` entry that excludes every call: no key, no server (a server
/// glob never covers a call with no backend), and no tool or exactly `*`.
fn excludes_every_call(rule: &FirewallRule) -> bool {
    rule.except.iter().flatten().any(|e| {
        e.key.is_none() && e.server.is_none() && e.tool.as_deref().is_none_or(|t| t == "*")
    })
}

/// The redaction switch, `scan_responses`, the firewall switch, and the
/// pinned rule with the earlier rules that decide credentials before it.
fn credentials(file: &FirewallConfig, run: &FirewallConfig) -> Value {
    let rules = &file.rules;
    let pinned_rule = match rules.iter().position(is_pinned) {
        None => json!({
            "present": false, "position": null, "path": null,
            "shadowed_by": null, "partly_shadowed_by": null,
        }),
        Some(at) => {
            let (mut full, mut partly) = (Vec::new(), Vec::new());
            for (j, earlier) in rules[..at].iter().enumerate() {
                if !decides(earlier).contains(&ScanType::Credentials)
                    || excludes_every_call(earlier)
                {
                    continue;
                }
                let path = format!("{FW}.rules[{j}]");
                let unscoped =
                    earlier.servers.is_none() && earlier.keys.is_none() && earlier.except.is_none();
                if earlier.tool_match == "*" && unscoped {
                    full.push(path);
                } else {
                    partly.push(path);
                }
            }
            json!({
                "present": true, "position": at, "path": format!("{FW}.rules[{at}]"),
                "shadowed_by": full, "partly_shadowed_by": partly,
            })
        }
    };
    json!({
        // Live: applied through the generation.
        "redaction": switch(&fw_path("credential_redaction"), file.credential_redaction, file.credential_redaction),
        "scan_responses": switch(&fw_path("scan_responses"), file.scan_responses, run.scan_responses),
        "firewall": switch(&fw_path("enabled"), file.enabled, run.enabled),
        "pinned_rule": pinned_rule,
        // A credential in a protected member of an interim question or a
        // challenge still refuses the whole artifact (ADR-029, Credentials).
        "scope_note": "interim_questions_and_challenges_refused",
    })
}

/// The relay: its four live fields as the file has them and as the gate
/// enforces them (the generation's compiled view), the detector settings,
/// the firewall precondition and the gate's inferred classes.
fn relay(file: &FirewallConfig, run: &FirewallConfig, view: &CollusionView) -> Value {
    let c = &file.collusion;
    let path = |field: &str| format!("{FW}.collusion.{field}");
    // Waiting for a restart means the gate would enforce something else if
    // the file applied: compare what compiling the file gives, so entries
    // the compiler drops (an `off` config is not validated) never count.
    let wanted = CollusionView::compile(c);
    let (want_sources, want_non_egress, want_flows) = wanted.lists();
    let (sources, non_egress, flows) = view.lists();
    let flow_json = |f: &[(String, String)]| -> Value {
        json!(
            f.iter()
                .map(|(s, e)| json!({ "source": s, "egress": e }))
                .collect::<Vec<_>>()
        )
    };
    let effect = match view.action() {
        CollusionAction::Off => "checks_nothing",
        CollusionAction::Observe => "records_and_allows",
        CollusionAction::Block => "refuses_relays_and_unkeyed_egress",
    };
    let (rc, s) = (&run.collusion, |f: &str, a: Value, b: Value| {
        setting(&path(f), a, b)
    });
    json!({
        "action": setting_pending(&path("action"), json!(c.action), json!(view.action()), wanted.action() != view.action()),
        "effect": effect,
        "sources": setting_pending(&path("sources"), json!(c.sources), json!(sources), want_sources != sources),
        "non_egress": setting_pending(&path("non_egress"), json!(c.non_egress), json!(non_egress), want_non_egress != non_egress),
        "allowed_flows": setting_pending(&path("allowed_flows"), json!(c.allowed_flows), flow_json(&flows), want_flows != flows),
        "detector": [
            s("window_secs", json!(c.window_secs), json!(rc.window_secs)),
            s("min_matches", json!(c.min_matches), json!(rc.min_matches)),
            s("common_principals", json!(c.common_principals), json!(rc.common_principals)),
        ],
        "firewall": switch(&fw_path("enabled"), file.enabled, run.enabled),
        "inferred_classes": SENSITIVE_CLASSES,
        "read_only": true,
    })
}
