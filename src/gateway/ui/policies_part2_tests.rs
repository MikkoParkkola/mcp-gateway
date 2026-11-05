// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The Policies read model, part 2: the offered scan types with their sides
//! and preconditions, the guards, the credentials pair, the relay settings
//! and the tool limits. Every setting carries the file's value and the value
//! the gateway enforces; a reload of a restart-only field leaves them apart.

use serde_json::{Value, json};

use super::policies_test_support::{FW, read_model, reloaded, setting, switch};
use crate::config::Config;
use crate::security::firewall::memory_scanner::MemoryScanner;

/// The scan type entry `ty`.
fn scan_type<'a>(model: &'a Value, ty: &str) -> &'a Value {
    model["scan_types"]
        .as_array()
        .and_then(|types| types.iter().find(|t| t["type"] == ty))
        .unwrap_or_else(|| panic!("no scan type {ty}: {model}"))
}

/// The precondition of `ty` at `path`.
fn precondition<'a>(model: &'a Value, ty: &str, path: &str) -> &'a Value {
    scan_type(model, ty)["preconditions"]
        .as_array()
        .and_then(|p| p.iter().find(|p| p["path"] == path))
        .unwrap_or_else(|| panic!("{ty} has no precondition {path}: {model}"))
}

fn produced(model: &Value, ty: &str) -> bool {
    scan_type(model, ty)["produced"]
        .as_bool()
        .unwrap_or_else(|| panic!("{ty}.produced: {model}"))
}

const CALL_SIDE: [&str; 4] = [
    "shell_injection",
    "path_traversal",
    "sql_injection",
    "memory_poisoning",
];
const ANSWER_SIDE: [&str; 2] = ["credentials", "prompt_injection"];

/// R4a: the six offered types in `ScanType` order, each with its side and
/// its preconditions in order (firewall, the side's switch, the type's own),
/// all on by default, so each is produced.
#[test]
fn r4a_the_offered_types_with_sides_and_preconditions() {
    let model = read_model(&Config::default());
    let types: Vec<&str> = model["scan_types"]
        .as_array()
        .expect("scan_types")
        .iter()
        .map(|t| t["type"].as_str().expect("type"))
        .collect();
    assert_eq!(
        types,
        [
            "credentials",
            "prompt_injection",
            "shell_injection",
            "path_traversal",
            "sql_injection",
            "memory_poisoning"
        ]
    );
    let on = |name: &str| switch(&format!("{FW}.{name}"), true, true);
    let expected = |ty: &str| -> Vec<Value> {
        match ty {
            "credentials" => vec![
                on("enabled"),
                on("scan_responses"),
                on("credential_redaction"),
            ],
            "prompt_injection" => vec![
                on("enabled"),
                on("scan_responses"),
                on("prompt_injection_detection"),
            ],
            "memory_poisoning" => {
                let tools = json!(["remember", "batch_remember", "store", "kv_set", "kv_search"]);
                let mut list = setting(
                    &format!("{FW}.memory_poisoning.scan_tools"),
                    tools.clone(),
                    tools,
                );
                list["on"] = json!(true);
                vec![
                    on("enabled"),
                    on("scan_requests"),
                    on("memory_poisoning.enabled"),
                    list,
                ]
            }
            _ => vec![on("enabled"), on("scan_requests")],
        }
    };
    for ty in &types {
        let entry = scan_type(&model, ty);
        let side = if ANSWER_SIDE.contains(ty) {
            "answer"
        } else {
            "call"
        };
        assert_eq!(entry["sides"], json!([side]), "{ty}");
        assert_eq!(entry["preconditions"], json!(expected(ty)), "{ty}");
        assert!(produced(&model, ty), "{ty}");
    }
}

/// R4b, R4i: each type's own switch, off alone, stops that type only.
#[test]
fn r4b_a_types_own_switch_stops_that_type_alone() {
    for (field, stopped) in [
        ("prompt_injection_detection", "prompt_injection"),
        ("memory_poisoning.enabled", "memory_poisoning"),
        ("credential_redaction", "credentials"),
    ] {
        let mut config = Config::default();
        let fw = &mut config.security.firewall;
        match field {
            "prompt_injection_detection" => fw.prompt_injection_detection = false,
            "memory_poisoning.enabled" => fw.memory_poisoning.enabled = false,
            _ => fw.credential_redaction = false,
        }
        let model = read_model(&config);
        let path = format!("{FW}.{field}");
        assert_eq!(
            precondition(&model, stopped, &path),
            &switch(&path, false, false)
        );
        for ty in ANSWER_SIDE.iter().chain(&CALL_SIDE) {
            assert_eq!(produced(&model, ty), *ty != stopped, "{field}: {ty}");
        }
    }
}

/// R4c, R4h, R4f: a side's switch stops that side; the firewall switch stops
/// every type.
#[test]
fn r4c_a_sides_switch_and_the_firewall_switch() {
    let mut config = Config::default();
    config.security.firewall.scan_requests = false;
    let model = read_model(&config);
    for ty in CALL_SIDE {
        assert!(!produced(&model, ty), "{ty}");
    }
    for ty in ANSWER_SIDE {
        assert!(produced(&model, ty), "{ty}");
    }

    let mut config = Config::default();
    config.security.firewall.scan_responses = false;
    let model = read_model(&config);
    for ty in ANSWER_SIDE {
        assert!(!produced(&model, ty), "{ty}");
    }
    for ty in CALL_SIDE {
        assert!(produced(&model, ty), "{ty}");
    }

    let mut config = Config::default();
    config.security.firewall.enabled = false;
    let model = read_model(&config);
    for ty in ANSWER_SIDE.iter().chain(&CALL_SIDE) {
        assert!(!produced(&model, ty), "{ty}");
        let path = format!("{FW}.enabled");
        assert_eq!(
            precondition(&model, ty, &path),
            &switch(&path, false, false)
        );
    }
}

/// The memory scanner's tool-list precondition for `tools`.
fn tool_list(tools: &[&str]) -> Value {
    let mut config = Config::default();
    config.security.firewall.memory_poisoning.scan_tools =
        tools.iter().map(|t| (*t).to_owned()).collect();
    let model = read_model(&config);
    precondition(
        &model,
        "memory_poisoning",
        &format!("{FW}.memory_poisoning.scan_tools"),
    )
    .clone()
}

/// R4d, R4g: the tool list is reported as configured; an empty list scans
/// no tool, so `memory_poisoning` is not produced.
#[test]
fn r4d_the_memory_scanners_tool_list() {
    let list = tool_list(&["a", "b"]);
    assert_eq!(list["file"], json!(["a", "b"]));
    assert_eq!(list["enforced"], json!(["a", "b"]));
    assert_eq!(list["on"], json!(true));

    let mut config = Config::default();
    config.security.firewall.memory_poisoning.scan_tools = Vec::new();
    let model = read_model(&config);
    let path = format!("{FW}.memory_poisoning.scan_tools");
    assert_eq!(
        precondition(&model, "memory_poisoning", &path)["on"],
        json!(false)
    );
    assert!(!produced(&model, "memory_poisoning"));
}

/// R4j: whether an entry can match a tool is the scanner's own answer, so
/// the row holds before and after the scanner normalises entries: with
/// `["STORE"]`, the list is on exactly when the scanner would scan a tool
/// named `store`.
#[test]
fn r4j_the_tool_list_follows_the_scanners_matcher() {
    let mut config = Config::default();
    config.security.firewall.memory_poisoning.scan_tools = vec!["STORE".to_owned()];
    let scans = MemoryScanner::new(config.security.firewall.memory_poisoning.clone())
        .is_memory_write_tool("store");
    let model = read_model(&config);
    let path = format!("{FW}.memory_poisoning.scan_tools");
    assert_eq!(
        precondition(&model, "memory_poisoning", &path)["on"],
        json!(scans)
    );
    assert_eq!(produced(&model, "memory_poisoning"), scans);
}

/// R4e: a reload that turns `credential_redaction` (live) and
/// `scan_responses` (restart-only) off: the first is enforced at once, the
/// second waits for a restart; `produced` follows the enforced values.
#[test]
fn r4e_a_reload_applies_live_fields_and_holds_restart_only_ones() {
    let startup = Config::default();
    let mut next = startup.clone();
    next.security.firewall.credential_redaction = false;
    next.security.firewall.scan_responses = false;
    let model = reloaded(&startup, &[&next]);
    let redaction = format!("{FW}.credential_redaction");
    let responses = format!("{FW}.scan_responses");
    assert_eq!(
        precondition(&model, "credentials", &redaction),
        &switch(&redaction, false, false)
    );
    assert_eq!(
        precondition(&model, "credentials", &responses),
        &switch(&responses, false, true)
    );
    assert_eq!(
        precondition(&model, "prompt_injection", &responses),
        &switch(&responses, false, true)
    );
    assert!(!produced(&model, "credentials"), "redaction is off now");
    assert!(
        produced(&model, "prompt_injection"),
        "scan_responses still runs"
    );
}

fn guard<'a>(model: &'a Value, name: &str) -> &'a Value {
    let g = &model["guards"][name];
    assert!(g.is_object(), "no guard {name}: {model}");
    g
}

/// R5a: the four guards, off by default, each with its settings in order
/// (file and enforced values), its rule-proof cases and its rule-decidable
/// findings.
#[test]
fn r5a_the_guards_and_their_settings() {
    let model = read_model(&Config::default());
    let same = |path: &str, v: Value| setting(&format!("{FW}.{path}"), v.clone(), v);
    let anomaly = guard(&model, "anomaly");
    assert_eq!(anomaly["running"], json!(false));
    assert_eq!(
        anomaly["settings"],
        json!([
            same("anomaly_detection", json!(false)),
            same("anomaly_threshold", json!(0.7)),
            same("anomaly_block_threshold", Value::Null),
            same("anomaly_min_observations", json!(20)),
        ])
    );
    assert_eq!(anomaly["rule_proof"], json!(["blind_no_identity"]));
    assert_eq!(anomaly["rule_decidable"], json!(["low_anomaly"]));

    let tenant = guard(&model, "tenant");
    assert_eq!(tenant["running"], json!(false));
    assert_eq!(
        tenant["settings"],
        json!([
            same("tenant_guard.enabled", json!(false)),
            same("tenant_guard.max_tenants_per_window", json!(3)),
            same("tenant_guard.window_secs", json!(300)),
            same("tenant_guard.arg_keys", json!([])),
        ])
    );
    assert_eq!(tenant["rule_proof"], json!(["unattributable_read"]));
    assert_eq!(tenant["rule_decidable"], json!(["tenant_limit"]));

    let budget = guard(&model, "budget");
    assert_eq!(budget["running"], json!(false));
    assert_eq!(
        budget["settings"],
        json!([
            same("budget.enabled", json!(false)),
            same("budget.max_calls_per_window", json!(600)),
            same("budget.window_secs", json!(60)),
        ])
    );
    assert_eq!(
        budget["rule_proof"],
        json!(["budget_limit", "budget_unattributable"])
    );
    assert_eq!(budget["rule_decidable"], json!([]));

    let reads = guard(&model, "tenant_reads");
    assert_eq!(
        reads["running"],
        json!(false),
        "no arg_keys: nothing attributes"
    );
    assert_eq!(
        reads["mode"],
        same("tenant_guard.cross_tenant_reads", json!("observe"))
    );
    assert_eq!(reads["effect"], json!("flags_and_delivers"));
    assert_eq!(reads["rule_proof"], json!(["cross_tenant_read"]));
}

/// The default config with every guard switched on and a block threshold.
fn guards_on() -> Config {
    let mut config = Config::default();
    let fw = &mut config.security.firewall;
    fw.anomaly_detection = true;
    fw.anomaly_block_threshold = Some(0.9);
    fw.tenant_guard.enabled = true;
    fw.budget.enabled = true;
    config
}

/// R5b, R5b2, R5g: switched on, each guard runs; `forced_block` is listed
/// only with a block threshold; turning content scanning off leaves the
/// guards running.
#[test]
fn r5b_switched_on_guards_run() {
    let model = read_model(&guards_on());
    for name in ["anomaly", "tenant", "budget"] {
        assert_eq!(guard(&model, name)["running"], json!(true), "{name}");
    }
    assert_eq!(
        guard(&model, "anomaly")["rule_proof"],
        json!(["blind_no_identity", "forced_block"])
    );

    let mut config = guards_on();
    config.security.firewall.anomaly_block_threshold = None;
    let model = read_model(&config);
    assert_eq!(
        guard(&model, "anomaly")["rule_proof"],
        json!(["blind_no_identity"])
    );

    // Under the hardened posture a full learned-pair map refuses too.
    let mut config = guards_on();
    config.security.posture = crate::security::posture::SecurityPosture::Hardened;
    let model = read_model(&config);
    assert_eq!(
        guard(&model, "anomaly")["rule_proof"],
        json!(["blind_no_identity", "blind_map_full", "forced_block"])
    );

    let mut config = guards_on();
    config.security.firewall.scan_requests = false;
    config.security.firewall.scan_responses = false;
    let model = read_model(&config);
    for name in ["anomaly", "tenant", "budget"] {
        assert_eq!(guard(&model, name)["running"], json!(true), "{name}");
    }
}

/// R5c: with the firewall off, no guard runs.
#[test]
fn r5c_no_guard_runs_with_the_firewall_off() {
    let mut config = guards_on();
    config.security.firewall.enabled = false;
    let model = read_model(&config);
    for name in ["anomaly", "tenant", "budget"] {
        assert_eq!(guard(&model, name)["running"], json!(false), "{name}");
    }
}

/// R5d: a reload that turns a guard on waits for a restart.
#[test]
fn r5d_a_reloaded_guard_waits_for_a_restart() {
    let startup = Config::default();
    let next = guards_on();
    let model = reloaded(&startup, &[&next]);
    for (name, path) in [
        ("anomaly", "anomaly_detection"),
        ("tenant", "tenant_guard.enabled"),
        ("budget", "budget.enabled"),
    ] {
        let g = guard(&model, name);
        assert_eq!(g["running"], json!(false), "{name}");
        assert_eq!(
            g["settings"][0],
            setting(&format!("{FW}.{path}"), json!(true), json!(false)),
            "{name}"
        );
    }
}

/// R5d2: the reverse: a guard on at startup and switched off by a reload
/// keeps running until a restart.
#[test]
fn r5d2_a_guard_switched_off_by_reload_keeps_running() {
    let startup = guards_on();
    let model = reloaded(&startup, &[&Config::default()]);
    for (name, path) in [
        ("anomaly", "anomaly_detection"),
        ("tenant", "tenant_guard.enabled"),
        ("budget", "budget.enabled"),
    ] {
        let g = guard(&model, name);
        assert_eq!(g["running"], json!(true), "{name}");
        assert_eq!(
            g["settings"][0],
            setting(&format!("{FW}.{path}"), json!(false), json!(true)),
            "{name}"
        );
    }
}

/// R6i2: R6i's refused shape in a file with the firewall off, the case the
/// load lets through: it still fully shadows the pinned rule.
#[test]
fn r6i2_a_refused_shape_with_the_firewall_off() {
    let mut config = with_rules(json!([
        { "match": "foo", "action": "warn", "scan": ["credentials"], "except": [{}] },
        pinned(),
    ]));
    config.security.firewall.enabled = false;
    let model = read_model(&config);
    assert_eq!(
        model["credentials"]["pinned_rule"]["shadowed_by"],
        json!([rule_path(0)])
    );
}

/// R5e: the cross-tenant read verdict runs whenever `arg_keys` attributes
/// tenants and its mode is not `off` (`outbound/judge.rs` `judging`), with
/// the tenant guard itself off and even with the firewall switched off: the
/// gateway builds its firewall either way and the verdict reads no switch.
#[test]
fn r5e_the_read_verdict_runs_on_its_own_keys() {
    let mut config = Config::default();
    config.security.firewall.tenant_guard.arg_keys = vec!["tenant".to_owned()];
    let model = read_model(&config);
    assert_eq!(guard(&model, "tenant_reads")["running"], json!(true));
    assert_eq!(guard(&model, "tenant")["running"], json!(false));

    config.security.firewall.enabled = false;
    let model = read_model(&config);
    assert_eq!(guard(&model, "tenant_reads")["running"], json!(true));

    config.security.firewall.tenant_guard.cross_tenant_reads =
        crate::security::firewall::tenant_guard::CrossTenantReads::Off;
    let model = read_model(&config);
    let reads = guard(&model, "tenant_reads");
    assert_eq!(reads["running"], json!(false));
    assert_eq!(reads["effect"], json!("checks_nothing"));

    config.security.firewall.tenant_guard.cross_tenant_reads =
        crate::security::firewall::tenant_guard::CrossTenantReads::Block;
    let model = read_model(&config);
    assert_eq!(
        guard(&model, "tenant_reads")["effect"],
        json!("withholds_frame")
    );
}

/// The pinned credentials rule, exactly.
fn pinned() -> Value {
    json!({ "match": "*", "action": "warn", "scan": ["credentials"] })
}

fn with_rules(rules: Value) -> Config {
    let mut config = Config::default();
    config.security.firewall.rules = serde_json::from_value(rules).expect("rules parse");
    config
}

fn rule_path(i: usize) -> String {
    format!("{FW}.rules[{i}]")
}

/// R6a, R6b: absent with no rules; at index 2, present with its position and
/// path, and the scope note.
#[test]
fn r6a_the_pinned_rule_present_or_not() {
    let model = read_model(&Config::default());
    assert_eq!(
        model["credentials"]["pinned_rule"],
        json!({
            "present": false,
            "position": null,
            "path": null,
            "shadowed_by": null,
            "partly_shadowed_by": null,
        })
    );
    assert_eq!(
        model["credentials"]["scope_note"],
        json!("interim_questions_and_challenges_refused")
    );
    let model = read_model(&with_rules(json!([
        { "match": "a", "action": "block", "scan": ["shell_injection"] },
        { "match": "b", "action": "block", "scan": ["sql_injection"] },
        pinned(),
    ])));
    assert_eq!(
        model["credentials"]["pinned_rule"],
        json!({
            "present": true,
            "position": 2,
            "path": rule_path(2),
            "shadowed_by": [],
            "partly_shadowed_by": [],
        })
    );
}

/// R6c: anything beyond the exact shape is not the pinned rule.
#[test]
fn r6c_only_the_exact_shape_is_the_pinned_rule() {
    for (field, value) in [
        ("reason", json!("r")),
        ("servers", json!(["a"])),
        ("keys", json!(["k"])),
        ("except", json!([{ "tool": "x" }])),
        ("scan", json!(["credentials", "shell_injection"])),
        ("action", json!("block")),
        ("match", json!("srv:*")),
        ("allowed_roots", json!(["/srv"])),
        ("path_args", json!(["p"])),
    ] {
        let mut rule = pinned();
        rule[field] = value;
        let model = read_model(&with_rules(json!([rule])));
        assert_eq!(
            model["credentials"]["pinned_rule"]["present"],
            json!(false),
            "{field}"
        );
    }
}

/// The pinned rule's (`shadowed_by`, `partly_shadowed_by`) behind `earlier`.
fn shadows_of_pinned(earlier: &Value) -> (Value, Value) {
    let model = read_model(&with_rules(json!([earlier, pinned()])));
    let p = &model["credentials"]["pinned_rule"];
    assert_eq!(p["position"], json!(1), "{model}");
    (p["shadowed_by"].clone(), p["partly_shadowed_by"].clone())
}

/// R6d, R6e, R6f, R6g: which earlier rules shadow the pinned rule fully,
/// which partly, and which not at all.
#[test]
fn r6d_what_shadows_the_pinned_rule() {
    let first = json!([rule_path(0)]);
    let none = json!([]);
    for (earlier, full, part) in [
        // R6d: an unscoped `*` rule deciding every type.
        (json!({ "match": "*", "action": "block" }), &first, &none),
        // R6e: scoped by key, a narrower match, and a scoped empty-scan rule.
        (
            json!({ "match": "*", "action": "block", "scan": ["credentials"], "keys": ["k"] }),
            &none,
            &first,
        ),
        (
            json!({ "match": "srv:*", "action": "block", "scan": ["credentials"] }),
            &none,
            &first,
        ),
        (
            json!({ "match": "*", "action": "block", "keys": ["k"] }),
            &none,
            &first,
        ),
        // R6f: a root rule, and a rule for a type no rule decides.
        (
            json!({ "match": "*", "action": "block", "allowed_roots": ["/srv"], "path_args": ["p"] }),
            &none,
            &none,
        ),
        (
            json!({ "match": "*", "action": "block", "scan": ["pii"] }),
            &none,
            &none,
        ),
        // R6g: a universal exception applies to no call; `server: "*"` is
        // not universal (a call with no backend is still covered), nor is a
        // key.
        (
            json!({ "match": "*", "action": "block", "scan": ["credentials"], "except": [{ "tool": "*" }] }),
            &none,
            &none,
        ),
        (
            json!({ "match": "*", "action": "block", "scan": ["credentials"], "except": [{ "server": "*" }] }),
            &none,
            &first,
        ),
        (
            json!({ "match": "*", "action": "block", "scan": ["credentials"], "except": [{ "key": "k" }] }),
            &none,
            &first,
        ),
        // R6i: a shape the load refuses (published with the firewall off)
        // compiles to an unscoped `*` block, a full shadower.
        (
            json!({ "match": "foo", "action": "warn", "scan": ["credentials"], "except": [{}] }),
            &first,
            &none,
        ),
        // R6j: an exception naming the rule's own match leaves it no call.
        (
            json!({ "match": "foo", "action": "block", "scan": ["credentials"], "except": [{ "tool": "foo" }] }),
            &none,
            &none,
        ),
    ] {
        let (shadowed, partly) = shadows_of_pinned(&earlier);
        assert_eq!(&shadowed, full, "{earlier}");
        assert_eq!(&partly, part, "{earlier}");
    }
}

/// R6h: the three switches, each off alone, then the R4e reload: redaction
/// applies at once, `scan_responses` waits for a restart.
#[test]
fn r6h_the_credentials_switches() {
    let sw =
        |name: &str, file: bool, enforced: bool| switch(&format!("{FW}.{name}"), file, enforced);
    let model = read_model(&Config::default());
    assert_eq!(
        model["credentials"]["redaction"],
        sw("credential_redaction", true, true)
    );
    assert_eq!(
        model["credentials"]["scan_responses"],
        sw("scan_responses", true, true)
    );
    assert_eq!(model["credentials"]["firewall"], sw("enabled", true, true));
    for field in ["credential_redaction", "scan_responses", "enabled"] {
        let mut config = Config::default();
        let fw = &mut config.security.firewall;
        match field {
            "credential_redaction" => fw.credential_redaction = false,
            "scan_responses" => fw.scan_responses = false,
            _ => fw.enabled = false,
        }
        let model = read_model(&config);
        let key = match field {
            "credential_redaction" => "redaction",
            "enabled" => "firewall",
            other => other,
        };
        assert_eq!(
            model["credentials"][key],
            sw(field, false, false),
            "{field}"
        );
    }
    let startup = Config::default();
    let mut next = startup.clone();
    next.security.firewall.credential_redaction = false;
    next.security.firewall.scan_responses = false;
    let model = reloaded(&startup, &[&next]);
    assert_eq!(
        model["credentials"]["redaction"],
        sw("credential_redaction", false, false)
    );
    assert_eq!(
        model["credentials"]["scan_responses"],
        sw("scan_responses", false, true)
    );
}
