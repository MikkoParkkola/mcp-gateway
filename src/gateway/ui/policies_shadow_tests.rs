// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The Policies read model's shadowing, reported per scan type and
//! conservatively, and where a scoped finding rule applies differently.

use serde_json::json;

use serde_json::Value;

use super::policies_test_support::read_model;
use crate::config::Config;

fn sh(ty: &str, by: &[usize]) -> (String, Vec<String>) {
    (ty.to_owned(), by.iter().map(|i| path(*i)).collect())
}

/// R3a: an earlier unscoped `*` rule shadows a later rule for the type both
/// decide.
#[test]
fn r3a_a_star_rule_shadows_a_later_rule() {
    let model = read_model(&rules(json!([
        { "match": "*", "action": "warn", "scan": ["shell_injection"] },
        { "match": "send_*", "action": "block", "scan": ["shell_injection"] }
    ])));
    assert_eq!(shadowed(&model, 1), vec![sh("shell_injection", &[0])]);
    assert_eq!(shadowed(&model, 0), vec![]);
}

/// R3b: an identical match shadows, each type reported.
#[test]
fn r3b_an_identical_match_shadows_each_type() {
    let model = read_model(&rules(json!([
        { "match": "send_*", "action": "warn", "scan": ["shell_injection", "credentials"] },
        { "match": "send_*", "action": "block", "scan": ["shell_injection", "credentials"] }
    ])));
    assert_eq!(
        shadowed(&model, 1),
        vec![sh("credentials", &[0]), sh("shell_injection", &[0])]
    );
}

/// R3c: not reported for a partial overlap, disjoint types, an earlier rule
/// with `servers`, `keys` or `except`, an earlier root rule, or a later root
/// rule behind a `*` rule.
#[test]
fn r3c_what_is_not_shadowing() {
    let later = json!({ "match": "send_mail", "action": "block", "scan": ["shell_injection"] });
    for earlier in [
        json!({ "match": "send_*", "action": "warn", "scan": ["shell_injection"] }),
        json!({ "match": "*", "action": "warn", "scan": ["credentials"] }),
        json!({ "match": "*", "action": "warn", "scan": ["shell_injection"], "servers": ["a"] }),
        json!({ "match": "*", "action": "warn", "scan": ["shell_injection"], "keys": ["k"] }),
        json!({ "match": "*", "action": "warn", "scan": ["shell_injection"], "except": [{ "tool": "t" }] }),
        json!({ "match": "*", "action": "block", "allowed_roots": ["/srv"], "path_args": ["p"] }),
    ] {
        let model = read_model(&rules(json!([earlier.clone(), later.clone()])));
        assert_eq!(shadowed(&model, 1), vec![], "{earlier}");
    }
    let model = read_model(&rules(json!([
        { "match": "*", "action": "warn" },
        { "match": "*", "action": "block", "allowed_roots": ["/srv"], "path_args": ["p"] }
    ])));
    assert_eq!(shadowed(&model, 1), vec![], "a root rule is never shadowed");
}

/// R3d: per type: behind an earlier `shell_injection` rule, a later rule
/// deciding `shell_injection` and `credentials` is shadowed for
/// `shell_injection` only.
#[test]
fn r3d_shadowing_is_per_type() {
    let model = read_model(&rules(json!([
        { "match": "*", "action": "warn", "scan": ["shell_injection"] },
        { "match": "*", "action": "block", "scan": ["shell_injection", "credentials"] }
    ])));
    assert_eq!(shadowed(&model, 1), vec![sh("shell_injection", &[0])]);
}

/// The types a rule decides, in `ScanType` order: every rule-listable type
/// but `pii` (no scanner produces it), `budget_exceeded` (both budget
/// outcomes force a block past the rules) and `collusion_relay` (the relay
/// gate alone decides it). R3e pins the set.
const DECIDED: [&str; 8] = [
    "credentials",
    "prompt_injection",
    "shell_injection",
    "path_traversal",
    "sql_injection",
    "sequence_anomaly",
    "memory_poisoning",
    "cross_tenant_reach",
];

/// R3e: an empty `scan` decides every type a rule decides: behind an
/// empty-scan `*` rule, an empty-scan rule is shadowed for each of the 8,
/// and a `shell_injection` rule for `shell_injection` alone.
#[test]
fn r3e_an_empty_scan_decides_every_decided_type() {
    let model = read_model(&rules(json!([
        { "match": "*", "action": "warn" },
        { "match": "*", "action": "block" },
        { "match": "send_*", "action": "block", "scan": ["shell_injection"] }
    ])));
    let every: Vec<_> = DECIDED.iter().map(|t| sh(t, &[0])).collect();
    assert_eq!(shadowed(&model, 1), every);
    assert_eq!(shadowed(&model, 2), vec![sh("shell_injection", &[0, 1])]);
}

/// R3f: A's action and reason do not matter, nor does B's scoping.
#[test]
fn r3f_shadow_eligibility_is_not_editability() {
    for earlier in [
        json!({ "match": "*", "action": "allow", "scan": ["shell_injection"] }),
        json!({ "match": "*", "action": "block", "scan": ["shell_injection"], "reason": "r" }),
    ] {
        let model = read_model(&rules(json!([
            earlier.clone(),
            { "match": "send_*", "action": "warn", "scan": ["shell_injection"], "servers": ["mail"] }
        ])));
        assert_eq!(
            shadowed(&model, 1),
            vec![sh("shell_injection", &[0])],
            "{earlier}"
        );
    }
}

/// R3g: order: a later `*` rule shadows nothing earlier.
#[test]
fn r3g_a_later_rule_never_shadows_an_earlier_one() {
    let model = read_model(&rules(json!([
        { "match": "send_*", "action": "block", "scan": ["shell_injection"] },
        { "match": "*", "action": "warn", "scan": ["shell_injection"] }
    ])));
    assert_eq!(shadowed(&model, 0), vec![]);
}

/// R3h: every eligible earlier rule is listed, earliest first; a type
/// repeated in a `scan` list is reported once.
#[test]
fn r3h_every_shadower_once_per_type() {
    let model = read_model(&rules(json!([
        { "match": "*", "action": "warn", "scan": ["shell_injection", "shell_injection"] },
        { "match": "send_*", "action": "warn", "scan": ["shell_injection"] },
        { "match": "send_*", "action": "block", "scan": ["shell_injection", "shell_injection"] }
    ])));
    assert_eq!(shadowed(&model, 2), vec![sh("shell_injection", &[0, 1])]);
}

/// R3i: with the firewall off, an earlier `*` rule with a present-but-empty
/// `servers`, `keys` or `except` shadows nothing.
#[test]
fn r3i_present_but_empty_scoping_does_not_shadow() {
    for field in ["servers", "keys", "except"] {
        let mut earlier = json!({ "match": "*", "action": "warn", "scan": ["shell_injection"] });
        earlier[field] = json!([]);
        let mut config = rules(json!([
            earlier,
            { "match": "send_*", "action": "block", "scan": ["shell_injection"] }
        ]));
        config.security.firewall.enabled = false;
        assert_eq!(shadowed(&read_model(&config), 1), vec![], "{field}");
    }
}

/// The surfaces where a rule's key is not known.
const KEY_NOT_KNOWN: [&str; 7] = [
    "event_delivery",
    "task_settlement",
    "outbound_rescan",
    "backend_error",
    "notification",
    "stored_task",
    "discovery",
];
/// The surfaces where a rule's backend is expanded over the registry.
const BACKEND_EXPANDED: [&str; 4] = [
    "notification",
    "stored_task",
    "discovery",
    "aggregate_answer",
];

/// R9a, R9b, R9d, R9e: a rule scoped by key lists the key-not-known
/// surfaces; by server, the expanded-backend ones; both, both; an unscoped
/// rule, and an `except` entry naming only a tool, neither.
#[test]
fn r9_where_a_scoped_rule_applies_differently() {
    let cases = [
        (json!({ "keys": ["k"] }), true, false),
        (json!({ "except": [{ "key": "k" }] }), true, false),
        (json!({ "servers": ["a"] }), false, true),
        (json!({ "except": [{ "server": "a" }] }), false, true),
        (json!({ "keys": ["k"], "servers": ["a"] }), true, true),
        (
            json!({ "except": [{ "key": "k", "server": "a" }] }),
            true,
            true,
        ),
        (json!({}), false, false),
        (json!({ "except": [{ "tool": "t" }] }), false, false),
    ];
    for (scope, keyed, served) in cases {
        let mut shape = json!({ "match": "*", "action": "block", "scan": ["shell_injection"] });
        for (k, v) in scope.as_object().expect("an object") {
            shape[k] = v.clone();
        }
        let model = read_model(&rules(json!([shape.clone()])));
        let differs = &rule(&model, 0)["scope_differs"];
        let expect = |on: bool, list: &[&str]| if on { json!(list) } else { json!([]) };
        assert_eq!(
            differs["key_not_known"],
            expect(keyed, &KEY_NOT_KNOWN),
            "{shape}"
        );
        assert_eq!(
            differs["backend_expanded"],
            expect(served, &BACKEND_EXPANDED),
            "{shape}"
        );
    }
    // R9e: present-but-empty scoping annotates as present (firewall off).
    let mut config = rules(
        json!([{ "match": "*", "action": "block", "scan": ["shell_injection"], "keys": [] }]),
    );
    config.security.firewall.enabled = false;
    assert_eq!(
        rule(&read_model(&config), 0)["scope_differs"]["key_not_known"],
        json!(KEY_NOT_KNOWN)
    );
}

/// Production constructions of `needle` per file under `src/`: `use` lines,
/// match arms and comparisons are not constructions; comments, string
/// literals and test code (`*_tests.rs` files, `tests/` and `*_tests/`
/// directories, and each `#[cfg(test)]` item wherever it sits) are skipped.
fn constructions(needle: &str) -> std::collections::BTreeMap<String, usize> {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read src") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                // `tests/` and `*_tests/` directories hold test modules only.
                let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
                if name.is_some_and(|n| n != "tests" && !n.ends_with("_tests")) {
                    walk(&path, out);
                }
            } else if path.extension().is_some_and(|e| e == "rs")
                && !path.to_string_lossy().ends_with("_tests.rs")
            {
                out.push(path);
            }
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    walk(&root.join("src"), &mut files);
    let mut found = std::collections::BTreeMap::new();
    for file in files {
        let text = std::fs::read_to_string(&file).expect("read");
        // Test items blanked, then comments and string literals.
        let production =
            crate::test_source_text::sanitize(&crate::test_source_text::production_text(&text));
        let count = production
            .lines()
            .map(str::trim_start)
            .filter(|l| !l.starts_with("use "))
            .filter(|l| l.contains(needle) && !l.contains("=>") && !l.contains("=="))
            .count();
        if count > 0 {
            let rel = file
                .strip_prefix(root)
                .expect("under the crate")
                .to_string_lossy()
                // One separator on every platform, as the table spells it.
                .replace('\\', "/");
            found.insert(rel, count);
        }
    }
    found
}

/// R9c: the surface lists are in step with the code: every production site
/// that resolves a key as not known, or expands a backend over the registry,
/// is one this table classifies (a surface the read model names, or excluded
/// with its reason), and no classified site is gone.
#[test]
fn r9c_the_surface_lists_match_the_code() {
    let key_sites = [
        // check_request, check_response: no production caller.
        ("src/security/firewall/mod.rs", 2),
        // log_request, log_response: audit records, no rule decision.
        ("src/security/firewall/audit.rs", 2),
        ("src/events/services.rs", 1), // event_delivery
        // audited_call_judged: the delivery record.
        ("src/gateway/router/backend_handlers/direct_audit.rs", 1),
        // the delivery-attempt record; the scan is scan_stored_task.
        ("src/gateway/meta_mcp/task_notify.rs", 1),
        ("src/gateway/meta_mcp/response_security.rs", 1), // task_settlement
        // rescan_outbound: the verdict (outbound_rescan) and its audit labels.
        ("src/gateway/meta_mcp/invoke/chokepoint.rs", 2),
        // backend_error, notification, stored_task, discovery, and
        // content_refuses_value (content checks only, excluded).
        ("src/gateway/meta_mcp/invoke/egress.rs", 5),
    ];
    let backend_sites = [
        // notification, stored_task, discovery.
        ("src/gateway/meta_mcp/invoke/egress.rs", 3),
        ("src/gateway/meta_mcp/response_security.rs", 1), // aggregate_answer
    ];
    let as_map = |sites: &[(&str, usize)]| -> std::collections::BTreeMap<String, usize> {
        sites.iter().map(|(f, n)| ((*f).to_owned(), *n)).collect()
    };
    assert_eq!(
        constructions("KeyOf::NotKnown"),
        as_map(&key_sites),
        "key-not-known sites moved"
    );
    assert_eq!(
        constructions("TargetOrigin::NoBackend"),
        as_map(&backend_sites),
        "expanded-backend sites moved"
    );
}

/// A config whose firewall has `rules` (each a JSON rule).
fn rules(rules: Value) -> Config {
    let mut config = Config::default();
    config.security.firewall.rules = serde_json::from_value(rules).expect("rules parse");
    config
}

/// The read model's finding rule `i`.
fn rule(model: &Value, i: usize) -> &Value {
    &model["finding_rules"][i]
}

/// The shadowed types of rule `i`, as (type, [paths]).
fn shadowed(model: &Value, i: usize) -> Vec<(String, Vec<String>)> {
    rule(model, i)["shadowed"]
        .as_array()
        .expect("shadowed")
        .iter()
        .map(|s| {
            let by = s["by"]
                .as_array()
                .expect("by")
                .iter()
                .map(|p| p.as_str().expect("path").to_owned())
                .collect();
            (s["scan_type"].as_str().expect("type").to_owned(), by)
        })
        .collect()
}

fn path(i: usize) -> String {
    format!("security.firewall.rules[{i}]")
}

/// R2a: the rules in order, each with its fields and path; absent
/// collections are `null`, present ones arrays.
#[test]
fn r2a_the_rules_in_order_with_their_paths() {
    let model = read_model(&rules(json!([
        { "match": "*", "action": "warn", "scan": ["shell_injection"] },
        { "match": "send_*", "action": "block", "servers": ["mail"],
          "except": [{ "key": "ops" }], "reason": "outbound" }
    ])));
    let first = rule(&model, 0);
    assert_eq!(first["path"], path(0));
    assert_eq!(first["match"], "*");
    assert_eq!(first["scan"], json!(["shell_injection"]));
    assert_eq!(first["servers"], Value::Null);
    let second = rule(&model, 1);
    assert_eq!(second["path"], path(1));
    assert_eq!(second["servers"], json!(["mail"]));
    assert_eq!(
        second["except"],
        json!([{ "server": null, "tool": null, "key": "ops" }])
    );
    assert_eq!(second["reason"], "outbound");
}

/// R2b: a rule is editable only with block or warn, a non-empty `scan`, and
/// nothing else; each other shape alone is read-only with its reason.
#[test]
fn r2b_editability_and_its_reasons() {
    let cases = [
        (
            json!({ "match": "*", "action": "warn", "scan": ["shell_injection"] }),
            json!([]),
        ),
        (
            json!({ "match": "*", "action": "allow", "scan": ["shell_injection"] }),
            json!(["allow"]),
        ),
        (
            json!({ "match": "*", "action": "warn", "scan": ["shell_injection"], "reason": "r" }),
            json!(["reason"]),
        ),
        (
            json!({ "match": "*", "action": "warn" }),
            json!(["empty_scan"]),
        ),
        (
            json!({ "match": "*", "action": "warn", "scan": ["shell_injection"], "servers": ["a"] }),
            json!(["servers"]),
        ),
        (
            json!({ "match": "*", "action": "warn", "scan": ["shell_injection"], "keys": ["k"] }),
            json!(["keys"]),
        ),
        (
            json!({ "match": "*", "action": "warn", "scan": ["shell_injection"], "except": [{ "tool": "t" }] }),
            json!(["except"]),
        ),
        (
            json!({ "match": "*", "action": "block", "allowed_roots": ["/srv"], "path_args": ["path"] }),
            json!(["empty_scan", "root"]),
        ),
        (
            json!({ "match": "*", "action": "warn", "scan": ["shell_injection"], "allowed_roots": ["/srv"] }),
            json!(["root"]),
        ),
        (
            json!({ "match": "*", "action": "warn", "scan": ["shell_injection"], "path_args": ["path"] }),
            json!(["root"]),
        ),
    ];
    for (shape, reasons) in cases {
        let model = read_model(&rules(json!([shape.clone()])));
        let r = rule(&model, 0);
        assert_eq!(r["read_only_reasons"], reasons, "{shape}");
        assert_eq!(r["editable"], reasons == json!([]), "{shape}");
    }
}

/// R2d: with the firewall off, a rule listing an output-only type loads and
/// is read-only for it.
#[test]
fn r2d_an_unoffered_type_is_read_only() {
    let mut config =
        rules(json!([{ "match": "*", "action": "warn", "scan": ["path_outside_root"] }]));
    config.security.firewall.enabled = false;
    let model = read_model(&config);
    assert_eq!(
        rule(&model, 0)["read_only_reasons"],
        json!(["unoffered_type"])
    );
}

/// The types the Policies screen offers (ADR-029), in `ScanType` order.
const OFFERED: [&str; 6] = [
    "credentials",
    "prompt_injection",
    "shell_injection",
    "path_traversal",
    "sql_injection",
    "memory_poisoning",
];

/// R2h: a one-type `warn` rule is editable exactly when its type is offered:
/// each of the 6, and none of the other 5 rule-listable types, which are
/// read-only `unoffered_type`.
#[test]
fn r2h_only_the_six_offered_types_are_editable() {
    let unoffered = [
        "pii",
        "sequence_anomaly",
        "cross_tenant_reach",
        "budget_exceeded",
        "collusion_relay",
    ];
    for ty in OFFERED.iter().chain(&unoffered) {
        let model = read_model(&rules(
            json!([{ "match": "*", "action": "warn", "scan": [ty] }]),
        ));
        let reasons = if OFFERED.contains(ty) {
            json!([])
        } else {
            json!(["unoffered_type"])
        };
        assert_eq!(rule(&model, 0)["read_only_reasons"], reasons, "{ty}");
    }
}

/// R3j: a rule for a type no rule decides shadows nothing and is shadowed
/// for nothing (`pii`, `collusion_relay`, `budget_exceeded`); the guard
/// types a rule does decide (`sequence_anomaly`, `cross_tenant_reach`) still
/// shadow.
#[test]
fn r3j_only_decided_types_shadow() {
    for ty in ["pii", "collusion_relay", "budget_exceeded"] {
        let model = read_model(&rules(json!([
            { "match": "*", "action": "warn", "scan": [ty] },
            { "match": "*", "action": "block", "scan": [ty] }
        ])));
        assert_eq!(shadowed(&model, 1), vec![], "{ty}");
    }
    for ty in ["sequence_anomaly", "cross_tenant_reach"] {
        let model = read_model(&rules(json!([
            { "match": "*", "action": "warn", "scan": [ty] },
            { "match": "*", "action": "block", "scan": [ty] }
        ])));
        assert_eq!(shadowed(&model, 1), vec![sh(ty, &[0])], "{ty}");
    }
}

/// R3k: a mixed list decides only its decided types: `[credentials,
/// collusion_relay]` shadows a later `credentials` rule for `credentials`,
/// and is itself read-only `unoffered_type`.
#[test]
fn r3k_a_mixed_list_decides_its_decided_types() {
    let model = read_model(&rules(json!([
        { "match": "*", "action": "warn", "scan": ["credentials", "collusion_relay"] },
        { "match": "*", "action": "block", "scan": ["credentials", "collusion_relay"] }
    ])));
    assert_eq!(shadowed(&model, 1), vec![sh("credentials", &[0])]);
    assert_eq!(
        rule(&model, 0)["read_only_reasons"],
        json!(["unoffered_type"])
    );
}

/// R2e: a present-but-empty collection counts as present.
#[test]
fn r2e_present_but_empty_is_present() {
    for (field, reason) in [
        ("servers", "servers"),
        ("keys", "keys"),
        ("except", "except"),
        ("allowed_roots", "root"),
        ("path_args", "root"),
    ] {
        let mut shape = json!({ "match": "*", "action": "warn", "scan": ["shell_injection"] });
        shape[field] = json!([]);
        let mut config = rules(json!([shape]));
        config.security.firewall.enabled = false;
        let model = read_model(&config);
        assert_eq!(
            rule(&model, 0)["read_only_reasons"],
            json!([reason]),
            "{field}"
        );
        assert_eq!(
            rule(&model, 0)[field],
            json!([]),
            "{field}: shown as present"
        );
    }
}

/// R2f: two identical rules are both listed with their own paths.
#[test]
fn r2f_identical_rules_keep_their_own_paths() {
    let shape = json!({ "match": "*", "action": "warn", "scan": ["shell_injection"] });
    let model = read_model(&rules(json!([shape.clone(), shape])));
    assert_eq!(rule(&model, 1)["path"], path(1));
}
