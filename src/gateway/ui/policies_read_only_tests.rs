// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which settings the save can change: each setting object on the Policies
//! screen carries `read_only` from the save table, and a value the hardened
//! posture holds says so. Firewall builds only: a hardened load needs the
//! firewall.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use super::policies::{Sources, read_model as model_from};
use super::policies_test_support::{FW, SAVEABLE, read_model, switch_obj};
use crate::config::Config;
use crate::config_reload::LiveConfig;
use crate::security::posture::SecurityPosture;

/// `posture` with SSRF protection off in the file, loaded through the real
/// `Config::load`, so the posture's own resolution runs. The signing secret is
/// one a hardened load requires.
fn load(posture: &str) -> Config {
    let dir = tempfile::tempdir().expect("a temp dir");
    let path = dir.path().join("gateway.yaml");
    let body = format!(
        "security:\n  posture: {posture}\n  ssrf_protection: false\n  message_signing:\n    \
         shared_secret: hardened-signing-secret-0123456789abcdef\n"
    );
    crate::gateway::test_helpers::write_owner_only(&path, &body).expect("the file is written");
    Config::load(Some(&path)).expect("the fixture loads")
}

fn model_of(config: Config) -> (Value, LiveConfig) {
    let live = LiveConfig::new(config);
    let model = model_from(&Sources::of(&live));
    (model, live)
}

/// Every object in `value`, depth first, with its JSON pointer.
fn objects<'a>(value: &'a Value, at: &str, found: &mut Vec<(String, &'a Map<String, Value>)>) {
    match value {
        Value::Object(map) => {
            found.push((at.to_owned(), map));
            for (key, child) in map {
                objects(child, &format!("{at}/{key}"), found);
            }
        }
        Value::Array(items) => {
            for (i, child) in items.iter().enumerate() {
                objects(child, &format!("{at}/{i}"), found);
            }
        }
        _ => {}
    }
}

fn all_objects(model: &Value) -> Vec<(String, &Map<String, Value>)> {
    let mut found = Vec::new();
    objects(model, "", &mut found);
    found
}

/// The pointers of the objects that carry `forced_by`.
fn forced_in(model: &Value) -> Vec<String> {
    all_objects(model)
        .into_iter()
        .filter(|(_, o)| o.contains_key("forced_by"))
        .map(|(at, _)| at)
        .collect()
}

/// The setting objects: those with a path, a file and an enforced value.
fn settings(model: &Value) -> Vec<(String, &Map<String, Value>)> {
    all_objects(model)
        .into_iter()
        .filter(|(_, o)| {
            ["path", "file", "enforced"]
                .iter()
                .all(|k| o.contains_key(*k))
        })
        .collect()
}

// rc2: under the hardened posture SSRF protection reads as held by the
// posture, read-only, whatever the file says; under standard the file's own
// value stands and nothing is forced. The two files differ only in posture.
#[test]
fn rc2_the_hardened_posture_forces_ssrf() {
    let hardened = load("hardened");
    assert_eq!(
        hardened.security.posture,
        SecurityPosture::Hardened,
        "premise"
    );
    assert!(
        hardened.security.ssrf_protection,
        "premise: the hardened load turns SSRF protection on"
    );
    let (model, live) = model_of(hardened);
    let checks = &model["request_checks"];
    let mut held = switch_obj("security.ssrf_protection", true, true, true);
    held["forced_by"] = json!("security.posture");
    assert_eq!(checks["ssrf_protection"], held, "{model}");
    assert!(
        checks["sanitize_input"].get("forced_by").is_none(),
        "{model}"
    );
    assert_eq!(checks["sanitize_input"]["read_only"], false, "{model}");
    assert_eq!(
        forced_in(&model),
        ["/request_checks/ssrf_protection"],
        "{model}"
    );
    // The value the config view serves verbatim.
    assert!(live.generation().ssrf_protection());

    let standard = load("standard");
    assert_eq!(
        standard.security.posture,
        SecurityPosture::Standard,
        "premise"
    );
    assert!(
        !standard.security.ssrf_protection,
        "premise: the file's off stands"
    );
    let (model, _live) = model_of(standard);
    assert_eq!(
        model["request_checks"]["ssrf_protection"],
        switch_obj("security.ssrf_protection", false, false, false),
        "{model}"
    );
    assert!(forced_in(&model).is_empty(), "{model}");
}

// rc3: read_only follows the save table. Every saveable id is served writable
// at its count (the credential redaction switch twice: its own setting and the
// credentials scan type's precondition), nothing else is writable, a sample of
// the restart-only fields reads read-only, and the literal list matches the
// table.
#[test]
fn rc3_read_only_follows_the_save_table() {
    let model = read_model(&Config::default());
    let found = settings(&model);
    assert!(!found.is_empty(), "the walk finds the setting objects");
    for (at, setting) in &found {
        assert!(
            setting.get("read_only").is_some_and(Value::is_boolean),
            "{at} has no boolean read_only: {model}"
        );
    }

    let mut writable: BTreeMap<String, usize> = BTreeMap::new();
    for (_, setting) in &found {
        if setting.get("read_only") == Some(&Value::Bool(false)) {
            let path = setting["path"].as_str().expect("a string path");
            *writable.entry(path.to_owned()).or_default() += 1;
        }
    }
    let mut want: BTreeMap<String, usize> =
        SAVEABLE.iter().map(|id| ((*id).to_owned(), 1)).collect();
    want.insert(format!("{FW}.credential_redaction"), 2);
    assert_eq!(writable, want, "{model}");

    let fixed = [
        "enabled",
        "scan_responses",
        "scan_requests",
        "collusion.sources",
        "anomaly_detection",
        "tenant_guard.enabled",
    ];
    for field in fixed {
        let path = format!("{FW}.{field}");
        let mut seen = 0;
        for (at, setting) in &found {
            if setting["path"] == path.as_str() {
                seen += 1;
                assert_eq!(setting["read_only"], true, "{at}: {model}");
            }
        }
        assert!(seen > 0, "{path} is served: {model}");
    }

    let table: Vec<&str> = crate::config_reload::ui_fields::FIELDS
        .iter()
        .map(|f| f.id)
        .filter(|id| id.starts_with("security."))
        .collect();
    assert_eq!(table, SAVEABLE, "the literal list is the save table's");

    assert!(
        forced_in(&model).is_empty(),
        "standard forces nothing: {model}"
    );

    let mut keys: Vec<&str> = model
        .as_object()
        .map(|o| o.keys().map(String::as_str).collect())
        .unwrap_or_default();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "credentials",
            "finding_rules",
            "guards",
            "relay",
            "request_checks",
            "scan_types",
            "tool_limits",
            "tool_policy",
        ],
        "{model}"
    );
}
