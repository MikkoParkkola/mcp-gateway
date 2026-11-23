// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `Config::default()` and a config loaded from an empty file agree field for
//! field: one source of defaults, held by these rows.

use std::collections::BTreeSet;

use super::Config;

/// The config `text` loads to, from an owner-only file.
fn load(text: &str) -> crate::Result<Config> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, text).expect("write the config");
    Config::load(Some(&path))
}

/// DEFAULTS.2, kills "Default and the loader disagree on a field", "the field
/// attribute names another function" and "the one function returns another
/// word": an empty file loads to exactly `Config::default()`, and the default
/// profile is "default". Fields a JSON form leaves out when unset
/// (`environment`, `secrets`, `accounts`) are compared directly too.
#[test]
fn config_default_equals_an_empty_file() {
    let loaded = load("").expect("an empty file loads");
    let built = Config::default();

    let loaded_json = serde_json::to_value(&loaded).expect("json");
    let built_json = serde_json::to_value(&built).expect("json");
    let differing: BTreeSet<&String> = loaded_json
        .as_object()
        .expect("an object")
        .keys()
        .chain(built_json.as_object().expect("an object").keys())
        .filter(|key| loaded_json.get(key.as_str()) != built_json.get(key.as_str()))
        .collect();
    assert!(
        differing.is_empty(),
        "Config::default() and an empty file differ at {differing:?}"
    );

    assert_eq!(loaded.environment, built.environment, "environment");
    assert!(
        loaded.secrets.is_default() && built.secrets.is_default(),
        "secrets"
    );
    assert!(
        loaded.accounts.is_none() && built.accounts.is_none(),
        "accounts"
    );

    assert_eq!(built.default_routing_profile, "default");
}

/// Pins how a file that names the key with no value loads: before this change
/// it is refused (a YAML null is not a string), and it still is. The field's
/// own default attribute is kept so that this does not change.
#[test]
fn a_key_written_with_no_value_loads_as_it_did() {
    let refused =
        load("default_routing_profile:\n").expect_err("a key with no value is refused, as before");
    let text = refused.to_string();
    assert!(
        text.contains(
            "invalid type: found unit, expected a string for key \"default.default_routing_profile\""
        ),
        "{text}"
    );
}
