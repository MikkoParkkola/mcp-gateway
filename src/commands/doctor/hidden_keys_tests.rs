// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;

fn yaml(text: &str) -> serde_yaml::Value {
    serde_yaml::from_str(text).expect("test yaml parses")
}

#[test]
fn a_set_hidden_key_is_listed_and_a_keep_key_is_not() {
    let raw = yaml(
        "server:\n  port: 39400\nmeta_mcp:\n  projection_mode: true\n\
         backends:\n  fs:\n    command: x\n    max_frame_bytes: 1024\n",
    );
    let set = set_hidden_keys(&raw);
    assert!(set.contains(&"meta_mcp.projection_mode"), "{set:?}");
    assert!(set.contains(&"backends.<name>.max_frame_bytes"), "{set:?}");
    assert!(!set.iter().any(|k| k.starts_with("server.port")), "{set:?}");
}

#[test]
fn a_hidden_key_inside_a_list_item_is_listed() {
    let raw = yaml("accounts:\n  adapters:\n    - clock_skew_seconds: 30\n");
    assert_eq!(
        set_hidden_keys(&raw),
        vec!["accounts.adapters[].clock_skew_seconds"]
    );
}

#[test]
fn a_config_without_hidden_keys_lists_none() {
    let raw = yaml("server:\n  port: 39400\nbackends:\n  fs:\n    command: x\n");
    assert!(set_hidden_keys(&raw).is_empty());
}

#[test]
fn doctor_names_the_hidden_keys_a_config_file_sets() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    std::fs::write(&path, "meta_mcp:\n  projection_mode: true\n").expect("write config");
    let row = check_hidden_keys(&path).expect("a row when a hidden key is set");
    assert!(
        row.detail.contains("meta_mcp.projection_mode"),
        "{}",
        row.detail
    );
    assert!(
        row.hint
            .as_deref()
            .is_some_and(|h| h.contains("still applied")),
        "{row:?}"
    );
}

#[test]
fn doctor_adds_no_row_when_no_hidden_key_is_set() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    std::fs::write(&path, "server:\n  port: 39400\n").expect("write config");
    assert!(check_hidden_keys(&path).is_none());
}

#[test]
fn the_table_is_not_empty() {
    assert!(
        HIDDEN_CONFIG_KEYS.len() >= 100,
        "{}",
        HIDDEN_CONFIG_KEYS.len()
    );
}
