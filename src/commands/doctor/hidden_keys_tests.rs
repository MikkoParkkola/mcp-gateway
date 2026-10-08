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

#[test]
fn doctor_adds_no_hidden_settings_row_for_a_fresh_init_config() {
    use mcp_gateway::cli::InitProfile;
    let dir = tempfile::tempdir().expect("tempdir");
    for profile in [InitProfile::Local, InitProfile::Minimal] {
        for with_examples in [true, false] {
            let path = dir.path().join(format!("{profile}-{with_examples}.yaml"));
            let config = crate::commands::build_init_config(with_examples, profile, "");
            std::fs::write(&path, &config).expect("write init config");
            assert!(
                check_hidden_keys(&path).is_none(),
                "init --profile {profile} (examples: {with_examples}) writes a hidden key: {:?}",
                set_hidden_keys(&serde_yaml::from_str(&config).expect("init config parses"))
            );
        }
    }
}

/// Everything `doctor` would print or emit as JSON for the hidden-key row.
fn rendered(row: &CheckResult) -> String {
    format!(
        "{} {} {:?} {}",
        row.label,
        row.detail,
        row.hint,
        super::super::check_result_json_value(row)
    )
}

#[test]
fn doctor_never_prints_a_config_value() {
    const SECRET: &str = "s3cr3t-never-printed-7f2c";
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    std::fs::write(
        &path,
        format!(
            "auth:\n  enabled: true\n  bearer_token: \"{SECRET}\"\n\
             meta_mcp:\n  projection_mode: \"{SECRET}\"\n\
             backends:\n  fs:\n    command: x\n    max_frame_bytes: \"{SECRET}\"\n"
        ),
    )
    .expect("write config");
    let row = check_hidden_keys(&path).expect("hidden keys are set");
    let out = rendered(&row);
    assert!(out.contains("meta_mcp.projection_mode"), "{out}");
    assert!(!out.contains(SECRET), "a config value leaked: {out}");
}

#[test]
fn a_malformed_config_produces_no_row_and_no_parse_text() {
    const SECRET: &str = "s3cr3t-in-a-broken-line-91ad";
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    std::fs::write(&path, format!("auth:\n  bearer_token: \"{SECRET}\n  : [\n"))
        .expect("write config");
    assert!(check_hidden_keys(&path).is_none());
}
