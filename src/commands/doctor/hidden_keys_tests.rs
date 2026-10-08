// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;
use figment::providers::{Format as _, Yaml};

/// Parse as the loader does.
fn yaml(text: &str) -> Dict {
    Yaml::from_str(text).expect("test yaml parses")
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
            let parsed: Dict = Yaml::from_str(&config)
                .unwrap_or_else(|e| panic!("init --profile {profile} writes invalid YAML: {e}"));
            std::fs::write(&path, &config).expect("write init config");
            assert!(
                check_hidden_keys(&path).is_none(),
                "init --profile {profile} (examples: {with_examples}) writes a hidden key: {:?}",
                set_hidden_keys(&parsed)
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

/// The keys a row names, read back from its detail ("<path> sets a, b").
fn named_keys(row: &CheckResult) -> Vec<String> {
    row.detail
        .split_once(" sets ")
        .map(|(_, keys)| keys.split(", ").map(str::to_string).collect())
        .unwrap_or_default()
}

#[test]
fn a_repeated_key_is_read_the_way_the_loader_reads_it() {
    // The loader's YAML reader keeps the last of two equal keys; a reader
    // that rejects the file would hide every hidden key it sets.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    std::fs::write(
        &path,
        "meta_mcp:\n  projection_mode: false\nmeta_mcp:\n  projection_mode: true\n",
    )
    .expect("write config");
    let row = check_hidden_keys(&path).expect("a row for a file the loader accepts");
    assert_eq!(named_keys(&row), vec!["meta_mcp.projection_mode"]);
}

#[test]
fn a_parent_key_is_not_listed_beside_its_child() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    std::fs::write(&path, "accounts:\n  limits:\n    authority_bytes: 4096\n")
        .expect("write config");
    let row = check_hidden_keys(&path).expect("a row when a hidden key is set");
    assert_eq!(named_keys(&row), vec!["accounts.limits.authority_bytes"]);
}

/// A config tree that sets `key`, placed after an empty sibling at every
/// `<name>` and `[]` step so later positions are searched too.
fn tree(segments: &[&str]) -> Value {
    use figment::value::Tag;
    let Some((head, rest)) = segments.split_first() else {
        return Value::from("set");
    };
    let child = tree(rest);
    let empty = || Value::Dict(Tag::Default, Dict::new());
    let entries = if *head == "<name>" {
        vec![("a0".to_string(), empty()), ("b0".to_string(), child)]
    } else if let Some(list_key) = head.strip_suffix("[]") {
        vec![(
            list_key.to_string(),
            Value::Array(Tag::Default, vec![empty(), child]),
        )]
    } else {
        vec![((*head).to_string(), child)]
    };
    Value::Dict(Tag::Default, entries.into_iter().collect())
}

#[test]
fn every_table_entry_is_found_where_a_config_sets_it() {
    for key in HIDDEN_CONFIG_KEYS {
        let Value::Dict(_, config) = tree(&key.split('.').collect::<Vec<_>>()) else {
            unreachable!("a tree is a dict")
        };
        assert!(set_hidden_keys(&config).contains(key), "{key} not found");
    }
}

#[cfg(unix)]
#[test]
fn a_fifo_at_the_config_path_returns_at_once_with_no_row() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    let status = std::process::Command::new("mkfifo")
        .args(["-m", "600"])
        .arg(&path)
        .status()
        .expect("run mkfifo(1)");
    assert!(status.success(), "mkfifo(1) failed");
    let (tx, rx) = std::sync::mpsc::channel();
    let probe = path.clone();
    std::thread::spawn(move || {
        let _ = tx.send(check_hidden_keys(&probe).is_none());
    });
    let no_row = rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("doctor blocked on a FIFO");
    assert!(no_row, "a FIFO produced a row");
}
