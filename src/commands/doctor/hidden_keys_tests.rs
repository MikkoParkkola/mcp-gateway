// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;

/// Parse as the loader does.
fn yaml(text: &str) -> Dict {
    crate::yaml::from_str_loose(text).expect("test yaml parses")
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
    assert_eq!(
        row.status,
        super::super::CheckStatus::Pass,
        "a set value is not a problem"
    );
    assert!(
        row.detail.contains("Each value is applied"),
        "{}",
        row.detail
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
            // The starter backends init writes when every launcher is present.
            let starter = if with_examples && profile == InitProfile::Local {
                crate::commands::init_backends::starter_backends(|_| true).0
            } else {
                String::new()
            };
            let config = crate::commands::build_init_config(with_examples, profile, &starter);
            let parsed: Dict = crate::yaml::from_str_loose(&config)
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
        .and_then(|(_, rest)| rest.split_once(". "))
        .map(|(keys, _)| keys.split(", ").map(str::to_string).collect())
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

    // Last wins, not a merge: a hidden key only in the first copy is gone.
    std::fs::write(
        &path,
        "meta_mcp:\n  projection_mode: true\nmeta_mcp:\n  warm_start: []\n",
    )
    .expect("write config");
    assert!(
        check_hidden_keys(&path).is_none(),
        "the first copy was kept"
    );
}

#[cfg(unix)]
#[test]
fn a_symlinked_config_is_read_like_the_loader_reads_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("real.yaml");
    std::fs::write(&target, "meta_mcp:\n  projection_mode: true\n").expect("write config");
    let link = dir.path().join("gateway.yaml");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");
    let row = check_hidden_keys(&link).expect("a symlinked config gets its row");
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

/// `check_hidden_keys` on `path`, which must answer within `limit`.
#[cfg(unix)]
fn answers_within(path: &std::path::Path, limit: std::time::Duration) -> Option<CheckResult> {
    let (tx, rx) = std::sync::mpsc::channel();
    let probe = path.to_path_buf();
    std::thread::spawn(move || {
        let _ = tx.send(check_hidden_keys(&probe));
    });
    rx.recv_timeout(limit)
        .unwrap_or_else(|_| panic!("doctor kept reading {}", path.display()))
}

#[cfg(unix)]
#[test]
fn a_config_linked_to_an_endless_device_is_refused_at_once() {
    // The device opens without blocking; only the regular-file check on the
    // opened handle stops an endless read.
    let dir = tempfile::tempdir().expect("tempdir");
    let link = dir.path().join("gateway.yaml");
    std::os::unix::fs::symlink("/dev/zero", &link).expect("symlink");
    let row = answers_within(&link, std::time::Duration::from_millis(500));
    assert!(row.is_none(), "a device produced a row");
}

#[cfg(unix)]
#[test]
fn a_config_linked_to_a_fifo_returns_at_once_with_no_row() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fifo = dir.path().join("pipe");
    let status = std::process::Command::new("mkfifo")
        .args(["-m", "600"])
        .arg(&fifo)
        .status()
        .expect("run mkfifo(1)");
    assert!(status.success(), "mkfifo(1) failed");
    let link = dir.path().join("gateway.yaml");
    std::os::unix::fs::symlink(&fifo, &link).expect("symlink");
    let row = answers_within(&link, std::time::Duration::from_secs(5));
    assert!(row.is_none(), "a FIFO produced a row");
}

#[test]
fn an_older_url_key_names_the_command_that_rewrites_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    std::fs::write(
        &path,
        "backends:\n  fs:\n    http_url: \"https://fs.example.com/mcp\"\n",
    )
    .expect("write config");
    let row = check_hidden_keys(&path).expect("an older url key is listed");
    assert!(
        row.detail
            .contains("backends.<name>.http_url (run mcp-gateway upgrade to rewrite it as url)"),
        "{}",
        row.detail
    );
}

#[test]
fn an_older_url_key_holding_a_variable_names_no_upgrade() {
    // `upgrade` leaves a value that is not an address of its scheme alone,
    // so doctor does not suggest running it.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    std::fs::write(&path, "backends:\n  fs:\n    http_url: \"${FS_URL}\"\n").expect("write config");
    let row = check_hidden_keys(&path).expect("an older url key is listed");
    assert!(
        row.detail.contains("backends.<name>.http_url") && !row.detail.contains("upgrade"),
        "{}",
        row.detail
    );
}

#[test]
fn an_older_url_key_upgrade_cannot_edit_names_no_upgrade() {
    // `upgrade` reports a flow-style backend for a hand edit instead of
    // rewriting it, so doctor does not suggest running it.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    std::fs::write(
        &path,
        "backends: {fs: {http_url: \"https://fs.example.test/mcp\"}}\n",
    )
    .expect("write config");
    let row = check_hidden_keys(&path).expect("an older url key is listed");
    assert!(
        row.detail.contains("backends.<name>.http_url") && !row.detail.contains("upgrade"),
        "{}",
        row.detail
    );
}

/// MIK-8425 MIG.2 G2: a file that does not parse gives no row, and so prints
/// nothing from it; the parse error is dropped unformatted. The control (a
/// file that parses and sets a hidden key) proves the path runs and names
/// the key, never its value.
#[test]
fn a_file_that_does_not_parse_prints_nothing_from_it() {
    const SENTINEL: &str = "MIK8425-SENTINEL-7f3a";
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    std::fs::write(
        &path,
        format!("meta_mcp:\n  projection_mode: \"{SENTINEL}\n"),
    )
    .expect("write config");
    assert!(
        check_hidden_keys(&path).is_none(),
        "an unparsable file must give no row"
    );
    std::fs::write(&path, format!("meta_mcp:\n  projection_mode: {SENTINEL}\n"))
        .expect("write config");
    let row = check_hidden_keys(&path).expect("the control parses and sets a hidden key");
    let shown = format!("{row:?}");
    assert!(
        shown.contains("projection_mode"),
        "the row names the key: {shown}"
    );
    assert!(
        !shown.contains(SENTINEL),
        "the row never prints the value: {shown}"
    );
}

/// A config written before the second hide pass keeps working: a newly hidden
/// config key and a newly hidden environment variable both still take effect,
/// and doctor names the key. (Naming hidden variables is a separate change.)
#[test]
fn a_newly_hidden_key_and_variable_still_take_effect_and_doctor_names_the_key() {
    use crate::gateway::test_helpers::write_owner_only;
    let dir = crate::test_dir_keep::kept_tempdir();
    let env = dir.path().join("hidden.env");
    write_owner_only(&env, "MCP_GATEWAY_SERVER__PORT=39641\n").expect("env file");
    let path = dir.path().join("gateway.yaml");
    let config = format!(
        "env_files:\n  - '{}'\nsecurity:\n  tool_policy:\n    deny: ['sentinel_tool_9641']\n    log_denied: false\n",
        env.display()
    );
    write_owner_only(&path, config).expect("config");
    let cfg =
        crate::config::Config::load(Some(&path)).expect("a config with hidden settings loads");
    // The variable's effect: the overlay sets the listen port.
    assert_eq!(cfg.server.port, 39641);
    // The key's effect: a denied call writes no warning, where the default
    // writes one.
    let warnings = |policy: &crate::security::policy::ToolPolicy| {
        crate::test_log_capture::records(|| {
            assert!(
                policy.check("s", "sentinel_tool_9641").is_err(),
                "premise: the tool is denied"
            );
        })
        .iter()
        .filter(|r| r["fields"]["message"] == "Tool invocation denied by policy")
        .count()
    };
    let quiet = crate::security::policy::ToolPolicy::from_config(&cfg.security.tool_policy);
    assert_eq!(warnings(&quiet), 0, "log_denied: false writes no warning");
    let default = crate::security::policy::ToolPolicyConfig {
        deny: vec!["sentinel_tool_9641".to_owned()],
        ..crate::security::policy::ToolPolicyConfig::default()
    };
    let loud = crate::security::policy::ToolPolicy::from_config(&default);
    assert_eq!(warnings(&loud), 1, "control: the default warns once");
    let row = check_hidden_keys(&path).expect("doctor names a set hidden key");
    assert!(
        row.detail.contains("security.tool_policy.log_denied"),
        "{}",
        row.detail
    );
}

/// `kind: personal` is a setting an operator writes by hand (the hardened
/// posture admits a key held by one person), so doctor never calls it
/// hidden; a machine-written field of the same key still is.
#[test]
fn a_hand_written_api_key_kind_is_not_a_hidden_setting() {
    let raw = yaml("auth:\n  api_keys:\n    - name: k\n      kind: personal\n");
    assert!(
        set_hidden_keys(&raw).is_empty(),
        "{:?}",
        set_hidden_keys(&raw)
    );
    let raw = yaml("auth:\n  api_keys:\n    - name: k\n      kind: personal\n      cli_host: h\n");
    assert_eq!(set_hidden_keys(&raw), vec!["auth.api_keys[].cli_host"]);
}

/// A `cache` section holding only the retired `enabled` switch applies no
/// hidden setting, so doctor names none; a real cache setting is named.
#[test]
fn a_retired_cache_switch_alone_names_no_hidden_setting() {
    let raw = yaml("cache:\n  enabled: false\n");
    assert!(
        set_hidden_keys(&raw).is_empty(),
        "{:?}",
        set_hidden_keys(&raw)
    );
    let raw = yaml("cache:\n  enabled: false\n  max_entries: 10\n");
    assert_eq!(set_hidden_keys(&raw), vec!["cache.max_entries"]);
}
