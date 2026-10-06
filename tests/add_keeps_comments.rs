// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway add` and `remove` keep the comments in gateway.yaml, through the shipped
//! binary.
//!
//! Both re-serialised the whole config, which dropped every comment,
//! including the security warning `init` writes next to `bearer_token`.

use std::path::Path;

fn gateway(home: &Path, args: &[&str]) {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_mcp-gateway"))
        .args(args)
        .current_dir(home)
        .env("HOME", home)
        .env("MCP_GATEWAY_TEST_HOME_DIR", home)
        .output()
        .expect("run mcp-gateway");
    assert!(
        output.status.success(),
        "{args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn comments(yaml: &str) -> Vec<&str> {
    yaml.lines()
        .map(str::trim)
        .filter(|line| line.starts_with('#'))
        .collect()
}

#[test]
fn add_keeps_the_comments_init_wrote() {
    for init_args in [&["init"][..], &["init", "--profile", "minimal"][..]] {
        let home = tempfile::tempdir().expect("home");
        let path = home.path().join("gateway.yaml");
        gateway(home.path(), init_args);
        let before = std::fs::read_to_string(&path).expect("init wrote gateway.yaml");
        assert!(before.contains("Do not commit it."), "init's warning moved");

        gateway(
            home.path(),
            &["add", "--url", "https://mcp.example.test/mcp", "remote"],
        );
        gateway(home.path(), &["add", "--command", "echo hi", "local"]);

        let after = std::fs::read_to_string(&path).expect("gateway.yaml");
        for comment in comments(&before) {
            assert!(
                after.contains(comment),
                "{init_args:?}: `add` dropped {comment:?}:\n{after}"
            );
        }
        let config = mcp_gateway::config::Config::load_literal(Some(&path)).expect("loads");
        assert!(
            config.backends.contains_key("remote") && config.backends.contains_key("local"),
            "{init_args:?}: both backends must be added:\n{after}"
        );

        gateway(home.path(), &["remove", "remote"]);
        let removed = std::fs::read_to_string(&path).expect("gateway.yaml");
        for comment in comments(&before) {
            assert!(
                removed.contains(comment),
                "{init_args:?}: `remove` dropped {comment:?}:\n{removed}"
            );
        }
        let config = mcp_gateway::config::Config::load_literal(Some(&path)).expect("loads");
        assert!(
            !config.backends.contains_key("remote") && config.backends.contains_key("local"),
            "{init_args:?}: `remove` must take out only its backend:\n{removed}"
        );
    }
}

/// `remove` alone, on a hand-written config: the row that bites the old
/// re-serialising `remove` without depending on `add`.
#[test]
fn remove_keeps_hand_written_comments() {
    let home = tempfile::tempdir().expect("home");
    let path = home.path().join("gateway.yaml");
    let yaml = "# operator notes: keep this file under review\n\
                server:\n  port: 39400  # fixed for the firewall rule\n\
                \n# backends we run\nbackends:\n  # the one that stays\n  keep:\n    command: \"echo keep\"\n  \
                drop:\n    command: \"echo drop\"\n";
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, yaml).expect("write");

    gateway(home.path(), &["remove", "drop"]);

    let after = std::fs::read_to_string(&path).expect("gateway.yaml");
    for comment in comments(yaml) {
        assert!(
            after.contains(comment),
            "`remove` dropped {comment:?}:\n{after}"
        );
    }
    assert!(
        after.contains("# fixed for the firewall rule"),
        "trailing comment lost:\n{after}"
    );
    let config = mcp_gateway::config::Config::load_literal(Some(&path)).expect("loads");
    assert!(config.backends.contains_key("keep") && !config.backends.contains_key("drop"));
}

#[test]
fn a_file_another_writer_broke_is_not_spliced_into() {
    use mcp_gateway::config::{BackendConfig, Config};
    use mcp_gateway::config_persistence::{
        load_existing_or_default, write_config_keeping_comments,
    };

    let home = tempfile::tempdir().expect("home");
    let path = home.path().join("gateway.yaml");
    std::fs::write(&path, "backends: {}\n").expect("write");
    let before = load_existing_or_default(&path).expect("load");
    let mut config = before.clone();
    let backend: BackendConfig = serde_yaml::from_str("command: echo\n").expect("backend");
    config.backends.insert("new".into(), backend);
    // Another writer adds a key the loader refuses after `add` loaded the file.
    std::fs::write(&path, "backends: {}\nnot_a_gateway_key: 1\n").expect("write");

    write_config_keeping_comments(&path, &before, &config, "new").expect("write config");
    let written = std::fs::read_to_string(&path).expect("read");
    Config::load_literal(Some(&path))
        .unwrap_or_else(|e| panic!("the written config must load: {e}\n{written}"));
}
