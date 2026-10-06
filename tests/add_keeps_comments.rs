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
