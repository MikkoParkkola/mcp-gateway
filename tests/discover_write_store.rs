// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `cap discover --write-config` end to end: the real binary, the real
//! scanner, and a client config file in the child's own home. A literal
//! value lands in the secret store and only its reference in the config; a
//! server the gateway could not run as the client does is skipped with its
//! reason, never its value.
//!
//! The child has its own home (`gateway_bin`), so neither the scan nor the
//! secret store touches the test runner's home or keychain. The scan also
//! lists running processes named like MCP servers (this test's own among
//! them), so only the two client-file servers are asserted on; a run that
//! adopts nothing is covered by the library tests.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::path::Path;
use std::process::Output;

const SECRET: &str = "zq-discover-write-secret";
const CLIENT_ONLY: &str = "zq-client-only-value";

fn write_owner_only(path: &Path, text: &str) {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).expect("dir");
    }
    mcp_gateway::gateway::test_helpers::write_owner_only(path, text).expect("write owner-only");
}

fn discover_write(home: &Path, config: &Path) -> Output {
    gateway_bin::command(home, gateway_bin::Inherit::Nothing)
        .current_dir(home)
        .args(["cap", "discover", "--write-config", "--config-path"])
        .arg(config)
        .output()
        .expect("the built mcp-gateway binary runs")
}

/// A gateway config choosing the files store, so the secrets land beside it.
fn files_store_config(home: &Path) -> std::path::PathBuf {
    let config = home.join("gateway.yaml");
    write_owner_only(&config, "secrets:\n  store: files\n");
    config
}

#[test]
fn d16_a_literal_is_stored_and_a_client_only_server_is_skipped() {
    let home = tempfile::tempdir().expect("home");
    let home = home.path();
    // Cursor's mcp.json sits at the same place under home on every platform.
    write_owner_only(
        &home.join(".cursor/mcp.json"),
        &serde_json::json!({"mcpServers": {
            "stored": {"command": "npx", "env": {"API_KEY": SECRET}},
            "client-only": {"command": "npx", "env": {"TOKEN": format!("${{input:{CLIENT_ONLY}}}")}},
        }})
        .to_string(),
    );
    let config = files_store_config(home);

    let output = discover_write(home, &config);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "{stdout}\n{stderr}");
    let written = std::fs::read_to_string(&config).expect("config");
    assert!(!written.contains(SECRET), "{written}");
    // The one `API_KEY:` line is the stored server's: its value is a files
    // reference, quoted or not.
    let reference = written
        .lines()
        .find_map(|line| line.trim().strip_prefix("API_KEY:"))
        .unwrap_or_else(|| panic!("no API_KEY line: {written}"))
        .trim()
        .trim_matches(|c| c == '\'' || c == '"');
    let path = reference
        .strip_prefix("file:")
        .unwrap_or_else(|| panic!("not a files reference: {reference}"));
    // The files store pads one `\n`, which the gateway's reader drops.
    assert_eq!(
        std::fs::read_to_string(path).expect("secret file"),
        format!("{SECRET}\n")
    );
    assert!(!written.contains("client-only"), "{written}");
    assert!(
        stderr.contains("\"client-only\": needs_client_only_secret (env.TOKEN)"),
        "{stderr}"
    );
    for leak in [SECRET, CLIENT_ONLY] {
        assert!(!stderr.contains(leak), "{leak} in {stderr}");
        assert!(!stdout.contains(leak), "{leak} in {stdout}");
    }
}
