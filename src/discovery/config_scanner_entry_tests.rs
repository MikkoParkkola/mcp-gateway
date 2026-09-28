// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #1876: a client's server entry keeps its env, headers and argument
//! boundaries through discovery, and a commented Zed settings file is read.

use std::path::Path;

use serde_json::json;

use super::*;

const SENTINEL: &str = "SENTINEL-1876-secret-value";

fn entry(value: &serde_json::Value) -> DiscoveredServer {
    ConfigScanner::parse_server_config(
        "srv",
        value,
        &DiscoverySource::ClaudeDesktop,
        Path::new("/client/config.json"),
    )
    .expect("entry imports")
}

#[test]
fn stdio_env_is_kept() {
    let server =
        entry(&json!({"command": "npx", "args": ["-y", "srv"], "env": {"API_KEY": SENTINEL}}));
    assert_eq!(
        server.env.expose().get("API_KEY").map(String::as_str),
        Some(SENTINEL)
    );
}

#[test]
fn http_headers_are_kept() {
    let server = entry(
        &json!({"url": "https://mcp.example.test/mcp", "headers": {"Authorization": SENTINEL}}),
    );
    assert_eq!(
        server
            .headers
            .expose()
            .get("Authorization")
            .map(String::as_str),
        Some(SENTINEL)
    );
}

#[test]
fn arguments_keep_their_boundaries() {
    let args = ["--config", "/Users/a b/c.json", r#"say "hi""#, ""];
    let server = entry(&json!({"command": "/opt/My Tools/srv", "args": args}));
    let TransportConfig::Stdio { command, .. } = &server.transport else {
        panic!("expected stdio");
    };
    let mut expected = vec!["/opt/My Tools/srv".to_string()];
    expected.extend(args.iter().map(|a| (*a).to_string()));
    assert_eq!(crate::transport::split_command(command), Some(expected));
}

#[tokio::test]
async fn a_commented_zed_settings_file_is_read() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    let text = r#"// Zed settings
{
  "theme": "One Dark", // trailing comment
  /* block */
  "context_servers": {
    "local": { "command": "npx", "args": ["-y", "srv",], "env": { "K": "v", }, },
    "remote": { "url": "https://mcp.example.test/mcp", },
  },
}
"#;
    crate::gateway::test_helpers::write_owner_only(&path, text).unwrap();
    let servers = ConfigScanner::new().parse_zed_config(&path).await.unwrap();
    let names: Vec<&str> = servers.iter().map(|s| s.name.as_str()).collect();
    assert!(
        names.contains(&"local") && names.contains(&"remote"),
        "{names:?}"
    );
    let local = servers.iter().find(|s| s.name == "local").unwrap();
    assert_eq!(local.env.expose().get("K").map(String::as_str), Some("v"));
}
