// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2070: VS Code user settings nest MCP servers under `mcp.servers`
//! (<https://code.visualstudio.com/docs/copilot/customization/mcp-servers>),
//! next to non-server keys such as `mcp.inputs`.

use super::*;

async fn parse(settings: &str) -> Vec<DiscoveredServer> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    std::fs::write(&path, settings).unwrap();
    let mut servers = ConfigScanner::new()
        .parse_vscode_config(&path, DiscoverySource::VsCode)
        .await
        .expect("a valid settings file parses");
    servers.sort_by(|a, b| a.name.cmp(&b.name));
    servers
}

#[tokio::test]
async fn servers_under_mcp_servers_are_discovered() {
    let servers = parse(
        r#"{
          "editor.fontSize": 13,
          "mcp": {
            "inputs": [],
            "servers": {
              "files": {"type": "stdio", "command": "npx", "args": ["-y", "fs-server"], "env": {"K": "v"}},
              "remote": {"type": "http", "url": "https://mcp.example.test/mcp", "headers": {"Authorization": "Bearer t"}}
            }
          }
        }"#,
    )
    .await;

    let names: Vec<&str> = servers.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(
        names,
        ["files", "remote"],
        "only the entries under mcp.servers"
    );
    assert!(servers.iter().all(|s| s.source == DiscoverySource::VsCode));
    match &servers[0].transport {
        TransportConfig::Stdio { command, .. } => assert_eq!(
            crate::transport::split_command(command),
            Some(vec![
                "npx".to_string(),
                "-y".to_string(),
                "fs-server".to_string()
            ]),
            "stdio entry keeps its command and args"
        ),
        other => panic!("expected stdio, got {other:?}"),
    }
    assert_eq!(
        servers[0].env.expose().get("K").map(String::as_str),
        Some("v")
    );
    assert_eq!(
        servers[1]
            .headers
            .expose()
            .get("Authorization")
            .map(String::as_str),
        Some("Bearer t")
    );
    match &servers[1].transport {
        TransportConfig::Http { http_url, .. } => {
            assert_eq!(http_url, "https://mcp.example.test/mcp");
        }
        other => panic!("expected http, got {other:?}"),
    }
}

#[tokio::test]
async fn keys_directly_under_mcp_are_not_servers() {
    // `mcp.<name>` was never a VS Code shape; an entry there is not imported.
    let servers = parse(r#"{"mcp": {"stray": {"command": "npx"}}}"#).await;
    assert!(servers.is_empty(), "got {servers:?}");
}

#[tokio::test]
async fn a_settings_file_with_comments_and_trailing_commas_is_read() {
    let servers = parse(
        r#"{
          // VS Code writes settings.json as JSONC.
          "mcp": {
            /* user servers */
            "servers": {
              "files": {"command": "npx", "args": ["-y", "fs-server",],},
            },
          },
        }"#,
    )
    .await;
    let names: Vec<&str> = servers.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["files"]);
    match &servers[0].transport {
        TransportConfig::Stdio { command, .. } => assert_eq!(
            crate::transport::split_command(command),
            Some(vec![
                "npx".to_string(),
                "-y".to_string(),
                "fs-server".to_string()
            ]),
            "args next to a trailing comma survive"
        ),
        other => panic!("expected stdio, got {other:?}"),
    }
}
