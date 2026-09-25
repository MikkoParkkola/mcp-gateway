// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F17-T11: discovery builds a `ws`/`wss` URL as a WebSocket backend, on both
//! URL-carrying paths (an `MCP_SERVER_*_URL` variable and a client-config `url`).

use std::sync::Arc;

use serde_json::json;

use super::ConfigScanner;
use crate::config::TransportConfig;
use crate::discovery::DiscoverySource;

fn ws_url_of(transport: &TransportConfig) -> Option<&str> {
    match transport {
        TransportConfig::WebSocket { ws_url, .. } => Some(ws_url),
        _ => None,
    }
}

#[test]
fn an_env_var_wss_endpoint_is_discovered_as_websocket() {
    let dir = tempfile::tempdir().unwrap();
    let env_file = dir.path().join(".env");
    crate::gateway::test_helpers::write_owner_only(&env_file, "MCP_SERVER_F17WS_URL=wss://h/mcp\n")
        .unwrap();
    let overlay = Arc::new(crate::config::EnvOverlay::from_paths(&[env_file]));
    let env = Arc::new(crate::config::LiveEnv::new(
        overlay,
        crate::config::ResolvedEnvFiles::default(),
    ));
    let servers = ConfigScanner::new()
        .with_env(env)
        .scan_environment()
        .unwrap();
    let server = servers
        .iter()
        .find(|s| s.name == "f17ws")
        .expect("the env-file endpoint is discovered");
    assert_eq!(ws_url_of(&server.transport), Some("wss://h/mcp"));
}

#[test]
fn a_client_config_wss_url_is_discovered_as_websocket() {
    let server = ConfigScanner::parse_server_config(
        "rt",
        &json!({ "url": "WSS://h/mcp" }),
        &DiscoverySource::ClaudeDesktop,
        std::path::Path::new("/dev/null"),
    )
    .expect("a url entry is discovered");
    assert_eq!(ws_url_of(&server.transport), Some("WSS://h/mcp"));
}
