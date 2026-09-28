// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #1876: a discovered server's env and headers reach the written backend,
//! and no other output. The sentinel stands for a credential.

use super::*;

const SENTINEL: &str = "SENTINEL-1876-secret-value";

fn secret(key: &str) -> SecretMap {
    [(key.to_string(), SENTINEL.to_string())]
        .into_iter()
        .collect()
}

fn stdio() -> DiscoveredServer {
    let mut server = DiscoveredServer::new(
        "srv".to_string(),
        "MCP server from Zed".to_string(),
        DiscoverySource::Zed,
        TransportConfig::Stdio {
            command: "npx -y some-server".to_string(),
            cwd: None,
            protocol_version: None,
        },
        ServerMetadata::default(),
    );
    server.env = secret("API_KEY");
    server
}

fn http() -> DiscoveredServer {
    let mut server = DiscoveredServer::new(
        "web".to_string(),
        "MCP server from Zed".to_string(),
        DiscoverySource::Zed,
        TransportConfig::for_url("https://mcp.example.test/mcp"),
        ServerMetadata::default(),
    );
    server.headers = secret("Authorization");
    server
}

#[test]
fn the_backend_carries_env_and_headers() {
    let backend = stdio().to_backend_config();
    assert_eq!(
        backend.env.get("API_KEY").map(String::as_str),
        Some(SENTINEL)
    );
    let backend = http().to_backend_config();
    assert_eq!(
        backend.headers.get("Authorization").map(String::as_str),
        Some(SENTINEL)
    );
}

#[test]
fn no_other_output_shows_a_value() {
    for server in [stdio(), http()] {
        let outputs = [
            format!("{server:?}"),
            format!("{server:#?}"),
            serde_json::to_string(&server).unwrap(),
            serde_yaml::to_string(&server).unwrap(),
            serde_json::to_string(&server.redacted_for_diagnostics()).unwrap(),
            server.diagnostic_value().to_string(),
        ];
        for text in outputs {
            assert!(!text.contains(SENTINEL), "value leaked: {text}");
        }
        let keys = serde_json::to_string(&server).unwrap();
        assert!(
            keys.contains("API_KEY") || keys.contains("Authorization"),
            "the keys stay visible: {keys}"
        );
    }
}
