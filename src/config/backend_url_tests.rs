// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! P2c1 (MIK-8044 SURF.2): one backend `url` key. Its scheme picks the
//! transport; `http_url` and `ws_url` stay as hidden aliases. Every test goes
//! through `Config::load`, the path a user's file takes.

use super::*;

/// Writes `yaml` as `gateway.yaml` under `dir` and loads it.
fn load(dir: &std::path::Path, yaml: &str) -> Result<Config> {
    let path = dir.join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, yaml).expect("write config");
    Config::load(Some(&path))
}

/// The transport of backend `b` in a config holding only that backend.
fn transport_of(backend_yaml: &str) -> TransportConfig {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = load(dir.path(), &format!("backends:\n  b:\n{backend_yaml}"))
        .unwrap_or_else(|e| panic!("config loads: {e}"));
    config.backends["b"].transport.clone()
}

fn refusal(backend_yaml: &str) -> String {
    let dir = tempfile::tempdir().expect("tempdir");
    match load(dir.path(), &format!("backends:\n  b:\n{backend_yaml}")) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("expected the config to be refused, it loaded"),
    }
}

#[test]
fn an_http_url_builds_the_http_transport() {
    for url in ["http://127.0.0.1:9000/mcp", "https://mcp.example.com/mcp"] {
        match transport_of(&format!("    url: \"{url}\"\n")) {
            TransportConfig::Http { http_url, .. } => assert_eq!(http_url, url),
            other => panic!("{url} built {other:?}"),
        }
    }
}

#[test]
fn a_ws_url_builds_the_websocket_transport() {
    for url in ["ws://127.0.0.1:9000/mcp", "wss://mcp.example.com/mcp"] {
        match transport_of(&format!("    url: \"{url}\"\n")) {
            TransportConfig::WebSocket { ws_url, .. } => assert_eq!(ws_url, url),
            other => panic!("{url} built {other:?}"),
        }
    }
}

#[test]
fn url_with_an_alias_is_refused_naming_both() {
    for alias in ["http_url", "ws_url"] {
        let message = refusal(&format!(
            "    url: \"https://a.example.com/mcp\"\n    {alias}: \"https://b.example.com/mcp\"\n"
        ));
        assert!(
            message.contains("b.url") && message.contains(&format!("b.{alias}")),
            "{alias}: {message}"
        );
    }
}

#[test]
fn a_url_with_another_scheme_is_refused_naming_the_key() {
    // A URL can carry credentials, so the refusal names the key, never the URL.
    let message = refusal("    url: \"ftp://a.example.com/mcp?token=canary-p2c1\"\n");
    assert!(message.contains("b.url"), "{message}");
    assert!(
        !message.contains("canary-p2c1") && !message.contains("a.example.com"),
        "the refusal echoed the URL: {message}"
    );
}

#[test]
fn the_3x_keys_load_unchanged() {
    match transport_of("    http_url: \"https://a.example.com/mcp\"\n") {
        TransportConfig::Http { http_url, .. } => assert_eq!(http_url, "https://a.example.com/mcp"),
        other => panic!("http_url built {other:?}"),
    }
    match transport_of("    ws_url: \"wss://a.example.com/mcp\"\n") {
        TransportConfig::WebSocket { ws_url, .. } => assert_eq!(ws_url, "wss://a.example.com/mcp"),
        other => panic!("ws_url built {other:?}"),
    }
}

#[test]
fn cleartext_credentials_on_url_are_refused_as_on_the_alias() {
    let headers = "    headers:\n      Authorization: \"Bearer t\"\n";
    let via_url = refusal(&format!("    url: \"ws://10.0.0.5/mcp\"\n{headers}"));
    let via_alias = refusal(&format!("    ws_url: \"ws://10.0.0.5/mcp\"\n{headers}"));
    assert_eq!(via_url, via_alias);
}
