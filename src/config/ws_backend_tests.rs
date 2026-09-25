// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F17 config rows: parse (T1), load validation (T4, T5, T16), URL
//! constructors (T11). Every validation row drives `Config::validate`, the
//! entry point config load calls.

use std::collections::HashMap;

use super::super::{BackendConfig, Config, OAuthConfig, TransportConfig};
use crate::gateway::ui::backend_ops::resolve_transport;
use crate::identity_propagation::IdentityPropagationConfig;
use crate::secret_injection::CredentialRule;

/// A credential-shaped URL. No refusal text may echo any part of it.
const CANARY: &str = "canary-f17";

fn ws(url: &str) -> BackendConfig {
    BackendConfig {
        transport: TransportConfig::WebSocket {
            ws_url: url.to_string(),
            protocol_version: None,
        },
        ..Default::default()
    }
}

fn with_header(mut backend: BackendConfig) -> BackendConfig {
    backend.headers = HashMap::from([("Authorization".to_string(), "Bearer t".to_string())]);
    backend
}

fn validate(backend: BackendConfig) -> crate::Result<()> {
    let mut config = Config::default();
    config.backends.insert("rt".to_string(), backend);
    config.validate()
}

fn refusal(backend: BackendConfig) -> String {
    match validate(backend) {
        Err(e) => e.to_string(),
        Ok(()) => panic!("expected the config to be refused, it was accepted"),
    }
}

// ── T1 ───────────────────────────────────────────────────────────────────────

#[test]
fn t1_ws_url_parses_to_the_websocket_variant() {
    let backend: BackendConfig = serde_yaml::from_str(
        "ws_url: wss://rt.example.com/mcp\n\
         protocol_version: \"2025-11-25\"\n\
         headers: { Authorization: \"Bearer x\" }\n\
         timeout: 30s\n",
    )
    .expect("a ws_url backend parses");
    match &backend.transport {
        TransportConfig::WebSocket {
            ws_url,
            protocol_version,
        } => {
            assert_eq!(ws_url, "wss://rt.example.com/mcp");
            assert_eq!(protocol_version.as_deref(), Some("2025-11-25"));
        }
        other => panic!("expected WebSocket, got {other:?}"),
    }
    assert_eq!(backend.transport.transport_type(), "websocket");
    assert!(!backend.transport.carries_identity_headers());
}

// ── T4 ───────────────────────────────────────────────────────────────────────

#[test]
fn t4_cleartext_ws_with_credentials_off_host_is_refused() {
    let message = refusal(with_header(ws("ws://10.0.0.5/mcp")));
    assert!(message.contains("cleartext"), "{message}");
    assert!(!message.contains("10.0.0.5"), "no URL in the text: {message}");
}

#[test]
fn t4_cleartext_opt_in_loopback_and_tls_are_accepted() {
    let mut opted_in = with_header(ws("ws://10.0.0.5/mcp"));
    opted_in.allow_cleartext_credentials = true;
    validate(opted_in).expect("allow_cleartext_credentials accepts ws://");
    validate(with_header(ws("ws://127.0.0.1:9000/mcp"))).expect("loopback ws:// is accepted");
    validate(with_header(ws("wss://rt.example.com/mcp"))).expect("wss:// is accepted");
}

#[test]
fn t4_empty_ws_url_is_refused_naming_the_key() {
    let message = refusal(ws(""));
    assert!(message.contains("has an empty ws_url"), "{message}");
}

#[test]
fn t4_non_websocket_scheme_is_refused_without_echoing_the_url() {
    let message = refusal(ws(&format!("https://user:{CANARY}@h/mcp?token={CANARY}")));
    assert!(message.contains("ws_url"), "{message}");
    assert!(message.contains("ws://") && message.contains("wss://"), "{message}");
    assert!(!message.contains(CANARY), "no URL in the text: {message}");
    let unparsable = refusal(ws(&format!("not a url {CANARY}")));
    assert!(!unparsable.contains(CANARY), "no URL in the text: {unparsable}");
}

// ── T5 ───────────────────────────────────────────────────────────────────────

fn oauth() -> OAuthConfig {
    OAuthConfig {
        enabled: true,
        scopes: Vec::new(),
        client_id: None,
        client_secret: None,
        callback_host: None,
        callback_port: None,
        callback_path: None,
        token_refresh_buffer_secs: 300,
        shared_account: false,
    }
}

fn secret(inject_as: &str) -> CredentialRule {
    serde_yaml::from_str(&format!(
        "{{name: k, value: \"env:K\", inject_as: {inject_as}, inject_key: \"X-Key\"}}"
    ))
    .expect("credential rule sample parses")
}

#[test]
fn t5_oauth_on_ws_url_is_refused() {
    let mut backend = ws("wss://rt.example.com/mcp");
    backend.oauth = Some(oauth());
    let message = refusal(backend);
    assert!(message.contains("oauth"), "{message}");
}

#[test]
fn t5_identity_propagation_on_ws_url_is_refused() {
    let mut backend = ws("wss://rt.example.com/mcp");
    backend.identity_propagation = Some(
        serde_yaml::from_str::<IdentityPropagationConfig>(
            "{strategy: token_exchange, audience: a, session_mode: stateless}",
        )
        .unwrap(),
    );
    assert!(refusal(backend).contains("identity_propagation"));
}

#[test]
fn t5_header_and_query_secrets_on_ws_url_are_refused() {
    for target in ["header", "query"] {
        let mut backend = ws("wss://rt.example.com/mcp");
        backend.secrets = vec![secret(target)];
        let message = refusal(backend);
        assert!(message.contains("secrets"), "{target}: {message}");
    }
}

#[test]
fn t5_argument_secrets_on_ws_url_are_accepted() {
    let mut backend = ws("wss://rt.example.com/mcp");
    backend.secrets = vec![secret("argument")];
    validate(backend).expect("an argument secret never touches the handshake");
}

// ── T16 ──────────────────────────────────────────────────────────────────────

fn ws_with_version(version: &str) -> BackendConfig {
    BackendConfig {
        transport: TransportConfig::WebSocket {
            ws_url: "wss://rt.example.com/mcp".to_string(),
            protocol_version: Some(version.to_string()),
        },
        ..Default::default()
    }
}

#[test]
fn t16_a_stateless_protocol_version_on_ws_url_is_refused() {
    for version in ["2026-07-28", "2027-01-01"] {
        let message = refusal(ws_with_version(version));
        assert!(message.contains("protocol_version"), "{version}: {message}");
    }
    validate(ws_with_version("2025-11-25")).expect("a legacy revision loads");
}

// ── T11 ──────────────────────────────────────────────────────────────────────

fn is_ws(transport: &TransportConfig) -> bool {
    matches!(transport, TransportConfig::WebSocket { .. })
}

#[test]
fn t11_for_url_selects_websocket_by_scheme_in_any_case() {
    for url in ["wss://h/mcp", "ws://h/mcp", "WS://h/mcp", "Wss://h/mcp"] {
        assert!(is_ws(&TransportConfig::for_url(url)), "{url}");
    }
    for url in ["https://h/mcp", "http://h/wss", "wsx://h"] {
        assert!(
            matches!(TransportConfig::for_url(url), TransportConfig::Http { .. }),
            "{url}"
        );
    }
}

#[test]
fn t11_admin_ui_and_cli_add_store_a_pasted_wss_url_as_websocket() {
    for url in ["wss://h/mcp", "WS://h/mcp"] {
        let (transport, _) = resolve_transport("rt", None, Some(url), None).unwrap();
        match transport {
            TransportConfig::WebSocket { ws_url, .. } => assert_eq!(ws_url, url),
            other => panic!("{url}: expected WebSocket, got {other:?}"),
        }
    }
}

// ── T8 ───────────────────────────────────────────────────────────────────────

fn load(backend_yaml: &str) -> crate::Result<Config> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, format!("backends:\n  x:\n{backend_yaml}"))
        .unwrap();
    Config::load(Some(&path))
}

fn load_refusal(backend_yaml: &str) -> String {
    match load(backend_yaml) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("expected the load to be refused"),
    }
}

#[test]
fn t8_ws_url_beside_http_url_is_refused_as_read_by_another_transport() {
    let message = load_refusal("    http_url: \"https://h/mcp\"\n    ws_url: \"wss://h/mcp\"\n");
    assert!(
        message.contains("`backends.x.ws_url` is never read: `http_url` selects the http transport"),
        "{message}"
    );
}

#[test]
fn t8_streamable_http_on_ws_url_is_refused_naming_the_websocket_transport() {
    let message = load_refusal("    ws_url: \"wss://h/mcp\"\n    streamable_http: true\n");
    assert!(
        message.contains(
            "`backends.x.streamable_http` is never read: `ws_url` selects the websocket transport"
        ),
        "{message}"
    );
}

#[test]
fn t8_ws_url_alone_loads() {
    let config = load("    ws_url: \"wss://h/mcp\"\n").expect("a ws_url backend loads");
    assert_eq!(config.backends["x"].transport.transport_type(), "websocket");
}
