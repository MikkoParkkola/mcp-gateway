// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Debug output of the auth configuration never carries a credential (CWE-532).

use super::*;

const SENTINEL: &str = "SENTINEL_SECRET_a1b2c3";

// AuthConfig::Debug must redact the bearer token and never print API keys.
#[test]
fn auth_config_debug_redacts_bearer_token() {
    let cfg = AuthConfig {
        enabled: true,
        bearer_token: Some(SENTINEL.to_string()),
        ..AuthConfig::default()
    };
    let dbg = format!("{cfg:?}");
    assert!(!dbg.contains(SENTINEL), "leaked bearer_token: {dbg}");
    assert!(
        dbg.contains("<redacted>"),
        "missing redaction marker: {dbg}"
    );
}

// AgentDefinitionConfig::Debug must redact the HS256 secret while keeping
// the (non-secret) RSA public key visible.
#[test]
fn agent_definition_config_debug_redacts_hs256_secret() {
    let cfg = AgentDefinitionConfig {
        client_id: "agent-1".to_string(),
        name: "Agent One".to_string(),
        hs256_secret: Some(SENTINEL.to_string()),
        rs256_public_key: Some("-----BEGIN PUBLIC KEY-----".to_string()),
        scopes: vec!["tools:*".to_string()],
        issuer: None,
        audience: None,
    };
    let dbg = format!("{cfg:?}");
    assert!(!dbg.contains(SENTINEL), "leaked hs256_secret: {dbg}");
    assert!(
        dbg.contains("<redacted>"),
        "missing redaction marker: {dbg}"
    );
    assert!(
        dbg.contains("BEGIN PUBLIC KEY"),
        "public key is not secret and should stay visible: {dbg}"
    );
}
