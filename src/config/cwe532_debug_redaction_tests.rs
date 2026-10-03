// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Debug redaction of backend and OAuth config (CWE-532).

use super::*;

const SENTINEL: &str = "SENTINEL_SECRET_a1b2c3";

// BackendConfig::Debug must never recurse into the credential-injection
// rules, nor print `env`/`headers` values (Authorization bearers, API
// keys); only counts are surfaced.
#[test]
fn backend_config_debug_redacts_secret_rules() {
    let cfg = BackendConfig {
        env: HashMap::from([("OPENAI_API_KEY".to_string(), SENTINEL.to_string())]),
        headers: HashMap::from([("Authorization".to_string(), SENTINEL.to_string())]),
        secrets: vec![crate::secret_injection::CredentialRule {
            name: "openai_api_key".to_string(),
            credential_type: crate::secret_injection::CredentialType::ApiKey,
            value: SENTINEL.to_string(),
            inject_as: crate::secret_injection::InjectTarget::Header,
            inject_key: "Authorization".to_string(),
            tools: vec!["*".to_string()],
        }],
        ..Default::default()
    };
    let dbg = format!("{cfg:?}");
    assert!(!dbg.contains(SENTINEL), "leaked credential value: {dbg}");
    assert!(
        dbg.contains("<1 rules>"),
        "missing rule-count marker: {dbg}"
    );
    assert!(dbg.contains("<1 vars>"), "missing env-count marker: {dbg}");
    assert!(
        dbg.contains("<1 headers>"),
        "missing headers-count marker: {dbg}"
    );
}

// OAuthConfig::Debug must never surface the fixed client secret.
#[test]
fn oauth_config_debug_redacts_client_secret() {
    let cfg = OAuthConfig {
        enabled: true,
        scopes: vec!["read".to_string()],
        client_id: Some("client-123".to_string()),
        client_secret: Some(SENTINEL.to_string()),
        callback_host: None,
        callback_port: None,
        callback_path: None,
        token_refresh_buffer_secs: 300,
        shared_account: false,
    };
    let dbg = format!("{cfg:?}");
    assert!(!dbg.contains(SENTINEL), "leaked client_secret: {dbg}");
    assert!(
        dbg.contains("<redacted>"),
        "missing redaction marker: {dbg}"
    );
    assert!(
        dbg.contains("client-123"),
        "client_id should stay visible: {dbg}"
    );
}
