// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A configured API key is never serialised whole, and the config that holds
//! keys writes them exactly as before.
//!
//! `ApiKeyConfig` does not implement `Serialize`, so `json!(key)` or
//! `to_value(&key)` fails to compile anywhere; `AuthConfig` writes its keys
//! through a private mirror. The golden below pins those bytes, in YAML and
//! JSON, for every serialisation-relevant shape of every field.

use crate::config::{ApiKeyBinding, ApiKeyConfig, ApiKeyKind, AuthConfig};

/// Reads `true` only for a type that implements `Serialize`: the inherent
/// const on the bounded impl shadows the trait's blanket const.
struct Probe<T>(std::marker::PhantomData<T>);

trait NotSerialize {
    const IS_SERIALIZE: bool = false;
}

impl<T> NotSerialize for Probe<T> {}

impl<T: serde::Serialize> Probe<T> {
    const IS_SERIALIZE: bool = true;
}

/// Kills "a key type implements Serialize again": the probe reads true for a
/// type that does (positive control) and false for both key types.
#[test]
fn neither_key_type_is_serialize() {
    assert!(Probe::<ApiKeyBinding>::IS_SERIALIZE, "positive control");
    assert!(!Probe::<ApiKeyConfig>::IS_SERIALIZE, "ApiKeyConfig");
    assert!(
        !Probe::<crate::gateway::auth::ResolvedApiKey>::IS_SERIALIZE,
        "ResolvedApiKey"
    );
}

fn at(rfc3339: &str) -> chrono::DateTime<chrono::Utc> {
    rfc3339.parse().expect("an RFC 3339 instant")
}

/// One key per shape: a legacy plaintext key with every option absent, every
/// option present, and the list fields in their other states.
fn shapes() -> AuthConfig {
    let hex = |c: char| std::iter::repeat_n(c, 64).collect::<String>();
    let minimal = ApiKeyConfig {
        key: Some("plaintext-never-written".into()),
        name: "minimal".into(),
        ..ApiKeyConfig::default()
    };
    let full = ApiKeyConfig {
        key: None,
        key_sha256: Some(format!("sha256:{}", hex('a'))),
        expires_at: Some(at("2030-01-02T03:04:05Z")),
        name: "full".into(),
        rate_limit: 60,
        backends: vec!["one".into(), "two".into()],
        allowed_tools: Some(Vec::new()),
        denied_tools: Some(vec!["tool*".into()]),
        admin: true,
        kind: ApiKeyKind::Personal,
        principal: Some("0123456789ab".into()),
        previous_key_sha256: Some("env:PREVIOUS_KEY".into()),
        previous_expires_at: Some(at("2030-02-03T04:05:06Z")),
        approved_by: Some(ApiKeyBinding {
            quota_principal: hex('b'),
            digest_tag: hex('c'),
        }),
        cli_host: Some("host-1".into()),
    };
    let lists = ApiKeyConfig {
        key_sha256: Some("env:KEY_DIGEST".into()),
        name: "lists".into(),
        backends: vec!["*".into()],
        allowed_tools: Some(vec!["a".into(), "b*".into()]),
        denied_tools: Some(Vec::new()),
        ..ApiKeyConfig::default()
    };
    AuthConfig {
        api_keys: vec![minimal, full, lists],
        ..AuthConfig::default()
    }
}

/// The config's YAML and JSON before the key type stopped being Serialize.
/// A change to another auth field's output changes them too: take the new
/// bytes from the failure message and check that only that field moved.
const GOLDEN_YAML: &str = r"enabled: false
bearer_token: null
api_keys:
- name: minimal
  rate_limit: 0
  backends: []
  allowed_tools: null
  denied_tools: null
  admin: false
- key_sha256: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  expires_at: 2030-01-02T03:04:05Z
  name: full
  rate_limit: 60
  backends:
  - one
  - two
  allowed_tools: []
  denied_tools:
  - tool*
  admin: true
  kind: personal
  principal: 0123456789ab
  previous_key_sha256: env:PREVIOUS_KEY
  previous_expires_at: 2030-02-03T04:05:06Z
  approved_by:
    quota_principal: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    digest_tag: cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
  cli_host: host-1
- key_sha256: env:KEY_DIGEST
  name: lists
  rate_limit: 0
  backends:
  - '*'
  allowed_tools:
  - a
  - b*
  denied_tools: []
  admin: false
public_paths:
- /health
client_circuit_breaker: null
single_user: false
dashboard_session:
  idle_timeout_secs: 1800
  absolute_timeout_secs: 28800
";
const GOLDEN_JSON: &str = concat!(
    r#"{"enabled":false,"bearer_token":null,"api_keys":[{"name":"minimal","rate_limit":0"#,
    r#","backends":[],"allowed_tools":null,"denied_tools":null,"admin":false}"#,
    r#",{"key_sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa""#,
    r#","expires_at":"2030-01-02T03:04:05Z","name":"full","rate_limit":60,"backends":["one""#,
    r#","two"],"allowed_tools":[],"denied_tools":["tool*"],"admin":true,"kind":"personal""#,
    r#","principal":"0123456789ab","previous_key_sha256":"env:PREVIOUS_KEY""#,
    r#","previous_expires_at":"2030-02-03T04:05:06Z""#,
    r#","approved_by":{"#,
    r#""quota_principal":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb""#,
    r#","digest_tag":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}"#,
    r#","cli_host":"host-1"},{"key_sha256":"env:KEY_DIGEST","name":"lists","rate_limit":0"#,
    r#","backends":["*"],"allowed_tools":["a","b*"],"denied_tools":[],"admin":false}]"#,
    r#","public_paths":["/health"],"client_circuit_breaker":null,"single_user":false"#,
    r#","dashboard_session":{"idle_timeout_secs":1800,"absolute_timeout_secs":28800}}"#,
);

/// Kills "the mirror drops, renames, reorders or re-skips a field": the auth
/// config's YAML and JSON, keys included, match the bytes written before the
/// change for every field shape.
#[test]
fn keys_are_written_exactly_as_before() {
    let auth = shapes();
    let yaml = crate::yaml::to_string(&auth).expect("yaml");
    let json = serde_json::to_string(&auth).expect("json");
    assert_eq!(yaml, GOLDEN_YAML, "YAML:\n{yaml}");
    assert_eq!(json, GOLDEN_JSON, "JSON:\n{json}");

    // The same keys through the whole config: the config file writer and the
    // reload diff (canonical JSON of `config.auth`) serialise from there.
    let config = crate::config::Config {
        auth: shapes(),
        ..crate::config::Config::default()
    };
    let config_yaml = crate::yaml::to_string(&config).expect("config yaml");
    let nested: String = GOLDEN_YAML
        .lines()
        .map(|line| format!("  {line}\n"))
        .collect();
    assert!(
        config_yaml.contains(&format!("auth:\n{nested}")),
        "config YAML:\n{config_yaml}"
    );
    let config_json = serde_json::to_value(&config).expect("config json");
    let golden: serde_json::Value = serde_json::from_str(GOLDEN_JSON).expect("golden json");
    assert_eq!(config_json["auth"], golden, "config JSON auth section");
}
