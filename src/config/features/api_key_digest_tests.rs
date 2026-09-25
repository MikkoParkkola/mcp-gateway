// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! E4 (APIKEY.1): API keys are configured as sha256 digests, with an optional
//! expiry. Every cell loads a real YAML file through `Config::load`, so the
//! refusal is proven reachable on the path a deployment takes.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::Error;
use crate::config::Config;
use crate::gateway::auth::ResolvedAuthConfig;

const KEY: &str = "k-abc";
/// Distinctive, so an error naming it cannot match by accident.
const VAR: &str = "E4_DIGEST_VAR";

fn digest_of(key: &str) -> String {
    format!("sha256:{}", crate::hashing::sha256_hex(key.as_bytes()))
}

fn quoted(path: &Path) -> String {
    serde_json::to_string(&path.to_string_lossy().as_ref()).expect("path must JSON-quote")
}

/// Write `auth_body` (already indented under `auth:`) and an optional env file,
/// then load. Auth stays disabled so no unrelated enabled-auth rule decides
/// the outcome; the digest rules hold whether or not auth is on.
fn load(auth_body: &str, env: Option<&str>) -> (tempfile::TempDir, crate::Result<Config>) {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let mut yaml = String::new();
    if let Some(env) = env {
        let env_path: PathBuf = dir.path().join("keys.env");
        crate::gateway::test_helpers::write_owner_only(&env_path, env).expect("env file");
        writeln!(yaml, "env_files:\n  - {}", quoted(&env_path)).expect("String write");
    }
    yaml.push_str("auth:\n  enabled: false\n  api_keys:\n");
    yaml.push_str(auth_body);
    let path = dir.path().join("config.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, yaml).expect("config file");
    let loaded = Config::load(Some(&path));
    (dir, loaded)
}

fn validation_error(result: crate::Result<Config>, case: &str) -> String {
    match result {
        Err(Error::ConfigValidation(message)) => message,
        Err(other) => panic!("{case}: expected ConfigValidation, got {other}"),
        Ok(_) => panic!("{case}: loaded, but it must be refused"),
    }
}

// E4-T1
#[test]
fn plaintext_api_key_fails_to_load() {
    let (_dir, literal) = load("    - name: laptop\n      key: k-abc\n", None);
    let message = validation_error(literal, "literal key");
    assert!(message.contains("mcp-gateway hash-key"), "{message}");
    assert!(message.contains("laptop"), "{message}");

    // `env:` with the variable unset: the refusal comes first, and the
    // variable is never looked up, so no missing-variable error.
    let (_dir, reference) = load("    - name: phone\n      key: env:E4_UNSET_KEY_VAR\n", None);
    let message = validation_error(reference, "env key");
    assert!(message.contains("mcp-gateway hash-key"), "{message}");
    assert!(message.contains("phone"), "{message}");
    assert!(
        !message.contains("missing environment variable"),
        "{message}"
    );
}

// E4-T7
#[test]
fn expired_key_does_not_block_startup() {
    let body = format!(
        "    - name: lapsed\n      key_sha256: \"{}\"\n      expires_at: \"2001-01-01T00:00:00Z\"\n    - name: live\n      key_sha256: \"{}\"\n",
        digest_of("k-old"),
        digest_of(KEY)
    );
    let (_dir, loaded) = load(&body, None);
    let config = loaded.expect("one lapsed key must not keep the gateway from starting");
    let resolved = ResolvedAuthConfig::try_from_config(&config.auth).expect("resolves");
    let client = resolved
        .validate_token(KEY)
        .expect("the live key authenticates");
    assert_eq!(client.name, "live");
    assert!(resolved.validate_token("k-old").is_none());
}

// E4-T8
#[test]
fn api_key_config_debug_redacts() {
    let digest = digest_of(KEY);
    let from_digest: super::ApiKeyConfig =
        serde_json::from_value(serde_json::json!({"name": "ops", "key_sha256": digest}))
            .expect("a digest key deserializes");
    let printed = format!("{from_digest:?}");
    assert!(printed.contains("ops"), "{printed}");
    assert!(
        !printed.contains(&digest[7..19]),
        "digest leaked: {printed}"
    );

    // A legacy plaintext key parses (so it can be refused by name) and must
    // not print either.
    let legacy: super::ApiKeyConfig =
        serde_json::from_value(serde_json::json!({"name": "ops", "key": KEY}))
            .expect("a legacy key still parses");
    let printed = format!("{legacy:?}");
    assert!(!printed.contains(KEY), "key leaked: {printed}");
}

// E4-T9
#[test]
fn malformed_digest_fails_to_load() {
    let hex = crate::hashing::sha256_hex(KEY.as_bytes());
    let cases = [
        "sha256:xyz".to_string(),
        format!("sha256:{}", &hex[..63]),
        format!("sha256:{}", hex.to_uppercase()),
        hex.clone(),
    ];
    for spec in cases {
        let body = format!("    - name: ops\n      key_sha256: \"{spec}\"\n");
        let (_dir, loaded) = load(&body, None);
        let message = validation_error(loaded, &spec);
        assert!(message.contains("key_sha256"), "{spec}: {message}");
    }
}

// E4-T12
#[test]
fn both_key_and_digest_fails_to_load() {
    let body = format!(
        "    - name: ops\n      key: k-abc\n      key_sha256: \"{}\"\n",
        digest_of(KEY)
    );
    let (_dir, loaded) = load(&body, None);
    let message = validation_error(loaded, "both fields");
    assert!(message.contains("ops"), "{message}");
}

// E4-T13
#[test]
fn env_digest_reference_authenticates() {
    let env = format!("{VAR}={}\n", digest_of(KEY));
    let body = format!("    - name: ops\n      key_sha256: env:{VAR}\n");
    let (_dir, loaded) = load(&body, Some(&env));
    let config = loaded.expect("an env: digest loads");
    let resolved = ResolvedAuthConfig::try_from_config(&config.auth).expect("resolves");
    assert_eq!(
        resolved.validate_token(KEY).expect("authenticates").name,
        "ops"
    );
}

// E4-T13b
#[test]
fn env_reference_holding_plaintext_is_refused() {
    let env = format!("{VAR}={KEY}\n");
    let body = format!("    - name: ops\n      key_sha256: env:{VAR}\n");
    let (_dir, loaded) = load(&body, Some(&env));
    let message = validation_error(loaded, "plaintext in the variable");
    assert!(message.contains(VAR), "{message}");
    assert!(
        !message.contains(KEY),
        "the variable's value leaked: {message}"
    );
}

// Neither field: a key with no credential at all is refused, not skipped.
#[test]
fn neither_key_nor_digest_fails_to_load() {
    let (_dir, loaded) = load("    - name: ops\n      backends: [\"*\"]\n", None);
    let message = validation_error(loaded, "neither field");
    assert!(message.contains("ops"), "{message}");
    assert!(message.contains("key_sha256"), "{message}");
}
