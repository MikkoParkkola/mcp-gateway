// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! ADR-028: every gateway.yaml secret slot accepts `keychain:NAME` the way
//! it accepts `env:` and `file:`, through a whole `Config` load.

use std::sync::Arc;

use super::Config;
use super::keychain::{FakeKeychain, with_test_keychain};

const BEARER: &str = "kc-bearer-0123456789abcdef0123456789abcdef";
const HS256: &str = "kc-hs256-secret-0123456789abcdef0123456789";
const ADMIN: &str = "kc-admin-token-0123456789abcdef0123456789";
const CURRENT_B64: &str = "UVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVE=";

fn api_digest() -> String {
    format!("sha256:{}", crate::hashing::sha256_hex(b"kc-api-key"))
}

fn fake() -> Arc<FakeKeychain> {
    let fake = Arc::new(FakeKeychain::default());
    fake.insert("gw.bearer", BEARER.as_bytes());
    fake.insert("gw.api", api_digest().as_bytes());
    fake.insert("gw.hs256", HS256.as_bytes());
    fake.insert("gw.admin", ADMIN.as_bytes());
    fake.insert("gw.current", CURRENT_B64.as_bytes());
    fake
}

/// Every slot as `keychain:`. `enabled` switches on the sections whose
/// references are required (an unresolved one in a disabled section is not an
/// error, the same as for `env:`).
fn yaml(dir: &std::path::Path, enabled: bool) -> std::path::PathBuf {
    let store_dir = dir.join("store");
    let authority_dir = dir.join("authority");
    let body = format!(
        "server:\n  port: 0\n\
         auth:\n  enabled: {enabled}\n  bearer_token: keychain:gw.bearer\n  api_keys:\n    - key_sha256: keychain:gw.api\n      name: kc-client\n\
         security:\n  transparency_log:\n    enabled: true\n    path: '{}'\n\
         agent_auth:\n  enabled: {enabled}\n  agents:\n    - client_id: kc-agent\n      name: KC Agent\n      hs256_secret: keychain:gw.hs256\n\
         key_server:\n  enabled: false\n  admin_token: keychain:gw.admin\n\
         accounts:\n  schema_version: accounts.v1\n  enabled: true\n  deployment: single_process\n  instance_id: gateway-a\n  store_dir: '{}'\n  authority_dir: '{}'\n  current_key_id: current\n  keys:\n    current: keychain:gw.current\n",
        dir.join("audit.jsonl").display(),
        store_dir.display(),
        authority_dir.display(),
    );
    let path = dir.join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, body).expect("write config");
    path
}

#[test]
fn a4_every_slot_resolves_from_the_keychain() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = yaml(dir.path(), false);
    let fake = fake();
    let evaluated = with_test_keychain(fake.clone(), || Config::load_evaluated(Some(&path)))
        .expect("keychain: references load");
    let config = &evaluated.config;
    assert_eq!(config.auth.bearer_token.as_deref(), Some(BEARER));
    assert_eq!(
        config.auth.api_keys[0].key_sha256.as_deref(),
        Some(api_digest().as_str())
    );
    assert_eq!(
        config.agent_auth.agents[0].hs256_secret.as_deref(),
        Some(HS256)
    );
    assert_eq!(config.key_server.admin_token.as_deref(), Some(ADMIN));
    // Account keys stay references, as `env:` ones do; they resolve on use.
    let accounts = config.accounts.as_ref().expect("accounts block");
    assert_eq!(accounts.keys["current"], "keychain:gw.current");
}

#[test]
fn a4_a_missing_entry_fails_the_load_naming_field_and_entry() {
    for (entry, field) in [
        ("gw.bearer", "auth.bearer_token"),
        ("gw.api", "auth.api_keys['kc-client'].key_sha256"),
        ("gw.hs256", "agent_auth.agents['kc-agent'].hs256_secret"),
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = yaml(dir.path(), true);
        let fake = fake();
        fake.fail(entry, super::keychain::KeychainError::Missing);
        let error = with_test_keychain(fake, || Config::load_evaluated(Some(&path)))
            .err()
            .unwrap_or_else(|| panic!("a missing {entry} loaded"))
            .to_string();
        assert!(error.contains(field), "{field}: {error}");
        assert!(error.contains(entry), "{entry}: {error}");
    }
}

#[test]
fn a4_the_metrics_token_warns_and_is_absent_when_missing() {
    let fake = fake();
    let server = super::ServerConfig {
        metrics_token: Some("keychain:gw.metrics".to_owned()),
        ..super::ServerConfig::default()
    };
    let overlay = super::EnvOverlay::none().with_keychain(fake.clone());
    assert_eq!(server.resolve_metrics_token(&overlay), None);
    fake.insert("gw.metrics", b"scrape");
    assert_eq!(
        server.resolve_metrics_token(&overlay).as_deref(),
        Some("scrape")
    );
}

#[test]
fn a4_message_signing_secrets_resolve_from_the_keychain() {
    let fake = fake();
    let key = "k".repeat(40);
    let previous = "p".repeat(40);
    fake.insert("gw.sign", key.as_bytes());
    fake.insert("gw.sign-prev", previous.as_bytes());
    let mut signing = super::SecurityConfig::default().message_signing;
    signing.enabled = true;
    signing.shared_secret = "keychain:gw.sign".to_owned();
    signing.previous_secret = "keychain:gw.sign-prev".to_owned();
    let overlay = super::EnvOverlay::none().with_keychain(fake);
    let resolved = signing
        .resolve_with_env(&overlay)
        .expect("keychain keys resolve");
    assert_eq!(resolved.shared_secret, key);
    assert_eq!(resolved.previous_secret, previous);
}

/// A value an `env:` reference resolves to is the secret, even when it reads
/// like a `keychain:` reference: it is never followed a second time.
#[test]
fn an_env_value_that_reads_as_a_reference_is_the_secret() {
    let dir = tempfile::tempdir().expect("tempdir");
    let env = dir.path().join("secrets.env");
    crate::gateway::test_helpers::write_owner_only(
        &env,
        "BEARER=keychain:not-a-reference-0123456789\n",
    )
    .expect("write env");
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(
        &path,
        format!(
            "env_files:\n  - '{}'\nauth:\n  bearer_token: env:BEARER\n",
            env.display()
        ),
    )
    .expect("write config");
    let fake = Arc::new(FakeKeychain::default());
    let evaluated =
        with_test_keychain(fake.clone(), || Config::load_evaluated(Some(&path))).expect("loads");
    let token = evaluated
        .config
        .auth
        .resolve_bearer_token(&evaluated.overlay)
        .expect("resolves");
    assert_eq!(
        token.as_deref(),
        Some("keychain:not-a-reference-0123456789")
    );
    assert!(
        fake.asked().is_empty(),
        "followed as a reference: {:?}",
        fake.asked()
    );
}

#[test]
fn a4_the_record_key_resolves_from_the_keychain() {
    let fake = fake();
    let key = "a".repeat(64);
    fake.insert("gw.record", key.as_bytes());
    let overlay = super::EnvOverlay::none().with_keychain(fake);
    let dir = tempfile::tempdir().expect("tempdir");
    let resolved = super::record_key::resolve_record_key_text(
        Some("keychain:gw.record"),
        &overlay,
        &dir.path().join("unused"),
        "security.record_principal_key",
    )
    .expect("resolves");
    assert_eq!(resolved, key);
}

/// The accounts block (`accounts.keys`, adapter `hmac_secret_ref`,
/// `client_secret_ref`) resolves through `EnvOverlay::resolve_reference`.
#[test]
fn a4_account_references_resolve_from_the_keychain() {
    let fake = fake();
    let overlay = super::EnvOverlay::none().with_keychain(fake);
    assert_eq!(
        overlay
            .resolve_reference("accounts.keys[current]", "keychain:gw.current")
            .expect("resolves")
            .as_deref(),
        Some(CURRENT_B64)
    );
    let missing = overlay
        .resolve_reference("accounts.keys[gone]", "keychain:gw.gone")
        .expect_err("a missing entry is refused");
    assert!(
        missing.contains("accounts.keys[gone]") && missing.contains("gw.gone"),
        "{missing}"
    );
}

#[test]
fn a19_capability_keychain_templates_keep_their_own_reader() {
    // ADR-028 rule 11: capability `{keychain.X}` reads stay on the existing
    // CLI reader, so the gateway.yaml reader is never asked for them.
    let fake = fake();
    fake.insert("a19-capability-entry", b"from-the-gateway-reader");
    let resolved = with_test_keychain(fake.clone(), || {
        crate::secrets::SecretResolver::new().resolve("key={keychain.a19-capability-entry}")
    });
    assert_ne!(
        resolved.ok().as_deref(),
        Some("key=from-the-gateway-reader")
    );
    assert!(fake.asked().is_empty(), "asked {:?}", fake.asked());
}
