// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Backend `env` and `headers` as secret slots (ADR-028, MIK-8908 B3): a
//! whole-value `env:`, `file:` or `keychain:` resolves once, for an enabled
//! backend, and its bytes are used verbatim; anything else keeps `${VAR}`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::Config;
use super::keychain::{FakeKeychain, with_test_keychain};

const VALUE: &str = "kc-backend-sentinel-7f3a";

fn write(dir: &Path, body: &str) -> PathBuf {
    let path = dir.join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, body).expect("write config");
    path
}

fn stdio(enabled: bool, env: &str) -> String {
    format!(
        "server:\n  port: 0\nbackends:\n  tool:\n    command: \"/bin/true\"\n    enabled: {enabled}\n    env:\n{env}"
    )
}

fn fake(entries: &[(&str, &[u8])]) -> Arc<FakeKeychain> {
    let fake = Arc::new(FakeKeychain::default());
    for (name, bytes) in entries {
        fake.insert(name, bytes);
    }
    fake
}

fn load(path: &Path, fake: Arc<FakeKeychain>) -> crate::Result<Config> {
    with_test_keychain(fake, || Config::load_evaluated(Some(path))).map(|e| e.config)
}

#[test]
fn b3a_an_enabled_stdio_backend_resolves_keychain_file_and_env_values() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secret_file = dir.path().join("token");
    crate::gateway::test_helpers::write_owner_only(&secret_file, VALUE).expect("write secret");
    let env_file = dir.path().join("vars.env");
    crate::gateway::test_helpers::write_owner_only(&env_file, format!("B3_TOKEN={VALUE}\n"))
        .expect("write env file");
    let body = format!(
        "env_files:\n  - '{}'\n{}",
        env_file.display(),
        stdio(
            true,
            &format!(
                "      FROM_KEYCHAIN: keychain:b3.k\n      FROM_FILE: 'file:{}'\n      FROM_ENV: env:B3_TOKEN\n",
                secret_file.display()
            ),
        )
    );
    let path = write(dir.path(), &body);
    let config = load(&path, fake(&[("b3.k", VALUE.as_bytes())])).expect("loads");
    let env = &config.backends["tool"].env;
    assert_eq!(env["FROM_KEYCHAIN"], VALUE);
    assert_eq!(env["FROM_FILE"], VALUE);
    assert_eq!(env["FROM_ENV"], VALUE);
}

#[test]
fn b3b_an_http_backend_header_resolves_from_the_keychain() {
    let dir = tempfile::tempdir().expect("tempdir");
    let body = "server:\n  port: 0\nbackends:\n  web:\n    http_url: \"https://example.invalid/mcp\"\n    headers:\n      Authorization: keychain:b3.h\n";
    let path = write(dir.path(), body);
    let config = load(&path, fake(&[("b3.h", b"Bearer abc")])).expect("loads");
    assert_eq!(
        config.backends["web"].headers["Authorization"],
        "Bearer abc"
    );
}

#[test]
fn b3c_a_disabled_backend_keeps_its_reference_and_reads_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write(
        dir.path(),
        &stdio(false, "      API_KEY: keychain:b3.off\n"),
    );
    let fake = fake(&[]);
    let config = load(&path, fake.clone()).expect("a disabled backend's reference is not read");
    assert_eq!(config.backends["tool"].env["API_KEY"], "keychain:b3.off");
    assert!(fake.asked().is_empty(), "asked {:?}", fake.asked());
}

#[test]
fn b3d_unresolved_references_fail_the_load_naming_every_field_never_the_value() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write(
        dir.path(),
        &stdio(
            true,
            "      A: keychain:b3.gone\n      B: keychain:b3.also-gone\n",
        ),
    );
    let error = load(&path, fake(&[])).err().expect("refused").to_string();
    assert!(error.contains("backends.tool.env.A"), "{error}");
    assert!(error.contains("backends.tool.env.B"), "{error}");
    assert!(error.contains("b3.gone"), "{error}");
    assert!(!error.contains(VALUE), "{error}");
}

#[test]
fn b3e_mid_string_references_stay_literal_and_templates_still_expand() {
    let dir = tempfile::tempdir().expect("tempdir");
    let env_file = dir.path().join("vars.env");
    crate::gateway::test_helpers::write_owner_only(&env_file, "B3_HOME=/srv\n").expect("env");
    let body = format!(
        "env_files:\n  - '{}'\n{}",
        env_file.display(),
        stdio(
            true,
            "      MID: 'Bearer keychain:b3.x'\n      TEMPLATE: '${B3_HOME}/x'\n",
        )
    );
    let path = write(dir.path(), &body);
    let fake = fake(&[]);
    let config = load(&path, fake.clone()).expect("loads");
    let env = &config.backends["tool"].env;
    assert_eq!(env["MID"], "Bearer keychain:b3.x");
    assert_eq!(env["TEMPLATE"], "/srv/x");
    assert!(fake.asked().is_empty(), "asked {:?}", fake.asked());
}

#[test]
fn b3e2_a_resolved_value_is_used_verbatim_never_read_as_a_reference_again() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secret_file = dir.path().join("token");
    crate::gateway::test_helpers::write_owner_only(&secret_file, "keychain:abc").expect("write");
    let env_file = dir.path().join("vars.env");
    crate::gateway::test_helpers::write_owner_only(&env_file, "B3_REF=keychain:abc\n")
        .expect("env");
    let body = format!(
        "env_files:\n  - '{}'\n{}",
        env_file.display(),
        stdio(
            true,
            &format!(
                "      FROM_FILE: 'file:{}'\n      FROM_ENV: env:B3_REF\n      FROM_TEMPLATE: '${{B3_REF}}'\n",
                secret_file.display()
            ),
        )
    );
    let path = write(dir.path(), &body);
    let fake = fake(&[("abc", b"must-not-be-read")]);
    let config = load(&path, fake.clone()).expect("loads");
    let env = &config.backends["tool"].env;
    assert_eq!(env["FROM_FILE"], "keychain:abc");
    assert_eq!(env["FROM_ENV"], "keychain:abc");
    assert_eq!(env["FROM_TEMPLATE"], "keychain:abc");
    assert!(
        fake.asked().is_empty(),
        "a resolved value was followed: {:?}",
        fake.asked()
    );
}

#[test]
fn b3g_the_literal_load_keeps_the_reference_text() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write(dir.path(), &stdio(true, "      API_KEY: keychain:b3.k\n"));
    let literal = with_test_keychain(fake(&[("b3.k", VALUE.as_bytes())]), || {
        Config::load_literal(Some(&path))
    })
    .expect("literal load");
    assert_eq!(literal.backends["tool"].env["API_KEY"], "keychain:b3.k");
}
