// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7973: two configured credentials whose digests share the first 48 bits
//! resolve to one principal, so each would own the other's sessions, grants
//! and tasks. The configuration is refused at load and at reload; the
//! principal encoding itself is unchanged.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::{LiveConfig, load_config_patch};
use crate::Error;
use crate::config::{Config, LiveEnv};
use crate::gateway::auth::{ResolvedAuthConfig, principal_of};
use crate::gateway::test_helpers::write_owner_only;

/// Twelve hex characters: one principal. Distinctive, so an error that
/// printed it could not match by accident.
const PREFIX: &str = "c0ffee7973ab";
const BEARER: &str = "mik7973-bearer-token";
const VAR: &str = "MIK7973_DIGEST_VAR";

/// A digest whose principal is `prefix`, with a tail of `fill`.
fn colliding(prefix: &str, fill: char) -> String {
    format!("sha256:{prefix}{}", fill.to_string().repeat(52))
}

fn digest_of(key: &str) -> String {
    format!("sha256:{}", crate::hashing::sha256_hex(key.as_bytes()))
}

fn quoted(path: &Path) -> String {
    serde_json::to_string(&path.to_string_lossy().as_ref()).expect("path must JSON-quote")
}

/// The config file body: `auth_body` sits under `auth:`; auth stays off so
/// no enabled-auth rule decides the outcome.
fn yaml(auth_body: &str, env_file: Option<&Path>) -> String {
    let mut yaml = String::new();
    if let Some(env_file) = env_file {
        writeln!(yaml, "env_files:\n  - {}", quoted(env_file)).expect("String write");
    }
    yaml.push_str("auth:\n  enabled: false\n");
    yaml.push_str(auth_body);
    yaml
}

fn two_keys(alpha: &str, bravo: &str) -> String {
    format!(
        "  api_keys:\n    - name: alpha\n      key_sha256: \"{alpha}\"\n\
         \x20   - name: bravo\n      key_sha256: \"{bravo}\"\n"
    )
}

fn load(body: &str, env: Option<&str>) -> (tempfile::TempDir, PathBuf, crate::Result<Config>) {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let env_path = env.map(|env| {
        let path = dir.path().join("keys.env");
        write_owner_only(&path, env).expect("env file");
        path
    });
    let path = dir.path().join("config.yaml");
    write_owner_only(&path, yaml(body, env_path.as_deref())).expect("config file");
    let loaded = Config::load(Some(&path));
    (dir, path, loaded)
}

/// The bearer token's principal: what a key must start with to collide with it.
fn bearer_prefix() -> String {
    crate::hashing::sha256_hex(BEARER.as_bytes())[..12].to_owned()
}

/// The refusal names both credentials and neither secret nor principal
/// (`shared` is the principal the two resolve to).
fn assert_collision_refused(
    result: crate::Result<Config>,
    first: &str,
    second: &str,
    shared: &str,
) {
    let message = match result {
        Err(Error::ConfigValidation(message)) => message,
        Err(other) => panic!("expected ConfigValidation, got {other}"),
        Ok(_) => panic!("{first} and {second} share a principal, but the config loaded"),
    };
    assert_collision_message(&message, first, second, shared);
}

fn assert_collision_message(message: &str, first: &str, second: &str, shared: &str) {
    assert!(message.contains("principal"), "{message}");
    assert!(message.contains(first), "{message}");
    assert!(message.contains(second), "{message}");
    assert!(!message.contains(shared), "the principal leaked: {message}");
    assert!(!message.contains(BEARER), "the bearer leaked: {message}");
}

#[test]
fn two_keys_sharing_a_principal_fail_to_load() {
    // MIK-7973.COLLIDE.1 / .3: same first 48 bits, different tails.
    let body = two_keys(&colliding(PREFIX, '0'), &colliding(PREFIX, '1'));
    let (_dir, _path, loaded) = load(&body, None);
    assert_collision_refused(loaded, "alpha", "bravo", PREFIX);
}

#[test]
fn two_ordinary_keys_still_load() {
    let body = two_keys(&digest_of("k-alpha"), &digest_of("k-bravo"));
    let (_dir, _path, loaded) = load(&body, None);
    loaded.expect("two distinct keys must load");
}

#[test]
fn a_key_sharing_the_bearer_principal_fails_to_load() {
    let bearer_prefix = bearer_prefix();
    let body = format!(
        "  bearer_token: \"{BEARER}\"\n  api_keys:\n    - name: alpha\n      key_sha256: \"{}\"\n",
        colliding(&bearer_prefix, 'f')
    );
    let (_dir, _path, loaded) = load(&body, None);
    assert_collision_refused(loaded, "bearer_token", "alpha", &bearer_prefix);
}

#[test]
fn a_key_referenced_through_env_is_checked_too() {
    let body = format!(
        "  api_keys:\n    - name: alpha\n      key_sha256: \"{}\"\n\
         \x20   - name: bravo\n      key_sha256: \"env:{VAR}\"\n",
        colliding(PREFIX, '0')
    );
    let env = format!("{VAR}={}\n", colliding(PREFIX, '1'));
    let (_dir, _path, loaded) = load(&body, Some(&env));
    assert_collision_refused(loaded, "alpha", "bravo", PREFIX);
}

#[test]
fn a_reload_that_introduces_a_shared_principal_is_refused() {
    // MIK-7973.COLLIDE.2: only bravo's digest changes, so nothing but the
    // collision can be what refuses the reload.
    let body = two_keys(&colliding(PREFIX, '0'), &digest_of("k-bravo"));
    let (_dir, path, loaded) = load(&body, None);
    loaded.expect("the starting config loads");
    let startup = Config::load_evaluated(Some(&path)).expect("startup loads");
    let live = Arc::new(LiveConfig::new(startup.config.clone()));
    let env = LiveEnv::new(startup.overlay, startup.env_paths);

    let colliding_body = two_keys(&colliding(PREFIX, '0'), &colliding(PREFIX, '1'));
    write_owner_only(&path, yaml(&colliding_body, None)).expect("rewrite config");
    let refused = load_config_patch(&path, &live, &env)
        .err()
        .expect("a reload that merges two keys' principals must be refused");
    assert_collision_message(&refused, "alpha", "bravo", PREFIX);
    let running = live.get();
    assert_eq!(
        running.auth.api_keys[1].key_sha256.as_deref(),
        Some(digest_of("k-bravo").as_str()),
        "a refused reload keeps the running config"
    );
}

#[test]
fn the_resolved_credentials_are_checked_at_startup() {
    // The startup path is where an `auto` bearer first exists; a literal one
    // proves the same check runs there.
    let bearer_prefix = bearer_prefix();
    let config: crate::config::AuthConfig = serde_yaml::from_str(&format!(
        "enabled: true\nbearer_token: \"{BEARER}\"\napi_keys:\n  - name: alpha\n    key_sha256: \"{}\"\n    backends: [\"*\"]\n",
        colliding(&bearer_prefix, 'f')
    ))
    .expect("auth section parses");
    let Err(error) =
        ResolvedAuthConfig::try_from_config(&config, &crate::config::EnvOverlay::none())
    else {
        panic!("a key sharing the bearer's principal must not resolve");
    };
    assert_collision_message(&error.to_string(), "bearer_token", "alpha", &bearer_prefix);
}

#[test]
fn the_principal_encoding_is_unchanged() {
    // MIK-7973.COLLIDE.4: known answer, computed outside the gateway
    // (first 12 hex characters of SHA-256 of the token).
    const TOKEN: &str = "mik7973-known-answer";
    assert_eq!(principal_of(TOKEN), "07635921daa7");
    let config: crate::config::AuthConfig = serde_yaml::from_str(&format!(
        "enabled: true\napi_keys:\n  - name: alpha\n    key_sha256: \"{}\"\n    backends: [\"*\"]\n",
        digest_of(TOKEN)
    ))
    .expect("auth section parses");
    let resolved = ResolvedAuthConfig::try_from_config(&config, &crate::config::EnvOverlay::none())
        .expect("one key resolves");
    let client = resolved.validate_token(TOKEN).expect("the key validates");
    assert_eq!(client.principal, "07635921daa7");
}
