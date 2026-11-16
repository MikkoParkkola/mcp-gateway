// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A literal or `env:` bearer token under 20 characters warns once at
//! load (AUTHGUESS.2) and refuses the load under `security.posture: hardened`
//! (AUTHGUESS.4). `auto` and secret-store references are never measured.

use std::path::{Path, PathBuf};

use crate::config::{AuthConfig, Config, EnvOverlay};
use crate::gateway::test_helpers::write_owner_only;

/// 19 characters: one under the floor.
const SHORT: &str = "short-bearer-19-chr";
/// 20 characters: exactly the floor.
const FLOOR: &str = "floor-bearer-20-chrs";

fn auth(token: &str) -> AuthConfig {
    AuthConfig {
        enabled: true,
        bearer_token: Some(token.to_string()),
        ..AuthConfig::default()
    }
}

fn owner_only(dir: &Path, name: &str, contents: &str) -> PathBuf {
    let path = dir.join(name);
    write_owner_only(&path, contents).expect("fixture writes");
    path
}

/// T5: what is measured, and how. Characters, not bytes: ten two-byte
/// characters are 20 bytes and still short.
#[test]
fn short_bearer_by_kind_and_length() {
    let none = EnvOverlay::none();
    assert_eq!(SHORT.chars().count(), 19, "premise");
    assert_eq!(FLOOR.chars().count(), 20, "premise");
    let multibyte = "é".repeat(10);
    assert_eq!(multibyte.len(), 20, "premise: 20 bytes");

    assert!(auth(SHORT).short_bearer(&none).is_some(), "literal 19");
    assert!(auth(FLOOR).short_bearer(&none).is_none(), "literal 20");
    assert!(auth(&multibyte).short_bearer(&none).is_some(), "10 chars");

    let dir = tempfile::tempdir().expect("tempdir");
    let env = owner_only(
        dir.path(),
        "gateway.env",
        &format!("MIK9721_T5_SHORT={SHORT}\nMIK9721_T5_FLOOR={FLOOR}\n"),
    );
    let overlay = EnvOverlay::from_paths(&[env]);
    assert!(
        auth("env:MIK9721_T5_SHORT")
            .short_bearer(&overlay)
            .is_some()
    );
    assert!(
        auth("env:MIK9721_T5_FLOOR")
            .short_bearer(&overlay)
            .is_none()
    );
    // Unset: the reference errors refuse it; this check stays out of the way.
    assert!(
        auth("env:MIK9721_T5_UNSET")
            .short_bearer(&overlay)
            .is_none()
    );

    // Never measured, never read: `auto` would read as a 4-character literal.
    let stored = owner_only(dir.path(), "token", "tok");
    for spec in [
        "auto".to_string(),
        format!("file:{}", stored.display()),
        "keychain:mik9721.t5.absent".to_string(),
    ] {
        assert!(auth(&spec).short_bearer(&overlay).is_none(), "{spec}");
    }
    assert!(
        AuthConfig::default().short_bearer(&none).is_none(),
        "no token"
    );
    // Empty is refused by the empty-credential check, with its own message.
    assert!(auth("").short_bearer(&none).is_none(), "empty literal");
    // A digest, never the token itself.
    let digest = auth(SHORT).short_bearer(&none).expect("short");
    assert!(!digest.contains(SHORT), "{digest}");
}

/// The config file for `auth.bearer_token: <spec>` under `posture`, with
/// `env` as its env file. Auth on needs the audit log; hardened needs the
/// signing secret.
fn config_file(dir: &Path, posture: &str, spec: &str, env: &str) -> PathBuf {
    let env_file = owner_only(dir, "gateway.env", env);
    let signing = if posture == "hardened" {
        format!(
            "  message_signing:\n    shared_secret: {}\n",
            crate::security::posture::tests::SIGNING_SECRET
        )
    } else {
        String::new()
    };
    let yaml = format!(
        "env_files:\n  - '{}'\nauth:\n  enabled: true\n  bearer_token: '{spec}'\nsecurity:\n  posture: {posture}\n{signing}  transparency_log:\n    enabled: true\n    path: '{}'\n",
        env_file.display(),
        dir.join("audit.jsonl").display()
    );
    owner_only(dir, "gateway.yaml", &yaml)
}

/// [`config_file`], loaded for use.
fn load(dir: &Path, posture: &str, spec: &str, env: &str) -> crate::Result<Config> {
    Config::load(Some(&config_file(dir, posture, spec, env)))
}

/// T6: one warning per short token, literal or `env:`, never the token.
/// Each token here appears in no other test, so no other load can have used
/// up its warning.
#[test]
fn a_short_bearer_warns_once_at_load() {
    let dir = tempfile::tempdir().expect("tempdir");
    let env = "MIK9721_T6_TOKEN=t6-short-env-bearer\n";
    for (spec, token) in [
        ("t6-short-bearer-one", "t6-short-bearer-one"),
        ("env:MIK9721_T6_TOKEN", "t6-short-env-bearer"),
    ] {
        let (loaded, lines) =
            crate::test_log_capture::capture_warnings(|| load(dir.path(), "standard", spec, env));
        loaded.unwrap_or_else(|e| panic!("{spec}: standard posture still loads: {e}"));
        let warned: Vec<&str> = lines
            .lines()
            .filter(|l| l.contains("auth.bearer_token"))
            .collect();
        assert_eq!(warned.len(), 1, "{spec}: {lines}");
        assert!(
            warned[0].contains("20"),
            "{spec}: the floor is named: {lines}"
        );
        assert!(
            !lines.contains(token),
            "{spec}: the token was logged: {lines}"
        );

        let (again, lines) =
            crate::test_log_capture::capture_warnings(|| load(dir.path(), "standard", spec, env));
        again.expect("loads");
        assert!(
            !lines.contains("auth.bearer_token"),
            "{spec}: repeated: {lines}"
        );
    }
    // A new short token warns again: a new literal, and a new value behind the
    // same `env:` reference (the warning follows the token, not the config text).
    for (spec, env) in [
        ("t6-short-bearer-two", env),
        (
            "env:MIK9721_T6_TOKEN",
            "MIK9721_T6_TOKEN=t6-short-env-other\n",
        ),
    ] {
        let (other, lines) =
            crate::test_log_capture::capture_warnings(|| load(dir.path(), "standard", spec, env));
        other.expect("loads");
        assert_eq!(
            lines.matches("auth.bearer_token").count(),
            1,
            "{spec}: {lines}"
        );
    }
}

/// T7: hardened refuses a short literal or `env:` token, naming the field,
/// the floor and the fix; 20 characters loads; standard only warns.
#[cfg(feature = "firewall")]
#[test]
fn hardened_refuses_a_short_bearer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let env = format!("MIK9721_T7_SHORT={SHORT}\nMIK9721_T7_FLOOR={FLOOR}\n");
    for (short, floor) in [
        (SHORT, FLOOR),
        ("env:MIK9721_T7_SHORT", "env:MIK9721_T7_FLOOR"),
    ] {
        let error = load(dir.path(), "hardened", short, &env)
            .expect_err("hardened refuses 19 characters")
            .to_string();
        for needed in ["auth.bearer_token", "20", "auto"] {
            assert!(error.contains(needed), "{short}: {needed}: {error}");
        }
        assert!(!error.contains(SHORT), "the token was printed: {error}");
        load(dir.path(), "hardened", floor, &env).expect("hardened loads 20 characters");
        load(dir.path(), "standard", short, &env).expect("standard only warns");
    }
    // The container form: an env-file override replaces the file's 20
    // characters with 19, and the override is what is measured.
    let overridden = format!("MCP_GATEWAY_AUTH__BEARER_TOKEN={SHORT}\n");
    let error = load(dir.path(), "hardened", FLOOR, &overridden)
        .expect_err("the override is measured")
        .to_string();
    assert!(error.contains("auth.bearer_token"), "{error}");
}

/// T7c: a config read to be rewritten still loads, so tooling can fix the
/// token a hardened start refuses.
#[test]
fn a_literal_load_reads_a_hardened_short_bearer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = config_file(dir.path(), "hardened", SHORT, "");
    let config = Config::load_literal(Some(&path)).expect("a rewrite can read it");
    assert_eq!(config.auth.bearer_token.as_deref(), Some(SHORT));
}

/// T7b: a stored token is not measured, however short. Fails if the check
/// runs after the load replaces references with their values.
#[cfg(feature = "firewall")]
#[test]
fn hardened_loads_a_short_stored_bearer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let stored = owner_only(dir.path(), "token", "tok12");
    let config = load(
        dir.path(),
        "hardened",
        &format!("file:{}", stored.display()),
        "",
    )
    .expect("a file: token is not measured");
    assert_eq!(
        config.auth.bearer_token.as_deref(),
        Some("tok12"),
        "premise: it resolved"
    );
}
