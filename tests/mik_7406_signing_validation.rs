// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7406 / MIK-7377.SIGNING.2: enabled message signing must reject startup
//! when its secret material cannot authenticate anything.
//!
//! `MessageSigner::sign_response` MACs whatever secret it is handed, so an
//! empty or short `shared_secret` produces a signature any caller can forge —
//! the config reads as having response signing on while it protects nothing.
//! `message_signing::validate_secret` already encodes the 32-byte floor; until
//! configuration validation calls it, the floor is advice.

use mcp_gateway::config::{Config, EnvOverlay};

/// The secret is checked on the RESOLVED value, so build the config the way a
/// deployment does rather than reaching past validation.
fn signing_config(enabled: bool, shared_secret: &str, previous_secret: &str) -> Config {
    let mut config = Config::default();
    config.security.message_signing.enabled = enabled;
    config.security.message_signing.shared_secret = shared_secret.to_string();
    config.security.message_signing.previous_secret = previous_secret.to_string();
    config
}

#[test]
fn enabled_signing_with_empty_secret_rejects_startup() {
    let config = signing_config(true, "", "");
    let err = config
        .validate()
        .expect_err("signing enabled with an empty shared secret must not start");
    let message = err.to_string();
    assert!(
        message.contains("message_signing"),
        "error should name the offending setting, got: {message}"
    );
}

#[test]
fn enabled_signing_with_short_secret_rejects_startup() {
    let config = signing_config(true, "short-secret", "");
    config
        .validate()
        .expect_err("signing enabled with a sub-32-byte shared secret must not start");
}

#[test]
fn enabled_signing_rejects_short_previous_secret() {
    // Rotation keeps the previous key live for verification, so a weak previous
    // secret is exactly as forgeable as a weak current one.
    let config = signing_config(true, &"a".repeat(32), "short");
    config
        .validate()
        .expect_err("a sub-32-byte previous_secret must not start");
}

#[test]
fn enabled_signing_checks_the_resolved_secret_not_the_reference() {
    // `env:MCP_GATEWAY_SIGNING_SECRET` is 34 characters; the value behind it is
    // 3. A length check on the literal would pass this and sign with "abc".
    let dir = tempfile::tempdir().expect("tempdir");
    let env_file = dir.path().join(".env");
    std::fs::write(&env_file, "MCP_GATEWAY_SIGNING_SECRET=abc\n").expect("write env file");
    let overlay = EnvOverlay::from_paths(&[env_file]);

    let config = signing_config(true, "env:MCP_GATEWAY_SIGNING_SECRET", "");
    config
        .validate_with_env(&overlay)
        .expect_err("the resolved secret is 3 bytes and must not start");
}

#[test]
fn enabled_signing_with_a_sound_secret_starts() {
    let config = signing_config(true, &"k".repeat(32), &"p".repeat(32));
    config
        .validate()
        .expect("a 32-byte secret meets the documented floor");
}

#[test]
fn disabled_signing_ignores_unresolved_placeholders() {
    // SIGNING.6: an unused signing placeholder must not prevent startup.
    let config = signing_config(false, "env:NOT_SET_ANYWHERE", "");
    config
        .validate()
        .expect("disabled signing must stay compatible");
}

#[test]
fn enabled_signing_rejects_blank_key_id() {
    let mut config = signing_config(true, &"k".repeat(32), "");
    config.security.message_signing.key_id = "  ".to_string();
    config
        .validate()
        .expect_err("a verifier cannot resolve a blank key_id");
}

#[test]
fn enabled_signing_rejects_zero_replay_window() {
    let mut config = signing_config(true, &"k".repeat(32), "");
    config.security.message_signing.replay_window = 0;
    config
        .validate()
        .expect_err("a zero replay window leaves replay protection off");
}

/// A signing secret that only an env file defines must survive the SECOND
/// validation.
///
/// `Config::load_evaluated` validates against the overlay the load produced,
/// which includes the env files. `Gateway::new` then re-validates the loaded
/// config through `Config::validate`, whose overlay is `EnvOverlay::none()` —
/// the process environment alone. A secret still spelled `env:NAME` at that
/// point resolves to nothing and refuses to boot a config that is correct.
/// Substituting the signing secrets during evaluation, with the rest, is what
/// keeps the two validations agreeing.
#[test]
fn signing_secret_from_an_env_file_survives_the_boot_revalidation() {
    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join("signing.env");
    std::fs::write(
        &env_path,
        "MCP_GW_TEST_7406_ENVFILE_SECRET=0123456789abcdef0123456789abcdef\n",
    )
    .unwrap();
    let cfg_path = dir.path().join("gateway.yaml");
    std::fs::write(
        &cfg_path,
        format!(
            "env_files:\n  - \"{}\"\nsecurity:\n  message_signing:\n    enabled: true\n    \
             shared_secret: \"env:MCP_GW_TEST_7406_ENVFILE_SECRET\"\n",
            env_path.display()
        ),
    )
    .unwrap();

    let evaluated = Config::load_evaluated(Some(&cfg_path))
        .expect("a config whose signing secret an env file defines must load");

    evaluated
        .config
        .validate()
        .expect("the boot re-validation runs without the env files and must still accept it");
}
