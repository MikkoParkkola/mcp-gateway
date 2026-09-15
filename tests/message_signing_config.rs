// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7406 / SIGNING.2: effective signing configuration and literal persistence.

use std::fmt::Write as _;
use std::path::PathBuf;

use mcp_gateway::config::{Config, EnvOverlay};
use serde_json::json;
use tempfile::TempDir;

const CURRENT: &str = "current-signing-key-sentinel-0123456789abcdef";
const PREVIOUS: &str = "previous-signing-key-sentinel-0123456789abcdef";

struct ConfigFixture {
    directory: TempDir,
    path: PathBuf,
    current_var: String,
    previous_var: String,
}

impl ConfigFixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("config fixture directory");
        let suffix: String = directory
            .path()
            .file_name()
            .expect("directory name")
            .to_string_lossy()
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .map(|character| character.to_ascii_uppercase())
            .collect();
        let current_var = format!("MIK7406_SIGNING_CURRENT_{suffix}");
        let previous_var = format!("MIK7406_SIGNING_PREVIOUS_{suffix}");
        assert!(std::env::var_os(&current_var).is_none());
        assert!(std::env::var_os(&previous_var).is_none());
        let path = directory.path().join("gateway.yaml");
        Self {
            directory,
            path,
            current_var,
            previous_var,
        }
    }

    fn env_path(&self) -> PathBuf {
        self.directory.path().join("signing.env")
    }

    fn set_env(&self, current: Option<&str>, previous: Option<&str>) {
        let mut contents = String::new();
        for (name, value) in [(&self.current_var, current), (&self.previous_var, previous)] {
            if let Some(value) = value {
                let _ = writeln!(contents, "{name}={value}");
            }
        }
        std::fs::write(self.env_path(), contents).expect("write signing env fixture");
    }

    fn write(&self, enabled: bool, current: &str, previous: &str) {
        let value = json!({
            "env_files": [self.env_path()],
            "security": {"message_signing": {
                "enabled": enabled, "shared_secret": current,
                "previous_secret": previous, "key_id": "fixture-current",
                "replay_window": 300
            }}
        });
        std::fs::write(
            &self.path,
            serde_yaml::to_string(&value).expect("fixture YAML"),
        )
        .expect("write config fixture");
    }

    fn overlay(&self) -> EnvOverlay {
        EnvOverlay::from_paths_checked(&[self.env_path()]).expect("valid env fixture")
    }

    fn assert_ambient_unchanged(&self) {
        assert!(std::env::var_os(&self.current_var).is_none());
        assert!(std::env::var_os(&self.previous_var).is_none());
    }
}

fn signing_config() -> Config {
    let mut config = Config::default();
    config.security.message_signing.enabled = true;
    CURRENT.clone_into(&mut config.security.message_signing.shared_secret);
    PREVIOUS.clone_into(&mut config.security.message_signing.previous_secret);
    config
}

fn assert_safe_error(result: mcp_gateway::Result<()>, field: &str, forbidden: &[&str]) {
    let error = result.expect_err("invalid enabled signing settings must be refused");
    let display = error.to_string();
    let debug = format!("{error:?}");
    assert!(
        display.contains(field),
        "error must identify affected signing field {field}: {display}"
    );
    assert!(
        debug.contains(field),
        "Debug must identify affected signing field {field}"
    );
    for token in forbidden {
        assert!(
            !display.contains(token),
            "configuration error leaked a signing token"
        );
        assert!(
            !debug.contains(token),
            "configuration error Debug leaked a signing token"
        );
    }
}

#[test]
fn signing_config_evaluates_current_and_previous_reference_spellings() {
    let fixture = ConfigFixture::new();
    fixture.set_env(Some(CURRENT), Some(PREVIOUS));
    let mut unresolved = Vec::new();
    for (case, current, previous) in [
        ("literal", CURRENT.to_owned(), PREVIOUS.to_owned()),
        (
            "env prefix",
            format!("env:{}", fixture.current_var),
            format!("env:{}", fixture.previous_var),
        ),
        (
            "expansion",
            format!("${{{}}}", fixture.current_var),
            format!("${{{}}}", fixture.previous_var),
        ),
    ] {
        fixture.write(true, &current, &previous);
        let evaluated =
            Config::load_evaluated(Some(&fixture.path)).expect("valid signing references");
        fixture.assert_ambient_unchanged();
        let settings = &evaluated.config.security.message_signing;
        if settings.shared_secret != CURRENT || settings.previous_secret != PREVIOUS {
            unresolved.push(case);
        }
        let debug = format!("{settings:?}");
        for sensitive in [current.as_str(), previous.as_str(), CURRENT, PREVIOUS] {
            assert!(
                !debug.contains(sensitive),
                "signing Debug leaked a key or reference"
            );
        }
    }
    assert!(
        unresolved.is_empty(),
        "SIGNING.2 runtime keys remained unresolved: {unresolved:?}"
    );
}

#[test]
fn signing_config_missing_variable_defaults_resolve_for_both_keys() {
    let fixture = ConfigFixture::new();
    fixture.set_env(None, None);
    fixture.write(
        true,
        &format!("${{{}:-{CURRENT}}}", fixture.current_var),
        &format!("${{{}:-{PREVIOUS}}}", fixture.previous_var),
    );
    let evaluated = Config::load_evaluated(Some(&fixture.path)).expect("valid fallback keys");
    fixture.assert_ambient_unchanged();
    assert_eq!(
        evaluated.config.security.message_signing.shared_secret,
        CURRENT
    );
    assert_eq!(
        evaluated.config.security.message_signing.previous_secret,
        PREVIOUS
    );
}

#[test]
fn signing_config_literal_round_trip_preserves_references_without_keys() {
    let fixture = ConfigFixture::new();
    fixture.set_env(Some(CURRENT), Some(PREVIOUS));
    for (current, previous) in [
        (
            format!("env:{}", fixture.current_var),
            format!("${{{}}}", fixture.previous_var),
        ),
        (
            format!("${{{}}}", fixture.current_var),
            format!("env:{}", fixture.previous_var),
        ),
    ] {
        fixture.write(true, &current, &previous);
        let literal = Config::load_literal(Some(&fixture.path)).expect("literal valid config");
        assert_eq!(literal.security.message_signing.shared_secret, current);
        assert_eq!(literal.security.message_signing.previous_secret, previous);
        mcp_gateway::config_persistence::write_config(&fixture.path, &literal)
            .expect("production literal config write");
        let serialized = std::fs::read_to_string(&fixture.path).expect("persisted config bytes");
        assert!(!serialized.contains(CURRENT));
        assert!(!serialized.contains(PREVIOUS));
        let reloaded = Config::load_literal(Some(&fixture.path)).expect("literal reload");
        assert_eq!(reloaded.security.message_signing.shared_secret, current);
        assert_eq!(reloaded.security.message_signing.previous_secret, previous);
        fixture.assert_ambient_unchanged();
    }
}

#[test]
fn signing_config_missing_current_reference_is_refused_without_leak() {
    let fixture = ConfigFixture::new();
    fixture.set_env(None, Some(PREVIOUS));
    let reference = format!("env:{}", fixture.current_var);
    let mut config = signing_config();
    config
        .security
        .message_signing
        .shared_secret
        .clone_from(&reference);
    assert_safe_error(
        config.validate_with_env(&fixture.overlay()),
        "shared_secret",
        &[&reference, &fixture.current_var, PREVIOUS],
    );
}

#[test]
fn signing_config_missing_previous_reference_is_refused_without_leak() {
    let fixture = ConfigFixture::new();
    fixture.set_env(Some(CURRENT), None);
    let reference = format!("${{{}}}", fixture.previous_var);
    let mut config = signing_config();
    config
        .security
        .message_signing
        .previous_secret
        .clone_from(&reference);
    assert_safe_error(
        config.validate_with_env(&fixture.overlay()),
        "previous_secret",
        &[&reference, &fixture.previous_var, CURRENT],
    );
}

#[test]
fn signing_config_empty_resolved_previous_is_not_absent_rotation() {
    let fixture = ConfigFixture::new();
    fixture.set_env(Some(CURRENT), Some(""));
    let reference = format!("env:{}", fixture.previous_var);
    let mut config = signing_config();
    config.security.message_signing.previous_secret.clear();
    assert!(
        config.validate_with_env(&fixture.overlay()).is_ok(),
        "literal empty previous is valid"
    );
    config
        .security
        .message_signing
        .previous_secret
        .clone_from(&reference);
    assert_safe_error(
        config.validate_with_env(&fixture.overlay()),
        "previous_secret",
        &[&reference, &fixture.previous_var, CURRENT],
    );
}

#[test]
fn signing_config_validates_effective_key_byte_lengths() {
    let fixture = ConfigFixture::new();
    let valid = "x".repeat(32);
    let short = "x".repeat(31);
    assert_eq!(valid.len(), 32);
    assert_eq!(short.len(), 31);
    let reference = format!("${{{}}}", fixture.current_var);
    let mut config = signing_config();
    config
        .security
        .message_signing
        .shared_secret
        .clone_from(&reference);
    fixture.set_env(Some(&valid), Some(PREVIOUS));
    assert!(
        config.validate_with_env(&fixture.overlay()).is_ok(),
        "32-byte effective key control"
    );
    fixture.set_env(Some(&short), Some(PREVIOUS));
    assert_safe_error(
        config.validate_with_env(&fixture.overlay()),
        "shared_secret",
        &[&reference, &fixture.current_var, &short, PREVIOUS],
    );
}

#[test]
fn signing_config_empty_resolved_current_is_refused() {
    let fixture = ConfigFixture::new();
    fixture.set_env(Some(""), Some(PREVIOUS));
    let reference = format!("${{{}}}", fixture.current_var);
    let mut config = signing_config();
    config
        .security
        .message_signing
        .shared_secret
        .clone_from(&reference);
    assert_safe_error(
        config.validate_with_env(&fixture.overlay()),
        "shared_secret",
        &[&reference, &fixture.current_var, PREVIOUS],
    );
}

#[test]
fn signing_config_previous_reference_uses_effective_byte_length() {
    let fixture = ConfigFixture::new();
    let valid = "x".repeat(32);
    let short = "x".repeat(31);
    assert_eq!(valid.len(), 32);
    assert_eq!(short.len(), 31);
    let reference = format!("env:{}", fixture.previous_var);
    let mut config = signing_config();
    config
        .security
        .message_signing
        .previous_secret
        .clone_from(&reference);
    fixture.set_env(Some(CURRENT), Some(&valid));
    assert!(
        config.validate_with_env(&fixture.overlay()).is_ok(),
        "32-byte previous control"
    );
    fixture.set_env(Some(CURRENT), Some(&short));
    assert_safe_error(
        config.validate_with_env(&fixture.overlay()),
        "previous_secret",
        &[&reference, &fixture.previous_var, &short, CURRENT],
    );
}

#[test]
fn signing_config_key_minimum_counts_utf8_bytes() {
    let mut config = signing_config();
    config.security.message_signing.shared_secret = "🦀".repeat(8);
    assert_eq!(config.security.message_signing.shared_secret.len(), 32);
    assert!(
        config.validate().is_ok(),
        "eight four-byte code points satisfy the byte minimum"
    );
    config.security.message_signing.shared_secret = "🦀".repeat(7);
    assert_safe_error(
        config.validate(),
        "shared_secret",
        &[&config.security.message_signing.shared_secret, PREVIOUS],
    );
}

#[test]
fn signing_config_evaluated_overlay_wins_ambient() {
    const CHILD_PATH: &str = "MIK7406_SIGNING_OVERLAY_TEST_PATH";
    const CHILD_CURRENT_VAR: &str = "MIK7406_SIGNING_OVERLAY_CURRENT_NAME";
    const CHILD_PREVIOUS_VAR: &str = "MIK7406_SIGNING_OVERLAY_PREVIOUS_NAME";
    const AMBIENT_CURRENT: &str = "ambient-current-must-not-select-signing-key";
    const AMBIENT_PREVIOUS: &str = "ambient-previous-must-not-select-signing-key";
    const CHILD_OK: &str = "MIK7406_SIGNING_OVERLAY_ASSERTIONS_COMPLETED";
    if let Some(path) = std::env::var_os(CHILD_PATH) {
        let current_var = std::env::var(CHILD_CURRENT_VAR).expect("child current name");
        let previous_var = std::env::var(CHILD_PREVIOUS_VAR).expect("child previous name");
        assert_eq!(std::env::var(&current_var).as_deref(), Ok(AMBIENT_CURRENT));
        assert_eq!(
            std::env::var(&previous_var).as_deref(),
            Ok(AMBIENT_PREVIOUS)
        );
        let evaluated = Config::load_evaluated(Some(std::path::Path::new(&path)))
            .expect("child evaluated overlay config");
        assert_eq!(std::env::var(&current_var).as_deref(), Ok(AMBIENT_CURRENT));
        assert_eq!(
            std::env::var(&previous_var).as_deref(),
            Ok(AMBIENT_PREVIOUS)
        );
        assert_eq!(
            evaluated.config.security.message_signing.shared_secret,
            CURRENT
        );
        assert_eq!(
            evaluated.config.security.message_signing.previous_secret,
            PREVIOUS
        );
        println!("{CHILD_OK}");
        return;
    }

    let fixture = ConfigFixture::new();
    fixture.set_env(Some(CURRENT), Some(PREVIOUS));
    fixture.write(
        true,
        &format!("env:{}", fixture.current_var),
        &format!("${{{}}}", fixture.previous_var),
    );
    let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .arg("--exact")
        .arg("signing_config_evaluated_overlay_wins_ambient")
        .arg("--nocapture")
        .env(CHILD_PATH, &fixture.path)
        .env(CHILD_CURRENT_VAR, &fixture.current_var)
        .env(CHILD_PREVIOUS_VAR, &fixture.previous_var)
        .env(&fixture.current_var, AMBIENT_CURRENT)
        .env(&fixture.previous_var, AMBIENT_PREVIOUS)
        .output()
        .expect("run isolated ambient/overlay comparison");
    assert!(
        output.status.success(),
        "SIGNING.2 overlay authority child failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains(CHILD_OK),
        "child must execute the authority assertions, not match zero tests"
    );
    fixture.assert_ambient_unchanged();
}

#[test]
fn signing_config_validates_previous_key_bytes_and_operational_settings() {
    assert!(
        signing_config().validate().is_ok(),
        "valid literal settings isolate operational failures"
    );
    let mut failures = Vec::new();
    for (case, field, previous, key_id, window) in [
        (
            "31-byte previous",
            "previous_secret",
            "x".repeat(31),
            "valid",
            300,
        ),
        (
            "all-zero previous",
            "previous_secret",
            "\0".repeat(32),
            "valid",
            300,
        ),
        ("empty key ID", "key_id", PREVIOUS.to_owned(), "", 300),
        ("blank key ID", "key_id", PREVIOUS.to_owned(), " \t\n", 300),
        (
            "zero replay window",
            "replay_window",
            PREVIOUS.to_owned(),
            "valid",
            0,
        ),
    ] {
        let mut config = signing_config();
        let forbidden_previous = previous.clone();
        config.security.message_signing.previous_secret = previous;
        config.security.message_signing.key_id = key_id.to_owned();
        config.security.message_signing.replay_window = window;
        match config.validate() {
            Ok(()) => failures.push(case),
            Err(error) => {
                assert_safe_error(Err(error), field, &[CURRENT, PREVIOUS, &forbidden_previous]);
            }
        }
    }
    assert!(
        failures.is_empty(),
        "SIGNING.2 invalid settings accepted: {failures:?}"
    );
}

#[test]
fn signing_config_disabled_dormant_settings_do_not_block_loading() {
    let fixture = ConfigFixture::new();
    fixture.set_env(None, Some(""));
    fixture.write(
        false,
        &format!("env:{}", fixture.current_var),
        &format!("${{{}}}", fixture.previous_var),
    );
    let mut literal = Config::load_literal(Some(&fixture.path)).expect("disabled literal config");
    literal.security.message_signing.key_id.clear();
    literal.security.message_signing.replay_window = 0;
    assert!(literal.validate_with_env(&fixture.overlay()).is_ok());
    let evaluated = Config::load_evaluated(Some(&fixture.path)).expect("disabled evaluated config");
    fixture.assert_ambient_unchanged();
    assert!(!evaluated.config.security.message_signing.enabled);
}

#[test]
fn signing_config_all_zero_effective_keys_refuse_for_both_reference_spellings() {
    let zeros = "\0".repeat(32);
    let nonzero = "x".repeat(32);
    assert_eq!(zeros.len(), 32);
    assert_eq!(nonzero.len(), 32);
    let mut accepted = Vec::new();
    for (slot, expansion) in [
        ("current", false),
        ("current", true),
        ("previous", false),
        ("previous", true),
    ] {
        let fixture = ConfigFixture::new();
        let name = if slot == "current" {
            &fixture.current_var
        } else {
            &fixture.previous_var
        };
        let reference = if expansion {
            format!("${{{name}}}")
        } else {
            format!("env:{name}")
        };
        let mut config = signing_config();
        if slot == "current" {
            config
                .security
                .message_signing
                .shared_secret
                .clone_from(&reference);
            fixture.set_env(Some(&nonzero), Some(PREVIOUS));
        } else {
            config
                .security
                .message_signing
                .previous_secret
                .clone_from(&reference);
            fixture.set_env(Some(CURRENT), Some(&nonzero));
        }
        assert!(
            config.validate_with_env(&fixture.overlay()).is_ok(),
            "nonzero effective key control"
        );
        if slot == "current" {
            fixture.set_env(Some(&zeros), Some(PREVIOUS));
        } else {
            fixture.set_env(Some(CURRENT), Some(&zeros));
        }
        let overlay = fixture.overlay();
        assert_eq!(
            overlay.resolve(name).as_deref(),
            Some(zeros.as_str()),
            "fixture must expose exactly32 NUL bytes through the real overlay"
        );
        match config.validate_with_env(&overlay) {
            Ok(()) => accepted.push((slot, expansion)),
            Err(error) => assert_safe_error(
                Err(error),
                if slot == "current" {
                    "shared_secret"
                } else {
                    "previous_secret"
                },
                &[CURRENT, PREVIOUS, &reference, name, &zeros],
            ),
        }
        fixture.assert_ambient_unchanged();
    }
    assert!(
        accepted.is_empty(),
        "SIGNING.2 effective all-zero keys were accepted: {accepted:?}"
    );
}
