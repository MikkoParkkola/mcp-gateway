// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8512 red tests through the built binary: the off switch, its
//! environment variable's values, the hardened posture, and the help text's
//! disclosure. Hermetic by construction: the config's only pin is a package
//! outside the registry, which the check never sends anywhere, so no run can
//! reach npm whatever the switch does. The lookup's traffic is tested against
//! a local fake in `src/commands/doctor/npm_pin_wire_tests.rs`.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::path::{Path, PathBuf};

use serde_json::Value;

const ENV: &str = "MCP_GATEWAY_DOCTOR_NO_REGISTRY_CHECK";
const SKIPPED_LABEL: &str = "npm registry check";
/// The lead's disclosure (2026-10-22), word for word.
const SENTENCE: &str = "This skips the gateway's own npm registry lookup; it does not stop npx or \
other servers started by --start-stdio from contacting npm, so air-gapped hosts should not use \
--start-stdio.";

/// One enabled backend pinning a package the registry does not ship. Doctor
/// only locates its command (no `--start-stdio`), so nothing is started.
const STANDARD: &str = "backends:\n  internal:\n    command: \"npx -y @company/internal-tool@1.2.3\"\n";

/// The same backend under `security.posture: hardened` (which forces message
/// signing, so it carries a secret).
const HARDENED: &str = "backends:\n  internal:\n    command: \"npx -y @company/internal-tool@1.2.3\"\n\
security:\n  posture: hardened\n  message_signing:\n    shared_secret: \"hardened-signing-secret-0123456789abcdef\"\n";

fn write_config(dir: &Path, text: &str) -> PathBuf {
    let path = dir.join("gateway.yaml");
    std::fs::write(&path, text).expect("the config writes");
    // The gateway refuses a config other users can read.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("the config is owner-only");
    }
    path
}

/// Run `doctor --format json` on `config` with `args` and `env`; the rows.
/// The config file is byte-identical afterwards (DOCTOR.3: read-only).
fn doctor(config: &str, args: &[&str], env: &[(&str, &str)]) -> Vec<Value> {
    let home = tempfile::tempdir().expect("a scratch home");
    let path = write_config(home.path(), config);
    let before = std::fs::read(&path).expect("the config reads");
    let mut command = gateway_bin::command(home.path(), gateway_bin::Inherit::Nothing);
    command
        .arg("doctor")
        .arg("--config")
        .arg(&path)
        .args(["--format", "json"])
        .args(args);
    for (name, value) in env {
        command.env(name, value);
    }
    let output = command.output().expect("the binary runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("doctor printed JSON ({e}): {stdout}"));
    assert_eq!(
        std::fs::read(&path).expect("the config reads"),
        before,
        "doctor changed the config"
    );
    let rows = report["checks"].as_array().expect("a checks array").clone();
    // The config itself loads: a fixture error would hide every other row.
    let config_row = rows.iter().find(|row| row["category"] == "config");
    assert!(
        config_row.is_some_and(|row| row["status"] != "fail"),
        "the fixture config must load: {rows:?}"
    );
    rows
}

fn skipped(rows: &[Value]) -> Option<&Value> {
    rows.iter().find(|row| row["label"] == SKIPPED_LABEL)
}

#[test]
fn the_flag_skips_the_lookup_with_a_pass_row() {
    let rows = doctor(STANDARD, &["--no-registry-check"], &[]);
    let row = skipped(&rows).expect("the skipped row");
    assert_eq!(row["status"], "pass", "{row}");
    assert!(row["detail"].as_str().unwrap_or_default().contains("--no-registry-check"), "{row}");
}

#[test]
fn the_environment_variable_turns_it_off_for_any_value_but_0_and_false() {
    for value in ["1", "true", "TRUE", "yes", "garbage"] {
        let rows = doctor(STANDARD, &[], &[(ENV, value)]);
        assert!(skipped(&rows).is_some(), "{ENV}={value} must skip: {rows:?}");
    }
    for value in ["0", "false", "False"] {
        let rows = doctor(STANDARD, &[], &[(ENV, value)]);
        assert!(skipped(&rows).is_none(), "{ENV}={value} must not skip: {rows:?}");
    }
    // Unset: the lookup runs (on by default), so no skipped row either.
    assert!(skipped(&doctor(STANDARD, &[], &[])).is_none());
}

#[test]
fn the_hardened_posture_skips_the_lookup() {
    let rows = doctor(HARDENED, &[], &[]);
    let row = skipped(&rows).expect("the skipped row under hardened");
    assert_eq!(row["status"], "pass", "{row}");
    assert!(row["detail"].as_str().unwrap_or_default().contains("hardened"), "{row}");
}

#[test]
fn the_help_text_carries_the_disclosure() {
    let home = tempfile::tempdir().expect("a scratch home");
    let output = gateway_bin::command(home.path(), gateway_bin::Inherit::Nothing)
        .args(["doctor", "--help"])
        .output()
        .expect("the binary runs");
    let help = String::from_utf8_lossy(&output.stdout);
    let flat: String = help.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(flat.contains("--no-registry-check"), "{help}");
    assert!(flat.contains(SENTENCE), "the disclosure, word for word: {help}");
    assert!(flat.contains(ENV), "{help}");
    // Operator ruling 2026-10-22: on by default, and the help says what that
    // costs in privacy: which names leave the machine, and that npm sees the IP.
    assert!(flat.contains("on by default"), "{help}");
    assert!(flat.contains("package names"), "{help}");
    assert!(flat.contains("IP address"), "{help}");
}
