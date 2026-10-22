// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8512 red tests through the built binary: the off switch, its
//! environment variable's values, and the help text's disclosure. Hermetic:
//! every run either switches the lookup off or gives it a proxy it refuses,
//! so no run reaches npm.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::path::Path;

use serde_json::Value;

const ENV: &str = "MCP_GATEWAY_DOCTOR_NO_REGISTRY_CHECK";
const SKIPPED_LABEL: &str = "npm registry check";
/// The lead's disclosure (2026-10-22), word for word.
const SENTENCE: &str = "This skips the gateway's own npm registry lookup; it does not stop npx or \
other servers started by --start-stdio from contacting npm, so air-gapped hosts should not use \
--start-stdio.";

/// A config with one enabled backend on the deprecated memory pin. Doctor
/// only locates its command (no `--start-stdio`), so nothing is started.
fn write_config(dir: &Path) -> std::path::PathBuf {
    let path = dir.join("gateway.yaml");
    std::fs::write(
        &path,
        "backends:\n  memory:\n    command: \"npx -y @modelcontextprotocol/server-memory@2026.8.31\"\n",
    )
    .expect("the config writes");
    // The gateway refuses a config other users can read.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("the config is owner-only");
    }
    path
}

/// Run `doctor --format json` with `args` and `env`; the rows.
fn doctor(args: &[&str], env: &[(&str, &str)]) -> Vec<Value> {
    let home = tempfile::tempdir().expect("a scratch home");
    let config = write_config(home.path());
    let mut command = gateway_bin::command(home.path(), gateway_bin::Inherit::Nothing);
    command
        .arg("doctor")
        .arg("--config")
        .arg(&config)
        .args(["--format", "json"])
        .args(args);
    for (name, value) in env {
        command.env(name, value);
    }
    let output = command.output().expect("the binary runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("doctor printed JSON ({e}): {stdout}"));
    report["checks"].as_array().expect("a checks array").clone()
}

fn skipped(rows: &[Value]) -> Option<&Value> {
    rows.iter().find(|row| row["label"] == SKIPPED_LABEL)
}

/// A proxy the lookup refuses, so a run with the lookup on sends nothing.
const REFUSED_PROXY: (&str, &str) = ("HTTPS_PROXY", "socks5://127.0.0.1:9");

#[test]
fn the_flag_skips_the_lookup_with_a_pass_row() {
    let rows = doctor(&["--no-registry-check"], &[REFUSED_PROXY]);
    let row = skipped(&rows).expect("the skipped row");
    assert_eq!(row["status"], "pass", "{row}");
}

#[test]
fn the_environment_variable_turns_it_off_for_any_value_but_0_and_false() {
    for value in ["1", "true", "TRUE", "yes", "garbage"] {
        let rows = doctor(&[], &[(ENV, value), REFUSED_PROXY]);
        assert!(skipped(&rows).is_some(), "{ENV}={value} must skip: {rows:?}");
    }
    for value in ["0", "false", "False"] {
        let rows = doctor(&[], &[(ENV, value), REFUSED_PROXY]);
        assert!(skipped(&rows).is_none(), "{ENV}={value} must not skip: {rows:?}");
    }
}

#[test]
fn the_check_never_adds_a_failing_row() {
    let rows = doctor(&[], &[REFUSED_PROXY]);
    for row in &rows {
        let label = row["label"].as_str().unwrap_or_default();
        if label == SKIPPED_LABEL || label.ends_with(": npm pin") {
            assert_ne!(row["status"], "fail", "{row}");
        }
    }
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
