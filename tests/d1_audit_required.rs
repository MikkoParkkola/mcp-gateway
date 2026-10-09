// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! 4.0.0 item D1-a: with auth on, the audit log is required (D1-T1, T2, T13).
//!
//! MIK-8044 P2c2: with auth on, an unset `security.transparency_log.enabled`
//! now means on, so an authenticated config no longer needs the line. Writing
//! `enabled: false` with auth on still fails the load: D1-a is unchanged.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::process::Stdio;
use std::time::Duration;

const AUTH_ON: &str = "auth:\n  enabled: true\n  bearer_token: d1-required-test-token-0123456789\n";
const LOG_OFF: &str = "security:\n  transparency_log:\n    enabled: false\n";

fn write_config(dir: &tempfile::TempDir, body: &str) -> std::path::PathBuf {
    let path = dir.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, body).expect("write config");
    path
}

/// D1-T1, as P2c2 left it: auth on with the log turned off does not load.
#[test]
fn auth_enabled_with_the_audit_log_turned_off_fails_to_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(&dir, &format!("{AUTH_ON}{LOG_OFF}"));
    let err = mcp_gateway::config::Config::load(Some(&path))
        .expect_err("auth on with the audit log turned off must not load");
    assert!(
        err.to_string().contains("security.transparency_log"),
        "the error must name the block: {err}"
    );
}

/// P2c2: auth on with no `transparency_log` section loads with the log on.
#[test]
fn auth_enabled_without_an_audit_section_turns_the_log_on() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(&dir, AUTH_ON);
    let config = mcp_gateway::config::Config::load(Some(&path))
        .expect("auth on with no audit section must load");
    assert!(config.security.transparency_log.enabled, "the log is on");
}

/// P2c2: a section that sets only the path also leaves `enabled` unset, so
/// the log is on.
#[test]
fn auth_enabled_with_a_section_that_omits_enabled_turns_the_log_on() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("audit").join("transparency.jsonl");
    let body = format!(
        "{AUTH_ON}security:\n  transparency_log:\n    path: {}\n",
        log.display()
    );
    let path = write_config(&dir, &body);
    let config = mcp_gateway::config::Config::load(Some(&path)).expect("loads");
    assert!(config.security.transparency_log.enabled, "the log is on");
}

/// P2c2 guard: the default follows auth, so auth off leaves the log off.
#[test]
fn auth_disabled_leaves_the_audit_log_off() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(&dir, "auth:\n  enabled: false\n");
    let config = mcp_gateway::config::Config::load(Some(&path)).expect("loads");
    assert!(
        !config.security.transparency_log.enabled,
        "the log stays off"
    );
}

/// D1-T2, positive control: auth off needs no log.
#[test]
fn auth_disabled_needs_no_audit_log() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(&dir, "auth:\n  enabled: false\n");
    mcp_gateway::config::Config::load(Some(&path)).expect("auth off loads without a log");
}

/// Positive control for T1: the same auth-on config with the log loads.
#[test]
fn auth_enabled_with_audit_log_loads() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("audit").join("transparency.jsonl");
    let body = format!(
        "{AUTH_ON}security:\n  transparency_log:\n    enabled: true\n    path: {}\n",
        log.display()
    );
    let path = write_config(&dir, &body);
    mcp_gateway::config::Config::load(Some(&path)).expect("auth on with a log loads");
}

/// D1-T13. `serve --stdio` obeys the same rule: it exits non-zero with the
/// D1-a message before reading stdin. Stdin is held open, so a gateway that
/// starts serving never exits and the timeout fails the test.
#[tokio::test]
async fn stdio_serve_obeys_audit_required() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(&dir, &format!("{AUTH_ON}{LOG_OFF}"));
    let mut command = tokio::process::Command::from(gateway_bin::command(
        dir.path(),
        gateway_bin::Inherit::Environment,
    ));
    command
        .args(["--config", path.to_str().unwrap(), "serve", "--stdio"])
        .current_dir(dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("XDG_DATA_HOME", dir.path().join("data"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().expect("spawn shipped binary");
    let _stdin = child.stdin.take();
    let output = tokio::time::timeout(Duration::from_secs(30), child.wait_with_output())
        .await
        .expect("stdio serve must exit before reading stdin, not start serving")
        .expect("reap child");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "must exit non-zero: {stderr}");
    assert!(
        stderr.contains("security.transparency_log"),
        "must name the D1-a rule: {stderr}"
    );
}
