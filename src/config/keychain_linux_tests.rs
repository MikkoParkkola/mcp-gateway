// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The Linux keychain against stand-in `gdbus` and `secret-tool` scripts: what
//! is spawned, in what order, and what is refused without a spawn.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::keychain::{KeychainError, KeychainRead};
use super::keychain_linux::LinuxKeychain;

const NAME: &str = "mcp-gateway.auth-bearer-token.1761418800123.9f3a1c2e04b7d815";
const SENTINEL: &str = "kc-sentinel-7f3a";

/// A script at `dir/name` that appends its argv to `dir/calls` and then runs `body`.
fn stub(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    let calls = dir.join("calls");
    let script = format!(
        "#!/bin/sh\nprintf '%s' \"{name}\" >> '{}'\nfor a in \"$@\"; do printf ' %s' \"$a\" >> '{}'; done\necho >> '{}'\n{body}\n",
        calls.display(),
        calls.display(),
        calls.display()
    );
    std::fs::write(&path, script).expect("write stub");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).expect("chmod stub");
    path
}

fn calls(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("calls")).unwrap_or_default()
}

/// A keychain whose `gdbus` prints `reply` and whose `secret-tool` runs `lookup`.
fn keychain(dir: &Path, reply: &str, lookup: &str) -> LinuxKeychain {
    let gdbus = stub(dir, "gdbus", &format!("printf '%s\\n' \"{reply}\""));
    let secret_tool = stub(dir, "secret-tool", lookup);
    LinuxKeychain::with_programs(gdbus, secret_tool, Duration::from_secs(2))
}

const UNLOCKED: &str = "([objectpath '/org/freedesktop/secrets/collection/login/7'], @ao [])";
const LOCKED: &str = "(@ao [], [objectpath '/org/freedesktop/secrets/collection/work/3'])";
const NONE: &str = "(@ao [], @ao [])";

#[test]
fn a8_an_unlocked_item_is_searched_then_looked_up() {
    let dir = tempfile::tempdir().expect("tempdir");
    let keychain = keychain(dir.path(), UNLOCKED, "printf ' a\\n'");
    let bytes = keychain.read(NAME).expect("an unlocked item reads");
    // A21: the stored bytes exactly, leading space and trailing newline kept.
    assert_eq!(bytes.as_bytes(), b" a\n");
    let log = calls(dir.path());
    let lines: Vec<&str> = log.lines().collect();
    assert_eq!(lines.len(), 2, "{log}");
    assert!(lines[0].starts_with("gdbus call --session"), "{log}");
    assert!(
        lines[0].contains("org.freedesktop.Secret.Service.SearchItems"),
        "{log}"
    );
    assert!(
        lines[0].contains(&format!("{{'service': '{NAME}'}}")),
        "{log}"
    );
    assert_eq!(
        lines[1],
        format!("secret-tool lookup service {NAME}"),
        "{log}"
    );
}

#[test]
fn a8_a_locked_item_is_refused_without_spawning_secret_tool() {
    let dir = tempfile::tempdir().expect("tempdir");
    let keychain = keychain(dir.path(), LOCKED, "printf 'never'");
    assert!(matches!(keychain.read(NAME), Err(KeychainError::Locked)));
    assert!(
        !calls(dir.path()).contains("secret-tool"),
        "{}",
        calls(dir.path())
    );
}

#[test]
fn a8_no_item_is_missing_without_spawning_secret_tool() {
    let dir = tempfile::tempdir().expect("tempdir");
    let keychain = keychain(dir.path(), NONE, "printf 'never'");
    assert!(matches!(keychain.read(NAME), Err(KeychainError::Missing)));
    assert!(
        !calls(dir.path()).contains("secret-tool"),
        "{}",
        calls(dir.path())
    );
}

#[test]
fn a8_a_bus_failure_is_unavailable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let gdbus = stub(
        dir.path(),
        "gdbus",
        "echo 'Error: no session bus' >&2; exit 1",
    );
    let secret_tool = stub(dir.path(), "secret-tool", "printf 'never'");
    let keychain = LinuxKeychain::with_programs(gdbus, secret_tool, Duration::from_secs(2));
    assert!(matches!(
        keychain.read(NAME),
        Err(KeychainError::Unavailable(_))
    ));
    assert!(!calls(dir.path()).contains("secret-tool"));
}

#[test]
fn a8_a_slow_tool_times_out_at_the_bound_and_is_reaped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pid_file = dir.path().join("pid");
    let gdbus = stub(
        dir.path(),
        "gdbus",
        &format!("echo $$ > '{}'; exec sleep 30", pid_file.display()),
    );
    let secret_tool = stub(dir.path(), "secret-tool", "printf 'never'");
    let keychain = LinuxKeychain::with_programs(gdbus, secret_tool, Duration::from_millis(300));
    let started = Instant::now();
    assert!(matches!(keychain.read(NAME), Err(KeychainError::Timeout)));
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "{:?}",
        started.elapsed()
    );
    let pid = std::fs::read_to_string(&pid_file).expect("stub ran");
    // Reaped before the call returned: the pid no longer names a process.
    let status = std::fs::read_to_string(format!("/proc/{}/status", pid.trim()));
    assert!(status.is_err(), "the child outlived the call: {status:?}");
}

#[test]
fn a7_no_refusal_or_spawn_carries_the_value() {
    let dir = tempfile::tempdir().expect("tempdir");
    // The value appears in a failing lookup's stdout and stderr.
    let keychain = keychain(
        dir.path(),
        UNLOCKED,
        &format!("printf '{SENTINEL}'; echo '{SENTINEL}' >&2; exit 1"),
    );
    let error = keychain.read(NAME).expect_err("a failed lookup is refused");
    assert!(!format!("{error:?}").contains(SENTINEL), "{error:?}");
    assert!(!error.reason().contains(SENTINEL));
    assert!(
        !calls(dir.path()).contains(SENTINEL),
        "argv carried the value"
    );
}

/// The entry the `linux-keychain` CI job stores, with `secret-tool store`,
/// before this test runs.
const REAL_NAME: &str = "mcp-gateway-ci-a15";

#[test]
#[ignore = "needs a real Secret Service; run by the linux-keychain CI job"]
fn a15_the_real_secret_service_reads_back_byte_exact_and_refuses_when_locked() {
    let keychain = LinuxKeychain::from_path();
    // Piped, `secret-tool lookup` prints the stored bytes and adds nothing.
    let read = keychain.read(REAL_NAME).expect("the stored entry");
    assert_eq!(read.as_bytes(), b" a\n");
    assert_eq!(
        keychain.read("mcp-gateway-ci-absent").expect_err("absent"),
        KeychainError::Missing
    );
    let locked = std::process::Command::new("gdbus")
        .args([
            "call",
            "--session",
            "--dest",
            "org.freedesktop.secrets",
            "--object-path",
            "/org/freedesktop/secrets",
            "--method",
            "org.freedesktop.Secret.Service.Lock",
            "[objectpath '/org/freedesktop/secrets/aliases/default']",
        ])
        .status()
        .expect("run gdbus");
    assert!(locked.success(), "could not lock the default collection");
    // No prompter runs in the job, so a read that asked to unlock would hang
    // until the bound instead of answering Locked.
    assert_eq!(
        keychain.read(REAL_NAME).expect_err("locked"),
        KeychainError::Locked
    );
}
