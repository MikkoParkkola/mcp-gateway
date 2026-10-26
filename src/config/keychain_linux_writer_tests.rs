// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The Linux keychain writer against stand-in `gdbus` and `secret-tool`
//! scripts: the gate before each spawn, the value on stdin only, and what is
//! refused without a spawn.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::LinuxKeychain;
use crate::secret_store::{SecretStore, StoreError};

const NAME: &str = "mcp-gateway.auth-bearer-token.1761418800123.9f3a1c2e04b7d815";
const SENTINEL: &[u8] = b"kc-sentinel-7f3a";

const FOUND: &str = "([objectpath '/org/freedesktop/secrets/collection/login/7'], @ao [])";
const LOCKED_ITEM: &str = "(@ao [], [objectpath '/org/freedesktop/secrets/collection/work/3'])";
const NONE: &str = "(@ao [], @ao [])";
const UNLOCKED: &str = "(<false>,)";
const LOCKED: &str = "(<true>,)";

/// A script at `dir/name` that appends its argv to `dir/calls`, then runs `body`.
fn stub(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    let calls = dir.join("calls");
    let script = format!(
        "#!/bin/sh\nprintf '%s' \"{name}\" >> '{c}'\nfor a in \"$@\"; do printf ' %s' \"$a\" >> '{c}'; done\necho >> '{c}'\n{body}\n",
        c = calls.display(),
    );
    std::fs::write(&path, script).expect("write stub");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).expect("chmod stub");
    path
}

fn calls(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("calls")).unwrap_or_default()
}

/// A `gdbus` answering the collection's `Locked` read with `collection` and
/// every `SearchItems` with `search`; `secret-tool` runs `tool`.
fn keychain(
    dir: &Path,
    collection: &str,
    search: &str,
    tool: &str,
    bound: Duration,
) -> LinuxKeychain {
    let gdbus = stub(
        dir,
        "gdbus",
        &format!(
            "case \"$*\" in *Properties.Get*) printf '%s\\n' \"{collection}\";; *) printf '%s\\n' \"{search}\";; esac"
        ),
    );
    let secret_tool = stub(dir, "secret-tool", tool);
    LinuxKeychain::with_programs(gdbus, secret_tool, bound)
}

fn two_seconds() -> Duration {
    Duration::from_secs(2)
}

#[test]
fn b11_create_gates_then_stores_the_value_on_stdin_only() {
    let dir = tempfile::tempdir().expect("tempdir");
    let stored = dir.path().join("stored");
    let keychain = keychain(
        dir.path(),
        UNLOCKED,
        NONE,
        &format!("cat > '{}'", stored.display()),
        two_seconds(),
    );
    let reference = keychain.create(NAME, b" a\n").expect("created");
    assert_eq!(reference, format!("keychain:{NAME}"));
    assert_eq!(std::fs::read(&stored).expect("stdin"), b" a\n");
    let log = calls(dir.path());
    let lines: Vec<&str> = log.lines().collect();
    assert_eq!(lines.len(), 3, "{log}");
    assert!(lines[0].contains("Properties.Get"), "{log}");
    assert!(lines[1].contains("SearchItems"), "{log}");
    assert_eq!(
        lines[2],
        format!("secret-tool store --label={NAME} service {NAME}"),
        "{log}"
    );
}

#[test]
fn b12_a_locked_collection_refuses_without_spawning_secret_tool() {
    let dir = tempfile::tempdir().expect("tempdir");
    let keychain = keychain(dir.path(), LOCKED, NONE, "exit 0", two_seconds());
    let refused = keychain.create(NAME, b"v").expect_err("locked");
    assert!(matches!(refused, StoreError::Unavailable(_)), "{refused:?}");
    assert!(keychain.probe().is_err());
    assert!(
        !calls(dir.path()).contains("secret-tool"),
        "{}",
        calls(dir.path())
    );
}

#[test]
fn b15_a_taken_name_is_refused_and_never_replaced() {
    let dir = tempfile::tempdir().expect("tempdir");
    let keychain = keychain(dir.path(), UNLOCKED, FOUND, "exit 0", two_seconds());
    assert_eq!(keychain.create(NAME, b"v"), Err(StoreError::Exists));
    assert!(
        !calls(dir.path()).contains("secret-tool"),
        "{}",
        calls(dir.path())
    );
}

#[test]
fn b16_delete_in_a_locked_collection_spawns_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let keychain = keychain(dir.path(), UNLOCKED, LOCKED_ITEM, "exit 0", two_seconds());
    assert!(matches!(
        keychain.delete(NAME),
        Err(StoreError::Unavailable(_))
    ));
    assert!(
        !calls(dir.path()).contains("secret-tool"),
        "{}",
        calls(dir.path())
    );
}

#[test]
fn b16_a_clear_that_leaves_the_entry_is_not_durable() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Every search still finds the item, whatever clear reports.
    let keychain = keychain(dir.path(), UNLOCKED, FOUND, "exit 0", two_seconds());
    assert!(matches!(keychain.delete(NAME), Err(StoreError::Failed(_))));
    assert!(calls(dir.path()).contains(&format!("secret-tool clear service {NAME}")));
}

#[test]
fn b17_a_missing_secret_tool_names_its_package() {
    let dir = tempfile::tempdir().expect("tempdir");
    let gdbus = stub(
        dir.path(),
        "gdbus",
        &format!("printf '%s\\n' \"{UNLOCKED}\""),
    );
    let keychain = LinuxKeychain::with_programs(gdbus, dir.path().join("absent"), two_seconds());
    // A path that does not exist is a tool that cannot start.
    let refused = keychain.create(NAME, b"v").expect_err("no secret-tool");
    assert!(matches!(refused, StoreError::Unavailable(_)), "{refused:?}");
}

#[test]
fn b13_a_store_that_never_reads_stdin_times_out_at_the_bound() {
    let dir = tempfile::tempdir().expect("tempdir");
    let keychain = keychain(
        dir.path(),
        UNLOCKED,
        NONE,
        "exec sleep 30",
        Duration::from_millis(300),
    );
    // Larger than any pipe buffer, so the write itself would stall.
    let value = vec![b'x'; 1 << 20];
    let started = Instant::now();
    assert_eq!(keychain.create(NAME, &value), Err(StoreError::TimedOut));
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn b13_no_spawn_or_refusal_carries_the_value() {
    let dir = tempfile::tempdir().expect("tempdir");
    let keychain = keychain(
        dir.path(),
        UNLOCKED,
        NONE,
        "cat >/dev/null; echo kc-sentinel-7f3a >&2; exit 1",
        two_seconds(),
    );
    let refused = keychain.create(NAME, SENTINEL).expect_err("failed store");
    assert!(!format!("{refused:?}").contains("kc-sentinel-7f3a"));
    assert!(
        !calls(dir.path()).contains("kc-sentinel-7f3a"),
        "argv carried the value"
    );
}

/// B18 on Linux: the production writer against a real Secret Service.
#[test]
#[ignore = "needs a real Secret Service; run by the linux-keychain CI job"]
fn b18_the_real_secret_service_round_trips_then_refuses_locked() {
    use super::super::keychain::KeychainRead as _;
    let store = LinuxKeychain::from_path();
    store.probe().expect("an unlocked collection probes clean");
    let name = "mcp-gateway.ci-b18.1.00ff";
    assert_eq!(store.exists(name), Ok(false));
    assert_eq!(store.create(name, b" a\n"), Ok(format!("keychain:{name}")));
    assert_eq!(store.exists(name), Ok(true));
    assert_eq!(store.read(name).expect("read back").as_bytes(), b" a\n");
    assert_eq!(store.create(name, b"other"), Err(StoreError::Exists));
    assert_eq!(store.read(name).expect("kept").as_bytes(), b" a\n");
    store.delete(name).expect("delete");
    assert_eq!(store.exists(name), Ok(false));
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
    // Locked after a passing probe: refused before any store spawn.
    assert!(store.probe().is_err());
    assert!(matches!(
        store.create("mcp-gateway.ci-b18-locked.1.00ff", b"v"),
        Err(StoreError::Unavailable(_))
    ));
}
