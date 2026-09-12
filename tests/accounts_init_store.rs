// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway accounts init-store` through the real binary.
//!
//! Everything here runs the shipped executable against a synthetic temp-dir
//! config and its own env file. Nothing in this file mutates the test
//! process's environment: the keys exist only inside the env file the config
//! names, which is exactly how an operator supplies them, and
//! `MCP_GATEWAY_CONFIG` is cleared from the *child* so an ambient value cannot
//! silently select a different config.
//!
//! The refusal cases assert the bytes on disk afterwards, not just the exit
//! code. "Refused existing state" is only true if the state is still there.

#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Variable name the fixture config references as `env:...`.
const KEY_VAR: &str = "ACCOUNTS_INIT_STORE_KEY";
/// 32 raw bytes (all 0x51) in standard base64: a well-formed store key.
const KEY_B64: &str = "UVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVE=";
/// Written by the existing initializer into `authority_dir`.
const AUTHORITY_FILE: &str = "authority.json";
/// Lock file both roots carry while a store is held.
const LOCK_FILE: &str = ".personal-accounts.lock";

struct Fixture {
    /// Kept alive: dropping it removes every path below.
    _root: tempfile::TempDir,
    config: PathBuf,
    store: PathBuf,
    authority: PathBuf,
}

/// A config whose `accounts` block points at two fresh roots, with `key_value`
/// supplied through the config's own `env_files` entry. `None` writes an env
/// file that does not define `KEY_VAR` at all.
fn fixture(key_value: Option<&str>) -> Fixture {
    let root = tempfile::TempDir::new().expect("tempdir");
    let store = root.path().join("store");
    let authority = root.path().join("authority");

    let env_path = root.path().join("keys.env");
    let env_body = match key_value {
        Some(value) => format!("{KEY_VAR}={value}\n"),
        None => "ACCOUNTS_INIT_STORE_UNRELATED=1\n".to_string(),
    };
    fs::write(&env_path, env_body).expect("env file");

    let config = root.path().join("gateway.yaml");
    fs::write(
        &config,
        format!(
            "env_files:\n  - {env}\nserver:\n  port: 18731\naccounts:\n  \
             schema_version: accounts.v1\n  enabled: true\n  deployment: single_process\n  \
             instance_id: gateway-init-store\n  store_dir: {store}\n  authority_dir: {authority}\n  \
             current_key_id: current\n  keys:\n    current: env:{KEY_VAR}\n  limits:\n    \
             store_entries: 1000\n    authority_bytes: 1048576\n",
            env = env_path.display(),
            store = store.display(),
            authority = authority.display(),
        ),
    )
    .expect("config file");

    Fixture {
        _root: root,
        config,
        store,
        authority,
    }
}

fn init_store(config: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mcp-gateway"))
        .args(["accounts", "init-store", "--config"])
        .arg(config)
        // Child-only: the test process's own environment is never touched.
        .env_remove("MCP_GATEWAY_CONFIG")
        .output()
        .expect("the gateway binary must run")
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Only the lock file may sit beside a freshly created store's records.
fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .expect("root must exist")
        .map(|entry| {
            entry
                .expect("dir entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

#[test]
fn init_store_creates_an_empty_store_and_a_second_run_refuses_without_touching_it() {
    let fixture = fixture(Some(KEY_B64));

    let first = init_store(&fixture.config);
    let out = stdout_of(&first);
    assert!(
        first.status.success(),
        "first run must succeed; stdout={out} stderr={}",
        stderr_of(&first)
    );

    let manifest = fixture.authority.join(AUTHORITY_FILE);
    assert!(manifest.is_file(), "a sealed authority must exist: {out}");
    let sealed = fs::read(&manifest).expect("authority bytes");

    // Zero records by construction: nothing but the lock is in the record root.
    let record_entries = entries(&fixture.store);
    assert!(
        record_entries.iter().all(|name| name == LOCK_FILE),
        "a fresh store must hold no records, found {record_entries:?}"
    );

    // Names, not values: the report must answer "which key did it read" without
    // printing what it read.
    assert!(
        out.contains(KEY_VAR),
        "the key NAME must be reported: {out}"
    );
    assert!(
        !out.contains(KEY_B64) && !stderr_of(&first).contains(KEY_B64),
        "key material must never be printed: {out}"
    );
    assert!(
        out.contains("gateway-init-store"),
        "the instance the authority was sealed for must be reported: {out}"
    );

    // The locks are released by the first run, so a second run fails on existing
    // state rather than on a lock the command forgot to drop.
    let second = init_store(&fixture.config);
    assert!(
        !second.status.success(),
        "an initialized store must not be re-initialized; stdout={}",
        stdout_of(&second)
    );
    let refusal = stderr_of(&second);
    assert!(
        refusal.to_lowercase().contains("refus"),
        "the second run must say it refused: {refusal}"
    );
    assert!(
        !refusal.contains(KEY_B64),
        "a refusal must not leak key material: {refusal}"
    );
    assert_eq!(
        fs::read(&manifest).expect("authority bytes after refusal"),
        sealed,
        "the existing authority must be byte-identical after a refused re-init"
    );
}

#[test]
fn a_nonempty_record_root_is_refused_and_its_file_keeps_its_original_bytes() {
    let fixture = fixture(Some(KEY_B64));

    // An owner-only root that already holds something: the refusal must be for
    // the existing content, not for the directory mode.
    fs::create_dir(&fixture.store).expect("store root");
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&fixture.store, fs::Permissions::from_mode(0o700))
            .expect("owner-only root");
    }
    let stray = fixture.store.join("pre-existing.bin");
    let original: &[u8] = b"records this command must never touch\n";
    fs::write(&stray, original).expect("pre-existing file");

    let output = init_store(&fixture.config);
    assert!(
        !output.status.success(),
        "a non-empty record root must be refused; stdout={}",
        stdout_of(&output)
    );
    assert_eq!(
        fs::read(&stray).expect("pre-existing bytes"),
        original,
        "the pre-existing file must be byte-identical after the refusal"
    );
    assert!(
        !fixture.authority.join(AUTHORITY_FILE).is_file(),
        "a refused run must not seal an authority"
    );
}

#[test]
fn an_unresolved_key_reference_is_refused_before_any_root_is_created() {
    // The env file exists and parses, but never defines the referenced name.
    let fixture = fixture(None);

    let output = init_store(&fixture.config);
    assert!(
        !output.status.success(),
        "an unresolvable key reference must be refused; stdout={}",
        stdout_of(&output)
    );
    let refusal = stderr_of(&output);
    assert!(
        refusal.contains(KEY_VAR),
        "the refusal must name the variable that did not resolve: {refusal}"
    );
    assert!(
        !fixture.store.exists() && !fixture.authority.exists(),
        "a configuration refusal must not create custody directories"
    );
}

#[test]
fn an_unparsable_key_is_refused_without_echoing_it() {
    let fixture = fixture(Some("%%%not-base64%%%"));

    let output = init_store(&fixture.config);
    assert!(
        !output.status.success(),
        "a malformed key must be refused; stdout={}",
        stdout_of(&output)
    );
    let refusal = stderr_of(&output);
    assert!(
        !refusal.contains("%%%not-base64%%%"),
        "the refusal must not echo the supplied material: {refusal}"
    );
    assert!(
        !fixture.store.exists() && !fixture.authority.exists(),
        "a configuration refusal must not create custody directories"
    );
}

#[test]
fn a_wrong_length_key_is_refused() {
    // Valid base64, but three bytes rather than the required thirty-two. A store
    // sealed under a short key would be a store no correct build can open.
    let fixture = fixture(Some("QUJD"));

    let output = init_store(&fixture.config);
    assert!(
        !output.status.success(),
        "a short key must be refused; stdout={}",
        stdout_of(&output)
    );
    assert!(
        !fixture.store.exists() && !fixture.authority.exists(),
        "a configuration refusal must not create custody directories"
    );
}

#[test]
fn init_store_without_a_config_refuses_instead_of_guessing_one() {
    let output = Command::new(env!("CARGO_BIN_EXE_mcp-gateway"))
        .args(["accounts", "init-store"])
        .env_remove("MCP_GATEWAY_CONFIG")
        .output()
        .expect("the gateway binary must run");

    assert!(
        !output.status.success(),
        "creating custody state from a discovered config must not happen; stdout={}",
        stdout_of(&output)
    );
    assert!(
        stderr_of(&output).contains("--config"),
        "the refusal must point at --config: {}",
        stderr_of(&output)
    );
}
