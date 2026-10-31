// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! R12: the radar's command-line producers read the record key and never
//! create it. With no key, `cap discover --shadow` says its URL ids are for
//! this run only and they differ run to run; with a key file or a configured
//! key, ids hold across runs. `doctor` writes nothing either. The real binary
//! runs in a child with its own home and data directory.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::Value;

const FIND: &str = "r12-remote";
const KEY: &str = "r12-record-key-not-a-secret-0123456789abcdef0123456789";
/// A key file holds 64 lowercase hex characters, as the gateway writes it.
const KEY_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn write(path: &Path, text: &str) {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).expect("dir");
    }
    mcp_gateway::gateway::test_helpers::write_owner_only(path, text).expect("write");
}

/// A home naming one HTTP server in Cursor's config, and a gateway config.
fn home(gateway: &str) -> tempfile::TempDir {
    home_in(tempfile::tempdir().expect("home"), gateway)
}

/// [`home`] in `home`, which may already hold files the config names.
fn home_in(home: tempfile::TempDir, gateway: &str) -> tempfile::TempDir {
    write(
        &home.path().join(".cursor/mcp.json"),
        &serde_json::json!({"mcpServers": {
            FIND: {"url": "https://r12.example.internal/a/mcp"},
        }})
        .to_string(),
    );
    write(&home.path().join("gateway.yaml"), gateway);
    // The data directory exists, owner-only, as an installed gateway leaves
    // it: a command that created the key on a miss could then write it.
    let data = data_dir(home.path());
    std::fs::create_dir_all(&data).expect("data dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700))
            .expect("owner-only data dir");
    }
    home
}

fn data_dir(home: &Path) -> PathBuf {
    home.join("data")
}

/// Every file under `dir`, relative to it.
fn files(dir: &Path) -> BTreeSet<PathBuf> {
    let mut found = BTreeSet::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&next) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                found.insert(path.strip_prefix(dir).expect("under").to_path_buf());
            }
        }
    }
    found
}

/// One `cap discover --shadow --format json` run: the find's asset id and
/// the whole stdout.
fn shadow_run(home: &Path) -> (String, String) {
    shadow_run_with(home, &[])
}

/// [`shadow_run`] with `vars` set in the child's environment.
fn shadow_run_with(home: &Path, vars: &[(&str, &str)]) -> (String, String) {
    let out = gateway_bin::command(home, gateway_bin::Inherit::Nothing)
        .current_dir(home)
        .env("MCP_GATEWAY_CONFIG_DIR", data_dir(home))
        .envs(vars.iter().copied())
        .args([
            "cap",
            "discover",
            "--shadow",
            "--format",
            "json",
            "--gateway-config",
        ])
        .arg(home.join("gateway.yaml"))
        .output()
        .expect("the built binary runs");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_str(&stdout).expect("a JSON report");
    let id = report["assets"]
        .as_array()
        .expect("assets")
        .iter()
        .find(|asset| asset["name"] == FIND)
        .and_then(|asset| asset["id"].as_str())
        .unwrap_or_else(|| panic!("{FIND} not reported: {stdout}"))
        .to_string();
    (id, stdout)
}

/// One `doctor --format json` run: its stdout.
fn doctor_run(home: &Path) -> String {
    let out = gateway_bin::command(home, gateway_bin::Inherit::Nothing)
        .current_dir(home)
        .env("MCP_GATEWAY_CONFIG_DIR", data_dir(home))
        .arg("doctor")
        .arg("--config")
        .arg(home.join("gateway.yaml"))
        .args(["--format", "json"])
        .output()
        .expect("the built binary runs");
    // Doctor exits non-zero on findings: its status is not judged here.
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn with_no_key_the_cli_writes_none_and_says_its_ids_are_for_this_run() {
    let home = home("backends: {}\n");
    let before = files(home.path());
    let (first, stdout) = shadow_run(home.path());
    let (second, _) = shadow_run(home.path());
    let doctor = doctor_run(home.path());
    let key = data_dir(home.path()).join("record-principal.key");
    if let Ok(meta) = std::fs::metadata(&key) {
        panic!("a read command created the key file ({} bytes)", meta.len());
    }
    assert_eq!(files(home.path()), before, "a read command wrote a file");
    assert!(
        stdout
            .to_ascii_lowercase()
            .contains("this run only: no record key was found"),
        "no note that no key was found: {stdout}"
    );
    assert!(
        doctor.to_ascii_lowercase().contains("this run only"),
        "doctor's findings carry no note that their ids are for this run: {doctor}"
    );
    assert_ne!(first, second, "ids from a one-run key held across runs");
}

#[test]
fn with_a_key_file_the_ids_hold_and_nothing_is_written() {
    let home = home("backends: {}\n");
    write(&data_dir(home.path()).join("record-principal.key"), KEY_HEX);
    let before = files(home.path());
    let (first, stdout) = shadow_run(home.path());
    let (second, _) = shadow_run(home.path());
    doctor_run(home.path());
    assert_eq!(files(home.path()), before, "a read command wrote a file");
    assert_eq!(first, second, "ids from the key file changed between runs");
    assert!(
        !stdout.to_ascii_lowercase().contains("this run only"),
        "a keyed run says its ids are for this run: {stdout}"
    );
    assert!(!stdout.contains(KEY_HEX), "the key reached the output");
}

#[test]
fn a_key_file_that_is_no_key_is_reported_not_replaced() {
    let home = home("backends: {}\n");
    write(&data_dir(home.path()).join("record-principal.key"), KEY);
    let before = files(home.path());
    let (_, stdout) = shadow_run(home.path());
    assert_eq!(files(home.path()), before, "a read command wrote a file");
    let lower = stdout.to_ascii_lowercase();
    assert!(
        lower.contains("this run only") && lower.contains("could not be read"),
        "no note that the key file could not be read: {stdout}"
    );
    assert!(!stdout.contains(KEY), "the file's text reached the output");
}

#[test]
fn with_a_configured_key_the_ids_hold_and_nothing_is_written() {
    let home = home(&format!(
        "backends: {{}}\nsecurity:\n  record_principal_key: \"{KEY}\"\n"
    ));
    let before = files(home.path());
    let (first, stdout) = shadow_run(home.path());
    let (second, _) = shadow_run(home.path());
    doctor_run(home.path());
    assert_eq!(files(home.path()), before, "a read command wrote a file");
    assert_eq!(first, second, "ids from the configured key changed");
    assert!(!stdout.contains(KEY), "the key reached the output");
}

/// A key named through the config's env files resolves as the gateway
/// resolves it: the ids equal those under the same key given literally, no
/// note says they are for one run, and the env file wins over a process
/// variable of the same name, as it does for the gateway.
#[test]
fn a_key_named_through_an_env_file_is_the_gateways_key() {
    let literal = home(&format!(
        "backends: {{}}\nsecurity:\n  record_principal_key: \"{KEY}\"\n"
    ));
    let (expected, _) = shadow_run(literal.path());

    let named = tempfile::tempdir().expect("home");
    let env_file = named.path().join("keys.env");
    write(&env_file, &format!("R12_RECORD_KEY={KEY}\n"));
    let gateway = format!(
        "env_files:\n  - \"{}\"\nbackends: {{}}\nsecurity:\n  record_principal_key: \"env:R12_RECORD_KEY\"\n",
        env_file.display()
    );
    let named = home_in(named, &gateway);
    let before = files(named.path());
    let (from_file, stdout) = shadow_run(named.path());
    assert_eq!(from_file, expected, "the env-file key is not the gateway's");
    assert!(
        !stdout.to_ascii_lowercase().contains("this run only"),
        "an env-file key read as no key: {stdout}"
    );
    let (overridden, _) = shadow_run_with(
        named.path(),
        &[(
            "R12_RECORD_KEY",
            "a-process-value-the-env-file-overrides-0123456789",
        )],
    );
    assert_eq!(overridden, expected, "a process variable beat the env file");
    assert_eq!(files(named.path()), before, "a read command wrote a file");
    assert!(!stdout.contains(KEY), "the key reached the output");
}
