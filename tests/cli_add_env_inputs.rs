// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `add`'s env inputs through the real binary: `add -e NAME`
//! takes the value from the process environment, `--env-file -` from stdin,
//! and a value joined to `-e` is refused (exit 2) without appearing in any
//! output or file. A cleared environment and a temporary home: nothing here
//! reads or writes the real one.
#![cfg(feature = "webui")]

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::io::Write;
use std::path::Path;
use std::process::{Output, Stdio};

const CANARY: &str = "zz-canary-value-0123456789";

fn run(root: &Path, args: &[&str], env: &[(&str, &str)], stdin: Option<&[u8]>) -> Output {
    let mut command = gateway_bin::command(root, gateway_bin::Inherit::Nothing);
    command
        .current_dir(root)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .args(args);
    for (name, value) in env {
        command.env(name, value);
    }
    if let Some(system_root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", system_root);
    }
    if let Ok(profile) = std::env::var("LLVM_PROFILE_FILE") {
        command.env("LLVM_PROFILE_FILE", profile);
    }
    let mut child = command.spawn().expect("run mcp-gateway"); // spawn-check: waits for exit: add exits by itself
    if let Some(bytes) = stdin {
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(bytes)
            .expect("write stdin");
    }
    child.wait_with_output().expect("wait")
}

/// A config whose secrets go to owner-only files beside it.
fn config(root: &Path) -> std::path::PathBuf {
    let path = root.join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, "secrets:\n  store: files\n")
        .expect("config");
    path
}

/// Every file under `root` whose bytes hold `needle`.
fn files_holding(root: &Path, needle: &str) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut dirs = vec![root.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).expect("dir").flatten() {
            let path = entry.path();
            if path.is_dir() {
                dirs.push(path);
            } else if std::fs::read(&path)
                .unwrap_or_default()
                .windows(needle.len())
                .any(|w| w == needle.as_bytes())
            {
                found.push(path);
            }
        }
    }
    found
}

/// E2x: `-e NAME` stores NAME's value from the environment; gateway.yaml
/// holds a reference, not the value.
#[test]
fn e2x_a_name_takes_its_value_from_the_process_environment() {
    let root = tempfile::tempdir().expect("tempdir");
    let path = config(root.path());
    let out = run(
        root.path(),
        &[
            "-c",
            path.to_str().expect("utf-8"),
            "add",
            "srv",
            "--command",
            "node server.js",
            "-e",
            "SERVICE_TOKEN",
        ],
        &[("SERVICE_TOKEN", CANARY)],
        None,
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let yaml = std::fs::read_to_string(&path).expect("read");
    assert!(yaml.contains("SERVICE_TOKEN"), "{yaml}");
    assert!(!yaml.contains(CANARY), "{yaml}");
    assert!(!String::from_utf8_lossy(&out.stdout).contains(CANARY));
    assert!(!String::from_utf8_lossy(&out.stderr).contains(CANARY));
}

/// E3x: `--env-file -` reads the JSON object from stdin.
#[test]
fn e3x_an_env_file_on_stdin_is_stored() {
    let root = tempfile::tempdir().expect("tempdir");
    let path = config(root.path());
    let body = format!(r#"{{"SERVICE_TOKEN":"{CANARY}"}}"#);
    let out = run(
        root.path(),
        &[
            "-c",
            path.to_str().expect("utf-8"),
            "add",
            "srv",
            "--command",
            "node server.js",
            "--env-file",
            "-",
        ],
        &[],
        Some(body.as_bytes()),
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let yaml = std::fs::read_to_string(&path).expect("read");
    assert!(
        yaml.contains("SERVICE_TOKEN") && !yaml.contains(CANARY),
        "{yaml}"
    );
}

/// E1x: a value joined to `-e` exits 2 before any write; the canary is in
/// no output and no file, and the config is unchanged.
#[test]
fn e1x_a_value_on_the_command_line_exits_2_and_is_written_nowhere() {
    let root = tempfile::tempdir().expect("tempdir");
    let path = config(root.path());
    let before = std::fs::read_to_string(&path).expect("read");
    let joined = format!("SERVICE_TOKEN={CANARY}");
    let out = run(
        root.path(),
        &[
            "-c",
            path.to_str().expect("utf-8"),
            "add",
            "srv",
            "--command",
            "node server.js",
            "-e",
            &joined,
        ],
        &[],
        None,
    );
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains(CANARY));
    assert!(!String::from_utf8_lossy(&out.stderr).contains(CANARY));
    assert_eq!(std::fs::read_to_string(&path).expect("read"), before);
    assert!(files_holding(root.path(), CANARY).is_empty());
}
