// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7824: `cap list` reads the readiness of each capability from the
//! gateway's own config, and says so when that config cannot be loaded.
//!
//! Every run is the real binary with a cleared environment, so a failure to
//! load the config cannot be hidden by a variable the test runner holds.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

const KEY: &str = "MIK7824_LIST_KEY";

fn run(root: &Path, args: &[&str]) -> Output {
    let mut command = gateway_bin::command(root, gateway_bin::Inherit::Nothing);
    command
        .env("PATH", root.join("no-system-programs"))
        .current_dir(root)
        .stdin(Stdio::null())
        .args(args);
    if let Some(system_root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", system_root);
    }
    if let Ok(profile) = std::env::var("LLVM_PROFILE_FILE") {
        command.env("LLVM_PROFILE_FILE", profile);
    }
    command.output().expect("run mcp-gateway")
}

/// A capabilities directory holding one keyed capability.
fn capabilities(root: &Path) -> PathBuf {
    let dir = root.join("caps");
    std::fs::create_dir_all(&dir).expect("caps dir");
    let yaml = format!(
        "name: keyed_cap\ndescription: Keyed\nproviders:\n  primary:\n    service: rest\n    \
         config:\n      base_url: https://api.invalid\n      path: /k\nauth:\n  required: true\n  \
         type: bearer\n  key: \"env:{KEY}\"\n"
    );
    std::fs::write(dir.join("keyed_cap.yaml"), yaml).expect("capability");
    dir
}

fn shown(output: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn a_missing_config_fails_the_listing_and_names_the_file() {
    let root = tempfile::tempdir().expect("root");
    let caps = capabilities(root.path());
    let missing = root.path().join("missing.yaml");
    let output = run(
        root.path(),
        &[
            "--config",
            missing.to_str().unwrap(),
            "cap",
            "list",
            caps.to_str().unwrap(),
        ],
    );
    let (out, err) = shown(&output);
    assert!(!output.status.success(), "exit 0 hid the error: {out}{err}");
    assert!(err.contains("Failed to load config"), "{err}");
    assert!(err.contains("missing.yaml"), "names the file: {err}");
    assert!(
        !out.contains("keyed_cap"),
        "listed against the environment: {out}"
    );
}

#[test]
fn a_malformed_config_is_reported_and_not_replaced_by_the_environment() {
    let root = tempfile::tempdir().expect("root");
    let caps = capabilities(root.path());
    let broken = root.path().join("broken.yaml");
    // Owner-only, so a permission refusal cannot stand in for a parse error.
    mcp_gateway::gateway::test_helpers::write_owner_only(&broken, "server: [this is: not, valid\n")
        .expect("config");
    let output = run(
        root.path(),
        &[
            "--config",
            broken.to_str().unwrap(),
            "cap",
            "list",
            caps.to_str().unwrap(),
        ],
    );
    let (out, err) = shown(&output);
    assert!(!output.status.success(), "exit 0 hid the error: {out}{err}");
    assert!(err.contains("Failed to load config"), "{err}");
    assert!(
        !out.contains("keyed_cap"),
        "listed against the environment: {out}"
    );
}

/// A config whose `env_files` hold `contents`, and the listing it produces.
fn listing_with_env_file(contents: &str) -> String {
    // An apostrophe in the path, as a TMPDIR may hold, must survive the YAML.
    let root = tempfile::Builder::new()
        .prefix("o'k")
        .tempdir()
        .expect("root");
    let caps = capabilities(root.path());
    let env_file = root.path().join("keys.env");
    mcp_gateway::gateway::test_helpers::write_owner_only(&env_file, contents).expect("env file");
    let config = root.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &config,
        // Single-quoted YAML keeps a Windows path's backslashes literal.
        format!("env_files:\n  - '{}'\n", env_file.display()),
    )
    .expect("config");
    let output = run(
        root.path(),
        &[
            "--config",
            config.to_str().unwrap(),
            "cap",
            "list",
            caps.to_str().unwrap(),
        ],
    );
    let (out, err) = shown(&output);
    assert!(output.status.success(), "{out}{err}");
    out
}

#[test]
fn a_key_held_in_the_configs_env_file_lists_the_capability_plainly() {
    let out = listing_with_env_file(&format!("{KEY}=present\n"));
    assert!(out.contains("keyed_cap - Keyed [bearer]"), "{out}");
    assert!(!out.contains("off: needs"), "{out}");
}

#[test]
fn a_key_absent_from_the_configs_env_file_marks_the_capability_off() {
    let out = listing_with_env_file("MIK7824_OTHER=x\n");
    assert!(
        out.contains(&format!("keyed_cap - Keyed [bearer] off: needs {KEY}")),
        "{out}"
    );
}
