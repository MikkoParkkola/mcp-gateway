// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Real init, isolated Auto/files custody. Native keychains need separate shards.
#![cfg(target_os = "linux")]

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use mcp_gateway::config::{Config, secret_slot};
use mcp_gateway::gateway::{ResolvedAuthConfig, test_helpers::write_owner_only};
use std::path::{Path, PathBuf};

fn command(root: &Path) -> std::process::Command {
    let mut cmd = gateway_bin::command(&root.join("home"), gateway_bin::Inherit::Nothing);
    // Linux probes find neither gdbus nor secret-tool, so Auto chooses files.
    cmd.current_dir(root).env("PATH", root.join("empty-bin"));
    cmd
}

fn initialized() -> (tempfile::TempDir, PathBuf, String, String) {
    let root = tempfile::tempdir().expect("isolated init");
    std::fs::create_dir(root.path().join("home")).expect("home");
    let path = root.path().join("gateway.yaml");
    let out = command(root.path())
        .args(["init", "--output"])
        .arg(&path)
        .output()
        .expect("real init");
    assert!(out.status.success(), "init must succeed");
    let written = Config::load_literal(Some(&path))
        .expect("literal config")
        .auth
        .bearer_token
        .expect("generated bearer slot");
    let token = if let Some(file) = written.strip_prefix("file:") {
        assert!(Path::new(file).starts_with(root.path().join("secrets")));
        std::fs::read_to_string(file)
            .expect("store entry")
            .trim_end_matches('\n')
            .to_owned()
    } else {
        assert_eq!(
            secret_slot(&written),
            "<set>",
            "isolated init must use files"
        );
        written.clone()
    };
    assert!(token.starts_with("mcpgw_") && token.len() > "mcpgw_".len());
    assert!(!String::from_utf8_lossy(&out.stdout).contains(&token));
    assert!(!String::from_utf8_lossy(&out.stderr).contains(&token));
    (root, path, written, token)
}

/// ADMINTOK.1 / design 6: real init writes no token into any config output
/// (including samples), and exactly one live file-store entry holds its value.
#[test]
fn admintok_1_init_writes_only_a_reference_and_one_store_entry() {
    let (root, _, written, token) = initialized();
    let mut dirs = vec![root.path().to_path_buf()];
    let mut configs = 0;
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(dir).expect("outputs") {
            let path = entry.expect("output").path();
            if path.is_dir() {
                dirs.push(path);
            } else if path
                .extension()
                .is_some_and(|ext| ext == "yaml" || ext == "yml")
            {
                configs += 1;
                assert!(
                    !std::fs::read_to_string(&path)
                        .expect("config output")
                        .contains(&token),
                    "init wrote the literal into {}",
                    path.display()
                );
            }
        }
    }
    assert_eq!(configs, 3, "gateway and both default sample configs");
    let entries: Vec<_> = std::fs::read_dir(root.path().join("secrets"))
        .expect("one store directory")
        .map(|e| e.expect("entry").path())
        .collect();
    assert_eq!(entries.len(), 1, "exactly one live entry");
    assert_eq!(written, format!("file:{}", entries[0].display()));
}

/// ADMINTOK.2 / design 2,6: the gateway's auth comparator loads the untouched
/// init config, grants admin to its retrieved token, and refuses a wrong token.
#[test]
fn admintok_2_init_token_authenticates_as_admin_and_wrong_token_is_refused() {
    let (_root, path, _, token) = initialized();
    let loaded = Config::load_evaluated(Some(&path)).expect("init config loads");
    let auth = ResolvedAuthConfig::try_from_config(
        &loaded.config.auth,
        &loaded.overlay,
        "9430-record-key-for-auth-check-32-bytes",
    )
    .expect("gateway auth");
    assert!(!auth.is_public_path("/ui/api/backends"));
    let client = auth
        .validate_token(&token)
        .expect("retrieved token authenticates");
    assert!(client.authenticated && client.admin);
    assert!(auth.validate_token(&format!("{token}-wrong")).is_none());
}

/// ADMINTOK.2 / A4: doctor uses secret_slot's reference/<set> semantics,
/// names legacy custody, never leaks the value, even when evaluation fails.
#[test]
fn admintok_2_doctor_names_custody_without_value_even_on_resolution_failure() {
    let (root, path, written, token) = initialized();
    let original = std::fs::read_to_string(&path).expect("init output");
    let file = root.path().join("doctor-token");
    write_owner_only(&file, &token).expect("reference fixture");
    for slot in [
        written.clone(),
        token.clone(),
        format!("file:{}", file.display()),
        format!("file:{}", root.path().join("missing-token").display()),
    ] {
        write_owner_only(&path, original.replace(&written, &slot)).expect("doctor fixture");
        let out = command(root.path())
            .args(["doctor", "--config"])
            .arg(&path)
            .args(["--format", "json", "--no-registry-check"])
            .output()
            .expect("doctor");
        assert!(!String::from_utf8_lossy(&out.stdout).contains(&token));
        assert!(!String::from_utf8_lossy(&out.stderr).contains(&token));
        let report: serde_json::Value = serde_json::from_slice(&out.stdout).expect("doctor JSON");
        let row = report["checks"]
            .as_array()
            .expect("checks")
            .iter()
            .find(|row| row["label"] == "admin-token")
            .expect("admin-token custody line");
        let shown = secret_slot(&slot);
        let expected = if shown == "<set>" {
            "legacy literal in config"
        } else {
            &shown
        };
        assert!(row["detail"].as_str().expect("detail").contains(expected));
        if slot.ends_with("missing-token") {
            assert!(
                !out.status.success(),
                "unresolved config must fail after custody is shown"
            );
        }
    }
}
