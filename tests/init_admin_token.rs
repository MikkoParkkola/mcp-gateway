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

/// ADMINTOK.2 / A4: doctor uses `secret_slot`'s reference/<set> semantics,
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

fn failure_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("isolated failure");
    std::fs::create_dir(root.path().join("home")).expect("home");
    root
}

fn failed_init(root: &Path, path: &Path, examples: bool) -> std::process::Output {
    let out = command(root)
        .args(["--log-level", "off", "init", "--output"])
        .arg(path)
        .arg(if examples {
            "--with-examples=true"
        } else {
            "--with-examples=false"
        })
        .output()
        .expect("real init failure");
    assert!(!out.status.success(), "init must refuse this attempt");
    out
}

// Include locks, index, staging, home/state, and non-YAML files; never follow links.
fn output_files(root: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    use std::os::unix::ffi::OsStrExt as _;
    let mut files = std::collections::BTreeMap::new();
    let mut dirs = vec![root.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(dir).expect("output directory") {
            let entry = entry.expect("output entry");
            let path = entry.path();
            let kind = entry.file_type().expect("output type");
            if kind.is_dir() {
                dirs.push(path);
            } else {
                let bytes = if kind.is_symlink() {
                    std::fs::read_link(&path)
                        .expect("link target")
                        .as_os_str()
                        .as_bytes()
                        .to_vec()
                } else {
                    assert!(kind.is_file(), "unexpected special output");
                    std::fs::read(&path).expect("output bytes")
                };
                files.insert(path, bytes);
            }
        }
    }
    files
}

fn no_token_leaks(root: &Path, out: &std::process::Output, store_entry: Option<&Path>) {
    // The generated value is unavailable after rollback; its fixed prefix lets
    // us reject any generated token, including one from a failed second attempt.
    let has_token = |bytes: &[u8]| bytes.windows(6).any(|part| part == b"mcpgw_");
    assert!(!has_token(&out.stdout), "token in stdout");
    assert!(!has_token(&out.stderr), "token in stderr");
    for (path, bytes) in output_files(root) {
        if Some(path.as_path()) != store_entry {
            assert!(!has_token(&bytes), "token outside its store entry");
        }
    }
}

fn one_attempt_removed(dir: &Path) {
    let index = std::fs::read_to_string(dir.join("secrets-index.jsonl")).expect("attempt index");
    let rows: Vec<serde_json::Value> = index
        .lines()
        .map(|line| serde_json::from_str(line).expect("index row"))
        .collect();
    assert_eq!(rows.len(), 2, "one indexed attempt and its removal");
    assert_eq!(rows[0]["store"], "files");
    assert!(rows[0]["created_at"].is_number());
    assert_eq!(rows[0]["name"], rows[1]["name"]);
    assert!(rows[1]["removed_at"].is_number());
    assert!(
        std::fs::read_dir(dir.join("secrets"))
            .expect("store")
            .next()
            .is_none()
    );
}

/// R1 / lead ruling: rerun preserves the config, samples, index and sole entry.
#[test]
fn admintok_1_existing_config_refusal_preserves_all_files_and_store_bytes() {
    let (root, path, written, _) = initialized();
    let entry = Path::new(written.strip_prefix("file:").expect("stored reference"));
    assert_eq!(
        std::fs::read_dir(root.path().join("secrets"))
            .expect("store")
            .count(),
        1
    );
    let before = output_files(root.path());
    let out = failed_init(root.path(), &path, true);
    let expected = format!(
        "Error: {} already exists. Remove it first or choose a different path with --output.\n",
        path.display()
    );
    assert!(
        out.stderr == expected.as_bytes(),
        "whole existing-config refusal message"
    );
    // Do not print the snapshot on failure: it contains the stored credential.
    assert!(
        before == output_files(root.path()),
        "rerun changed existing files or added an entry"
    );
    no_token_leaks(root.path(), &out, Some(entry));
}

/// R2 / A6: a pre-existing dangling link passes absence checks, but `create_new`
/// refuses it after the first sample and entry exist. This is not the R4 race.
#[test]
fn admintok_1_sample_create_failure_removes_owned_files_and_entry_preserving_competitors() {
    let root = failure_root();
    let samples = root.path().join("capabilities/knowledge");
    std::fs::create_dir_all(&samples).expect("samples directory");
    let blocked = samples.join("public_holidays.yaml");
    let target = root.path().join("missing-competitor-target");
    std::os::unix::fs::symlink(&target, &blocked).expect("competing dangling link");
    let collision = std::fs::File::create_new(&blocked).expect_err("sample must refuse link");
    let competitor = samples.join("keep.txt");
    std::fs::write(&competitor, b"competing bytes").expect("competitor");
    let path = root.path().join("gateway.yaml");
    let out = failed_init(root.path(), &path, true);
    let error = format!("Error: {}: {collision}", blocked.display());
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .lines()
            .any(|line| line == error)
    );
    assert!(!path.try_exists().expect("config absence"));
    assert_eq!(
        std::fs::symlink_metadata(samples.join("weather_current.yaml"))
            .expect_err("owned sample removed")
            .kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(
        std::fs::read_link(&blocked).expect("competitor remains"),
        target
    );
    assert!(!target.try_exists().expect("no link traversal"));
    assert_eq!(
        std::fs::read(competitor).expect("competitor bytes"),
        b"competing bytes"
    );
    one_attempt_removed(root.path());
    no_token_leaks(root.path(), &out, None);
}

/// R3 / A6: probe succeeds, then `FilesStore::create` cannot encode its reference.
/// Unlike chmod, this is deterministic even as root (probe resets mode to 0700).
#[test]
fn admintok_1_chosen_store_create_failure_leaves_no_config_samples_or_literal_fallback() {
    use std::os::unix::ffi::OsStringExt as _;
    let root = failure_root();
    let dir = root
        .path()
        .join(std::ffi::OsString::from_vec(b"config-\xff".to_vec()));
    std::fs::create_dir(&dir).expect("non-UTF-8 config directory");
    let path = dir.join("gateway.yaml");
    let out = failed_init(root.path(), &path, true);
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .lines()
            .any(|line| line == STORE_FAILURE)
    );
    assert!(!path.try_exists().expect("config absence"));
    assert!(!dir.join("capabilities").try_exists().expect("no samples"));
    one_attempt_removed(&dir);
    no_token_leaks(root.path(), &out, None);
}

const STORE_FAILURE: &str = "Error: init store failed; inspect unused entries with doctor \
                            and remove any orphan before retrying";

/// R5 / A2: a handled store-probe failure prints the helper's entire message.
#[test]
fn admintok_1_handled_failure_reports_whole_helper_message_without_write_wrapper_or_token() {
    let root = failure_root();
    let store = root.path().join("secrets");
    std::fs::write(&store, b"competing store-path file").expect("blocked store directory");
    let path = root.path().join("gateway.yaml");
    let out = failed_init(root.path(), &path, false);
    assert!(
        out.stderr == format!("{STORE_FAILURE}\n").as_bytes(),
        "whole helper message"
    );
    assert!(!String::from_utf8_lossy(&out.stderr).contains("Failed to write"));
    assert!(!path.try_exists().expect("config absence"));
    assert!(
        !root
            .path()
            .join("capabilities")
            .try_exists()
            .expect("no samples")
    );
    assert!(
        !root
            .path()
            .join("secrets-index.jsonl")
            .try_exists()
            .expect("no entry indexed")
    );
    assert_eq!(
        std::fs::read(store).expect("store-path competitor"),
        b"competing store-path file"
    );
    no_token_leaks(root.path(), &out, None);
}
