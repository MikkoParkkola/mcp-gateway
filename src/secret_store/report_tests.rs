// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The doctor report: read-only, names no entry and carries no value.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::super::tests::Fake;
use super::super::{FilesStore, NewSecret, SecretStore, StoreError, Vault, save_secrets};
use super::{named, named_in_yaml, report_with};
use crate::config::SecretStoreChoice;

const SENTINEL: &[u8] = b"kc-sentinel-7f3a";

/// Every file under `dir`, with its bytes.
fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        for entry in std::fs::read_dir(&next).expect("read dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                files.insert(path.clone(), Vec::new());
                pending.push(path);
            } else {
                files.insert(path.clone(), std::fs::read(&path).expect("read"));
            }
        }
    }
    files
}

/// A config dir with two saved file entries, the second named by
/// `gateway.yaml`, and a vault whose lock lives elsewhere.
fn saved() -> (tempfile::TempDir, tempfile::TempDir, PathBuf) {
    let config = tempfile::tempdir().expect("tempdir");
    let locks = tempfile::tempdir().expect("tempdir");
    let vault = Vault::with_lock(config.path(), locks.path().join("vault.lock"));
    let files = FilesStore::new(config.path());
    let path = config.path().join("gateway.yaml");
    for value in [&b"old"[..], SENTINEL] {
        let secret = [NewSecret {
            field: "auth.bearer_token",
            value,
        }];
        save_secrets(&vault, &files, &secret, |refs| {
            // Double-quoted YAML: a Windows path's backslashes are escaped.
            let quoted = refs[0].replace('\\', "\\\\");
            let yaml = format!("auth:\n  bearer_token: \"{quoted}\"\n");
            std::fs::write(&path, yaml)
        })
        .expect("saved");
    }
    owner_only(&path);
    (config, locks, path)
}

/// The mode the loader's checked read accepts for `gateway.yaml`.
fn owner_only(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }
    #[cfg(windows)]
    crate::private_fs::test_support::plant_owner_only("doctor-report", path);
}

fn vault_for(config: &Path, locks: &Path) -> Vault {
    Vault::with_lock(config, locks.join("vault.lock"))
}

fn os(probe: Result<(), StoreError>) -> Arc<dyn SecretStore + Send + Sync> {
    let mut fake = Fake::new();
    fake.probe = probe;
    Arc::new(fake)
}

#[test]
fn the_report_writes_nothing_and_counts_the_entry_no_config_names() {
    let (config, locks, path) = saved();
    let before = snapshot(config.path());
    for (choice, store) in [
        (SecretStoreChoice::Files, None),
        (SecretStoreChoice::Auto, Some(os(Ok(())))),
        (
            SecretStoreChoice::Keychain,
            Some(os(Err(StoreError::Unavailable("locked".into())))),
        ),
    ] {
        let report = report_with(
            &path,
            choice,
            Ok(vault_for(config.path(), locks.path())),
            store.as_ref(),
        );
        assert_eq!(report.unused, Some(1), "{report:?}");
        assert_eq!(
            snapshot(config.path()),
            before,
            "{choice:?} wrote to the config dir"
        );
    }
}

#[test]
fn the_report_names_no_entry_and_carries_no_value() {
    let (config, locks, path) = saved();
    let report = report_with(
        &path,
        SecretStoreChoice::Auto,
        Ok(vault_for(config.path(), locks.path())),
        Some(&os(Err(StoreError::Unavailable("no session bus".into())))),
    );
    assert!(report.fell_back);
    assert_eq!(report.chosen, Some("files"));
    assert!(report.reason.contains("no session bus"), "{report:?}");
    for shown in [
        format!("{report:?}"),
        serde_json::to_string(&report).expect("json"),
    ] {
        assert!(!shown.contains("mcp-gateway."), "an entry name: {shown}");
        assert!(!shown.contains("kc-sentinel-7f3a"), "a value: {shown}");
        assert!(
            !shown.contains("secrets/"),
            "a path under secrets/: {shown}"
        );
    }
}

#[test]
fn explicit_keychain_with_a_failing_probe_reports_that_saves_are_refused() {
    let (config, locks, path) = saved();
    let report = report_with(
        &path,
        SecretStoreChoice::Keychain,
        Ok(vault_for(config.path(), locks.path())),
        Some(&os(Err(StoreError::Unavailable("locked".into())))),
    );
    assert_eq!(report.chosen, None, "{report:?}");
    assert!(report.reason.contains("saves are refused"), "{report:?}");
    assert!(!report.fell_back);
}

#[test]
fn a_config_names_entries_by_keychain_reference_and_by_file_path() {
    let text = "a: keychain:mcp-gateway.auth-bearer-token.1.00ff\n\
                b: \"file:secrets/mcp-gateway.key-server.2.abcd\"\n\
                c: mcp-gateway.\n";
    let names = named(text);
    assert!(
        names.contains("mcp-gateway.auth-bearer-token.1.00ff"),
        "{names:?}"
    );
    assert!(names.contains("mcp-gateway.key-server.2.abcd"), "{names:?}");
}

#[test]
fn a_reference_hidden_by_a_yaml_escape_is_still_named() {
    let text = "auth:\n  bearer_token: \"keychain:mcp-gateway\\u002eauth-bearer-token.1.00ff\"\n";
    let names = named_in_yaml(text).expect("parses");
    assert!(
        names.contains("mcp-gateway.auth-bearer-token.1.00ff"),
        "{names:?}"
    );
    assert!(named_in_yaml("a: [unclosed").is_err());
}

#[test]
fn with_no_vault_lock_yet_the_count_is_zero_and_no_lock_is_made() {
    let config = tempfile::tempdir().expect("tempdir");
    let locks = tempfile::tempdir().expect("tempdir");
    let path = config.path().join("gateway.yaml");
    std::fs::write(&path, "{}\n").expect("write");
    owner_only(&path);
    let report = report_with(
        &path,
        SecretStoreChoice::Files,
        Ok(vault_for(config.path(), locks.path())),
        None,
    );
    assert_eq!(report.unused, Some(0), "{report:?}");
    assert!(
        !locks.path().join("vault.lock").exists(),
        "the report made the vault lock"
    );
}

#[test]
fn an_index_without_a_vault_lock_is_not_counted_as_zero() {
    let (config, locks, path) = saved();
    std::fs::remove_file(locks.path().join("vault.lock")).expect("drop the lock");
    let report = report_with(
        &path,
        SecretStoreChoice::Files,
        Ok(vault_for(config.path(), locks.path())),
        None,
    );
    assert_eq!(report.unused, None, "{report:?}");
    assert!(
        !locks.path().join("vault.lock").exists(),
        "the report made the vault lock"
    );
}

#[test]
fn an_escaped_reference_and_a_broken_config_go_through_the_whole_report() {
    let (config, locks, path) = saved();
    let text = std::fs::read_to_string(&path).expect("read");
    // The live reference, with its dots written as YAML escapes.
    std::fs::write(&path, text.replace("mcp-gateway.", "mcp-gateway\\u002e")).expect("write");
    owner_only(&path);
    let report = report_with(
        &path,
        SecretStoreChoice::Files,
        Ok(vault_for(config.path(), locks.path())),
        None,
    );
    assert_eq!(
        report.unused,
        Some(1),
        "the escaped live entry counted as unused: {report:?}"
    );
    std::fs::write(&path, "auth: [unclosed\n").expect("write");
    owner_only(&path);
    let report = report_with(
        &path,
        SecretStoreChoice::Files,
        Ok(vault_for(config.path(), locks.path())),
        None,
    );
    assert_eq!(report.unused, None, "{report:?}");
}
