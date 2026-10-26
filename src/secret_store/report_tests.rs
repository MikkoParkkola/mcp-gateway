// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The doctor report: read-only, names no entry and carries no value.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::super::tests::Fake;
use super::super::{FilesStore, NewSecret, SecretStore, StoreError, Vault, save_secrets};
use super::{named, report_with};
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
            let yaml = format!("auth:\n  bearer_token: \"{}\"\n", refs[0]);
            std::fs::write(&path, yaml)
        })
        .expect("saved");
    }
    (config, locks, path)
}

fn vault_for(config: &Path, locks: &Path) -> Result<Vault, StoreError> {
    Ok(Vault::with_lock(config, locks.join("vault.lock")))
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
        let report = report_with(&path, choice, vault_for(config.path(), locks.path()), store);
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
        vault_for(config.path(), locks.path()),
        Some(os(Err(StoreError::Unavailable("no session bus".into())))),
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
        vault_for(config.path(), locks.path()),
        Some(os(Err(StoreError::Unavailable("locked".into())))),
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
