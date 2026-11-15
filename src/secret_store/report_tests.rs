// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The doctor report: read-only, names no entry and carries no value.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::super::tests::Fake;
use super::super::{FilesStore, NewSecret, SecretStore, StoreError, Vault, save_secrets};
use super::report_with;
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
            &[],
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
        &[],
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
        &[],
    );
    assert_eq!(report.chosen, None, "{report:?}");
    assert!(report.reason.contains("saves are refused"), "{report:?}");
    assert!(!report.fell_back);
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
        &[],
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
        &[],
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
        &[],
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
        &[],
    );
    assert_eq!(report.unused, None, "{report:?}");
    // A fixed sentence: a loader error can quote config text holding a secret.
    assert_eq!(
        report.unused_error.as_deref(),
        Some("gateway.yaml did not load, so references were not read")
    );
}

/// [`saved`], plus the name of its first entry, which `gateway.yaml` does not
/// name: the one entry each row below names through a single other source.
fn saved_unused() -> (tempfile::TempDir, tempfile::TempDir, PathBuf, String) {
    let (config, locks, path) = saved();
    assert_eq!(
        count(config.path(), locks.path(), &path, &[]),
        Some(1),
        "premise: exactly one entry is unused before any other source names it"
    );
    let live = std::fs::read_to_string(&path).expect("read");
    let entries = FilesStore::new(config.path()).entries_dir().to_path_buf();
    let name = std::fs::read_dir(&entries)
        .expect("entries dir")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .into_string()
                .expect("utf8")
        })
        .find(|name| name.starts_with("mcp-gateway.") && !live.contains(name.as_str()))
        .expect("the unused entry");
    (config, locks, path, name)
}

/// The doctor count over the files store, with `process_env` as the environment.
fn count(
    config: &Path,
    locks: &Path,
    path: &Path,
    process_env: &[std::ffi::OsString],
) -> Option<usize> {
    report_with(
        path,
        SecretStoreChoice::Files,
        Ok(vault_for(config, locks)),
        None,
        process_env,
    )
    .unused
}

/// `path` written as a double-quoted YAML string (a Windows path's backslashes escaped).
fn yaml_path(path: &Path) -> String {
    format!("\"{}\"", path.display().to_string().replace('\\', "\\\\"))
}

/// Prepends `head` to `gateway.yaml`, keeping its owner-only mode.
fn prepend(path: &Path, head: &str) {
    let text = std::fs::read_to_string(path).expect("read");
    std::fs::write(path, format!("{head}{text}")).expect("write");
    owner_only(path);
}

#[test]
fn an_entry_named_only_by_an_env_file_is_not_unused() {
    let (config, locks, path, name) = saved_unused();
    let env = config.path().join("names.env");
    std::fs::write(&env, format!("SPARE_TOKEN=keychain:{name}\n")).expect("env file");
    owner_only(&env);
    prepend(&path, &format!("env_files:\n  - {}\n", yaml_path(&env)));
    assert_eq!(
        count(config.path(), locks.path(), &path, &[]),
        Some(0),
        "env file names {name}"
    );
}

#[test]
fn an_entry_named_only_by_a_process_environment_value_is_not_unused() {
    let (config, locks, path, name) = saved_unused();
    let env = [std::ffi::OsString::from(format!("keychain:{name}"))];
    assert_eq!(
        count(config.path(), locks.path(), &path, &env),
        Some(0),
        "process env names {name}"
    );
}

#[test]
fn an_entry_named_only_by_a_capability_file_is_not_unused() {
    let (config, locks, path, name) = saved_unused();
    let caps = config.path().join("caps");
    std::fs::create_dir(&caps).expect("caps dir");
    std::fs::write(
        caps.join("tool.yaml"),
        format!("name: tool\ndescription: keychain:{name}\n"),
    )
    .expect("capability file");
    prepend(
        &path,
        &format!(
            "capabilities:\n  directories:\n    - {}\n",
            yaml_path(&caps)
        ),
    );
    assert_eq!(
        count(config.path(), locks.path(), &path, &[]),
        Some(0),
        "capability file names {name}"
    );
}

#[test]
fn an_entry_named_only_through_a_file_link_is_not_unused() {
    let (config, locks, path, name) = saved_unused();
    let entry = FilesStore::new(config.path()).entries_dir().join(&name);
    let alias = config.path().join("alias");
    std::fs::hard_link(&entry, &alias).expect("hard link to the entry");
    let env = config.path().join("link.env");
    std::fs::write(&env, format!("SPARE_FILE=file:{}\n", alias.display())).expect("env file");
    owner_only(&env);
    prepend(&path, &format!("env_files:\n  - {}\n", yaml_path(&env)));
    assert!(
        !std::fs::read_to_string(&env).expect("read").contains(&name),
        "premise: the env file names the entry only through the link"
    );
    assert_eq!(
        count(config.path(), locks.path(), &path, &[]),
        Some(0),
        "file: link names {name}"
    );
}

#[test]
fn naming_sources_that_cannot_be_read_leave_the_count_out_never_zero() {
    let (config, locks, path, _) = saved_unused();
    // One level past the scan's depth bound: the config loads, the corpus refuses.
    let mut deep = config.path().join("caps");
    for level in 0..=16 {
        deep.push(format!("d{level}"));
    }
    std::fs::create_dir_all(&deep).expect("deep capability tree");
    std::fs::write(deep.join("tool.yaml"), "name: tool\n").expect("capability file");
    prepend(
        &path,
        &format!(
            "capabilities:\n  directories:\n    - {}\n",
            yaml_path(&config.path().join("caps"))
        ),
    );
    let report = report_with(
        &path,
        SecretStoreChoice::Files,
        Ok(vault_for(config.path(), locks.path())),
        None,
        &[],
    );
    assert_eq!(report.unused, None, "{report:?}");
    assert_eq!(
        report.unused_error.as_deref(),
        Some("a capability directory is nested deeper than the scan reads")
    );
}
