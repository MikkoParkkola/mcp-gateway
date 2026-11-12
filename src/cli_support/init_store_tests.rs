// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Init store selection and token custody without a native keychain.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use super::init::write_init_files_with;
use crate::config::Config;
use crate::secret_store::{SecretStore, StoreError, StoreKind};

const AUTO: &str = "auth:\n  bearer_token: \"\"\n";
const KEYCHAIN: &str = "auth:\n  bearer_token: \"\"\nsecrets:\n  store: keychain\n";
const FILES: &str = "auth:\n  bearer_token: \"\"\nsecrets:\n  store: files\n";

enum WriteBehavior {
    Healthy,
    Denied,
    TimedOut,
}

#[derive(Default)]
struct State {
    writes: usize,
    entries: BTreeMap<String, Vec<u8>>,
}

struct Fake {
    probe: Result<(), StoreError>,
    write: WriteBehavior,
    state: Mutex<State>,
}

impl Fake {
    fn new(write: WriteBehavior) -> Self {
        Self {
            probe: Ok(()),
            write,
            state: Mutex::default(),
        }
    }
}

impl SecretStore for Fake {
    fn kind(&self) -> StoreKind {
        StoreKind::Keychain
    }

    fn limit(&self) -> usize {
        65_535
    }

    fn probe(&self) -> Result<(), StoreError> {
        self.probe.clone()
    }

    fn exists(&self, name: &str) -> Result<bool, StoreError> {
        Ok(self.state.lock().unwrap().entries.contains_key(name))
    }

    fn create(&self, name: &str, value: &[u8]) -> Result<String, StoreError> {
        let mut state = self.state.lock().unwrap();
        state.writes += 1;
        if state.entries.contains_key(name) {
            return Err(StoreError::Exists);
        }
        match self.write {
            WriteBehavior::Denied => Err(StoreError::Failed("denied".to_owned())),
            WriteBehavior::Healthy | WriteBehavior::TimedOut => {
                state.entries.insert(name.to_owned(), value.to_vec());
                if matches!(self.write, WriteBehavior::TimedOut) {
                    // A timed-out native call can land despite its caller's error.
                    Err(StoreError::TimedOut)
                } else {
                    Ok(format!("keychain:{name}"))
                }
            }
        }
    }

    fn delete(&self, name: &str) -> Result<(), StoreError> {
        self.state.lock().unwrap().entries.remove(name);
        Ok(())
    }
}

/// Read custody literally so loading the config cannot resolve a keychain.
fn file_token(destination: &Path, returned: &str) -> String {
    let config = Config::load_literal(Some(destination)).expect("literal init config");
    let reference = config.auth.bearer_token.expect("admin reference");
    assert_eq!(
        reference, returned,
        "the returned reference must be published"
    );
    let path = Path::new(reference.strip_prefix("file:").expect("file custody"));
    let dir = destination.parent().expect("config directory");
    let secrets = std::fs::canonicalize(dir.join("secrets")).expect("secrets directory");
    assert_eq!(path.parent(), Some(secrets.as_path()));
    let entries: Vec<_> = std::fs::read_dir(&secrets)
        .expect("file entries")
        .map(|entry| entry.expect("file entry").path())
        .collect();
    assert_eq!(entries, vec![path.to_path_buf()], "one live file token");
    let token = std::fs::read_to_string(path)
        .expect("stored token")
        .trim_end_matches('\n')
        .to_owned();
    assert!(token.starts_with("mcpgw_") && token.len() > "mcpgw_".len());
    assert!(
        !returned.contains(&token),
        "the return must not disclose the token"
    );
    let text = std::fs::read_to_string(destination).expect("published config");
    assert!(
        !text.contains(&token),
        "the config must not hold the token text"
    );
    assert!(
        !text.contains("keychain:"),
        "the config must name only the file"
    );
    token
}

#[test]
fn auto_falls_back_to_files_when_the_keychain_write_fails() {
    let root = tempfile::tempdir().expect("tempdir");
    let destination = root.path().join("gateway.yaml");
    let os = Arc::new(Fake::new(WriteBehavior::Denied));
    let result = write_init_files_with(Some(os.clone()), None, &destination, AUTO, &[]);
    assert!(
        result.is_ok(),
        "auto must recover from a denied keychain write: {result:?}"
    );
    file_token(&destination, &result.unwrap());
    let state = os.state.lock().unwrap();
    assert_eq!(
        state.writes, 1,
        "the keychain write must have been attempted"
    );
    assert!(state.entries.is_empty());
}

#[test]
fn a_timed_out_keychain_write_never_leaves_the_live_token_there() {
    let root = tempfile::tempdir().expect("tempdir");
    let destination = root.path().join("gateway.yaml");
    let os = Arc::new(Fake::new(WriteBehavior::TimedOut));
    let result = write_init_files_with(Some(os.clone()), None, &destination, AUTO, &[]);
    assert!(
        result.is_ok(),
        "auto must recover from an ambiguous keychain write: {result:?}"
    );
    let token = file_token(&destination, &result.unwrap());
    let state = os.state.lock().unwrap();
    assert_eq!(state.writes, 1);
    assert_eq!(
        state.entries.len(),
        1,
        "the abandoned write may remain in the keychain"
    );
    let abandoned = state.entries.values().next().expect("landed write");
    assert!(
        token.as_bytes() != abandoned.as_slice(),
        "the live file token must be freshly minted after a timeout"
    );
}

fn assert_explicit_keychain_refused(template: &str, env_store: Option<&OsStr>) {
    let root = tempfile::tempdir().expect("tempdir");
    let destination = root.path().join("gateway.yaml");
    let sample = root.path().join("capabilities/sample.yaml");
    let os = Arc::new(Fake::new(WriteBehavior::Denied));
    let result = write_init_files_with(
        Some(os.clone()),
        env_store,
        &destination,
        template,
        &[(sample.clone(), "sample")],
    );
    assert!(
        result.is_err(),
        "explicit keychain must refuse a denied write"
    );
    assert!(!destination.exists(), "no config may be published");
    assert!(!sample.exists(), "no sample may be published");
    assert!(
        !root.path().join("secrets").exists(),
        "no file fallback may be created"
    );
    let state = os.state.lock().unwrap();
    assert_eq!(
        state.writes, 1,
        "refusal must follow the requested keychain write"
    );
    assert!(state.entries.is_empty());
}

#[test]
fn explicit_keychain_still_refuses_after_a_failed_write() {
    // An ignored override would succeed with files, exposing the missing precedence.
    assert_explicit_keychain_refused(FILES, Some(OsStr::new("keychain")));
}

#[test]
fn explicit_keychain_from_the_template_still_refuses_after_a_failed_write() {
    assert_explicit_keychain_refused(KEYCHAIN, None);
}

#[test]
fn auto_with_a_failing_probe_is_unchanged() {
    let root = tempfile::tempdir().expect("tempdir");
    let destination = root.path().join("gateway.yaml");
    let mut fake = Fake::new(WriteBehavior::Healthy);
    fake.probe = Err(StoreError::Unavailable("locked".to_owned()));
    let os = Arc::new(fake);
    let reference = write_init_files_with(Some(os.clone()), None, &destination, AUTO, &[])
        .expect("a failed auto probe still chooses files");
    file_token(&destination, &reference);
    let state = os.state.lock().unwrap();
    assert_eq!(state.writes, 0);
    assert!(state.entries.is_empty());
}

#[test]
fn the_env_override_beats_the_template() {
    let root = tempfile::tempdir().expect("tempdir");
    let destination = root.path().join("gateway.yaml");
    let os = Arc::new(Fake::new(WriteBehavior::Healthy));
    let reference = write_init_files_with(
        Some(os.clone()),
        Some(OsStr::new("files")),
        &destination,
        KEYCHAIN,
        &[],
    )
    .expect("the files override must succeed");
    let state = os.state.lock().unwrap();
    assert_eq!(
        state.writes, 0,
        "files must override the template's keychain selection"
    );
    assert!(state.entries.is_empty());
    file_token(&destination, &reference);
}

fn assert_invalid_override_refused(env_store: &OsStr) {
    let root = tempfile::tempdir().expect("tempdir");
    let dir = root.path().join("absent");
    let destination = dir.join("gateway.yaml");
    let os = Arc::new(Fake::new(WriteBehavior::Healthy));
    let result = write_init_files_with(Some(os.clone()), Some(env_store), &destination, AUTO, &[]);
    assert!(result.is_err(), "invalid store overrides must be refused");
    let error = result.unwrap_err();
    assert!(error.contains("MCP_GATEWAY_SECRETS__STORE"), "{error}");
    assert!(!dir.exists(), "validation must precede directory creation");
    assert!(!crate::config_persistence::lock::lock_path(&destination).exists());
    assert_eq!(
        std::fs::read_dir(root.path())
            .expect("untouched root")
            .count(),
        0
    );
    let state = os.state.lock().unwrap();
    assert_eq!(state.writes, 0);
    assert!(state.entries.is_empty());
}

#[test]
fn an_invalid_env_override_is_refused_before_anything_is_created() {
    assert_invalid_override_refused(OsStr::new("tape"));
}

#[cfg(unix)]
#[test]
fn a_non_utf8_env_override_is_refused_before_anything_is_created() {
    use std::os::unix::ffi::OsStrExt;

    assert_invalid_override_refused(OsStr::from_bytes(b"\xff"));
}

#[test]
fn an_empty_env_override_is_unset() {
    let root = tempfile::tempdir().expect("tempdir");
    let destination = root.path().join("gateway.yaml");
    let os = Arc::new(Fake::new(WriteBehavior::Healthy));
    let reference = write_init_files_with(
        Some(os.clone()),
        Some(OsStr::new("")),
        &destination,
        AUTO,
        &[],
    )
    .expect("an empty override leaves auto selection intact");
    assert!(reference.starts_with("keychain:"));
    let config = Config::load_literal(Some(&destination)).expect("literal init config");
    assert_eq!(
        config.auth.bearer_token.as_deref(),
        Some(reference.as_str())
    );
    assert!(!root.path().join("secrets").exists());
    let state = os.state.lock().unwrap();
    assert_eq!(state.writes, 1);
    assert_eq!(state.entries.len(), 1);
}
