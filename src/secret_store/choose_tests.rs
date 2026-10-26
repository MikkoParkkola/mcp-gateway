// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which store a save writes to (ADR-028 rule 7), over a fake OS keychain,
//! and the log line that keeps a fallback to files visible.

use std::sync::Arc;

use super::tests::{Fake, three, vault};
use super::{SaveError, SecretStore, StoreError, StoreKind, choose_with, log_choice, save_secrets};
use crate::config::SecretStoreChoice;

fn os(probe: Result<(), StoreError>) -> Arc<dyn SecretStore + Send + Sync> {
    let mut fake = Fake::new();
    fake.probe = probe;
    Arc::new(fake)
}

fn no_bus() -> Result<(), StoreError> {
    Err(StoreError::Unavailable(
        "no Secret Service on the session bus".to_owned(),
    ))
}

#[test]
fn auto_takes_the_keychain_when_its_probe_passes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let chosen =
        choose_with(SecretStoreChoice::Auto, dir.path(), Some(os(Ok(())))).expect("chosen");
    assert_eq!(chosen.store.kind(), StoreKind::Keychain);
    assert!(!chosen.fell_back);
    assert!(chosen.reason.contains("probe passed"), "{}", chosen.reason);
}

#[test]
fn auto_falls_back_to_files_naming_the_probe_reason() {
    let dir = tempfile::tempdir().expect("tempdir");
    let chosen =
        choose_with(SecretStoreChoice::Auto, dir.path(), Some(os(no_bus()))).expect("chosen");
    assert_eq!(chosen.store.kind(), StoreKind::Files);
    assert!(chosen.fell_back);
    assert!(
        chosen.reason.contains("no Secret Service"),
        "{}",
        chosen.reason
    );

    let none = choose_with(SecretStoreChoice::Auto, dir.path(), None).expect("chosen");
    assert_eq!(none.store.kind(), StoreKind::Files);
    assert!(none.fell_back);
}

#[test]
fn explicit_keychain_is_never_switched_and_a_failing_probe_refuses_the_save() {
    let dir = tempfile::tempdir().expect("tempdir");
    let refused = choose_with(SecretStoreChoice::Keychain, dir.path(), None)
        .err()
        .expect("no keychain on this target");
    assert!(
        refused.reason().contains("secrets.store: files"),
        "{refused}"
    );

    let chosen =
        choose_with(SecretStoreChoice::Keychain, dir.path(), Some(os(no_bus()))).expect("chosen");
    assert_eq!(chosen.store.kind(), StoreKind::Keychain);
    let (_dir, vault) = vault();
    let result = save_secrets(&vault, chosen.store.as_ref(), &three(), |_| Ok::<_, ()>(()));
    let Err(SaveError::Refused(error)) = result else {
        panic!("{result:?}");
    };
    assert!(error.reason().contains("secrets.store: files"), "{error}");
}

#[test]
fn auto_passing_at_choice_then_failing_at_save_refuses_before_any_write() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut fake = Fake::new();
    fake.probe = Ok(());
    let fake = Arc::new(fake);
    let chosen = choose_with(
        SecretStoreChoice::Auto,
        dir.path(),
        Some(fake.clone() as Arc<dyn SecretStore + Send + Sync>),
    )
    .expect("chosen");
    assert_eq!(chosen.store.kind(), StoreKind::Keychain);
    // The keychain goes away between the choice and the save.
    let mut gone = Fake::new();
    gone.probe = no_bus();
    let (vault_dir, vault) = vault();
    let result = save_secrets(&vault, &gone, &three(), |_| Ok::<_, ()>(()));
    assert!(matches!(result, Err(SaveError::Refused(_))), "{result:?}");
    assert_eq!(gone.calls(), vec!["probe"]);
    assert!(super::tests::index_text(vault_dir.path()).is_empty());
}

#[test]
fn files_is_files_and_the_choice_is_logged_once_at_its_level() {
    let dir = tempfile::tempdir().expect("tempdir");
    let files =
        choose_with(SecretStoreChoice::Files, dir.path(), Some(os(Ok(())))).expect("chosen");
    assert_eq!(files.store.kind(), StoreKind::Files);
    assert!(!files.fell_back);

    let fallback =
        choose_with(SecretStoreChoice::Auto, dir.path(), Some(os(no_bus()))).expect("chosen");
    let records =
        crate::test_log_capture::records(|| log_choice(SecretStoreChoice::Auto, &fallback));
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["level"], "WARN", "{records:?}");
    assert_eq!(records[0]["fields"]["setting"], "auto");
    assert_eq!(records[0]["fields"]["store"], "files");
    assert!(
        records[0]["fields"]["reason"]
            .as_str()
            .is_some_and(|r| r.contains("no Secret Service")),
        "{records:?}"
    );

    let passed =
        choose_with(SecretStoreChoice::Auto, dir.path(), Some(os(Ok(())))).expect("chosen");
    let records = crate::test_log_capture::records(|| log_choice(SecretStoreChoice::Auto, &passed));
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["level"], "INFO", "{records:?}");
    assert_eq!(records[0]["fields"]["store"], "keychain");
}

#[test]
fn files_needs_no_keychain_on_any_target() {
    let dir = tempfile::tempdir().expect("tempdir");
    let chosen = super::choose_store(SecretStoreChoice::Files, dir.path()).expect("files");
    assert_eq!(chosen.store.kind(), StoreKind::Files);
}
