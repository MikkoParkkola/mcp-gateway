// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A journal recovery that cannot act names a state-neutral manual step, and
//! leaves gateway.yaml and the journal as the crash left them.

use super::*;

/// The manual step a journal recovery cannot act on names: state-neutral,
/// because the journal's state may be unknown, it may name another file, or
/// the staged original may be wrong. Never "copy the original over".
fn manual_step(path: &Path) -> String {
    use crate::config_persistence::journal;
    let target = crate::identity_grants::journal::resolved(path);
    format!(
        "nothing was changed; inspect the journal {} before touching {}: if its state is staged, restore the staged original {} over {} only if its SHA-256 matches the journal's original_revision, then delete the journal; if its state is all_renamed, only delete the journal",
        journal::journal_path(path).display(),
        target.display(),
        journal::original_path(path).display(),
        target.display(),
    )
}

/// The lock refused with the state-neutral manual step; gateway.yaml and the
/// journal are as the crash left them.
async fn assert_refused_by_hand(path: &Path) {
    match lock_now(path).await {
        Err(crate::config_persistence::lock::NotLocked::Failed(message)) => {
            assert!(message.ends_with(&manual_step(path)), "{message}");
            assert!(!message.contains("copy the staged original"), "{message}");
        }
        Err(other) => panic!("expected a refusal, got {other:?}"),
        Ok(_) => panic!("an unusable journal must refuse the lock"),
    }
    assert_eq!(read(path), NEXT, "gateway.yaml changed");
    assert!(crate::config_persistence::journal::exists(path));
}

/// T9: a `staged` journal whose original is gone cannot be acted on: the
/// lock is refused with the manual step, and no file changes.
#[tokio::test]
async fn a_journal_without_its_original_refuses_the_lock() {
    let (_dir, path, _ctx) = setup();
    crashed_after_rename(&path, NEXT);
    std::fs::remove_file(crate::config_persistence::journal::original_path(&path)).expect("rm");

    assert_refused_by_hand(&path).await;
}

/// A journal that cannot be read may be `all_renamed`: the manual step must
/// not tell the operator to put the original back.
#[tokio::test]
async fn an_unreadable_journal_refuses_the_lock_with_a_neutral_step() {
    let (_dir, path, _ctx) = setup();
    crashed_after_rename(&path, NEXT);
    write_owner_only(
        crate::config_persistence::journal::journal_path(&path),
        "{not a journal",
    )
    .expect("corrupt the journal");

    assert_refused_by_hand(&path).await;
}

/// A journal naming another file says nothing about this one: the manual
/// step must not tell the operator to put an original over it.
#[tokio::test]
async fn a_journal_naming_another_file_refuses_the_lock_with_a_neutral_step() {
    let (dir, path, _ctx) = setup();
    crashed_after_rename(&path, NEXT);
    let journal = crate::config_persistence::journal::journal_path(&path);
    let mut record: serde_json::Value =
        serde_json::from_str(&read(&journal)).expect("the journal is JSON");
    let other = dir.path().join("other.yaml");
    record["target"] = serde_json::Value::from(other.to_string_lossy().into_owned());
    write_owner_only(&journal, record.to_string()).expect("re-point the journal");

    assert_refused_by_hand(&path).await;
}
