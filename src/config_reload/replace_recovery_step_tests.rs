// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A journal recovery that cannot act gives the reviewed manual step for its
//! case, word for word, and leaves gateway.yaml and the journal as the crash
//! left them. Exact texts: a phrase list can be beaten by a synonym, so any
//! rewording fails here and goes back to review.

use super::*;

/// The journal's and the staged original's bytes (`None` where absent or
/// unreadable), to prove a refusal rewrote neither.
fn recovery_bytes(path: &Path) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    use crate::config_persistence::journal;
    (
        std::fs::read(journal::journal_path(path)).ok(),
        std::fs::read(journal::original_path(path)).ok(),
    )
}

/// The lock's refusal, with gateway.yaml, the journal and the staged
/// original unchanged.
async fn refusal(path: &Path) -> String {
    let before = recovery_bytes(path);
    let message = match lock_now(path).await {
        Err(crate::config_persistence::lock::NotLocked::Failed(message)) => message,
        Err(other) => panic!("expected a refusal, got {other:?}"),
        Ok(_) => panic!("an unusable journal must refuse the lock"),
    };
    assert_eq!(read(path), NEXT, "gateway.yaml changed");
    assert!(crate::config_persistence::journal::exists(path));
    assert_eq!(
        recovery_bytes(path),
        before,
        "a recovery file was rewritten"
    );
    message
}

/// The journal, the staged original and the resolved target, as the step
/// names them.
fn names(path: &Path) -> (String, String, String) {
    use crate::config_persistence::journal;
    (
        journal::journal_path(path).display().to_string(),
        journal::original_path(path).display().to_string(),
        crate::identity_grants::journal::resolved(path)
            .display()
            .to_string(),
    )
}

/// T9: a `staged` journal whose original is gone: restore nothing, check the
/// file by hand, then drop the journal.
#[tokio::test]
async fn a_journal_without_its_original_refuses_the_lock() {
    let (_dir, path, _ctx) = setup();
    crashed_after_rename(&path, NEXT);
    std::fs::remove_file(crate::config_persistence::journal::original_path(&path)).expect("rm");
    let (journal, original, target) = names(&path);

    assert_eq!(
        refusal(&path).await,
        format!(
            "{original} cannot be read (it is gone); nothing was changed. Do not restore it: check {target} by hand against the change that was being made, then delete the journal {journal}"
        )
    );
}

/// A journal that cannot be read may be `all_renamed`: inspect it before
/// touching the file; a restore only of this file's digest-matching original.
#[tokio::test]
async fn an_unreadable_journal_refuses_the_lock_with_a_neutral_step() {
    let (_dir, path, _ctx) = setup();
    crashed_after_rename(&path, NEXT);
    let (journal, original, target) = names(&path);
    write_owner_only(&journal, "{not a journal").expect("corrupt the journal");
    let e = serde_json::from_str::<serde_json::Value>("{not a journal").expect_err("not JSON");

    assert_eq!(
        refusal(&path).await,
        format!(
            "{journal} cannot be read ({e}); nothing was changed. Its state is unknown, so leave {target} as it is until you have inspected the journal. If it names {target} and its state is staged, restore the staged original {original} over {target} only if its SHA-256 matches the journal's original_revision, then delete the journal; if its state is all_renamed, only delete the journal; if it names another file, restore nothing over {target}"
        )
    );
}

/// A journal naming another file says nothing about this one: restore
/// nothing over it, and keep the journal.
#[tokio::test]
async fn a_journal_naming_another_file_refuses_the_lock_with_a_neutral_step() {
    let (dir, path, _ctx) = setup();
    crashed_after_rename(&path, NEXT);
    let (journal, _, target) = names(&path);
    let mut record: serde_json::Value =
        serde_json::from_str(&read(Path::new(&journal))).expect("the journal is JSON");
    let other = dir.path().join("other.yaml");
    record["target"] = serde_json::Value::from(other.to_string_lossy().into_owned());
    write_owner_only(&journal, record.to_string()).expect("re-point the journal");
    let other = other.display();

    assert_eq!(
        refusal(&path).await,
        format!(
            "{journal} names {other}, not {target}; nothing was changed. Resolve that journal for {other} first: restore nothing over {target}, and do not delete the journal"
        )
    );
}
