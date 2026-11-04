// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A journal recovery that cannot act names a safe manual step, and leaves
//! gateway.yaml and the journal as the crash left them. The asserts are
//! properties of the step, not its sentence: which file it names, and
//! whether it advises a restore only where one can be safe.

use super::*;

/// What the case allows the manual step to advise.
#[derive(Clone, Copy, Debug)]
enum Restore {
    /// The journal is unreadable: inspect it first; any restore is only of
    /// an original matching the journal's digest.
    AfterInspection,
    /// No restore advice of any kind.
    Never,
}

/// The lock's refusal, with gateway.yaml and the journal unchanged.
async fn refusal(path: &Path) -> String {
    let message = match lock_now(path).await {
        Err(crate::config_persistence::lock::NotLocked::Failed(message)) => message,
        Err(other) => panic!("expected a refusal, got {other:?}"),
        Ok(_) => panic!("an unusable journal must refuse the lock"),
    };
    assert_eq!(read(path), NEXT, "gateway.yaml changed");
    assert!(crate::config_persistence::journal::exists(path));
    message
}

/// The step names the journal, never says to copy the original over, and
/// advises a restore only as `restore` allows.
fn assert_safe_step(message: &str, path: &Path, restore: Restore) {
    let journal = crate::config_persistence::journal::journal_path(path);
    assert!(
        message.contains(&journal.display().to_string()),
        "the step does not name the journal: {message}"
    );
    assert!(!message.contains("copy"), "{message}");
    let advice = message.find("restore the staged original");
    match restore {
        Restore::Never => assert!(advice.is_none(), "restore advice: {message}"),
        Restore::AfterInspection => {
            let inspect = message
                .find("inspect")
                .expect("the step says to inspect first");
            if let Some(at) = advice {
                assert!(inspect < at, "restore advised before inspection: {message}");
                assert!(
                    message[at..].contains("only if its SHA-256 matches"),
                    "a restore not bound to the recorded digest: {message}"
                );
            }
        }
    }
}

/// T9: a `staged` journal whose original is gone cannot be acted on: the
/// lock is refused, and the step advises no restore.
#[tokio::test]
async fn a_journal_without_its_original_refuses_the_lock() {
    let (_dir, path, _ctx) = setup();
    crashed_after_rename(&path, NEXT);
    std::fs::remove_file(crate::config_persistence::journal::original_path(&path)).expect("rm");

    let message = refusal(&path).await;
    assert_safe_step(&message, &path, Restore::Never);
}

/// A journal that cannot be read may be `all_renamed`: the step says to
/// inspect it before touching gateway.yaml.
#[tokio::test]
async fn an_unreadable_journal_refuses_the_lock_with_a_neutral_step() {
    let (_dir, path, _ctx) = setup();
    crashed_after_rename(&path, NEXT);
    write_owner_only(
        crate::config_persistence::journal::journal_path(&path),
        "{not a journal",
    )
    .expect("corrupt the journal");

    let message = refusal(&path).await;
    assert_safe_step(&message, &path, Restore::AfterInspection);
}

/// A journal naming another file says nothing about this one: the step
/// names that file, advises no restore over this one, and keeps the journal.
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

    let message = refusal(&path).await;
    assert_safe_step(&message, &path, Restore::Never);
    assert!(
        message.contains(&other.display().to_string()),
        "the step does not name the other file: {message}"
    );
    assert!(
        !message.contains("then delete") && !message.contains("only delete"),
        "the step advises deleting another file's journal: {message}"
    );
}
