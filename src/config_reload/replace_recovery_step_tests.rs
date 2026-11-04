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
    /// The journal is unreadable: inspect it first; a restore is offered
    /// only of this target's staged original matching the recorded digest.
    AfterInspection,
    /// No restore and no journal deletion before the file is checked.
    Never,
}

/// Advice that changes gateway.yaml or drops the journal: unsafe wherever
/// the step cannot know the journal is this file's and readable.
const UNSAFE: &[&str] = &[
    "restore",
    "copy",
    "overwrite",
    "replace",
    "rename",
    "move",
    "delete the journal",
    "remove the journal",
];

/// The step's clauses: each alternative (`;`) or sentence (`. `) it gives.
/// Paths hold dots, never a dot and a space.
fn clauses(message: &str) -> Vec<&str> {
    message
        .split(';')
        .flat_map(|part| part.split(". "))
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .collect()
}

/// A clause that forbids rather than advises.
fn forbids(clause: &str) -> bool {
    let lower = clause.to_lowercase();
    lower.contains("do not") || lower.contains("nothing")
}

/// The unsafe advice `clause` gives, if any. Paths and identifiers are left
/// out: the journal's own name holds "replace", and `all_renamed` "rename".
fn unsafe_in(clause: &str) -> Vec<&'static str> {
    let words = clause
        .split_whitespace()
        .filter(|w| !w.contains('/') && !w.contains('_'))
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    UNSAFE
        .iter()
        .copied()
        .filter(|advice| words.contains(advice))
        .collect()
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

/// The step names the journal and gives unsafe advice only where `restore`
/// allows it: a restore of this target's staged original matching the
/// recorded digest, after inspection, and for `all_renamed` only a journal
/// deletion that leaves gateway.yaml alone.
fn assert_safe_step(message: &str, path: &Path, restore: Restore) {
    let journal = crate::config_persistence::journal::journal_path(path);
    let target = crate::identity_grants::journal::resolved(path)
        .display()
        .to_string();
    assert!(
        message.contains(&journal.display().to_string()),
        "the step does not name the journal: {message}"
    );
    match restore {
        Restore::Never => {
            for clause in clauses(message) {
                let advice = unsafe_in(clause);
                // A journal deletion is safe once the file was checked by hand.
                let checked = clause.contains("by hand") && advice == ["delete the journal"];
                assert!(
                    advice.is_empty() || forbids(clause) || checked,
                    "unsafe advice {advice:?} in {clause:?}: {message}"
                );
            }
        }
        Restore::AfterInspection => {
            let inspect = message
                .find("inspect")
                .expect("the step says to inspect first");
            for clause in clauses(message) {
                let advice = unsafe_in(clause);
                if advice.is_empty() || forbids(clause) {
                    continue;
                }
                let at = message.find(clause).expect("a clause of the message");
                assert!(inspect < at, "advice before inspection: {clause:?}");
                if clause.contains("all_renamed") {
                    assert_eq!(
                        advice,
                        ["delete the journal"],
                        "all_renamed must leave gateway.yaml alone: {clause:?}"
                    );
                    continue;
                }
                for needed in [target.as_str(), "staged", "SHA-256", "original_revision"] {
                    assert!(
                        clause.contains(needed),
                        "a restore not bound to {needed:?}: {clause:?}"
                    );
                }
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
