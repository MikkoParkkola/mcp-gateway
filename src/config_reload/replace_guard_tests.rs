// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The byte writer's read of gateway.yaml goes through the guard every loader
//! uses: a file it refuses, or a missing one, creates no secret entry at all.

use std::path::Path;
use std::sync::Arc;

use super::super::reload_context::replace::{
    Expected, Replace, ReplaceError, Replaced, replace_detached,
};
use super::super::replace_test_support::{START, WAIT, read, setup};
use super::{Counting, step, with_slot};
use crate::secret_store::FilesStore;

/// A secret save over `path` through a store that counts its creates.
fn counted_save(dir: &Path) -> (Replace, Arc<std::sync::atomic::AtomicUsize>) {
    let creates = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let store = Counting {
        inner: FilesStore::new(dir),
        creates: Arc::clone(&creates),
    };
    let save = Replace {
        expected: Expected::Any,
        compute: Box::new(|_| Ok(with_slot())),
        replaced: Replaced::Discard,
        secrets: Some(step(dir, Arc::new(store))),
    };
    (save, creates)
}

/// A gateway.yaml the guard refuses creates no store entry, not even one
/// created and then discarded, and keeps its bytes and mode: group write,
/// group read (refused because the test owns the file) and world write.
#[cfg(unix)]
#[tokio::test]
async fn a_config_the_guard_refuses_creates_no_entry() {
    use std::os::unix::fs::PermissionsExt as _;
    for mode in [0o620, 0o640, 0o602] {
        let (dir, path, ctx) = setup();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
        let (save, creates) = counted_save(dir.path());

        let failure = replace_detached(ctx, save, WAIT)
            .await
            .expect_err("refused");

        assert!(
            matches!(failure, ReplaceError::ConfigRefused(_)),
            "mode {mode:o}: {failure:?}"
        );
        assert_eq!(creates.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(read(&path), START);
        let now = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(now & 0o777, mode, "mode {mode:o}: the file was rewritten");
    }
}

/// A gateway.yaml removed before the writer's read is `NoConfigFile`, with
/// no store entry created and no file written.
#[tokio::test]
async fn a_missing_config_creates_no_entry() {
    let (dir, path, ctx) = setup();
    std::fs::remove_file(&path).expect("remove");
    let (save, creates) = counted_save(dir.path());

    let failure = replace_detached(ctx, save, WAIT)
        .await
        .expect_err("refused");

    assert!(matches!(failure, ReplaceError::NoConfigFile), "{failure:?}");
    assert_eq!(creates.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(!path.exists(), "a config was written");
}

/// Windows: a gateway.yaml whose DACL lets Everyone write is refused by the
/// writer's read, with no entry created and the file as it was.
#[cfg(windows)]
#[tokio::test]
async fn a_config_everyone_can_write_is_refused_on_windows() {
    let row = "writer-dacl";
    let (dir, path, ctx) = setup();
    crate::private_fs::test_support::plant_file_with(row, &path, "(A;;FW;;;WD)");
    let (save, creates) = counted_save(dir.path());

    let failure = replace_detached(ctx, save, WAIT)
        .await
        .expect_err("refused");

    assert!(
        matches!(failure, ReplaceError::ConfigRefused(_)),
        "WT-ASSERT {row}: {failure:?}"
    );
    assert_eq!(creates.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(read(&path), START);
}

/// A crashed write's recovery restores the staged original as gateway.yaml,
/// so it reads both the journal and the original through the config guard.
/// Here another account could have planted the one named by `loose`, with a
/// digest to match: recovery refuses, gateway.yaml keeps its bytes, nothing
/// is restored, and the refusal names no path.
#[cfg(unix)]
async fn a_loose_recovery_file_is_never_restored(loose: fn(&Path) -> std::path::PathBuf) {
    use crate::config_persistence::journal;
    use std::os::unix::fs::PermissionsExt as _;
    const PLANTED: &str = "# planted by another account\nbackends: {}\n";
    let (dir, path, ctx) = setup();
    journal::stage_original(&path, PLANTED.as_bytes()).expect("stage");
    journal::begin(&path, crate::hashing::sha256_hex(PLANTED.as_bytes())).expect("journal");
    let planted = loose(&path);
    std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o660)).expect("chmod");

    let result = replace_detached(
        ctx,
        super::super::replace_test_support::to(
            Expected::Any,
            super::super::replace_test_support::NEXT,
            Replaced::Discard,
        ),
        WAIT,
    )
    .await;

    let failure = result.expect_err("a refused recovery file was restored");
    // The guard's own refusal, not some other failure of the write.
    assert!(
        matches!(failure, ReplaceError::ConfigRefused(_)),
        "{failure:?}"
    );
    assert_eq!(read(&path), START, "the planted original was restored");
    assert!(
        journal::journal_path(&path).exists(),
        "the journal was settled"
    );
    let text = format!("{failure:?}");
    assert_reviewed_recovery_refusal(&failure);
    let shown = dir.path().to_string_lossy().into_owned();
    assert!(!text.contains(&shown), "the refusal names a path: {text}");
    assert_safe_recovery_advice(&text);
}

/// Advice a refused journal or staged original must never get: either may
/// be another account's plant with a matching digest, so fixing its owner or
/// mode, retrying while it is in place, or restoring, copying or comparing
/// from it would install the plant as a trusted gateway.yaml.
const FORBIDDEN_RECOVERY_ADVICE: &[&str] = &[
    "chmod",
    "chown",
    "fix it as the gateway log says",
    "fix its mode",
    "fix its owner",
    "and retry",
    "restoring anything",
    "restore it",
    "copy the staged original",
    "compare the staged original",
    "then delete the journal",
];

/// The reviewed refusal for a journal or staged original the guard refused,
/// word for word: a phrase list can be beaten by a synonym, so any rewording
/// fails here and goes back to review.
const REVIEWED_RECOVERY_REFUSAL: &str = "a pending config recovery was not run: its replace \
     journal and staged original are untrusted, because the config guard refuses one of them \
     (another account could have planted or changed it, it is not a regular file, or it is not \
     UTF-8 text), so nothing was restored. Leave their owner and mode alone: fixing them would \
     make the next recovery restore them. Check gateway.yaml against a known-good copy, move \
     both files aside, then retry";

fn assert_reviewed_recovery_refusal(failure: &ReplaceError) {
    let ReplaceError::ConfigRefused(text) = failure else {
        panic!("not the guard's refusal: {failure:?}");
    };
    assert_eq!(text, REVIEWED_RECOVERY_REFUSAL);
}

/// The refusal for a journal or staged original the guard refused: no
/// forbidden advice, phrase by phrase; both files called untrusted; both
/// moved aside before any retry.
fn assert_safe_recovery_advice(text: &str) {
    let lower = text.to_lowercase();
    for phrase in FORBIDDEN_RECOVERY_ADVICE {
        assert!(
            !lower.contains(phrase),
            "the refusal advises {phrase:?}: {text}"
        );
    }
    assert!(
        lower.contains("untrusted"),
        "both files are not called untrusted: {text}"
    );
    let aside = lower
        .find("move both files aside")
        .unwrap_or_else(|| panic!("the refusal does not say to move both files aside: {text}"));
    let retry = lower
        .rfind("retry")
        .unwrap_or_else(|| panic!("the refusal gives no retry step: {text}"));
    assert!(
        aside < retry,
        "the retry comes before moving both files aside: {text}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn a_staged_original_others_can_write_is_never_restored() {
    a_loose_recovery_file_is_never_restored(|path| {
        crate::config_persistence::journal::original_path(path)
    })
    .await;
}

#[cfg(unix)]
#[tokio::test]
async fn a_journal_others_can_write_is_never_acted_on() {
    a_loose_recovery_file_is_never_restored(|path| {
        crate::config_persistence::journal::journal_path(path)
    })
    .await;
}

/// An owner-only gateway.yaml that is not UTF-8 is refused by the writer's
/// read like any file the guard refuses: no store entry, bytes unchanged.
#[tokio::test]
async fn a_config_that_is_not_utf8_creates_no_entry() {
    let (dir, path, ctx) = setup();
    let bytes = b"backends: {}\n# \xff\xfe\n";
    crate::gateway::test_helpers::write_owner_only(&path, bytes).expect("write");
    let (save, creates) = counted_save(dir.path());

    let failure = replace_detached(ctx, save, WAIT)
        .await
        .expect_err("refused");

    assert!(
        matches!(failure, ReplaceError::ConfigRefused(_)),
        "{failure:?}"
    );
    assert_eq!(creates.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(std::fs::read(&path).expect("read"), bytes);
}

/// A staged original that is not UTF-8 (staged before the writer read
/// through the guard) is refused, and the refusal says so and gives the
/// by-hand step: both files untrusted, gateway.yaml checked against a
/// known-good copy, both moved aside before a retry.
#[tokio::test]
async fn a_staged_original_that_is_not_utf8_names_encoding_and_the_manual_step() {
    use crate::config_persistence::journal;
    let (dir, path, ctx) = setup();
    let staged = b"backends: {}\n# \xff\n";
    journal::stage_original(&path, staged).expect("stage");
    journal::begin(&path, crate::hashing::sha256_hex(staged)).expect("journal");
    let journal_bytes = std::fs::read(journal::journal_path(&path)).expect("journal");

    let failure = replace_detached(
        ctx,
        super::super::replace_test_support::to(Expected::Any, START, Replaced::Discard),
        WAIT,
    )
    .await
    .expect_err("refused");

    assert!(
        matches!(failure, ReplaceError::ConfigRefused(_)),
        "{failure:?}"
    );
    let text = format!("{failure:?}");
    assert_reviewed_recovery_refusal(&failure);
    assert!(text.contains("UTF-8"), "{text}");
    assert_safe_recovery_advice(&text);
    assert!(!text.contains(&*dir.path().to_string_lossy()), "{text}");
    assert_eq!(read(&path), START);
    // Both files are kept byte for byte, for the operator to move aside.
    assert_eq!(
        std::fs::read(journal::original_path(&path)).expect("staged original"),
        staged,
        "the staged original was changed"
    );
    assert_eq!(
        std::fs::read(journal::journal_path(&path)).expect("journal"),
        journal_bytes,
        "the journal was changed"
    );
}

/// What recovery logs when the guard refuses the journal or staged original
/// `loose` names (made group-writable, a plant with a matching digest).
#[cfg(unix)]
fn recovery_log_for(loose: fn(&Path) -> std::path::PathBuf) -> String {
    use crate::config_persistence::journal;
    use std::os::unix::fs::PermissionsExt as _;
    const PLANTED: &str = "# planted by another account\nbackends: {}\n";
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, START).expect("config");
    journal::stage_original(&path, PLANTED.as_bytes()).expect("stage");
    journal::begin(&path, crate::hashing::sha256_hex(PLANTED.as_bytes())).expect("journal");
    std::fs::set_permissions(loose(&path), std::fs::Permissions::from_mode(0o660)).expect("chmod");

    let (result, logs) = crate::test_log_capture::capture_warnings(|| journal::recover(&path));

    assert!(
        matches!(result, Err(journal::NotRecovered::Refused(_))),
        "{result:?}"
    );
    assert_eq!(read(&path), START, "the planted original was restored");
    logs
}

/// The log line for a refused recovery file keeps the guard's facts (the
/// mode it breaks) but never an owner or mode fix: following one would make
/// the next recovery restore the plant. It gives the untrusted, move-aside
/// guidance instead.
#[cfg(unix)]
fn assert_safe_recovery_log(logs: &str) {
    let lower = logs.to_lowercase();
    for advice in ["chmod", "chown", "icacls", "fix: "] {
        assert!(
            !lower.contains(advice),
            "the log advises {advice:?}: {logs}"
        );
    }
    assert!(
        lower.contains("mode 0660"),
        "the log lost the guard's facts: {logs}"
    );
    assert!(
        lower.contains("untrusted"),
        "the log does not call them untrusted: {logs}"
    );
    assert!(
        lower.contains("move both files aside"),
        "the log does not say to move both files aside: {logs}"
    );
}

#[cfg(unix)]
#[test]
fn a_refused_staged_original_logs_no_owner_or_mode_fix() {
    assert_safe_recovery_log(&recovery_log_for(|path| {
        crate::config_persistence::journal::original_path(path)
    }));
}

#[cfg(unix)]
#[test]
fn a_refused_journal_logs_no_owner_or_mode_fix() {
    assert_safe_recovery_log(&recovery_log_for(|path| {
        crate::config_persistence::journal::journal_path(path)
    }));
}

/// A gateway.yaml with a staged original and a journal beside it.
fn config_with_recovery_files(dir: &Path) -> std::path::PathBuf {
    use crate::config_persistence::journal;
    let path = dir.join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, START).expect("config");
    journal::stage_original(&path, START.as_bytes()).expect("stage");
    journal::begin(&path, crate::hashing::sha256_hex(START.as_bytes())).expect("journal");
    path
}

/// `file` is refused as not the config, by the typed refusal.
fn assert_not_the_config(file: &Path) {
    let read = crate::config::read_config_text(file);
    assert!(
        matches!(read, Err(crate::config::UnreadConfig::NotTheConfig(_))),
        "{} was read as a config: {read:?}",
        file.display()
    );
}

/// `path` reads as the config it is.
fn assert_reads_as_config(path: &Path) {
    let read = crate::config::read_config_text(path);
    assert!(
        matches!(&read, Ok(Some(text)) if text == START),
        "{} no longer reads: {read:?}",
        path.display()
    );
}

/// The config class's guarded read refuses the replace journal and the
/// staged original, and a symlink to either from another directory, with
/// its own typed refusal; gateway.yaml itself reads as before.
#[test]
fn the_config_read_refuses_a_journal_or_staged_original() {
    use crate::config_persistence::journal;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = config_with_recovery_files(dir.path());
    assert_reads_as_config(&path);
    let recovery_files = [journal::journal_path(&path), journal::original_path(&path)];
    for file in &recovery_files {
        assert_not_the_config(file);
    }
    // Links live in another directory, so the refusal cannot lean on the
    // link sitting next to gateway.yaml.
    #[cfg(unix)]
    {
        let elsewhere = tempfile::tempdir().expect("another directory");
        for (index, file) in recovery_files.iter().enumerate() {
            let link = elsewhere.path().join(format!("link-{index}.yaml"));
            std::os::unix::fs::symlink(file, &link).expect("symlink");
            assert_not_the_config(&link);
        }
    }
}

/// Through a symlinked config directory, the recovery files are still
/// refused and gateway.yaml still reads.
#[cfg(unix)]
#[test]
fn the_config_read_refuses_a_recovery_file_through_a_linked_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    config_with_recovery_files(dir.path());
    let elsewhere = tempfile::tempdir().expect("another directory");
    let linked = elsewhere.path().join("config-dir");
    std::os::unix::fs::symlink(dir.path(), &linked).expect("symlink");
    assert_reads_as_config(&linked.join("gateway.yaml"));
    for name in [
        ".gateway.yaml.replace-journal",
        ".gateway.yaml.replace-original",
    ] {
        assert_not_the_config(&linked.join(name));
    }
}

/// A gateway.yaml that is a hard link to its own journal is the journal
/// under another name, which no path comparison sees: refused by identity.
#[test]
fn the_config_read_refuses_a_config_hard_linked_to_its_journal() {
    use crate::config_persistence::journal;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = config_with_recovery_files(dir.path());
    std::fs::remove_file(&path).expect("remove the config");
    std::fs::hard_link(journal::journal_path(&path), &path).expect("hard link");
    assert_not_the_config(&path);
}
