// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The capability writer: lock, restore, create race, swap race, rename
//! failure and account binding.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::{Base, Change, Committed, Edit, PinUpdate, Refused, commit, commit_observed};
use crate::capability::{compute_capability_hash, rewrite_with_pin};
use crate::config_persistence::lock::{lock_config, lock_path, waiters_for_test};
use crate::identity_propagation::AccountStrategyRegistry;

const TEXT: &str = "fulcrum: \"1.0\"\nname: kept\ndescription: Original\n\nschema:\n  input:\n    type: object\n  output:\n    type: object\n\nproviders:\n  primary:\n    service: rest\n    config:\n      base_url: https://api.example\n      path: /api\n      method: GET\n";

fn sha(text: &str) -> String {
    crate::hashing::sha256_hex(text.as_bytes())
}

fn pinned(text: &str) -> String {
    rewrite_with_pin(text, &compute_capability_hash(text))
}

fn described(text: &str, description: &str) -> String {
    text.replace(
        "description: Original",
        &format!("description: {description}"),
    )
}

/// A directory holding `kept.yaml` with `text`.
fn dir_with(text: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("kept.yaml");
    std::fs::write(&file, text).unwrap();
    (dir, file)
}

fn edit<'a>(dir: &'a Path, base: Base, change: Change, pin: PinUpdate) -> Edit<'a> {
    Edit {
        dir,
        name: "kept",
        base,
        change,
        pin,
    }
}

fn soon() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

// ── T11: the directory lock ───────────────────────────────────────────

#[tokio::test]
async fn lock_held_is_busy_and_writes_nothing() {
    let (dir, file) = dir_with(TEXT);
    let pseudo = dir.path().join("capabilities");
    let _held = lock_config(&pseudo, soon())
        .await
        .expect("the test takes the lock");
    assert_eq!(lock_path(&pseudo), dir.path().join(".capabilities.lock"));

    let result = commit(
        edit(
            dir.path(),
            Base::Bytes(sha(TEXT)),
            Change::Write(described(TEXT, "Edited")),
            PinUpdate::InPlace,
        ),
        None,
        Instant::now(),
    )
    .await;

    assert_eq!(result, Err(Refused::LockBusy));
    assert_eq!(std::fs::read_to_string(&file).unwrap(), TEXT);
    assert!(!dir.path().join("..capabilities.lock").exists());
}

// ── T12: a restore writes stored bytes as stored ──────────────────────

#[tokio::test]
async fn restore_writes_stored_bytes_verbatim() {
    let current = pinned(TEXT);
    let (dir, file) = dir_with(&current);
    let stored = pinned(&described(TEXT, "Stored version"));

    let committed = commit(
        edit(
            dir.path(),
            Base::Bytes(sha(&current)),
            Change::Write(stored.clone()),
            PinUpdate::Verbatim,
        ),
        None,
        soon(),
    )
    .await
    .expect("a restore of a loadable stored version commits");

    assert_eq!(std::fs::read_to_string(&file).unwrap(), stored);
    assert_eq!(committed.after.as_deref(), Some(sha(&stored).as_str()));
}

#[tokio::test]
async fn restore_over_a_tampered_file_commits() {
    let tampered = described(&pinned(TEXT), "Tampered on disk");
    let (dir, file) = dir_with(&tampered);
    let stored = pinned(TEXT);

    let result = commit(
        edit(
            dir.path(),
            Base::Bytes(sha(&tampered)),
            Change::Write(stored.clone()),
            PinUpdate::Verbatim,
        ),
        None,
        soon(),
    )
    .await;

    assert!(
        result.is_ok(),
        "restoring known-good bytes is the fix: {result:?}"
    );
    assert_eq!(std::fs::read_to_string(&file).unwrap(), stored);
}

#[tokio::test]
async fn restore_never_unpins() {
    let current = pinned(TEXT);
    let (dir, file) = dir_with(&current);

    let result = commit(
        edit(
            dir.path(),
            Base::Bytes(sha(&current)),
            Change::Write(TEXT.to_string()),
            PinUpdate::Verbatim,
        ),
        None,
        soon(),
    )
    .await;

    assert!(matches!(result, Err(Refused::Unpin { .. })), "{result:?}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), current);
}

#[tokio::test]
async fn restore_of_an_unloadable_version_is_invalid() {
    let (dir, file) = dir_with(TEXT);

    let result = commit(
        edit(
            dir.path(),
            Base::Bytes(sha(TEXT)),
            Change::Write("name: kept\nproviders: 5\n".into()),
            PinUpdate::Verbatim,
        ),
        None,
        soon(),
    )
    .await;

    assert!(matches!(result, Err(Refused::Invalid { .. })), "{result:?}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), TEXT);
}

// ── T9: two creates of one name, serialized by the lock ───────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_race_has_one_winner() {
    let dir = tempfile::tempdir().unwrap();
    // Canonical, as the writer locks it (a temp dir can sit behind a link).
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let pseudo = root.join("capabilities");
    let held = lock_config(&pseudo, soon())
        .await
        .expect("the test takes the lock");

    let racer = |description: &'static str| {
        let root = root.clone();
        tokio::spawn(async move {
            let edit = Edit {
                dir: &root,
                name: "kept",
                base: Base::Absent,
                change: Change::Write(described(TEXT, description)),
                pin: PinUpdate::InPlace,
            };
            commit(edit, None, Instant::now() + Duration::from_secs(30)).await
        })
    };
    let first = racer("First");
    let second = racer("Second");

    // Both reached the lock (so both did whatever they do before it).
    let guard = Instant::now() + Duration::from_secs(10);
    while waiters_for_test(&lock_path(&pseudo)) < 2 {
        assert!(
            Instant::now() < guard,
            "both creates never reached the lock"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    drop(held);

    let results = [first.await.unwrap(), second.await.unwrap()];
    let won: Vec<&Committed> = results.iter().filter_map(|r| r.as_ref().ok()).collect();
    let stale = results
        .iter()
        .filter(|r| matches!(r, Err(Refused::Stale { .. })))
        .count();
    assert_eq!((won.len(), stale), (1, 1), "{results:?}");
    let on_disk = std::fs::read_to_string(root.join("kept.yaml")).unwrap();
    assert_eq!(won[0].after.as_deref(), Some(sha(&on_disk).as_str()));
}

// ── T18c: a link swapped in after the base check is replaced, not followed ──

#[cfg(unix)]
#[tokio::test]
async fn swapped_in_link_is_replaced_not_followed() {
    let (dir, file) = dir_with(TEXT);
    let other = dir.path().join("other.yaml");
    std::fs::write(&other, described(TEXT, "Other")).unwrap();
    let sent = described(TEXT, "Saved");

    let result = commit_observed(
        edit(
            dir.path(),
            Base::Bytes(sha(TEXT)),
            Change::Write(sent.clone()),
            PinUpdate::InPlace,
        ),
        None,
        soon(),
        |target| {
            std::fs::remove_file(target).unwrap();
            std::os::unix::fs::symlink("other.yaml", target).unwrap();
        },
    )
    .await;

    assert!(result.is_ok(), "{result:?}");
    let meta = std::fs::symlink_metadata(&file).unwrap();
    assert!(
        meta.file_type().is_file(),
        "kept.yaml is a regular file again"
    );
    assert_eq!(std::fs::read_to_string(&file).unwrap(), sent);
    assert_eq!(
        std::fs::read_to_string(&other).unwrap(),
        described(TEXT, "Other")
    );
}

// ── T10: a failed write leaves the file as it was ─────────────────────

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn failure_at_the_rename_is_unwritable() {
    let (dir, file) = dir_with(TEXT);
    let root = dir.path().to_path_buf();

    let result = commit_observed(
        edit(
            dir.path(),
            Base::Bytes(sha(TEXT)),
            Change::Write(described(TEXT, "Edited")),
            PinUpdate::InPlace,
        ),
        None,
        soon(),
        |_| set_mode(&root, 0o555),
    )
    .await;
    set_mode(&root, 0o755);

    match result {
        Err(Refused::Unwritable { patch, .. }) => {
            assert!(patch.contains("+description: Edited"), "{patch}");
        }
        other => panic!("expected Unwritable, got {other:?}"),
    }
    assert_eq!(std::fs::read_to_string(&file).unwrap(), TEXT);
}

#[cfg(unix)]
#[tokio::test]
async fn read_only_directory_is_unwritable() {
    let (dir, file) = dir_with(TEXT);
    // The lock sidecar exists first, so the refusal is the write's.
    let _ = lock_config(&dir.path().join("capabilities"), soon())
        .await
        .unwrap();
    set_mode(dir.path(), 0o555);

    let result = commit(
        edit(
            dir.path(),
            Base::Bytes(sha(TEXT)),
            Change::Write(described(TEXT, "Edited")),
            PinUpdate::InPlace,
        ),
        None,
        soon(),
    )
    .await;
    set_mode(dir.path(), 0o755);

    assert!(
        matches!(result, Err(Refused::Unwritable { .. })),
        "{result:?}"
    );
    assert_eq!(std::fs::read_to_string(&file).unwrap(), TEXT);
}

// ── T19: the account binding the reload admission gate applies ────────

#[tokio::test]
async fn unresolved_account_binding_is_invalid() {
    let (dir, file) = dir_with(TEXT);
    let registry = AccountStrategyRegistry::default();
    let bound = TEXT.replace(
        "\nproviders:",
        "\nauth:\n  required: false\n  account: nobody\n\nproviders:",
    );

    let result = commit(
        edit(
            dir.path(),
            Base::Bytes(sha(TEXT)),
            Change::Write(bound),
            PinUpdate::InPlace,
        ),
        Some(&registry),
        soon(),
    )
    .await;

    match result {
        Err(Refused::Invalid { errors, .. }) => {
            assert!(
                errors.iter().any(|e| e.message.contains("nobody")),
                "{errors:?}"
            );
        }
        other => panic!("expected Invalid, got {other:?}"),
    }
    assert_eq!(std::fs::read_to_string(&file).unwrap(), TEXT);
}

// ── T17: `cap pin` takes the resolved directory's lock ────────────────

#[cfg(unix)]
#[tokio::test]
async fn cap_pin_follows_the_link_under_the_real_directory_lock() {
    let (real_dir, real_file) = dir_with(TEXT);
    let links = tempfile::tempdir().unwrap();
    let link = links.path().join("link.yaml");
    std::os::unix::fs::symlink(&real_file, &link).unwrap();

    let held = lock_config(&real_dir.path().join("capabilities"), soon())
        .await
        .unwrap();
    let refused = super::pin_file_until(&link, Instant::now());
    assert!(refused.is_err(), "{refused:?}");
    assert_eq!(
        std::fs::read_to_string(&real_file).unwrap(),
        TEXT,
        "nothing written while held"
    );
    assert!(
        !links.path().join(".capabilities.lock").exists(),
        "the link's directory is not the lock"
    );
    drop(held);

    let hash = super::pin_file_until(&link, soon()).expect("pins once the lock is free");
    assert_eq!(hash, compute_capability_hash(TEXT));
    assert_eq!(std::fs::read_to_string(&real_file).unwrap(), pinned(TEXT));
    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

// ── T21: on Windows a save never widens a private file ────────────────

#[cfg(windows)]
#[tokio::test]
async fn windows_save_keeps_a_private_file_private() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    // The directory others can read: what an inheriting write would copy.
    let granted = std::process::Command::new("icacls")
        .arg(dir.path())
        .args(["/grant", "*S-1-1-0:(OI)(CI)R"])
        .status()
        .expect("icacls runs");
    assert!(granted.success(), "the directory is readable by Everyone");
    let file = dir.path().join("kept.yaml");
    crate::config_persistence::create_new_private(&file)
        .unwrap()
        .write_all(TEXT.as_bytes())
        .unwrap();
    let private = |path: &Path| {
        crate::private_fs::privacy_refusals(&crate::private_fs::open_file_read(path).unwrap()).len()
    };
    assert_eq!(private(&file), 0, "the fixture starts private");

    let result = commit(
        edit(
            dir.path(),
            Base::Bytes(sha(TEXT)),
            Change::Write(described(TEXT, "Edited")),
            PinUpdate::InPlace,
        ),
        None,
        soon(),
    )
    .await;

    assert!(result.is_ok(), "{result:?}");
    assert_eq!(private(&file), 0, "the save widened a private file");
}

// ── T5 (review r1): a first-line pin in a BOM file still verifies ─────

#[tokio::test]
async fn first_line_pin_in_a_bom_file_verifies_after_a_save() {
    // An unpinned BOM file; the save adds a pin on the first line, as a
    // browser sends it (the BOM dropped).
    let base = format!("\u{feff}{TEXT}");
    let (dir, file) = dir_with(&base);
    let sent = format!("sha256: 0\n{}", described(TEXT, "Edited"));

    let result = commit(
        edit(
            dir.path(),
            Base::Bytes(sha(&base)),
            Change::Write(sent),
            PinUpdate::InPlace,
        ),
        None,
        soon(),
    )
    .await;

    assert_eq!(
        result.as_ref().map(|c| c.pin),
        Ok(super::PinChange::Added),
        "{result:?}"
    );
    let on_disk = std::fs::read_to_string(&file).unwrap();
    assert!(
        on_disk.starts_with("sha256: "),
        "the pin is a line the loader sees: {on_disk:?}"
    );
    let cap = crate::capability::parser::parse_capability_text(&on_disk, &file)
        .expect("the saved file verifies its own pin");
    assert_eq!(
        cap.providers.integrity,
        crate::capability::Integrity::Verified
    );
}

#[tokio::test]
async fn a_bom_before_a_first_line_pin_is_a_mismatch_not_a_save() {
    // The pin covers the text without the BOM, so the file as stored does not
    // verify: the loader drops it, and an edit-save must not re-pin it.
    let base = format!("\u{feff}{}", pinned(TEXT));
    let (dir, file) = dir_with(&base);
    let sent = pinned(TEXT).replace("description: Original", "description: Edited");

    let result = commit(
        edit(
            dir.path(),
            Base::Bytes(sha(&base)),
            Change::Write(sent),
            PinUpdate::InPlace,
        ),
        None,
        soon(),
    )
    .await;

    assert!(
        matches!(result, Err(Refused::PinMismatch { .. })),
        "{result:?}"
    );
    assert_eq!(std::fs::read_to_string(&file).unwrap(), base);
}

#[path = "file_writer_review_tests.rs"]
mod review;
