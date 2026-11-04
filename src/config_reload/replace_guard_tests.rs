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
    assert_eq!(read(&path), START, "the planted original was restored");
    assert!(
        journal::journal_path(&path).exists(),
        "the journal was settled"
    );
    let text = format!("{failure:?}");
    let shown = dir.path().to_string_lossy().into_owned();
    assert!(!text.contains(&shown), "the refusal names a path: {text}");
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
