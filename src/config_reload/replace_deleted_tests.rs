// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! gateway.yaml deleted while the writer works on it: during the compute
//! and checks the write answers `NoConfigFile` before any intent or entry;
//! during the secret fill it answers `NoConfigFile` and discards the entries
//! it made. A deleted or moved symlink is never answered as a missing file.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use super::super::reload_context::replace::{
    Audit, Intent, IntentId, IntentKind, IntentSink, Replace, replace_audited,
};
use super::*;
use crate::config_persistence::journal;

/// The intents a write appended, in order.
#[derive(Clone, Default)]
struct Kinds(Arc<Mutex<Vec<IntentKind>>>);

impl IntentSink for Kinds {
    fn append(&mut self, intent: &Intent) -> Result<IntentId, String> {
        let mut kinds = self.0.lock().expect("lock");
        kinds.push(intent.kind.clone());
        Ok(IntentId(format!("intent-{}", kinds.len())))
    }
}

impl Kinds {
    fn list(&self) -> Vec<IntentKind> {
        self.0.lock().expect("lock").clone()
    }
}

/// A files store that counts creates and deletes, and on its first create
/// deletes `config`: gateway.yaml goes while the secret fill runs.
struct Deleting {
    inner: FilesStore,
    config: PathBuf,
    creates: Arc<AtomicUsize>,
    deletes: Arc<AtomicUsize>,
}

impl SecretStore for Deleting {
    fn kind(&self) -> StoreKind {
        self.inner.kind()
    }
    fn limit(&self) -> usize {
        self.inner.limit()
    }
    fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe()
    }
    fn exists(&self, name: &str) -> Result<bool, StoreError> {
        self.inner.exists(name)
    }
    fn create(&self, name: &str, value: &[u8]) -> Result<String, StoreError> {
        if self.creates.fetch_add(1, Ordering::SeqCst) == 0 {
            assert!(self.config.exists(), "premise: gateway.yaml is there");
            std::fs::remove_file(&self.config).expect("delete during the fill");
        }
        self.inner.create(name, value)
    }
    fn delete(&self, name: &str) -> Result<(), StoreError> {
        self.deletes.fetch_add(1, Ordering::SeqCst);
        self.inner.delete(name)
    }
}

/// A plain replacement whose compute deletes `config` first.
fn deleting_compute(config: &Path) -> Replace {
    let gone = config.to_path_buf();
    Replace {
        expected: Expected::Any,
        compute: Box::new(move |_| {
            std::fs::remove_file(&gone).expect("delete during the compute");
            assert!(!gone.exists(), "premise: deleted");
            Ok(Template::plain(NEXT.as_bytes().to_vec()))
        }),
        replaced: Replaced::Discard,
        secrets: None,
    }
}

/// The disk a writer killed after its rename leaves: `NEXT` in place, `START`
/// staged, the journal `staged`.
fn crashed_after_rename(path: &Path) {
    journal::stage_original(path, START.as_bytes()).expect("stage");
    journal::begin(path, FileRevision::of(START.as_bytes()).as_str().to_owned()).expect("journal");
    crate::gateway::test_helpers::write_owner_only(
        crate::identity_grants::journal::resolved(path),
        NEXT,
    )
    .expect("rename");
}

/// Nothing of the write is left: no config, no journal, no staged original.
fn assert_nothing_left(path: &Path) {
    crate::gateway::test_helpers::ConfigFiles::assert_absent(path, "a deleted config's write");
}

async fn audited(
    ctx: Arc<ReloadContext>,
    replace: Replace,
    kinds: &Kinds,
) -> Result<ReplaceOutcome, ReplaceError> {
    replace_audited(
        ctx,
        replace,
        Audit::Required {
            sink: Box::new(kinds.clone()),
            kind: IntentKind::Save { fields: Vec::new() },
            writer: None,
        },
        WAIT,
    )
    .await
}

/// Deleted during the compute: `NoConfigFile`, and nothing is left or made.
#[tokio::test]
async fn a_config_deleted_during_compute_is_no_config_file() {
    let (_dir, path, ctx) = setup();
    let result = replace_detached(ctx, deleting_compute(&path), WAIT).await;
    assert!(
        matches!(result, Err(ReplaceError::NoConfigFile)),
        "{result:?}"
    );
    assert_nothing_left(&path);
}

/// On an audited gateway the deletion is seen before the operation's intent
/// and before any store entry: no intent, no create.
#[tokio::test]
async fn an_audited_deletion_during_compute_creates_nothing() {
    let (dir, path, ctx) = setup();
    let creates = Arc::new(AtomicUsize::new(0));
    let store = Counting {
        inner: FilesStore::new(dir.path()),
        creates: Arc::clone(&creates),
    };
    let gone = path.clone();
    let save = Replace {
        expected: Expected::Any,
        compute: Box::new(move |_| {
            std::fs::remove_file(&gone).expect("delete during the compute");
            Ok(with_slot())
        }),
        replaced: Replaced::Discard,
        secrets: Some(step(dir.path(), Arc::new(store))),
    };
    let kinds = Kinds::default();
    let result = audited(ctx, save, &kinds).await;
    assert!(
        matches!(result, Err(ReplaceError::NoConfigFile)),
        "{result:?}"
    );
    assert_eq!(kinds.list(), [], "an operation intent was appended");
    assert_eq!(creates.load(Ordering::SeqCst), 0, "an entry was created");
    assert_nothing_left(&path);
}

/// A crashed write recovered first, then the restored file deleted during
/// the compute: still `NoConfigFile`, and the write does not recreate it.
#[tokio::test]
async fn a_recovered_config_deleted_during_compute_is_no_config_file() {
    let (_dir, path, ctx) = setup();
    crashed_after_rename(&path);
    let gone = path.clone();
    let replace = Replace {
        expected: Expected::Any,
        compute: Box::new(move |bytes| {
            assert_eq!(bytes, START.as_bytes(), "premise: recovery restored START");
            std::fs::remove_file(&gone).expect("delete during the compute");
            Ok(Template::plain(NEXT.as_bytes().to_vec()))
        }),
        replaced: Replaced::Discard,
        secrets: None,
    };
    let kinds = Kinds::default();
    let result = audited(ctx, replace, &kinds).await;
    assert!(
        matches!(result, Err(ReplaceError::NoConfigFile)),
        "{result:?}"
    );
    assert_eq!(kinds.list(), [IntentKind::Recovery]);
    assert_nothing_left(&path);
}

/// gateway.yaml a symlink to `real.yaml` in a temp dir, with its context.
#[cfg(unix)]
fn linked() -> (tempfile::TempDir, PathBuf, PathBuf, Arc<ReloadContext>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let real = dir.path().join("real.yaml");
    crate::gateway::test_helpers::write_owner_only(&real, START).expect("write");
    let link = dir.path().join("gateway.yaml");
    std::os::unix::fs::symlink(&real, &link).expect("link");
    let ctx = super::super::replace_test_support::context(&link);
    (dir, link, real, ctx)
}

/// A symlinked gateway.yaml whose target is deleted during the compute is a
/// dangling link, not a missing config: `Failed`, never `NoConfigFile`, and
/// nothing is written through the link.
#[cfg(unix)]
#[tokio::test]
async fn a_symlinked_config_whose_target_goes_is_not_no_config_file() {
    let (_dir, link, real, ctx) = linked();
    let result = replace_detached(ctx, deleting_compute(&real), WAIT).await;
    assert!(matches!(result, Err(ReplaceError::Failed(_))), "{result:?}");
    assert!(!real.exists(), "the target was recreated");
    assert_nothing_left(&real);
    assert!(
        std::fs::symlink_metadata(&link).is_ok_and(|m| m.file_type().is_symlink()),
        "the link was replaced"
    );
}

/// The link itself removed during the compute: the path no longer names the
/// locked target, so `Failed`, never `NoConfigFile`; the target keeps its
/// bytes and nothing new appears at the link's name.
#[cfg(unix)]
#[tokio::test]
async fn a_config_symlink_removed_during_compute_is_not_no_config_file() {
    let (_dir, link, real, ctx) = linked();
    let files = crate::gateway::test_helpers::ConfigFiles::snapshot(&real);
    let result = replace_detached(ctx, deleting_compute(&link), WAIT).await;
    assert!(matches!(result, Err(ReplaceError::Failed(_))), "{result:?}");
    assert_eq!(read(&real), START, "the target was written");
    files.assert_unchanged(&real, "the target behind a removed link");
    assert!(
        std::fs::symlink_metadata(&link).is_err(),
        "something was created at the link"
    );
}

/// One secret save whose store deletes gateway.yaml during the fill.
fn deleting_save(dir: &Path, config: &Path) -> (Replace, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let (creates, deletes) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let store = Deleting {
        inner: FilesStore::new(dir),
        config: config.to_path_buf(),
        creates: Arc::clone(&creates),
        deletes: Arc::clone(&deletes),
    };
    let save = Replace {
        expected: Expected::Any,
        compute: Box::new(|_| Ok(with_slot())),
        replaced: Replaced::Discard,
        secrets: Some(step(dir, Arc::new(store))),
    };
    (save, creates, deletes)
}

/// Deleted while the secret entries are created: `NoConfigFile`; the
/// operation's intent, appended before the fill, stays as its record; every
/// entry made is discarded; nothing is written.
#[tokio::test]
async fn a_config_deleted_while_entries_are_created_discards_them() {
    let (dir, path, ctx) = setup();
    let (save, creates, deletes) = deleting_save(dir.path(), &path);
    let kinds = Kinds::default();
    let result = audited(ctx, save, &kinds).await;
    assert!(
        matches!(result, Err(ReplaceError::NoConfigFile)),
        "{result:?}"
    );
    assert_eq!(kinds.list(), [IntentKind::Save { fields: Vec::new() }]);
    assert_eq!(
        creates.load(Ordering::SeqCst),
        1,
        "premise: one entry was made"
    );
    assert_eq!(
        deletes.load(Ordering::SeqCst),
        1,
        "the entry was not discarded"
    );
    assert_nothing_left(&path);
}

/// The same after a crashed write was recovered first: the lock's snapshot
/// said the file was missing, so only a check of the disk now sees the
/// deletion.
#[tokio::test]
async fn a_recovered_config_deleted_while_entries_are_created_discards_them() {
    let (dir, path, ctx) = setup();
    crashed_after_rename(&path);
    let (save, creates, deletes) = deleting_save(dir.path(), &path);
    let kinds = Kinds::default();
    let result = audited(ctx, save, &kinds).await;
    assert!(
        matches!(result, Err(ReplaceError::NoConfigFile)),
        "{result:?}"
    );
    assert_eq!(
        kinds.list(),
        [
            IntentKind::Recovery,
            IntentKind::Save { fields: Vec::new() }
        ]
    );
    assert_eq!(
        creates.load(Ordering::SeqCst),
        1,
        "premise: one entry was made"
    );
    assert_eq!(
        deletes.load(Ordering::SeqCst),
        1,
        "the entry was not discarded"
    );
    assert_nothing_left(&path);
}
