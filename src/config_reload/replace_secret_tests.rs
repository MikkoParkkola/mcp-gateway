// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The byte writer's secret step: a save's new store entries stay when its
//! bytes stand, go only when the old file provably stayed, and are left
//! listed as unused whenever the file on disk may name them.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use super::reload_context::replace::{
    Expected, FileRevision, Replace, ReplaceError, ReplaceOutcome, Replaced, SecretStep, Settle,
    replace_detached, settle_for,
};
use super::replace_test_support::{NEXT, START, WAIT, read, setup};
use super::*;
use crate::secret_store::{
    FilesStore, NewSecretOwned, SecretStore, StoreError, StoreKind, Vault, unused_entries,
};
use crate::wiped_bytes::WipedBytes;

/// The secret's bytes: never in gateway.yaml, only in the store.
const VALUE: &[u8] = b"secret-step-value";

fn vault(dir: &Path) -> Vault {
    Vault::with_lock(dir, dir.join("vault.lock"))
}

fn step(dir: &Path, store: Arc<dyn SecretStore + Send + Sync>) -> SecretStep {
    SecretStep {
        vault: vault(dir),
        store,
        values: vec![NewSecretOwned {
            field: "backends.b.env.K".to_owned(),
            value: WipedBytes::new(VALUE.to_vec()),
        }],
    }
}

/// `NEXT`, with backend `b`'s env naming the first reference.
fn with_ref(refs: &[String]) -> Vec<u8> {
    format!("{NEXT}    env:\n      K: \"{}\"\n", refs[0]).into_bytes()
}

/// A replacement of `START` that writes `compute`'s bytes and saves one
/// secret to the files store in `dir`.
fn secret_save(
    dir: &Path,
    expected: Expected,
    compute: impl FnOnce(&[u8], &[String]) -> Result<Vec<u8>, String> + Send + 'static,
) -> Replace {
    Replace {
        expected,
        compute: Box::new(compute),
        replaced: Replaced::Discard,
        secrets: Some(step(dir, Arc::new(FilesStore::new(dir)))),
    }
}

/// The live entries no config names, waiting out a save still settling.
fn live_entries(dir: &Path) -> Vec<String> {
    let store = FilesStore::new(dir);
    unused_entries(&vault(dir), &[&store], &BTreeSet::new())
        .expect("list entries")
        .into_iter()
        .map(|entry| entry.name)
        .collect()
}

#[tokio::test]
async fn a_save_that_stands_keeps_its_entries_and_writes_only_references() {
    let (dir, path, ctx) = setup();

    replace_detached(
        Arc::clone(&ctx),
        secret_save(dir.path(), Expected::Any, |_, refs| Ok(with_ref(refs))),
        WAIT,
    )
    .await
    .expect("the save stands");

    let written = read(&path);
    assert!(written.contains("K: \""), "{written}");
    assert!(
        !written.contains(std::str::from_utf8(VALUE).unwrap()),
        "the value never reaches gateway.yaml"
    );
    assert_eq!(live_entries(dir.path()).len(), 1);
    // The reference resolved to the stored bytes for the running backend.
    let running = ctx.live_config.get();
    assert_eq!(
        running.backends["b"].env.get("K").map(String::as_bytes),
        Some(VALUE)
    );
}

#[tokio::test]
async fn a_stale_view_creates_no_entry() {
    let (dir, path, ctx) = setup();
    let stale = Expected::Revision(FileRevision::of(b"another file"));

    let failure = replace_detached(
        ctx,
        secret_save(dir.path(), stale, |_, refs| Ok(with_ref(refs))),
        WAIT,
    )
    .await
    .expect_err("stale");

    assert!(matches!(failure, ReplaceError::Stale { .. }), "{failure:?}");
    assert_eq!(read(&path), START);
    assert_eq!(live_entries(dir.path()), Vec::<String>::new());
}

/// A store that refuses every write.
struct Refusing;

impl SecretStore for Refusing {
    fn kind(&self) -> StoreKind {
        StoreKind::Files
    }
    fn limit(&self) -> usize {
        1 << 16
    }
    fn probe(&self) -> Result<(), StoreError> {
        Ok(())
    }
    fn exists(&self, _: &str) -> Result<bool, StoreError> {
        Ok(false)
    }
    fn create(&self, _: &str, _: &[u8]) -> Result<String, StoreError> {
        Err(StoreError::Failed("refused for the test".to_owned()))
    }
    fn delete(&self, _: &str) -> Result<(), StoreError> {
        Ok(())
    }
}

#[tokio::test]
async fn a_store_refusal_writes_nothing() {
    let (dir, path, ctx) = setup();
    let save = Replace {
        expected: Expected::Any,
        compute: Box::new(|_, refs| Ok(with_ref(refs))),
        replaced: Replaced::Discard,
        secrets: Some(step(dir.path(), Arc::new(Refusing))),
    };

    let failure = replace_detached(ctx, save, WAIT)
        .await
        .expect_err("the store refuses");

    assert!(matches!(failure, ReplaceError::Secrets(_)), "{failure:?}");
    assert_eq!(read(&path), START);
    assert_eq!(live_entries(dir.path()), Vec::<String>::new());
}

#[tokio::test]
async fn a_refused_compute_discards_the_entries() {
    let (dir, path, ctx) = setup();

    let failure = replace_detached(
        ctx,
        secret_save(dir.path(), Expected::Any, |_, _| Err("no".to_owned())),
        WAIT,
    )
    .await
    .expect_err("refused");

    assert!(matches!(failure, ReplaceError::Refused(_)), "{failure:?}");
    assert_eq!(read(&path), START);
    assert_eq!(live_entries(dir.path()), Vec::<String>::new());
}

#[tokio::test]
async fn a_refused_reload_restores_the_original_and_discards() {
    let (dir, path, ctx) = setup();
    // A public URL over open tools: the posture check refuses the reload.
    let exposed = |refs: &[String]| {
        let mut bytes = b"server:\n  public_url: \"https://gw.public.test\"\n".to_vec();
        bytes.extend(with_ref(refs));
        bytes
    };

    let failure = replace_detached(
        ctx,
        secret_save(dir.path(), Expected::Any, move |_, refs| Ok(exposed(refs))),
        WAIT,
    )
    .await
    .expect_err("the posture refuses the reload");

    assert!(
        matches!(failure, ReplaceError::ReloadRefused(_)),
        "{failure:?}"
    );
    assert_eq!(read(&path), START);
    assert_eq!(live_entries(dir.path()), Vec::<String>::new());
}

#[tokio::test]
async fn bytes_that_name_no_entry_are_refused_and_discard() {
    let (dir, path, ctx) = setup();

    let failure = replace_detached(
        ctx,
        secret_save(dir.path(), Expected::Any, |current, _| Ok(current.to_vec())),
        WAIT,
    )
    .await
    .expect_err("nothing names the entries");

    assert!(matches!(failure, ReplaceError::Refused(_)), "{failure:?}");
    assert_eq!(read(&path), START);
    assert_eq!(live_entries(dir.path()), Vec::<String>::new());
}

/// The reload's load starts here, in the write task itself: a panic
/// unwinds that task after the rename.
fn panicking_spawn(_: Box<dyn FnOnce() + Send>) -> std::io::Result<()> {
    panic!("the write task dies after the rename");
}

/// A write task that dies after the rename leaves its entries live: the
/// file on disk may name them until the next lock holder recovers it.
#[tokio::test]
async fn a_panic_after_the_rename_keeps_the_entries() {
    let (dir, path, _) = setup();
    let running = crate::config::Config::load(Some(&path)).expect("config loads");
    let ctx = Arc::new(
        ReloadContext::new(
            path.clone(),
            Arc::new(LiveConfig::new(running)),
            Arc::new(crate::backend::BackendRegistry::new()),
            crate::config::FailsafeConfig::default(),
            std::time::Duration::from_secs(60),
        )
        .expect("the registry pairs with the config")
        .with_spawn(panicking_spawn),
    );

    let failure = replace_detached(
        ctx,
        secret_save(dir.path(), Expected::Any, |_, refs| Ok(with_ref(refs))),
        WAIT,
    )
    .await
    .expect_err("the write task died");

    assert!(matches!(failure, ReplaceError::Failed(_)), "{failure:?}");
    // The listing waits for the vault lock, so for the abandon to finish.
    assert_eq!(live_entries(dir.path()).len(), 1);
}

#[test]
fn entries_settle_by_the_final_result() {
    let journal = std::path::PathBuf::from("j");
    let err = |e: ReplaceError| -> Result<ReplaceOutcome, ReplaceError> { Err(e) };
    let cases = [
        (err(ReplaceError::Busy), Settle::Discard),
        (err(ReplaceError::Refused(String::new())), Settle::Discard),
        (err(ReplaceError::Stage(String::new())), Settle::Discard),
        (err(ReplaceError::Write(String::new())), Settle::Discard),
        (
            err(ReplaceError::ReloadRefused(String::new())),
            Settle::Discard,
        ),
        (
            err(ReplaceError::Unsupported(String::new())),
            Settle::Discard,
        ),
        (err(ReplaceError::Failed(String::new())), Settle::Abandon),
        (
            err(ReplaceError::RollbackFailed {
                journal: journal.clone(),
                error: String::new(),
            }),
            Settle::Abandon,
        ),
        (
            err(ReplaceError::Unconfirmed {
                journal,
                error: String::new(),
            }),
            Settle::Abandon,
        ),
    ];
    for (result, settle) in cases {
        assert_eq!(settle_for(&result), settle, "{result:?}");
    }
}

/// A refused reload whose rollback cannot finish leaves the journal staged:
/// the file on disk may name the entries until the next lock holder
/// recovers it, so they stay live and listed.
#[tokio::test]
async fn a_rollback_that_fails_keeps_the_entries() {
    use crate::config_persistence::journal::fault;
    let (dir, path, ctx) = setup();
    let exposed = |refs: &[String]| {
        let mut bytes = b"server:\n  public_url: \"https://gw.public.test\"\n".to_vec();
        bytes.extend(with_ref(refs));
        bytes
    };
    let armed = fault::set(&path, fault::Fault::FailJournalRemove);

    let failure = replace_detached(
        ctx,
        secret_save(dir.path(), Expected::Any, move |_, refs| Ok(exposed(refs))),
        WAIT,
    )
    .await
    .expect_err("the posture refuses the reload");
    drop(armed);

    assert!(
        matches!(failure, ReplaceError::RollbackFailed { .. }),
        "{failure:?}"
    );
    assert_eq!(live_entries(dir.path()).len(), 1);
}

/// A compute that panics dies before the rename: the old file stands, so
/// the guard deletes the entries.
#[tokio::test]
async fn a_panic_before_the_rename_discards_the_entries() {
    let (dir, path, ctx) = setup();

    let failure = replace_detached(
        ctx,
        secret_save(dir.path(), Expected::Any, |_, _| {
            panic!("the compute dies before the rename")
        }),
        WAIT,
    )
    .await
    .expect_err("the write task died");

    assert!(matches!(failure, ReplaceError::Failed(_)), "{failure:?}");
    assert_eq!(read(&path), START);
    // The discard is queued off the dying task; the listing waits for the
    // vault lock it holds until it finishes.
    assert_eq!(live_entries(dir.path()), Vec::<String>::new());
}
