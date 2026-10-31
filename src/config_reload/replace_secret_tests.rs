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
use crate::config_persistence::keyedit::{Segment, SlotId, Template};
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

/// The slot of the step's one secret: backend `b`'s env `K`.
fn k_slot() -> SlotId {
    SlotId(
        ["backends", "b", "env", "K"]
            .map(|k| Segment::Key(k.to_owned()))
            .to_vec(),
    )
}

/// `prefix`, then `NEXT` with backend `b`'s env `K` holding the secret's
/// slot; the writer fills it with the entry's reference.
fn slotted(prefix: &str) -> Template {
    let placeholder = Template::placeholder_for(&k_slot());
    let text = format!("{prefix}{NEXT}    env:\n      K: {placeholder}\n");
    Template::from_placeholders(text.into_bytes(), &[k_slot()]).expect("one slot")
}

fn with_slot() -> Template {
    slotted("")
}

/// A replacement of `START` that writes `compute`'s bytes and saves one
/// secret to the files store in `dir`.
fn secret_save(
    dir: &Path,
    expected: Expected,
    compute: impl FnOnce(&[u8]) -> Result<Template, String> + Send + 'static,
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
        secret_save(dir.path(), Expected::Any, |_| Ok(with_slot())),
        WAIT,
    )
    .await
    .expect("the save stands");

    let written = read(&path);
    // The writer fills the slot as a double-quoted scalar (escapes
    // included, so a Windows reference's backslashes survive).
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
        secret_save(dir.path(), stale, |_| Ok(with_slot())),
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
        compute: Box::new(|_| Ok(with_slot())),
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
        secret_save(dir.path(), Expected::Any, |_| Err("no".to_owned())),
        WAIT,
    )
    .await
    .expect_err("refused");

    assert!(matches!(failure, ReplaceError::Refused(_)), "{failure:?}");
    assert_eq!(read(&path), START);
    assert_eq!(live_entries(dir.path()), Vec::<String>::new());
}

/// A files store that counts the entries it is asked to create.
struct Counting {
    inner: FilesStore,
    creates: Arc<std::sync::atomic::AtomicUsize>,
}

impl SecretStore for Counting {
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
        self.creates
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.create(name, value)
    }
    fn delete(&self, name: &str) -> Result<(), StoreError> {
        self.inner.delete(name)
    }
}

/// API8.7 (U8 PR b): a save whose compute refuses creates no store entry at
/// all, not one created and then discarded: the compute runs before any
/// entry exists.
#[tokio::test]
async fn a_refused_compute_creates_no_entry() {
    let (dir, path, ctx) = setup();
    let creates = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let store = Counting {
        inner: FilesStore::new(dir.path()),
        creates: Arc::clone(&creates),
    };
    let save = Replace {
        expected: Expected::Any,
        compute: Box::new(|_| Err("no".to_owned())),
        replaced: Replaced::Discard,
        secrets: Some(step(dir.path(), Arc::new(store))),
    };

    let failure = replace_detached(ctx, save, WAIT)
        .await
        .expect_err("refused");

    assert!(matches!(failure, ReplaceError::Refused(_)), "{failure:?}");
    assert_eq!(read(&path), START);
    assert_eq!(
        creates.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "an entry was created for a save its compute refused"
    );
}

#[tokio::test]
async fn a_refused_reload_restores_the_original_and_discards() {
    let (dir, path, ctx) = setup();
    // A public URL over open tools: the posture check refuses the reload.
    let exposed = || slotted("server:\n  public_url: \"https://gw.public.test\"\n");

    let failure = replace_detached(
        ctx,
        secret_save(dir.path(), Expected::Any, move |_| Ok(exposed())),
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
        // A plain template with a secret step: the slot check refuses it
        // before any entry exists.
        secret_save(dir.path(), Expected::Any, |current| {
            Ok(Template::plain(current.to_vec()))
        }),
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
        secret_save(dir.path(), Expected::Any, |_| Ok(with_slot())),
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
    let exposed = || slotted("server:\n  public_url: \"https://gw.public.test\"\n");
    let armed = fault::set(&path, fault::Fault::FailJournalRemove);

    let failure = replace_detached(
        ctx,
        secret_save(dir.path(), Expected::Any, move |_| Ok(exposed())),
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

/// A compute that panics dies before any entry exists (it runs first): the
/// old file stands and the store holds nothing.
#[tokio::test]
async fn a_panic_before_the_rename_discards_the_entries() {
    let (dir, path, ctx) = setup();

    let failure = replace_detached(
        ctx,
        secret_save(dir.path(), Expected::Any, |_| {
            panic!("the compute dies before any entry exists")
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

/// An empty step saves nothing, so unchanged bytes are the usual no-op.
#[tokio::test]
async fn an_empty_secret_step_counts_as_none() {
    let (dir, path, ctx) = setup();
    let mut save = secret_save(dir.path(), Expected::Any, |current| {
        Ok(Template::plain(current.to_vec()))
    });
    if let Some(step) = save.secrets.as_mut() {
        step.values.clear();
    }

    replace_detached(ctx, save, WAIT)
        .await
        .expect("an unchanged save with nothing to store stands");

    assert_eq!(read(&path), START);
    assert_eq!(live_entries(dir.path()), Vec::<String>::new());
}

/// The writer writes a reference double-quoted, escapes included: one that
/// holds a backslash (every Windows path does) is read back by the real
/// config loader as the same reference, and resolves to the stored bytes.
#[tokio::test]
async fn a_reference_with_a_backslash_round_trips_through_the_loader() {
    let (dir, path, ctx) = setup();
    let store_dir = dir.path().join("we\\ird");
    std::fs::create_dir_all(&store_dir).expect("store dir");
    let save = Replace {
        expected: Expected::Any,
        compute: Box::new(|_| Ok(with_slot())),
        replaced: Replaced::Discard,
        secrets: Some(step(dir.path(), Arc::new(FilesStore::new(&store_dir)))),
    };

    replace_detached(Arc::clone(&ctx), save, WAIT)
        .await
        .expect("the save stands");

    let written = read(&path);
    let doc: crate::yaml::Value = crate::yaml::from_str(&written).expect("parses");
    let reference = doc["backends"]["b"]["env"]["K"]
        .as_str()
        .expect("a reference");
    assert!(
        reference.contains('\\'),
        "the backslash was lost: {reference}"
    );
    let loaded = crate::config::Config::load(Some(&path)).expect("the loader reads it");
    assert_eq!(
        loaded.backends["b"].env.get("K").map(String::as_bytes),
        Some(VALUE),
        "the reference no longer names the stored entry"
    );
}

/// How the second create goes wrong.
#[derive(Clone, Copy)]
enum SecondCreate {
    Errs,
    Panics,
}

/// A files store whose second create fails, after the first has stored.
struct FailsSecond {
    inner: FilesStore,
    creates: std::sync::atomic::AtomicUsize,
    how: SecondCreate,
}

impl SecretStore for FailsSecond {
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
        if self
            .creates
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            == 1
        {
            match self.how {
                SecondCreate::Errs => {
                    return Err(StoreError::Failed("the second create fails".to_owned()));
                }
                SecondCreate::Panics => panic!("the second create dies"),
            }
        }
        self.inner.create(name, value)
    }
    fn delete(&self, name: &str) -> Result<(), StoreError> {
        self.inner.delete(name)
    }
}

/// The slots for `K` and `J` under backend `b`'s env.
fn two_slot_save(dir: &Path, store: Arc<dyn SecretStore + Send + Sync>) -> Replace {
    let slot = |k: &str| {
        SlotId(
            ["backends", "b", "env", k]
                .map(|s| Segment::Key(s.to_owned()))
                .to_vec(),
        )
    };
    let text = format!(
        "{NEXT}    env:\n      K: {}\n      J: {}\n",
        Template::placeholder_for(&slot("K")),
        Template::placeholder_for(&slot("J"))
    );
    let template =
        Template::from_placeholders(text.into_bytes(), &[slot("K"), slot("J")]).expect("two slots");
    let value = |field: &str| NewSecretOwned {
        field: field.to_owned(),
        value: WipedBytes::new(VALUE.to_vec()),
    };
    Replace {
        expected: Expected::Any,
        compute: Box::new(move |_| Ok(template)),
        replaced: Replaced::Discard,
        secrets: Some(SecretStep {
            vault: vault(dir),
            store,
            values: vec![value("backends.b.env.K"), value("backends.b.env.J")],
        }),
    }
}

/// The window W1 opened: entries exist, the file is not yet renamed. A
/// second secret that fails, by error or by panic, leaves no first entry
/// behind and the file as it was.
#[tokio::test]
async fn a_second_secret_that_fails_leaves_no_first_entry() {
    for how in [SecondCreate::Errs, SecondCreate::Panics] {
        let (dir, path, ctx) = setup();
        let store = FailsSecond {
            inner: FilesStore::new(dir.path()),
            creates: std::sync::atomic::AtomicUsize::new(0),
            how,
        };

        let result = replace_detached(ctx, two_slot_save(dir.path(), Arc::new(store)), WAIT).await;

        assert!(result.is_err(), "the save stood");
        assert_eq!(read(&path), START);
        assert_eq!(
            live_entries(dir.path()),
            Vec::<String>::new(),
            "the first entry was left behind"
        );
    }
}

/// Entries exist and filling them in fails (a slot inside single quotes
/// reads back as another string): refused, the entries removed, the file
/// as it was.
#[tokio::test]
async fn a_fill_that_fails_after_the_entries_removes_them() {
    let (dir, path, ctx) = setup();
    let template = || {
        let text = format!(
            "{NEXT}    env:\n      K: '{}'\n",
            Template::placeholder_for(&k_slot())
        );
        Template::from_placeholders(text.into_bytes(), &[k_slot()]).expect("a bare slot")
    };

    let failure = replace_detached(
        ctx,
        secret_save(dir.path(), Expected::Any, move |_| Ok(template())),
        WAIT,
    )
    .await
    .expect_err("the fill refuses");

    assert!(matches!(failure, ReplaceError::Refused(_)), "{failure:?}");
    assert_eq!(read(&path), START);
    assert_eq!(live_entries(dir.path()), Vec::<String>::new());
}

/// W3: the filled file must fit the parser's limit, counting each slot at
/// its escaped worst case (a control byte escapes to four); a template that
/// could outgrow it is refused before any entry is created.
#[tokio::test]
async fn the_size_bound_counts_escaped_references_before_any_entry() {
    let (dir, path, ctx) = setup();
    let creates = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let store = Counting {
        inner: FilesStore::new(dir.path()),
        creates: Arc::clone(&creates),
    };
    let worst = 4 * crate::secret_store::MAX_REFERENCE_LEN + 2;
    let body = format!(
        "{NEXT}    env:\n      K: {}\n",
        Template::placeholder_for(&k_slot())
    );
    // One byte past what a worst-case reference may still fill into.
    let pad = crate::yaml::MAX_YAML_BYTES - worst + 1 - body.len() - 3;
    let text = format!("# {}\n{body}", "x".repeat(pad));
    let template = Template::from_placeholders(text.into_bytes(), &[k_slot()]).expect("one slot");
    let save = Replace {
        expected: Expected::Any,
        compute: Box::new(move |_| Ok(template)),
        replaced: Replaced::Discard,
        secrets: Some(step(dir.path(), Arc::new(store))),
    };

    let failure = replace_detached(ctx, save, WAIT)
        .await
        .expect_err("too large");

    assert!(matches!(failure, ReplaceError::Refused(_)), "{failure:?}");
    assert_eq!(read(&path), START);
    assert_eq!(
        creates.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "an entry was created"
    );
}

/// A files store that returns a reference longer than any store may.
struct LongReference(FilesStore);

impl SecretStore for LongReference {
    fn kind(&self) -> StoreKind {
        self.0.kind()
    }
    fn limit(&self) -> usize {
        self.0.limit()
    }
    fn probe(&self) -> Result<(), StoreError> {
        self.0.probe()
    }
    fn exists(&self, name: &str) -> Result<bool, StoreError> {
        self.0.exists(name)
    }
    fn create(&self, name: &str, value: &[u8]) -> Result<String, StoreError> {
        let reference = self.0.create(name, value)?;
        let pad = crate::secret_store::MAX_REFERENCE_LEN + 1 - reference.len();
        Ok(format!("{reference}{}", "x".repeat(pad)))
    }
    fn delete(&self, name: &str) -> Result<(), StoreError> {
        self.0.delete(name)
    }
}

/// The reference-length bound the size check counts on is enforced: a store
/// that returns a longer reference is refused before the file is written,
/// and the entry it made is removed.
#[tokio::test]
async fn a_reference_longer_than_the_bound_is_refused_and_removed() {
    let (dir, path, ctx) = setup();
    let save = Replace {
        expected: Expected::Any,
        compute: Box::new(|_| Ok(with_slot())),
        replaced: Replaced::Discard,
        secrets: Some(step(
            dir.path(),
            Arc::new(LongReference(FilesStore::new(dir.path()))),
        )),
    };

    let failure = replace_detached(ctx, save, WAIT)
        .await
        .expect_err("too long");

    assert!(matches!(failure, ReplaceError::Refused(_)), "{failure:?}");
    assert_eq!(read(&path), START);
    assert_eq!(live_entries(dir.path()), Vec::<String>::new());
}

/// Two secrets for one field match one slot as sets but not as lists: the
/// second entry would be named by no field, so the save is refused before
/// any entry exists.
#[tokio::test]
async fn two_secrets_for_one_field_are_refused_before_any_entry() {
    let (dir, path, ctx) = setup();
    let creates = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let store = Counting {
        inner: FilesStore::new(dir.path()),
        creates: Arc::clone(&creates),
    };
    let mut twice = step(dir.path(), Arc::new(store));
    twice.values.push(NewSecretOwned {
        field: "backends.b.env.K".to_owned(),
        value: WipedBytes::new(VALUE.to_vec()),
    });
    let save = Replace {
        expected: Expected::Any,
        compute: Box::new(|_| Ok(with_slot())),
        replaced: Replaced::Discard,
        secrets: Some(twice),
    };

    let failure = replace_detached(ctx, save, WAIT)
        .await
        .expect_err("refused");

    assert!(matches!(failure, ReplaceError::Refused(_)), "{failure:?}");
    assert_eq!(read(&path), START);
    assert_eq!(creates.load(std::sync::atomic::Ordering::SeqCst), 0);
}
