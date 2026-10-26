// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The two-phase save: keep, discard, abandon and an undecided drop, the
//! deadline on the vault lock, the lock order, and write times in the unused
//! listing.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use crate::secret_store::tests::{Fake, count, index_text, three, vault as fresh_vault};
use crate::secret_store::{
    FilesStore, LOCK_WAIT, NewSecretOwned, PendingSecrets, SaveError, SecretStore, StoreError,
    StoreKind, UnusedEntry, Vault, create_secrets, save_secrets, unused_entries,
};
use crate::wiped_bytes::WipedBytes;

fn owned(field: &str, value: &[u8]) -> NewSecretOwned {
    NewSecretOwned {
        field: field.to_owned(),
        value: WipedBytes::new(value.to_vec()),
    }
}

fn two() -> Vec<NewSecretOwned> {
    vec![
        owned("auth.bearer_token", b"one"),
        owned("key_server.admin_token", b"two"),
    ]
}

fn soon() -> Instant {
    Instant::now() + LOCK_WAIT
}

fn pending(vault: &Vault, store: &Arc<Fake>) -> PendingSecrets {
    create_secrets(vault.clone(), store.clone(), &two(), soon()).expect("phase one")
}

fn lock_is_free(vault: &Vault) -> bool {
    crate::fs_lock::ExclusiveFileLock::try_acquire(vault.lock_path()).is_ok()
}

fn live_names(dir: &std::path::Path) -> Vec<String> {
    crate::secret_store::index::Index::at(dir)
        .live()
        .unwrap()
        .into_iter()
        .map(|entry| entry.name)
        .collect()
}

#[test]
fn keep_leaves_the_entries_live_and_frees_the_lock() {
    let (dir, vault) = fresh_vault();
    let store = Arc::new(Fake::new());
    let saved = pending(&vault, &store);
    assert_eq!(saved.refs().len(), 2);
    assert!(!lock_is_free(&vault), "phase one released the vault lock");
    saved.keep();
    assert_eq!(store.names().len(), 2);
    assert_eq!(live_names(dir.path()).len(), 2);
    assert!(lock_is_free(&vault));
}

#[test]
fn discard_removes_only_this_saves_entries_and_reports_what_stays() {
    let (dir, vault) = fresh_vault();
    let store = Arc::new(Fake::new());
    pending(&vault, &store).discard();
    assert!(store.names().is_empty(), "{:?}", store.names());
    assert!(live_names(dir.path()).is_empty());
    assert!(lock_is_free(&vault));

    // A delete that fails leaves the name live, so the listing still shows it.
    let (dir, vault) = fresh_vault();
    let mut failing = Fake::new();
    failing.fail_delete = true;
    let store = Arc::new(failing);
    let kept = pending(&vault, &store).discard();
    assert_eq!(kept.len(), 2, "{kept:?}");
    assert_eq!(live_names(dir.path()).len(), 2);
}

#[test]
fn an_undecided_drop_discards() {
    let (dir, vault) = fresh_vault();
    let store = Arc::new(Fake::new());
    drop(pending(&vault, &store));
    assert!(
        store.names().is_empty(),
        "a dropped save left entries: {:?}",
        store.names()
    );
    assert!(live_names(dir.path()).is_empty());
    assert!(lock_is_free(&vault));
}

#[test]
fn abandon_keeps_the_entries_for_an_unconfirmed_rollback() {
    let (dir, vault) = fresh_vault();
    let store = Arc::new(Fake::new());
    pending(&vault, &store).abandon();
    assert_eq!(store.names().len(), 2);
    assert_eq!(live_names(dir.path()).len(), 2);
    assert!(lock_is_free(&vault));
}

#[test]
fn a_panic_inside_the_commit_removes_this_saves_entries() {
    let (_dir, vault) = fresh_vault();
    let store = Fake::new();
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = save_secrets(&vault, &store, &three(), |_| -> Result<(), ()> {
            panic!("the commit panicked")
        });
    }));
    assert!(unwound.is_err());
    assert!(store.names().is_empty(), "{:?}", store.names());
    assert_eq!(count(&store.calls(), "delete"), 3);
}

#[test]
fn an_async_commit_that_fails_discards_across_threads() {
    let (_dir, vault) = fresh_vault();
    let store = Arc::new(Fake::new());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let (phase_vault, phase_store) = (vault.clone(), store.clone());
        let saved = tokio::task::spawn_blocking(move || {
            create_secrets(phase_vault, phase_store, &two(), soon()).expect("phase one")
        })
        .await
        .unwrap();
        let reload = tokio::spawn(async { Err::<(), &str>("refused on posture") });
        assert!(reload.await.unwrap().is_err());
        let kept = tokio::task::spawn_blocking(move || saved.discard())
            .await
            .unwrap();
        assert!(kept.is_empty());
    });
    assert!(store.names().is_empty(), "{:?}", store.names());
}

#[test]
fn a_held_vault_lock_refuses_at_the_deadline_before_any_store_call() {
    let (dir, vault) = fresh_vault();
    let _held = crate::fs_lock::ExclusiveFileLock::try_acquire(vault.lock_path()).expect("hold");
    let store = Arc::new(Fake::new());
    let started = Instant::now();
    let refused = create_secrets(vault.clone(), store.clone(), &two(), started)
        .err()
        .expect("refused");
    // Refused at the caller's deadline, not after the 30 s default.
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "waited past the deadline: {:?}",
        started.elapsed()
    );
    match refused {
        SaveError::Refused(StoreError::Failed(why)) => {
            assert!(why.contains("held the vault lock"), "{why}");
        }
        other => panic!("{other:?}"),
    }
    assert!(
        store.calls().is_empty(),
        "a store call before the lock: {:?}",
        store.calls()
    );
    assert!(index_text(dir.path()).is_empty());
}

#[test]
fn the_unused_listing_carries_write_times_in_index_order() {
    let (dir, vault) = fresh_vault();
    let store = FilesStore::new(dir.path());
    let one = save_secrets(&vault, &store, &three()[..1], |r| Ok::<_, ()>(r[0].clone())).unwrap();
    // A line with no time, as a clock before the epoch writes it, stays in place.
    let index = dir.path().join("secrets-index.jsonl");
    let mut text = std::fs::read_to_string(&index).unwrap();
    let zero = "mcp-gateway.zero.0.0000000000000000";
    writeln!(text, "{{\"name\":\"{zero}\",\"store\":\"files\"}}").unwrap();
    std::fs::write(&index, text).unwrap();
    std::fs::write(dir.path().join("secrets").join(zero), "z\n").unwrap();
    let two = save_secrets(&vault, &store, &three()[..1], |r| Ok::<_, ()>(r[0].clone())).unwrap();
    let unused: Vec<UnusedEntry> =
        unused_entries(&vault, &[&store], &BTreeSet::new()).expect("listed");
    let base = |r: &str| r.rsplit('/').next().unwrap().to_owned();
    let names: Vec<&str> = unused.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec![base(&one).as_str(), zero, base(&two).as_str()]);
    assert_eq!(unused[1].created_at_ms, 0);
    assert!(unused[0].created_at_ms > 0 && unused[2].created_at_ms > 0);
    assert!(unused.iter().all(|e| e.store == StoreKind::Files));
}

#[test]
fn a_crash_between_delete_and_removal_line_is_filtered_by_exists() {
    let (dir, vault) = fresh_vault();
    let store = Arc::new(Fake::new());
    let saved = pending(&vault, &store);
    // The deletes succeed; the removal lines cannot be written, as after a
    // crash between the two.
    let index = dir.path().join("secrets-index.jsonl");
    let mut readonly = std::fs::metadata(&index).unwrap().permissions();
    readonly.set_readonly(true);
    std::fs::set_permissions(&index, readonly).unwrap();
    let kept = saved.discard();
    assert!(kept.is_empty());
    assert!(store.names().is_empty());
    assert_eq!(
        live_names(dir.path()).len(),
        2,
        "the removal lines were written"
    );
    let stores: [&dyn SecretStore; 1] = [store.as_ref()];
    let unused = unused_entries(&vault, &stores, &BTreeSet::new()).expect("listed");
    assert!(unused.is_empty(), "a gone entry was listed: {unused:?}");
}

#[test]
fn a_two_phase_save_and_a_secret_only_save_both_complete_under_contention() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let (dir, vault) = fresh_vault();
    let config = dir.path().join("gateway.yaml");
    std::fs::write(&config, "{}\n").unwrap();
    let store = Arc::new(Fake::new());
    let held = Arc::new(Barrier::new(2));
    let kept = Arc::new(AtomicBool::new(false));
    let started = Arc::new(AtomicBool::new(false));
    let writer = {
        let (vault, store, held, kept, started) = (
            vault.clone(),
            store.clone(),
            held.clone(),
            kept.clone(),
            started.clone(),
        );
        std::thread::spawn(move || {
            // Reload, then the config sidecar, then the vault: the global order.
            let reload = std::sync::Mutex::new(());
            let _reload = reload.lock().unwrap();
            let _sidecar = crate::config_persistence::lock::lock_config_blocking(
                &config,
                Instant::now() + LOCK_WAIT,
                |_| {},
            )
            .expect("config lock");
            let saved = create_secrets(vault, store, &two(), soon()).expect("phase one");
            // The secret-only save starts while this one holds the vault lock.
            held.wait();
            // Keep only once the other save has begun: it is then at, or on
            // its way to, the vault lock this save still holds.
            while !started.load(Ordering::SeqCst) {
                std::thread::yield_now();
            }
            kept.store(true, Ordering::SeqCst);
            saved.keep();
        })
    };
    let secret_only = {
        let (vault, store, held, kept) = (vault.clone(), store.clone(), held.clone(), kept.clone());
        std::thread::spawn(move || {
            held.wait();
            started.store(true, Ordering::SeqCst);
            save_secrets(&vault, store.as_ref(), &three(), |_| {
                // Its entries exist only once the vault lock was free, after
                // the two-phase save kept: without the lock this runs first.
                assert!(
                    kept.load(Ordering::SeqCst),
                    "both saves held the vault at once"
                );
                Ok::<_, ()>(())
            })
            .expect("saved");
        })
    };
    writer.join().expect("the two-phase save");
    secret_only.join().expect("the secret-only save");
    assert_eq!(store.names().len(), 5);
}

#[test]
fn the_store_core_takes_no_lock_but_the_vault_lock() {
    for (name, text) in [
        ("mod.rs", include_str!("mod.rs")),
        ("save.rs", include_str!("save.rs")),
        ("pending.rs", include_str!("pending.rs")),
        ("files.rs", include_str!("files.rs")),
        ("index.rs", include_str!("index.rs")),
    ] {
        for call in [
            "lock_config(",
            "lock_config_blocking(",
            "try_acquire(",
            "::acquire(",
            "lease(",
        ] {
            assert!(!text.contains(call), "{name} takes another lock: {call}");
        }
    }
    let sites: usize = [
        include_str!("mod.rs"),
        include_str!("save.rs"),
        include_str!("pending.rs"),
        include_str!("files.rs"),
        include_str!("index.rs"),
    ]
    .iter()
    .map(|text| text.matches("lock_file_blocking(").count())
    .sum();
    assert_eq!(sites, 1, "one vault lock site in the store core");
}

#[test]
fn a_panic_inside_a_store_call_rolls_phase_one_back() {
    let (_dir, vault) = fresh_vault();
    let mut store = Fake::new();
    store.panic_create = Some(2);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = save_secrets(&vault, &store, &three(), |_| Ok::<_, ()>(()));
    }));
    assert!(unwound.is_err(), "the store did not panic");
    assert!(
        store.names().is_empty(),
        "phase one left entries: {:?}",
        store.names()
    );
    assert_eq!(count(&store.calls(), "delete"), 1, "{:?}", store.calls());
}
