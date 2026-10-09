// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A repaired sealed row that cannot be served again stays sealed (admission
//! refusal, duplicate task or key, record budget); and expiry that cannot
//! remove a record keeps the task and its dedupe entry.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use super::admission::{services, settled_task};
use super::support::*;
use super::*;

fn private(path: &Path) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn row_of(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.json"))
}

/// Damage after the admission and model members: the envelope still reads
/// its key and task id, but the full record no longer restores.
fn key_only(text: &str) -> String {
    let end = text.rfind('}').expect("a record object");
    format!("{},\"tail\":@{}", &text[..end], &text[end..])
}

/// What one re-read of `name` did: sealed rows left, task ids handed to
/// import, rows served again.
struct Swept {
    sealed: usize,
    reserved: usize,
    imported: Vec<String>,
    served: usize,
}

/// Seal `name`, then re-read it; `accept` is admission's answer to import.
async fn sweep(store: &TaskStore, name: &str, accept: bool) -> Swept {
    store.seal_for_test(name);
    let imported = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&imported);
    let (sealed, served) = store
        .reread_sealed(
            move |_, id| {
                sink.lock().unwrap().push(id);
                accept
            },
            |_| None,
        )
        .await;
    let imported = imported.lock().unwrap().clone();
    Swept {
        sealed,
        reserved: store.skipped_records().reserved,
        imported,
        served: served.len(),
    }
}

/// A key that reads while its task does not is kept only if admission takes
/// it; a refusal keeps the row sealed and reserves nothing.
#[tokio::test]
async fn a_key_only_row_refused_by_admission_stays_sealed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let (id, _) = settled_task(&store, &services(), "k-refused").await;
    let row = row_of(&path, &id);
    let text = std::fs::read_to_string(&row).unwrap();
    std::fs::write(&row, key_only(&text)).unwrap();
    private(&row);

    let swept = sweep(&store, &format!("{id}.json"), false).await;

    assert_eq!(swept.imported, vec![id], "admission was asked for the key");
    assert_eq!((swept.sealed, swept.reserved), (1, 0));
}

/// A repaired row whose task is already served is not applied twice.
#[tokio::test]
async fn a_repaired_row_for_a_served_task_stays_sealed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let (id, binding) = settled_task(&store, &services(), "k-served").await;

    let swept = sweep(&store, &format!("{id}.json"), true).await;

    assert_eq!((swept.sealed, swept.served), (1, 0));
    assert!(
        swept.imported.is_empty(),
        "no key is imported for a duplicate"
    );
    assert!(store.get(binding.principal_digest(), &id).is_ok());
}

/// A repaired row whose task id is already reserved by a key-only row is a
/// duplicate of that key: it stays sealed and the reservation is untouched.
#[tokio::test]
async fn a_repaired_row_for_a_reserved_key_stays_sealed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let (id, _) = settled_task(&store, &services(), "k-reserved").await;
    store.close().await.unwrap();
    let row = row_of(&path, &id);
    let original = std::fs::read(&row).unwrap();
    std::fs::write(
        &row,
        key_only(&String::from_utf8(original.clone()).unwrap()),
    )
    .unwrap();
    let store = open(&path).await;
    assert_eq!(store.skipped_records().reserved, 1, "premise: key reserved");

    std::fs::write(&row, &original).unwrap();
    let swept = sweep(&store, &format!("{id}.json"), true).await;

    assert_eq!((swept.sealed, swept.reserved, swept.served), (1, 1, 0));
    assert!(swept.imported.is_empty());
}

/// A repaired row that reads within the record budget but serializes past it
/// is not rewritten: it stays sealed, unimported, and its bytes are untouched.
#[tokio::test]
async fn a_repaired_row_that_rewrites_past_the_budget_stays_sealed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let (id, binding) = settled_task(&store, &services(), "k-wide").await;
    store.close().await.unwrap();
    let row = row_of(&path, &id);
    let text = std::fs::read_to_string(&row).unwrap();
    // A defaulted member the writer always emits: absent, the row reads
    // smaller than the bytes a rewrite produces.
    let shrunk = text.replacen("\"dispatched\":false,", "", 1);
    assert_ne!(shrunk, text, "fixture shape");
    let sealed = shrunk.replacen("\"admission\":{", "\"admission\":@", 1);
    assert_ne!(sealed, shrunk, "fixture shape");
    std::fs::write(&row, &sealed).unwrap();
    let limits = StoreLimits {
        record_bytes: shrunk.len(),
        ..StoreLimits::default()
    };
    let store = TaskStore::open(&path, limits).await.unwrap();
    assert_eq!(store.skipped_records().sealed, 1, "premise: row sealed");

    std::fs::write(&row, &shrunk).unwrap();
    let swept = sweep(&store, &format!("{id}.json"), true).await;

    assert_eq!((swept.sealed, swept.served), (1, 0));
    assert!(swept.imported.is_empty(), "nothing imported before durable");
    assert_eq!(std::fs::read_to_string(&row).unwrap(), shrunk);
    assert_eq!(
        store.get(binding.principal_digest(), &id).unwrap_err(),
        StoreError::NotFound
    );
}

/// Expiry that cannot remove the record (anything but "already gone") fails
/// as storage and leaves the task, its file and its dedupe entry in place.
#[tokio::test]
async fn expiry_that_cannot_remove_the_record_keeps_everything() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let admission = services();
    let store = open(&path).await;
    let (id, binding) = settled_task(&store, &admission, "k-stuck").await;
    let row = row_of(&path, &id);
    std::fs::remove_file(&row).unwrap();
    std::fs::create_dir(&row).unwrap();
    let held = admission.snapshot();

    let refused = store.expire(&id, 2, &admission).await;

    assert_eq!(refused.unwrap_err(), StoreError::Storage);
    assert!(row.is_dir(), "the path was not touched");
    assert_eq!(admission.snapshot(), held, "dedupe capacity is kept");
    assert!(store.get(binding.principal_digest(), &id).is_ok());
}
