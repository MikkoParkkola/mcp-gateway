// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The record-size cap at its boundary: the reader refuses one byte past it,
//! and a record of exactly the cap is accepted on both write paths.

use super::*;

#[test]
fn store_04_the_record_reader_refuses_one_byte_past_its_cap() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("payload");

    // Exactly at the cap is accepted, whole.
    fs::write(&path, vec![b'x'; 64]).unwrap();
    let mut file = fs::File::open(&path).unwrap();
    assert_eq!(read_bounded(&mut file, 64).unwrap(), vec![b'x'; 64]);

    // One byte past it is refused as over-budget — not parsed, not truncated
    // into something that looks like a smaller record.
    fs::write(&path, vec![b'x'; 65]).unwrap();
    let mut file = fs::File::open(&path).unwrap();
    assert_eq!(
        read_bounded(&mut file, 64).unwrap_err(),
        StoreError::Capacity
    );

    // A zero cap still refuses rather than accepting an empty read of a file
    // that has content.
    let mut file = fs::File::open(&path).unwrap();
    assert_eq!(
        read_bounded(&mut file, 0).unwrap_err(),
        StoreError::Capacity
    );
}

/// Serialize one creation and one settlement under a generous cap and report
/// the exact byte sizes the store writes for each.
///
/// Measured rather than computed on purpose: a size calculation would agree
/// with today's serialization and drift silently the day the record gains a
/// field, which is the failure mode a boundary case exists to prevent.
async fn measured_record_sizes(root: &std::path::Path) -> (usize, usize) {
    let path = root.join("measure");
    let store = open(&path).await;
    let task = task();
    store.create(padded(&task, OWNER, 1)).await.unwrap();
    let record = path.join(format!("{}.json", task.id()));
    let created = usize::try_from(fs::metadata(&record).unwrap().len()).unwrap();
    store
        .transition(OWNER, task.id(), 1, settlement(), at(1))
        .await
        .unwrap();
    let settled = usize::try_from(fs::metadata(&record).unwrap().len()).unwrap();
    store.close().await.unwrap();
    assert!(
        created + 1 < settled,
        "the settled record must be more than one byte larger, or the under-cap \
         half of this case would be testing the same number twice"
    );
    // The row is padded with a target its fallback drops, so one
    // byte under the cap is refused by the size check, not the fallback room.
    let (_, fallback) = created_and_fallback_of(&task, padded(&task, OWNER, 1)).await;
    assert!(
        widest(fallback) < created,
        "the padding outgrows the fallback"
    );
    (created, settled)
}

fn settlement() -> TaskTransition {
    TaskTransition::Complete(json!({"content":[{"type":"text","text":"settled"}]}))
}

fn capped(bytes: usize) -> StoreLimits {
    StoreLimits {
        record_bytes: bytes,
        ..StoreLimits::default()
    }
}

#[tokio::test]
async fn store_04_a_record_of_exactly_the_cap_is_accepted_on_both_write_paths() {
    let dir = tempfile::tempdir().unwrap();
    let (created, settled) = measured_record_sizes(dir.path()).await;

    // `record_bytes` is an INCLUSIVE maximum: §13.3 calls it "512 KiB maximum
    // serialized record", and `read_bounded` already refuses only at cap+1. A
    // record landing exactly on the cap is legal on every write path, and both
    // of these sites were mutable to `>=` without any case noticing.

    // Creation, exactly at the cap — pins store.rs `admit`.
    let exact_create = dir.path().join("exact-create");
    let store = TaskStore::open(&exact_create, capped(created))
        .await
        .unwrap();
    let task = task();
    store
        .create(padded(&task, OWNER, 1))
        .await
        .expect("a creation of exactly the cap is within an inclusive maximum");
    store.close().await.unwrap();

    // Settlement, exactly at the cap — pins store.rs `transition_blocking`.
    // `self::task()` from here on: the binding above shadows the fixture
    // function, so a bare `task()` would try to call a `Task` value.
    let exact_settle = dir.path().join("exact-settle");
    let store = TaskStore::open(&exact_settle, capped(settled))
        .await
        .unwrap();
    let task = self::task();
    store.create(padded(&task, OWNER, 1)).await.unwrap();
    let done = store
        .transition(OWNER, task.id(), 1, settlement(), at(1))
        .await
        .expect("a settlement of exactly the cap is within an inclusive maximum");
    assert_eq!(done.revision, 2);
    assert_eq!(done.task.status(), TaskStatus::Completed);
    store.close().await.unwrap();

    // One byte under each, refused. Without this half the case would pass
    // against a store with no cap at all — it would raise a ceiling rather than
    // pin a boundary, and an oracle that cannot fail is the thing being avoided.
    let under_create = dir.path().join("under-create");
    let store = TaskStore::open(&under_create, capped(created - 1))
        .await
        .unwrap();
    assert_eq!(
        store
            .create(padded(&self::task(), OWNER, 1))
            .await
            .unwrap_err(),
        StoreError::Capacity
    );
    store.close().await.unwrap();

    let under_settle = dir.path().join("under-settle");
    let store = TaskStore::open(&under_settle, capped(settled - 1))
        .await
        .unwrap();
    let task = self::task();
    store.create(padded(&task, OWNER, 1)).await.unwrap();
    assert_eq!(
        store
            .transition(OWNER, task.id(), 1, settlement(), at(1))
            .await
            .unwrap_err(),
        StoreError::Capacity
    );
    assert_eq!(store.get(OWNER, task.id()).unwrap().revision, 1);
    store.close().await.unwrap();
}
