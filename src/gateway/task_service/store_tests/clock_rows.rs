// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202 part 2 (P2), T13a and T13b: loading a stored live row measures
//! the failure it could settle as. That measure is about width, not time: it
//! needs no clock and must not depend on one.

use super::*;

/// The largest fallback record, measured with the widest timestamp chrono can
/// print for the settle instant, `+262142-12-31T23:59:59.999999999Z`
/// (expanded year, nine fractional digits) and the largest revision, for the
/// fixture task. Measured on the first run.
const WIDEST_FALLBACK_BYTES: usize = 843;
const WIDEST_STAMP: &str = "+262142-12-31T23:59:59.999999999Z";

fn limits(record_bytes: usize) -> StoreLimits {
    StoreLimits {
        record_bytes,
        ..StoreLimits::default()
    }
}

/// A store directory holding one live (working) row, closed.
async fn store_with_a_live_row(task: &Task) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = TaskStore::open(&path, limits(4 * 1024)).await.unwrap();
    store
        .create(PreparedTask::for_test(task, OWNER, 1))
        .await
        .unwrap();
    store.close().await.unwrap();
    (dir, path)
}

/// T13a (guard): a stored live row loads and reads on a clock before 1970.
#[tokio::test]
async fn t13a_a_live_row_loads_and_reads_on_an_unreadable_clock() {
    let task = task();
    let (_dir, path) = store_with_a_live_row(&task).await;
    let _clock = crate::clock::test_clock::before_epoch();
    let store = TaskStore::open(&path, limits(4 * 1024))
        .await
        .expect("loads");
    assert!(store.get(OWNER, task.id()).is_ok(), "the row reads");
    store.close().await.unwrap();
}

/// T13b (MIK-8202 SIZING rule, P2 row 14): an ordinary dated live row is
/// measured with the widest encodable timestamp, so a record budget one byte
/// under that measure refuses the row at load. Surviving mutant on record:
/// sample the clock, then ignore it. Mutant killed: width taken from `now`.
#[tokio::test]
async fn t13b_load_sizes_the_fallback_at_the_widest_timestamp() {
    // GIVEN: the fallback of the fixture row, re-encoded at the widest stamp
    let task = task();
    let (_, mut fallback) = created_and_fallback(&task).await;
    fallback["revision"] = json!(u64::MAX);
    fallback["model"]["task"]["lastUpdatedAt"] = json!(WIDEST_STAMP);
    let widest = encoded_len(&fallback);
    assert_eq!(
        widest, WIDEST_FALLBACK_BYTES,
        "the literal is the widest size"
    );
    let (_dir, path) = store_with_a_live_row(&task).await;
    // WHEN / THEN: one byte short refuses; the exact size loads
    let short = TaskStore::open(&path, limits(widest - 1)).await;
    assert!(
        matches!(short, Err(StoreError::Capacity)),
        "{:?}",
        short.map(|_| ())
    );
    let exact = TaskStore::open(&path, limits(widest)).await.expect("fits");
    exact.close().await.unwrap();
}
