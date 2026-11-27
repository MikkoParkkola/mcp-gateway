// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Removing a subscription reports success only once its unlink has reached
//! disk. These rows fail the directory sync on purpose (`sync_fault`) and
//! check what the caller hears; cutting power is out of reach in a unit test.

use chrono::{DateTime, Utc};

use super::super::super::Store;
use super::{TAIL, open_with, record};
use crate::events::outbox::OutboxCaps;
use crate::events::records::sync_fault;

const OUTBOX: OutboxCaps = OutboxCaps {
    global: 10,
    per_subscription: 10,
};

/// A fixed instant: these rows need no wall clock.
fn t0() -> DateTime<Utc> {
    DateTime::from_timestamp(1_900_000_000, 0).expect("instant")
}

/// Failed sync: an error, the row kept. Failed sync again on the retry (the
/// file is gone by then): still an error. A third try that syncs: removed.
#[test]
fn unsub1_a_failed_directory_sync_is_never_reported_as_unsubscribed() {
    let dir = tempfile::tempdir().expect("dir");
    let t0 = t0();
    let subs = dir.path().join("subs");
    let store = open_with(dir.path(), t0, &["s1"]);
    // Something in the outbox, so the removal cancels it before the unlink;
    // that work touches the outbox folder, never the armed one.
    store.enqueue(record("a", "s1", t0), OUTBOX).expect("io");
    sync_fault::arm(&subs, 1);
    let first = store.remove("s1", Ok(t0), TAIL);
    assert!(first.is_err(), "a failed directory sync answered {first:?}");
    assert_eq!(
        sync_fault::armed(&subs),
        0,
        "the armed failure was not reached"
    );
    assert!(
        store.get("s1").is_some(),
        "the row left memory before its unlink was on disk"
    );
    assert!(!subs.join("s1.json").exists(), "the file was not unlinked");
    sync_fault::arm(&subs, 1);
    let second = store.remove("s1", Ok(t0), TAIL);
    assert!(
        second.is_err(),
        "a retry on the unlinked file skipped the sync: {second:?}"
    );
    assert_eq!(sync_fault::armed(&subs), 0);
    assert!(
        store.get("s1").is_some(),
        "the retry dropped the row on a failed sync"
    );
    assert!(store.remove("s1", Ok(t0), TAIL).expect("a durable retry"));
    assert!(
        store.get("s1").is_none(),
        "the row stayed after a durable removal"
    );
    drop(store);
    let store = Store::open(dir.path(), Ok(t0), TAIL).expect("reopen");
    assert!(store.get("s1").is_none(), "the removed row came back");
}

/// Every open syncs the subscription folder, a reopen included, and an open
/// whose sync fails is refused with the folder in its message.
#[test]
fn unsub1b_the_store_syncs_its_directory_when_it_opens() {
    let dir = tempfile::tempdir().expect("dir");
    let t0 = t0();
    let subs = dir.path().join("subs");
    sync_fault::arm(&subs, 1);
    let opened = Store::open(dir.path(), Ok(t0), TAIL);
    assert_eq!(
        sync_fault::armed(&subs),
        0,
        "the open did not sync the subscription folder"
    );
    let error = opened.err().expect("an open whose folder sync failed");
    assert!(
        error.to_string().contains(&subs.display().to_string()),
        "the error does not name the folder: {error}"
    );
    let store = open_with(dir.path(), t0, &["s1"]);
    sync_fault::arm(&subs, 1);
    assert!(store.remove("s1", Ok(t0), TAIL).is_err());
    assert!(store.get("s1").is_some());
    drop(store);
    let before = sync_fault::synced(&subs);
    let store = Store::open(dir.path(), Ok(t0), TAIL).expect("reopen");
    // Counted across a reopen: syncing only when the folder was just made fails.
    assert!(
        sync_fault::synced(&subs) > before,
        "the reopen did not sync the subscription folder"
    );
    assert!(
        !store.remove("s1", Ok(t0), TAIL).expect("io"),
        "an unlinked row was still there"
    );
}
