// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! SIGNING.5: bounded admission and actual guarded-storage concurrency.
//! Helpers observe and exercise the production store's one guarded state.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use super::NonceStore;
use crate::{Error, Result};

#[derive(Debug)]
pub(super) struct AdmissionPause {
    nonce: String,
    claimed: AtomicBool,
    entered: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}

#[derive(Debug)]
pub(super) struct CleanupPause {
    claimed: AtomicBool,
    entered: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}

#[derive(Debug)]
pub(super) struct TestClock(Mutex<Instant>);
impl TestClock {
    pub(super) fn now(&self) -> Instant {
        *self.0.lock().unwrap()
    }
    fn advance(&self, duration: Duration) {
        *self.0.lock().unwrap() += duration;
    }
}

impl NonceStore {
    fn with_limits_for_test(global: usize, principal: usize) -> Self {
        Self::with_limits(Duration::from_secs(300), global, principal)
    }

    fn admit_for_test(&self, nonce: &str, principal: &str) -> Result<()> {
        self.check_and_register_for_principal(nonce, principal)
    }

    fn principal_bucket_count_for_test(&self) -> usize {
        self.state.lock().principal_counts.len()
    }

    pub(super) fn pause_inside_admission_for_test(&self, nonce: &str) {
        if let Some(pause) = &self.admission_pause
            && pause.nonce == nonce
            && !pause.claimed.swap(true, Ordering::AcqRel)
        {
            pause.entered.send(()).expect("inside-lock observer");
            pause
                .release
                .lock()
                .unwrap()
                .recv()
                .expect("release admission pause");
        }
    }

    pub(super) fn with_clock_for_test(global: usize, principal: usize) -> Self {
        let mut store = Self::with_limits_for_test(global, principal);
        store.test_clock = Some(TestClock(Mutex::new(Instant::now())));
        store
    }

    pub(super) fn advance_for_test(&self, seconds: u64) {
        self.test_clock
            .as_ref()
            .expect("injected monotonic clock")
            .advance(Duration::from_secs(seconds));
    }

    pub(super) fn pause_cleanup_after_selection_for_test(&self) {
        if let Some(pause) = &self.cleanup_pause
            && !pause.claimed.swap(true, Ordering::AcqRel)
        {
            pause.entered.send(()).expect("cleanup selection observer");
            pause
                .release
                .lock()
                .unwrap()
                .recv()
                .expect("release cleanup pause");
        }
    }

    fn expire_for_test(&self, nonce: &str) {
        // This existing fixture hook expires one chosen real record. Keep its
        // production expiry index consistent with the stored timestamp.
        let expired = self
            .now()
            .checked_sub(self.replay_window)
            .unwrap()
            .checked_sub(Duration::from_secs(1))
            .unwrap();
        let mut state = self.state.lock();
        state
            .seen
            .get_mut(nonce)
            .expect("nonce was admitted")
            .admitted_at = expired;
        for (at, key) in &mut state.expiries {
            if key == nonce {
                *at = expired;
            }
        }
        state
            .expiries
            .make_contiguous()
            .sort_unstable_by_key(|(at, _)| *at);
    }

    fn storage_available_for_test(&self, _nonce: &str) -> bool {
        // Probe the SAME guard admission and expiry actually hold.
        self.state.try_lock().is_some()
    }

    fn distinct_storage_key_for_test(first: &str) -> String {
        // Different keys now intentionally contend on the one global guard.
        format!("{first}-other")
    }
}

fn assert_refusal(result: Result<()>, code: i32, expected: &str) {
    match result.expect_err("nonce admission must refuse") {
        Error::JsonRpc {
            code: actual,
            message,
            data,
        } => {
            assert_eq!(actual, code);
            assert_eq!(message, expected);
            assert!(data.is_none());
        }
        other => panic!("typed nonce refusal required: {other:?}"),
    }
}

const CAPACITY: &str = "Signing nonce capacity exceeded";

#[test]
fn signing_nonce_principal_buckets_follow_live_entries_only() {
    let store = NonceStore::with_clock_for_test(3, 2);
    assert_eq!(store.principal_bucket_count_for_test(), 0);
    store.admit_for_test("alice-one", "alice").unwrap();
    store.advance_for_test(1);
    store.admit_for_test("bob-one", "bob").unwrap();
    store.advance_for_test(1);
    store.admit_for_test("alice-two", "alice").unwrap();
    assert_eq!(store.len(), 3, "three actual live nonce registrations");
    assert_eq!(store.principal_bucket_count_for_test(), 2);

    for index in 0..16 {
        assert_refusal(
            store.admit_for_test(
                &format!("refused-{index}"),
                &format!("new-principal-{index}"),
            ),
            -32001,
            CAPACITY,
        );
        assert_eq!(
            store.principal_bucket_count_for_test(),
            2,
            "refusal retained a bucket"
        );
    }
    store.advance_for_test(299); // t301: only Alice's first registration expires.
    store.evict_expired();
    assert_eq!(store.len(), 2);
    assert_eq!(
        store.principal_bucket_count_for_test(),
        2,
        "Alice still owns one nonce"
    );
    store.advance_for_test(1); // t302: Bob's last registration expires.
    store.evict_expired();
    assert_eq!(store.len(), 1);
    assert_eq!(
        store.principal_bucket_count_for_test(),
        1,
        "Bob's empty bucket must go"
    );
    store.advance_for_test(1); // t303: Alice's last registration expires.
    store.evict_expired();
    assert!(store.is_empty());
    assert_eq!(store.principal_bucket_count_for_test(), 0);
    store.admit_for_test("alice-new", "alice").unwrap();
    assert_eq!(store.principal_bucket_count_for_test(), 1);
}

#[test]
fn signing_nonce_global_capacity_refuses_without_growing_or_evicting() {
    let store = NonceStore::with_limits_for_test(2, 2);
    store.admit_for_test("one", "principal-a").unwrap();
    store.admit_for_test("two", "principal-b").unwrap();
    assert_eq!(store.len(), 2);
    assert_refusal(
        store.admit_for_test("three", "principal-c"),
        -32001,
        CAPACITY,
    );
    assert_eq!(store.len(), 2);
    assert_refusal(
        store.admit_for_test("one", "principal-a"),
        -32001,
        "Nonce replay detected",
    );
    assert_refusal(
        store.admit_for_test("two", "principal-b"),
        -32001,
        "Nonce replay detected",
    );
}

#[test]
fn signing_nonce_principal_quota_reserves_capacity_for_another_principal() {
    let store = NonceStore::with_limits_for_test(3, 1);
    store.admit_for_test("a-one", "principal-a").unwrap();
    assert_refusal(
        store.admit_for_test("a-two", "principal-a"),
        -32001,
        CAPACITY,
    );
    assert_eq!(store.len(), 1);
    store
        .admit_for_test("b-one", "principal-b")
        .expect("another principal retains capacity");
    assert_eq!(store.len(), 2);
    assert_refusal(
        store.admit_for_test("b-two", "principal-b"),
        -32001,
        CAPACITY,
    );
}

#[test]
fn signing_nonce_principal_limit_counts_multiple_live_nonces() {
    let store = NonceStore::with_limits_for_test(5, 2);
    store.admit_for_test("a-one", "alice").unwrap();
    store
        .admit_for_test("a-two", "alice")
        .expect("configured quota permits a second nonce");
    assert_refusal(store.admit_for_test("a-three", "alice"), -32001, CAPACITY);
    assert_eq!(store.len(), 2);
    store
        .admit_for_test("b-one", "bob")
        .expect("another principal retains capacity");
    store.admit_for_test("b-two", "bob").unwrap();
    assert_eq!(store.len(), 4);
}

#[test]
fn signing_nonce_global_limit_counts_entries_not_principal_buckets() {
    let store = NonceStore::with_limits_for_test(2, 10);
    store.admit_for_test("one", "alice").unwrap();
    store.admit_for_test("two", "alice").unwrap();
    assert_refusal(store.admit_for_test("three", "alice"), -32001, CAPACITY);
    assert_eq!(store.len(), 2);
    assert_refusal(store.admit_for_test("four", "bob"), -32001, CAPACITY);
    assert_eq!(store.len(), 2);
}

#[test]
fn signing_nonce_uniqueness_is_global_across_principals() {
    let store = NonceStore::with_limits_for_test(5, 2);
    store.admit_for_test("shared-nonce", "principal-a").unwrap();
    assert_refusal(
        store.admit_for_test("shared-nonce", "principal-b"),
        -32001,
        "Nonce replay detected",
    );
    store.admit_for_test("fresh-nonce", "principal-b").unwrap();
    assert_eq!(store.len(), 2);
}

#[test]
fn signing_nonce_utf8_limits_accept_exact_boundaries() {
    for nonce in ["x".to_owned(), "x".repeat(256), "🦀".repeat(64)] {
        assert!(nonce.len() <= 256);
        let store = NonceStore::with_limits_for_test(1, 1);
        store
            .admit_for_test(&nonce, "principal-a")
            .expect("valid byte bound");
        assert_eq!(store.len(), 1);
        assert_refusal(
            store.admit_for_test(&nonce, "principal-a"),
            -32001,
            "Nonce replay detected",
        );
    }
}

#[test]
fn signing_nonce_invalid_bytes_never_consume_store_capacity() {
    let mut accepted = Vec::new();
    for nonce in [String::new(), "x".repeat(257), "🦀".repeat(65)] {
        let store = NonceStore::with_limits_for_test(1, 1);
        match store.admit_for_test(&nonce, "principal-a") {
            Ok(()) => accepted.push(nonce.len()),
            Err(error) => {
                assert_refusal(Err(error), -32602, "Invalid signing nonce");
                assert_eq!(store.len(), 0);
                store
                    .admit_for_test("valid-after-invalid", "principal-a")
                    .unwrap();
            }
        }
    }
    assert!(
        accepted.is_empty(),
        "invalid nonce byte lengths were admitted: {accepted:?}"
    );
}

#[test]
fn signing_nonce_invalid_bytes_precede_full_store_capacity() {
    for nonce in [String::new(), "x".repeat(257), "🦀".repeat(65)] {
        let store = NonceStore::with_limits_for_test(1, 1);
        store.admit_for_test("already-full", "alice").unwrap();
        assert_refusal(
            store.admit_for_test(&nonce, "alice"),
            -32602,
            "Invalid signing nonce",
        );
        assert_eq!(store.len(), 1);
        assert_refusal(
            store.admit_for_test("already-full", "bob"),
            -32001,
            "Nonce replay detected",
        );
    }
}

#[test]
fn signing_nonce_expired_full_store_admits_immediately_without_background_tick() {
    let store = NonceStore::with_limits_for_test(2, 2);
    store.admit_for_test("one", "principal-a").unwrap();
    store.admit_for_test("two", "principal-b").unwrap();
    assert_eq!(store.len(), 2);
    store.expire_for_test("one");
    store.expire_for_test("two");
    store
        .admit_for_test("three", "principal-c")
        .expect("admission reclaims already-expired capacity");
    assert_eq!(
        store.len(),
        1,
        "expired entries must leave occupancy before admission returns"
    );
}

#[test]
fn signing_nonce_expiry_reclaims_only_expired_principal_capacity() {
    let store = NonceStore::with_limits_for_test(2, 1);
    store.admit_for_test("a-one", "principal-a").unwrap();
    store.admit_for_test("b-one", "principal-b").unwrap();
    store.expire_for_test("a-one");
    store
        .admit_for_test("a-two", "principal-a")
        .expect("expired principal slot reopens");
    assert_eq!(store.len(), 2);
    assert_refusal(
        store.admit_for_test("b-two", "principal-b"),
        -32001,
        CAPACITY,
    );
    assert_refusal(
        store.admit_for_test("b-one", "principal-b"),
        -32001,
        "Nonce replay detected",
    );
}

#[test]
fn signing_nonce_capacity_refusal_does_not_poison_the_refused_nonce() {
    let store = NonceStore::with_limits_for_test(1, 1);
    store.admit_for_test("occupied", "principal-a").unwrap();
    assert_refusal(
        store.admit_for_test("refused", "principal-b"),
        -32001,
        CAPACITY,
    );
    store.expire_for_test("occupied");
    store
        .admit_for_test("refused", "principal-b")
        .expect("capacity refusal never registered this nonce");
    assert_eq!(store.len(), 1);
}

#[test]
fn signing_nonce_replay_has_precedence_over_full_capacity() {
    let store = NonceStore::with_limits_for_test(1, 1);
    store.admit_for_test("occupied", "principal-a").unwrap();
    assert_refusal(
        store.admit_for_test("occupied", "principal-b"),
        -32001,
        "Nonce replay detected",
    );
    assert_eq!(store.len(), 1);
}

#[test]
fn signing_nonce_background_eviction_reclaims_quota_before_readmission() {
    let store = NonceStore::with_limits_for_test(1, 1);
    store.admit_for_test("expired", "principal-a").unwrap();
    store.expire_for_test("expired");
    store.evict_expired();
    assert!(store.is_empty());
    store.admit_for_test("fresh", "principal-a").unwrap();
    assert_refusal(
        store.admit_for_test("over-quota", "principal-a"),
        -32001,
        CAPACITY,
    );
}

struct ReleaseOnDrop(Option<mpsc::Sender<()>>);
impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

fn paused_store(first: &str) -> (NonceStore, mpsc::Receiver<()>, ReleaseOnDrop) {
    let (entered, arrival) = mpsc::channel();
    let (release, receiver) = mpsc::channel();
    let mut store = NonceStore::with_limits_for_test(1, 1);
    store.admission_pause = Some(AdmissionPause {
        nonce: first.into(),
        claimed: AtomicBool::new(false),
        entered,
        release: Mutex::new(receiver),
    });
    (store, arrival, ReleaseOnDrop(Some(release)))
}

#[test]
fn signing_nonce_same_nonce_race_observes_real_guard_exclusion() {
    let (store, arrival, release) = paused_store("racing");
    let store = Arc::new(store);
    let first_store = Arc::clone(&store);
    let first = std::thread::spawn(move || first_store.admit_for_test("racing", "principal-a"));
    arrival
        .recv_timeout(Duration::from_secs(5))
        .expect("first contender pauses INSIDE entry guard");
    let guard_available = store.storage_available_for_test("racing");
    let (started, ready) = mpsc::channel();
    let second_store = Arc::clone(&store);
    let second = std::thread::spawn(move || {
        started.send(()).unwrap();
        second_store.admit_for_test("racing", "principal-b")
    });
    ready
        .recv_timeout(Duration::from_secs(5))
        .expect("second contender started while first is paused");
    drop(release);
    first
        .join()
        .expect("first contender")
        .expect("first nonce admission");
    assert_refusal(
        second.join().expect("second contender"),
        -32001,
        "Nonce replay detected",
    );
    assert!(
        !guard_available,
        "actual same-key storage guard must be unavailable during first admission"
    );
    assert_eq!(store.len(), 1);
}

#[test]
fn signing_nonce_last_global_slot_race_observes_one_shared_guard() {
    let (store, arrival, release) = paused_store("first-key");
    // The baseline selector is only fixture staging: it avoids accidentally
    // testing two keys on the same old shard and falsely blessing that lock.
    let second_key = NonceStore::distinct_storage_key_for_test("first-key");
    assert_ne!(second_key, "first-key");
    let store = Arc::new(store);
    let first_store = Arc::clone(&store);
    let first = std::thread::spawn(move || first_store.admit_for_test("first-key", "principal-a"));
    arrival
        .recv_timeout(Duration::from_secs(5))
        .expect("first contender pauses INSIDE storage guard");
    let guard_available = store.storage_available_for_test(&second_key);
    let (started, ready) = mpsc::channel();
    let second_store = Arc::clone(&store);
    let second = std::thread::spawn(move || {
        started.send(()).unwrap();
        second_store.admit_for_test(&second_key, "principal-b")
    });
    ready
        .recv_timeout(Duration::from_secs(5))
        .expect("second contender started while first is paused");
    drop(release);
    let first_result = first.join().expect("first contender");
    let second_result = second.join().expect("second contender");
    assert!(
        !guard_available,
        "quota admission has no single guarded state across distinct keys"
    );
    first_result.expect("the first caller already owns the empty-state admission guard");
    assert_refusal(second_result, -32001, CAPACITY);
    assert_eq!(store.len(), 1);
}

#[test]
fn signing_nonce_readmission_uses_new_deadline_and_reassigns_principal_quota() {
    let store = NonceStore::with_clock_for_test(3, 1);
    store.admit_for_test("reused", "alice").unwrap();
    store.advance_for_test(301);
    store
        .admit_for_test("reused", "bob")
        .expect("expired nonce can be admitted anew");
    store.evict_expired();
    assert_eq!(
        store.len(),
        1,
        "old expiry record must not erase the new registration"
    );
    store.advance_for_test(299); // t600: old expiry300 passed; new expiry601 has not.
    store.evict_expired();
    assert_eq!(store.len(), 1);
    assert_refusal(
        store.admit_for_test("reused", "alice"),
        -32001,
        "Nonce replay detected",
    );
    store
        .admit_for_test("a-new", "alice")
        .expect("old owner's count was reclaimed");
    assert_refusal(store.admit_for_test("b-new", "bob"), -32001, CAPACITY);
    store.advance_for_test(2); // t602: only the new reused registration expires.
    store.evict_expired();
    assert_eq!(store.len(), 1, "only a-new remains live");
    store
        .admit_for_test("b-new", "bob")
        .expect("new owner quota reopens only at new deadline");
    assert_eq!(store.len(), 2);
}

#[test]
fn signing_nonce_cleanup_cannot_erase_a_concurrent_fresh_readmission() {
    let mut store = NonceStore::with_clock_for_test(2, 2);
    store.admit_for_test("reused", "alice").unwrap();
    store.advance_for_test(301);
    let (entered, arrival) = mpsc::channel();
    let (release, receiver) = mpsc::channel();
    store.cleanup_pause = Some(CleanupPause {
        claimed: AtomicBool::new(false),
        entered,
        release: Mutex::new(receiver),
    });
    let release = ReleaseOnDrop(Some(release));
    let store = Arc::new(store);
    let cleanup_store = Arc::clone(&store);
    let cleanup = std::thread::spawn(move || cleanup_store.evict_expired());
    arrival
        .recv_timeout(Duration::from_secs(5))
        .expect("cleanup selected actual elapsed state");
    // Baseline releases its guards after collecting names. The fixed queue
    // hook stays inside the actual single-state guard at this same boundary.
    let guard_available = store.storage_available_for_test("reused");
    let (completed, completion) = mpsc::channel();
    let readmit_store = Arc::clone(&store);
    let readmit = std::thread::spawn(move || {
        let result = readmit_store.admit_for_test("reused", "bob");
        completed.send(()).unwrap();
        result
    });
    if guard_available {
        // Demonstrate the old defect deterministically: fresh replacement has
        // completed BEFORE cleanup deletes its previously collected stale name.
        completion
            .recv_timeout(Duration::from_secs(5))
            .expect("unguarded baseline readmission completes");
    }
    drop(release);
    cleanup.join().expect("cleanup worker");
    readmit
        .join()
        .expect("readmission worker")
        .expect("readmission succeeds after expiry");
    assert_eq!(store.len(), 1, "cleanup erased a fresh registration");
    assert_refusal(
        store.admit_for_test("reused", "alice"),
        -32001,
        "Nonce replay detected",
    );
    assert!(
        !guard_available,
        "cleanup selection and deletion share actual admission storage guard"
    );
}
