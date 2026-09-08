// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Adapter design §3.1 — the widened create facade. Finding F3 of the P1
//! verdict, CLOSED, and therefore buildable.
//!
//! All I1. Four claims, and they are the whole of F3: one `admit_task` call, on
//! the facade, with every task-mode outcome reaching the caller distinctly
//! instead of collapsing into one unavailability; the worker permit taken ONLY
//! on the `Owned` branch, which is why a saturated pool still answers a repeat
//! with its original handle; a worker-cap refusal writing no record and leaving
//! the key unclaimed; and `Created` carrying its permit out to the consumer.
//!
//! Deliberately NOT here: `TaskExecutor`, `begin`, `BeginOutcome`, the oneshot.
//! F1's permit-ownership remainder is open and being corrected independently;
//! nothing below constructs an executor or asserts who holds the permit after
//! `create` returns it.
//!
//! Outcomes come from a real `ExecutionAdmission` in every row — the same
//! instance the service was opened with — so the mapping is measured against
//! admission's own answers and no digest, binding or refusal is fabricated.
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};

use serde_json::{Value, json};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::super::service::{CreateOutcome, ServiceError, TaskService};
use super::super::store::StoreLimits;
use super::{ALICE, BACKEND, assert_fixture_lifetime, other_task, request, task};
use crate::idempotency::admission::{ExecutionAdmission, Mode, Request, TaskAdmission};

/// The same operation under a DIFFERENT representation: a changed body under a
/// live key, which admission answers `Err(Refusal::Mismatch)`.
static ALTERED: LazyLock<Value> = LazyLock::new(|| json!({"full": true}));

fn altered_request<'a>(principal: &'a str, key: &'a str) -> Request<'a> {
    Request {
        principal,
        key,
        operation: &super::OPERATION,
        representation: &ALTERED,
        mode: Mode::Task,
    }
}

/// A service over a fresh store, sharing the admission the test holds. One
/// directory per fixture: the store's lease is exclusive.
async fn service_with(
    dir: &Path,
    admission: &Arc<ExecutionAdmission>,
    limits: StoreLimits,
) -> TaskService {
    TaskService::open(&dir.join("tasks"), limits, Arc::clone(admission))
        .await
        .expect("a fresh directory opens")
}

/// A worker reservation that counts its own invocations. §3.1 step 4 reserves
/// only on the `Owned` branch, so "was this called at all?" separates a
/// conforming facade from one that reserves first and releases afterwards.
fn counting_reserve(
    workers: &Arc<Semaphore>,
    calls: &Arc<AtomicUsize>,
) -> impl FnOnce() -> Option<OwnedSemaphorePermit> + Send {
    let workers = Arc::clone(workers);
    let calls = Arc::clone(calls);
    move || {
        calls.fetch_add(1, Ordering::SeqCst);
        workers.try_acquire_owned().ok()
    }
}

/// Committed record files: "no record was written" is measured on the disk.
fn record_files(path: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("task-"))
        .collect();
    names.sort();
    names
}

/// I1 — one admission, four outcomes, and only `Created` asks for a worker.
#[tokio::test]
async fn facade_01_one_admission_maps_created_existing_mismatch_and_in_flight() {
    let dir = tempfile::tempdir().unwrap();
    let store_dir = dir.path().join("tasks");
    let admission = ExecutionAdmission::new(Arc::new(|| 1_000));
    let service = service_with(dir.path(), &admission, StoreLimits::default()).await;
    let workers = Arc::new(Semaphore::new(4));
    let calls = Arc::new(AtomicUsize::new(0));
    let first = task();

    let created = service
        .create(
            request(ALICE, "k-1"),
            &first,
            BACKEND,
            counting_reserve(&workers, &calls),
        )
        .await
        .expect("a fresh key creates a task");
    let slot = match created {
        CreateOutcome::Created { task, slot } => {
            assert_eq!(task.task.id(), first.id());
            assert_eq!(task.revision, 1);
            assert_fixture_lifetime(&task.task);
            slot
        }
        _ => panic!("an admitted fresh key must be Created"),
    };
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the Owned branch reserves exactly once"
    );
    assert_eq!(
        workers.available_permits(),
        3,
        "and the reservation it took is the one the outcome carries"
    );
    drop(slot);

    // Existing — a DIFFERENT task value under the same key recovers the one task,
    // and needs no worker: it answers for a backend that is already running.
    let repeat = service
        .create(
            request(ALICE, "k-1"),
            &other_task(),
            BACKEND,
            counting_reserve(&workers, &calls),
        )
        .await
        .expect("an identical retry is not a refusal");
    match repeat {
        CreateOutcome::Existing(committed) => {
            assert_eq!(committed.task.id(), first.id());
            assert_eq!(committed.revision, 1);
            assert_fixture_lifetime(&committed.task);
        }
        _ => panic!("a retried key must recover the task it already owns"),
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a retry that needs no worker must not reserve one"
    );

    // Mismatch — the same key with a different body. Admission refuses it, and
    // the facade must not report that as a broken store.
    let mismatched = service
        .create(
            altered_request(ALICE, "k-1"),
            &task(),
            BACKEND,
            counting_reserve(&workers, &calls),
        )
        .await
        .expect("a refusal is an outcome of create, not a failure of the service");
    assert!(
        matches!(mismatched, CreateOutcome::Mismatch),
        "a changed fingerprint under a live key is a Mismatch, not an Unavailable"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // InFlight — a lease this test holds, unpublished. Bound to a name: a
    // `matches!` temporary would drop it and free the key at once.
    let held = match admission.admit_task(request(ALICE, "k-2")) {
        Ok(TaskAdmission::Owned(lease)) => lease,
        other => panic!("the fixture needs a live, unpublished lease, got {other:?}"),
    };
    let in_flight = service
        .create(
            request(ALICE, "k-2"),
            &task(),
            BACKEND,
            counting_reserve(&workers, &calls),
        )
        .await
        .expect("an in-flight key is answered, not failed");
    assert!(
        matches!(in_flight, CreateOutcome::InFlight),
        "a key whose first attempt has not published yet is InFlight"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "no branch but Owned may take a worker permit"
    );
    drop(held);

    assert_eq!(
        record_files(&store_dir).len(),
        1,
        "exactly one create wrote a record; three refusals wrote none"
    );
    assert_eq!(
        workers.available_permits(),
        4,
        "and no reservation was left behind"
    );
    service.close().await.unwrap();
}

/// I1 / X5b — a saturated worker pool still answers a repeat with its original
/// handle. The permit sits AFTER admission for exactly this reason: refusing a
/// repeat that needs no worker breaks the idempotent handle `.8a` promises.
#[tokio::test]
async fn facade_02_a_saturated_pool_still_answers_the_original_handle() {
    let dir = tempfile::tempdir().unwrap();
    let admission = ExecutionAdmission::new(Arc::new(|| 1_000));
    let service = service_with(dir.path(), &admission, StoreLimits::default()).await;
    let workers = Arc::new(Semaphore::new(1));
    let calls = Arc::new(AtomicUsize::new(0));
    let first = task();

    let created = service
        .create(
            request(ALICE, "k-1"),
            &first,
            BACKEND,
            counting_reserve(&workers, &calls),
        )
        .await
        .expect("a fresh key creates a task");
    let slot = match created {
        CreateOutcome::Created { slot, .. } => slot,
        _ => panic!("an admitted fresh key must be Created"),
    };
    assert_eq!(
        workers.available_permits(),
        0,
        "the running task holds the only worker"
    );

    let retries = Arc::new(AtomicUsize::new(0));
    let repeat = service
        .create(
            request(ALICE, "k-1"),
            &first,
            BACKEND,
            counting_reserve(&workers, &retries),
        )
        .await
        .expect("a repeat under saturation is answered, not refused");
    match repeat {
        CreateOutcome::Existing(committed) => {
            assert_eq!(committed.task.id(), first.id());
            assert_eq!(committed.revision, 1);
            assert_fixture_lifetime(&committed.task);
        }
        _ => panic!("a saturated pool must not turn a repeat into a capacity refusal"),
    }
    assert_eq!(
        retries.load(Ordering::SeqCst),
        0,
        "the Existing branch never reaches the reservation"
    );
    assert_eq!(
        workers.available_permits(),
        0,
        "and it neither took a permit nor released the running task's"
    );
    drop(slot);
    service.close().await.unwrap();
}

/// I1 / X5 — a worker-cap refusal on a NEW key writes no durable record and
/// leaves the key unclaimed, so the next attempt can still create.
#[tokio::test]
async fn facade_03_a_worker_cap_refusal_writes_nothing_and_leaves_the_key_unclaimed() {
    let dir = tempfile::tempdir().unwrap();
    let store_dir = dir.path().join("tasks");
    let admission = ExecutionAdmission::new(Arc::new(|| 1_000));
    let service = service_with(dir.path(), &admission, StoreLimits::default()).await;
    let workers = Arc::new(Semaphore::new(1));
    let running = Arc::new(AtomicUsize::new(0));
    let first = task();
    let second = other_task();

    let created = service
        .create(
            request(ALICE, "k-1"),
            &first,
            BACKEND,
            counting_reserve(&workers, &running),
        )
        .await
        .expect("a fresh key creates a task");
    let slot = match created {
        CreateOutcome::Created { slot, .. } => slot,
        _ => panic!("an admitted fresh key must be Created"),
    };
    assert_eq!(workers.available_permits(), 0);
    let before_files = record_files(&store_dir);
    let before_admission = admission.snapshot();

    let calls = Arc::new(AtomicUsize::new(0));
    let refused = service
        .create(
            request(ALICE, "k-2"),
            &second,
            BACKEND,
            counting_reserve(&workers, &calls),
        )
        .await
        .expect("a worker-cap refusal is an outcome, not a service failure");
    assert!(
        matches!(refused, CreateOutcome::Capacity),
        "worker-cap excess is counted BEFORE dispatch and is its own outcome"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the Owned branch did ask for a worker, and was told there was none"
    );
    assert_eq!(
        record_files(&store_dir),
        before_files,
        "a task refused for want of a worker must leave no durable record"
    );
    assert!(
        matches!(service.get(ALICE, second.id()), Err(ServiceError::NotFound)),
        "and nothing readable either"
    );
    assert_eq!(
        admission.snapshot(),
        before_admission,
        "the dropped lease gives its reservation back rather than stranding the key"
    );

    // Unclaimed means usable: the same key creates once a worker is free.
    drop(slot);
    let retries = Arc::new(AtomicUsize::new(0));
    let retried = service
        .create(
            request(ALICE, "k-2"),
            &second,
            BACKEND,
            counting_reserve(&workers, &retries),
        )
        .await
        .expect("the refused key is free to create");
    match retried {
        CreateOutcome::Created { task, slot } => {
            assert_eq!(task.task.id(), second.id());
            assert_eq!(task.revision, 1);
            drop(slot);
        }
        _ => panic!("a key whose only refusal was capacity must still be creatable"),
    }
    assert_eq!(record_files(&store_dir).len(), 2);
    service.close().await.unwrap();
}

/// I1 — a store failure is `Unavailable`, and it releases BOTH reservations: the
/// publication is dropped unresolved and the worker permit is not kept.
#[tokio::test]
async fn facade_04_a_store_refusal_is_unavailable_and_releases_both_reservations() {
    let dir = tempfile::tempdir().unwrap();
    let store_dir = dir.path().join("tasks");
    let admission = ExecutionAdmission::new(Arc::new(|| 1_000));
    let limits = StoreLimits {
        records: 1,
        ..StoreLimits::default()
    };
    let service = service_with(dir.path(), &admission, limits).await;
    let workers = Arc::new(Semaphore::new(1));
    let running = Arc::new(AtomicUsize::new(0));
    let first = task();
    let second = other_task();

    let created = service
        .create(
            request(ALICE, "k-1"),
            &first,
            BACKEND,
            counting_reserve(&workers, &running),
        )
        .await
        .expect("the first task fits the store");
    match created {
        CreateOutcome::Created { slot, .. } => drop(slot),
        _ => panic!("an admitted fresh key must be Created"),
    }
    let before_files = record_files(&store_dir);
    let before_admission = admission.snapshot();

    let calls = Arc::new(AtomicUsize::new(0));
    let refused = service
        .create(
            request(ALICE, "k-2"),
            &second,
            BACKEND,
            counting_reserve(&workers, &calls),
        )
        .await
        .expect("a full store is an outcome the caller is told about");
    assert!(
        matches!(refused, CreateOutcome::Unavailable),
        "every store failure is Unavailable — distinct from the worker cap, which wrote nothing for a different reason"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the reservation is taken before the commit that then fails"
    );
    assert_eq!(
        workers.available_permits(),
        1,
        "a commit failure drops the slot instead of leaking a worker"
    );
    assert_eq!(
        record_files(&store_dir),
        before_files,
        "the refused commit left nothing behind"
    );
    assert_eq!(
        admission.snapshot(),
        before_admission,
        "and the publication was dropped unresolved, releasing the key"
    );
    service.close().await.unwrap();
}

/// I1 — the permit lives in the outcome. `Created` hands the reservation to its
/// consumer and it stays held until that consumer drops it; nothing inside the
/// facade releases it early. (Where it travels next is F1's open remainder.)
#[tokio::test]
async fn facade_05_created_holds_its_permit_until_the_consumer_drops_it() {
    let dir = tempfile::tempdir().unwrap();
    let admission = ExecutionAdmission::new(Arc::new(|| 1_000));
    let service = service_with(dir.path(), &admission, StoreLimits::default()).await;
    let workers = Arc::new(Semaphore::new(1));
    let running = Arc::new(AtomicUsize::new(0));
    let blocked_calls = Arc::new(AtomicUsize::new(0));
    let next_calls = Arc::new(AtomicUsize::new(0));
    let first = task();
    let second = other_task();

    let created = service
        .create(
            request(ALICE, "k-1"),
            &first,
            BACKEND,
            counting_reserve(&workers, &running),
        )
        .await
        .expect("a fresh key creates a task");
    let slot = match created {
        CreateOutcome::Created { slot, .. } => slot,
        _ => panic!("an admitted fresh key must be Created"),
    };
    assert_eq!(
        workers.available_permits(),
        0,
        "the facade hands the reservation out; it does not release it on the way"
    );

    // Held, not merely counted: while this outcome lives, the pool is saturated.
    let blocked = service
        .create(
            request(ALICE, "k-2"),
            &second,
            BACKEND,
            counting_reserve(&workers, &blocked_calls),
        )
        .await
        .expect("a saturated pool answers rather than fails");
    assert!(
        matches!(blocked, CreateOutcome::Capacity),
        "the permit is genuinely held while the Created outcome lives"
    );

    drop(slot);
    assert_eq!(
        workers.available_permits(),
        1,
        "and it returns to the pool when the consumer drops it"
    );
    let next = service
        .create(
            request(ALICE, "k-2"),
            &second,
            BACKEND,
            counting_reserve(&workers, &next_calls),
        )
        .await
        .expect("the freed worker is usable");
    match next {
        CreateOutcome::Created { task, slot } => {
            assert_eq!(task.task.id(), second.id());
            drop(slot);
        }
        _ => panic!("the released permit must be available to the next create"),
    }
    service.close().await.unwrap();
}
