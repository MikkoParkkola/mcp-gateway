// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! S1 integration rows — admission and the durable store together.
//!
//! Rows 15-18c of the reviewed test plan. They live beside the store's suite
//! because the store's surface is `pub(super)` and unreachable from
//! `src/idempotency`; that is a visibility fact, not a preference.
//!
//! Two P2 corrections are load-bearing here. The record's owner is the
//! BINDING'S principal digest, never the suite's `OWNER` constant — reading back
//! with the wrong owner is a row that could never go green. And every seam is
//! TIMED, copying `durability.rs`: an absent stage must fail the assertion that
//! names it, not strand a blocking worker until CI gives up.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use serde_json::{Value, json};

use super::super::record::PreparedTask;
use super::super::store::{CommitHook, CommitStage, StoreError, TaskStore};
use super::support::*;
use crate::idempotency::admission::{
    ExecutionAdmission, Mode, Request, TaskAdmission, TaskBinding,
};
use crate::protocol::tasks::TaskTransition;

/// Owned fixture values: a `Request` borrows these, so an inline `json!` would
/// borrow a temporary that dies at the end of the statement (E0515).
static OPERATION: LazyLock<Value> =
    LazyLock::new(|| json!({"backend": "orders", "tool": "create"}));
static REPRESENTATION: LazyLock<Value> = LazyLock::new(|| json!({"full": false}));

fn services() -> Arc<ExecutionAdmission> {
    ExecutionAdmission::new(Arc::new(|| 1_000))
}

fn task_request<'a>(principal: &'a str, key: &'a str) -> Request<'a> {
    Request {
        principal,
        key,
        operation: &OPERATION,
        representation: &REPRESENTATION,
        mode: Mode::Task,
    }
}

/// One-shot TIMED seam at a named stage, modelled on `durability.rs`'s
/// `paused_at_final_sync`. Every wait is bounded, so a stage that never fires
/// makes the row fail at its own assertion instead of hanging the worker.
fn paused_at(
    stage: CommitStage,
) -> (
    std::sync::mpsc::Receiver<()>,
    std::sync::mpsc::Sender<()>,
    CommitHook,
) {
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let receiver = Mutex::new(release_rx);
    let arrivals = AtomicUsize::new(0);
    let hook: CommitHook = Arc::new(move |fired| {
        if fired == stage && arrivals.fetch_add(1, Ordering::SeqCst) == 0 {
            entered_tx.send(()).unwrap();
            // Bounded, and a dropped sender ends the wait: an assertion that
            // fails before the release cannot strand this thread.
            receiver
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))
                .map_err(std::io::Error::other)?;
        }
        Ok(())
    });
    (entered_rx, release_tx, hook)
}

/// Wait for a seam, bounded. The message names the stage the row depends on, so
/// an unimplemented seam reads as exactly that.
async fn wait_for(entered: std::sync::mpsc::Receiver<()>, stage: &str) {
    let reached = tokio::task::spawn_blocking(move || entered.recv_timeout(Duration::from_secs(5)))
        .await
        .unwrap();
    assert!(reached.is_ok(), "the {stage} seam was never reached");
}

/// A directory sync that fails once, after its unlink has already succeeded.
fn failing_sync_once() -> CommitHook {
    let armed = AtomicUsize::new(0);
    Arc::new(move |stage| {
        if stage == CommitStage::DirectorySync && armed.fetch_add(1, Ordering::SeqCst) == 0 {
            return Err(std::io::Error::other("directory sync refused once"));
        }
        Ok(())
    })
}

/// Admit one task, commit its record, settle it, and hand back the id and the
/// binding admission retained. The record's owner is the binding's principal
/// digest: the store suite's `OWNER` constant does not apply to a record that
/// admission authorized.
async fn settled_task(
    store: &TaskStore,
    admission: &Arc<ExecutionAdmission>,
    key: &str,
) -> (String, TaskBinding) {
    let lease = match admission.admit_task(task_request("oidc:acme:alice", key)) {
        Ok(TaskAdmission::Owned(lease)) => lease,
        other => panic!("expected an owner, got {other:?}"),
    };
    let binding = lease.binding().clone();
    let task = task();
    let id = task.id().to_owned();
    store
        .create(PreparedTask::admitted(
            &task,
            &binding,
            lease.into_publication(),
            "fixture",
        ))
        .await
        .unwrap();
    store
        .transition(
            binding.principal_digest(),
            &id,
            1,
            TaskTransition::Complete(json!({"content":[{"type":"text","text":"settled"}]})),
            at(1),
        )
        .await
        .expect("a settlement makes the record terminal, which is what expiry requires");
    (id, binding)
}

/// Row 15 — MIK-7272.TASK.1.1: a committed task is readable the moment it is
/// discoverable. The seam holds the creating thread AFTER the readable insert
/// and BEFORE the dedupe publication — the only interval in which those two can
/// be observed out of order.
#[tokio::test]
async fn task_15_a_discoverable_task_is_already_readable() {
    let dir = tempfile::tempdir().unwrap();
    let admission = services();
    let store = open(&dir.path().join("tasks")).await;
    let (entered, release, hook) = paused_at(CommitStage::Published);
    store.set_hook(Some(hook)).await;

    let lease = match admission.admit_task(task_request("oidc:acme:alice", "k-1")) {
        Ok(TaskAdmission::Owned(lease)) => lease,
        other => panic!("expected an owner, got {other:?}"),
    };
    let binding = lease.binding().clone();
    let task = task();
    let id = task.id().to_owned();
    let creating = {
        let writer = store.clone();
        let prepared = PreparedTask::admitted(&task, &binding, lease.into_publication(), "fixture");
        tokio::spawn(async move { writer.create(prepared).await })
    };

    wait_for(entered, "CommitStage::Published").await;
    let readable = store.get(binding.principal_digest(), &id).is_ok();
    let retry_in_flight = matches!(
        admission.admit_task(task_request("oidc:acme:alice", "k-1")),
        Ok(TaskAdmission::InFlight)
    );
    // Release BEFORE asserting: a failed assertion must not leave the writer
    // parked on this seam.
    release.send(()).unwrap();
    creating.await.unwrap().unwrap();

    assert!(
        readable,
        "the record must be readable before its key advertises it"
    );
    assert!(
        retry_in_flight,
        "the key must not answer Existing before publication resolves"
    );
    match admission.admit_task(task_request("oidc:acme:alice", "k-1")) {
        Ok(TaskAdmission::Existing { task_id, .. }) => assert_eq!(task_id, id),
        other => panic!("after publication the retry must recover the task, got {other:?}"),
    }
    store.close().await.unwrap();
}

/// Row 16 — a creation cancelled BEFORE the worker accepts it leaves nothing.
#[tokio::test]
async fn task_16_a_cancellation_before_hand_off_leaves_no_reservation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let admission = services();
    let store = open(&path).await;

    let lease = match admission.admit_task(task_request("oidc:acme:alice", "k-1")) {
        Ok(TaskAdmission::Owned(lease)) => lease,
        other => panic!("expected an owner, got {other:?}"),
    };
    let task = task();
    let binding = lease.binding().clone();
    let prepared = PreparedTask::admitted(&task, &binding, lease.into_publication(), "fixture");

    // Dropped without ever being polled: the worker never accepted it.
    let creating = store.create(prepared);
    drop(creating);

    assert!(
        matches!(
            admission.admit_task(task_request("oidc:acme:alice", "k-1")),
            Ok(TaskAdmission::Owned(_))
        ),
        "an unresolved publication token must release its slot"
    );
    // No RECORD and no TEMPORARY was written. `store.lease` is the sidecar every
    // open creates, so asserting an empty directory would fail on conforming
    // behaviour rather than on the claim.
    let residue: Vec<_> = files(&path)
        .into_keys()
        .filter(|name| name != "store.lease")
        .collect();
    assert!(
        residue.is_empty(),
        "a creation that never reached the worker must leave no record or temp: {residue:?}"
    );
    store.close().await.unwrap();
}

/// Row 17 — a creation cancelled AFTER the worker accepted it still publishes.
/// Opposite outcome from row 16, so an implementation treating both drops alike
/// fails one of the pair. The join goes through the SAME store's ordering lock:
/// a second `open` against a live lease answers `AlreadyOwned` and would prove
/// nothing about cancellation.
#[tokio::test]
async fn task_17_a_cancellation_after_hand_off_still_publishes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let admission = services();
    let store = open(&path).await;
    let (entered, release, hook) = paused_at(CommitStage::DirectorySync);
    store.set_hook(Some(hook)).await;

    let lease = match admission.admit_task(task_request("oidc:acme:alice", "k-1")) {
        Ok(TaskAdmission::Owned(lease)) => lease,
        other => panic!("expected an owner, got {other:?}"),
    };
    let binding = lease.binding().clone();
    let task = task();
    let id = task.id().to_owned();
    let pending = {
        let writer = store.clone();
        let prepared = PreparedTask::admitted(&task, &binding, lease.into_publication(), "fixture");
        tokio::spawn(async move { writer.create(prepared).await })
    };

    wait_for(entered, "CommitStage::DirectorySync").await;
    // The caller goes away while the writer is still inside the commit, and the
    // abort is proved to have landed BEFORE the write was allowed to finish.
    pending.abort();
    let cancelled = pending.await;
    release.send(()).unwrap();
    assert!(
        cancelled
            .as_ref()
            .is_err_and(tokio::task::JoinError::is_cancelled),
        "the creating caller must be gone before the write completes: {cancelled:?}"
    );

    // Taking the ordering lock IS the join — no sleep, and no reopen against a
    // lease this test still holds.
    let settled = store
        .transition(
            binding.principal_digest(),
            &id,
            1,
            TaskTransition::StatusMessage(Some("still ours".into())),
            at(2),
        )
        .await
        .expect("an accepted creation survives its caller");
    assert_eq!(settled.revision, 2);
    assert!(
        matches!(
            admission.admit_task(task_request("oidc:acme:alice", "k-1")),
            Ok(TaskAdmission::Existing { .. })
        ),
        "and its dedupe entry survives with it"
    );
    store.close().await.unwrap();
}

/// Row 18 — expiry unblocks the key: the next identical retry is a fresh owner.
#[tokio::test]
async fn task_18_expiry_frees_the_key_for_a_new_task() {
    let dir = tempfile::tempdir().unwrap();
    let admission = services();
    let store = open(&dir.path().join("tasks")).await;
    let (id, binding) = settled_task(&store, &admission, "k-1").await;

    store.expire(&id, 2, &admission).await.unwrap();

    assert!(matches!(
        store.get(binding.principal_digest(), &id),
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        admission.admit_task(task_request("oidc:acme:alice", "k-1")),
        Ok(TaskAdmission::Owned(_))
    ));
    store.close().await.unwrap();
}

/// Row 18b — §13.3: the record and the dedupe entry die together. The seam holds
/// ONE interval — after the durable deletion, before the dedupe release, guard
/// live — and the row asserts a concurrent `admit_task` is BLOCKED for exactly
/// that interval, not that arbitrary call pairs are atomic.
#[tokio::test]
async fn task_18b_no_admission_path_runs_inside_the_expiry_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let admission = services();
    let store = open(&dir.path().join("tasks")).await;
    let (id, binding) = settled_task(&store, &admission, "k-1").await;
    let (entered, release, hook) = paused_at(CommitStage::Deleted);
    store.set_hook(Some(hook)).await;

    let expiring = {
        let store = store.clone();
        let admission = Arc::clone(&admission);
        let id = id.clone();
        tokio::spawn(async move { store.expire(&id, 2, &admission).await })
    };
    wait_for(entered, "CommitStage::Deleted").await;

    // The witness fires INSIDE `admit_task`, immediately before it takes the
    // admission mutex. Signalling from the test thread would only prove the
    // racer was scheduled; this proves it reached the lock.
    let (at_lock_tx, at_lock_rx) = std::sync::mpsc::channel();
    let witness = Mutex::new(at_lock_tx);
    admission.set_lock_witness(Some(Arc::new(move || {
        let _ = witness.lock().unwrap().send(());
    })));
    let (finished_tx, finished_rx) = std::sync::mpsc::channel();
    let racer = {
        let admission = Arc::clone(&admission);
        std::thread::spawn(move || {
            let outcome = admission.admit_task(task_request("oidc:acme:alice", "k-1"));
            finished_tx.send(()).unwrap();
            matches!(outcome, Ok(TaskAdmission::Owned(_)))
        })
    };
    let entered_admission = at_lock_rx.recv_timeout(Duration::from_secs(5)).is_ok();
    let ran_inside = finished_rx.recv_timeout(Duration::from_millis(300)).is_ok();

    // Release before asserting, then join both workers: a failure here must not
    // leave the expiry parked or the racer detached.
    release.send(()).unwrap();
    let expired = expiring.await.unwrap();
    let freed = racer.join().unwrap();

    assert!(
        entered_admission,
        "the racing admission never reached the admission mutex, so its silence proves nothing"
    );
    assert!(
        !ran_inside,
        "an admission path ran INSIDE the expiry transaction"
    );
    assert!(
        finished_rx.recv_timeout(Duration::from_secs(5)).is_ok(),
        "the racing admission must complete once the transaction ends"
    );
    expired.expect("the expiry itself must succeed");
    assert!(freed, "after the transaction the key is free");
    assert!(matches!(
        store.get(binding.principal_digest(), &id),
        Err(StoreError::NotFound)
    ));
    store.close().await.unwrap();
}

/// Row 18c — a directory-sync failure AFTER a successful unlink is retryable:
/// nothing is released, and the same call repeated completes the deletion.
#[tokio::test]
async fn task_18c_a_failed_sync_releases_nothing_and_the_retry_completes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let admission = services();
    let store = open(&path).await;
    let (id, binding) = settled_task(&store, &admission, "k-1").await;
    // The exact aggregate before the failed transaction. Entry equality alone
    // would pass while the bytes were freed underneath it.
    let held = admission.snapshot();
    assert!(
        held.metadata_bytes > 0,
        "the settled task must hold capacity"
    );
    store.set_hook(Some(failing_sync_once())).await;

    assert_eq!(
        store.expire(&id, 2, &admission).await.unwrap_err(),
        StoreError::Storage
    );
    assert_eq!(
        admission.snapshot(),
        held,
        "a failed sync must leave the entry AND its aggregate capacity exactly as they were"
    );
    // The readable view is untouched too: the store removes it only after the
    // sync succeeds.
    let retained = store
        .get(binding.principal_digest(), &id)
        .expect("a refused expiry leaves the task readable");
    assert_eq!(retained.revision, 2);
    // Nothing released, and the id and binding prove WHICH task still holds the
    // key: a release that dropped the capacity but left the key would answer
    // `Existing` too.
    match admission.admit_task(task_request("oidc:acme:alice", "k-1")) {
        Ok(TaskAdmission::Existing {
            task_id,
            binding: held,
        }) => {
            assert_eq!(task_id, id);
            assert_eq!(held, binding);
        }
        other => {
            panic!("a failed sync must release neither the entry nor its capacity, got {other:?}")
        }
    }
    // The unlink itself DID succeed, so the record file is already gone: that is
    // exactly why the retry must not treat its absence as an error.
    assert!(
        !files(&path).contains_key(&format!("{id}.json")),
        "the unlink preceded the failing sync, so the record must already be absent"
    );

    // The retry meets an already-absent record and must treat that as a deletion
    // to finish rather than an error.
    store
        .expire(&id, 2, &admission)
        .await
        .expect("an already-unlinked record is a deletion to complete");
    // The lease is BOUND, not matched and dropped: an unpublished lease that
    // goes out of scope abandons its slot, so measuring after a `matches!`
    // temporary would read the state of a task that no longer exists.
    let fresh = match admission.admit_task(task_request("oidc:acme:alice", "k-1")) {
        Ok(TaskAdmission::Owned(lease)) => lease,
        other => panic!("the completed deletion must release the key, got {other:?}"),
    };
    // And the capacity actually came back: a release that dropped the entry but
    // kept its bytes would satisfy the line above and fail this one. The fresh
    // admission above holds one entry's worth, so the comparison is against that
    // reservation rather than against zero.
    let after = admission.snapshot();
    assert_eq!(after.entries, 1, "only the new admission remains");
    assert_eq!(
        after.metadata_bytes, held.metadata_bytes,
        "the expired task's bytes were returned, not leaked"
    );
    drop(fresh);
    assert!(matches!(
        store.get(binding.principal_digest(), &id),
        Err(StoreError::NotFound)
    ));
    store.close().await.unwrap();
}

/// F2 — `create` can return `Storage` after the readable insert if the
/// Published hook fails. The unresolved publication must not abandon the
/// slot: a retry of the same request is `Existing`, not a fresh `Owned`.
#[tokio::test]
async fn task_published_hook_error_retry_is_existing() {
    let dir = tempfile::tempdir().unwrap();
    let admission = services();
    let store = open(&dir.path().join("tasks")).await;
    store
        .set_hook(Some(Arc::new(|stage| {
            if stage == CommitStage::Published {
                return Err(std::io::Error::other("published hook refused"));
            }
            Ok(())
        })))
        .await;

    let lease = match admission.admit_task(task_request("oidc:acme:alice", "k-1")) {
        Ok(TaskAdmission::Owned(lease)) => lease,
        other => panic!("expected an owner, got {other:?}"),
    };
    let binding = lease.binding().clone();
    let task = task();
    let id = task.id().to_owned();
    let prepared = PreparedTask::admitted(&task, &binding, lease.into_publication(), "fixture");

    assert_eq!(
        store.create(prepared).await.unwrap_err(),
        StoreError::Storage
    );
    let retained = store
        .get(binding.principal_digest(), &id)
        .expect("a refused publication leaves the committed record readable");
    assert_eq!(retained.task.id(), id);
    assert_eq!(retained.revision, 1);
    match admission.admit_task(task_request("oidc:acme:alice", "k-1")) {
        Ok(TaskAdmission::Existing {
            task_id,
            binding: held,
        }) => {
            assert_eq!(task_id, id);
            assert_eq!(held, binding);
        }
        other => panic!(
            "a failed published hook must not abandon the committed task's admission slot, got {other:?}"
        ),
    }
    store.close().await.unwrap();
}
