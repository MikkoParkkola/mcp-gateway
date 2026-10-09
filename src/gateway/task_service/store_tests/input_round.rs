// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7311.LIFECYCLE.1: the input round's durable writes. Each test names
//! the mutant it must fail on.

use super::*;
use crate::gateway::task_service::record::InputRound;
use crate::gateway::task_service::store::input::{ProvideOutcome, RoundClosed};
use std::sync::Arc;

const CAP: usize = 4 * 1024;

fn limits() -> StoreLimits {
    StoreLimits {
        record_bytes: CAP,
        ..StoreLimits::default()
    }
}

fn question(key: &str) -> InputRequired {
    InputRequired {
        requests: vec![(
            key.to_owned(),
            json!({ "method": "elicitation/create", "params": {} }),
        )],
        request_state: None,
    }
}

fn round(state: &str) -> InputRound {
    InputRound {
        request_state: Some(state.to_owned()),
        tool: "gateway_invoke".to_owned(),
        arguments: json!({ "server": "mock", "tool": "echo", "arguments": { "q": 1 } }),
        accepted_inputs: serde_json::Map::new(),
        continuation_deadline: None,
    }
}

fn answers(value: Value) -> serde_json::Map<String, Value> {
    let Value::Object(map) = value else {
        panic!("answers are an object")
    };
    map
}

async fn parked(store: &TaskStore, task: &Task, keys: &[&str]) -> u64 {
    parked_with(store, task, keys, round("sealed")).await
}

/// Park `round` under `keys`, with the store's clock frozen at the fixture's
/// own time (the fixture task was created at `at(0)` with a one-day TTL).
async fn parked_with(store: &TaskStore, task: &Task, keys: &[&str], round: InputRound) -> u64 {
    store.set_clock_for_test(Some(at(1)));
    let created = store
        .create(PreparedTask::for_test(task, OWNER, 1))
        .await
        .unwrap();
    let requested = InputRequired {
        requests: keys
            .iter()
            .map(|key| {
                (
                    (*key).to_owned(),
                    json!({ "method": "elicitation/create", "params": {} }),
                )
            })
            .collect(),
        request_state: None,
    };
    store
        .require_input(OWNER, task.id(), created.revision, requested, round, at(1))
        .await
        .expect("a small round fits")
        .revision
}

fn on_disk(path: &std::path::Path, id: &str) -> Value {
    serde_json::from_slice(&fs::read(path.join(format!("{id}.json"))).unwrap()).unwrap()
}

/// Mutant: the continuation cap check removed.
#[tokio::test]
async fn a_continuation_over_the_byte_cap_is_refused_at_produce() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = TaskStore::open(&path, limits()).await.unwrap();
    let task = task();
    let created = store
        .create(PreparedTask::for_test(&task, OWNER, 1))
        .await
        .unwrap();
    let refused = store
        .require_input(
            OWNER,
            task.id(),
            created.revision,
            question("confirm"),
            round(&"x".repeat(CAP)),
            at(1),
        )
        .await;
    assert!(matches!(refused, Err(StoreError::Capacity)), "{refused:?}");
    let after = store.get(OWNER, task.id()).unwrap();
    assert_eq!(after.task.status(), TaskStatus::Working);
    assert_eq!(after.revision, created.revision, "nothing was written");
}

/// Mutant: the answers cap check removed.
#[tokio::test]
async fn answers_over_the_byte_cap_are_refused_and_nothing_is_written() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = TaskStore::open(&path, limits()).await.unwrap();
    let task = task();
    let revision = parked(&store, &task, &["confirm"]).await;
    let before = on_disk(&path, task.id());

    let refused = store
        .provide_input(
            OWNER,
            task.id(),
            answers(json!({ "confirm": { "blob": "x".repeat(CAP) } })),
            || None,
            at(2),
        )
        .await;
    assert!(
        matches!(refused, Err(StoreError::Capacity)),
        "{:?}",
        refused.err()
    );
    let after = store.get(OWNER, task.id()).unwrap();
    assert_eq!(after.task.status(), TaskStatus::InputRequired);
    assert_eq!(after.revision, revision);
    assert_eq!(on_disk(&path, task.id()), before, "the record is untouched");
}

/// Mutant: a subset accepted before the outstanding-key check.
#[tokio::test]
async fn a_foreign_key_refuses_the_whole_write() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let task = task();
    let revision = parked(&store, &task, &["a", "b"]).await;
    let refused = store
        .provide_input(
            OWNER,
            task.id(),
            answers(json!({ "a": {}, "zzz": {} })),
            || None,
            at(2),
        )
        .await;
    assert!(
        matches!(refused, Err(StoreError::InvalidTransition)),
        "{:?}",
        refused.err()
    );
    assert_eq!(store.get(OWNER, task.id()).unwrap().revision, revision);
}

/// Mutant: accepted answers not persisted on the record.
#[tokio::test]
async fn a_partial_answer_is_durable_and_the_completing_one_returns_them_all() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let task = task();
    parked(&store, &task, &["a", "b"]).await;
    let partial = store
        .provide_input(
            OWNER,
            task.id(),
            answers(json!({ "a": { "v": 1 } })),
            || None,
            at(2),
        )
        .await
        .unwrap();
    assert!(matches!(partial, ProvideOutcome::Partial(_)));
    assert_eq!(
        on_disk(&path, task.id()).pointer("/inputRound/acceptedInputs/a"),
        Some(&json!({ "v": 1 }))
    );

    let workers = Arc::new(tokio::sync::Semaphore::new(1));
    let slot = Arc::clone(&workers);
    let done = store
        .provide_input(
            OWNER,
            task.id(),
            answers(json!({ "b": { "v": 2 } })),
            move || slot.try_acquire_owned().ok(),
            at(3),
        )
        .await
        .unwrap();
    let ProvideOutcome::Resumed {
        task: now, round, ..
    } = done
    else {
        panic!("the completing answer resumes");
    };
    assert_eq!(now.task.status(), TaskStatus::Working);
    assert_eq!(
        Value::Object(round.accepted_inputs),
        json!({ "a": { "v": 1 }, "b": { "v": 2 } })
    );
    assert_eq!(round.request_state.as_deref(), Some("sealed"));
    assert_eq!(
        workers.available_permits(),
        0,
        "the permit travels with the resume"
    );
}

/// Mutant: CAS before permit acquisition.
#[tokio::test]
async fn a_completing_answer_with_no_free_worker_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let task = task();
    let revision = parked(&store, &task, &["confirm"]).await;
    let outcome = store
        .provide_input(
            OWNER,
            task.id(),
            answers(json!({ "confirm": {} })),
            || None,
            at(2),
        )
        .await
        .unwrap();
    assert!(matches!(outcome, ProvideOutcome::PoolFull));
    let after = store.get(OWNER, task.id()).unwrap();
    assert_eq!(after.task.status(), TaskStatus::InputRequired);
    assert_eq!(after.revision, revision);
}

/// Mutant: the continuation kept after a terminal transition.
#[tokio::test]
async fn cancel_drops_the_continuation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let task = task();
    let revision = parked(&store, &task, &["confirm"]).await;
    assert!(on_disk(&path, task.id()).get("inputRound").is_some());
    store
        .transition(OWNER, task.id(), revision, TaskTransition::Cancel, at(2))
        .await
        .unwrap();
    assert!(on_disk(&path, task.id()).get("inputRound").is_none());
}

/// Mutant: expiry skips `input_required` rows.
#[tokio::test]
async fn expired_input_rounds_selects_open_rounds_past_their_ttl_only() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let open_round = task();
    parked(&store, &open_round, &["confirm"]).await;
    let running = task();
    store
        .create(PreparedTask::for_test(&running, OWNER, 2))
        .await
        .unwrap();
    let later = at(0) + chrono::Duration::milliseconds(86_400_001);
    let selected: Vec<_> = store
        .expired_input_rounds(later)
        .into_iter()
        .map(|(id, _, owner, _)| (id, owner))
        .collect();
    assert_eq!(
        selected,
        vec![(open_round.id().to_owned(), OWNER.to_owned())]
    );
    assert!(
        store.expired_input_rounds(at(5)).is_empty(),
        "not before the TTL"
    );
}

// ---------------------------------------------------------------------------
// #2429: the round closes at its continuation deadline.
// ---------------------------------------------------------------------------

fn secs(at: chrono::DateTime<chrono::Utc>) -> u64 {
    u64::try_from(at.timestamp()).unwrap()
}

fn due(deadline: u64) -> InputRound {
    InputRound {
        continuation_deadline: Some(deadline),
        ..round("sealed")
    }
}

async fn opened() -> (tempfile::TempDir, TaskStore, Task) {
    let dir = tempfile::tempdir().unwrap();
    let store = TaskStore::open(&dir.path().join("tasks"), limits())
        .await
        .unwrap();
    (dir, store, task())
}

/// Mutant: the clock read before the ordering lock, or taken from the
/// caller's `at`: an update queued while the round was open is let through
/// after it closed.
#[tokio::test]
#[expect(
    clippy::await_holding_lock,
    reason = "holding the ordering lock across the wait is the race under test"
)]
async fn an_update_queued_across_the_deadline_is_refused_under_the_lock() {
    let (_dir, store, task) = opened().await;
    let deadline = secs(at(30));
    let revision = parked_with(&store, &task, &["confirm"], due(deadline)).await;
    let workers = Arc::new(tokio::sync::Semaphore::new(1));
    let held = store.hold_order_for_test();
    let queued = {
        let (store, id) = (store.clone(), task.id().to_owned());
        tokio::spawn(async move {
            store
                .provide_input(
                    OWNER,
                    &id,
                    answers(json!({ "confirm": {} })),
                    move || workers.try_acquire_owned().ok(),
                    at(2),
                )
                .await
        })
    };
    // The write has entered the store and is waiting on the held lock, with
    // the clock still before the deadline.
    let bound = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while store.arrivals_for_test() == 0 {
        assert!(
            tokio::time::Instant::now() < bound,
            "the update never reached the store"
        );
        tokio::task::yield_now().await;
    }
    store.set_clock_for_test(Some(at(30)));
    drop(held);
    let refused = queued.await.unwrap();
    assert!(
        matches!(
            refused,
            Ok(ProvideOutcome::Closed(RoundClosed::Continuation(d))) if d == deadline
        ),
        "refused naming the deadline"
    );
    assert_eq!(store.get(OWNER, task.id()).unwrap().revision, revision);
}

/// Pin: a round with no stored continuation has no deadline; the TTL alone
/// bounds it. Mutant: `None` read as already expired.
#[tokio::test]
async fn a_round_without_a_deadline_takes_answers_until_the_ttl() {
    let (_dir, store, task) = opened().await;
    parked(&store, &task, &["a", "b"]).await;
    store.set_clock_for_test(Some(at(1) + chrono::Duration::hours(1)));
    let accepted = store
        .provide_input(
            OWNER,
            task.id(),
            answers(json!({ "a": {} })),
            || None,
            at(2),
        )
        .await;
    assert!(matches!(accepted, Ok(ProvideOutcome::Partial(_))));
}

/// Pin: a record written before the field loads as `None`, and a `None`
/// round writes no field. Mutant: `skip_serializing_if` removed.
#[test]
fn the_deadline_field_is_absent_when_none_and_round_trips_when_set() {
    let old = json!({ "requestState": "s", "tool": "t", "arguments": {} });
    let loaded: InputRound = serde_json::from_value(old.clone()).unwrap();
    assert_eq!(loaded.continuation_deadline, None);
    assert_eq!(serde_json::to_value(&loaded).unwrap(), old);
    let set = InputRound {
        continuation_deadline: Some(7),
        ..loaded
    };
    let back: InputRound = serde_json::from_value(serde_json::to_value(&set).unwrap()).unwrap();
    assert_eq!(back, set);
}

/// Mutant: the settlement written without the revision check.
#[tokio::test]
async fn closing_a_round_at_a_stale_revision_writes_nothing() {
    let (_dir, store, task) = opened().await;
    let revision = parked_with(&store, &task, &["confirm"], due(secs(at(30)))).await;
    let stale = store
        .close_round(OWNER, task.id(), revision - 1, "closed".to_owned())
        .await;
    assert!(
        matches!(stale, Err(StoreError::RevisionConflict)),
        "{stale:?}"
    );
    let after = store.get(OWNER, task.id()).unwrap();
    assert_eq!(after.task.status(), TaskStatus::InputRequired);
    assert_eq!(after.revision, revision);
}

/// Mutants: two writes; the round kept; the reason dropped.
#[tokio::test]
async fn closing_a_round_cancels_it_with_the_reason_in_one_write() {
    let (_dir, store, task) = opened().await;
    let revision = parked_with(&store, &task, &["confirm"], due(secs(at(30)))).await;
    let closed = store
        .close_round(OWNER, task.id(), revision, "the reason".to_owned())
        .await
        .expect("an open round closes");
    assert_eq!(closed.revision, revision + 1);
    assert_eq!(closed.task.status(), TaskStatus::Cancelled);
    let wire = serde_json::to_value(closed.task.wire()).unwrap();
    assert_eq!(wire["statusMessage"], "the reason");
    assert!(store.input_round_for_test(task.id()).0.is_none());
}

/// Mutant: a settled row closed again (a second terminal write and publish).
#[tokio::test]
async fn closing_an_already_settled_round_writes_nothing() {
    let (_dir, store, task) = opened().await;
    let revision = parked_with(&store, &task, &["confirm"], due(secs(at(30)))).await;
    let closed = store
        .close_round(OWNER, task.id(), revision, "first".to_owned())
        .await
        .expect("an open round closes");
    let again = store
        .close_round(OWNER, task.id(), closed.revision, "second".to_owned())
        .await;
    assert!(
        matches!(again, Err(StoreError::InvalidTransition)),
        "{again:?}"
    );
    assert_eq!(
        store.get(OWNER, task.id()).unwrap().revision,
        closed.revision
    );
}

/// Every round write and the expiry sweep refuse a store that is not serving.
async fn assert_rounds_unserved(
    reader: &TaskStore,
    task: &Task,
    revision: u64,
    far: chrono::DateTime<chrono::Utc>,
) {
    let closed = reader
        .require_input(
            OWNER,
            task.id(),
            revision,
            question("again"),
            round("sealed"),
            at(2),
        )
        .await;
    assert!(matches!(closed, Err(StoreError::Unavailable)), "{closed:?}");
    let closed = reader
        .provide_input(
            OWNER,
            task.id(),
            answers(json!({ "confirm": {} })),
            || None,
            at(2),
        )
        .await;
    assert!(
        matches!(closed, Err(StoreError::Unavailable)),
        "{:?}",
        closed.err()
    );
    let closed = reader
        .close_round(OWNER, task.id(), revision, "expired".into())
        .await;
    assert!(matches!(closed, Err(StoreError::Unavailable)), "{closed:?}");
    assert!(reader.expired_input_rounds(far).is_empty());
}

/// Mutant: the readiness check removed from the owner-scoped row read, or the
/// revision compare-and-set removed from `require_input`.
#[tokio::test]
async fn a_closed_store_and_a_moved_revision_refuse_every_input_round_write() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = TaskStore::open(&path, limits()).await.unwrap();
    let task = task();
    // Parking at the committed revision is the positive control: it succeeds
    // and moves the row to revision 2.
    let revision = parked(&store, &task, &["confirm"]).await;
    assert_eq!(revision, 2);
    let before = on_disk(&path, task.id());
    let stale = store
        .require_input(
            OWNER,
            task.id(),
            1,
            question("again"),
            round("sealed"),
            at(2),
        )
        .await;
    assert!(
        matches!(stale, Err(StoreError::RevisionConflict)),
        "{stale:?}"
    );
    assert_eq!(on_disk(&path, task.id()), before, "nothing was written");

    // Past the task's TTL the sweep sees the round while the store serves.
    let far = at(0) + chrono::Duration::days(2);
    assert_eq!(store.expired_input_rounds(far).len(), 1, "control");

    // Poisoned with every row still in memory: the guards, not an empty map.
    let spare = super::support::task();
    store
        .create(PreparedTask::for_test(&spare, OWNER, 2))
        .await
        .unwrap();
    poison(&store, OWNER, spare.id(), 1).await;
    assert_rounds_unserved(&store, &task, revision, far).await;

    let reader = store.clone();
    store.close().await.unwrap();
    assert_rounds_unserved(&reader, &task, revision, far).await;
}

/// MIK-7738: the dispatch marker and every input-round write refuse a foreign
/// owner as `NotFound` and leave the record's bytes as they were. The owner's
/// own writes on the same row are the control: each refused write could land.
/// Mutant: the owner check in the store's record lookup removed.
#[tokio::test]
async fn a_foreign_owner_cannot_write_the_dispatch_marker_or_a_round() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = TaskStore::open(&path, limits()).await.unwrap();
    store.set_clock_for_test(Some(at(1)));
    let task = task();
    let created = store
        .create(PreparedTask::for_test(&task, OWNER, 1))
        .await
        .unwrap();
    let file = path.join(format!("{}.json", task.id()));
    let bytes = || fs::read(&file).unwrap();

    let before = bytes();
    let refused = store
        .mark_dispatched(OTHER, task.id(), created.revision)
        .await;
    assert!(matches!(refused, Err(StoreError::NotFound)), "{refused:?}");
    let refused = store
        .require_input(
            OTHER,
            task.id(),
            created.revision,
            question("confirm"),
            round("sealed"),
            at(1),
        )
        .await;
    assert!(matches!(refused, Err(StoreError::NotFound)), "{refused:?}");
    assert_eq!(bytes(), before, "a refused write changed the record");

    store
        .mark_dispatched(OWNER, task.id(), created.revision)
        .await
        .expect("control: the owner marks dispatch");
    assert_ne!(bytes(), before, "control: the marker is written");
    let revision = store
        .require_input(
            OWNER,
            task.id(),
            created.revision,
            question("confirm"),
            round("sealed"),
            at(1),
        )
        .await
        .expect("control: the owner opens a round")
        .revision;

    let before = bytes();
    let refused = store
        .provide_input(
            OTHER,
            task.id(),
            answers(json!({ "confirm": { "ok": true } })),
            || None,
            at(2),
        )
        .await;
    assert!(
        matches!(refused, Err(StoreError::NotFound)),
        "{:?}",
        refused.as_ref().err()
    );
    let refused = store
        .close_round(OTHER, task.id(), revision, "closed".to_owned())
        .await;
    assert!(matches!(refused, Err(StoreError::NotFound)), "{refused:?}");
    assert_eq!(bytes(), before, "a refused write changed the record");

    store
        .close_round(OWNER, task.id(), revision, "closed".to_owned())
        .await
        .expect("control: the owner closes its round");
    assert_ne!(bytes(), before, "control: the round is closed on disk");
}

/// Park a padded round under `keys` on a store capped at `record_bytes`,
/// returning what `require_input` answered. The continuation is padded so
/// the parked record, not the fallback reservation, is the binding size.
async fn park_capped(
    path: &std::path::Path,
    record_bytes: usize,
    task: &Task,
    keys: &[&str],
) -> (TaskStore, Result<u64, StoreError>) {
    let store = TaskStore::open(
        path,
        StoreLimits {
            record_bytes,
            ..StoreLimits::default()
        },
    )
    .await
    .unwrap();
    store.set_clock_for_test(Some(at(1)));
    let created = store
        .create(PreparedTask::for_test(task, OWNER, 1))
        .await
        .unwrap();
    let requested = InputRequired {
        requests: keys
            .iter()
            .map(|key| {
                (
                    (*key).to_owned(),
                    json!({ "method": "elicitation/create", "params": {} }),
                )
            })
            .collect(),
        request_state: None,
    };
    let parked = store
        .require_input(
            OWNER,
            task.id(),
            created.revision,
            requested,
            round(&"s".repeat(600)),
            at(1),
        )
        .await
        .map(|committed| committed.revision);
    (store, parked)
}

/// `MIK-7661.GH2418.1`: the room check measures the shortest answer as
/// `provide_input` writes it, which drops the answered request from the
/// model. That record is never larger than the parked one, so a round is
/// taken exactly when it fits: at a cap of the parked record's size it is
/// taken and its shortest answer accepted; one byte less, it is refused.
#[tokio::test]
async fn a_round_that_fits_exactly_is_taken_and_answerable() {
    let task = task();
    let keys = ["a", "bb"];
    let shortest = || answers(json!({ "a": {} }));

    let roomy = tempfile::tempdir().unwrap();
    let path = roomy.path().join("tasks");
    let (_store, parked) = park_capped(&path, CAP, &task, &keys).await;
    parked.expect("a round fits a roomy cap");
    let size = fs::read(path.join(format!("{}.json", task.id())))
        .unwrap()
        .len();

    let exact = tempfile::tempdir().unwrap();
    let path = exact.path().join("tasks");
    let (store, parked) = park_capped(&path, size, &task, &keys).await;
    assert!(
        parked.is_ok(),
        "a round that fits the cap exactly was refused: {parked:?}"
    );
    let answered = store
        .provide_input(OWNER, task.id(), shortest(), || None, at(1))
        .await;
    assert!(
        matches!(answered, Ok(ProvideOutcome::Partial(_))),
        "the shortest answer did not fit the cap the round was taken under"
    );

    let short = tempfile::tempdir().unwrap();
    let path = short.path().join("tasks");
    let (_store, parked) = park_capped(&path, size - 1, &task, &keys).await;
    assert_eq!(
        parked.err(),
        Some(StoreError::Capacity),
        "a round over the cap was taken"
    );
}
