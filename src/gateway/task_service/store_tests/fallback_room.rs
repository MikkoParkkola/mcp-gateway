// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-7651.GH2470.1`: every record the store accepts leaves room for the
//! bounded output-free failure it may have to settle as. Each test names the
//! mutant it must fail on.

use super::*;
use crate::gateway::task_service::record::InputRound;

fn limits(record_bytes: usize) -> StoreLimits {
    StoreLimits {
        record_bytes,
        ..StoreLimits::default()
    }
}

fn record_file(path: &std::path::Path, id: &str) -> Value {
    serde_json::from_slice(&fs::read(path.join(format!("{id}.json"))).unwrap()).unwrap()
}

fn encoded_len(value: &Value) -> usize {
    serde_json::to_vec(value).unwrap().len()
}

/// An outcome no record under `limit` can hold, so settling it takes the
/// bounded fallback.
fn oversize(limit: usize) -> TaskTransition {
    TaskTransition::Complete(json!({ "content": [{ "type": "text", "text": "q".repeat(limit) }] }))
}

/// The smallest round the store accepts: one one-byte key, no request state,
/// no arguments. It is the round whose own bytes least exceed its fallback's.
fn smallest_round() -> (InputRequired, InputRound) {
    let requested = InputRequired {
        requests: vec![("k".to_owned(), json!({}))],
        request_state: None,
    };
    let round = InputRound {
        request_state: None,
        tool: "t".to_owned(),
        arguments: json!({}),
        accepted_inputs: serde_json::Map::new(),
        continuation_deadline: None,
    };
    (requested, round)
}

/// The bytes of `task`'s freshly created record, and of the bounded failure it
/// settles as straight after, at its natural revision and settle instant. Both
/// measured in a store with room for them.
async fn created_and_fallback(task: &Task) -> (usize, Value) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = TaskStore::open(&path, limits(4 * 1024)).await.unwrap();
    store
        .create(PreparedTask::for_test(task, OWNER, 1))
        .await
        .unwrap();
    let created = fs::read(path.join(format!("{}.json", task.id())))
        .unwrap()
        .len();
    let settled = store
        .settle_bounded(
            OWNER,
            task.id(),
            1,
            (oversize(4 * 1024), Some(Vec::new())),
            at(1),
        )
        .await
        .unwrap();
    assert!(
        settled.output_free,
        "the fixture outcome takes the fallback"
    );
    let fallback = record_file(&path, task.id());
    store.close().await.unwrap();
    (created, fallback)
}

/// `fallback` re-encoded at its widest: the largest revision and a settle
/// instant printed with all nine fractional digits.
fn widest(mut fallback: Value) -> usize {
    fallback["revision"] = json!(u64::MAX);
    let updated = &mut fallback["model"]["task"]["lastUpdatedAt"];
    assert!(
        updated.is_string(),
        "the record keeps its update instant: {fallback}"
    );
    *updated = json!("2026-09-07T00:00:01.999999999Z");
    encoded_len(&fallback)
}

/// The exact boundary: the working record fits, its fallback does not.
/// Mutant: the creation check removed.
#[tokio::test]
async fn a_task_whose_fallback_cannot_fit_is_refused_at_creation() {
    let task = task();
    let (created, fallback) = created_and_fallback(&task).await;
    assert!(
        created < encoded_len(&fallback),
        "the fixture fallback is larger"
    );
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = TaskStore::open(&path, limits(created)).await.unwrap();

    let refused = store.create(PreparedTask::for_test(&task, OWNER, 1)).await;

    assert!(matches!(refused, Err(StoreError::Capacity)), "{refused:?}");
    assert!(store.get(OWNER, task.id()).is_err(), "nothing was stored");
    assert!(!path.join(format!("{}.json", task.id())).exists());
    store.close().await.unwrap();
}

/// At the widest fallback's size a task is admitted and a too-large outcome
/// settles as the bounded failure; one byte less and it is refused.
/// Mutants: the revision or the settle instant measured at its natural width.
#[tokio::test]
async fn the_creation_bound_is_the_widest_fallback() {
    let task = task();
    let (_, fallback) = created_and_fallback(&task).await;
    let bound = widest(fallback);

    let dir = tempfile::tempdir().unwrap();
    let below = TaskStore::open(&dir.path().join("below"), limits(bound - 1))
        .await
        .unwrap();
    // A whole-second clock: an unwidened instant would print no fraction.
    below.set_clock_for_test(Some(at(1)));
    let refused = below.create(PreparedTask::for_test(&task, OWNER, 1)).await;
    assert!(matches!(refused, Err(StoreError::Capacity)), "{refused:?}");
    below.close().await.unwrap();

    let at_bound = TaskStore::open(&dir.path().join("at"), limits(bound))
        .await
        .unwrap();
    at_bound
        .create(PreparedTask::for_test(&task, OWNER, 1))
        .await
        .expect("the widest fallback fits");
    let settled = at_bound
        .settle_bounded(
            OWNER,
            task.id(),
            1,
            (oversize(bound), Some(Vec::new())),
            at(1),
        )
        .await
        .expect("the fallback is stored, not left working");
    assert_eq!(settled.task.status(), TaskStatus::Failed);
    assert!(settled.output_free);
    at_bound.close().await.unwrap();
}

/// A round adds its keys to the model, which the fallback keeps. A round whose
/// own record (and its shortest answer) fits but whose fallback does not is
/// refused, so the task can still settle. Mutant: the round check removed.
#[tokio::test]
async fn a_round_that_leaves_no_room_for_the_fallback_is_refused() {
    let task = task();
    // Measured in a store with room: the round's record with its shortest
    // answer, and the fallback the task settles as once the round is open.
    let (with_answer, fallback) = {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tasks");
        let store = TaskStore::open(&path, limits(4 * 1024)).await.unwrap();
        store
            .create(PreparedTask::for_test(&task, OWNER, 1))
            .await
            .unwrap();
        let (requested, round) = smallest_round();
        let parked = store
            .require_input(OWNER, task.id(), 1, requested, round, at(1))
            .await
            .unwrap();
        let mut open = record_file(&path, task.id());
        open["inputRound"]["acceptedInputs"] = json!({ "k": {} });
        let with_answer = encoded_len(&open);
        let settled = store
            .settle_bounded(
                OWNER,
                task.id(),
                parked.revision,
                (oversize(4 * 1024), Some(Vec::new())),
                at(2),
            )
            .await
            .unwrap();
        assert!(
            settled.output_free,
            "the fixture outcome takes the fallback"
        );
        let fallback = widest(record_file(&path, task.id()));
        store.close().await.unwrap();
        (with_answer, fallback)
    };
    // Room for the round and its answer, none for its widest fallback: before
    // the check, this round was accepted. The created task's own fallback,
    // without the round's key, still fits.
    let limit = fallback - 1;
    assert!(
        with_answer <= limit,
        "the fixture round must fit where its fallback does not: {with_answer} > {limit}"
    );
    let dir = tempfile::tempdir().unwrap();
    let store = TaskStore::open(&dir.path().join("tasks"), limits(limit))
        .await
        .unwrap();
    let created = store
        .create(PreparedTask::for_test(&task, OWNER, 1))
        .await
        .expect("the created task's own fallback fits");
    let (requested, round) = smallest_round();

    let refused = store
        .require_input(OWNER, task.id(), created.revision, requested, round, at(1))
        .await;

    assert!(matches!(refused, Err(StoreError::Capacity)), "{refused:?}");
    let after = store.get(OWNER, task.id()).unwrap();
    assert_eq!(after.task.status(), TaskStatus::Working);
    assert_eq!(after.revision, created.revision, "nothing was written");
    store.close().await.unwrap();
}

/// A working row written with room, reopened under a cap it fits but its
/// fallback does not (a lowered cap, or a row from before this check): the
/// store refuses to open, as it does for a row over the cap. Mutant: the
/// loader check removed.
#[tokio::test]
async fn a_stored_working_row_without_fallback_room_refuses_the_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let task = task();
    let store = TaskStore::open(&path, limits(4 * 1024)).await.unwrap();
    store
        .create(PreparedTask::for_test(&task, OWNER, 1))
        .await
        .unwrap();
    store.close().await.unwrap();
    let row = fs::read(path.join(format!("{}.json", task.id())))
        .unwrap()
        .len();

    let refused = TaskStore::open(&path, limits(row)).await;
    assert!(
        matches!(refused, Err(StoreError::Capacity)),
        "{:?}",
        refused.err()
    );

    let reopened = TaskStore::open(&path, limits(4 * 1024))
        .await
        .expect("with room for the fallback the row loads");
    assert_eq!(
        reopened.get(OWNER, task.id()).unwrap().task.status(),
        TaskStatus::Working
    );
    reopened.close().await.unwrap();
}

/// The loader judges every live row, a row waiting on input included, and
/// never a settled one: a settled row does not settle again, so it loads
/// under a cap that fits it exactly. Mutants: the check applied to terminal
/// rows, or skipped for rows waiting on input.
#[tokio::test]
async fn the_open_judges_live_rows_and_not_settled_ones() {
    let dir = tempfile::tempdir().unwrap();
    let (waiting, settled) = (task(), task());
    let measure = |path: &std::path::Path, task: &Task| {
        fs::read(path.join(format!("{}.json", task.id())))
            .unwrap()
            .len()
    };

    let waiting_path = dir.path().join("waiting");
    let store = TaskStore::open(&waiting_path, limits(4 * 1024))
        .await
        .unwrap();
    store
        .create(PreparedTask::for_test(&waiting, OWNER, 1))
        .await
        .unwrap();
    let (requested, round) = smallest_round();
    store
        .require_input(OWNER, waiting.id(), 1, requested, round, at(1))
        .await
        .unwrap();
    store.close().await.unwrap();
    let row = measure(&waiting_path, &waiting);
    let refused = TaskStore::open(&waiting_path, limits(row)).await;
    assert!(
        matches!(refused, Err(StoreError::Capacity)),
        "{:?}",
        refused.err()
    );

    let settled_path = dir.path().join("settled");
    let store = TaskStore::open(&settled_path, limits(4 * 1024))
        .await
        .unwrap();
    store
        .create(PreparedTask::for_test(&settled, OWNER, 1))
        .await
        .unwrap();
    store
        .settle_bounded(
            OWNER,
            settled.id(),
            1,
            (oversize(4 * 1024), Some(Vec::new())),
            at(1),
        )
        .await
        .unwrap();
    store.close().await.unwrap();
    let row = measure(&settled_path, &settled);
    let reopened = TaskStore::open(&settled_path, limits(row))
        .await
        .expect("a settled row needs no room beyond itself");
    assert_eq!(
        reopened.get(OWNER, settled.id()).unwrap().task.status(),
        TaskStatus::Failed
    );
    reopened.close().await.unwrap();
}
