// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7311.LIFECYCLE.1: the input round's durable writes. Each test names
//! the mutant it must fail on.

use super::*;
use crate::gateway::task_service::record::InputRound;
use crate::gateway::task_service::store::input::ProvideOutcome;

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
    }
}

fn answers(value: Value) -> serde_json::Map<String, Value> {
    let Value::Object(map) = value else {
        panic!("answers are an object")
    };
    map
}

async fn parked(store: &TaskStore, task: &Task, keys: &[&str]) -> u64 {
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
        .require_input(OWNER, task.id(), created.revision, requested, round("sealed"), at(1))
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
    assert!(matches!(refused, Err(StoreError::Capacity)), "{:?}", refused.err());
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
        .provide_input(OWNER, task.id(), answers(json!({ "a": { "v": 1 } })), || None, at(2))
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
    let ProvideOutcome::Resumed { task: now, round, .. } = done else {
        panic!("the completing answer resumes");
    };
    assert_eq!(now.task.status(), TaskStatus::Working);
    assert_eq!(
        Value::Object(round.accepted_inputs),
        json!({ "a": { "v": 1 }, "b": { "v": 2 } })
    );
    assert_eq!(round.request_state.as_deref(), Some("sealed"));
    assert_eq!(workers.available_permits(), 0, "the permit travels with the resume");
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
        .provide_input(OWNER, task.id(), answers(json!({ "confirm": {} })), || None, at(2))
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
        .map(|(id, _, owner)| (id, owner))
        .collect();
    assert_eq!(selected, vec![(open_round.id().to_owned(), OWNER.to_owned())]);
    assert!(store.expired_input_rounds(at(5)).is_empty(), "not before the TTL");
}
