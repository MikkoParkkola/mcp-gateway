// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! No stored row holds both an upstream handle and parked input requests: the
//! store refuses the handle write on a waiting row. A record that holds both
//! anyway (written by hand, or by another build) still loads, and is served
//! withheld.
use super::*;
use crate::gateway::task_service::record::{InputRound, UpstreamRecord};

/// A prompt text that appears nowhere but in the stored request.
const PROMPT: &str = "stored-prompt-91ad finish with key legacy-secret-c3e0";
/// The request's key, also the backend's.
const KEY: &str = "ask-91ad";

fn waiting() -> Task {
    let mut task = task();
    task.transition(
        TaskTransition::RequireInput(InputRequired {
            requests: vec![(
                KEY.to_owned(),
                json!({"method": "elicitation/create", "params": {"message": PROMPT}}),
            )],
            request_state: None,
        }),
        at(1),
    )
    .expect("a live task parks");
    task
}

/// A handle descriptor for a row admitted by `PreparedTask::for_test`.
fn handle(fingerprint: &str) -> UpstreamRecord {
    UpstreamRecord {
        handle: "upstream-handle-91ad".into(),
        backend: "orders".into(),
        tool: "create".into(),
        arguments: json!({}),
        operation_digest: "a".repeat(64),
        secret_fingerprint: Some(fingerprint.to_owned()),
    }
}

/// The store refuses to write a handle onto a row waiting on input and leaves
/// every file as it was; a working row still takes its handle (the control).
#[tokio::test]
async fn a_handle_is_never_written_onto_a_row_waiting_on_input() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let parked = waiting();
    store
        .create(PreparedTask::for_test(&parked, OWNER, 1))
        .await
        .unwrap();
    let before = files(&path);
    let refused = store
        .mark_upstream(OWNER, parked.id(), 1, (handle("none"), Vec::new()))
        .await;
    assert!(
        matches!(refused, Err(StoreError::InvalidTransition)),
        "{refused:?}"
    );
    assert_eq!(files(&path), before, "a refused handle wrote something");
    let working = task();
    store
        .create(PreparedTask::for_test(&working, OWNER, 2))
        .await
        .unwrap();
    store
        .mark_upstream(OWNER, working.id(), 1, (handle("none"), Vec::new()))
        .await
        .expect("a working row takes its handle");
    store.close().await.unwrap();
}

/// The other order: a row that holds a handle never parks a round, and stays
/// as it was. A row without one still parks (the control).
#[tokio::test]
async fn a_row_holding_a_handle_never_parks_a_round() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    store.set_clock_for_test(Some(at(1)));
    let round = || InputRound {
        request_state: Some("sealed".to_owned()),
        tool: "gateway_invoke".to_owned(),
        arguments: json!({}),
        accepted_inputs: serde_json::Map::new(),
        continuation_deadline: None,
        surfaced_server: None,
    };
    let ask = || InputRequired {
        requests: vec![(
            KEY.to_owned(),
            json!({"method": "elicitation/create", "params": {}}),
        )],
        request_state: None,
    };
    let held = task();
    store
        .create(PreparedTask::for_test(&held, OWNER, 1))
        .await
        .unwrap();
    store
        .mark_upstream(OWNER, held.id(), 1, (handle("none"), Vec::new()))
        .await
        .expect("a working row takes its handle");
    let revision = store.get(OWNER, held.id()).unwrap().revision;
    let before = files(&path);
    let refused = store
        .require_input(OWNER, held.id(), revision, ask(), round(), at(1))
        .await;
    assert!(
        matches!(refused, Err(StoreError::InvalidTransition)),
        "{refused:?}"
    );
    assert_eq!(files(&path), before, "a refused round wrote something");
    let plain = task();
    store
        .create(PreparedTask::for_test(&plain, OWNER, 2))
        .await
        .unwrap();
    store
        .require_input(OWNER, plain.id(), 1, ask(), round(), at(1))
        .await
        .expect("a row without a handle parks its round");
    store.close().await.unwrap();
}

/// A record holding an unvouched handle and parked input requests together
/// loads after a reopen, and its read serves no stored prompt and no request
/// key: the state stays `input_required`, with the fixed withheld sentence as
/// its status message.
#[tokio::test]
async fn a_stored_unvouched_row_waiting_on_input_is_served_withheld() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let parked = waiting();
    store
        .create(PreparedTask::for_test(&parked, OWNER, 1))
        .await
        .unwrap();
    store.close().await.unwrap();
    let file = path.join(format!("{}.json", parked.id()));
    let mut record: Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    record["upstream"] =
        serde_json::to_value(handle(crate::security::dispatched::MISSING)).unwrap();
    fs::write(&file, serde_json::to_vec(&record).unwrap()).unwrap();

    let reopened = open(&path).await;
    let row = reopened
        .get(OWNER, parked.id())
        .expect("the record with both loads");
    assert!(row.withholds_outcome(), "premise: the row is unvouched");
    let served = row.delivered_wire();
    reopened.close().await.unwrap();
    let text = served.to_string();
    assert!(!text.contains(PROMPT), "a stored prompt was served: {text}");
    assert!(
        !text.contains(KEY),
        "a stored request key was served: {text}"
    );
    assert_eq!(served["status"], json!("input_required"), "{served}");
    assert_eq!(
        served["statusMessage"],
        json!(crate::gateway::meta_mcp::upstream::SECRETS_WITHHELD),
        "{served}"
    );
}
