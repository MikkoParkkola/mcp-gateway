// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend's copy of a gateway-only member never reaches the
//! client through a task result or a stored replay.
use super::super::*;
use super::support::*;

use crate::protocol::reserved_members::test_support::{assert_nothing_forged, planted};

/// FORGE.3, a task result: the stored result a `tasks/get` serves.
#[tokio::test]
async fn a_task_result_delivers_no_planted_member() {
    let mock = MockBackend::answering(Answer::Result(planted()));
    let (state, store) = state_with(&mock).await;
    let created = post(&state, "key-a", task_invoke(1, "forge-task", json!({}))).await;
    let task = task_id(&created);
    let settled = poll_until_terminal(&state, "key-a", &task).await;
    std::assert_eq!(status_of(&settled), "completed", "{settled}");
    assert_nothing_forged("task result", &settled);
    // The row on disk: what ingress withheld for a chain is never stored.
    let row = std::fs::read_to_string(store.path().join("tasks").join(format!("{task}.json")))
        .expect("the task row is on disk");
    assert!(
        !row.contains("FORGED-"),
        "a stripped member was stored: {row}"
    );
}

/// FORGE.3, a stored replay: the same keyed call again is answered from the
/// stored delivery, without the backend.
#[tokio::test]
async fn a_stored_replay_delivers_no_planted_member() {
    let mock = MockBackend::answering(Answer::Result(planted()));
    let (state, _store) = state_with(&mock).await;
    let first = post(
        &state,
        "key-a",
        keyed(sync_invoke(1, json!({})), "forge-replay"),
    )
    .await;
    assert_nothing_forged("first keyed call", &first);
    let replayed = post(
        &state,
        "key-a",
        keyed(sync_invoke(2, json!({})), "forge-replay"),
    )
    .await;
    std::assert_eq!(mock.calls(), 1, "the second call is a replay: {replayed}");
    assert_nothing_forged("stored replay", &replayed);
}
