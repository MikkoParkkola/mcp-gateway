// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7778 PAYLOAD.1: `notifications/tasks` carries the full task state, as
//! the tasks extension says, but only what `tasks/get` would deliver to that
//! reader at that moment: output states are re-authorized per reader, and a
//! refused reader gets the task id and status and no output.
//!
//! A child of `notifications`, declared there with `#[path]`, so it reads the
//! same bounded stream reader.
use super::super::super::*;
use super::super::stored_result_policy::withhold;
use super::super::support::*;
use super::helpers::{ReleasedOnDrop, expect_message, open_listen};

/// The completion notification for `id` on `stream`.
async fn completion(stream: &mut super::helpers::EventStream, id: &str, who: &str) -> Value {
    let event = expect_message(stream, &format!("{who}'s completion notification")).await;
    std::assert_eq!(event["params"]["taskId"], json!(id), "{who}: {event}");
    event
}

/// The owner receives the whole task, result included; each principal's
/// notification carries its own task and nothing of the other's.
#[tokio::test]
async fn the_owner_receives_the_full_task_and_never_the_other_principals() {
    let (mock, gate) = MockBackend::holding(Answer::ok());
    let mut gate = ReleasedOnDrop(gate);
    let (state, _store) = state_with(&mock).await;

    let id_a = task_id(
        &post(
            &state,
            "key-a",
            task_invoke(7501, "p1-a", json!({ "q": "a" })),
        )
        .await,
    );
    let id_b = task_id(
        &post(
            &state,
            "key-b",
            task_invoke(7502, "p1-b", json!({ "q": "b" })),
        )
        .await,
    );
    gate.0.wait_for_dispatch().await;
    gate.0.wait_for_dispatch().await;

    let mut stream_a = open_listen(&state, "key-a", 7511, json!({ "taskIds": [&id_a] })).await;
    let mut stream_b = open_listen(&state, "key-b", 7512, json!({ "taskIds": [&id_b] })).await;
    gate.0.release_all();
    assert_carries_the_backend_result(&poll_until_terminal(&state, "key-a", &id_a).await);
    assert_carries_the_backend_result(&poll_until_terminal(&state, "key-b", &id_b).await);

    let a = completion(&mut stream_a, &id_a, "principal-a").await;
    let b = completion(&mut stream_b, &id_b, "principal-b").await;
    for (event, own, other) in [(&a, &id_a, &id_b), (&b, &id_b, &id_a)] {
        std::assert_eq!(event["params"]["status"], json!("completed"), "{event}");
        std::assert_eq!(
            event["params"].pointer("/result/structuredContent/marker"),
            Some(&json!("mock-backend-answered")),
            "the notification carries the full task, result included, for {own}: {event}"
        );
        std::assert!(
            event["params"].get("resultType").is_none(),
            "resultType belongs to a response, not a notification: {event}"
        );
        std::assert!(
            !event.to_string().contains(other.as_str()),
            "a notification names no other principal's task: {event}"
        );
    }
}

/// A reader whose stored target is no longer deliverable to it learns the task
/// id and status and never the output.
#[tokio::test]
async fn a_reader_refused_by_policy_gets_the_status_and_no_output() {
    let (mock, gate) = MockBackend::holding(Answer::ok());
    let mut gate = ReleasedOnDrop(gate);
    let (state, _store) = state_with(&mock).await;

    let id = task_id(
        &post(
            &state,
            "key-a",
            task_invoke(7601, "p2-a", json!({ "q": "a" })),
        )
        .await,
    );
    gate.0.wait_for_dispatch().await;
    let mut stream = open_listen(&state, "key-a", 7611, json!({ "taskIds": [&id] })).await;

    // The tool is withheld after the task started and before it settles, the
    // same condition that makes `tasks/get` refuse the stored result.
    withhold(&state, TOOL);
    gate.0.release_all();

    let event = completion(&mut stream, &id, "principal-a").await;
    std::assert_eq!(event["params"]["status"], json!("completed"), "{event}");
    std::assert!(
        event["params"].get("result").is_none()
            && !event.to_string().contains("mock-backend-answered"),
        "a refused reader must receive no output: {event}"
    );
}
