// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7778: the tasks extension names the task filter at
//! `params.notifications.taskIds`, so a listen naming it there is scoped by the
//! same all-or-empty ownership narrowing as the root form, never wider.
//!
//! A child of `notifications`, declared there with `#[path]`, so it reads the
//! same bounded stream reader and shaped assertions.
use super::super::super::*;
use super::super::support::*;
use super::helpers::{assert_only_its_own_task, assert_receives_nothing, open_listen};

/// The nested form delivers the caller's own task, and a foreign or a mixed
/// nested filter receives nothing, its own task included.
#[tokio::test]
async fn a_nested_task_filter_is_narrowed_like_the_root_one() {
    let (mock, gate) = MockBackend::holding(Answer::ok());
    let mut gate = ReleasedOnDrop(gate);
    let (state, _store) = state_with(&mock).await;

    let created_a = post(
        &state,
        "key-a",
        task_invoke(7401, "n4-a", json!({ "q": "a" })),
    )
    .await;
    let id_a = task_id(&created_a);
    let created_b = post(
        &state,
        "key-b",
        task_invoke(7402, "n4-b", json!({ "q": "b" })),
    )
    .await;
    let id_b = task_id(&created_b);
    gate.0.wait_for_dispatch().await;
    gate.0.wait_for_dispatch().await;

    let mut control = open_listen(
        &state,
        "key-a",
        7411,
        json!({ "notifications": { "taskIds": [&id_a] } }),
    )
    .await;
    let mut mixed = open_listen(
        &state,
        "key-a",
        7412,
        json!({ "notifications": { "taskIds": [&id_a, &id_b] } }),
    )
    .await;
    let mut foreign = open_listen(
        &state,
        "key-a",
        7413,
        json!({ "notifications": { "taskIds": [&id_b] } }),
    )
    .await;
    // An owned id at the root must not launder a foreign one nested beside it.
    let mut split = open_listen(
        &state,
        "key-a",
        7414,
        json!({ "taskIds": [&id_a], "notifications": { "taskIds": [&id_b] } }),
    )
    .await;

    gate.0.release_all();
    assert_carries_the_backend_result(&poll_until_terminal(&state, "key-a", &id_a).await);
    assert_carries_the_backend_result(&poll_until_terminal(&state, "key-b", &id_b).await);

    assert_only_its_own_task(&mut control, &id_a, 7411, "the nested control stream").await;
    assert_receives_nothing(
        &mut mixed,
        "a nested filter naming an owned and a foreign task is narrowed to the empty list",
    )
    .await;
    assert_receives_nothing(
        &mut foreign,
        "a nested filter naming only another principal's task receives nothing",
    )
    .await;
    assert_receives_nothing(
        &mut split,
        "an owned root id does not launder a foreign nested id",
    )
    .await;
}
