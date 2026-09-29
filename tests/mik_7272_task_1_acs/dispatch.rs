// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `dispatch` cases of `mik_7272_task_1_acs`, split out to keep that file
//! under its size baseline.

use std::sync::Arc;

use serde_json::json;

use axum::http::StatusCode;

use super::http::{
    modern, post, post_against, post_direct, state, state_holding, task_id_of, task_invoke,
};

/// An id nothing ever created. A negative control, and it stays one.
const FABRICATED_ID: &str = "task-00000000-0000-4000-8000-000000000000";

// =======================================================================
// MIK-7272.TASK.1.1 — a task-augmented call returns `CreateTaskResult` with
// `resultType: "task"` and a `taskId` that `tasks/get` already resolves.
// =======================================================================

/// The round trip the criterion words: the created id resolves immediately,
/// before any status change.
///
/// It used to be VACUOUS AS A CONSTRAINT — any stub returning a handle
/// passed it — and it is still `.4` that catches a stub and `.11` that
/// catches a missing ownership check. What has changed is that the call is
/// now eligible to BECOME a task, so the handle is a real durable UUID and
/// the backend really ran: the dispatch count below is the half that a
/// hand-built handle could never satisfy.
#[tokio::test]
async fn ac_task_1_1_a_created_task_id_resolves_immediately() {
    let fixture = state().await;
    let (_, created) = post_against(
        Arc::clone(&fixture.state),
        "key-a",
        task_invoke(10, "mik-7272-task-1-1-create"),
    )
    .await;

    assert_eq!(
        created.pointer("/result/resultType"),
        Some(&json!("task")),
        "a declared task-augmented call is answered with a task handle: {created}"
    );
    let task_id = task_id_of(&created);

    // The dispatch is spawned, so the count becomes observable only once
    // the worker has run: bounded by scheduler turns, never by a clock. The
    // equality is what matters — one create is one backend run.
    fixture.backend.wait_for_calls(1).await;

    let (_, fetched) = post_against(
        Arc::clone(&fixture.state),
        "key-a",
        modern(11, "tasks/get", json!({ "taskId": task_id.clone() }), true),
    )
    .await;
    assert_eq!(
        fetched.pointer("/result/taskId"),
        Some(&json!(task_id)),
        "the id the creator was handed resolves before any status change: {fetched}"
    );
}

// =======================================================================
// MIK-7272.TASK.1.3 — `tasks/update` is accepted, refuses an
// `inputResponses` key matching no outstanding input request, and
// acknowledges with an empty `resultType: "complete"`.
// =======================================================================

/// The refusal half. It names an id nothing created, which is deliberate:
/// the rule under test is that an input response matching no outstanding
/// request is refused, and there is no configuration of this gateway in
/// which one is outstanding.
///
/// CARVE-OUT (§11.6): nothing here asserts what an update does to `ttlMs` or
/// `pollIntervalMs`. The specification's MAY-change clauses for both fields
/// are unstated in §3 and open; a case pinning either behaviour would pin an
/// unresolved design question.
#[tokio::test]
async fn ac_task_1_3_an_input_response_with_no_outstanding_request_is_refused() {
    // `input_required` is out of scope for TASK.1, so there are never
    // outstanding keys and any non-empty map is refused.
    let (_, body) = post(
        "key-a",
        modern(
            12,
            "tasks/update",
            json!({ "taskId": FABRICATED_ID, "inputResponses": { "prompt-1": "yes" } }),
            true,
        ),
    )
    .await;
    assert!(
        body.get("error").is_some(),
        "an input response matching no outstanding request is refused: {body}"
    );
}

/// The acceptance half, on a task that is genuinely RUNNING.
///
/// The held backend is what makes that true. With a backend that answers
/// immediately the task can settle between the create and the update, and
/// the row would then be reporting on an update to a terminal task while
/// claiming to report on an accepted one — a difference no assertion here
/// could see. `wait_for_dispatch` is a barrier at the seam, not a delay:
/// it returns when the dispatch has actually reached the backend and is
/// being held there.
#[tokio::test]
async fn ac_task_1_3_an_accepted_update_acknowledges_with_an_empty_result() {
    let (fixture, mut gate) = state_holding().await;
    let (_, created) = post_against(
        Arc::clone(&fixture.state),
        "key-a",
        task_invoke(13, "mik-7272-task-1-3-create"),
    )
    .await;
    let task_id = task_id_of(&created);
    gate.wait_for_dispatch().await;

    let (_, body) = post_against(
        Arc::clone(&fixture.state),
        "key-a",
        modern(14, "tasks/update", json!({ "taskId": task_id }), true),
    )
    .await;
    assert_eq!(
        body.pointer("/result/resultType"),
        Some(&json!("complete")),
        "the acknowledgement is an empty `complete` result: {body}"
    );
    // `_meta` is excluded because it is the gateway's envelope, not the
    // ack's payload: `handlers.rs` stamps `serverInfo` into every result it
    // serves, so a count including it could never be 1 and the case could
    // never go green. What the criterion is about is that the ack carries
    // NO payload of its own.
    let payload_keys: Vec<&str> = body["result"]
        .as_object()
        .expect("the ack is an object")
        .keys()
        .map(String::as_str)
        .filter(|key| *key != "_meta")
        .collect();
    assert_eq!(
        payload_keys,
        ["resultType"],
        "empty means empty: the ack carries `resultType` and nothing else: {body}"
    );

    // An update is not a dispatch: the one held call is still the only one.
    assert_eq!(
        fixture.backend.calls(),
        1,
        "an accepted `tasks/update` must not run the tool a second time"
    );
    gate.release_all();
}

// =======================================================================
// MIK-7311.LIFECYCLE.1 (as amended by the #2268 ruling) — tasks run through
// POST /mcp only; POST /mcp/{backend} refuses task access with -32601, as
// MIK-7596.OWNER.1 requires.
// =======================================================================

/// A task created and still running on `/mcp` is not reachable through the
/// per-backend route, even by its OWNER; `/mcp` still serves it.
///
/// The owner sends every call, so the refusal is the route's and not an
/// ownership answer. The cross-caller cells (caller B never reaches the
/// backend) are `router::direct_tasks_owner_tests`, which an integration
/// test cannot import. The code and message are checked together because
/// the counted backend answers any forwarded method with success `{}`.
#[tokio::test]
async fn lifecycle_1_the_per_backend_route_refuses_a_task_served_on_mcp() {
    let (fixture, mut gate) = state_holding().await;
    let (_, created) = post_against(
        Arc::clone(&fixture.state),
        "key-a",
        task_invoke(15, "mik-7311-lifecycle-1-direct-refusal"),
    )
    .await;
    let task_id = task_id_of(&created);
    gate.wait_for_dispatch().await;

    let mut request_id = 16;
    for (method, params) in [
        ("tasks/get", json!({ "taskId": task_id })),
        ("tasks/result", json!({ "taskId": task_id })),
        ("tasks/update", json!({ "taskId": task_id })),
        ("tasks/cancel", json!({ "taskId": task_id })),
        ("subscriptions/listen", json!({ "taskIds": [task_id] })),
    ] {
        let (status, body) = post_direct(
            Arc::clone(&fixture.state),
            "key-a",
            modern(request_id, method, params, true),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{method}: {body}");
        assert_eq!(
            body.pointer("/error/code"),
            Some(&json!(-32601)),
            "{method} on /mcp/{{backend}} is refused -32601: {body}"
        );
        assert!(
            body.pointer("/error/message")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|message| message.contains("use /mcp")),
            "{method} refusal must point at /mcp: {body}"
        );
        assert_eq!(body["id"], json!(request_id), "{method}: {body}");
        request_id += 1;
    }
    assert_eq!(
        fixture.backend.calls(),
        1,
        "no refused call may dispatch the tool again"
    );

    // Positive control: the same task, same owner, on /mcp is served and
    // was not cancelled by the refused `tasks/cancel`.
    let (_, fetched) = post_against(
        Arc::clone(&fixture.state),
        "key-a",
        modern(request_id, "tasks/get", json!({ "taskId": task_id }), true),
    )
    .await;
    assert_eq!(
        fetched.pointer("/result/taskId"),
        Some(&json!(task_id)),
        "/mcp still serves the task: {fetched}"
    );
    assert_ne!(
        fetched.pointer("/result/status"),
        Some(&json!("cancelled")),
        "a refused per-backend cancel must not cancel the task: {fetched}"
    );
    gate.release_all();
}
