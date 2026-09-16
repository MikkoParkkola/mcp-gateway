// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! X1 — the first vertical row, and the two controls that make it readable.
//!
//! Adapter design r3 §9: *"one task-augmented `tools/call` through the real HTTP
//! router, answered `working` with a `taskId`, dispatched to a mock backend
//! whose call counter is exactly 1, polled through `tasks/get` to `completed`
//! carrying the backend's result verbatim. It is the single row that cannot pass
//! unless all three lanes are actually joined."*
//!
//! RED at `13e97b30`, and red for the intended reason rather than for a fixture
//! one: `handlers.rs:1194` answers a task-augmented call by minting a record and
//! returning before authorization, the firewall, the dispatcher and the backend
//! all of them. So today the create arm answers a handle, the handle stays
//! `working` forever, and the mock's counter stays at 0. The control below runs
//! the identical call with no `task` member and reaches the same backend through
//! the same transport, which is what tells "the adapter does not dispatch" apart
//! from "this fixture was never wired".
use super::super::*;
use super::support::*;

// =====================================================================
// Controls — not acceptance criteria; the reason X1 means anything
// =====================================================================

/// GIVEN the fixture backend, WHEN an ordinary synchronous call is made,
/// THEN it reaches the backend and its result reaches the client.
///
/// Without this, X1's "the counter is exactly 1" cannot tell a dispatched task
/// from a transport that was never reachable at all: both leave the counter
/// where they found it, and no assertion in this suite can separate them.
#[tokio::test]
async fn fixture_control_an_ordinary_call_reaches_the_mock_backend() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;

    let body = post(
        &state,
        "key-a",
        keyed(sync_invoke(1, json!({ "q": "control" })), "x1-sync-control"),
    )
    .await;

    std::assert_eq!(
        mock.calls(),
        1,
        "an ordinary `tools/call` must reach the fixture transport exactly once; \
         the gateway answered {body}"
    );
    assert!(
        serde_json::to_string(&body)
            .unwrap_or_default()
            .contains("mock-backend-answered"),
        "the backend's own result must reach the caller on the synchronous path, \
         or every result assertion in this suite is measuring the fixture: {body}"
    );
}

/// GIVEN the fixture backend, WHEN a call names a backend the credential may
/// not reach, THEN nothing arrives at the transport.
///
/// The negative half of the control above. A recorder that fills on every call
/// regardless of the gateway's decision would make each "the backend never ran"
/// assertion in this suite vacuous.
#[tokio::test]
async fn fixture_control_a_refused_call_reaches_nothing() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let forbidden = register_forbidden(&state);

    let body = post(
        &state,
        "key-a",
        modern(
            2,
            "tools/call",
            json!({
                "name": "gateway_invoke",
                "arguments": { "server": FORBIDDEN_BACKEND, "tool": TOOL, "arguments": {} }
            }),
            true,
        ),
    )
    .await;

    assert!(
        body.get("error").is_some(),
        "a credential scoped away from '{FORBIDDEN_BACKEND}' must be refused: {body}"
    );
    std::assert_eq!(
        forbidden.calls(),
        0,
        "the named backend is registered and answering, so the refusal is the \
         credential's scope and not a missing backend — and it still reached \
         nothing: {body}"
    );
    std::assert_eq!(
        mock.calls(),
        0,
        "and the refused call did not land on the OTHER backend either: {body}"
    );
}

// =====================================================================
// MIK-7272.TASK.1 / adapter design r3 §9 — X1
// =====================================================================

/// X1 — a declared, keyed, task-augmented call is dispatched exactly once and
/// its handle resolves to `completed` carrying the backend's own result.
///
/// The whole vertical in one row:
/// * the create answers a `CreateTaskResult` handle (`resultType: "task"`,
///   design §5) with a `taskId` and status `working`;
/// * the backend is reached exactly once — not zero times (never dispatched)
///   and not twice (dispatched by both the request thread and the worker);
/// * `tasks/get` reaches `completed`;
/// * the settled result is the backend's, byte-for-byte, rather than a summary
///   the gateway invented.
#[tokio::test]
async fn x1_a_task_augmented_call_dispatches_once_and_completes_with_the_backend_result() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;

    let created = post(
        &state,
        "key-a",
        task_invoke(10, "x1-key", json!({ "q": 1 })),
    )
    .await;

    std::assert_eq!(
        created.pointer("/result/resultType"),
        Some(&json!("task")),
        "a declared task-augmented call is answered with a task handle: {created}"
    );
    std::assert_eq!(
        status_of(&created),
        "working",
        "the handle a create hands back names the task as running, not as finished: {created}"
    );
    let id = task_id(&created);

    let fetched = poll_until_terminal(&state, "key-a", &id).await;

    assert_carries_the_backend_result(&fetched);
    std::assert_eq!(
        mock.calls(),
        1,
        "the task must reach the backend exactly once — 0 means the handle was \
         minted and nothing was ever dispatched, which is the arm at \
         `handlers.rs:1194`; 2 means both the request thread and the worker \
         dispatched it. The backend saw {:?} and the task settled as {fetched}",
        mock.seen()
    );
}

/// X1, second half of the same claim: the dispatched call is the caller's call.
///
/// Split from the row above rather than folded into it because it fails for a
/// different defect — a worker that dispatches a call it reconstructed from the
/// record instead of forwarding the arguments the client sent. The counter row
/// cannot see that; this one can.
#[tokio::test]
async fn x1_the_dispatched_call_carries_the_callers_own_arguments() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;

    let created = post(
        &state,
        "key-a",
        task_invoke(11, "x1-args", json!({ "q": "carried-through" })),
    )
    .await;
    let id = task_id(&created);
    let _ = poll_until_terminal(&state, "key-a", &id).await;

    let seen = mock.seen();
    std::assert_eq!(
        seen.len(),
        1,
        "exactly one dispatch reaches the backend, it saw {seen:?}"
    );
    std::assert_eq!(
        seen[0].get("name").and_then(Value::as_str),
        Some(TOOL),
        "the worker dispatches the tool the caller named: {seen:?}"
    );
    std::assert_eq!(
        seen[0].pointer("/arguments/q"),
        Some(&json!("carried-through")),
        "the worker forwards the caller's own arguments rather than a \
         reconstruction of them: {seen:?}"
    );
}
