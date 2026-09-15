// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! X2 and X3 — the handle while the work is still running, and cancel winning
//! against a dispatch that is already in flight.
//!
//! Both rows are built on one barrier: [`MockBackend::holding`] reports when a
//! dispatch has actually reached the backend and holds it there until the test
//! releases it. Nothing waits on a clock. The distinction that makes the barrier
//! necessary is that a `working` status proves nothing on its own — a task that
//! was never dispatched reads exactly the same as one whose backend has not
//! answered yet, and only "the backend has been reached" tells them apart.
//!
//! X3 is pinned to the **after-dispatch** race deliberately: the cancel arrives
//! while the backend holds the call, so the worker's settlement and the cancel's
//! terminal write genuinely compete. The before-dispatch window is X16a's, and
//! its barrier is a durable-write stage this suite cannot observe yet (see
//! `interlock.rs`).
use super::super::*;
use super::support::*;

// =====================================================================
// adapter design r3 §9 — X2
// =====================================================================

/// X2 — the handle resolves `working`, with no result, **before** the backend
/// has answered.
///
/// The row the whole background handoff exists for: a task-augmented call must
/// return to the client while the work is still outstanding, and the handle it
/// returned must already be resolvable. The barrier is what makes it an
/// observation — the assertions run at a moment when the backend provably has
/// the call and provably has not answered it.
#[tokio::test]
async fn x2_a_handle_resolves_working_before_the_backend_answers() {
    let (mock, mut gate) = MockBackend::holding(Answer::ok());
    let (state, _store) = state_with(&mock).await;

    let created = post(&state, "key-a", task_invoke(20, "x2-key", json!({}))).await;
    let id = task_id(&created);

    gate.wait_for_dispatch().await;

    let fetched = get_task(&state, "key-a", &id).await;
    std::assert_eq!(
        status_of(&fetched),
        "working",
        "a task whose backend is holding the call is `working`: {fetched}"
    );
    assert!(
        fetched.pointer("/result/result").is_none(),
        "a `working` task carries no result — the payload belongs to the status, \
         and a result here would be a finished answer wearing a running status: {fetched}"
    );
    assert!(
        fetched.pointer("/result/error").is_none(),
        "a `working` task carries no error either: {fetched}"
    );
    std::assert_eq!(
        fetched.pointer("/result/resultType"),
        Some(&json!("complete")),
        "design §5: `tasks/get` answers a `DetailedTask` — `resultType: \"complete\"`. \
         The create arm is the one that answers `\"task\"`; today one projection \
         serves both and the poll arm is the one that must change: {fetched}"
    );

    gate.release();
    let settled = poll_until_terminal(&state, "key-a", &id).await;
    assert_carries_the_backend_result(&settled);
    std::assert_eq!(
        mock.calls(),
        1,
        "the held call is the only dispatch: {:?}",
        mock.seen()
    );
}

// =====================================================================
// adapter design r3 §9 — X3
// =====================================================================

/// X3 — a cancel that lands while the backend holds the call commits
/// `cancelled`, and the backend's later answer does not overwrite it.
///
/// Three separate claims, and the row fails if any one of them breaks:
/// * `tasks/cancel` is a real terminal transition, not the `-32800` failure the
///   arm at `handlers.rs:1550-1567` writes today;
/// * the settle that loses the race leaves the committed `cancelled` view
///   alone — design §4's bounded compare-and-set, "terminal ⇒ keep the
///   committed outcome";
/// * `failed` is never observed at any point, which is what stops a "cancel"
///   implemented as a failure from passing the first two.
#[tokio::test]
async fn x3_a_cancel_during_dispatch_is_terminal_and_the_late_answer_does_not_overwrite_it() {
    let (mock, mut gate) = MockBackend::holding(Answer::ok());
    let (state, _store) = state_with(&mock).await;

    let created = post(&state, "key-a", task_invoke(30, "x3-key", json!({}))).await;
    let id = task_id(&created);
    gate.wait_for_dispatch().await;

    let ack = post(
        &state,
        "key-a",
        task_method(31, "tasks/cancel", json!({ "taskId": id.clone() })),
    )
    .await;
    assert!(
        ack.get("error").is_none(),
        "the owner's cancel of a live task is acknowledged, not refused: {ack}"
    );

    let cancelled = get_task(&state, "key-a", &id).await;
    std::assert_eq!(
        status_of(&cancelled),
        "cancelled",
        "a cancelled task is `cancelled`. `failed` is a different outcome with a \
         different meaning, and `-32800` leaves the tree with the arm that wrote \
         it (design §5): {cancelled}"
    );

    // The backend answers only now. Everything below is about what that answer
    // is allowed to do to a record that is already terminal.
    gate.release();

    // Bounded observation rather than a single read: the settle runs on the
    // worker, so one read immediately after the release could precede it and
    // see the cancelled view for the trivial reason that nothing has happened
    // yet. Every turn is checked, so a transient `failed` cannot slip through
    // between two reads either. The bound is generous enough for the released
    // dispatch and its settlement attempt to run to completion, and it is a
    // count of scheduler turns rather than of elapsed time.
    for _ in 0..500 {
        let fetched = get_task(&state, "key-a", &id).await;
        let status = status_of(&fetched);
        std::assert_eq!(
            status,
            "cancelled",
            "a settlement that lost the race must not write over the committed \
             cancel, and must never produce `failed`: {fetched}"
        );
        assert!(
            fetched.pointer("/result/result").is_none(),
            "the loser's result must not be published on a cancelled task: {fetched}"
        );
        tokio::task::yield_now().await;
    }

    std::assert_eq!(
        mock.calls(),
        1,
        "the cancel must not cause a second dispatch: {:?}",
        mock.seen()
    );
}

/// X3, ownership half: a foreign principal cannot cancel someone else's task,
/// and the refusal is the one that discloses nothing.
///
/// Kept with X3 rather than filed as ownership because it is the same
/// transition: a cancel that any caller can drive is a terminal write with no
/// owner check, and the row above would not notice.
#[tokio::test]
async fn x3_a_foreign_cancel_is_answered_as_an_absent_task_and_changes_nothing() {
    let (mock, mut gate) = MockBackend::holding(Answer::ok());
    let (state, _store) = state_with(&mock).await;

    let created = post(&state, "key-a", task_invoke(32, "x3-foreign", json!({}))).await;
    let id = task_id(&created);
    gate.wait_for_dispatch().await;

    let refused = post(
        &state,
        "key-b",
        task_method(33, "tasks/cancel", json!({ "taskId": id.clone() })),
    )
    .await;
    std::assert_eq!(
        refused.pointer("/error/code"),
        Some(&json!(-32602)),
        "another principal's task answers as an absent one: {refused}"
    );
    assert!(
        !serde_json::to_string(&refused)
            .unwrap_or_default()
            .contains(id.as_str()),
        "the refusal names no task — naming it would let a caller tell \
         \"not yours\" from \"never existed\": {refused}"
    );

    gate.release();
    let settled = poll_until_terminal(&state, "key-a", &id).await;
    assert_carries_the_backend_result(&settled);
}
