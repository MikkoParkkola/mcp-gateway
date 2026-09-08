// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Three review findings, one row each. Every row fails on the runtime as it
//! stood at the 35GREEN checkpoint and passes on the repaired one; no existing
//! row's body or oracle is touched.
//!
//! * **A** — a confirmed destructive accept whose durable record exists but
//!   whose dedupe entry is not yet published (the real `Active` window) answers
//!   a replay of that same accepted grant with `InFlight` (-32002), not with
//!   "this grant will not be honoured". The window is held open at the store's
//!   own publication seam, not simulated by an inserted entry.
//! * **B** — a grant-free repeat of an already-admitted destructive call is
//!   answered with the handle it already owns instead of a fresh challenge,
//!   while a different operation, argument, key or owner is still challenged or
//!   refused and can borrow nothing.
//! * **C** — a `cancel` that loses its revision to a settling worker is
//!   answered from the committed terminal view instead of being reported as an
//!   unavailable store, and writes nothing.
//!
//! Both barriers here are real seams and both are unwind-safe. The store
//! barrier's `Sender` lives in the test frame only: any failed assertion drops
//! it, the blocked commit's `recv()` returns `Err(Disconnected)`, and the held
//! write finishes. Nothing sleeps, nothing is aborted, and every blocked
//! producer is released and joined before the assertions that follow it.
use super::*;

use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{Receiver, TryRecvError, channel};

use crate::gateway::task_service::{ServiceError, TaskStatus};
use crate::key_server::oidc::VerifiedIdentity;

/// The admission principal the route derives for `key-a`.
///
/// Built rather than hardcoded: `support.rs` injects exactly this
/// `VerifiedIdentity` into the request extensions (its `verified_subject` and
/// `http_request` are private to that module), and `handlers.rs:966` keys every
/// task on `VerifiedIdentity::stable_actor_id`. Rendering the id any other way
/// here would test a second identity scheme rather than the route's own.
fn alice() -> String {
    VerifiedIdentity {
        subject: "alice".to_string(),
        email: "alice@adapter.test".to_string(),
        name: None,
        groups: Vec::new(),
        issuer: "https://idp.adapter.test".to_string(),
    }
    .stable_actor_id()
}

/// Wait until the publication barrier reports that a commit has arrived.
///
/// A deadline bounds a missing publication without relying on scheduler speed.
/// Yielding lets the request and its blocking durable write make progress.
async fn wait_for_publication_seam(arrived: &Receiver<()>) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match arrived.try_recv() {
                Ok(()) => return,
                Err(TryRecvError::Empty) => tokio::task::yield_now().await,
                Err(TryRecvError::Disconnected) => {
                    panic!("the publication barrier was dropped before a commit arrived")
                }
            }
        }
    })
    .await
    .expect("no durable publication reached the store before the deadline");
}

/// A: the accepted grant is replayed while the first accept is still `Active`.
///
/// The barrier is the store's own `CommitStage::Published` hook, which fires
/// between the readable-record insert and the dedupe publication
/// (`store.rs:250-258`) — the real window, not a fabricated one. Three things
/// are true inside it and each is asserted: the backend has not been reached,
/// the record is committed, and admission owns the key as `Active`, which is
/// the only state that can answer -32002.
#[tokio::test]
async fn a_replayed_accept_inside_the_active_window_is_in_flight_not_a_dead_grant() {
    let (mock, mut gate) = MockBackend::holding(Answer::ok());
    let (state, _store) = fixture(&mock).await;

    let (arrived_tx, arrived_rx) = channel::<()>();
    let (resume_tx, resume_rx) = channel::<()>();
    // Both halves the blocked thread owns live behind one mutex, which is what
    // makes the barrier `Sync` without a second synchronisation primitive.
    let held = Arc::new(Mutex::new((arrived_tx, resume_rx)));
    let fired = AtomicBool::new(false);
    state
        .task_executor
        .barrier_on_publication(Arc::new(move || {
            // Fire once. The hook stays installed for the whole row, and a
            // later publication must not block on a sender this frame has
            // already used.
            if fired.swap(true, std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            let guard = held.lock().expect("the barrier mutex is never poisoned");
            let _ = guard.0.send(());
            // Returns immediately once the test frame sends OR unwinds.
            let _ = guard.1.recv();
        }))
        .await;

    let original = request("active-window");
    let challenge = post(&state, "key-a", original.clone()).await;
    let accepted = retry(&original, &challenge, "accept");

    // The accepted call is left in flight: its commit is parked at the
    // publication seam with the record already readable.
    let producer = tokio::spawn({
        let state = Arc::clone(&state);
        let accepted = accepted.clone();
        async move { post(&state, "key-a", accepted).await }
    });
    wait_for_publication_seam(&arrived_rx).await;

    std::assert_eq!(
        mock.calls(),
        0,
        "the held commit has not dispatched yet, so this window is before any effect"
    );
    // The same accepted grant, presented again. Its hold is completed and its
    // redemption spent by the call that is still committing, so this can only
    // be answered by the admission entry that call already owns.
    let replayed = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        post(&state, "key-a", accepted.clone()),
    )
    .await
    .expect("Active replay must answer without waiting for the held store publication");
    // Released and joined BEFORE the window assertions are read, so no outcome
    // can leave the producer parked.
    let _ = resume_tx.send(());
    let created = tokio::time::timeout(std::time::Duration::from_secs(5), producer)
        .await
        .expect("the released create must finish before the deadline")
        .expect("the held create must not panic");

    std::assert_eq!(
        replayed.pointer("/error/code"),
        Some(&json!(-32002)),
        "a replay inside the Active window is admission answering 'already being created', \
         not an unusable grant: {replayed}"
    );
    assert!(
        replayed.pointer("/result/taskId").is_none(),
        "the in-flight answer mints no second handle: {replayed}"
    );

    let id = task_id(&created);
    // Published now. The same grant, and the ORIGINAL grant-free call, both
    // name the one durable task.
    std::assert_eq!(
        task_id(&post(&state, "key-a", accepted.clone()).await),
        id,
        "the accepted grant replayed after publication returns the original handle"
    );
    std::assert_eq!(
        task_id(&post(&state, "key-a", original.clone()).await),
        id,
        "the original grant-free call returns the original handle"
    );

    gate.wait_for_dispatch().await;
    std::assert_eq!(status_of(&get_task(&state, "key-a", &id).await), "working");
    gate.release_all();
    assert_carries_the_backend_result(&poll_until_terminal(&state, "key-a", &id).await);

    // After settlement, still the same durable id from both shapes.
    std::assert_eq!(task_id(&post(&state, "key-a", accepted).await), id);
    std::assert_eq!(task_id(&post(&state, "key-a", original).await), id);
    std::assert_eq!(
        mock.calls(),
        1,
        "one confirmed destructive call reaches the backend exactly once"
    );
}

/// B: a grant-free repeat of an admitted destructive call, and the four
/// neighbours that must not be able to borrow its authorization.
#[tokio::test]
async fn b_grant_free_repeat_returns_the_admitted_handle_and_borrows_nothing() {
    let (mock, mut gate) = MockBackend::holding(Answer::ok());
    let (state, _store) = fixture(&mock).await;

    let original = request("fresh-retry");
    let challenge = post(&state, "key-a", original.clone()).await;
    let accepted = retry(&original, &challenge, "accept");
    let created = post(&state, "key-a", accepted).await;
    let id = task_id(&created);
    gate.wait_for_dispatch().await;
    std::assert_eq!(status_of(&get_task(&state, "key-a", &id).await), "working");

    // The defect: a retry that carries no `requestState` and no
    // `inputResponses` — a lost continuation, a job-queue replay, a retry after
    // the grant's five minutes expired — was always challenged, so the caller
    // never got the handle its own key already owns.
    let repeat = post(&state, "key-a", original.clone()).await;
    std::assert_eq!(
        task_id(&repeat),
        id,
        "an identical grant-free repeat is the admitted task, not a new question: {repeat}"
    );

    // Negatives. Each differs from the admitted call in exactly one bound
    // field, and none may be handed the task that call owns.
    let mut other_arguments = original.clone();
    other_arguments["params"]["arguments"]["record"] = json!("another-record");
    let other_key = keyed(original.clone(), "a-second-key");
    for (case, principal, body) in [
        ("arguments", "key-a", other_arguments),
        ("key", "key-a", other_key),
        ("owner", "key-b", original.clone()),
    ] {
        let refused = post(&state, principal, body).await;
        assert!(
            refused.pointer("/result/taskId").is_none(),
            "{case}: a call that was never admitted must be challenged, not handed a handle: \
             {refused}"
        );
        std::assert_eq!(
            refused.pointer("/result/resultType"),
            Some(&json!("input_required")),
            "{case}: and the challenge is the ordinary first-call question: {refused}"
        );
    }
    // A DIFFERENT operation under the admitted owner and key is refused by
    // admission in its own words, and still cannot reach a backend: the
    // destructive authorization is bound to its operation, not to the key.
    let borrowed = post(
        &state,
        "key-a",
        task_invoke(4, "fresh-retry", json!({ "read": true })),
    )
    .await;
    assert!(
        borrowed.pointer("/result/taskId").is_none(),
        "a different operation may not borrow the admitted key: {borrowed}"
    );
    std::assert_eq!(borrowed.pointer("/error/code"), Some(&json!(-32602)));
    std::assert_eq!(
        mock.calls(),
        1,
        "only the confirmed destructive call ever dispatched"
    );

    // The same repeat after settlement still names the one durable task.
    gate.release_all();
    assert_carries_the_backend_result(&poll_until_terminal(&state, "key-a", &id).await);
    std::assert_eq!(task_id(&post(&state, "key-a", original).await), id);
    std::assert_eq!(mock.calls(), 1);
}

/// C: `tasks/cancel` loses the revision race to the settling worker.
///
/// Driven against the real executor and the real service record, with the
/// revision a handler would have captured before the worker settled
/// (`handlers/tasks.rs:179-187` reads, then cancels at what it read). The
/// executor is where this is answered, so the assertion is on
/// `TaskExecutor::cancel` itself rather than on a handler that had swallowed
/// the distinction.
#[tokio::test]
async fn c_cancel_that_loses_to_settlement_is_answered_from_the_committed_view() {
    let (mock, mut gate) = MockBackend::holding(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let owner = alice();

    let created = post(
        &state,
        "key-a",
        task_invoke(2, "cancel-race", json!({ "read": true })),
    )
    .await;
    let id = task_id(&created);
    gate.wait_for_dispatch().await;

    // The revision the client's handle names while the work is still running.
    let captured = state
        .tasks
        .get(&owner, &id)
        .expect("the working record is readable by its own owner")
        .revision;
    std::assert_eq!(status_of(&get_task(&state, "key-a", &id).await), "working");

    // Let the worker win the race, exactly as it would in production.
    gate.release_all();
    assert_carries_the_backend_result(&poll_until_terminal(&state, "key-a", &id).await);
    let settled = state
        .tasks
        .get(&owner, &id)
        .expect("the settled record is readable by its own owner");
    let settled_revision = settled.revision;
    assert!(
        settled_revision > captured,
        "the settlement must have moved the record past the captured revision \
         ({settled_revision} vs {captured}), or this row proves nothing"
    );

    let answer = state
        .task_executor
        .cancel(&owner, &id, captured)
        .await
        .expect(
            "a cancel that lost to settlement is answered from the committed terminal view, \
             not reported as an unavailable store",
        );
    std::assert_eq!(
        answer.task.status(),
        TaskStatus::Completed,
        "the answer is the committed outcome, not a cancellation"
    );
    std::assert_eq!(
        answer.revision,
        settled_revision,
        "answering from the committed view writes nothing"
    );

    // Durable state is untouched: same revision, same status, same result.
    let after = state
        .tasks
        .get(&owner, &id)
        .expect("the record is still readable after the losing cancel");
    std::assert_eq!(after.revision, settled_revision, "no second transition");
    std::assert_eq!(after.task.status(), TaskStatus::Completed);
    assert_carries_the_backend_result(&get_task(&state, "key-a", &id).await);
    std::assert_eq!(
        mock.calls(),
        1,
        "a losing cancel dispatches nothing of its own"
    );

    // The re-read is bounded to the conflict: a task this owner does not have
    // is still `NotFound`, so nothing was broadly swallowed.
    assert!(
        matches!(
            state
                .task_executor
                .cancel(&owner, "no-such-task", captured)
                .await,
            Err(ServiceError::NotFound)
        ),
        "an absent task stays NotFound"
    );
}
