// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! X12 — the idempotency key at the route, and the fields a repeat must not
//! move.
//!
//! Design §3.1: `create` makes exactly one admission call and the facade is the
//! only path that publishes. What a client observes from that is three answers
//! and no fourth: the same key with the same body is the SAME task (`Existing`),
//! the same key with a different body is refused `-32602` (`Mismatch`) with no
//! second record, and a different key is a different task.
//!
//! The counter is what makes each of those mean something. `Existing` that
//! dispatched twice is not deduplication, and `Mismatch` that dispatched at all
//! has already done the thing it refused.
//!
//! Fixture note (design §9): the fixture's `MetaMcp::new` carries `cache: None`
//! and `idempotency_cache: None` (`meta_mcp/mod.rs:488-490`), so nothing below
//! can be answered from a response cache. Every "the counter did not move" is
//! about dispatch.
use super::super::*;
use super::support::*;

/// The two fields §13.3 fixes at creation and no later call may move.
fn ttl_and_poll(body: &Value) -> (Option<&Value>, Option<&Value>) {
    (
        body.pointer("/result/ttlMs"),
        body.pointer("/result/pollIntervalMs"),
    )
}

/// X12 — the same principal, key and body is answered with the same task, and
/// the backend runs once.
#[tokio::test]
async fn x12_a_repeat_of_the_same_key_and_body_is_the_same_task_and_dispatches_once() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let call = |id: i64| task_invoke(id, "x12-same", json!({ "q": "same" }));

    let first = post(&state, "key-a", call(120)).await;
    let id = task_id(&first);
    let settled = poll_until_terminal(&state, "key-a", &id).await;
    assert_carries_the_backend_result(&settled);

    let repeat = post(&state, "key-a", call(121)).await;

    std::assert_eq!(
        task_id(&repeat),
        id,
        "the repeat is answered with the ORIGINAL handle, not a new one: {repeat}"
    );
    std::assert_eq!(
        mock.calls(),
        1,
        "a deduplicated repeat dispatches nothing — that is the whole point of \
         the key. The backend saw {:?}",
        mock.seen()
    );

    let (ttl, poll) = ttl_and_poll(&repeat);
    let (original_ttl, original_poll) = ttl_and_poll(&first);
    std::assert_eq!(
        ttl,
        original_ttl,
        "design §5: the repeat carries the ORIGINAL TTL. TTL is fixed at \
         creation (§13.3), so a repeat that restated it would be extending a \
         deadline the client was already given: {repeat}"
    );
    std::assert_eq!(
        poll,
        original_poll,
        "and the original poll interval, for the same reason: {repeat}"
    );
    assert!(
        ttl.is_some_and(|value| !value.is_null()),
        "design §10: `ttlMs` is a real value now; the arm that emitted \
         `ttlMs: null` unconditionally (`handlers.rs:222`) is replaced: {repeat}"
    );
    assert!(
        poll.is_some(),
        "and `pollIntervalMs` is present — a client told to poll needs to know \
         how often: {repeat}"
    );
}

/// X12 — the same key with a different body is refused, and refuses cleanly.
///
/// "Cleanly" is the load-bearing half: the refusal must not have dispatched, and
/// must not have written a second record that a later poll or a later repeat
/// could find. The original task is re-read afterwards to show it survived
/// untouched.
#[tokio::test]
async fn x12_the_same_key_with_a_different_body_is_refused_and_writes_no_second_record() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;

    let first = post(
        &state,
        "key-a",
        task_invoke(122, "x12-mismatch", json!({ "q": "original" })),
    )
    .await;
    let id = task_id(&first);
    let _ = poll_until_terminal(&state, "key-a", &id).await;

    let mismatched = post(
        &state,
        "key-a",
        task_invoke(123, "x12-mismatch", json!({ "q": "CHANGED" })),
    )
    .await;

    std::assert_eq!(
        mismatched.pointer("/error/code"),
        Some(&json!(-32602)),
        "design §5: a key already used with a different request is `-32602`. \
         Today's tree runs the call instead, which is transfer R4 and owes a \
         release note: {mismatched}"
    );
    assert!(
        mismatched.pointer("/result/taskId").is_none(),
        "a refusal is not a handle: {mismatched}"
    );
    std::assert_eq!(
        mock.calls(),
        1,
        "the refused body must not have been dispatched — a refusal that ran the \
         call first has already done the thing it declined. The backend saw {:?}",
        mock.seen()
    );

    let original = get_task(&state, "key-a", &id).await;
    assert_carries_the_backend_result(&original);
}

/// X12 — different keys are different tasks, and both run.
///
/// The row that stops "deduplication" from being implemented as "one task per
/// principal, forever".
#[tokio::test]
async fn x12_two_keys_are_two_tasks_and_the_backend_runs_for_each() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let body = json!({ "q": "identical" });

    let first = post(&state, "key-a", task_invoke(124, "x12-one", body.clone())).await;
    let first_id = task_id(&first);
    let _ = poll_until_terminal(&state, "key-a", &first_id).await;

    let second = post(&state, "key-a", task_invoke(125, "x12-two", body)).await;
    let second_id = task_id(&second);
    let _ = poll_until_terminal(&state, "key-a", &second_id).await;

    assert_ne!(
        first_id, second_id,
        "two keys are two tasks even when the bodies are identical: {second}"
    );
    std::assert_eq!(
        mock.calls(),
        2,
        "each key's task dispatches on its own; the backend saw {:?}",
        mock.seen()
    );
}

/// X12 — the key is scoped to the caller, and the caller is admission's.
///
/// Two principals presenting the SAME key get two tasks, each private to its
/// owner. Without this, one caller's key choice would deduplicate another
/// caller's work — or hand them a handle to it. The identities here are the
/// fixture's real credentials and its real verified subjects; nothing computes
/// a digest, which is admission's to derive.
#[tokio::test]
async fn x12_the_same_key_from_two_principals_is_two_private_tasks() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let shared_key = "x12-shared-key";

    let mine = post(
        &state,
        "key-a",
        task_invoke(126, shared_key, json!({ "q": "shared" })),
    )
    .await;
    let mine_id = task_id(&mine);
    let _ = poll_until_terminal(&state, "key-a", &mine_id).await;

    let theirs = post(
        &state,
        "key-b",
        task_invoke(127, shared_key, json!({ "q": "shared" })),
    )
    .await;
    let theirs_id = task_id(&theirs);
    let _ = poll_until_terminal(&state, "key-b", &theirs_id).await;

    assert_ne!(
        mine_id, theirs_id,
        "one principal's idempotency key must not reach another's: {theirs}"
    );
    std::assert_eq!(
        mock.calls(),
        2,
        "both callers' work runs; the backend saw {:?}",
        mock.seen()
    );

    let cross = get_task(&state, "key-b", &mine_id).await;
    std::assert_eq!(
        cross.pointer("/error/code"),
        Some(&json!(-32602)),
        "and neither can read the other's task: {cross}"
    );
}
