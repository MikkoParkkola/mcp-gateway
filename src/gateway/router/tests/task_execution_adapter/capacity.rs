// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! X5 and X5b — the worker cap, and the two invariants design §3.1 argues must
//! hold together.
//!
//! # NOT DECLARED IN `task_execution_adapter.rs`, AND WHY
//!
//! This file is complete and its oracles are final. It is **not reachable** from
//! the parent module because it names a declaration that does not exist at
//! `13e97b30`. This is a compile limit, reported as one; it is not an `#[ignore]`,
//! not a weakened assertion and not a row quietly dropped.
//!
//! Required, and the whole of what is required:
//!
//! ```text
//! // src/config/  (design §8, "tasks.{...,max_workers,...}"; lane 3)
//! config.tasks.max_workers: usize          // default 16, per design §3.2
//!
//! // src/gateway/router/tests.rs  (lane 1/3 own that file; design §9 already
//! // rewrites its seven fixtures)
//! fn test_router_app_state_with_auth_and_config(&AuthConfig, Config) -> Arc<AppState>
//! ```
//!
//! Neither is inventable from here: saturation IS the barrier all three rows are
//! built on, and there is no other way to produce it. `max_workers` cannot be
//! reached through `state.live_config` after construction either — design §3.2
//! sizes the executor's semaphore once, at construction, which is the correct
//! design and the reason the knob has to be in the config the fixture builds
//! with.
//!
//! Once both exist, `mod capacity;` in the parent activates the file unchanged.
use super::super::*;
use super::support::*;

/// One worker, authentication on, and the suite's mock backend.
///
/// `max_workers = 1` is the barrier: with a single permit, a held dispatch means
/// the executor is provably saturated for the duration of the hold, and every
/// row below observes a real refusal rather than a contrived one.
async fn saturated_state(mock: &Arc<MockBackend>) -> (Arc<AppState>, tempfile::TempDir) {
    let mut config = crate::config::Config::default();
    config.tasks.max_workers = 1;
    let (state, store) =
        test_router_app_state_with_auth_and_config(&two_principal_auth(), config).await;
    register(&state, BACKEND, mock);
    (state, store)
}

/// X5 — a NEW key refused for capacity writes no record and leaves the key
/// unclaimed.
///
/// Design §3.1 step 4: on `Owned(lease)` with no permit available the lease is
/// **dropped**, and `Drop for TaskLease` (`admission.rs:538-546`) calls `abandon`,
/// which removes the `Active` entry. So the refusal is complete — nothing durable
/// and nothing reserved — and the next attempt with the same key can create.
///
/// Both halves matter. A refusal that wrote a record leaves a `working` task no
/// worker will ever pick up; a refusal that kept the reservation leaves the key
/// permanently unusable, which is worse than the refusal it was answering.
#[tokio::test]
async fn x5_a_new_key_refused_for_capacity_writes_no_record_and_frees_the_key() {
    let (mock, mut gate) = MockBackend::holding(Answer::ok());
    let (state, _store) = saturated_state(&mock).await;

    let held = post(&state, "key-a", task_invoke(50, "x5-held", json!({}))).await;
    let held_id = task_id(&held);
    gate.wait_for_dispatch().await;

    let refused = post(
        &state,
        "key-a",
        task_invoke(51, "x5-new", json!({ "q": 2 })),
    )
    .await;

    std::assert_eq!(
        refused.pointer("/error/code"),
        Some(&json!(-32603)),
        "design §5: worker-cap refusal is `-32603`. It is kept distinct from a \
         broken store INTERNALLY (`CreateOutcome::Capacity`) and identical on the \
         wire: {refused}"
    );
    assert!(
        refused.pointer("/result/taskId").is_none(),
        "a capacity refusal is not a handle: {refused}"
    );
    std::assert_eq!(
        mock.calls(),
        1,
        "only the held task ever reached the backend: {:?}",
        mock.seen()
    );

    // Release, let the held task settle, and try the refused key again. It has
    // to work: the abandoned lease left it unclaimed. `release_all`, because the
    // retry below is a SECOND dispatch at the same mock — one permit would leave
    // it blocked and the row would fail as "never settled".
    gate.release_all();
    let settled = poll_until_terminal(&state, "key-a", &held_id).await;
    assert_carries_the_backend_result(&settled);

    // Terminal visibility precedes worker cleanup; join before testing a new key.
    let joined = state
        .task_executor
        .drain(std::time::Duration::from_secs(5))
        .await;
    assert!(
        joined.is_clean(),
        "the previous worker must finish: {joined:?}"
    );
    std::assert_eq!(joined.acquired, 1, "the single worker must be free");

    let retried = post(
        &state,
        "key-a",
        task_invoke(52, "x5-new", json!({ "q": 2 })),
    )
    .await;
    let retried_id = task_id(&retried);
    assert_ne!(
        retried_id, held_id,
        "the retry is its own task, not the held one: {retried}"
    );
    let retried_settled = poll_until_terminal(&state, "key-a", &retried_id).await;
    assert_carries_the_backend_result(&retried_settled);
    std::assert_eq!(
        mock.calls(),
        2,
        "the retry dispatched — so the capacity refusal wrote no record and \
         claimed no key: {retried_settled}"
    );
}

/// X5b — a repeat of an already-created task is answered under saturation.
///
/// The clause design §3.1 moved the permit for. Taking the worker permit before
/// admission (r2's order) refuses a repeat that needs no worker at all, which
/// breaks `.8a`'s idempotent handle for a call that was already dispatched.
/// Deferring the permit to the `Owned` branch keeps both invariants: a saturated
/// *repeat* still gets its original handle, and a saturated *new* key still
/// writes no record (X5 above).
#[tokio::test]
async fn x5b_a_repeat_of_the_same_key_is_answered_even_when_every_worker_is_busy() {
    let (mock, mut gate) = MockBackend::holding(Answer::ok());
    let (state, _store) = saturated_state(&mock).await;

    let call = |id: i64| task_invoke(id, "x5b-key", json!({ "q": "held" }));
    let held = post(&state, "key-a", call(53)).await;
    let held_id = task_id(&held);
    gate.wait_for_dispatch().await;

    let repeat = post(&state, "key-a", call(54)).await;

    std::assert_eq!(
        task_id(&repeat),
        held_id,
        "under saturation, a repeat is still answered with its ORIGINAL handle — \
         it needs no worker, because its worker is already running: {repeat}"
    );
    std::assert_eq!(
        repeat.pointer("/result/ttlMs"),
        held.pointer("/result/ttlMs"),
        "and with the TTL it was created with: {repeat}"
    );
    std::assert_eq!(
        mock.calls(),
        1,
        "the repeat took no permit and dispatched nothing: {:?}",
        mock.seen()
    );

    gate.release();
    let settled = poll_until_terminal(&state, "key-a", &held_id).await;
    assert_carries_the_backend_result(&settled);
    std::assert_eq!(
        mock.calls(),
        1,
        "and the whole exchange dispatched exactly once: {settled}"
    );
}

/// X5 — the control that makes the refusal a decision rather than the fixture's
/// default.
///
/// With the single worker free, the same second call succeeds. Without this, a
/// route that refused every second create would satisfy X5 completely.
///
/// "Free" is a claim about the PERMIT, and a terminal status does not make it.
/// Design §3.1 holds the permit through settlement, unregister and drop, so the
/// record is terminal — and `poll_until_terminal` returns — while the first
/// worker still owns the only permit there is; a second create landing in that
/// window is refused `-32603` for capacity, which is the row's own subject
/// firing against it. The barrier below is the real one and is the executor's
/// own join: `drain` acquires every worker permit (design §3.2: acquiring all
/// `max_workers` is a complete join over every committed-but-unsettled task),
/// so it returns only once the first worker has actually let go, and it then
/// drops what it acquired — there is no shutdown flag, and the second create
/// finds the same free worker a client would. Same bounded pattern as X16b, no
/// sleep and no clock in the assertions.
#[tokio::test]
async fn fixture_control_a_second_task_succeeds_when_the_worker_is_free() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = saturated_state(&mock).await;

    let first = post(&state, "key-a", task_invoke(55, "x5-free-one", json!({}))).await;
    let first_id = task_id(&first);
    let _ = poll_until_terminal(&state, "key-a", &first_id).await;

    let joined = state
        .task_executor
        .drain(std::time::Duration::from_secs(5))
        .await;
    assert!(
        joined.is_clean(),
        "the first worker must give its permit back; a drain that timed out means \
         it never did, and the second create below would be refused for a reason \
         this row is not about: {joined:?}"
    );
    std::assert_eq!(
        joined.acquired,
        1,
        "and the join covered the single configured worker: {joined:?}"
    );

    let second = post(&state, "key-a", task_invoke(56, "x5-free-two", json!({}))).await;
    let second_id = task_id(&second);
    let settled = poll_until_terminal(&state, "key-a", &second_id).await;

    assert_carries_the_backend_result(&settled);
    std::assert_eq!(
        mock.calls(),
        2,
        "with `max_workers = 1` and the worker FREE, a second task runs — the \
         permit is released at settlement, not held for the process: {settled}"
    );
}
