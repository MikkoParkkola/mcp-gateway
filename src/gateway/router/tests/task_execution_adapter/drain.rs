// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The queued-handoff drain race: what `TaskExecutor::drain` is allowed to call
//! "clean" while a handoff it already accepted has never been polled.
//!
//! # This is an executor boundary test, not an HTTP admission test
//!
//! Every other row in this suite drives `/mcp`. These two do not, and the reason
//! is the boundary they observe. `TaskExecutor::begin`
//! (`task_service/execution.rs:152`) registers the task and `tokio::spawn`s
//! `commit_and_run` BEFORE the spawned worker has run at all — the worker
//! reserves its capacity inside `commit`, which is on the child task. `drain`
//! (`:275`) only acquires the worker permits. So between the spawn and the
//! child's first poll there is an owned handoff that holds no permit, and a
//! drain in that window has nothing to see.
//!
//! Reaching that window through an HTTP request would mean betting on the
//! scheduler. Here it is not a bet: a `current_thread` runtime with the
//! initiating future polled exactly once by hand cannot have run the child, so
//! "the child has never been polled" is a fact of the test rather than a timing
//! guess. Everything downstream of the probe — the store, the executor, the
//! backend transport — is production: real `AppState` from
//! [`fixture_state`], the real registered mock backend, the real durable record.
//!
//! Authentication is off here, and the caller is therefore honestly
//! identity-less: no `VerifiedIdentity` is fabricated, and the owner is the
//! trusted local constant [`OWNER`] which is the same string the admission
//! request and the durable record are keyed on.
//!
//! Nothing here changes admission capacity or replay policy, and nothing closes
//! the executor: `drain` must remain a join, so a drained-then-reused executor
//! is one of the controls below.
use super::super::*;
use super::support::*;

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use crate::gateway::meta_mcp::task_admission_request;
use crate::gateway::router::OwnedRouterAuthorizer;
use crate::gateway::task_service::execution::{
    BeginOutcome, OwnedCallerContext, TaskCall, TaskIntent,
};
use crate::protocol::meta::Declared;
use crate::protocol::tasks::{Task, TaskOptions, TaskStatus};

/// The owner an auth-disabled gateway admits under.
///
/// A constant rather than a rendered identity: with authentication off there is
/// no verified subject to derive one from, and inventing a `VerifiedIdentity`
/// would give these rows an authority the production path does not have.
const OWNER: &str = "local:auth-disabled:tasks:v1";

/// The bound on every await below. Whole futures are wrapped in it; no row
/// sleeps and no row counts scheduler turns to decide an outcome.
const BOUND: Duration = Duration::from_secs(5);

/// The record options, spelled out. Immutable per record and irrelevant to the
/// boundary — named only so nothing here depends on a default that could move.
fn options() -> TaskOptions {
    TaskOptions {
        ttl_ms: Some(86_400_000),
        poll_interval_ms: Some(1_000),
    }
}

/// Authentication off, and nothing else changed.
fn auth_disabled() -> AuthConfig {
    AuthConfig {
        enabled: false,
        ..Default::default()
    }
}

/// The arguments a `gateway_invoke` task carries, at the counted mock.
fn arguments() -> Value {
    json!({
        "server": BACKEND,
        "tool": TOOL,
        "arguments": { "marker": "drain-owned-handoff" }
    })
}

/// One task-augmented `gateway_invoke`, built the way the production admission
/// site builds it: the same `task_admission_request` renderer, the same owner
/// string on the admission request and on the caller context.
fn intent(state: &Arc<AppState>, key: &str, arguments: &Value) -> TaskIntent {
    TaskIntent {
        executor: Arc::clone(&state.task_executor),
        owned: OwnedCallerContext::new(
            Arc::downgrade(state),
            OwnedRouterAuthorizer::capture(None, None, None),
            None,
            None,
            None,
            None,
            OWNER.to_owned(),
            false,
            Declared::NONE,
            None,
            None,
        ),
        request: task_admission_request(
            OWNER.to_owned(),
            key.to_owned(),
            "gateway_invoke",
            arguments,
        ),
        options: options(),
    }
}

fn call(arguments: &Value) -> TaskCall {
    TaskCall {
        tool: "gateway_invoke".to_owned(),
        arguments: arguments.clone(),
    }
}

/// Poll a pinned future exactly once, on a waker that wakes nothing.
///
/// `begin` can schedule its child during this poll. The current-thread runtime
/// and absence of an await between probe polls prevent that child from running
/// before the drain observation; the noop waker does not prevent scheduling.
fn poll_once<F: Future>(future: &mut Pin<Box<F>>) -> Poll<F::Output> {
    let mut cx = Context::from_waker(Waker::noop());
    future.as_mut().poll(&mut cx)
}

/// A [`GateHandle`] that releases every held dispatch when it is dropped.
///
/// Installed before the first await. A panic between the barrier and the
/// release would otherwise leave the worker parked inside the backend forever,
/// and the row would report a hang instead of the assertion that failed.
struct GateGuard {
    gate: GateHandle,
}

impl Drop for GateGuard {
    fn drop(&mut self) {
        self.gate.release_all();
    }
}

/// Await the durable record reaching a terminal status, reading the real store
/// through the real service. Bounded by the [`BOUND`] its caller wraps it in.
async fn await_terminal(state: &Arc<AppState>, id: &str) -> (TaskStatus, Value) {
    loop {
        if let Ok(committed) = state.tasks.get(OWNER, id) {
            let status = committed.task.status();
            if matches!(
                status,
                TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
            ) {
                return (
                    status,
                    committed.task.result().cloned().unwrap_or(Value::Null),
                );
            }
        }
        tokio::task::yield_now().await;
    }
}

/// Assert a terminal record is the completed one the mock answered.
fn assert_completed_with_marker(status: TaskStatus, result: &Value) {
    std::assert_eq!(
        status,
        TaskStatus::Completed,
        "the handed-off task must run to completion; it settled {status:?} with {result}"
    );
    assert!(
        result.to_string().contains("mock-backend-answered"),
        "the settled record carries the fixture backend's own result: {result}"
    );
}

// =====================================================================
// The race
// =====================================================================

/// A handoff that has been enqueued and never polled must stop `drain` from
/// reporting clean, and must still run once the drain is over.
///
/// The sequence is the claim:
///
/// 1. `begin` is polled ONCE by hand. It registers the task, spawns
///    `commit_and_run`, and parks on the `oneshot` — `Pending`, with the child
///    enqueued and never polled, because a `current_thread` runtime runs
///    nothing between two synchronous statements.
/// 2. `drain` is polled ONCE, with no await in between. A `Ready` here is the
///    defect: the executor has an owned handoff it has already accepted, and
///    reports every worker free because the permit for it is taken on the child.
/// 3. The backend counter is still 0, which is what makes step 2 a claim about
///    queued work rather than about work that has already finished.
///
/// Then the cleanup, which is also three of the oracles: the initiating future
/// is dropped deliberately (a client that walked away must not lose owned
/// work), the dispatch really arrives at the real backend exactly once, and the
/// drain that was `Pending` completes clean once the worker settles. The
/// scheduler observation is asserted only after all of that, so a failing row
/// never strands a worker.
#[tokio::test(flavor = "current_thread")]
async fn a_queued_owned_handoff_that_has_never_been_polled_is_not_a_clean_drain() {
    let (mock, gate) = MockBackend::holding(Answer::ok());
    let (state, _store) = fixture_state(&auth_disabled()).await;
    register(&state, BACKEND, &mock);
    // Installed before the first await: a panic below must not park the worker
    // inside the backend forever.
    let mut guard = GateGuard { gate };

    let arguments = arguments();
    let task = Task::create_at("gateway_invoke", chrono::Utc::now(), options());
    // The REAL generated handle, recorded before the task moves into `begin`.
    let id = task.id().to_owned();

    let mut begin = Box::pin(state.task_executor.begin(
        intent(&state, "drain-queued-handoff", &arguments),
        task,
        BACKEND.to_owned(),
        call(&arguments),
    ));

    // Step 1. No await, no yield, from here to the drain poll below.
    let begin_poll = poll_once(&mut begin);
    assert!(
        begin_poll.is_pending(),
        "begin parks on its oneshot after enqueuing the handoff; a ready answer \
         means the child already ran and this row observes nothing"
    );

    // Step 2 and 3. Observations, not assertions: the cleanup runs first.
    let mut drain = Box::pin(state.task_executor.drain(BOUND));
    let drained_early = poll_once(&mut drain);
    let clean_before_the_worker_ran =
        matches!(&drained_early, Poll::Ready(outcome) if outcome.is_clean());
    let early_outcome = match drained_early {
        Poll::Ready(outcome) => Some(outcome),
        Poll::Pending => None,
    };
    let calls_at_the_probe = mock.calls();

    // The client goes away. The record is the executor's now.
    drop(begin);

    tokio::time::timeout(BOUND, guard.gate.wait_for_dispatch())
        .await
        .expect("the dropped request future must not lose the owned handoff: no dispatch arrived");
    std::assert_eq!(
        mock.calls(),
        1,
        "the abandoned handoff reached the real backend exactly once: {:?}",
        mock.seen()
    );
    guard.gate.release_all();

    // Only a drain that was still Pending can be awaited; a completed one is
    // the defect itself and is asserted on below.
    if early_outcome.is_none() {
        let joined = tokio::time::timeout(BOUND, drain)
            .await
            .expect("drain must join the handoff it was waiting for, within its own bound");
        assert!(
            joined.is_clean(),
            "the drain that waited for the queued handoff joins it cleanly: {joined:?}"
        );
    }

    let (status, result) = tokio::time::timeout(BOUND, await_terminal(&state, &id))
        .await
        .expect("the durable record must reach a terminal status");
    assert_completed_with_marker(status, &result);

    let after = tokio::time::timeout(BOUND, state.task_executor.drain(BOUND))
        .await
        .expect("a settled executor drains without waiting out its timeout");
    assert!(
        after.is_clean(),
        "no worker and no permit is retained after settlement: {after:?}"
    );

    // The scheduler result, last.
    assert!(
        !clean_before_the_worker_ran,
        "drain reported clean while an owned handoff it had already accepted had \
         never been polled (early outcome {early_outcome:?}, backend calls at the \
         probe {calls_at_the_probe}); the work then committed and dispatched \
         AFTER that clean drain — drain must wait for every handoff already \
         enqueued when it was called"
    );
    std::assert_eq!(
        calls_at_the_probe,
        0,
        "the probe observed queued work, not finished work"
    );
}

/// The controls the row above is only meaningful against: an executor with
/// nothing enqueued drains clean, and a drained executor still accepts and runs
/// new work.
///
/// Both halves matter. Without the first, "not clean" above could be a drain
/// that is never clean. Without the second, the fix for the race could be an
/// executor that stops accepting work once drained — which would pass the row
/// above and break the gateway.
#[tokio::test(flavor = "current_thread")]
async fn an_idle_executor_drains_clean_and_still_runs_the_next_task() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = fixture_state(&auth_disabled()).await;
    register(&state, BACKEND, &mock);

    let idle = tokio::time::timeout(BOUND, state.task_executor.drain(BOUND))
        .await
        .expect("an idle drain answers immediately");
    assert!(
        idle.is_clean(),
        "nothing has been enqueued, so the drain is clean: {idle:?}"
    );
    assert!(
        idle.acquired > 0,
        "a clean drain holds the worker permits it acquired: {idle:?}"
    );

    let arguments = arguments();
    let task = Task::create_at("gateway_invoke", chrono::Utc::now(), options());
    let id = task.id().to_owned();

    let outcome = tokio::time::timeout(
        BOUND,
        state.task_executor.begin(
            intent(&state, "drain-idle-control", &arguments),
            task,
            BACKEND.to_owned(),
            call(&arguments),
        ),
    )
    .await
    .expect("the create answers within the bound")
    .expect("a drained executor still admits a new task");
    assert!(
        matches!(outcome, BeginOutcome::Created(_)),
        "the drain joined workers; it did not close the executor"
    );

    let (status, result) = tokio::time::timeout(BOUND, await_terminal(&state, &id))
        .await
        .expect("the new task must reach a terminal status");
    assert_completed_with_marker(status, &result);
    std::assert_eq!(
        mock.calls(),
        1,
        "exactly one dispatch reached the backend: {:?}",
        mock.seen()
    );

    let quiescent = tokio::time::timeout(BOUND, state.task_executor.drain(BOUND))
        .await
        .expect("a quiescent drain answers immediately");
    assert!(
        quiescent.is_clean(),
        "every permit is back after settlement: {quiescent:?}"
    );
    std::assert_eq!(
        quiescent.acquired,
        idle.acquired,
        "the same worker pool is free again; none was retained"
    );
}
