// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! X4, X9, X16a and X16b — the durable interlock: what the worker is allowed to
//! do between the record becoming readable and the backend being called, and
//! what survives a client that walked away.
//!
//! # NOT DECLARED IN `task_execution_adapter.rs`, AND WHY
//!
//! Complete rows, final oracles, unreachable from the parent module because
//! every barrier here is a **durable-write stage**, and a stage nothing can
//! observe cannot be a barrier. This is a compile limit, reported as one — not
//! an `#[ignore]`, not a weakened assertion, not a dropped row.
//!
//! ## The required test seam, in full
//!
//! Design §6 already puts every durable write through one call site
//! (`TaskExecutor::commit`, with `published` as its single tail call). The seam
//! below is that call site made observable, and nothing more:
//!
//! ```text
//! // src/gateway/task_service/execution.rs   (lane 2)
//! #[derive(Clone, Copy, Debug, PartialEq, Eq)]
//! pub(crate) enum CommitStage {
//!     Published,     // the create facade committed a new record
//!     Dispatched,    // `mark_dispatched` wrote the durable marker (§7)
//!     Transitioned,  // a terminal transition was committed (settle/cancel)
//! }
//!
//! #[async_trait::async_trait]
//! pub(crate) trait CommitObserver: Send + Sync {
//!     /// After a successful durable write at `stage`, before the worker
//!     /// proceeds. Counts successful writes, not attempts or entry — same
//!     /// rule as `published`. A rejected CAS settle must not invoke this.
//!     /// Awaiting here is what lets a test place a request inside the
//!     /// window after that write is already durable.
//!     async fn reached(&self, stage: CommitStage, task_id: &str);
//!     /// Force `mark_dispatched` to answer a store failure (X4).
//!     fn fail_marker(&self, _task_id: &str) -> bool { false }
//!     /// Force the `Weak<AppState>` upgrade to be taken as failed (X4).
//!     fn fail_state_upgrade(&self, _task_id: &str) -> bool { false }
//! }
//!
//! impl TaskExecutor {
//!     #[cfg(test)]
//!     pub(crate) fn observe_commits(&self, observer: Arc<dyn CommitObserver>);
//!     pub(crate) async fn drain(&self, timeout: Duration) -> DrainOutcome;  // §3.2
//! }
//!
//! // src/gateway/router/mod.rs                (lane 3)
//! AppState.task_executor: Arc<TaskExecutor>
//!
//! // src/config/                              (lane 3, design §8)
//! config.tasks.max_workers: usize             // X16b's permit half only
//!
//! // src/gateway/router/tests.rs              (lane 1/3 own that file)
//! fn test_router_app_state_with_auth_and_config(&AuthConfig, Config) -> Arc<AppState>
//! ```
//!
//! Two of the injections deserve their justification stated rather than assumed.
//! `fail_marker` is the only way to reach design §4's "`mark_dispatched` failed
//! on a store error" row: the alternative is corrupting a store directory
//! underneath a running executor, which tests the filesystem rather than the
//! branch. `fail_state_upgrade` replaces the design's "teardown-order fixture"
//! for a reason the design could not have weighed: dropping the last strong
//! `Arc<AppState>` also destroys the route, and a settlement no `tasks/get` can
//! read is a settlement no wire row can assert. The flag keeps the state alive
//! and takes the same branch.
//!
//! Once the seam lands, `mod interlock;` in the parent activates this file
//! unchanged.
use super::super::*;
use super::support::*;

use std::sync::atomic::{AtomicUsize, Ordering};

use crate::gateway::task_service::execution::{CommitObserver, CommitStage};

/// A `CommitObserver` that counts successful durable writes, can hold the
/// worker after one of them, and can force either of the two injected failures.
struct Interlock {
    writes: AtomicUsize,
    hold_at: Option<CommitStage>,
    arrived: tokio::sync::mpsc::UnboundedSender<()>,
    release: Arc<tokio::sync::Semaphore>,
    fail_marker: bool,
    fail_upgrade: bool,
}

/// The test's end of an [`Interlock`].
struct InterlockHandle {
    writes: Arc<Interlock>,
    arrived: tokio::sync::mpsc::UnboundedReceiver<()>,
}

impl InterlockHandle {
    /// Block until the held stage's durable write has succeeded.
    ///
    /// `reached` is invoked only after that write; this is not an entry probe.
    async fn wait(&mut self) {
        for _ in 0..20_000 {
            match self.arrived.try_recv() {
                Ok(()) => return,
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                    tokio::task::yield_now().await;
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                    panic!(
                        "the executor was dropped before it completed the observed durable write"
                    )
                }
            }
        }
        panic!("the worker never completed the observed durable write");
    }

    fn release(&self) {
        self.writes.release.add_permits(1);
    }

    /// Successful durable writes observed via `reached`.
    fn writes(&self) -> usize {
        self.writes.writes.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl CommitObserver for Interlock {
    async fn reached(&self, stage: CommitStage, _task_id: &str) {
        // Invoked after the seam write succeeded. A rejected CAS must never
        // arrive here, or X9's three-write count is lying.
        self.writes.fetch_add(1, Ordering::SeqCst);
        if self.hold_at == Some(stage) {
            let _ = self.arrived.send(());
            self.release
                .acquire()
                .await
                .expect("the interlock semaphore is never closed")
                .forget();
        }
    }

    fn fail_marker(&self, _task_id: &str) -> bool {
        self.fail_marker
    }

    fn fail_state_upgrade(&self, _task_id: &str) -> bool {
        self.fail_upgrade
    }
}

/// Install an interlock on the state's executor.
fn observe(
    state: &Arc<AppState>,
    hold_at: Option<CommitStage>,
    fail_marker: bool,
    fail_upgrade: bool,
) -> InterlockHandle {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let interlock = Arc::new(Interlock {
        writes: AtomicUsize::new(0),
        hold_at,
        arrived: tx,
        release: Arc::new(tokio::sync::Semaphore::new(0)),
        fail_marker,
        fail_upgrade,
    });
    state
        .task_executor
        .observe_commits(Arc::clone(&interlock) as Arc<dyn CommitObserver>);
    InterlockHandle {
        writes: interlock,
        arrived: rx,
    }
}

/// Assert design §4's interrupted-before-dispatch settlement.
fn assert_interrupted_before_dispatch(fetched: &Value) {
    std::assert_eq!(
        status_of(fetched),
        "completed",
        "design §4/§13.5: an interruption before dispatch is an explicit \
         COMPLETED tool-error result, not `failed` and not a stuck `working` \
         handle: {fetched}"
    );
    std::assert_eq!(
        fetched.pointer("/result/result/isError"),
        Some(&json!(true)),
        "the completed result is an error result: {fetched}"
    );
    std::assert_eq!(
        fetched.pointer("/result/result/_meta/io.mcp-gateway~1executionOutcome"),
        Some(&json!("not_executed")),
        "the backend PROVABLY never ran, so the outcome is `not_executed` — the \
         one claim §13.5 lets the gateway make, and only when it is true: {fetched}"
    );
}

// =====================================================================
// adapter design r3 §9 — X4
// =====================================================================

/// X4 — a `mark_dispatched` store failure settles as interrupted, not failed.
#[tokio::test]
async fn x4_a_marker_write_failure_settles_completed_not_executed_and_dispatches_nothing() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let _interlock = observe(&state, None, true, false);

    let created = post(&state, "key-a", task_invoke(40, "x4-marker", json!({}))).await;
    let id = task_id(&created);

    let fetched = poll_until_terminal(&state, "key-a", &id).await;

    assert_interrupted_before_dispatch(&fetched);
    std::assert_eq!(
        mock.calls(),
        0,
        "the marker gates the backend call: a marker that could not be written \
         means the backend must not be called at all, or a restart could never \
         tell whether it had been: {fetched}"
    );
}

/// X4 — a `Weak<AppState>` that no longer upgrades settles the same way.
///
/// The other half of design §4's row: the executor cannot build a dispatch
/// context, so nothing was executed and the record has to say so rather than
/// remain `working` for a process that is going away.
#[tokio::test]
async fn x4_a_state_that_no_longer_upgrades_settles_completed_not_executed() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let _interlock = observe(&state, None, false, true);

    let created = post(&state, "key-a", task_invoke(41, "x4-upgrade", json!({}))).await;
    let id = task_id(&created);

    let fetched = poll_until_terminal(&state, "key-a", &id).await;

    assert_interrupted_before_dispatch(&fetched);
    std::assert_eq!(
        mock.calls(),
        0,
        "no dispatch context, no dispatch: {fetched}"
    );
}

// =====================================================================
// adapter design r3 §9 — X9
// =====================================================================

/// X9 — the after-dispatch cancel race writes exactly three times.
///
/// Create, marker, cancel. The settle that arrives afterwards holds the creation
/// revision, gets `RevisionConflict` from `transition_blocking`
/// (`store.rs:245-263`), re-reads, finds the record terminal and **keeps the
/// committed outcome**. That rejected CAS is not a write and must not increment
/// `reached`. A fourth count is the defect: either the settle overwrote a
/// cancel the client has already been told about, or `reached` fired on entry
/// / on the failed attempt.
#[tokio::test]
async fn x9_a_settle_that_loses_to_a_cancel_writes_exactly_three_times_in_total() {
    let (mock, mut gate) = MockBackend::holding(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let interlock = observe(&state, None, false, false);

    let created = post(&state, "key-a", task_invoke(90, "x9-key", json!({}))).await;
    let id = task_id(&created);
    gate.wait_for_dispatch().await;

    let ack = post(
        &state,
        "key-a",
        task_method(91, "tasks/cancel", json!({ "taskId": id.clone() })),
    )
    .await;
    assert!(ack.get("error").is_none(), "the cancel is accepted: {ack}");

    gate.release();

    // Give the losing settle every chance to write. Turns, not time.
    for _ in 0..500 {
        std::assert_eq!(
            status_of(&get_task(&state, "key-a", &id).await),
            "cancelled",
            "the committed cancel is the only terminal view"
        );
        tokio::task::yield_now().await;
    }

    std::assert_eq!(
        interlock.writes(),
        3,
        "exactly three durable writes: the create, the dispatch marker and the \
         cancel. A fourth is the conflicted settle writing over a terminal \
         record — the failure design §4's bounded compare-and-set exists to stop."
    );
}

// =====================================================================
// adapter design r3 §9 — X16a / X16b
// =====================================================================

/// X16a — a cancel that commits after the dispatch marker and before the
/// backend call leaves the backend counter at 0.
///
/// **The barrier is `Dispatched`, and the `Published` one it replaced was not a
/// weaker choice but an impossible one.** `reached` is awaited *inside*
/// `TaskExecutor::commit` (`execution.rs:300`), which the worker calls before it
/// answers the `oneshot` this row's create POST is waiting on
/// (`worker.rs:28-57`) — so holding at `Published` means the create never
/// returns a handle, and the release below is never reached to let it. The row
/// as written could only deadlock.
///
/// What `Dispatched` observes: `mark_dispatched` awaits the observer AFTER the
/// durable marker write and returns `Marker::Marked` (`worker.rs:178-192`), and
/// the worker then goes back to its pre-dispatch cancel check — the
/// `*cancel_rx.borrow()` interlock of design §3.2 step 4, re-read at
/// `worker.rs:115` after the marker — before it builds a dispatch context or
/// calls the backend. The cancel below therefore commits, durably and
/// durable-first (the record is written, *then* `cancel_signal` fires), inside a
/// window where the backend provably has not run, and that interlock refuses to
/// dispatch it: `mock.calls() == 0` is a backend that was never started, not one
/// started and abandoned, and the committed `cancelled` stays the only terminal
/// view.
///
/// The window is reachable rather than lucky, for two reasons. A `working`
/// record that already carries the dispatch marker is cancellable — X9 above
/// cancels one at exactly that point and asserts the ack — and `hold_at` is
/// `Some(Dispatched)` alone, so the cancel's own `reached(Transitioned)` does
/// not block and the cancel POST cannot deadlock the way the `Published`
/// version's create did.
///
/// **Reported gap, not covered by this row.** The other half of design §3.2
/// step 5 — `mark_dispatched` answering `Marker::Refused` on an
/// already-terminal record, the durable check that holds the line when the
/// in-memory `watch` signal is lost — has no row: this window opens *after* the
/// marker write, X4's `fail_marker` injects a store failure rather than a
/// terminal record, and X9 is the post-dispatch settle race. Recorded here
/// rather than implied to be tested; covering it needs a barrier before the
/// marker CAS, which the create's own publication cannot be.
#[tokio::test]
async fn x16a_a_cancel_before_dispatch_stops_the_backend_call_durably() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let mut interlock = observe(&state, Some(CommitStage::Dispatched), false, false);

    let created = post(&state, "key-a", task_invoke(160, "x16a-key", json!({}))).await;
    let id = task_id(&created);

    // `reached(Dispatched)` fires after the marker write succeeded and before
    // the worker's return to its cancel check, so the record is readable and
    // the backend has not been called — the exact window.
    interlock.wait().await;

    let ack = post(
        &state,
        "key-a",
        task_method(161, "tasks/cancel", json!({ "taskId": id.clone() })),
    )
    .await;
    assert!(
        ack.get("error").is_none(),
        "a task that has been published is cancellable: {ack}"
    );

    interlock.release();

    for _ in 0..500 {
        std::assert_eq!(
            status_of(&get_task(&state, "key-a", &id).await),
            "cancelled",
            "the cancel committed first and stays committed"
        );
        tokio::task::yield_now().await;
    }
    std::assert_eq!(
        mock.calls(),
        0,
        "no backend dispatch on a pre-dispatch cancel — not one that was started \
         and abandoned, but none at all: {:?}",
        mock.seen()
    );
}

/// X16b — a create whose HTTP request future is dropped still runs to a terminal
/// status, and gives its worker permit back.
///
/// Design §3.2: the send on the `oneshot` is deliberately ignorable, because a
/// dropped HTTP request future must never abort the follow-through of a record
/// that is already durable. The client is dropped inside the publication window,
/// so the record exists and nobody is waiting for it.
///
/// The task is recovered by its own idempotency key rather than by an id the
/// client never received — which is also the only way a real client could
/// recover it, and is why `Existing` has to answer here.
#[tokio::test]
async fn x16b_a_dropped_request_future_still_settles_and_releases_its_permit() {
    let (mock, mut gate) = MockBackend::holding(Answer::ok());
    let mut config = crate::config::Config::default();
    config.tasks.max_workers = 1;
    let (state, _store) =
        test_router_app_state_with_auth_and_config(&two_principal_auth(), config).await;
    register(&state, BACKEND, &mock);
    let mut interlock = observe(&state, Some(CommitStage::Published), false, false);

    let call = |id: i64| task_invoke(id, "x16b-key", json!({ "q": "orphan" }));

    {
        // The handler runs INSIDE this future — `oneshot` does not spawn — so
        // dropping it is exactly the "client went away" cancellation the adapter
        // has to survive. `wait()` returns after the Published write succeeded
        // and before the handler proceeds, which pins the drop to that window
        // rather than to a moment that happens to work.
        let mut client = Box::pin(post(&state, "key-a", call(162)));
        tokio::select! {
            answered = &mut client => panic!(
                "the create answered before the publication window closed; this row \
                 needs the client still in flight when the record becomes durable, \
                 and it got {answered}"
            ),
            () = interlock.wait() => {}
        }
        drop(client);
    }

    interlock.release();
    gate.wait_for_dispatch().await;
    // `release_all`: the permit half below drives a SECOND dispatch at the same
    // mock, and one permit would leave it blocked forever — which would fail as
    // "the task never settled" and read as an adapter defect rather than as a
    // fixture out of permits.
    gate.release_all();

    // The same key recovers the handle the dropped client never read.
    let recovered = post(&state, "key-a", call(163)).await;
    let id = task_id(&recovered);
    let settled = poll_until_terminal(&state, "key-a", &id).await;
    assert_carries_the_backend_result(&settled);
    std::assert_eq!(
        mock.calls(),
        1,
        "the abandoned task ran exactly once — the dropped client neither \
         cancelled it nor caused it to run twice: {settled}"
    );

    // The permit half. With `max_workers = 1`, a task that settled without
    // returning its permit makes every later create fail; this one must not.
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

    // The same observer also sees the second publication; its first permit was consumed.
    interlock.release();
    let after = post(&state, "key-a", task_invoke(164, "x16b-after", json!({}))).await;
    let after_id = task_id(&after);
    let after_settled = poll_until_terminal(&state, "key-a", &after_id).await;
    assert_carries_the_backend_result(&after_settled);
    std::assert_eq!(
        mock.calls(),
        2,
        "the orphaned worker released its permit at settlement, so the single \
         worker is available again: {after_settled}"
    );

    // And drain joins cleanly: design §3.2's invariant is that acquiring every
    // permit is a complete join over every committed-but-unsettled task, so a
    // permit stranded by a dropped request future would show up here.
    let outcome = state
        .task_executor
        .drain(std::time::Duration::from_secs(5))
        .await;
    assert!(
        outcome.is_clean(),
        "drain must join every worker; a dropped request future must not leave \
         one behind: {outcome:?}"
    );
}
