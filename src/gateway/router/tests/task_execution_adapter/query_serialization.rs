// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! I5 addendum — concurrent queries of one record serialize, INCLUDING the
//! live worker's own follow of its handle.
//!
//! The reader half already takes the record's query slot. The worker half did
//! not, so a `tasks/get` arriving while its worker was mid-query reached the
//! peer at the same time, on the same handle, and then raced it to the
//! settlement. Both halves are real here: a genuine dispatch through `/mcp`
//! leaves a live worker holding a captured handle, and a genuine authenticated
//! `tasks/get` by the owner drives the production recovery read.
//!
//! # The oracle
//!
//! [`BarrierRecovery`] counts queries and, from a drop guard, the number in
//! flight at once. `max_in_flight()` is the property the addendum names: one.
//! A row that only counted total queries could not tell serialization from two
//! simultaneous queries of which one lost the CAS.
//!
//! # Why it cannot pass by accident
//!
//! * The reader might never reach the query at all — a policy refusal issues
//!   zero queries and would leave `max_in_flight` at one. The retained-row
//!   control asserts that the SAME route read, on the same fixture, does reach
//!   exactly one query, so a denied read fails there rather than passing here.
//! * The contention window is anchored on the reader's own `claims` call, which
//!   `recover_upstream_read` makes BEFORE it contends for the slot, and the
//!   yield loop that follows stops early the moment a second query is in
//!   flight. An unserialized runtime therefore fails on evidence rather than on
//!   the budget running out.
//! * No row sleeps. Every wait is bounded by scheduler turns or by an explicit
//!   timeout, exactly as the rest of this suite waits.
use super::super::*;
use super::support::*;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::gateway::task_service::{UpstreamAnswer, UpstreamHandle, UpstreamRecovery};

/// The opaque handle the peer answers the task-augmented call with.
const UPSTREAM_HANDLE: &str = "upstream-job-serialization";

/// Scheduler turns a row spends looking for contention that must not appear.
/// Bounded, and cheap when nothing arrives: the queued half is parked on the
/// record's slot, so these turns do no work.
const CONTENTION_TURNS: usize = 2_000;

/// Scheduler turns a row waits for an event it expects to arrive.
const ARRIVAL_TURNS: usize = 20_000;

/// The bound on a read that must not be stranded by a cancelled predecessor.
/// A stranded slot has to fail this row, not hang the test binary.
const READ_BOUND: Duration = Duration::from_secs(10);

// =====================================================================
// The peer
// =====================================================================

/// A `Transport` that counts every dispatch and answers the task-augmented leg
/// with a genuine peer `CreateTask` envelope.
///
/// Local to this file for the reason the descriptor suite's copy is: the
/// upstream leg is `request_with_task_capability`, which the shared
/// `MockBackend` does not implement, and teaching it that method would change a
/// fixture every other row in this suite depends on.
struct CountedUpstream {
    calls: AtomicUsize,
}

impl CountedUpstream {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl Transport for CountedUpstream {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        match method {
            "initialize" => Ok(JsonRpcResponse::success(
                RequestId::Number(1),
                json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "mock", "version": "0" }
                }),
            )),
            "tools/list" => Ok(JsonRpcResponse::success(
                RequestId::Number(1),
                json!({
                    "tools": [
                        { "name": TOOL, "description": "d", "inputSchema": { "type": "object" } }
                    ]
                }),
            )),
            // Counted too: a job that took the ordinary leg was never submitted
            // as an upstream task, and no row below would have a handle to
            // serialize queries of.
            "tools/call" => {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(JsonRpcResponse::success(
                    RequestId::Number(1),
                    json!({ "content": [{ "type": "text", "text": "ordinary-leg" }] }),
                ))
            }
            _ => Ok(JsonRpcResponse::success(RequestId::Number(1), json!({}))),
        }
    }

    async fn request_with_task_capability(
        &self,
        method: &str,
        params: Option<Value>,
        _extra_headers: &[(String, String)],
        _identity_key: Option<&str>,
    ) -> crate::Result<JsonRpcResponse> {
        if method == "tools/call" {
            self.calls.fetch_add(1, Ordering::SeqCst);
            return Ok(JsonRpcResponse::success(
                RequestId::Number(1),
                json!({
                    "resultType": "task",
                    "taskId": UPSTREAM_HANDLE,
                    "status": "working"
                }),
            ));
        }
        self.request(method, params).await
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

// =====================================================================
// The recovery adapter
// =====================================================================

/// What the adapter does with the queries it receives.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Script {
    /// Hold every query at the barrier until the row releases it, then answer
    /// `Completed`. The shape the live-worker row needs.
    Hold,
    /// Answer the FIRST query `Unavailable` — which retains the handle and the
    /// `working` record and ends the worker's follow at once — then hold and
    /// answer `Completed`. The shape a row needs when it wants a recoverable
    /// row with no worker left in it.
    RetainThenHold,
}

/// Counts queries, holds them, and reports the most that were ever in flight
/// together.
///
/// The in-flight count is decremented from a drop guard, so a query whose
/// caller was cancelled mid-await does not poison the count for the row's later
/// assertions.
struct BarrierRecovery {
    script: Script,
    claims: AtomicUsize,
    queries: AtomicUsize,
    handles: parking_lot::Mutex<Vec<String>>,
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
    release: Arc<tokio::sync::Semaphore>,
}

/// Decrements the in-flight count on every exit from a query, cancelled or not.
/// A `Drop` impl rather than a line at the end of `query`, because a cancelled
/// query has no end: only this runs, and a count left standing would make every
/// later assertion in the row read as contention that never happened.
struct InFlight<'a>(&'a BarrierRecovery);

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

impl BarrierRecovery {
    fn new(script: Script) -> Arc<Self> {
        Arc::new(Self {
            script,
            claims: AtomicUsize::new(0),
            queries: AtomicUsize::new(0),
            handles: parking_lot::Mutex::new(Vec::new()),
            in_flight: AtomicUsize::new(0),
            max_in_flight: AtomicUsize::new(0),
            release: Arc::new(tokio::sync::Semaphore::new(0)),
        })
    }

    fn claims_seen(&self) -> usize {
        self.claims.load(Ordering::SeqCst)
    }

    fn queries(&self) -> usize {
        self.queries.load(Ordering::SeqCst)
    }

    fn handles(&self) -> Vec<String> {
        self.handles.lock().clone()
    }

    fn max_in_flight(&self) -> usize {
        self.max_in_flight.load(Ordering::SeqCst)
    }

    /// Let every held query answer, this one and any that follow.
    fn release_all(&self) {
        self.release.add_permits(1_000);
    }

    /// Wait until at least `count` queries have entered the adapter.
    async fn wait_for_queries(&self, count: usize) {
        for _ in 0..ARRIVAL_TURNS {
            if self.queries() >= count {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!(
            "only {} upstream queries entered the adapter in {ARRIVAL_TURNS} scheduler turns; \
             {count} were expected",
            self.queries()
        );
    }

    /// Wait until a caller has passed the trust check that `recover_upstream_read`
    /// makes before it contends for the record's query slot.
    ///
    /// This is what makes the contention window an observation rather than a
    /// guess: past this point the reader is either querying or queued, and the
    /// row can tell those two apart.
    async fn wait_for_claims_after(&self, seen: usize) {
        for _ in 0..ARRIVAL_TURNS {
            if self.claims_seen() > seen {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!(
            "no recovery read reached the adapter's trust check in {ARRIVAL_TURNS} scheduler \
             turns; the read never entered the recovery path and this row would observe nothing"
        );
    }

    /// Spend a bounded number of scheduler turns looking for a second query in
    /// flight, stopping the moment one appears.
    async fn look_for_contention(&self) {
        for _ in 0..CONTENTION_TURNS {
            if self.max_in_flight() >= 2 {
                return;
            }
            tokio::task::yield_now().await;
        }
    }
}

#[async_trait::async_trait]
impl UpstreamRecovery for BarrierRecovery {
    async fn claims(&self, backend: &str) -> bool {
        self.claims.fetch_add(1, Ordering::SeqCst);
        backend == BACKEND
    }

    async fn query(&self, handle: &UpstreamHandle, _deadline: Duration) -> UpstreamAnswer {
        let seen = self.queries.fetch_add(1, Ordering::SeqCst);
        self.handles.lock().push(handle.handle.clone());
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_in_flight.fetch_max(now, Ordering::SeqCst);
        let _in_flight = InFlight(self);
        if self.script == Script::RetainThenHold && seen == 0 {
            return UpstreamAnswer::Unavailable;
        }
        // Held until the row says so: the answer arrives when the test decides,
        // not when a timer does.
        let permit = self
            .release
            .clone()
            .acquire_owned()
            .await
            .expect("the barrier semaphore outlives every held query");
        permit.forget();
        UpstreamAnswer::Completed(json!({
            "content": [{ "type": "text", "text": "upstream-answered" }],
            "structuredContent": { "marker": "upstream-answered" }
        }))
    }
}

// =====================================================================
// The fixture
// =====================================================================

/// The suite's real state, with the counted upstream transport registered under
/// [`BACKEND`] and the barrier adapter installed as the recovery seam.
async fn armed_fixture(
    script: Script,
) -> (
    Arc<AppState>,
    Arc<CountedUpstream>,
    Arc<BarrierRecovery>,
    tempfile::TempDir,
) {
    let (state, store) = fixture_state(&two_principal_auth()).await;
    let transport = CountedUpstream::new();
    let backend = Arc::new(Backend::new(
        BACKEND,
        BackendConfig {
            enabled: true,
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::clone(&transport) as Arc<dyn Transport>);
    assert!(
        state.backends.register(backend),
        "the counted upstream backend must register under a name nothing else holds"
    );
    let adapter = BarrierRecovery::new(script);
    assert!(
        state
            .task_executor
            .install_recovery(Arc::clone(&adapter) as Arc<dyn UpstreamRecovery>),
        "the recovery adapter must be the one this executor was given; without it no \
         candidate is ever armed and no row below observes anything"
    );
    (state, transport, adapter, store)
}

/// Submit one task-augmented call and return its task id.
async fn submit(state: &Arc<AppState>, key: &str) -> String {
    let created = post(state, "key-a", task_invoke(1, key, json!({ "n": 1 }))).await;
    task_id(&created)
}

/// Join the executor's workers within the row's bound.
async fn join_workers(state: &Arc<AppState>) {
    let bound = Duration::from_secs(5);
    let joined = tokio::time::timeout(bound, state.task_executor.drain(bound))
        .await
        .expect("the worker settles within the fixture bound");
    std::assert!(joined.is_clean(), "the worker must finish: {joined:?}");
}

// =====================================================================
// Rows
// =====================================================================

/// GIVEN a live worker holding its own upstream query open, WHEN the owner's
/// authenticated `tasks/get` reaches the same record, THEN the two queries
/// never overlap, and once the worker's terminal answer is committed the queued
/// read serves it without asking the peer again.
#[tokio::test]
async fn a_reader_never_queries_a_record_its_worker_is_already_querying() {
    let (state, transport, adapter, _store) = armed_fixture(Script::Hold).await;
    let id = submit(&state, "i5-query-serialization").await;

    // The worker's own query, held at the barrier. Until this returns there is
    // a genuine live query on this record, which is the condition the row is
    // about — not a status a poll happened to catch.
    adapter.wait_for_queries(1).await;
    let claims_before = adapter.claims_seen();

    let reader = tokio::spawn({
        let (state, id) = (Arc::clone(&state), id.clone());
        async move { get_task(&state, "key-a", &id).await }
    });
    // Past its trust check the read is either querying or queued behind the
    // record's slot, and the loop below tells those apart.
    adapter.wait_for_claims_after(claims_before).await;
    adapter.look_for_contention().await;
    std::assert_eq!(
        adapter.max_in_flight(),
        1,
        "a worker's query and an owner read's query of the SAME record must never be in \
         flight together: the reader took the record's query slot, the worker did not, \
         and both reached the peer on one handle"
    );

    // The worker's answer, first. The queued read may only proceed after it.
    adapter.release_all();
    let fetched = reader.await.expect("the owner's read must answer");
    join_workers(&state).await;

    std::assert_eq!(
        status_of(&fetched),
        "completed",
        "the queued read serves the terminal outcome its predecessor committed: {fetched}"
    );
    std::assert_eq!(
        fetched.pointer("/result/result/structuredContent/marker"),
        Some(&json!("upstream-answered")),
        "the committed outcome is the UPSTREAM job's result, not the `working` stub the \
         submission answered with: {fetched}"
    );
    std::assert_eq!(
        adapter.queries(),
        1,
        "the queued read must find the record already settled and issue NO further \
         terminal query; it asked the peer {} times",
        adapter.queries()
    );
    std::assert_eq!(
        transport.calls(),
        1,
        "one dispatch, and nothing resubmitted: the recovery path never calls the tool"
    );
    let durable = state
        .task_executor
        .durable_upstream_for_test(&id)
        .expect("a dispatched upstream job's descriptor is on disk");
    std::assert_eq!(
        durable.handle,
        UPSTREAM_HANDLE,
        "the durable handle is the opaque one the peer chose"
    );
    std::assert_eq!(
        adapter.handles(),
        vec![UPSTREAM_HANDLE.to_string()],
        "the one query that ran used exactly the durable handle of this record"
    );
}

/// The control that keeps the row above honest: on the same fixture, with no
/// worker left in the record, ONE authenticated `tasks/get` by the owner
/// reaches exactly one upstream query and settles on its answer.
///
/// Without this, a `tasks/get` refused by current policy — zero queries — would
/// satisfy every assertion above.
#[tokio::test]
async fn an_authorized_read_of_a_retained_row_makes_exactly_one_query() {
    let (state, transport, adapter, _store) = armed_fixture(Script::RetainThenHold).await;
    let id = submit(&state, "i5-query-serialization-control").await;

    // The worker's single query is answered `Unavailable`, which retains the
    // handle and the `working` record and ends the follow at once.
    adapter.wait_for_queries(1).await;
    join_workers(&state).await;
    std::assert_eq!(
        status_of(&get_task(&state, "key-b", &id).await),
        "",
        "a foreign reader learns nothing and causes no query"
    );
    std::assert_eq!(
        adapter.queries(),
        1,
        "the foreign read must reach no upstream query at all"
    );

    adapter.release_all();
    let fetched = get_task(&state, "key-a", &id).await;
    std::assert_eq!(
        status_of(&fetched),
        "completed",
        "the owner's read recovers the retained row through the production recovery \
         path: {fetched}"
    );
    std::assert_eq!(
        adapter.queries(),
        2,
        "exactly one query belongs to the owner's read: the worker's retained attempt \
         and this one, and nothing else"
    );
    std::assert_eq!(
        transport.calls(),
        1,
        "recovery reads never resubmit the original call"
    );
}

/// GIVEN an owner read cancelled while it holds the record's query slot, WHEN
/// the owner reads again, THEN the second read acquires the slot and settles.
///
/// The release is the property: a slot held by a guard that is never dropped
/// would strand every later read of that record behind a request nobody is
/// waiting for any more.
#[tokio::test]
async fn a_cancelled_read_does_not_strand_the_next_read_of_the_record() {
    let (state, _transport, adapter, _store) = armed_fixture(Script::RetainThenHold).await;
    let id = submit(&state, "i5-query-serialization-cancel").await;

    // Retain the row and get the worker out of it, so the only contenders for
    // the slot below are the two reads.
    adapter.wait_for_queries(1).await;
    join_workers(&state).await;

    let abandoned = tokio::spawn({
        let (state, id) = (Arc::clone(&state), id.clone());
        async move { get_task(&state, "key-a", &id).await }
    });
    adapter.wait_for_queries(2).await;
    abandoned.abort();
    let cancelled = abandoned.await;
    std::assert!(
        cancelled.is_err_and(|error| error.is_cancelled()),
        "the abandoned read must really be cancelled while its query is held"
    );

    adapter.release_all();
    let fetched = tokio::time::timeout(READ_BOUND, get_task(&state, "key-a", &id))
        .await
        .expect(
            "the next read must acquire the record's query slot: a cancelled holder that \
             never released it strands every later read of this record",
        );
    std::assert_eq!(
        status_of(&fetched),
        "completed",
        "the read that followed a cancelled one still recovers the row: {fetched}"
    );
}
