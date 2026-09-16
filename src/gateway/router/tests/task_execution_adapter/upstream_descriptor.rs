// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! I5 — the recovery descriptor's capacity, decided BEFORE the first
//! `tools/call`.
//!
//! An upstream job is recoverable only through the complete descriptor its
//! dispatch persisted: backend, tool and the ORIGINAL inner arguments. That
//! descriptor is bounded by the same `record_bytes` budget as every other
//! durable row, so a candidate whose descriptor cannot fit has exactly two
//! possible treatments. Submit first and discover it afterwards, which leaves a
//! real backend job running under a handle this gateway cannot address; or
//! refuse before the wire, with nothing started anywhere. The approved design
//! takes the second, and these two rows are what tells them apart.
//!
//! # The oracle, and why it is two-sided
//!
//! Both rows run the real `/mcp` route, the real worker, and a counted
//! transport, so `calls()` is a fact about the wire rather than about a
//! predicate:
//!
//! * the refused row asserts ZERO calls and a `not_executed` settlement — a
//!   measurement that under-counts would dispatch, and the counter would say so;
//! * the fitting row asserts ONE call AND that the handle became durable — a
//!   measurement that over-counts would refuse it (zero calls), and one that
//!   reserved too little for the handle would let the dispatch through and then
//!   lose the descriptor at `mark_upstream`, leaving no durable row to read.
//!
//! One property is not visible at the wire and has its own oracle: the refusal
//! happens before the dispatch MARKER as well as before the call, so a crash in
//! that window leaves a row startup settles as `not_executed`. [`Stages`] is
//! what observes it; every other assertion below would hold either way.
//!
//! # Escaping is the falsifier
//!
//! The refused argument's UTF-8 length is COMFORTABLY under the record budget;
//! only its JSON encoding is over it, because every byte of it is a quotation
//! mark serde_json must escape. A preflight that measured raw bytes — the
//! obvious under-count — would accept it, dispatch, and fail this row on the
//! counter. Each row asserts that property of its own payload inline, so a
//! future edit that resizes them cannot quietly remove it.
//!
//! The handle allowance is satisfied by construction rather than falsified
//! here: the fitting row leaves ~20 KiB of headroom, far more than the 3 KiB a
//! maximal handle can encode to, so it is not a boundary case for that
//! reservation and does not pretend to be one.
use super::super::*;
use super::support::*;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::gateway::task_service::{
    CommitObserver, CommitStage, UpstreamAnswer, UpstreamHandle, UpstreamRecovery,
};

/// The opaque handle the peer answers a task-augmented call with.
const UPSTREAM_HANDLE: &str = "upstream-job-1";

/// The gateway default this suite's store is opened with (`StoreLimits`,
/// `store.rs:82`). Named here so the payload sizes below are readable as what
/// they are: one deliberately over it, one deliberately under it.
const RECORD_BYTES: usize = 512 * 1024;

/// An argument string of `count` quotation marks.
///
/// Every byte of it doubles under `serde_json`, which is what makes the two
/// payloads below differ from their own encodings. Quotation marks rather than
/// C0 controls — which would escape six-fold — because a null byte is rejected
/// wherever input sanitization is enabled (`security/sanitize.rs`), and a row
/// that only works with sanitization off is a row about the wrong rule.
fn escape_heavy(count: usize) -> Value {
    json!({ "payload": "\"".repeat(count) })
}

/// The raw and encoded sizes of an argument value.
fn sizes(arguments: &Value) -> (usize, usize) {
    let raw = arguments
        .pointer("/payload")
        .and_then(Value::as_str)
        .expect("the fixture payload is a string")
        .len();
    let encoded = serde_json::to_vec(arguments)
        .expect("a fixture argument serialises")
        .len();
    (raw, encoded)
}

/// A `Transport` that counts every dispatch reaching it and answers the
/// task-augmented leg with a genuine peer `CreateTask` envelope.
///
/// Local to this file rather than an edit to the suite's shared `MockBackend`:
/// the upstream leg is `request_with_task_capability`, which the shared mock
/// does not implement, and teaching it that method would change a fixture every
/// other row in this suite depends on. Both entry points count, so "the backend
/// was never called" cannot be satisfied by a call that took the other one.
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

    fn envelope() -> JsonRpcResponse {
        JsonRpcResponse::success(
            RequestId::Number(1),
            json!({
                "resultType": "task",
                "taskId": UPSTREAM_HANDLE,
                "status": "working"
            }),
        )
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
            // The ordinary leg. Counted too: a preflight that refused an armed
            // candidate and then dispatched it unarmed would arrive here, and
            // that is the silent fallback these rows forbid.
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
            return Ok(Self::envelope());
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

/// Every durable stage the executor reached, in order.
///
/// The refused row's one non-wire oracle. A preflight placed BELOW the dispatch
/// marker would refuse the same candidate, call nothing and settle the same
/// `not_executed` — every other assertion here would still hold — but it would
/// have written `dispatched: true` first, and a crash in that window is the
/// difference between a row startup settles as `not_executed` and one it can
/// only report as `unknown`. This observer is what keeps the ordering from
/// being undone silently.
struct Stages {
    seen: parking_lot::Mutex<Vec<(CommitStage, String)>>,
}

impl Stages {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            seen: parking_lot::Mutex::new(Vec::new()),
        })
    }

    fn saw(&self, stage: CommitStage, id: &str) -> bool {
        self.seen
            .lock()
            .iter()
            .any(|(seen, task)| *seen == stage && task == id)
    }
}

#[async_trait::async_trait]
impl CommitObserver for Stages {
    async fn reached(&self, stage: CommitStage, task_id: &str) {
        self.seen.lock().push((stage, task_id.to_owned()));
    }
}

/// The trusted recovery adapter, reduced to what these rows need: it claims the
/// fixture backend and answers one query with a distinctive result.
///
/// It records the handles it was queried with, so "the durable handle is the one
/// the peer chose" is observed rather than assumed.
struct FakeRecovery {
    queried: parking_lot::Mutex<Vec<String>>,
}

impl FakeRecovery {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            queried: parking_lot::Mutex::new(Vec::new()),
        })
    }

    fn queried(&self) -> Vec<String> {
        self.queried.lock().clone()
    }
}

#[async_trait::async_trait]
impl UpstreamRecovery for FakeRecovery {
    async fn claims(&self, backend: &str) -> bool {
        backend == BACKEND
    }

    /// Deliberately a SMALL result. The settlement re-serializes the whole
    /// record, descriptor included, so a large answer here would spend the
    /// fitting row's headroom on the fixture and fail it as a capacity refusal
    /// far from anything it is about.
    async fn query(&self, handle: &UpstreamHandle, _deadline: Duration) -> UpstreamAnswer {
        self.queried.lock().push(handle.handle.clone());
        UpstreamAnswer::Completed(json!({
            "content": [{ "type": "text", "text": "upstream-answered" }],
            "structuredContent": { "marker": "upstream-answered" }
        }))
    }
}

/// The fixture state, with the counted transport registered under [`BACKEND`]
/// and the recovery adapter installed.
async fn armed_fixture() -> (
    Arc<AppState>,
    Arc<CountedUpstream>,
    Arc<FakeRecovery>,
    Arc<Stages>,
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
    let adapter = FakeRecovery::new();
    assert!(
        state
            .task_executor
            .install_recovery(Arc::clone(&adapter) as Arc<dyn UpstreamRecovery>),
        "the recovery adapter must be the one this executor was given; without it \
         no candidate is ever armed and neither row observes anything"
    );
    let stages = Stages::new();
    state
        .task_executor
        .observe_commits(Arc::clone(&stages) as Arc<dyn CommitObserver>);
    (state, transport, adapter, stages, store)
}

/// GIVEN a task-augmented call whose ORIGINAL arguments cannot fit the durable
/// recovery descriptor, WHEN it is dispatched, THEN the backend is never called
/// and the task settles `not_executed`.
#[tokio::test]
async fn an_oversized_recovery_descriptor_is_refused_before_the_first_call() {
    let (state, transport, adapter, stages, _store) = armed_fixture().await;

    // 300_000 quotation marks: 300 KB raw, 600 KB encoded. A preflight that
    // measured raw bytes would accept this and dispatch.
    let arguments = escape_heavy(300_000);
    let (raw, encoded) = sizes(&arguments);
    std::assert!(
        raw < RECORD_BYTES && encoded > RECORD_BYTES,
        "this row only falsifies an under-counting preflight while its payload \
         fits raw ({raw}) and overflows encoded ({encoded})"
    );

    let created = post(
        &state,
        "key-a",
        task_invoke(1, "i5-descriptor-oversized", arguments),
    )
    .await;
    let id = task_id(&created);
    let settled = poll_until_terminal(&state, "key-a", &id).await;

    std::assert_eq!(
        transport.calls(),
        0,
        "a candidate whose recovery descriptor cannot be made durable is refused \
         before the wire: the backend must see nothing, on either leg. The task \
         settled as {settled}"
    );
    std::assert_eq!(
        settled.pointer("/result/result/_meta/io.mcp-gateway~1executionOutcome"),
        Some(&json!("not_executed")),
        "the refusal must say the backend never ran, and never claim an outcome \
         it did not observe: {settled}"
    );
    std::assert!(
        state.task_executor.durable_upstream_for_test(&id).is_none(),
        "a refused candidate holds no handle and no descriptor: nothing was \
         submitted for one to describe"
    );
    std::assert!(
        adapter.queried().is_empty(),
        "no handle exists, so no upstream query may have been made"
    );
    std::assert!(
        !stages.saw(CommitStage::Dispatched, &id),
        "the capacity question is answered before the row claims to have been \
         dispatched: a refused candidate never writes the marker, so a crash in \
         that window is `not_executed` rather than `unknown`"
    );
}

/// GIVEN a task-augmented call whose descriptor fits the record budget with the
/// widest handle reserved, WHEN it is dispatched, THEN it reaches the backend
/// exactly once and the handle the peer answered with is made durable.
#[tokio::test]
async fn a_fitting_descriptor_reaches_one_call_and_its_handle_is_made_durable() {
    let (state, transport, adapter, stages, _store) = armed_fixture().await;

    // 250_000 quotation marks: 250 KB raw, 500 KB encoded — under the budget
    // with room for the record's own fields and the handle reservation, and
    // still escape-heavy, so an over-counting preflight refuses it and this row
    // reports zero calls.
    let arguments = escape_heavy(250_000);
    let (raw, encoded) = sizes(&arguments);
    std::assert!(
        encoded < RECORD_BYTES && encoded > raw,
        "this row must stay inside the budget as ENCODED ({encoded}) rather than \
         as raw bytes ({raw}), or it stops measuring the same rule"
    );

    let created = post(
        &state,
        "key-a",
        task_invoke(1, "i5-descriptor-fitting", arguments.clone()),
    )
    .await;
    let id = task_id(&created);
    // Join the live worker before the first recovery-capable read. This makes
    // the query count below evidence of the worker's own handle follow.
    let bound = Duration::from_secs(5);
    let joined = tokio::time::timeout(bound, state.task_executor.drain(bound))
        .await
        .expect("the worker settles within the fixture bound");
    std::assert!(joined.is_clean(), "the worker must finish: {joined:?}");
    std::assert_eq!(adapter.queried(), vec![UPSTREAM_HANDLE.to_string()]);
    let settled = poll_until_terminal(&state, "key-a", &id).await;

    std::assert_eq!(
        transport.calls(),
        1,
        "a fitting candidate takes exactly one dispatch — the preflight refuses \
         nothing it can hold, and it never submits twice. The task settled as \
         {settled}"
    );
    let durable = state.task_executor.durable_upstream_for_test(&id).expect(
        "a dispatched upstream job's descriptor must be on disk; without it \
                 the row is unrecoverable and the preflight reserved too little",
    );
    std::assert_eq!(
        durable.handle,
        UPSTREAM_HANDLE,
        "the durable handle is the opaque one the peer chose, verbatim"
    );
    std::assert_eq!(
        (durable.backend.as_str(), durable.tool.as_str()),
        (BACKEND, TOOL),
        "the descriptor names the original target of the call that ran"
    );
    std::assert_eq!(
        durable.arguments,
        arguments,
        "the COMPLETE original inner arguments are what a later read \
         re-authorizes; a narrower descriptor would authorize a different call"
    );
    std::assert_eq!(
        adapter.queried(),
        vec![UPSTREAM_HANDLE.to_string()],
        "the worker follows the handle it captured, and only that one"
    );
    std::assert_eq!(
        settled.pointer("/result/result/structuredContent/marker"),
        Some(&json!("upstream-answered")),
        "the settlement carries the UPSTREAM job's result, not the `working` \
         stub the submission answered with: {settled}"
    );
    std::assert!(
        stages.saw(CommitStage::Dispatched, &id),
        "a candidate the preflight admitted still takes the ordinary marker \
         before its dispatch: the preflight moved that write, it did not remove it"
    );
}
