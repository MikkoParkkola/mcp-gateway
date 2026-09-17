// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The counted backend the task-producing rows of `mik_7272_task_1_acs`
//! dispatch to.
//!
//! Why this file exists at all: every row that needs a REAL task needs a tool
//! call that is eligible to become one. `gateway_list_servers` is not — it is a
//! governed built-in the gateway answers synchronously in I1, so a
//! task-augmented call naming it is answered `complete` and no task is ever
//! created. Rows built on it were asserting against a handle that never
//! existed. The fix is a backend that really is eligible, not a relabelling of
//! the built-in and not a weakened authorization rule.
//!
//! Three properties, each of which is a property because the alternative gives
//! a row that passes without observing anything:
//!
//! * **Real transport.** [`CountedBackend`] is served over a REAL loopback
//!   Streamable HTTP listener and registered through the public
//!   `TransportConfig::Http` seam, so a dispatch reaches it through `Backend`
//!   -> the invoke chokepoint -> the pool -> an actual HTTP round trip,
//!   exactly as a production call does. No test-only injection API is used;
//!   `set_transport_for_test` is `cfg(test)` and does not exist for an
//!   external test binary.
//! * **Counted, per fixture.** The `tools/call` counter is an `AtomicUsize` on
//!   the instance, never a static: two tests running in one binary cannot read
//!   each other's count, so no "the backend ran once" assertion depends on
//!   test ordering. Discovery (`initialize`, `tools/list`) is deliberately NOT
//!   counted — it is not a dispatch, and counting it would let a row pass on a
//!   backend that was merely listed.
//! * **Honest tool definition.** [`TOOL`] declares itself read-only and
//!   non-destructive because it IS: it returns a fixed marker and mutates
//!   nothing. A fixture that claimed otherwise would be borrowing a
//!   destructive-authorization decision it has no right to.
//!
//! [`GateHandle`] is the only waiting primitive here, and it is a barrier at a
//! lifecycle seam rather than a delay: `arrived` fires when a dispatch has
//! genuinely reached the backend, and `release` holds that dispatch until the
//! test lets it answer. Nothing in this file sleeps, and every loop is bounded
//! by scheduler turns rather than by a clock, so a route that never dispatches
//! FAILS its row instead of hanging the binary.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use mcp_gateway::backend::Backend;
use mcp_gateway::config::{BackendConfig, FailsafeConfig, TransportConfig};
use mcp_gateway::gateway::test_helpers::AppState;
use mcp_gateway::protocol::{JsonRpcResponse, RequestId};
use mcp_gateway::transport::Transport;
use serde_json::{Value, json};

/// The backend name every task-producing row dispatches to, and the only name
/// the fixture's API keys are scoped to reach.
pub(crate) const BACKEND: &str = "mock";

/// The tool on that backend. Read-only and non-destructive, as declared.
pub(crate) const TOOL: &str = "echo";

/// A distinctive payload, so "carries the backend's own result" is an
/// observation rather than a coincidence between two empty objects.
pub(crate) const MARKER: &str = "mik-7272-backend-answered";

/// The outer bound on every wait in this suite.
///
/// A bound, not a delay: nothing here sleeps and no wait consumes it on a
/// healthy run — a dispatch that crosses the loopback listener arrives in
/// microseconds. It exists so a route that never dispatches FAILS its row
/// finitely instead of hanging the binary, and it is a clock rather than a
/// scheduler-turn count only because the arrival now depends on real HTTP I/O
/// making progress, which a spin of `yield_now` alone cannot bound honestly.
///
/// Visible to the suite, not just to this file: a row that polls a task to its
/// terminal state over the wire needs the same outer bound, and a second
/// constant spelled beside it would be a second clock that can disagree with
/// this one about how long "never happened" takes.
pub(crate) const BOUND: Duration = Duration::from_secs(5);

/// The backend's end of a dispatch barrier.
struct Gate {
    arrived: tokio::sync::mpsc::UnboundedSender<()>,
    release: Arc<tokio::sync::Semaphore>,
}

/// The test's end of a [`Gate`].
pub(crate) struct GateHandle {
    arrived: tokio::sync::mpsc::UnboundedReceiver<()>,
    release: Arc<tokio::sync::Semaphore>,
}

impl GateHandle {
    /// Block until a dispatch has actually reached the backend.
    ///
    /// The "the worker really started" barrier: a row that asserts a task is
    /// `working` uses it so the assertion observes a dispatch genuinely in
    /// flight, rather than one that was never handed to the executor — two
    /// states a status poll cannot tell apart.
    pub(crate) async fn wait_for_dispatch(&mut self) {
        let deadline = Instant::now() + BOUND;
        while Instant::now() < deadline {
            match self.arrived.try_recv() {
                Ok(()) => return,
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                    tokio::task::yield_now().await;
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                    panic!("the fixture backend was dropped before any dispatch reached it")
                }
            }
        }
        panic!(
            "no dispatch reached the backend within {BOUND:?}; \
             the task was accepted and never handed to the executor"
        );
    }

    /// Let every held dispatch answer, this one and any that follow.
    pub(crate) fn release_all(&self) {
        self.release.add_permits(1_000);
    }
}

/// A `Transport` that answers the surface a dispatch needs, counts the
/// `tools/call`s it receives, and can hold them open.
pub(crate) struct CountedBackend {
    calls: AtomicUsize,
    seen: Mutex<Vec<Value>>,
    gate: Option<Gate>,
}

impl CountedBackend {
    /// A backend that answers every dispatch immediately.
    pub(crate) fn open() -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
            gate: None,
        })
    }

    /// A backend that holds every dispatch until the returned handle releases
    /// it, and reports each arrival on that handle.
    ///
    /// The rows that need a task to still be `working` when a second request
    /// reaches it use this. Without it they would race the executor: a mock
    /// that answers immediately can settle the task before the next request is
    /// built, and the row would then be asserting about a terminal task while
    /// claiming to assert about a running one.
    pub(crate) fn holding() -> (Arc<Self>, GateHandle) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let backend = Arc::new(Self {
            calls: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
            gate: Some(Gate {
                arrived: tx,
                release: Arc::clone(&release),
            }),
        });
        (
            backend,
            GateHandle {
                arrived: rx,
                release,
            },
        )
    }

    /// How many `tools/call`s reached the backend.
    ///
    /// Counted on ARRIVAL, before the gate: a held dispatch HAS reached the
    /// backend, and a row proving "the backend never ran" must not be satisfied
    /// by one that ran and is merely still waiting.
    pub(crate) fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// Wait until exactly `expected` dispatches have arrived, then hold the
    /// count to that number.
    ///
    /// Bounded by scheduler turns, not by a clock, and it is not a sleep: task
    /// dispatch is spawned, so the count becomes observable only once the
    /// worker has run. The trailing equality is the half that matters — a route
    /// that dispatches TWICE for one create satisfies "at least one" and is
    /// precisely the defect the counter exists to catch.
    pub(crate) async fn wait_for_calls(&self, expected: usize) {
        let deadline = Instant::now() + BOUND;
        while Instant::now() < deadline {
            if self.calls() >= expected {
                assert_eq!(
                    self.calls(),
                    expected,
                    "the backend must be dispatched to exactly {expected} time(s)"
                );
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!(
            "the backend saw {} dispatch(es) within {BOUND:?}, expected {expected}",
            self.calls()
        );
    }

    fn result() -> Value {
        json!({
            "content": [{ "type": "text", "text": MARKER }],
            "structuredContent": { "marker": MARKER }
        })
    }
}

#[async_trait]
impl Transport for CountedBackend {
    async fn request(
        &self,
        method: &str,
        params: Option<Value>,
    ) -> mcp_gateway::Result<JsonRpcResponse> {
        match method {
            "initialize" => Ok(JsonRpcResponse::success(
                RequestId::Number(1),
                json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": BACKEND, "version": "0" }
                }),
            )),
            "tools/list" => Ok(JsonRpcResponse::success(
                RequestId::Number(1),
                json!({
                    "tools": [{
                        "name": TOOL,
                        "description": "Returns a fixed marker; reads and mutates nothing.",
                        "inputSchema": { "type": "object", "properties": {} },
                        "annotations": {
                            "title": "Echo",
                            "readOnlyHint": true,
                            "destructiveHint": false,
                            "idempotentHint": true,
                            "openWorldHint": false
                        }
                    }]
                }),
            )),
            "tools/call" => {
                self.seen
                    .lock()
                    .expect("recorder is never poisoned")
                    .push(params.unwrap_or(Value::Null));
                self.calls.fetch_add(1, Ordering::SeqCst);
                if let Some(ref gate) = self.gate {
                    // Announce BEFORE waiting: the barrier a row waits on is
                    // "the backend was reached", and announcing after the wait
                    // would make that barrier unreachable.
                    let _ = gate.arrived.send(());
                    gate.release
                        .acquire()
                        .await
                        .expect("the gate semaphore is never closed")
                        .forget();
                }
                Ok(JsonRpcResponse::success(
                    RequestId::Number(1),
                    Self::result(),
                ))
            }
            _ => Ok(JsonRpcResponse::success(RequestId::Number(1), json!({}))),
        }
    }

    /// Notifications are accepted and dropped, and deliberately uncounted: a
    /// cancellation notice or a progress ping is not a dispatch, and counting
    /// one would let a row pass on a tool that was never invoked.
    async fn notify(&self, _method: &str, _params: Option<Value>) -> mcp_gateway::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> mcp_gateway::Result<()> {
        Ok(())
    }
}

/// The loopback listener serving [`CountedBackend`], owned by the fixture for
/// the whole test.
///
/// Owned narrowly and on purpose: dropping it aborts THIS server task and
/// nothing else. It never touches the gateway's own `TaskExecutor` or any other
/// product-owned task, so a test tearing down its mock cannot be mistaken for
/// the product shutting its executor down.
pub(crate) struct ServerGuard {
    server: tokio::task::JoinHandle<()>,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        self.server.abort();
    }
}

/// The one JSON-RPC entry point of the mock, delegating to the SAME
/// [`CountedBackend`] methods a directly-injected transport would have called.
///
/// Every oracle in the suite — the arrival counter, the hold gate, the tool
/// descriptor — therefore observes exactly what it observed before; only the
/// path in is now real HTTP.
async fn mcp_handler(
    State(backend): State<Arc<CountedBackend>>,
    Json(body): Json<Value>,
) -> Response {
    let method = body
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let params = body.get("params").cloned();

    // No `id` is a notification by definition: accepted, answered with an empty
    // 202, and NOT counted — the same rule `notify` encodes below.
    let Some(id) = body.get("id").filter(|id| !id.is_null()).cloned() else {
        let _ = Transport::notify(backend.as_ref(), &method, params).await;
        return StatusCode::ACCEPTED.into_response();
    };

    match Transport::request(backend.as_ref(), &method, params).await {
        Ok(response) => {
            let mut body = serde_json::to_value(&response)
                .expect("a JSON-RPC response always serializes to JSON");
            // Echo the INBOUND id. The helper answers with a fixed `1`, which a
            // real client correlating responses to requests would reject.
            body["id"] = id;
            Json(body).into_response()
        }
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

/// Serve `backend` over a real loopback Streamable HTTP listener and register
/// it under [`BACKEND`] through the public transport configuration.
///
/// Startup stays lazy: `Backend::new` does not connect, so the first dispatch
/// drives the handshake through the production HTTP transport, which is the
/// point — the fixture buys a real path in, not a shortcut around one.
pub(crate) async fn register(state: &Arc<AppState>, backend: &Arc<CountedBackend>) -> ServerGuard {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the fixture backend binds an ephemeral loopback port");
    let addr = listener
        .local_addr()
        .expect("the bound listener reports its address");
    let app = Router::new()
        .route("/mcp", post(mcp_handler))
        .with_state(Arc::clone(backend));
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let registered = Arc::new(Backend::new(
        BACKEND,
        BackendConfig {
            enabled: true,
            transport: TransportConfig::Http {
                http_url: format!("http://{addr}/mcp"),
                streamable_http: true,
                protocol_version: None,
            },
            timeout: Duration::from_secs(10),
            env: HashMap::default(),
            headers: HashMap::default(),
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    assert!(
        state.backends.register(registered),
        "the fixture backend '{BACKEND}' must register under a name nothing else holds"
    );
    ServerGuard { server }
}
