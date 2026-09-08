// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The counted mock backend, and the barrier the holding rows are built on.
//!
//! Injected through `set_transport_for_test`, the same seam the router suite's
//! own transport fixtures use, so a dispatch reaches it through `Backend` -> the
//! invoke chokepoint -> the pool exactly as a production call does.
//!
//! The counter is the suite's primary oracle: "exactly once" is the whole
//! adapter. It is per-instance rather than static, so two fixtures running in
//! one test binary cannot read each other's count — which would make every
//! "the backend ran once" assertion depend on test ordering.
use super::super::super::*;

use std::sync::atomic::{AtomicUsize, Ordering};

/// The backend tool every row calls.
pub(crate) const TOOL: &str = "echo";

/// What the mock answers a `tools/call` with.
///
/// One variant, deliberately. A mock that could also answer a JSON-RPC error
/// would be the obvious way to drive a `failed` task, and it would be the wrong
/// way: the `failed` rows in `settlement.rs` need the error the GATEWAY
/// produces — `Error::Forbidden`, the one variant
/// `error_response_preserving_status` stamps its internal HTTP-status key onto —
/// and a backend-authored error carries no such key, so the row that exists to
/// see the key stripped would never have had one to strip.
pub(crate) enum Answer {
    /// A successful tool result, carried verbatim.
    Result(Value),
}

impl Answer {
    /// The suite's canonical successful result. A distinctive payload, so
    /// "carries the backend's result verbatim" is an observation and not a
    /// coincidence between two empty objects.
    pub(crate) fn ok() -> Self {
        Self::Result(json!({
            "content": [{ "type": "text", "text": "mock-backend-answered" }],
            "structuredContent": { "marker": "mock-backend-answered" }
        }))
    }
}

/// The barrier the holding rows use.
///
/// Two halves, both real seams: `arrived` fires when the backend has actually
/// been called (so a row never asserts "working" before the worker has even
/// started), and `release` is a semaphore the held dispatch waits on (so the
/// answer arrives when the test says so, not when a timer says so).
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
    /// Block until a dispatch has reached the backend.
    ///
    /// This is the "the worker really started" barrier. Rows that assert a
    /// `working` handle use it so that the assertion observes a task whose
    /// dispatch is genuinely in flight, rather than one that has not been
    /// dispatched at all — two states a status poll cannot tell apart.
    ///
    /// Bounded by attempts rather than by a clock, and for the same reason
    /// `poll_until_terminal` is: a route that never dispatches must make its
    /// rows FAIL, not hang the whole test binary waiting for a message that is
    /// never sent. `yield_now` is what lets the spawned worker — and the
    /// `spawn_blocking` durable write it awaits — make progress; it is not a
    /// delay, and no row's correctness depends on how many turns it takes.
    pub(crate) async fn wait_for_dispatch(&mut self) {
        const ATTEMPTS: usize = 20_000;
        for _ in 0..ATTEMPTS {
            match self.arrived.try_recv() {
                Ok(()) => return,
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                    tokio::task::yield_now().await;
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                    panic!("the mock backend was dropped before any dispatch reached it")
                }
            }
        }
        panic!(
            "no dispatch reached the backend in {ATTEMPTS} scheduler turns; \
             the task was accepted and never handed to the executor"
        );
    }

    /// Let one held dispatch answer.
    pub(crate) fn release(&self) {
        self.release.add_permits(1);
    }

    /// Let every dispatch answer, this one and any that follow.
    ///
    /// For rows that expect more dispatches AFTER the barrier has done its work.
    /// [`release`](Self::release) hands out exactly one permit, so a second
    /// arrival at the same mock would block forever and the row would fail with
    /// "the task never settled" — a fixture that ran out of permits, reading as
    /// an adapter that never settles. The two are indistinguishable from the
    /// failure message, which is the whole reason this is a separate method
    /// rather than a larger constant inside the other one.
    pub(crate) fn release_all(&self) {
        self.release.add_permits(1_000);
    }
}

/// A `Transport` that answers the protocol surface a dispatch needs, counts the
/// `tools/call`s it receives, and can hold one open.
pub(crate) struct MockBackend {
    calls: AtomicUsize,
    seen: Mutex<Vec<Value>>,
    answer: Answer,
    gate: Option<Gate>,
}

impl MockBackend {
    /// A backend that answers every call the same way, immediately.
    pub(crate) fn answering(answer: Answer) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
            answer,
            gate: None,
        })
    }

    /// A backend that holds every dispatch until the returned handle releases
    /// it, and reports each arrival on that handle.
    pub(crate) fn holding(answer: Answer) -> (Arc<Self>, GateHandle) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let mock = Arc::new(Self {
            calls: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
            answer,
            gate: Some(Gate {
                arrived: tx,
                release: Arc::clone(&release),
            }),
        });
        (
            mock,
            GateHandle {
                arrived: rx,
                release,
            },
        )
    }

    /// How many `tools/call`s reached the backend.
    ///
    /// Counted on ARRIVAL, before the gate: a held dispatch has reached the
    /// backend, and a row that proves "the backend never ran" must not be
    /// satisfied by one that ran and is merely still waiting.
    pub(crate) fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// The `params` of every `tools/call`, in arrival order.
    pub(crate) fn seen(&self) -> Vec<Value> {
        self.seen
            .lock()
            .expect("recorder is never poisoned")
            .clone()
    }

    fn answer(&self) -> JsonRpcResponse {
        let Answer::Result(ref value) = self.answer;
        JsonRpcResponse::success(RequestId::Number(1), value.clone())
    }
}

#[async_trait]
impl Transport for MockBackend {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
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
            "tools/call" => {
                self.seen
                    .lock()
                    .expect("recorder is never poisoned")
                    .push(params.unwrap_or(Value::Null));
                self.calls.fetch_add(1, Ordering::SeqCst);
                if let Some(ref gate) = self.gate {
                    // Announce before waiting: a row's barrier is "the backend
                    // was reached", and announcing after the wait would make
                    // that barrier unreachable.
                    let _ = gate.arrived.send(());
                    gate.release
                        .acquire()
                        .await
                        .expect("the gate semaphore is never closed")
                        .forget();
                }
                Ok(self.answer())
            }
            _ => Ok(JsonRpcResponse::success(RequestId::Number(1), json!({}))),
        }
    }

    /// Notifications are accepted and dropped.
    ///
    /// Deliberately silent about the counter and the recorder: `calls()` is the
    /// suite's "exactly once" oracle for `tools/call`, and a notification the
    /// dispatch path happens to send — a cancellation notice, a progress ping —
    /// is not a dispatch. Counting one here would let a row pass on a
    /// notification that never invoked the tool.
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
