// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit tests for [`super::Backend`] construction, start/health-probe
//! lifecycle, request/notify dispatch, cached-metadata single-flight
//! behavior, and tool-annotation inference.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use async_trait::async_trait;
use serde_json::{Value, json};
use tokio::sync::Barrier;
use tokio::time::sleep;

use super::cached_metadata::CachedMetadata;
use super::*;
use crate::config::TransportConfig;
use crate::protocol::{JsonRpcResponse, RequestId, Tool, ToolAnnotations, ToolsListResult};
use crate::transport::Transport;
use crate::{Error, Result};

mod breaker_and_status;
mod era_probe;
mod login_probe;
mod login_window;
mod per_identity_catalogue;
mod tool_cache;

struct MockTransport {
    response: JsonRpcResponse,
    delay: Duration,
    connected: AtomicBool,
    requests: AtomicUsize,
}

impl MockTransport {
    fn new(response: JsonRpcResponse, delay: Duration) -> Self {
        Self {
            response,
            delay,
            connected: AtomicBool::new(true),
            requests: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl Transport for MockTransport {
    async fn request(&self, method: &str, _params: Option<Value>) -> Result<JsonRpcResponse> {
        assert_eq!(method, "tools/list");
        self.requests.fetch_add(1, Ordering::SeqCst);
        sleep(self.delay).await;
        Ok(self.response.clone())
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    async fn close(&self) -> Result<()> {
        self.connected.store(false, Ordering::Relaxed);
        Ok(())
    }
}

// Method-agnostic transport for health-probe / recovery tests: answers any
// request with success unless `fail` is set, with a settable `connected`
// flag. Distinct from MockTransport, which hard-asserts "tools/list".
struct RecoveryMock {
    connected: AtomicBool,
    fail: AtomicBool,
    pings: AtomicUsize,
}

impl RecoveryMock {
    fn connected() -> Self {
        Self {
            connected: AtomicBool::new(true),
            fail: AtomicBool::new(false),
            pings: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl Transport for RecoveryMock {
    async fn request(&self, _method: &str, _params: Option<Value>) -> Result<JsonRpcResponse> {
        self.pings.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::Relaxed) {
            return Err(Error::BackendUnavailable("probe failed".to_string()));
        }
        Ok(JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            json!({}),
        ))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    async fn close(&self) -> Result<()> {
        self.connected.store(false, Ordering::Relaxed);
        Ok(())
    }
}

fn sample_tool(name: &str) -> Tool {
    Tool {
        name: name.to_string(),
        title: None,
        description: Some(format!("{name} tool")),
        input_schema: json!({"type": "object"}),
        output_schema: None,
        annotations: None,
        role: None,
        projection: None,
    }
}

#[path = "prepare_tool_metadata_tests.rs"]
mod prepare_tool_metadata_tests;

// ── MIK-7217 OUTBOUND.1/.2 — era-gated health probe ─────────────────────
//
// Rows from section 6 of
// `docs/design/2026-09-11-outbound-era-gated-health-probe.md`. Each test names
// the row it pins. Rows marked fail-first there must fail against HEAD; a row
// that passes today is pinning something other than the defect it names.

/// One scripted answer from the peer, in the shape the probe actually receives
/// it. The two error shapes are not interchangeable: an in-band JSON-RPC error
/// is `Ok(JsonRpcResponse)` with `error` set (stdio, WebSocket), a
/// status-carried one is `Err(Error::JsonRpc)` (HTTP). An implementation that
/// covers only the first restarts every HTTP peer that declines a probe.
#[derive(Clone)]
enum ProbeAnswer {
    Result(Value),
    InBandError(i32),
    StatusError(i32),
    Fault,
}

/// Records the method of every request and answers from a script, so a row can
/// pin *which* method reached the wire rather than only how many did.
struct ProbeMock {
    methods: std::sync::Mutex<Vec<String>>,
    answers: std::sync::Mutex<std::collections::VecDeque<ProbeAnswer>>,
    /// Answer given once the script runs out. It exists because an
    /// invalidation spawns a **detached** classification probe: that probe
    /// draws from the same mock at a time no test controls, so a row scripting
    /// one answer per tick would be racing it for queue slots. A standing
    /// answer makes every row that outlives its script deterministic.
    default_answer: std::sync::Mutex<ProbeAnswer>,
    connected: AtomicBool,
    /// Set by [`ProbeMock::gated`]: every answer waits for it.
    gate: std::sync::Mutex<Option<Arc<tokio::sync::Notify>>>,
}

impl ProbeMock {
    fn scripted(answers: Vec<ProbeAnswer>) -> Self {
        Self {
            methods: std::sync::Mutex::new(Vec::new()),
            answers: std::sync::Mutex::new(answers.into()),
            default_answer: std::sync::Mutex::new(ProbeAnswer::Result(json!({}))),
            connected: AtomicBool::new(true),
            gate: std::sync::Mutex::new(None),
        }
    }

    /// The era classification probe answers `server/discover` with a code only
    /// a modern peer knows, which is what leaves the cache `Probed`/`Modern`.
    /// `-32601` would do the opposite: `classify` reads it as legacy evidence.
    fn modern_then(mut rest: Vec<ProbeAnswer>) -> Self {
        let mut answers = vec![ProbeAnswer::InBandError(
            crate::protocol::era::UNSUPPORTED_PROTOCOL_VERSION,
        )];
        answers.append(&mut rest);
        Self::scripted(answers)
    }

    /// The mirror of `modern_then`: `-32601` to `server/discover` is the
    /// honest legacy answer, so this leaves the cache `Probed`/`Legacy`.
    fn legacy_then(mut rest: Vec<ProbeAnswer>) -> Self {
        let mut answers = vec![ProbeAnswer::InBandError(
            crate::protocol::era::METHOD_NOT_FOUND_CODE,
        )];
        answers.append(&mut rest);
        Self::scripted(answers)
    }

    /// Set the standing answer. Rows that need the peer's behaviour to change
    /// mid-test use this rather than lengthening the script, so a detached
    /// probe arriving late gets the same answer a tick would.
    fn set_default(&self, answer: ProbeAnswer) {
        *self.default_answer.lock().expect("default lock") = answer;
    }

    /// Refuse everything after the scripted prefix, the way a peer that knows
    /// neither `server/discover` nor `ping` does.
    fn refusing(self, code: i32) -> Self {
        self.set_default(ProbeAnswer::InBandError(code));
        self
    }

    /// Hold every answer until the returned gate is notified, so a test can
    /// keep one probe outstanding across a tick.
    fn gated(self, gate: Arc<tokio::sync::Notify>) -> Self {
        *self.gate.lock().expect("gate lock") = Some(gate);
        self
    }

    fn methods(&self) -> Vec<String> {
        self.methods.lock().expect("methods lock").clone()
    }

    /// Methods seen after the era classification probe consumed the first one.
    fn probed_methods(&self) -> Vec<String> {
        self.methods().into_iter().skip(1).collect()
    }
}

#[async_trait]
impl Transport for ProbeMock {
    async fn request(&self, method: &str, _params: Option<Value>) -> Result<JsonRpcResponse> {
        self.methods
            .lock()
            .expect("methods lock")
            .push(method.to_string());
        let gate = self.gate.lock().expect("gate lock").clone();
        if let Some(gate) = gate {
            gate.notified().await;
        }
        let answer = self
            .answers
            .lock()
            .expect("answers lock")
            .pop_front()
            .unwrap_or_else(|| self.default_answer.lock().expect("default lock").clone());
        match answer {
            ProbeAnswer::Result(value) => Ok(JsonRpcResponse::success_serialized(
                RequestId::Number(1),
                value,
            )),
            ProbeAnswer::InBandError(code) => Ok(JsonRpcResponse::error(
                Some(RequestId::Number(1)),
                code,
                "declined",
            )),
            ProbeAnswer::StatusError(code) => Err(Error::JsonRpc {
                code,
                message: "declined".to_string(),
                data: None,
            }),
            ProbeAnswer::Fault => Err(Error::BackendUnavailable("socket closed".to_string())),
        }
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    async fn close(&self) -> Result<()> {
        self.connected.store(false, Ordering::Relaxed);
        Ok(())
    }
}

/// Whether the shared pool slot still holds `mock`.
///
/// `force_restart` takes the transport out of that slot before it does anything
/// else, so losing the slot is the probe's restart observable. Counting
/// `close()` calls is not: the probe holds an internal-activity lease for its
/// whole duration, so `force_restart` always takes its busy branch and defers
/// the close to a task that waits for every other owner of the `Arc` to let
/// go, and a test that keeps `mock` to assert on is one of those owners, so
/// the count cannot move in any row here. Row 7 is the control that proves
/// this observable does.
fn still_wired(backend: &Backend, mock: &Arc<ProbeMock>) -> bool {
    backend
        .pooled_transport_for_test(&crate::backend::pool::PoolKey::Shared)
        .is_some_and(|t| std::ptr::addr_eq(Arc::as_ptr(&t), Arc::as_ptr(mock)))
}

/// A backend wired to `mock`, with its era resolved from the mock's first
/// scripted answer when `classify` is asked to run.
async fn probe_backend(mock: Arc<ProbeMock>, resolve_era: bool) -> Arc<Backend> {
    let backend = Arc::new(Backend::new(
        "test",
        BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let transport = mock as Arc<dyn Transport>;
    backend.set_transport_for_test(Arc::clone(&transport));
    if resolve_era {
        backend.resolve_era(&transport).await;
    }
    backend
}

// Rows 9d, 9f and 10e: the unserved count across an era invalidation (#579).
mod unserved_era;
