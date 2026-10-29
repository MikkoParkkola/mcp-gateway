// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8014 per-call timing harness (design r3 M2): the full HTTP handler
//! stack in-process (`create_router` → `oneshot`), timed per call.
//!
//! Ignored: it only prints numbers. `scripts/perf/per_call_gate.py` runs it on
//! the bench host for base and head builds in counterbalanced ABBA blocks,
//! with an A/A null arm and a negative-control arm, and applies the gate's
//! VOID / FAIL rules. Run alone:
//! `cargo test --lib -- --ignored --exact <path>::per_call_timing --nocapture`.
//!
//! Every row is a named stage of the `STAGES` table; the gate script refuses
//! a table entry that printed no row (design r5).

use std::sync::Arc;
use std::time::Instant;

use serde_json::{Value, json};
use tower::ServiceExt;

use crate::gateway::router::create_router;

/// The rows this harness measures, one per per-call stage the family gates:
/// each entry keeps its name with the parameters that produce it, as
/// `(name, over_http, blob_bytes, calls_per_frame)`, so a reorder cannot
/// mislabel a row. `scripts/ci/check_per_call_stages.py` keeps this table in
/// step with the tools/call path.
pub(crate) const STAGES: &[(&str, bool, usize, usize)] = &[
    ("http_invoke_tiny", true, 16, 1),
    ("http_invoke_64k", true, 64 * 1024, 1),
    ("http_surfaced_tiny", true, 16, 1),
    ("stdio_invoke_tiny", false, 16, 1),
    ("stdio_batch_tiny", false, 16, BATCH),
];

/// The gate's per-row budget ceiling (`per_call_gate.py`'s `CEILING_NS`): the
/// smallest slowdown the gate claims it can detect, so the size of the
/// negative-control spin below.
const CEILING_NS: u64 = 4000;

/// Calls per batch frame in the `stdio_batch_tiny` row; its time is reported
/// per call.
const BATCH: usize = 3;

const WARMUP: usize = 200;
const CALLS: usize = 2000;

/// Set only by the negative-control arm (`PER_CALL_NEGATIVE_CONTROL=1`): the
/// harness's own backend spins this long per call, so the gate can prove it
/// catches a slowdown. It lives in test code that both arms carry, so no
/// production path holds a hook and the arms pay identical costs.
static NEGATIVE_CONTROL_SPIN_NS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// The negative-control stage: a deliberate busy wait, off unless armed.
fn negative_control_stage() {
    let ns = NEGATIVE_CONTROL_SPIN_NS.load(std::sync::atomic::Ordering::Relaxed);
    if ns > 0 {
        let start = Instant::now();
        while start.elapsed().as_nanos() < u128::from(ns) {
            std::hint::spin_loop();
        }
    }
}

/// The one tool the bench backend lists.
fn search_tool() -> serde_json::Value {
    json!({
        "name": "search",
        "description": "probe",
        "inputSchema": {"type": "object", "properties": {"blob": {"type": "string"}}}
    })
}

/// `tools/call`s the harness backend has answered: each timed sample must move
/// it by exactly its call count, so a cached or refused answer cannot be
/// priced as a dispatch (design M6).
static DISPATCHED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn dispatched() -> usize {
    DISPATCHED.load(std::sync::atomic::Ordering::Relaxed)
}

/// A backend that answers every call at once and keeps nothing.
struct Answer;

#[async_trait::async_trait]
impl crate::transport::Transport for Answer {
    async fn request(
        &self,
        method: &str,
        _params: Option<serde_json::Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        let result = match method {
            "tools/list" => json!({"tools": [search_tool()]}),
            "tools/call" => {
                negative_control_stage();
                DISPATCHED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                json!({"content": []})
            }
            _ => json!({}),
        };
        Ok(crate::protocol::JsonRpcResponse::success_serialized(
            crate::protocol::RequestId::Number(1),
            result,
        ))
    }
    async fn notify(&self, _method: &str, _params: Option<serde_json::Value>) -> crate::Result<()> {
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// The fixture state plus a `bench` backend with the failsafe rate limit and
/// circuit breaker off: thousands of calls must all be dispatches, not
/// refusals priced as calls.
async fn bench_state() -> (
    Arc<crate::gateway::router::AppState>,
    crate::gateway::router::tests::FixtureDir,
) {
    let (state, store) = super::invoke_argument_copies::state().await;
    let mut failsafe = crate::config::FailsafeConfig::default();
    failsafe.rate_limit.enabled = false;
    // The breaker is always on (MIK-8783); a threshold the bench cannot reach
    // keeps it out of the timing.
    failsafe.circuit_breaker.failure_threshold = u32::MAX;
    let backend = Arc::new(crate::backend::Backend::new(
        "bench",
        crate::config::BackendConfig::default(),
        &failsafe,
        std::time::Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(Answer));
    backend.remember_listed_tools(None, false, &[search_tool()]);
    assert!(state.backends.register(backend), "bench backend registered");
    (state, store)
}

/// [`bench_state`] with `search` surfaced from `bench`, so a row can time a
/// call that resolves a surfaced name (the surfaced-tools reload reads that
/// name through a request snapshot).
async fn surfaced_bench_state() -> (
    Arc<crate::gateway::router::AppState>,
    crate::gateway::router::tests::FixtureDir,
) {
    let (mut state, store) = bench_state().await;
    let inner = Arc::get_mut(&mut state).expect("bench state is not shared yet");
    inner.meta_mcp = Arc::new(
        crate::gateway::meta_mcp::MetaMcp::new(Arc::clone(&inner.backends)).with_surfaced_tools(
            vec![crate::config::SurfacedToolConfig {
                server: "bench".to_string(),
                tool: "search".to_string(),
            }],
        ),
    );
    (state, store)
}

/// The `tools/call` body a row times: `gateway_invoke` at `bench`, or the
/// surfaced `search` name directly.
fn http_call(stage: &str, blob: usize) -> String {
    let arguments = json!({"blob": "x".repeat(blob)});
    let params = if stage == "http_surfaced_tiny" {
        json!({"name": "search", "arguments": arguments})
    } else {
        json!({"name": "gateway_invoke", "arguments": {
            "server": "bench", "tool": "search", "arguments": arguments,
        }})
    };
    json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": params}).to_string()
}

async fn median_ns(state: &Arc<crate::gateway::router::AppState>, body: String) -> u128 {
    let mut samples = Vec::with_capacity(CALLS);
    for round in 0..WARMUP + CALLS {
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.clone()))
            .expect("request");
        let router = create_router(Arc::clone(state));
        let before = dispatched();
        let start = Instant::now();
        let response = router.oneshot(request).await.expect("router");
        let elapsed = start.elapsed().as_nanos();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            dispatched() - before == 1
                && text.contains("\"result\"")
                && !text.contains("\"isError\":true"),
            "round {round}: the timed call must reach the backend once: {text}"
        );
        if round >= WARMUP {
            samples.push(elapsed);
        }
    }
    samples.sort_unstable();
    samples[samples.len() / 2]
}

/// A gateway serving stdio (`run_stdio_on`) over in-memory pipes, its
/// `bench` backend on the harness transport, past its handshake.
struct StdioLoop {
    stdin: tokio::io::DuplexStream,
    stdout: tokio::io::Lines<tokio::io::BufReader<tokio::io::DuplexStream>>,
    _served: tokio::task::JoinHandle<crate::Result<()>>,
    _dir: tempfile::TempDir,
}

impl StdioLoop {
    async fn start() -> Self {
        use tokio::io::AsyncBufReadExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gateway.yaml");
        // The URL is never dialled: the transport is replaced below.
        let yaml = format!(
            "backends:\n  bench:\n    http_url: \"http://127.0.0.1:9/\"\n\
             failsafe:\n  rate_limit:\n    enabled: false\n  circuit_breaker:\n    enabled: false\n\
             cache:\n  enabled: false\n\
             tasks:\n  store_dir: {}\n",
            serde_json::to_string(&dir.path().join("tasks").display().to_string())
                .expect("a JSON string")
        );
        crate::gateway::test_helpers::write_owner_only(&path, yaml).expect("write config");
        let config = crate::config::Config::load(Some(&path)).expect("config loads");
        let gateway = super::super::Gateway::new(config)
            .await
            .expect("gateway boots")
            .with_data_dir(dir.path().to_path_buf());
        let backend = gateway.backends.get("bench").expect("bench backend");
        backend.set_transport_for_test(Arc::new(Answer));
        backend.remember_listed_tools(None, false, &[search_tool()]);
        let (stdin, input) = tokio::io::duplex(64 * 1024);
        let (output, reader) = tokio::io::duplex(1 << 20);
        let served = tokio::spawn(async move { gateway.run_stdio_on(input, output, None).await });
        let mut served_loop = Self {
            stdin,
            stdout: tokio::io::BufReader::new(reader).lines(),
            _served: served,
            _dir: dir,
        };
        let handshake = json!({
            "jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "per-call-timing", "version": "0"},
            },
        });
        let answer = served_loop.round_trip(&handshake.to_string()).await;
        assert!(answer.contains("\"result\""), "handshake: {answer}");
        served_loop
    }

    /// Writes one line and reads the next line the gateway writes.
    async fn round_trip(&mut self, line: &str) -> String {
        use tokio::io::AsyncWriteExt as _;
        self.stdin
            .write_all(format!("{line}\n").as_bytes())
            .await
            .expect("stdin");
        self.stdout
            .next_line()
            .await
            .expect("stdout")
            .expect("stdout open")
    }
}

/// One `gateway_invoke` of the bench backend's `search`, as a stdio frame,
/// its argument carrying a `blob`-byte string.
fn stdio_invoke(id: &str, blob: usize) -> Value {
    json!({
        "jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": {"name": "gateway_invoke", "arguments": {
            "server": "bench", "tool": "search", "arguments": {"blob": "x".repeat(blob)},
        }},
    })
}

/// The stdio rows: the whole stdio loop (`run_stdio_on`), from the line
/// written to its stdin to the answer read from its stdout, so the request
/// task's spawn and its `CountOnly` hold (MIK-8176) are on the timed path.
/// `batch` calls go in one array frame; the time is reported per call.
async fn stdio_median_ns(stdio: &mut StdioLoop, blob: usize, batch: usize) -> u128 {
    let mut samples = Vec::with_capacity(CALLS);
    for round in 0..WARMUP + CALLS {
        let line = if batch == 1 {
            stdio_invoke(&format!("t{round}"), blob).to_string()
        } else {
            Value::Array(
                (0..batch)
                    .map(|i| stdio_invoke(&format!("b{round}-{i}"), blob))
                    .collect(),
            )
            .to_string()
        };
        let before = dispatched();
        let start = Instant::now();
        let answer = stdio.round_trip(&line).await;
        let elapsed = start.elapsed().as_nanos();
        let answers: Vec<Value> = match serde_json::from_str(&answer).expect("one JSON frame") {
            Value::Array(items) => items,
            single => vec![single],
        };
        assert!(
            dispatched() - before == batch
                && answers.len() == batch
                && answers
                    .iter()
                    .all(|a| a.get("result").is_some() && a["result"]["isError"] != json!(true)),
            "round {round}: every timed stdio call must reach the backend: {answer}"
        );
        if round >= WARMUP {
            samples.push(elapsed / batch as u128);
        }
    }
    samples.sort_unstable();
    samples[samples.len() / 2]
}

#[test]
#[ignore = "timing harness: run by scripts/perf/per_call_gate.py on the bench host"]
fn per_call_timing() {
    if std::env::var_os("PER_CALL_NEGATIVE_CONTROL").is_some() {
        // Exactly the ceiling the gate claims it can detect (F5): a larger
        // spin would prove less sensitivity than the gate asserts.
        NEGATIVE_CONTROL_SPIN_NS.store(CEILING_NS, std::sync::atomic::Ordering::Relaxed);
    }
    super::signing_nonce_allocations_support::runtime().block_on(async {
        let (state, _store) = bench_state().await;
        let (surfaced, _surfaced_store) = surfaced_bench_state().await;
        for &(stage, _, blob, _) in STAGES.iter().filter(|stage| stage.1) {
            let on = if stage == "http_surfaced_tiny" {
                &surfaced
            } else {
                &state
            };
            println!(
                "PER_CALL_NS {stage} {}",
                median_ns(on, http_call(stage, blob)).await
            );
        }
        let mut stdio = StdioLoop::start().await;
        for &(stage, _, blob, batch) in STAGES.iter().filter(|stage| !stage.1) {
            println!(
                "PER_CALL_NS {stage} {}",
                stdio_median_ns(&mut stdio, blob, batch).await
            );
        }
    });
}
