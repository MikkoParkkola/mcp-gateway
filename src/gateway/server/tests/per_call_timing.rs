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

use serde_json::json;
use tower::ServiceExt;

use crate::gateway::router::create_router;

/// The rows this harness measures, one per per-call stage the family gates.
/// `scripts/ci/check_per_call_stages.py` keeps this table in step with the
/// tools/call path.
pub(crate) const STAGES: &[&str] = &["http_invoke_tiny", "http_invoke_64k"];

const WARMUP: usize = 200;
const CALLS: usize = 2000;

/// Set only by the negative-control arm (`PER_CALL_NEGATIVE_CONTROL=1`): the
/// dispatch spins this long per call, so the gate can prove it catches a
/// slowdown. Test builds only; nothing in production reads it.
pub(crate) static NEGATIVE_CONTROL_SPIN_NS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// The negative-control stage: a deliberate busy wait, off unless armed.
pub(crate) fn negative_control_stage() {
    let ns = NEGATIVE_CONTROL_SPIN_NS.load(std::sync::atomic::Ordering::Relaxed);
    if ns > 0 {
        let start = Instant::now();
        while start.elapsed().as_nanos() < u128::from(ns) {
            std::hint::spin_loop();
        }
    }
}

/// A backend that answers every call at once and keeps nothing.
struct Answer;

#[async_trait::async_trait]
impl crate::transport::Transport for Answer {
    async fn request(
        &self,
        _method: &str,
        _params: Option<serde_json::Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        Ok(crate::protocol::JsonRpcResponse::success_serialized(
            crate::protocol::RequestId::Number(1),
            json!({"content": []}),
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
async fn bench_state() -> (Arc<crate::gateway::router::AppState>, tempfile::TempDir) {
    let (state, store) = super::invoke_argument_copies::state().await;
    let mut failsafe = crate::config::FailsafeConfig::default();
    failsafe.rate_limit.enabled = false;
    failsafe.circuit_breaker.enabled = false;
    let backend = Arc::new(crate::backend::Backend::new(
        "bench",
        crate::config::BackendConfig::default(),
        &failsafe,
        std::time::Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(Answer));
    backend.remember_listed_tools(
        None,
        false,
        &[json!({
            "name": "search",
            "description": "probe",
            "inputSchema": {"type": "object", "properties": {"blob": {"type": "string"}}}
        })],
    );
    assert!(state.backends.register(backend), "bench backend registered");
    (state, store)
}

async fn median_ns(state: &Arc<crate::gateway::router::AppState>, blob: usize) -> u128 {
    let body = json!({
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "gateway_invoke", "arguments": {
            "server": "bench", "tool": "search", "arguments": {"blob": "x".repeat(blob)},
        }},
    })
    .to_string();
    let mut samples = Vec::with_capacity(CALLS);
    for round in 0..WARMUP + CALLS {
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.clone()))
            .expect("request");
        let router = create_router(Arc::clone(state));
        let start = Instant::now();
        let response = router.oneshot(request).await.expect("router");
        let elapsed = start.elapsed().as_nanos();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            !text.contains("\"isError\":true"),
            "round {round}: the timed call must reach the backend: {text}"
        );
        if round >= WARMUP {
            samples.push(elapsed);
        }
    }
    samples.sort_unstable();
    samples[samples.len() / 2]
}

#[test]
#[ignore = "timing harness: run by scripts/perf/per_call_gate.py on the bench host"]
fn per_call_timing() {
    if std::env::var_os("PER_CALL_NEGATIVE_CONTROL").is_some() {
        NEGATIVE_CONTROL_SPIN_NS.store(10_000, std::sync::atomic::Ordering::Relaxed);
    }
    super::signing_nonce_allocations_support::runtime().block_on(async {
        let (state, _store) = bench_state().await;
        for (stage, blob) in STAGES.iter().zip([16, 64 * 1024]) {
            println!("PER_CALL_NS {stage} {}", median_ns(&state, blob).await);
        }
    });
}
