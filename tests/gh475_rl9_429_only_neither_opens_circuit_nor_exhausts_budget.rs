// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! GH475.RL.9 — a `429`-only backend neither opens its circuit nor exhausts a
//! budget (GH #475 / #481).
//!
//! Drives a real, standalone-axum MCP backend that answers every `tools/call`
//! with HTTP 429 through the production `Backend::request` stack (the same
//! stub-backend-over-real-HTTP harness pattern as
//! `tests/mik_7214_header5_mirroring.rs`), well past both thresholds that a
//! `429` must not move:
//!   - the circuit breaker's `failure_threshold` (default 5,
//!     `src/config/features/failsafe.rs`)
//!   - `HealthTracker`'s hardcoded unhealthy flip at 3 consecutive failures
//!     (`src/failsafe/health.rs`)
//!
//! Chain asserted end-to-end (not just at the `Failsafe` unit level, which
//! `src/failsafe/mod.rs`'s `a_rate_limited_response_does_not_reset_the_failure_streak`
//! already covers): the mock's HTTP 429 becomes `Err(Error::Transport("HTTP
//! 429 Too Many Requests"))` in `src/transport/http/mod.rs`'s
//! `!status.is_success()` branch; `Backend::request_with_headers`
//! (`src/backend/ops.rs`) hands that text to
//! `Failsafe::record_dispatch_failure`; `is_rate_limited`
//! (`src/gateway/recovery.rs`) matches the "too many requests" substring in
//! the rendered status line and routes to `record_rate_limited`, which touches
//! only `HealthTracker::record_success` — the circuit breaker never sees the
//! call.

use std::collections::HashMap;
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{Value, json};

use mcp_gateway::backend::Backend;
use mcp_gateway::config::{
    BackendConfig, CircuitBreakerConfig, FailsafeConfig, RetryConfig, TransportConfig,
};

/// A mock Streamable HTTP backend that answers the handshake normally and
/// every `tools/call` with a bare HTTP 429 — no JSON-RPC envelope, matching
/// what a real rate-limiting proxy in front of an MCP backend sends.
async fn mcp_handler(State(()): State<()>, Json(body): Json<Value>) -> Response {
    let id = body.get("id").cloned().unwrap_or(Value::Null);
    match body
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default()
    {
        "initialize" => Json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": body["params"]["protocolVersion"],
                "capabilities": {},
                "serverInfo": {"name": "mock-429", "version": "0"}
            }
        }))
        .into_response(),
        // Every tools/call is throttled — no retries needed to reach the
        // production classification, so the test disables retry (see
        // `backend_for`) and still exercises the real dispatch path.
        _ => (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response(),
    }
}

async fn start_mock() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let app = Router::new()
        .route("/mcp", post(mcp_handler))
        .with_state(());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}/mcp")
}

fn backend_for(url: &str) -> Backend {
    let config = BackendConfig {
        description: "429-only mock".to_string(),
        enabled: true,
        transport: TransportConfig::Http {
            http_url: url.to_string(),
            streamable_http: true,
            protocol_version: None,
        },
        stop_when_idle_for: None,
        timeout: Duration::from_secs(10),
        env: HashMap::default(),
        headers: HashMap::default(),
        oauth: None,
        secrets: Vec::new(),
        passthrough: false,
        allow_cleartext_credentials: false,
        runtime_profile: None,
        identity_propagation: None,
    };
    let failsafe = FailsafeConfig {
        circuit_breaker: CircuitBreakerConfig {
            enabled: true,
            ..CircuitBreakerConfig::default()
        },
        // Retry would re-drive the same 429 through the mock several times
        // per call, which does not change what is being proven (the failsafe
        // recording layer runs once on the final dispatch result) and only
        // adds latency to the test.
        retry: RetryConfig {
            enabled: false,
            ..RetryConfig::default()
        },
        ..FailsafeConfig::default()
    };
    Backend::new("rl9-mock", config, &failsafe, Duration::from_secs(300))
}

/// Comfortably past the circuit breaker's default `failure_threshold` (5)
/// and `HealthTracker`'s hardcoded unhealthy flip at 3 consecutive failures —
/// either mechanism tripping would show here.
const ATTEMPTS: usize = 10;

#[tokio::test]
async fn a_429_only_backend_neither_opens_its_circuit_nor_exhausts_its_health_budget() {
    let url = start_mock().await;
    let backend = backend_for(&url);

    for n in 0..ATTEMPTS {
        let result = backend
            .request(
                "tools/call",
                Some(json!({"name": "anything", "arguments": {}})),
            )
            .await;
        assert!(
            result.is_err(),
            "attempt {n}: mock always answers 429, so the request must surface as an error"
        );
    }

    assert!(
        !backend.is_circuit_tripped(),
        "a run of {ATTEMPTS} rate-limited responses must not open the circuit breaker \
         (production: record_dispatch_failure routes a 429 to record_rate_limited, \
         never record_failure — src/failsafe/mod.rs)"
    );

    let health = backend.health_metrics();
    assert!(
        health.healthy,
        "HealthTracker must still report healthy after {ATTEMPTS} 429s: a rate-limited \
         response is recorded as a health success, not a failure (src/failsafe/health.rs)"
    );
    assert_eq!(
        health.failure_count, 0,
        "no 429 in this run may be counted as a health failure"
    );
    assert_eq!(
        health.consecutive_failures, 0,
        "the consecutive-failure streak (hardcoded unhealthy flip at 3) must stay at 0"
    );
    assert_eq!(
        health.success_count, ATTEMPTS as u64,
        "record_rate_limited absorbs a 429 into HealthTracker::record_success, so every \
         attempt in this run should count as a health success"
    );

    let stats = backend.circuit_breaker_stats();
    assert_eq!(
        stats.current_failures, 0,
        "the circuit breaker's own consecutive-failure counter must never be touched by a 429"
    );
    assert_eq!(
        stats.trips_count, 0,
        "the circuit breaker must never have tripped"
    );
}
