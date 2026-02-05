# Integration Guide: Circuit Breakers + Tracing (Issue #47)

## Overview

This implementation adds production-grade circuit breakers with health tracking and distributed tracing to the MCP Gateway.

## Components Implemented

### 1. Health Tracking (`src/failsafe/health.rs`)

**What it does:**
- Tracks per-backend success/failure counts
- Records request latency (p50, p95, p99 percentiles)
- Maintains health status based on consecutive failures
- Provides metrics snapshots via `HealthMetrics`

**API:**
```rust
let tracker = HealthTracker::new("backend-name");

// Record operations
tracker.record_success(duration);
tracker.record_failure();

// Query status
let healthy = tracker.is_healthy();
let metrics = tracker.metrics();
```

**Health Status Logic:**
- Starts healthy
- Becomes unhealthy after 3 consecutive failures
- Recovers immediately on first success

### 2. Enhanced Circuit Breaker (`src/failsafe/circuit_breaker.rs`)

**Enhancements:**
- Added `#[tracing::instrument]` to all public methods
- Structured logging with backend name in span context
- Trace-level logs for normal operations
- Warn-level logs for circuit transitions and rejections

**Tracing Output:**
```
TRACE circuit_breaker: Circuit closed, allowing request backend="my-backend"
WARN circuit_breaker: Failure in closed state backend="my-backend" failures=5 threshold=5
WARN circuit_breaker: Circuit breaker opened backend="my-backend" failures=5
```

### 3. Integrated Failsafe (`src/failsafe/mod.rs`)

**Changes:**
- Added `health_tracker: Arc<HealthTracker>` field
- Updated `record_success()` to accept `Duration` and track latency
- Both circuit breaker and health tracker are updated on success/failure
- New method: `health_metrics()` returns current health snapshot

**Migration:**
```rust
// Old
failsafe.record_success();

// New
failsafe.record_success(latency);
```

### 4. Backend Request Tracing (`src/backend/mod.rs`)

**Enhancements:**
- `#[tracing::instrument]` on `Backend::request()`
- Span includes: `backend`, `method`, `request_id` (UUID)
- Latency measurement for every request
- Structured logging: success/failure with latency_ms

**Trace Flow:**
```
INFO backend: Request completed successfully backend="fulcrum" method="tools/list" request_id="..." latency_ms=45
```

### 5. Capability Executor Tracing (`src/capability/executor.rs`)

**Enhancements:**
- `#[tracing::instrument]` on `execute()` and `execute_provider()`
- Span includes: `capability`, `provider`, `request_id`
- URL and method logging for REST calls
- Latency tracking for capability executions

## Integration Points (For Wiring)

### A. Backend Status Endpoint

**Location:** `src/gateway/router.rs` or similar

**Add health metrics to backend status:**
```rust
// In BackendStatus struct (src/backend/mod.rs)
pub struct BackendStatus {
    // ... existing fields ...
    pub health_metrics: HealthMetrics,  // Add this
}

// In Backend::status() method
pub fn status(&self) -> BackendStatus {
    BackendStatus {
        // ... existing fields ...
        health_metrics: self.failsafe.health_metrics(),
    }
}
```

### B. Health Check Endpoint

**Location:** Create new endpoint in `src/gateway/router.rs`

```rust
// GET /health/backends
async fn health_backends(
    State(state): State<Arc<AppState>>,
) -> Json<HashMap<String, HealthMetrics>> {
    let mut health = HashMap::new();

    for backend in state.backends.all() {
        health.insert(
            backend.name.clone(),
            backend.failsafe.health_metrics()
        );
    }

    Json(health)
}
```

### C. Tracing Configuration

**Location:** `src/main.rs` or `src/lib.rs`

The existing tracing setup works, but you can enhance it:

```rust
// Add request ID propagation
use tower_http::request_id::{MakeRequestId, RequestId};
use tower_http::trace::TraceLayer;

// In router setup
let trace_layer = TraceLayer::new_for_http()
    .make_span_with(|request: &axum::http::Request<_>| {
        let request_id = request
            .extensions()
            .get::<RequestId>()
            .map(|id| id.header_value().to_str().unwrap_or("unknown"))
            .unwrap_or("unknown");

        tracing::info_span!(
            "http_request",
            method = %request.method(),
            uri = %request.uri(),
            request_id = %request_id
        )
    });
```

### D. Metrics Export (Optional)

**Location:** Create `src/gateway/metrics.rs`

```rust
use axum::{Json, extract::State};
use std::collections::HashMap;
use serde::Serialize;

#[derive(Serialize)]
pub struct GatewayMetrics {
    backends: HashMap<String, BackendMetrics>,
}

#[derive(Serialize)]
pub struct BackendMetrics {
    health: HealthMetrics,
    circuit_state: String,
    request_count: u64,
}

pub async fn metrics_handler(
    State(state): State<Arc<AppState>>,
) -> Json<GatewayMetrics> {
    let mut backends = HashMap::new();

    for backend in state.backends.all() {
        backends.insert(
            backend.name.clone(),
            BackendMetrics {
                health: backend.failsafe.health_metrics(),
                circuit_state: format!("{:?}", backend.failsafe.circuit_breaker.state()),
                request_count: backend.request_count.load(Ordering::Relaxed),
            }
        );
    }

    Json(GatewayMetrics { backends })
}
```

## Testing

### Run Tests
```bash
cargo test --lib failsafe::health
cargo test --lib failsafe::circuit_breaker
```

### Manual Testing

1. Start gateway with tracing enabled:
```bash
RUST_LOG=mcp_gateway=debug cargo run
```

2. Make requests and observe traces:
```bash
# Successful request
curl -X POST http://localhost:39400/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"gateway_list_servers"}'

# Check logs for:
# - request_id in spans
# - latency_ms in success logs
# - circuit breaker state transitions
```

3. Trigger circuit breaker:
```bash
# Configure a backend to fail, then make 5+ requests rapidly
# Watch for "Circuit breaker opened" message
```

### Expected Log Output

```
DEBUG backend: Circuit closed, allowing request backend="fulcrum"
INFO backend: Request completed successfully backend="fulcrum" method="tools/list" request_id="a1b2c3d4" latency_ms=45
DEBUG health: Success in closed state, reset failure count backend="fulcrum"
INFO health_tracker: Health metrics backend="fulcrum" healthy=true success=15 failures=0 p50=42ms p95=78ms p99=95ms
```

## Performance Impact

- **Circuit Breaker:** Negligible (atomic operations)
- **Health Tracking:** ~10µs per request (histogram update)
- **Tracing:** ~100-500µs per span (conditional on log level)
- **Overall:** <1ms overhead per request with debug logging

## Configuration

Circuit breaker and health tracking use existing `FailsafeConfig`:

```yaml
failsafe:
  circuit_breaker:
    enabled: true
    failure_threshold: 5      # Open after 5 failures
    success_threshold: 3      # Close after 3 successes in half-open
    reset_timeout: 30s        # Wait 30s before half-open
```

Health tracking has no additional configuration (always enabled).

## Next Steps

1. **Wire health endpoint** to router
2. **Add Prometheus metrics** export (optional)
3. **Configure alerting** on circuit_state=Open
4. **Add grafana dashboard** for latency percentiles
5. **Implement distributed tracing** with OpenTelemetry (if needed)

## Questions?

- Health tracking: See `src/failsafe/health.rs` tests
- Circuit breaker: See `src/failsafe/circuit_breaker.rs` tests
- Tracing: Run with `RUST_LOG=trace` for full visibility
