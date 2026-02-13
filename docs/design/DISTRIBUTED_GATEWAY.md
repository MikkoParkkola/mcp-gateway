# Distributed Gateway Design

**Issue**: [#47 - Distributed Gateway with Circuit Breakers + Tracing](https://github.com/MikkoParkkola/mcp-gateway/issues/47)
**Status**: Draft
**Author**: rust-excellence-engineer
**Date**: 2026-02-13

---

## Problem Statement

The current `mcp-gateway` runs as a single process with in-memory state for circuit breakers, rate limiters, health tracking, and tool caches. This works well for single-user/single-machine deployments but prevents:

1. **Horizontal scaling** -- multiple gateway instances cannot share failsafe state
2. **High availability** -- single process failure loses all accumulated health data
3. **Observability** -- no distributed tracing across gateway-to-backend call chains
4. **Intelligent routing** -- no cross-instance awareness of backend health or capacity

## Current Architecture (Baseline)

```
                     ┌─────────────────────────────────────┐
                     │         mcp-gateway (single)        │
                     │                                     │
   Client ──POST──>  │  Router ──> BackendRegistry         │
                     │              ├── Backend A           │
                     │              │   ├── Failsafe        │
                     │              │   │   ├── CircuitBreaker (in-memory)
                     │              │   │   ├── RateLimiter  (governor, in-memory)
                     │              │   │   ├── HealthTracker (atomics)
                     │              │   │   └── RetryPolicy  │
                     │              │   └── Transport        │
                     │              └── Backend B           │
                     │                  └── ...             │
                     └─────────────────────────────────────┘
```

Key in-memory structures (from `src/failsafe/`):

| Component | State | Current Storage |
|-----------|-------|-----------------|
| `CircuitBreaker` | `CircuitState` enum, failure/success counters, last state change timestamp | `RwLock<CircuitState>`, `AtomicU32`, `AtomicU64` |
| `RateLimiter` | Token bucket state | `governor::RateLimiter` (in-memory) |
| `HealthTracker` | Success/failure counts, consecutive failures, latency histogram | `AtomicU64`, `AtomicBool`, `RwLock<LatencyHistogram>` |
| `RetryPolicy` | Stateless (config only) | N/A (no shared state needed) |

## Proposed Architecture

### Phase 1: Shared State Backend

Introduce an optional shared state layer behind a trait abstraction, allowing multiple gateway instances to coordinate.

```
   Client A ──>  ┌──────────────┐     ┌─────────────────┐
                 │ Gateway #1   │────>│                 │
   Client B ──>  │              │     │  Shared State   │──> MCP Backends
                 └──────────────┘     │  (Redis/etcd)   │
   Client C ──>  ┌──────────────┐     │                 │
                 │ Gateway #2   │────>│  - CB state     │
   Client D ──>  │              │     │  - Rate limits  │
                 └──────────────┘     │  - Health data  │
                                      │  - Tool cache   │
                                      └─────────────────┘
```

### State Store Trait

```rust
/// Trait for distributed state storage.
///
/// Implementations must be `Send + Sync + 'static` for use across
/// async tasks and gateway instances.
#[async_trait]
pub trait StateStore: Send + Sync + 'static {
    // Circuit breaker operations
    async fn get_circuit_state(&self, backend: &str) -> Result<CircuitState>;
    async fn set_circuit_state(&self, backend: &str, state: CircuitState) -> Result<()>;
    async fn increment_failures(&self, backend: &str) -> Result<u32>;
    async fn increment_successes(&self, backend: &str) -> Result<u32>;
    async fn reset_counters(&self, backend: &str) -> Result<()>;

    // Rate limiting (distributed token bucket)
    async fn try_acquire_rate_limit(&self, key: &str, rps: u32, burst: u32) -> Result<bool>;

    // Health metrics
    async fn record_health_event(&self, backend: &str, event: HealthEvent) -> Result<()>;
    async fn get_health_metrics(&self, backend: &str) -> Result<HealthMetrics>;

    // Tool cache (shared across instances)
    async fn get_cached_tools(&self, backend: &str) -> Result<Option<Vec<Tool>>>;
    async fn set_cached_tools(&self, backend: &str, tools: &[Tool], ttl: Duration) -> Result<()>;
}
```

### Implementation Options

#### Option A: Redis (Recommended for most deployments)

**Pros**: Battle-tested, low latency (~1ms), built-in TTL, Lua scripting for atomic operations, pub/sub for state change notifications.

**Cons**: Additional infrastructure dependency, no strong consistency guarantees (eventual consistency in cluster mode).

```rust
pub struct RedisStateStore {
    pool: deadpool_redis::Pool,
    prefix: String, // namespace keys, e.g., "mcpgw:"
}
```

Key schema:

| Key Pattern | Type | TTL | Purpose |
|-------------|------|-----|---------|
| `mcpgw:cb:{backend}:state` | String (enum ordinal) | None | Circuit breaker state |
| `mcpgw:cb:{backend}:failures` | Counter | Reset on state change | Failure count |
| `mcpgw:cb:{backend}:successes` | Counter | Reset on state change | Success count (half-open) |
| `mcpgw:cb:{backend}:last_change` | String (epoch ms) | None | Last state transition |
| `mcpgw:rl:{key}` | Token bucket (Lua) | Auto | Rate limiter state |
| `mcpgw:health:{backend}` | Hash | None | Health counters and timestamps |
| `mcpgw:health:{backend}:latencies` | Sorted set | Rolling window | Latency samples |
| `mcpgw:tools:{backend}` | String (JSON) | Configurable | Cached tool list |

Rate limiting via Lua script (atomic token bucket):

```lua
-- KEYS[1] = rate limit key
-- ARGV[1] = max tokens, ARGV[2] = refill rate, ARGV[3] = now (ms)
local tokens = tonumber(redis.call('get', KEYS[1]) or ARGV[1])
local last = tonumber(redis.call('get', KEYS[1]..':ts') or ARGV[3])
local now = tonumber(ARGV[3])
local rate = tonumber(ARGV[2])
local max = tonumber(ARGV[1])

-- Refill tokens
local elapsed = (now - last) / 1000.0
tokens = math.min(max, tokens + elapsed * rate)

if tokens >= 1 then
    tokens = tokens - 1
    redis.call('set', KEYS[1], tokens)
    redis.call('set', KEYS[1]..':ts', now)
    return 1  -- allowed
else
    redis.call('set', KEYS[1], tokens)
    redis.call('set', KEYS[1]..':ts', now)
    return 0  -- denied
end
```

#### Option B: etcd (For strong consistency requirements)

**Pros**: Strong consistency (Raft), built-in watch/notify, lease-based TTL.

**Cons**: Higher latency (~5-10ms), more complex operations, less suitable for high-frequency rate limiting.

Best for: Deployments already running Kubernetes (etcd available), or when strong consistency of circuit breaker state is critical.

#### Option C: In-Memory (Default, current behavior)

```rust
pub struct InMemoryStateStore {
    // Wraps current AtomicU32/AtomicU64/RwLock state
    // Zero additional dependencies
    // Single-instance only
}
```

### Recommendation

Use **Redis** as the primary distributed backend with **in-memory as the default** fallback. The `StateStore` trait allows swapping implementations via configuration:

```yaml
# gateway.yaml
distributed:
  enabled: false  # default: single-instance mode (in-memory)
  # enabled: true
  # backend: redis
  # redis:
  #   url: "redis://localhost:6379"
  #   prefix: "mcpgw:"
  #   pool_size: 8
  #   connect_timeout: 5s
```

---

## Enhanced Circuit Breakers

The current circuit breaker in `src/failsafe/circuit_breaker.rs` already implements the three-state model (Closed/Open/HalfOpen). Enhancements for distributed operation:

### 1. Configurable Thresholds Per Backend

Currently, all backends share the global `FailsafeConfig`. Allow per-backend overrides:

```yaml
failsafe:
  circuit_breaker:
    failure_threshold: 5
    success_threshold: 3
    reset_timeout: 30s

backends:
  fragile-backend:
    command: "npx fragile-server"
    failsafe:
      circuit_breaker:
        failure_threshold: 2    # Lower tolerance
        reset_timeout: 60s      # Longer cooldown

  resilient-backend:
    command: "npx resilient-server"
    failsafe:
      circuit_breaker:
        failure_threshold: 20   # Higher tolerance
        reset_timeout: 10s      # Quick recovery
```

### 2. Sliding Window Failure Detection

Replace the current simple counter with a sliding window to avoid penalizing backends for old failures:

```rust
/// Sliding window circuit breaker configuration
pub struct SlidingWindowConfig {
    /// Window duration for counting failures
    pub window: Duration,            // e.g., 60s
    /// Failure rate threshold (0.0 to 1.0) within window
    pub failure_rate_threshold: f64, // e.g., 0.5 = 50% failure rate
    /// Minimum number of calls before evaluating
    pub min_calls: u32,              // e.g., 10
    /// Success threshold to close from half-open
    pub success_threshold: u32,
    /// Time to wait in open state before half-open
    pub reset_timeout: Duration,
}
```

This prevents a backend from staying open because of 5 failures that happened 30 minutes ago while the last 1000 requests succeeded.

### 3. Half-Open Probe Limiting

Current behavior allows all requests through in half-open state. Add a probe limiter:

```rust
/// In half-open state, allow only N concurrent probe requests.
/// Additional requests receive CircuitOpen error until probes resolve.
pub struct HalfOpenConfig {
    /// Maximum concurrent probe requests
    pub max_probes: u32,  // default: 1
    /// Timeout for probe requests
    pub probe_timeout: Duration,
}
```

### 4. State Change Notifications

When running distributed, state changes should propagate to all instances:

```rust
/// Emitted when circuit breaker state changes.
/// In distributed mode, published via Redis pub/sub or etcd watch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitStateChange {
    pub backend: String,
    pub from: CircuitState,
    pub to: CircuitState,
    pub instance_id: String,
    pub timestamp: u64,
    pub reason: String, // e.g., "failure_threshold_reached", "reset_timeout_elapsed"
}
```

---

## Distributed Tracing (OpenTelemetry)

### Integration Points

```
Client Request
    │
    ▼
┌─ Gateway Span ─────────────────────────────────────┐
│  trace_id: abc123                                   │
│  span: gateway.request                              │
│                                                     │
│  ┌─ Auth Span ───────────┐                          │
│  │  span: gateway.auth   │                          │
│  └───────────────────────┘                          │
│                                                     │
│  ┌─ Route Span ──────────────────────────────────┐  │
│  │  span: gateway.route                          │  │
│  │                                               │  │
│  │  ┌─ Failsafe Span ────────────────────────┐   │  │
│  │  │  span: failsafe.check                 │   │  │
│  │  │  cb.state: closed                      │   │  │
│  │  │  rl.allowed: true                      │   │  │
│  │  └────────────────────────────────────────┘   │  │
│  │                                               │  │
│  │  ┌─ Backend Span ─────────────────────────┐   │  │
│  │  │  span: backend.{name}.request          │   │  │
│  │  │  backend.name: tavily                  │   │  │
│  │  │  rpc.method: tools/call                │   │  │
│  │  │  rpc.tool: tavily-search               │   │  │
│  │  │                                        │   │  │
│  │  │  ┌─ Transport Span ─────────────────┐  │   │  │
│  │  │  │  span: transport.http.request    │  │   │  │
│  │  │  │  http.method: POST               │  │   │  │
│  │  │  │  http.url: https://...           │  │   │  │
│  │  │  │  http.status_code: 200           │  │   │  │
│  │  │  └──────────────────────────────────┘  │   │  │
│  │  └────────────────────────────────────────┘   │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

### Span Attributes

| Span | Key Attributes |
|------|---------------|
| `gateway.request` | `http.method`, `http.route`, `http.status_code`, `client.name`, `mcp.session_id` |
| `gateway.auth` | `auth.method` (bearer/api_key/public), `auth.client`, `auth.rate_limited` |
| `failsafe.check` | `cb.state`, `cb.failures`, `rl.allowed`, `rl.rps` |
| `backend.{name}.request` | `backend.name`, `rpc.method`, `rpc.tool`, `backend.transport` (stdio/http) |
| `transport.{type}.request` | Protocol-specific: HTTP status, stdio exit code, response size |
| `retry.attempt` | `retry.attempt_number`, `retry.delay_ms`, `retry.error` |

### Implementation Approach

Use the `tracing` crate (already a dependency) with `tracing-opentelemetry` bridge:

```rust
// In Cargo.toml (new dependencies)
// opentelemetry = "0.28"
// opentelemetry-otlp = "0.28"
// tracing-opentelemetry = "0.28"

// In gateway startup
fn init_tracing(config: &TracingConfig) -> Result<()> {
    if config.otlp_enabled {
        let tracer = opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(
                opentelemetry_otlp::new_exporter()
                    .tonic()
                    .with_endpoint(&config.otlp_endpoint),
            )
            .install_batch(opentelemetry_sdk::runtime::Tokio)?;

        let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);
        // Add to existing tracing subscriber
    }
    Ok(())
}
```

### Configuration

```yaml
tracing:
  # OpenTelemetry export
  otlp:
    enabled: false
    endpoint: "http://localhost:4317"  # gRPC endpoint (Jaeger/Tempo)
    service_name: "mcp-gateway"
    # Sampling: 1.0 = all traces, 0.1 = 10% of traces
    sampling_ratio: 1.0

  # Propagation: inject trace context into backend requests
  propagation:
    enabled: true
    # W3C Trace Context headers (traceparent, tracestate)
    format: w3c
```

### Trace ID Propagation

For HTTP backends, inject W3C `traceparent` header into outbound requests:

```rust
// In HttpTransport::send_request
if let Some(context) = tracing::Span::current().context() {
    let mut injector = HeaderInjector(&mut headers);
    opentelemetry::global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&context, &mut injector);
    });
}
```

For stdio backends, trace context can be passed as JSON-RPC extension params if the backend supports it, or logged for correlation.

---

## Request Routing Strategies

When multiple gateway instances front the same backend pool, or when a single gateway has multiple backends providing overlapping capabilities:

### Strategy 1: Round-Robin (Default)

Simple, stateless rotation across healthy backends.

```rust
pub struct RoundRobinRouter {
    index: AtomicUsize,
}

impl Router for RoundRobinRouter {
    fn select<'a>(&self, candidates: &'a [&Backend]) -> &'a Backend {
        let idx = self.index.fetch_add(1, Ordering::Relaxed) % candidates.len();
        candidates[idx]
    }
}
```

### Strategy 2: Least-Connections

Route to the backend with fewest in-flight requests. Uses the existing `Semaphore` in `Backend`.

```rust
pub struct LeastConnectionsRouter;

impl Router for LeastConnectionsRouter {
    fn select<'a>(&self, candidates: &'a [&Backend]) -> &'a Backend {
        candidates
            .iter()
            .min_by_key(|b| b.active_requests())
            .unwrap()
    }
}
```

### Strategy 3: Capability-Aware (Unique to MCP)

Route based on which backends actually provide the requested tool:

```rust
pub struct CapabilityAwareRouter;

impl Router for CapabilityAwareRouter {
    fn select_for_tool<'a>(
        &self,
        tool_name: &str,
        candidates: &'a [&Backend],
    ) -> Option<&'a Backend> {
        // 1. Filter to backends that have this tool
        let capable: Vec<_> = candidates
            .iter()
            .filter(|b| b.has_tool(tool_name))
            .collect();

        if capable.is_empty() {
            return None;
        }

        // 2. Among capable backends, prefer:
        //    a) Healthy over degraded
        //    b) Lower latency (p50)
        //    c) Lower current load
        capable
            .iter()
            .filter(|b| b.failsafe.health_tracker.is_healthy())
            .min_by_key(|b| {
                let metrics = b.failsafe.health_metrics();
                metrics.latency_p50_ms.unwrap_or(u64::MAX)
            })
            .or_else(|| capable.first())
            .copied()
    }
}
```

### Strategy 4: Weighted (For heterogeneous backends)

Assign weights based on backend capacity. Configured per-backend:

```yaml
backends:
  fast-server:
    command: "fast-mcp-server"
    routing:
      weight: 10   # Gets 10x more traffic

  slow-server:
    command: "slow-mcp-server"
    routing:
      weight: 1
```

### Router Configuration

```yaml
routing:
  strategy: round-robin  # round-robin | least-connections | capability-aware | weighted
  # Health-aware: automatically exclude unhealthy backends regardless of strategy
  health_aware: true
  # Sticky sessions: route same client to same backend (optional)
  sticky: false
```

---

## Migration Path: Single to Distributed

### Phase 0: Current (v0.x) -- Single Instance

No changes needed. In-memory state store is the default.

### Phase 1: State Store Abstraction

1. Extract `StateStore` trait from current in-memory implementations
2. Implement `InMemoryStateStore` wrapping existing `AtomicU32`/`RwLock` state
3. Refactor `Failsafe` to accept `Arc<dyn StateStore>` instead of owning state directly
4. All existing tests continue to pass with `InMemoryStateStore`
5. **Zero behavioral change for existing users**

Estimated scope: ~400 lines changed in `src/failsafe/`, ~200 lines new trait + in-memory impl.

### Phase 2: Redis State Store

1. Add `redis` feature flag to `Cargo.toml`
2. Implement `RedisStateStore` behind feature gate
3. Add `distributed` config section
4. Integration tests with testcontainers (Redis)
5. Documentation for multi-instance deployment

### Phase 3: OpenTelemetry Integration

1. Add `tracing` feature flag (opt-in to avoid dependency bloat)
2. Wire `tracing-opentelemetry` into existing `tracing` spans
3. Add span attributes at each integration point
4. Test with local Jaeger instance

### Phase 4: Advanced Routing

1. Implement `Router` trait
2. Add routing strategies behind `routing.strategy` config
3. Capability-aware routing leverages existing tool cache

### Phase 5: Multi-Instance Deployment

1. Docker Compose example with 2 gateways + Redis
2. Kubernetes Helm chart with horizontal pod autoscaler
3. Health endpoint aggregation across instances
4. Load balancer configuration guide

---

## Configuration Reference (Complete)

```yaml
# Full distributed gateway configuration
distributed:
  enabled: false
  backend: redis   # redis | etcd | memory

  redis:
    url: "redis://localhost:6379"
    prefix: "mcpgw:"
    pool_size: 8
    connect_timeout: 5s
    command_timeout: 2s

  etcd:
    endpoints: ["http://localhost:2379"]
    prefix: "/mcpgw/"
    connect_timeout: 5s

tracing:
  otlp:
    enabled: false
    endpoint: "http://localhost:4317"
    service_name: "mcp-gateway"
    sampling_ratio: 1.0
  propagation:
    enabled: true
    format: w3c

routing:
  strategy: round-robin
  health_aware: true
  sticky: false

failsafe:
  circuit_breaker:
    enabled: true
    # Simple threshold mode (current)
    failure_threshold: 5
    success_threshold: 3
    reset_timeout: 30s
    # Sliding window mode (new, optional)
    # window: 60s
    # failure_rate_threshold: 0.5
    # min_calls: 10
    half_open:
      max_probes: 1
      probe_timeout: 10s
```

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Redis unavailability | Medium | High (all circuit breakers reset) | Fall back to in-memory on connection loss |
| State store latency overhead | Low | Medium (adds ~1ms per request) | Local caching with async sync |
| Split-brain in distributed CB | Low | Medium (inconsistent open/closed) | Accept eventual consistency; safety bias (prefer open) |
| Complexity for single-instance users | High | Low | Feature-gated, disabled by default |
| Migration breaks existing configs | Low | High | All new config is additive, defaults match current behavior |

## Non-Goals

- **Multi-region replication** -- out of scope; single-region cluster is sufficient
- **Custom routing plugins** -- the trait abstraction allows future extension but no plugin system yet
- **Distributed request queuing** -- requests are still synchronous; no message broker integration
- **Consensus-based leader election** -- all gateway instances are equal peers

## Open Questions

1. Should the distributed circuit breaker bias toward "open" (safe) or "closed" (available) when state store is unreachable?
2. Should tool cache invalidation be push (pub/sub) or pull (TTL-based)?
3. Is etcd support worth the implementation cost given Redis covers most use cases?

---

## References

- Current circuit breaker: `src/failsafe/circuit_breaker.rs`
- Current health tracker: `src/failsafe/health.rs`
- Current rate limiter: `src/failsafe/rate_limiter.rs`
- Current config: `src/config.rs` (`FailsafeConfig`, `CircuitBreakerConfig`)
- Issue: [#47](https://github.com/MikkoParkkola/mcp-gateway/issues/47)
- OpenClaw Gateway (inspiration): WebSocket-based session/channel/tool/event control plane
- Martin Fowler - Circuit Breaker pattern
- OpenTelemetry Rust SDK: https://opentelemetry.io/docs/languages/rust/
