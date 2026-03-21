# Circuit Breaker Implementation Summary

## Overview
Enhanced circuit breaker implementation for mcp-gateway with comprehensive tracing, per-backend configuration, and detailed error messages.

## Features Implemented

### 1. Per-Backend Configuration
Backends can now override global circuit breaker settings with custom values:

```yaml
backends:
  flaky-backend:
    http_url: "http://localhost:8081/mcp"
    circuit_breaker:
      enabled: true
      failure_threshold: 10    # More lenient than global
      success_threshold: 3
      reset_timeout: "60s"
```

### 2. Enhanced Tracing
All circuit breaker operations now emit structured trace events:

- `can_proceed()`: Logs decision with timing details
- `record_success()`: Tracks failure reset and half-open progression
- `record_failure()`: Logs threshold progression
- `transition_to()`: INFO/WARN/DEBUG logs for state changes

Example trace output:
```
INFO  Circuit breaker for 'backend-name' closed
WARN  Circuit breaker for 'backend-name' opened after 5 failures (reset_timeout: 30s)
DEBUG Circuit breaker half-open (testing recovery)
```

### 3. Detailed Error Messages
Circuit breaker errors now include timing information:

Before:
```
Backend unavailable: backend-name
```

After:
```
Backend 'backend-name' circuit breaker is open (5 failures in last 10 seconds, retry in 20 seconds)
```

### 4. Bug Fixes
- Fixed time calculation in `can_proceed()` that used incorrect `Instant` arithmetic
- Now uses `SystemTime` with proper epoch-based calculations
- Added `opened_at` tracking for accurate elapsed time reporting

## Configuration

### Global Failsafe Config
Default settings applied to all backends:

```yaml
failsafe:
  circuit_breaker:
    enabled: true
    failure_threshold: 5      # Open after 5 consecutive failures
    success_threshold: 2      # Close after 2 consecutive successes in half-open
    reset_timeout: "30s"      # Wait 30s before trying again
```

### Per-Backend Override
Individual backends can customize their circuit breaker:

```yaml
backends:
  critical-service:
    http_url: "http://localhost:8080/mcp"
    circuit_breaker:
      failure_threshold: 3    # Stricter - open after 3 failures
      success_threshold: 5    # Require more successes to trust
      reset_timeout: "10s"    # Quick retry for critical services
```

### Disable Per-Backend
```yaml
backends:
  testing-service:
    command: "npx -y @test/server"
    circuit_breaker:
      enabled: false          # No circuit breaker for this backend
```

## Circuit Breaker States

### Closed (Normal Operation)
- All requests flow through
- Failures increment counter
- Successes reset failure counter
- Transition to **Open** after `failure_threshold` consecutive failures

### Open (Blocking Requests)
- All requests blocked immediately with detailed error
- No backend calls made
- After `reset_timeout` passes, transition to **HalfOpen**

### HalfOpen (Testing Recovery)
- Limited requests allowed to test backend recovery
- Success increments success counter
- Any failure immediately returns to **Open**
- After `success_threshold` consecutive successes, transition to **Closed**

## Implementation Details

### Files Modified

1. **src/config.rs**
   - Added `circuit_breaker: Option<CircuitBreakerConfig>` to `BackendConfig`
   - Per-backend configuration overrides global settings

2. **src/backend/mod.rs**
   - Uses per-backend circuit breaker config if provided
   - Enhanced error messages with `status_message()`

3. **src/failsafe/mod.rs**
   - Added `new_with_cb()` constructor for custom circuit breaker config
   - Maintains backward compatibility with existing `new()`

4. **src/failsafe/circuit_breaker.rs**
   - Complete rewrite with `#[instrument]` spans on key methods
   - Added `opened_at` field for timing tracking
   - Fixed time calculation bugs
   - Added `status_message()` for user-friendly errors
   - Comprehensive structured logging

5. **tests/backend_tests.rs**
   - Updated test fixtures with new `circuit_breaker` field

6. **examples/circuit-breaker.yaml**
   - Comprehensive configuration example with comments
   - Shows global, per-backend, and disabled configurations

## Test Coverage

8 comprehensive tests covering all scenarios:

1. `test_initial_state_is_closed` - Verify initial state
2. `test_opens_after_failure_threshold` - Threshold enforcement
3. `test_resets_failures_on_success` - Success counter reset
4. `test_transitions_to_half_open_after_timeout` - Timeout recovery
5. `test_closes_after_success_threshold_in_half_open` - Recovery success
6. `test_reopens_on_failure_in_half_open` - Recovery failure
7. `test_disabled_circuit_breaker_always_allows` - Disabled mode
8. `test_status_message_includes_timing` - Error message quality

All tests pass:
```
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured
```

## Performance Characteristics

- Lock-free atomic operations for state checks
- Read locks for state inspection (no write contention)
- Write locks only during state transitions
- Zero allocation in hot path (`can_proceed`)

## Usage Example

```rust
// Create backend with custom circuit breaker
let config = BackendConfig {
    http_url: "http://backend:8080/mcp".to_string(),
    circuit_breaker: Some(CircuitBreakerConfig {
        enabled: true,
        failure_threshold: 5,
        success_threshold: 2,
        reset_timeout: Duration::from_secs(30),
    }),
    ..Default::default()
};

let backend = Backend::new("my-backend", config, &failsafe_config, cache_ttl);

// Request automatically uses circuit breaker
match backend.request("tools/list", None).await {
    Ok(response) => { /* success */ },
    Err(Error::BackendUnavailable(msg)) => {
        // msg = "Backend 'my-backend' circuit breaker is open (5 failures in last 10 seconds, retry in 20 seconds)"
        eprintln!("Circuit breaker active: {}", msg);
    },
    Err(e) => { /* other error */ }
}
```

## Tracing Integration

Enable structured tracing to see circuit breaker events:

```bash
# JSON format for production
RUST_LOG=mcp_gateway=debug mcp-gateway --log-format json

# Human-readable for development
RUST_LOG=mcp_gateway::failsafe=debug mcp-gateway
```

Example trace output:
```json
{
  "timestamp": "2025-02-05T16:45:23.123Z",
  "level": "WARN",
  "target": "mcp_gateway::failsafe::circuit_breaker",
  "fields": {
    "message": "Circuit breaker opened",
    "backend": "flaky-service",
    "from_state": "Closed",
    "failures": 5,
    "reset_timeout_secs": 30
  }
}
```

## Migration Guide

Existing configurations work unchanged - per-backend circuit breaker config is optional:

```yaml
# Before (still works)
backends:
  my-service:
    http_url: "http://localhost:8080/mcp"

# After (with per-backend config)
backends:
  my-service:
    http_url: "http://localhost:8080/mcp"
    circuit_breaker:
      failure_threshold: 10  # Override global setting
```

## References

- Issue: #47
- Branch: `feature/circuit-breakers`
- Files changed: 6 files, +358 insertions, -30 deletions
- Tests: 8 new tests, all existing tests pass
- Example config: `examples/circuit-breaker.yaml`
