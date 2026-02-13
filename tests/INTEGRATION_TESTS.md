# Integration Tests for MCP Gateway

This document describes the integration tests for the new MCP Gateway features introduced in version 2.0.0.

## Overview

The integration tests verify 5 key features:

1. **Stats meta-tool** (`gateway_get_stats`)
2. **Search tools with ranking** (`gateway_search_tools`)
3. **Response caching** (`gateway_invoke` with cache)
4. **List servers** (`gateway_list_servers`)
5. **CLI commands** (`mcp-gateway cap registry-list`)

## Prerequisites

### 1. Build the Gateway

```bash
cargo build --release
```

### 2. Start the Gateway

```bash
./target/release/mcp-gateway
```

The gateway should be running on `http://localhost:39400` (default port).

### 3. Verify Gateway is Running

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | xh POST http://localhost:39400/mcp
```

You should see a successful JSON-RPC response with the list of meta-tools.

## Running Tests

### Run All Integration Tests

```bash
cargo test --test integration_tests -- --ignored
```

**Note**: Tests are marked with `#[ignore]` by default because they require the gateway to be running.

### Run Individual Tests

```bash
# Test 1: Stats meta-tool
cargo test --test integration_tests test_gateway_get_stats -- --ignored --nocapture

# Test 2: Search tools
cargo test --test integration_tests test_gateway_search_tools -- --ignored --nocapture

# Test 3: Caching
cargo test --test integration_tests test_invoke_caching -- --ignored --nocapture

# Test 4: List servers
cargo test --test integration_tests test_gateway_list_servers -- --ignored --nocapture

# Test 5: CLI commands
cargo test --test integration_tests test_cap_registry_list -- --ignored --nocapture

# Test 6: Integration flow (combines multiple features)
cargo test --test integration_tests test_gateway_integration_flow -- --ignored --nocapture
```

### Skip Gateway-Required Tests

If the gateway is not running, tests will gracefully skip with a warning:

```
⚠️  Gateway not running on http://localhost:39400/mcp, skipping test
```

## Test Descriptions

### 1. `test_gateway_get_stats`

**Purpose**: Verify the stats meta-tool returns usage statistics.

**What it tests**:
- Calls `gateway_get_stats` via MCP JSON-RPC
- Verifies response contains: `invocations`, `cache_hits`, `tokens_saved`, `top_tools`, `cache_hit_rate`, `tools_discovered`, `tools_available`, `estimated_savings_usd`
- Validates field types (numbers, arrays, strings)

**Expected output**:
```json
{
  "invocations": 42,
  "cache_hits": 12,
  "cache_hit_rate": "28.6%",
  "tokens_saved": 123456,
  "estimated_savings_usd": "$1.85",
  "tools_discovered": 15,
  "tools_available": 20,
  "top_tools": [...]
}
```

### 2. `test_gateway_search_tools`

**Purpose**: Verify tool search with keyword ranking.

**What it tests**:
- Searches for "weather" tools
- Verifies each result has: `server`, `tool`, `description`
- Optional `score` field if ranking is enabled
- Validates result structure and types

**Expected output**:
```json
{
  "query": "weather",
  "matches": [
    {
      "server": "capabilities",
      "tool": "weather_current",
      "description": "Get current weather...",
      "score": 0.95
    }
  ],
  "total": 1
}
```

### 3. `test_invoke_caching`

**Purpose**: Verify response caching works correctly.

**What it tests**:
- Makes the same tool call twice
- Verifies cache hits increase after second call
- Compares execution times (cached should be faster)
- Uses `weather_current` capability as test target

**Expected behavior**:
- First call: Cache miss, normal execution time
- Second call: Cache hit, faster execution
- `cache_hits` stat increases by at least 1

### 4. `test_gateway_list_servers`

**Purpose**: Verify server listing functionality.

**What it tests**:
- Calls `gateway_list_servers`
- Verifies at least one server is returned (capabilities backend always present)
- Each server has: `name`, `running`, `transport`, `tools_count`, `circuit_state`
- Validates field types

**Expected output**:
```json
{
  "servers": [
    {
      "name": "capabilities",
      "running": true,
      "transport": "capability",
      "tools_count": 8,
      "circuit_state": "Closed"
    }
  ]
}
```

### 5. `test_cap_registry_list`

**Purpose**: Verify CLI commands work correctly.

**What it tests**:
- Executes `mcp-gateway cap registry-list`
- Verifies output contains all capabilities from `registry/index.json`
- Expected capabilities: `stripe_list_charges`, `yahoo_stock_quote`, `ecb_exchange_rates`, `gmail_send_email`, `slack_post_message`, `weather_current`, `wikipedia_search`, `github_create_issue`

**Expected output** (example):
```
Available capabilities in registry:

Finance:
  - stripe_list_charges: List Stripe charges with pagination and filtering
  - yahoo_stock_quote: Get real-time stock quotes from Yahoo Finance
  - ecb_exchange_rates: Get ECB foreign exchange rates

Communication:
  - gmail_send_email: Send email via Gmail API
  - slack_post_message: Post message to Slack channel

Productivity:
  - weather_current: Get current weather using OpenMeteo API
  - wikipedia_search: Search Wikipedia articles
  - github_create_issue: Create a GitHub issue

Total: 8 capabilities
```

### 6. `test_gateway_integration_flow`

**Purpose**: Verify multiple features work together in a realistic workflow.

**What it tests**:
- Lists servers
- Searches for tools
- Gets stats
- Verifies stats reflect the operations performed

**Expected behavior**:
- All operations succeed
- Stats show increasing invocation counts
- Search results are consistent with available tools

## Troubleshooting

### Gateway Not Running

**Error**: `Connection refused (os error 61)`

**Solution**: Start the gateway before running tests:
```bash
./target/release/mcp-gateway
```

### Binary Not Found (CLI test)

**Error**: `⚠️  mcp-gateway binary not found, skipping CLI test`

**Solution**: Build the gateway:
```bash
cargo build --release
```

### Port Already in Use

**Error**: `Address already in use`

**Solution**: Either:
1. Kill the existing process using port 39400
2. Configure a different port in `config.yaml`

### Tests Timing Out

If tests are slow or timing out, verify:
1. Gateway is healthy: `xh GET http://localhost:39400/health`
2. No network issues blocking localhost connections
3. Sufficient system resources

## Test Architecture

### JSON-RPC Communication

Tests use the MCP JSON-RPC protocol over HTTP:

```rust
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "gateway_get_stats",
    "arguments": {}
  }
}
```

### Response Parsing

MCP wraps tool responses in `result.content[0].text` as a JSON string:

```rust
fn parse_tool_response(response: &Value) -> Result<Value, String> {
    let content_text = response
        .get("result")
        .and_then(|r| r.get("content"))
        .and_then(|c| c.get(0))
        .and_then(|item| item.get("text"))
        .and_then(|t| t.as_str())
        .ok_or("Missing content.text in response")?;

    serde_json::from_str(content_text)
        .map_err(|e| format!("Failed to parse content JSON: {e}"))
}
```

### Graceful Skipping

Tests check if the gateway is running before executing:

```rust
async fn is_gateway_running() -> bool {
    let client = Client::new();
    client
        .post(GATEWAY_URL)
        .json(&JsonRpcRequest::new("tools/list", json!({})))
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .is_ok()
}
```

## CI/CD Integration

To run these tests in CI/CD pipelines:

1. Start the gateway in the background
2. Wait for health check to pass
3. Run tests
4. Stop the gateway

Example GitHub Actions workflow:

```yaml
- name: Start Gateway
  run: |
    ./target/release/mcp-gateway &
    sleep 2
    curl --retry 10 --retry-delay 1 --retry-connrefused http://localhost:39400/health

- name: Run Integration Tests
  run: cargo test --test integration_tests -- --ignored

- name: Stop Gateway
  run: pkill mcp-gateway
```

## Performance Benchmarks

Expected test execution times (with gateway running):

| Test | Expected Duration |
|------|-------------------|
| `test_gateway_get_stats` | <100ms |
| `test_gateway_search_tools` | <200ms |
| `test_invoke_caching` | <500ms (includes cache warmup) |
| `test_gateway_list_servers` | <100ms |
| `test_cap_registry_list` | <50ms (CLI only) |
| `test_gateway_integration_flow` | <500ms |

Total suite: **<2 seconds**

## Coverage

These integration tests provide coverage for:

- ✅ Meta-tool functionality (stats, search, list, invoke)
- ✅ Response caching with TTL
- ✅ Search ranking based on usage
- ✅ Server discovery across backends
- ✅ CLI commands for capability management
- ✅ JSON-RPC protocol compliance
- ✅ Error handling and graceful degradation

## Future Enhancements

Potential additions to the test suite:

1. **Load testing**: Concurrent requests, cache contention
2. **Cache eviction**: Test TTL expiration, cache invalidation
3. **Ranking accuracy**: Verify usage-based ranking is correct
4. **Error scenarios**: Test circuit breaker, retry logic, timeout handling
5. **Multi-backend**: Test with multiple MCP backends running
6. **Capability execution**: Test actual capability calls (requires API keys)
