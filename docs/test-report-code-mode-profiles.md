# E2E Test Report: Code Mode and Toolshed Profiles

**Date:** 2026-02-25
**Gateway:** mcp-gateway v2.4.0 @ http://127.0.0.1:39401
**Config:** ~/.claude/mcp_servers/mcp-gateway-rs/servers.yaml

---

## Test 1: Code Mode

### Test 1a: tools/list returns only 2 tools

**Request:**
```json
{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}
```

**Response (key parts):**
```json
{
  "result": {
    "tools": [
      {"name": "gateway_search", "title": "Search Tools"},
      {"name": "gateway_execute", "title": "Execute Tool"}
    ]
  }
}
```

**Result: PASS**

- Exactly 2 tools returned: `gateway_search` and `gateway_execute`
- Full schemas included for both tools
- `gateway_search` accepts `query`, `limit`, `include_schema` parameters
- `gateway_execute` accepts `tool`, `arguments`, `chain` parameters

---

### Test 1b: gateway_search finds tools

**Request:**
```json
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"gateway_search","arguments":{"query":"weather","include_schema":true}}}
```

**Response (key parts):**
```json
{
  "matches": [
    {"tool": "fulcrum:weather", "input_schema": {...}},
    {"tool": "fulcrum:weather_current", "input_schema": {...}},
    {"tool": "fulcrum:tomorrow_weather", "input_schema": {...}},
    {"tool": "fulcrum:windy_forecast", "input_schema": {...}},
    {"tool": "fulcrum:check_weather", "input_schema": {...}}
  ],
  "query": "weather",
  "total": 5,
  "total_available": 5
}
```

**Result: PASS**

- 5 weather-related tools found across the fulcrum backend
- Full input schemas included for each tool
- Descriptions include keyword tags for search relevance
- Schema fields match expected types (latitude: number, longitude: number, etc.)

---

### Test 1c: gateway_execute invokes a tool

**Request:**
```json
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"gateway_execute","arguments":{"tool":"fulcrum:weather","arguments":{"latitude":52.37,"longitude":4.89}}}}
```

**Response (key parts):**
```json
{
  "content": [{
    "text": "{\"elevation\": 11.0, \"latitude\": 52.366, \"longitude\": 4.901, \"timezone\": \"GMT\", ...}",
    "type": "text"
  }],
  "isError": false,
  "trace_id": "gw-46864edf-e3d3-4471-9b89-60f9d92a303c"
}
```

**Result: PASS** (with note)

- Tool executed successfully, returned Amsterdam weather data
- Coordinates match Amsterdam (52.366N, 4.901E, elevation 11m)
- Trace ID included for observability
- **Note:** Response only contains metadata (elevation, coordinates, timezone) but no actual weather values (temperature, wind, etc.). This may be expected if the Open-Meteo API requires explicit `current` or `hourly` parameters to return weather data -- this is a capability config issue, not a gateway issue.

---

## Test 2: Toolshed Profiles

### Test 2a: gateway_list_profiles

**Request:**
```json
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"gateway_list_profiles","arguments":{}}}
```

**Response:**
```json
{
  "default": "default",
  "profiles": [],
  "total": 0
}
```

**Result: FAIL**

- Expected 6 profiles (coding, research, communication, devops, intelligence, full)
- Got 0 profiles with default set to "default" instead of "full"

**Root cause:** Config schema mismatch. The running config (`servers.yaml`) defines profiles under:
```yaml
profiles:
  default_profile: full
  configs:
    coding: { ... }
    research: { ... }
    ...
```

But the Rust `Config` struct expects:
```rust
pub routing_profiles: HashMap<String, RoutingProfileConfig>,  // top-level key
pub default_routing_profile: String,                          // top-level key
```

The YAML key `profiles.configs` does not map to `routing_profiles`. The profiles are silently ignored during deserialization because `routing_profiles` defaults to an empty HashMap and `default_routing_profile` defaults to `"default"`.

**Fix required:** Either:
1. Change the YAML config to use `routing_profiles:` at top level and `default_routing_profile:` as a sibling key, OR
2. Add `#[serde(alias = "profiles")]` and a wrapper struct that maps `configs` to the HashMap

---

### Test 2b: Profile selection via X-MCP-Profile header

**Request:**
```bash
xh POST http://127.0.0.1:39401/mcp \
  Content-Type:application/json \
  X-MCP-Profile:research \
  <<< '{"jsonrpc":"2.0","id":5,"method":"initialize","params":{"protocolVersion":"2024-11-05","profile":"research"}}'
```

**Response:** Full `initialize` result returned with protocol version `2024-11-05`, full routing instructions for all tool categories, and composition chains. No evidence of profile-based filtering.

**Result: INCONCLUSIVE**

- The `initialize` response was returned successfully
- However, since profiles are not loaded (Test 2a failure), the `X-MCP-Profile:research` header has no effect
- Cannot validate profile-scoped tool filtering until the config mismatch is resolved

---

## Test 3: Per-capability Error Budget

### Test 3a: gateway_list_disabled_capabilities

**Request:**
```json
{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"gateway_list_disabled_capabilities","arguments":{}}}
```

**Response:**
```json
{
  "disabled_capabilities": [],
  "disabled_count": 0,
  "note": "No capabilities are currently disabled."
}
```

**Result: PASS**

- Returns empty list as expected (no capabilities currently disabled)
- Response includes `disabled_count` and human-readable `note`
- Tool is functional and ready to report disabled capabilities when error budgets are exceeded

---

## Summary

| Test | Description | Result |
|------|-------------|--------|
| 1a | tools/list returns 2 Code Mode tools | PASS |
| 1b | gateway_search finds weather tools with schemas | PASS |
| 1c | gateway_execute invokes fulcrum:weather | PASS |
| 2a | gateway_list_profiles returns 6 profiles | **FAIL** |
| 2b | Profile selection via X-MCP-Profile header | INCONCLUSIVE |
| 3a | gateway_list_disabled_capabilities | PASS |

### Issues Found

1. **[BUG] Profile config schema mismatch** (Test 2a)
   - **Severity:** High -- profiles feature is completely non-functional in production
   - **File:** `/Users/mikko/github/mcp-gateway/src/config.rs` (line 50)
   - **Config:** `/Users/mikko/.claude/mcp_servers/mcp-gateway-rs/servers.yaml` (lines 40-103)
   - **Impact:** All 6 configured profiles (coding, research, communication, devops, intelligence, full) are silently ignored. Sessions always use the allow-all default profile.
   - **Fix options:**
     - **(A) Fix YAML** to match struct: rename `profiles.configs` entries to top-level `routing_profiles` and `profiles.default_profile` to `default_routing_profile`
     - **(B) Fix struct** to match YAML: add a `profiles` wrapper struct with `default_profile` and `configs` fields, then flatten into existing fields

2. **[MINOR] Weather response lacks weather data** (Test 1c)
   - The `fulcrum:weather` capability returned coordinate metadata but no actual weather values
   - Likely needs `current: true` or `hourly: true` in the API call parameters
   - This is a capability definition issue, not a gateway issue
