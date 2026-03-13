-- wrk Lua script — MCP Gateway throughput baseline
--
-- Tests POST /mcp with JSON-RPC 2.0 tools/list requests.
-- Cycles through initialize and tools/list to exercise the meta-mcp path.
--
-- Usage:
--   wrk -t4 -c50 -d30s -s tests/load/wrk_basic.lua http://127.0.0.1:39400
--   wrk -t8 -c200 -d60s -s tests/load/wrk_basic.lua http://127.0.0.1:39400 -- bearer_token
--
-- Arguments (passed after --):
--   $1  Optional bearer token for authenticated gateways
--
-- Output includes: requests/sec, latency percentiles (p50/p90/p99), transfer/sec.

local counter = 0
local bearer = nil

-- Cycle of JSON-RPC methods to distribute request types realistically.
-- initialize (20%), tools/list (60%), tools/call (20%)
local methods = {
  { method = "initialize", params = '{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"wrk","version":"1.0"}}' },
  { method = "tools/list",   params = '{}' },
  { method = "tools/list",   params = '{}' },
  { method = "tools/list",   params = '{}' },
  { method = "tools/call",   params = '{"name":"gateway_status","arguments":{}}' },
}

-- init() is called once per thread before the benchmark starts.
function init(args)
  if args and args[1] and args[1] ~= "" then
    bearer = args[1]
  end
end

-- request() is called for every HTTP request wrk generates.
function request()
  counter = counter + 1
  local entry = methods[(counter % #methods) + 1]

  local body = string.format(
    '{"jsonrpc":"2.0","id":%d,"method":"%s","params":%s}',
    counter,
    entry.method,
    entry.params
  )

  local hdrs = {
    ["Content-Type"] = "application/json",
    ["Accept"]       = "application/json",
  }

  if bearer then
    hdrs["Authorization"] = "Bearer " .. bearer
  end

  return wrk.format("POST", "/mcp", hdrs, body)
end

-- response() is called for every HTTP response received.
-- Tracks non-200 / JSON-RPC error responses.
local error_count  = 0
local total_count  = 0
local rpc_errors   = 0

function response(status, headers, body)
  total_count = total_count + 1

  if status ~= 200 then
    error_count = error_count + 1
    return
  end

  -- Light JSON-RPC error detection without a full parser.
  -- Checks for the presence of '"error"' in the body (false positives are
  -- possible in tool output; this is a coarse proxy, not a strict check).
  if body and string.find(body, '"error"', 1, true) then
    -- Exclude the case where the field appears inside a successful result
    -- (e.g. a tool returning error details in its content).
    if not string.find(body, '"result"', 1, true) then
      rpc_errors = rpc_errors + 1
    end
  end
end

-- done() is called once after the benchmark completes.
function done(summary, latency, requests)
  local error_rate = 0
  if total_count > 0 then
    error_rate = (error_count / total_count) * 100
  end

  io.write("\n=== MCP Gateway wrk Report ===\n")
  io.write(string.format("  Total requests   : %d\n", total_count))
  io.write(string.format("  HTTP errors      : %d (%.2f%%)\n", error_count, error_rate))
  io.write(string.format("  RPC errors (est) : %d\n", rpc_errors))
  io.write(string.format("  Requests/sec     : %.2f\n", summary.requests / (summary.duration / 1e6)))
  io.write(string.format("  Latency p50      : %.2f ms\n", latency:percentile(50) / 1000))
  io.write(string.format("  Latency p90      : %.2f ms\n", latency:percentile(90) / 1000))
  io.write(string.format("  Latency p99      : %.2f ms\n", latency:percentile(99) / 1000))
  io.write(string.format("  Latency max      : %.2f ms\n", latency.max / 1000))
  io.write("==============================\n\n")
end
