/**
 * k6 Load Test — MCP Gateway
 *
 * Endpoints under test:
 *   POST /mcp              — Meta-MCP JSON-RPC 2.0 (initialize / tools/list / tools/call)
 *   GET  /health           — Health check (unauthenticated)
 *   GET  /dashboard        — Operator dashboard HTML (webui feature)
 *   GET  /ui/api/status    — UI status API (authenticated)
 *   GET  /ui/api/tools     — UI tools API (authenticated)
 *
 * Scenarios
 *   smoke   — 1 VU, 10 s  (basic sanity, no load)
 *   load    — 50 VU, 60 s  (steady-state production traffic)
 *   stress  — 200 VU, 120 s (find breaking point)
 *   spike   — 0 → 300 VU → 0 (sudden burst)
 *
 * Usage
 *   k6 run k6_gateway.js                               # smoke (default)
 *   k6 run -e SCENARIO=load k6_gateway.js
 *   k6 run -e SCENARIO=stress k6_gateway.js
 *   k6 run -e SCENARIO=spike k6_gateway.js
 *   k6 run -e BASE_URL=http://10.0.0.5:39400 -e API_KEY=secret k6_gateway.js
 */

import http from "k6/http";
import { check, group, sleep } from "k6";
import { Counter, Rate, Trend } from "k6/metrics";

// ── Configuration ──────────────────────────────────────────────────────────

const BASE_URL = __ENV.BASE_URL || "http://127.0.0.1:39400";
const API_KEY = __ENV.API_KEY || "";
const SCENARIO = __ENV.SCENARIO || "smoke";

// Custom metrics — one Trend per logical endpoint for granular percentiles
const mcpInitLatency = new Trend("mcp_initialize_latency", true);
const mcpToolsListLatency = new Trend("mcp_tools_list_latency", true);
const mcpToolsCallLatency = new Trend("mcp_tools_call_latency", true);
const healthLatency = new Trend("health_latency", true);
const dashboardLatency = new Trend("dashboard_latency", true);
const uiStatusLatency = new Trend("ui_status_latency", true);

const rpcErrors = new Counter("rpc_errors");
const httpErrors = new Rate("http_error_rate");

// ── Scenario definitions ───────────────────────────────────────────────────

const SCENARIOS = {
  smoke: {
    executor: "constant-vus",
    vus: 1,
    duration: "10s",
  },
  load: {
    executor: "ramping-vus",
    startVUs: 0,
    stages: [
      { duration: "10s", target: 50 },
      { duration: "40s", target: 50 },
      { duration: "10s", target: 0 },
    ],
  },
  stress: {
    executor: "ramping-vus",
    startVUs: 0,
    stages: [
      { duration: "15s", target: 50 },
      { duration: "30s", target: 100 },
      { duration: "30s", target: 200 },
      { duration: "30s", target: 200 },
      { duration: "15s", target: 0 },
    ],
  },
  spike: {
    executor: "ramping-vus",
    startVUs: 0,
    stages: [
      { duration: "5s", target: 0 },
      { duration: "10s", target: 300 },
      { duration: "20s", target: 300 },
      { duration: "10s", target: 0 },
      { duration: "20s", target: 0 },
    ],
  },
};

// ── k6 options ─────────────────────────────────────────────────────────────

export const options = {
  scenarios: {
    gateway: SCENARIOS[SCENARIO],
  },
  thresholds: {
    // Overall HTTP error rate must stay below 1 %
    http_error_rate: ["rate<0.01"],

    // Per-endpoint p95 latency budgets
    mcp_initialize_latency: ["p(95)<500"],
    mcp_tools_list_latency: ["p(95)<500"],
    mcp_tools_call_latency: ["p(95)<500"],
    health_latency: ["p(95)<100"],
    dashboard_latency: ["p(95)<300"],
    ui_status_latency: ["p(95)<300"],

    // Global HTTP request duration guard
    http_req_duration: ["p(95)<500", "p(99)<2000"],

    // k6 built-in: no failed checks allowed above 1 %
    checks: ["rate>0.99"],
  },
};

// ── Helpers ────────────────────────────────────────────────────────────────

/** Build common request headers. API_KEY is optional — gateway may run open. */
function headers(extra = {}) {
  const base = {
    "Content-Type": "application/json",
    Accept: "application/json",
  };
  if (API_KEY) {
    base["Authorization"] = `Bearer ${API_KEY}`;
  }
  return Object.assign(base, extra);
}

/** Construct a JSON-RPC 2.0 request body. */
function rpc(method, params, id) {
  return JSON.stringify({
    jsonrpc: "2.0",
    id: id !== undefined ? id : Math.floor(Math.random() * 1_000_000),
    method,
    params: params || {},
  });
}

/**
 * Post a JSON-RPC 2.0 request to POST /mcp.
 * Records latency to the provided Trend and increments error counters.
 *
 * @param {string} method  - JSON-RPC method name
 * @param {object} params  - method parameters
 * @param {Trend}  trend   - metric to record latency into
 * @param {string} tag     - value for the `endpoint` tag
 * @returns {object}       - parsed response body (or null on parse error)
 */
function postMcp(method, params, trend, tag) {
  const res = http.post(`${BASE_URL}/mcp`, rpc(method, params), {
    headers: headers(),
    tags: { endpoint: tag },
  });

  trend.add(res.timings.duration);
  httpErrors.add(res.status >= 400);

  const ok = check(res, {
    [`${tag}: HTTP 200`]: (r) => r.status === 200,
    [`${tag}: has jsonrpc field`]: (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.jsonrpc === "2.0";
      } catch {
        return false;
      }
    },
  });

  if (!ok) {
    rpcErrors.add(1);
  }

  try {
    return JSON.parse(res.body);
  } catch {
    return null;
  }
}

// ── MCP workflow helpers ────────────────────────────────────────────────────

/** initialize — establishes MCP session. Returns capabilities object. */
function mcpInitialize() {
  return postMcp(
    "initialize",
    {
      protocolVersion: "2025-03-26",
      capabilities: {},
      clientInfo: { name: "k6-load-test", version: "1.0.0" },
    },
    mcpInitLatency,
    "mcp_initialize"
  );
}

/** tools/list — enumerate available tools from all backends. */
function mcpToolsList() {
  const res = postMcp("tools/list", {}, mcpToolsListLatency, "mcp_tools_list");
  return res;
}

/**
 * tools/call — invoke a named tool.
 *
 * The test uses "gateway_status" which is always present when meta-mcp
 * is enabled (it is a built-in meta tool). Falls back gracefully if absent.
 */
function mcpToolsCall(toolName, toolArgs) {
  return postMcp(
    "tools/call",
    {
      name: toolName,
      arguments: toolArgs || {},
    },
    mcpToolsCallLatency,
    "mcp_tools_call"
  );
}

// ── VU iteration ───────────────────────────────────────────────────────────

export default function () {
  // 1. Health check — lightweight, run every iteration
  group("health", () => {
    const res = http.get(`${BASE_URL}/health`, {
      headers: { Accept: "application/json" },
      tags: { endpoint: "health" },
    });

    healthLatency.add(res.timings.duration);
    httpErrors.add(res.status >= 400);

    check(res, {
      "health: HTTP 200 or 503": (r) => r.status === 200 || r.status === 503,
      "health: has status field": (r) => {
        try {
          const body = JSON.parse(r.body);
          return (
            body.status === "healthy" ||
            body.status === "degraded" ||
            typeof body.status === "string"
          );
        } catch {
          return false;
        }
      },
      "health: has version field": (r) => {
        try {
          return typeof JSON.parse(r.body).version === "string";
        } catch {
          return false;
        }
      },
    });
  });

  sleep(0.1);

  // 2. MCP initialize → tools/list → tools/call sequence
  group("mcp_workflow", () => {
    // initialize
    const initRes = mcpInitialize();
    check(initRes, {
      "initialize: result present": (r) => r !== null && r.result !== undefined,
      "initialize: no error": (r) => r !== null && r.error === undefined,
    });

    sleep(0.05);

    // tools/list
    const listRes = mcpToolsList();
    check(listRes, {
      "tools/list: result present": (r) => r !== null && r.result !== undefined,
      "tools/list: no error": (r) => r !== null && r.error === undefined,
    });

    // Extract first available tool for tools/call (graceful if list is empty)
    let toolName = "gateway_status"; // always available when meta-mcp enabled
    if (
      listRes &&
      listRes.result &&
      listRes.result.tools &&
      listRes.result.tools.length > 0
    ) {
      toolName = listRes.result.tools[0].name;
    }

    sleep(0.05);

    // tools/call
    const callRes = mcpToolsCall(toolName, {});
    check(callRes, {
      "tools/call: result present": (r) => r !== null && r.result !== undefined,
      // Error is acceptable for tools/call — tool may require arguments
      "tools/call: jsonrpc 2.0": (r) => r !== null && r.jsonrpc === "2.0",
    });
  });

  sleep(0.1);

  // 3. Dashboard — HTML endpoint (webui feature). Accept 404 when feature disabled.
  group("dashboard", () => {
    const res = http.get(`${BASE_URL}/dashboard`, {
      headers: headers({ Accept: "text/html,application/json" }),
      tags: { endpoint: "dashboard" },
    });

    dashboardLatency.add(res.timings.duration);
    httpErrors.add(res.status >= 500);

    check(res, {
      "dashboard: not 5xx": (r) => r.status < 500,
      "dashboard: 200 or 404": (r) => r.status === 200 || r.status === 404,
    });
  });

  sleep(0.1);

  // 4. UI status API (authenticated admin endpoint)
  group("ui_api", () => {
    const res = http.get(`${BASE_URL}/ui/api/status`, {
      headers: headers(),
      tags: { endpoint: "ui_status" },
    });

    uiStatusLatency.add(res.timings.duration);
    httpErrors.add(res.status >= 500);

    check(res, {
      "ui/api/status: not 5xx": (r) => r.status < 500,
      "ui/api/status: 200 or 401 or 403 or 404": (r) =>
        [200, 401, 403, 404].includes(r.status),
    });
  });

  // Pacing: keep iteration duration ~0.5 s to avoid overwhelming small servers
  sleep(0.05);
}

// ── Summary output ─────────────────────────────────────────────────────────

export function handleSummary(data) {
  const thresholds = data.metrics;
  const passed = Object.entries(thresholds)
    .filter(([, m]) => m.thresholds)
    .every(([, m]) => m.thresholds.every((t) => !t.ok === false));

  console.log("\n=== MCP Gateway Load Test Summary ===");
  console.log(`Scenario : ${SCENARIO}`);
  console.log(`Base URL : ${BASE_URL}`);

  const dur = data.metrics["http_req_duration"];
  if (dur) {
    const v = dur.values;
    console.log(
      `http_req_duration : p50=${v["p(50)"].toFixed(1)}ms  p95=${v["p(95)"].toFixed(1)}ms  p99=${v["p(99)"].toFixed(1)}ms`
    );
  }

  const errRate = data.metrics["http_error_rate"];
  if (errRate) {
    console.log(
      `http_error_rate   : ${(errRate.values.rate * 100).toFixed(2)}%`
    );
  }

  const checks = data.metrics["checks"];
  if (checks) {
    const rate = (checks.values.rate * 100).toFixed(2);
    console.log(`checks pass rate  : ${rate}%`);
  }

  console.log(`\nThresholds        : ${passed ? "ALL PASSED" : "SOME FAILED"}`);
  console.log("=====================================\n");

  return {
    stdout: "",
  };
}
