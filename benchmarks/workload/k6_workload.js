/**
 * k6 workload — NFR.WORKLOAD.1 deterministic real-backend arm.
 *
 * Separate from k6_gateway.js on purpose. That script is byte-pinned by the
 * NFR.PERF.1 contract whose scored run is unfired, it has no way to pin a
 * tool name, and its tools/call check accepts an error response. This row
 * requires successful semantic payloads, so it needs its own script.
 *
 * This file is supplied by the runner, not taken from the checkout, so it is
 * byte-identical across every cell by construction.
 *
 * Required env:
 *   BASE_URL          gateway under test, e.g. http://127.0.0.1:39420
 *   BACKEND_NAME      registered backend name
 *   TOOL_NAME         pinned backend tool -- never discovered by ordering
 *   EXPECT_TEXT       exact substring the semantic assertion requires
 *   PROTOCOL_VERSION  version the client requests at initialize
 * Optional: API_KEY, SCENARIO (smoke|load).
 */

import http from "k6/http";
import exec from "k6/execution";
import { check, group, sleep } from "k6";
import { Counter, Rate, Trend } from "k6/metrics";

const BASE_URL = __ENV.BASE_URL;
const API_KEY = __ENV.API_KEY || "";
const SCENARIO = __ENV.SCENARIO || "load";
const BACKEND_NAME = __ENV.BACKEND_NAME;
const TOOL_NAME = __ENV.TOOL_NAME;
const EXPECT_TEXT = __ENV.EXPECT_TEXT;
const PROTOCOL_VERSION = __ENV.PROTOCOL_VERSION;

for (const [k, v] of Object.entries({
  BASE_URL,
  BACKEND_NAME,
  TOOL_NAME,
  EXPECT_TEXT,
  PROTOCOL_VERSION,
})) {
  if (!v) throw new Error(`missing required env ${k}`);
}

// Primary metric. Same name as the NFR.PERF.1 contract uses, so the two are
// read the same way -- they are still never pooled.
const mcpToolsCallLatency = new Trend("mcp_tools_call_latency", true);
const mcpToolsListLatency = new Trend("mcp_tools_list_latency", true);
const mcpInitLatency = new Trend("mcp_initialize_latency", true);
const healthLatency = new Trend("health_latency", true);

const httpErrors = new Rate("http_error_rate");
const semanticOk = new Rate("semantic_assertion_rate");
const semanticFailures = new Counter("semantic_failures");

const SCENARIOS = {
  smoke: { executor: "constant-vus", vus: 1, duration: "10s" },
  load: {
    executor: "ramping-vus",
    startVUs: 0,
    stages: [
      { duration: "10s", target: 50 },
      { duration: "40s", target: 50 },
      { duration: "10s", target: 0 },
    ],
  },
};

export const options = {
  scenarios: { [SCENARIO]: SCENARIOS[SCENARIO] },
  // No thresholds on purpose: eval_workload.py owns every pass/void rule, so
  // k6's exit code never competes with the evaluator's INCONCLUSIVE status.
  thresholds: {},
  summaryTrendStats: ["avg", "min", "med", "p(50)", "p(90)", "p(95)", "p(99)", "max"],
};

// A legacy-shaped request (A/B/C) with no `MCP-Protocol-Version` header and
// no bound session revision makes `cache_protocol_revision`
// (src/protocol/meta.rs) fail closed and skip the cache on 4.0.0, while
// 3.5.0/3.5.1 cache that same headerless shape unconditionally. That
// divergence, not gateway performance, is what a prior rehearsal measured.
// Sending the header on every call puts all three gating cells on the
// same cache terms.
//
// D/E run the modern era (2026-07-28), where the same header is only one
// quarter of a well-formed request. `classify_request`
// (src/protocol/meta.rs:150-217) reads a 2026 revision as an era declaration
// and then holds the request to everything that declaration implies:
// `params._meta` carrying `io.modelcontextprotocol/protocolVersion` and
// `io.modelcontextprotocol/clientCapabilities`, plus the mirrored
// `Mcp-Method` header and, on `tools/call`, `Mcp-Name`
// (src/protocol/headers.rs:176-236). Header alone is malformed, not modern:
// a prior rehearsal measured exactly that (-32602, missing required request
// metadata). All four parts are sent below.
//
// The modern block stays scoped to the modern era. A `_meta` declaration
// naming a legacy revision also classifies Modern and is then refused as a
// version the gateway will not serve statelessly
// (src/gateway/router/handlers.rs:838-851), and 3.5.0/3.5.1 have no `_meta`
// handling at all.
const IS_MODERN_ERA = PROTOCOL_VERSION.startsWith("2026-");

// Same key the gateway parses (src/protocol/mrtr.rs:33). A non-read-only
// `tools/call` in the modern era is refused with -32602 unless this is
// present (src/gateway/meta_mcp/admission.rs:151-159); accepted, not
// required, on the legacy era, so sending it unconditionally keeps A/B/C
// and D/E on one code path.
const IDEMPOTENCY_KEY_META = "io.mcp-gateway/idempotency-key";

// `Mcp-Name` mirrors `params.name` -- the meta-surface tool the request
// executes (`gateway_invoke`), never the pinned backend tool nested inside
// `arguments` (`mcp_name_body_field`, src/protocol/headers.rs:63-70).
function headers(method, name) {
  const h = {
    "Content-Type": "application/json",
    "MCP-Protocol-Version": PROTOCOL_VERSION,
  };
  if (IS_MODERN_ERA) {
    h["Mcp-Method"] = method;
    if (name) h["Mcp-Name"] = name;
  }
  if (API_KEY) h["Authorization"] = `Bearer ${API_KEY}`;
  return h;
}

// Request ids only have to be unique within one connection, and the runtime's
// per-iteration counter does not exist during setup(), where the handshake is
// rehearsed. A plain counter is defined everywhere the script runs.
let rpcSeq = 0;

// One key per request, never reused: the gateway treats a repeated key as a
// replay and returns the first response instead of executing again
// (src/gateway/meta_mcp/admission.rs:177-192), which would make the load
// phase measure cache hits, not the backend. `exec.vu`/`exec.scenario` are
// unset outside a scheduled VU iteration -- true during setup(), which runs
// before any VU is scheduled -- so that path falls back to a fixed scope and
// still gets uniqueness from `rpcSeq`, which is per-VU in k6 and therefore
// not unique across VUs on its own.
function idempotencyKey() {
  let scope = "setup";
  try {
    scope = `vu${exec.vu.idInInstance}-iter${exec.scenario.iterationInTest}`;
  } catch (e) {
    // no VU context yet (setup()/teardown()); rpcSeq still disambiguates.
  }
  return `nfr-workload-1-${scope}-${rpcSeq}`;
}

function rpc(method, params, trend) {
  rpcSeq += 1;
  // `_meta` belongs to `params`, not to the JSON-RPC envelope -- that is where
  // the gateway reads it (src/protocol/meta.rs:150-217). `{}` is the spec's
  // own "no client options" form for clientCapabilities. The inner
  // `Object.assign` preserves a caller-supplied `_meta` (the idempotency key)
  // instead of replacing it wholesale.
  const sent = IS_MODERN_ERA
    ? Object.assign({}, params, {
        _meta: Object.assign({}, params && params._meta, {
          "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
          "io.modelcontextprotocol/clientCapabilities": {},
        }),
      })
    : params;
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id: `${rpcSeq}-${method}`,
    method,
    params: sent,
  });
  const res = http.post(`${BASE_URL}/mcp`, body, {
    headers: headers(method, params && params.name),
  });
  if (trend) trend.add(res.timings.duration);
  httpErrors.add(res.status !== 200);
  try {
    return JSON.parse(res.body);
  } catch (e) {
    return null;
  }
}

function initialize(trend) {
  return rpc(
    "initialize",
    {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: "nfr-workload-1", version: "1" },
    },
    trend,
  );
}

function invokePinnedTool(trend) {
  return rpc(
    "tools/call",
    {
      name: "gateway_invoke",
      arguments: {
        server: BACKEND_NAME,
        tool: TOOL_NAME,
        arguments: { case_reference: "042" },
      },
      _meta: { [IDEMPOTENCY_KEY_META]: idempotencyKey() },
    },
    trend,
  );
}

// Runs once, before any measured request. A failure here aborts the whole
// run rather than producing a cell that silently measured the wrong thing.
export function setup() {
  const init = initialize(null);
  if (!init || init.error || !init.result) {
    throw new Error(`initialize failed: ${JSON.stringify(init)}`);
  }

  const listed = rpc("tools/list", {}, null);
  if (!listed || !listed.result || !Array.isArray(listed.result.tools)) {
    throw new Error(`tools/list failed: ${JSON.stringify(listed)}`);
  }
  const names = listed.result.tools.map((t) => t.name);
  if (!names.includes("gateway_invoke")) {
    throw new Error(
      `void: gateway_invoke absent from the meta surface; saw ${names.join(",")}`,
    );
  }

  // Prove the pinned tool resolves and returns the pinned payload before the
  // measured reps start. Void condition 1 and 2 are checked here, once.
  const probe = invokePinnedTool(null);
  const text = probe && probe.result ? JSON.stringify(probe.result) : "";
  if (!text.includes(EXPECT_TEXT)) {
    throw new Error(
      `void: pinned tool ${TOOL_NAME} did not return the pinned payload; got ${JSON.stringify(probe)}`,
    );
  }
  return { verified: true };
}

export default function () {
  group("health", () => {
    const res = http.get(`${BASE_URL}/health`);
    healthLatency.add(res.timings.duration);
    httpErrors.add(res.status !== 200);
  });

  sleep(0.1);

  group("mcp_workflow", () => {
    const init = initialize(mcpInitLatency);
    check(init, {
      "initialize: no error": (r) => r !== null && r.error === undefined,
    });

    sleep(0.05);

    const listed = rpc("tools/list", {}, mcpToolsListLatency);
    check(listed, {
      "tools/list: no error": (r) => r !== null && r.error === undefined,
    });

    sleep(0.05);

    // The measured call. Tool name comes from env, never from list ordering.
    const callRes = invokePinnedTool(mcpToolsCallLatency);

    const payload = callRes && callRes.result ? JSON.stringify(callRes.result) : "";
    const ok = callRes !== null && callRes.error === undefined && payload.includes(EXPECT_TEXT);

    semanticOk.add(ok);
    if (!ok) semanticFailures.add(1);

    check(callRes, {
      "tools/call: no error": (r) => r !== null && r.error === undefined,
      "tools/call: semantic payload matches the pin": () => ok,
    });
  });

  sleep(0.1);
}
