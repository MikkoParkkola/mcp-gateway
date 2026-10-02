"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const hb = require("./heartbeat.js");

function scratch() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "heartbeat-"));
}

test("opt-out, ci, and dev builds do not send or write state", () => {
  const home = scratch();
  const posts = [];
  const base = {
    project: "mcp-gateway",
    version: "3.5.1",
    optOut: ["MCP_GATEWAY_NO_TELEMETRY"],
    endpointEnv: "MCP_GATEWAY_TELEMETRY_ENDPOINT",
    stateParts: ["telemetry"],
  };
  const cases = [
    { version: "dev", env: {} },
    { version: "", env: {} },
    { version: "3.5.1", env: { NO_TELEMETRY: "1" } },
    { version: "3.5.1", env: { DO_NOT_TRACK: "yes" } },
    { version: "3.5.1", env: { MCP_GATEWAY_NO_TELEMETRY: "1" } },
    { version: "3.5.1", env: { CI: "true" } },
    { version: "3.5.1", env: { NO_TELEMETRY: "0", DO_NOT_TRACK: "false" } },
  ];
  for (const item of cases.slice(0, 6)) {
    hb.start(
      { ...base, version: item.version },
      { env: item.env, home, now: new Date(), post: (url, body) => posts.push({ url, body }) },
    );
  }
  assert.equal(posts.length, 0);
  assert.equal(fs.existsSync(path.join(home, "telemetry")), false);

  hb.start(base, {
    env: cases[6].env,
    home,
    now: new Date("2026-10-02T12:00:00Z"),
    post: (url, body) => posts.push(JSON.parse(body.toString())),
  });
  assert.equal(posts.length, 1);
  assert.deepEqual(Object.keys(posts[0]).sort(), [
    "event",
    "install_date",
    "install_id",
    "machine_id",
    "project",
    "runtime",
    "version",
  ]);
  assert.equal(posts[0].install_date, "2026-10-02");
  assert.match(posts[0].machine_id, /^[0-9a-f]{32}$/);
  assert.equal(posts[0].project, "mcp-gateway");
  assert.equal(posts[0].event, "heartbeat");
  assert.equal(posts[0].version, "3.5.1");
  assert.match(posts[0].install_id, /^[0-9a-f]{32}$/);
  fs.rmSync(home, { recursive: true, force: true });
});

test("an empty endpoint override keeps the default and a value replaces it", () => {
  assert.equal(hb.resolveEndpoint({}, "MCP_GATEWAY_TELEMETRY_ENDPOINT"), hb.DEFAULT_ENDPOINT);
  assert.equal(
    hb.resolveEndpoint({ MCP_GATEWAY_TELEMETRY_ENDPOINT: "" }, "MCP_GATEWAY_TELEMETRY_ENDPOINT"),
    hb.DEFAULT_ENDPOINT,
  );
  assert.equal(
    hb.resolveEndpoint(
      { MCP_GATEWAY_TELEMETRY_ENDPOINT: "http://127.0.0.1:9/v1/heartbeat" },
      "MCP_GATEWAY_TELEMETRY_ENDPOINT",
    ),
    "http://127.0.0.1:9/v1/heartbeat",
  );
  assert.equal(
    hb.resolveEndpoint({ MCP_GATEWAY_TELEMETRY_ENDPOINT: "ftp://example.test" }, "MCP_GATEWAY_TELEMETRY_ENDPOINT"),
    "",
  );
});

test("the daily slot is claimed before the post and a second call does not post", () => {
  const home = scratch();
  const posts = [];
  const options = {
    project: "nab",
    version: "0.12.3",
    optOut: ["NAB_NO_TELEMETRY"],
    endpointEnv: "NAB_TELEMETRY_ENDPOINT",
    stateParts: ["telemetry"],
  };
  const now = new Date("2026-10-02T12:00:00Z");
  let markedBeforePost = false;
  hb.start(options, {
    env: {},
    home,
    now,
    post: () => {
      markedBeforePost = fs.existsSync(path.join(home, "telemetry", "heartbeat"));
      posts.push("one");
    },
  });
  assert.equal(markedBeforePost, true);
  assert.equal(posts.length, 1);
  const stamp = fs.readFileSync(path.join(home, "telemetry", "heartbeat"), "utf8");
  assert.equal(stamp, "2026-10-02T12:00:00Z");
  hb.start(options, {
    env: {},
    home,
    now: new Date("2026-10-02T18:00:00Z"),
    post: () => posts.push("two"),
  });
  assert.deepEqual(posts, ["one"]);
  hb.start(options, {
    env: {},
    home,
    now: new Date("2026-10-03T12:00:00Z"),
    post: () => posts.push("three"),
  });
  assert.deepEqual(posts, ["one", "three"]);
  const mode = fs.statSync(path.join(home, "telemetry", "install-id")).mode & 0o777;
  assert.equal(mode, 0o600);
  const shared = fs.readFileSync(path.join(home, ".revaluator", "machine-id"), "utf8").trim();
  const other = [];
  hb.start(
    {
      project: "axterminator",
      version: "0.10.2",
      optOut: [],
      endpointEnv: "AXTERMINATOR_TELEMETRY_ENDPOINT",
      stateParts: [".axterminator", "telemetry"],
    },
    {
      env: {},
      home,
      now,
      post: (_url, body) => other.push(JSON.parse(body.toString())),
    },
  );
  assert.equal(other.length, 1);
  assert.equal(other[0].machine_id, shared);
  assert.equal(other[0].install_date, "2026-10-02");
  assert.notEqual(
    other[0].install_id,
    fs.readFileSync(path.join(home, "telemetry", "install-id"), "utf8").trim(),
  );
  fs.mkdirSync(path.join(home, ".kept", "telemetry"), { recursive: true });
  fs.writeFileSync(path.join(home, ".kept", "telemetry", "install-date"), "2024-05-01");
  fs.writeFileSync(path.join(home, ".kept", "telemetry", "install-id"), "abc");
  const kept = [];
  hb.start(
    {
      project: "nab",
      version: "0.12.3",
      optOut: [],
      endpointEnv: "NAB_TELEMETRY_ENDPOINT",
      stateParts: [".kept", "telemetry"],
    },
    {
      env: {},
      home,
      now,
      post: (_url, body) => kept.push(JSON.parse(body.toString())),
    },
  );
  assert.equal(kept[0].install_date, "2024-05-01");
  assert.equal(kept[0].machine_id, shared);
  fs.rmSync(home, { recursive: true, force: true });
});

test("0 and false do not opt out", () => {
  assert.equal(hb.suppressed("1.0.0", { NO_TELEMETRY: "0" }, ["NAB_NO_TELEMETRY"]), false);
  assert.equal(hb.suppressed("1.0.0", { NO_TELEMETRY: "false" }, []), false);
  assert.equal(hb.suppressed("1.0.0", { NAB_NO_TELEMETRY: "1" }, ["NAB_NO_TELEMETRY"]), true);
});

test("a body over 2048 bytes is not posted", () => {
  const body = hb.buildBody("mcp-gateway", "v".repeat(hb.MAX_BODY), "abc");
  assert.equal(body, null);
});

test("post reaches a local server and does not add fields", async () => {
  const seen = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      seen.push({
        type: req.headers["content-type"],
        body: Buffer.concat(chunks).toString("utf8"),
      });
      res.writeHead(204);
      res.end();
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  const body = hb.buildBody("axterminator", "0.10.2", "0123456789abcdef0123456789abcdef");
  await hb.post(`http://127.0.0.1:${port}/v1/heartbeat`, body);
  server.close();
  assert.equal(seen.length, 1);
  assert.equal(seen[0].type, "application/json");
  const parsed = JSON.parse(seen[0].body);
  assert.deepEqual(Object.keys(parsed).sort(), [
    "event",
    "install_id",
    "project",
    "runtime",
    "version",
  ]);
  assert.equal(parsed.project, "axterminator");
  assert.equal(Object.prototype.hasOwnProperty.call(parsed, "hostname"), false);
});
