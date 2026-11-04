"use strict";
// Tests for the release-binary check in run.js. No network: every download
// is either an injected function or a local HTTP server on 127.0.0.1.
// Run from the repository root: node --test npm/run.test.js

const test = require("node:test");
const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");

const {
  download,
  expectedDigest,
  getPlatform,
  install,
  placeVerified,
  VERSION,
} = require("./run.js");

// SHA256SUMS.txt from the v4.0.0-beta.3 release, verbatim (trailing newline
// and the .spdx.json siblings included).
const RELEASE_SUMS =
  "b07282e3bce7bad4a643ac2f3a0fda75b32a08c37cad9896ac0db8435689b4bb  mcp-gateway-darwin-arm64\n" +
  "bb8e945a3d632dadeda96c74aa92e3cf3846efcc1921a458f14b97cdc1dbdc98  mcp-gateway-darwin-arm64.spdx.json\n" +
  "cb9a81348ecd6e9f1ab6620187bf0665e8d74bf8ad143d546d4f2e215bf1eba1  mcp-gateway-darwin-x86_64\n" +
  "3aa0a11e42de7c7e38f54fbd5bbc930adaca9d398251788987ee2993f36857f8  mcp-gateway-darwin-x86_64.spdx.json\n" +
  "6587ec874ab306828363968af18f1ec50e2d2cef6596d57b955178824ad661b4  mcp-gateway-linux-aarch64\n" +
  "bd20db3a4c651d18d712a56233700d6c9be3d04cf4f669badabeeacb2f0fb602  mcp-gateway-linux-aarch64.spdx.json\n" +
  "13e2aae59d33adb2cc9dac91b753b590a296a124a2fb332d6dc5ce78533f6431  mcp-gateway-linux-x86_64\n" +
  "7dfb4356162143f5f0c6048a7f179f1efc06efb827d551bd3d4760a817ac1861  mcp-gateway-linux-x86_64.spdx.json\n" +
  "bf4f1a93ae48a2e4806f99dc34acbb48dbd5b293ef59bf6cd703b9a0ac6b151f  mcp-gateway-windows-x86_64.exe\n" +
  "3b5c9860c66354ea85eb9b97a334f4b2f2f517cf6d21c7165a3d8023709a6f89  mcp-gateway-windows-x86_64.exe.spdx.json\n";

const ARTIFACT = getPlatform();
const MARKER = "verified-binary-ran";
// A stand-in "binary" that proves it ran by printing MARKER.
const GOOD = Buffer.from(`#!/bin/sh\necho ${MARKER}\n`);
const TAMPERED = Buffer.from(`#!/bin/sh\necho ${MARKER}!\n`);

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

// The release sums with this platform's line pointing at `bytes`.
function sumsFor(bytes) {
  return RELEASE_SUMS.split("\n")
    .map((line) => (line.endsWith(`  ${ARTIFACT}`) ? `${sha256(bytes)}  ${ARTIFACT}` : line))
    .join("\n");
}

const made = [];
function tempDir() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-gateway-npm-"));
  made.push(dir);
  return dir;
}
test.after(() => {
  for (const dir of made) fs.rmSync(dir, { recursive: true, force: true });
});

// A fetch serving exactly the two release URLs install() must ask for.
function releaseFetch(binary, sums) {
  const base = `https://github.com/MikkoParkkola/mcp-gateway/releases/download/v${VERSION}`;
  return async (url) => {
    if (url === `${base}/${ARTIFACT}`) return binary;
    if (url === `${base}/SHA256SUMS.txt`) return Buffer.from(sums);
    throw new Error(`unexpected download: ${url}`);
  };
}

test("the release sums file yields each artifact's own digest, not a sibling's", () => {
  assert.equal(
    expectedDigest(RELEASE_SUMS, "mcp-gateway-darwin-arm64"),
    "b07282e3bce7bad4a643ac2f3a0fda75b32a08c37cad9896ac0db8435689b4bb"
  );
  assert.equal(
    expectedDigest(RELEASE_SUMS, "mcp-gateway-linux-x86_64"),
    "13e2aae59d33adb2cc9dac91b753b590a296a124a2fb332d6dc5ce78533f6431"
  );
});

test("a sibling listed before the artifact does not shadow it", () => {
  const reordered = `${"a".repeat(64)}  ${ARTIFACT}.spdx.json\n${"b".repeat(64)}  ${ARTIFACT}\n`;
  assert.equal(expectedDigest(reordered, ARTIFACT), "b".repeat(64));
});

test("CRLF line endings, an uppercase digest and the binary-mode marker parse", () => {
  const crlf = `${"C".repeat(64)} *${ARTIFACT}\r\n${"d".repeat(64)}  other\r\n`;
  assert.equal(expectedDigest(crlf, ARTIFACT), "c".repeat(64));
});

test("an artifact the sums file does not list is refused", () => {
  const without = RELEASE_SUMS.split("\n")
    .filter((line) => !line.endsWith(`  ${ARTIFACT}`))
    .join("\n");
  assert.throws(() => expectedDigest(without, ARTIFACT), /no entry/);
});

test("an artifact listed twice is refused", () => {
  const twice = `${RELEASE_SUMS}${"0".repeat(64)}  ${ARTIFACT}\n`;
  assert.throws(() => expectedDigest(twice, ARTIFACT), /more than one entry/);
});

test("a malformed digest is refused", () => {
  assert.throws(() => expectedDigest(`abc123  ${ARTIFACT}\n`, ARTIFACT), /malformed digest/);
});

test("a tampered binary is refused and nothing is written", () => {
  const dir = tempDir();
  const dest = path.join(dir, "mcp-gateway");
  assert.throws(() => placeVerified(TAMPERED, sumsFor(GOOD), ARTIFACT, dest), /checksum mismatch/);
  assert.deepEqual(fs.readdirSync(dir), []);
});

test("a binary missing from the sums is refused and nothing is written", () => {
  const dir = tempDir();
  const dest = path.join(dir, "mcp-gateway");
  assert.throws(() => placeVerified(GOOD, "", ARTIFACT, dest), /no entry/);
  assert.deepEqual(fs.readdirSync(dir), []);
});

test("install refuses a tampered download and removes an older binary", async () => {
  const dir = tempDir();
  const dest = path.join(dir, "mcp-gateway");
  fs.writeFileSync(dest, GOOD, { mode: 0o755 });
  await assert.rejects(
    install({ fetch: releaseFetch(TAMPERED, sumsFor(GOOD)), dir }),
    /checksum mismatch/
  );
  assert.deepEqual(fs.readdirSync(dir), []);
});

test("install leaves nothing runnable when a download fails", async () => {
  const dir = tempDir();
  const dest = path.join(dir, "mcp-gateway");
  fs.writeFileSync(dest, GOOD, { mode: 0o755 });
  const failing = async () => {
    throw new Error("download interrupted: test");
  };
  await assert.rejects(install({ fetch: failing, dir }), /download interrupted/);
  assert.deepEqual(fs.readdirSync(dir), []);
});

test("install places a verified binary that runs", async () => {
  const dir = tempDir();
  const dest = await install({ fetch: releaseFetch(GOOD, sumsFor(GOOD)), dir });
  assert.equal(dest, path.join(dir, "mcp-gateway"));
  assert.equal(fs.statSync(dest).mode & 0o777, 0o755);
  assert.deepEqual(fs.readdirSync(dir), ["mcp-gateway"]);
  assert.equal(execFileSync(dest).toString().trim(), MARKER);
});

// A local server that answers each path with `handler(req, res)`.
async function serve(handler) {
  const server = http.createServer(handler);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { server, url: `http://127.0.0.1:${server.address().port}` };
}

test("a transfer cut off mid-body is an error, not a short file", async () => {
  const { server, url } = await serve((req, res) => {
    res.writeHead(200, { "content-length": "1000" });
    res.write("partial");
    setImmediate(() => res.socket.destroy());
  });
  try {
    await assert.rejects(download(`${url}/bin`, http.get), /interrupted|aborted|socket hang up/);
  } finally {
    server.close();
  }
});

test("a redirect off HTTPS is refused", async () => {
  const { server, url } = await serve((req, res) => {
    res.writeHead(302, { location: "http://example.invalid/bin" });
    res.end();
  });
  try {
    await assert.rejects(download(`${url}/bin`, http.get), /redirect off HTTPS/);
  } finally {
    server.close();
  }
});

test("a malformed redirect is an error, not a crash", async () => {
  const { server, url } = await serve((req, res) => {
    res.writeHead(302, { location: "https://[::1" });
    res.end();
  });
  try {
    await assert.rejects(download(`${url}/bin`, http.get), /malformed redirect/);
  } finally {
    server.close();
  }
});

test("a redirect loop stops at the cap", async () => {
  let hits = 0;
  const { server, url } = await serve((req, res) => {
    hits += 1;
    res.writeHead(302, { location: "https://127.0.0.1/loop" });
    res.end();
  });
  // Every hop, HTTPS target included, is served by the same local HTTP server.
  const get = (target, cb) => http.get(target.replace(/^https:\/\/127\.0\.0\.1\//, `${url}/`), cb);
  try {
    await assert.rejects(download(`${url}/start`, get), /too many redirects/);
    assert.equal(hits, 6);
  } finally {
    server.close();
  }
});

test("a complete transfer resolves to its bytes", async () => {
  const { server, url } = await serve((req, res) => {
    res.writeHead(200, { "content-length": String(GOOD.length) });
    res.end(GOOD);
  });
  try {
    assert.deepEqual(await download(`${url}/bin`, http.get), GOOD);
  } finally {
    server.close();
  }
});
