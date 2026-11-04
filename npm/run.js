#!/usr/bin/env node
"use strict";

const { execFileSync } = require("child_process");
const { createHash } = require("crypto");
const {
  chmodSync,
  existsSync,
  mkdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} = require("fs");
const { join } = require("path");
const https = require("https");
const os = require("os");

const { version: VERSION } = require("./package.json");
const REPO = "MikkoParkkola/mcp-gateway";
const BIN_DIR = join(__dirname, ".bin");
const BIN_NAME = "mcp-gateway";
const SUMS_NAME = "SHA256SUMS.txt";
const MAX_REDIRECTS = 5;
// No bytes for this long ends the download; a slow but moving one continues.
const IDLE_TIMEOUT_MS = 30_000;

function getPlatform() {
  const arch = os.arch();
  const platform = os.platform();

  if (platform === "darwin" && arch === "arm64")
    return "mcp-gateway-darwin-arm64";
  if (platform === "darwin" && arch === "x64")
    return "mcp-gateway-darwin-x86_64";
  if (platform === "linux" && arch === "x64")
    return "mcp-gateway-linux-x86_64";

  throw new Error(
    `Unsupported platform: ${platform}-${arch}. ` +
      `Install via cargo: cargo install mcp-gateway`
  );
}

// Fetch `url` into memory. Rejects on a transport error, a non-200 answer, a
// transfer that ends early or stalls, too many redirects, or a redirect off HTTPS.
// `get` is a parameter only so a test can serve plain HTTP from localhost.
function download(url, get = https.get, redirects = 0) {
  return new Promise((resolve, reject) => {
    const req = get(url, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        const next = new URL(res.headers.location, url);
        if (next.protocol !== "https:")
          return reject(new Error(`refusing a redirect off HTTPS for ${url}`));
        if (redirects >= MAX_REDIRECTS)
          return reject(new Error(`too many redirects for ${url}`));
        return download(next.href, get, redirects + 1).then(resolve, reject);
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
      }
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("error", reject);
      res.on("aborted", () => reject(new Error(`download interrupted: ${url}`)));
      res.on("end", () => {
        if (!res.complete) return reject(new Error(`download interrupted: ${url}`));
        resolve(Buffer.concat(chunks));
      });
      // A connection can close without "end"; a settled promise ignores this.
      res.on("close", () => {
        if (!res.complete) reject(new Error(`download interrupted: ${url}`));
      });
    });
    req.on("error", reject);
    req.setTimeout(IDLE_TIMEOUT_MS, () =>
      req.destroy(new Error(`download stalled for ${IDLE_TIMEOUT_MS / 1000} s: ${url}`))
    );
  });
}

// The digest SHA256SUMS.txt lists for `artifact`. Throws unless exactly one
// line names it and its digest is 64 hex characters.
function expectedDigest(sumsText, artifact) {
  const found = [];
  for (const line of sumsText.split("\n")) {
    const fields = line.trim().split(/\s+/);
    if (fields.length !== 2) continue;
    const name = fields[1].startsWith("*") ? fields[1].slice(1) : fields[1];
    if (name === artifact) found.push(fields[0].toLowerCase());
  }
  if (found.length !== 1)
    throw new Error(
      `${SUMS_NAME} has ${found.length === 0 ? "no" : "more than one"} entry for ${artifact}`
    );
  if (!/^[0-9a-f]{64}$/.test(found[0]))
    throw new Error(`${SUMS_NAME} lists a malformed digest for ${artifact}`);
  return found[0];
}

// Write `bytes` to `dest` as an executable only if their SHA-256 matches the
// sums entry for `artifact`. A refusal writes nothing; a write goes through a
// temporary file and a rename, so `dest` never holds a partial binary.
function placeVerified(bytes, sumsText, artifact, dest) {
  const expected = expectedDigest(sumsText, artifact);
  const actual = createHash("sha256").update(bytes).digest("hex");
  if (actual !== expected)
    throw new Error(`checksum mismatch for ${artifact}: expected ${expected}, got ${actual}`);
  const tmp = `${dest}.tmp-${process.pid}`;
  try {
    writeFileSync(tmp, bytes, { mode: 0o755 });
    chmodSync(tmp, 0o755);
    renameSync(tmp, dest);
  } finally {
    rmSync(tmp, { force: true });
  }
  return dest;
}

async function install({ fetch = download, dir = BIN_DIR } = {}) {
  const artifact = getPlatform();
  const base = `https://github.com/${REPO}/releases/download/v${VERSION}`;
  const dest = join(dir, BIN_NAME);

  mkdirSync(dir, { recursive: true });
  // A failed or refused install must not leave an older, unchecked binary
  // behind for the next run to exec.
  rmSync(dest, { force: true });

  console.log(`Downloading mcp-gateway v${VERSION} (${artifact})...`);
  const [bytes, sums] = await Promise.all([
    fetch(`${base}/${artifact}`),
    fetch(`${base}/${SUMS_NAME}`),
  ]);
  placeVerified(bytes, sums.toString("utf8"), artifact, dest);
  console.log(`Verified and installed to ${dest}`);
  return dest;
}

async function main() {
  const args = process.argv.slice(2);

  if (args[0] === "--install") {
    await install();
    return;
  }

  const binPath = join(BIN_DIR, BIN_NAME);

  if (!existsSync(binPath)) {
    await install();
  }

  try {
    execFileSync(binPath, args, { stdio: "inherit" });
  } catch (e) {
    process.exit(e.status || 1);
  }
}

if (require.main === module) {
  main().catch((e) => {
    console.error(e.message);
    process.exit(1);
  });
}

module.exports = { download, expectedDigest, getPlatform, install, placeVerified, VERSION };
