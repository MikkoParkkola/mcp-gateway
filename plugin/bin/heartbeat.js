"use strict";

// Daily heartbeat. The JSON body is exactly project, event, version, runtime,
// and install_id. At most one attempt per 24 hours. Failure is ignored.
// Importing this file does no I/O.

const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const https = require("https");
const os = require("os");
const path = require("path");

const DEFAULT_ENDPOINT = "https://telemetry.revaluator.ai/v1/heartbeat";
const MAX_BODY = 2048;
const DAY_MS = 24 * 60 * 60 * 1000;
const CI_ENVS = [
  "CI",
  "CONTINUOUS_INTEGRATION",
  "GITHUB_ACTIONS",
  "GITLAB_CI",
  "CIRCLECI",
  "TRAVIS",
  "BUILDKITE",
  "DRONE",
  "JENKINS_URL",
  "TEAMCITY_VERSION",
  "BITBUCKET_BUILD_NUMBER",
  "APPVEYOR",
  "CODEBUILD_BUILD_ID",
];

function truthy(value) {
  return value != null && value !== "" && value !== "0" && value !== "false";
}

function suppressed(version, env, optOutNames) {
  if (!version || version === "dev") return true;
  for (const name of CI_ENVS) {
    if (truthy(env[name])) return true;
  }
  const names = ["DO_NOT_TRACK", "NO_TELEMETRY"].concat(optOutNames || []);
  for (const name of names) {
    if (truthy(env[name])) return true;
  }
  return false;
}

function resolveEndpoint(env, endpointEnv) {
  const override = env[endpointEnv];
  if (!override) return DEFAULT_ENDPOINT;
  if (override.startsWith("https://") || override.startsWith("http://")) return override;
  return "";
}

function formatStamp(date) {
  return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}

function parseStamp(text) {
  const trimmed = String(text).trim().replace(/\.\d+Z$/, "Z");
  const ms = Date.parse(trimmed);
  return Number.isNaN(ms) ? null : ms;
}

function due(dir, nowMs) {
  let text;
  try {
    text = fs.readFileSync(path.join(dir, "heartbeat"), "utf8");
  } catch {
    return true;
  }
  const last = parseStamp(text);
  if (last === null) return true;
  return nowMs - last >= DAY_MS;
}

function markSent(dir, now) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  try {
    fs.chmodSync(dir, 0o700);
  } catch {
    // mode is best-effort on filesystems that ignore it
  }
  const dest = path.join(dir, "heartbeat");
  const tmp = path.join(dir, "heartbeat.tmp");
  fs.writeFileSync(tmp, formatStamp(now), { mode: 0o600 });
  try {
    fs.chmodSync(tmp, 0o600);
  } catch {
    // best-effort
  }
  fs.renameSync(tmp, dest);
}

function installId(dir) {
  const file = path.join(dir, "install-id");
  try {
    const existing = fs.readFileSync(file, "utf8").trim();
    if (existing) return existing;
  } catch {
    // create one below
  }
  const id = crypto.randomBytes(16).toString("hex");
  try {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(file, id, { mode: 0o600 });
    fs.chmodSync(file, 0o600);
  } catch {
    return "";
  }
  return id;
}

function runtimeString() {
  return `${process.platform}/${process.arch}/${process.version}`;
}

function buildBody(project, version, id) {
  const payload = {
    project,
    event: "heartbeat",
    version,
    runtime: runtimeString(),
  };
  if (id) payload.install_id = id;
  const body = Buffer.from(JSON.stringify(payload));
  if (body.length > MAX_BODY) return null;
  return body;
}

function post(url, body) {
  return new Promise((resolve) => {
    let settled = false;
    const done = () => {
      if (!settled) {
        settled = true;
        resolve();
      }
    };
    try {
      const parsed = new URL(url);
      const lib = parsed.protocol === "https:" ? https : http;
      const req = lib.request(
        parsed,
        {
          method: "POST",
          timeout: 3000,
          headers: {
            "Content-Type": "application/json",
            "Content-Length": body.length,
            "User-Agent": "heartbeat",
          },
        },
        (res) => {
          res.resume();
          res.on("end", done);
          res.on("error", done);
        },
      );
      req.on("error", done);
      req.on("timeout", () => {
        req.destroy();
        done();
      });
      req.end(body);
    } catch {
      done();
    }
  });
}

function start(options, deps) {
  try {
    const env = (deps && deps.env) || process.env;
    const now = (deps && deps.now) || new Date();
    const home = (deps && deps.home) || os.homedir();
    const sender = (deps && deps.post) || post;
    if (!home) return;
    if (suppressed(options.version, env, options.optOut)) return;
    const url = resolveEndpoint(env, options.endpointEnv);
    if (!url) return;
    const dir = path.join(home, ...options.stateParts);
    if (!due(dir, now.getTime())) return;
    try {
      markSent(dir, now);
    } catch {
      // still attempt the send; the next launch may retry if the stamp is missing
    }
    const body = buildBody(options.project, options.version, installId(dir));
    if (!body) return;
    const pending = sender(url, body);
    if (pending && typeof pending.catch === "function") pending.catch(() => {});
  } catch {
    // failure-open: telemetry never blocks the product
  }
}

module.exports = {
  DEFAULT_ENDPOINT,
  MAX_BODY,
  suppressed,
  resolveEndpoint,
  due,
  markSent,
  installId,
  buildBody,
  post,
  start,
  formatStamp,
  parseStamp,
};
