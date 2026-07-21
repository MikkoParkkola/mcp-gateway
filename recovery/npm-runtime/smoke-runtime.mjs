#!/opt/homebrew/bin/node
// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import { spawn, spawnSync } from "node:child_process";
import { writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { buildIsolatedEnvironment, readJson } from "./lib/runtime.mjs";

const BUNDLE_ROOT = path.dirname(fileURLToPath(import.meta.url));
const MAX_STREAM_BYTES = 4 * 1024 * 1024;
const PHASE_TIMEOUT_MS = 15_000;

function safeKillGroup(child, signal) {
  if (!child.pid) return;
  try {
    process.kill(-child.pid, signal);
  } catch (error) {
    if (error?.code !== "ESRCH") throw error;
  }
}

async function stopChild(child, exited) {
  if (!child.stdin.destroyed) child.stdin.end();
  safeKillGroup(child, "SIGTERM");
  const stopped = await Promise.race([
    exited.then(() => true),
    new Promise((resolve) => setTimeout(() => resolve(false), 2_000)),
  ]);
  if (!stopped) {
    safeKillGroup(child, "SIGKILL");
    const killed = await Promise.race([
      exited.then(() => true),
      new Promise((resolve) => setTimeout(() => resolve(false), 2_000)),
    ]);
    if (!killed) throw new Error("server process did not close after SIGKILL");
  }
}

async function smokeBackend({ backend, pin, installRoot, nodePath, cwd, env }) {
  const entrypoint = path.join(installRoot, "node_modules", pin.package, pin.entrypoint);
  // Morph hides every tool when the variable is absent, but does not contact
  // the API during tools/list. A fixed, explicitly non-secret placeholder
  // exercises registration without reading the operator's real credential.
  const childEnvironment =
    backend === "morphllm"
      ? { ...env, MORPH_API_KEY: "morph-SMOKE-NONSECRET-DO-NOT-USE" }
      : env;
  const child = spawn(nodePath, [entrypoint, ...(pin.args ?? [])], {
    cwd,
    detached: true,
    env: childEnvironment,
    stdio: ["pipe", "pipe", "pipe"],
  });
  let settleLifecycle;
  const exited = new Promise((resolve) => {
    settleLifecycle = resolve;
  });
  child.once("close", (code, signal) => settleLifecycle({ code, signal }));
  const pending = new Map();
  let stdoutBuffer = "";
  let stdoutBytes = 0;
  let stderrBytes = 0;
  let terminalError;

  const fail = (message) => {
    if (terminalError) return;
    terminalError = new Error(`${backend}: ${message}`);
    for (const waiter of pending.values()) waiter.reject(terminalError);
    pending.clear();
    safeKillGroup(child, "SIGKILL");
  };

  child.on("error", () => {
    settleLifecycle({ code: null, signal: "spawn-error" });
    fail("server process failed to start");
  });
  child.stdin.on("error", () => {
    if (pending.size > 0) fail("protocol stdin failed");
  });
  child.on("exit", (code, signal) => {
    if (pending.size > 0) fail(`server exited before responding (${code ?? signal ?? "unknown"})`);
  });
  child.stderr.on("data", (chunk) => {
    stderrBytes += chunk.length;
    if (stderrBytes > MAX_STREAM_BYTES) fail("stderr exceeded the bounded capture limit");
  });
  child.stdout.on("data", (chunk) => {
    stdoutBytes += chunk.length;
    if (stdoutBytes > MAX_STREAM_BYTES) {
      fail("stdout exceeded the bounded capture limit");
      return;
    }
    stdoutBuffer += chunk.toString("utf8");
    for (;;) {
      const newline = stdoutBuffer.indexOf("\n");
      if (newline < 0) break;
      const line = stdoutBuffer.slice(0, newline).trim();
      stdoutBuffer = stdoutBuffer.slice(newline + 1);
      if (!line) continue;
      let message;
      try {
        message = JSON.parse(line);
      } catch {
        fail("server wrote non-JSON data to protocol stdout");
        return;
      }
      if (message.id !== undefined && pending.has(String(message.id))) {
        const waiter = pending.get(String(message.id));
        pending.delete(String(message.id));
        waiter.resolve(message);
      }
    }
  });

  const writeProtocol = (message) =>
    new Promise((resolve, reject) => {
      if (terminalError) {
        reject(terminalError);
        return;
      }
      child.stdin.write(`${JSON.stringify(message)}\n`, (error) => {
        if (error) {
          fail("protocol stdin write failed");
          reject(terminalError);
        } else {
          resolve();
        }
      });
    });

  const request = async (id, method, params) => {
    if (terminalError) return Promise.reject(terminalError);
    const response = new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(String(id));
        fail(`${method} timed out`);
        reject(terminalError);
      }, PHASE_TIMEOUT_MS);
      pending.set(String(id), {
        resolve: (value) => {
          clearTimeout(timer);
          resolve(value);
        },
        reject: (error) => {
          clearTimeout(timer);
          reject(error);
        },
      });
    });
    try {
      await writeProtocol({ jsonrpc: "2.0", id, method, params });
    } catch (error) {
      const waiter = pending.get(String(id));
      pending.delete(String(id));
      waiter?.reject(error);
    }
    return response;
  };

  try {
    const initialized = await request(1, "initialize", {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "mcp-gateway-recovery-smoke", version: "1.0.0" },
    });
    if (initialized.error || !initialized.result?.protocolVersion) {
      throw new Error(`${backend}: initialize returned an error or malformed result`);
    }

    await writeProtocol({ jsonrpc: "2.0", method: "notifications/initialized" });
    const listed = await request(2, "tools/list", {});
    if (listed.error || !Array.isArray(listed.result?.tools) || listed.result.tools.length === 0) {
      throw new Error(`${backend}: tools/list returned an error or empty tool list`);
    }
    const toolNames = listed.result.tools.map((tool) => tool?.name);
    if (toolNames.some((name) => typeof name !== "string" || name.length === 0)) {
      throw new Error(`${backend}: tools/list contained an invalid tool name`);
    }

    return {
      backend,
      success: true,
      protocol_version: initialized.result.protocolVersion,
      server_name: initialized.result.serverInfo?.name ?? null,
      server_version: initialized.result.serverInfo?.version ?? null,
      tool_count: toolNames.length,
      tool_names: toolNames.sort(),
      credential_validation: "not-performed",
      credential_presence_mode:
        backend === "morphllm" ? "synthetic-non-secret-placeholder" : "none",
      stderr_bytes: stderrBytes,
      transcript: [
        { request: "initialize", response_id: 1, success: true },
        { notification: "notifications/initialized" },
        { request: "tools/list", response_id: 2, success: true },
      ],
    };
  } finally {
    await stopChild(child, exited);
  }
}

function runNativeChecks({ pins, installRoot, cwd, env }) {
  return (pins.runtime_checks ?? []).map((check) => {
    const executable = path.join(installRoot, "node_modules", check.package, check.path);
    const result = spawnSync(executable, check.args ?? [], {
      cwd,
      encoding: "utf8",
      env,
      maxBuffer: 1024 * 1024,
      timeout: 10_000,
    });
    if (result.error || result.status !== 0 || !result.stdout.includes(check.stdout_contains)) {
      throw new Error(`${check.name}: native runtime check failed`);
    }
    return {
      name: check.name,
      success: true,
      version_output: result.stdout.trim().split("\n")[0],
    };
  });
}

export async function smokeRuntime({ installRoot, home, tmpdir, cwd, pins }) {
  for (const [label, value] of Object.entries({ installRoot, home, tmpdir, cwd })) {
    if (!path.isAbsolute(value)) throw new Error(`${label} must be absolute`);
  }
  const env = {
    ...buildIsolatedEnvironment({ home, tmpdir }),
    DO_NOT_TRACK: "1",
    NO_TELEMETRY: "1",
  };
  const nativeChecks = runNativeChecks({ pins, installRoot, cwd, env });
  const backends = [];
  for (const [backend, pin] of Object.entries(pins.packages)) {
    backends.push(
      await smokeBackend({
        backend,
        pin,
        installRoot,
        nodePath: pins.toolchain.node.path,
        cwd,
        env,
      }),
    );
  }
  return {
    protocol_version_requested: "2025-11-25",
    environment: "sanitized-no-credentials",
    native_checks: nativeChecks,
    backends,
  };
}

function argument(argv, name) {
  const index = argv.indexOf(name);
  if (index < 0 || !argv[index + 1]) throw new Error(`missing ${name}`);
  return argv[index + 1];
}

async function main() {
  const installRoot = argument(process.argv.slice(2), "--install-root");
  const home = argument(process.argv.slice(2), "--home");
  const tmpdir = argument(process.argv.slice(2), "--tmpdir");
  const cwd = argument(process.argv.slice(2), "--cwd");
  const output = argument(process.argv.slice(2), "--output");
  const pins = await readJson(path.join(BUNDLE_ROOT, "pins.json"));
  const result = await smokeRuntime({ installRoot, home, tmpdir, cwd, pins });
  await writeFile(output, `${JSON.stringify(result, null, 2)}\n`, { flag: "wx", mode: 0o600 });
}

if (fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((error) => {
    console.error(`smoke-runtime: ${error.message}`);
    process.exitCode = 1;
  });
}
