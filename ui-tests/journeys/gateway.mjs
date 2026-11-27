// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The journey harness (spec D3): each test gets the REAL gateway binary, started by this file in a private
// home H with a seed, while HOME points at a decoy home D that must leave no trace. One shared fixture owns the process,
// the stub servers, both homes, the port and the teardown; no journey manages them itself.
// Inputs: JOURNEYS_GATEWAY_BIN only. Unset, missing or not executable fails the run; nothing here ever skips.
import { spawn, spawnSync } from 'node:child_process';
import { constants, openSync, closeSync, realpathSync } from 'node:fs';
import { access, appendFile, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { createHash, randomBytes } from 'node:crypto';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test as base, expect } from '../tests/base.mjs';
import { applySeed, mcpExchange } from './seeds.mjs';

export { expect };

const HERE = dirname(fileURLToPath(import.meta.url));
const HEALTH_MS = 20_000;
const SETTLE_MS = 20_000; // discovery's first scan, and each seed's own readiness
const STOP_MS = 5_000;
const REQUEST_MS = 5_000; // one HTTP request: a listener that accepts and never answers must not outlast a deadline
export const TIMING_FILE = join(HERE, '..', 'test-results', 'jh-timing.jsonl');

// Every gateway this worker started and has not stopped: the exit hook kills them if a test is torn down abruptly.
const live = new Set();
process.on('exit', () => { for (const pid of live) { try { process.kill(-pid, 'SIGKILL'); } catch { /* gone */ } } });

/** The binary, checked; any problem throws with the harness's own words. */
export async function gatewayBinary() {
  const bin = process.env.JOURNEYS_GATEWAY_BIN;
  if (!bin) throw new Error('JOURNEYS_GATEWAY_BIN is not set: point it at a debug mcp-gateway build');
  try { await access(bin, constants.F_OK); } catch { throw new Error(`JOURNEYS_GATEWAY_BIN ${bin} does not exist`); }
  try { await access(bin, constants.X_OK); } catch { throw new Error(`JOURNEYS_GATEWAY_BIN ${bin} is not executable`); }
  return bin;
}

/** lsof proves which process holds the port (no HTTP route exposes a pid); its absence fails the run. */
export function requireLsof() {
  const found = spawnSync('sh', ['-c', 'command -v lsof'], { encoding: 'utf8' });
  if (found.status !== 0 || !found.stdout.trim()) throw new Error('lsof is required: it is how the harness proves the listener is its own child');
}

/** True only when the listening set is exactly the child: a foreign listener beside it is refused. */
export function listenerIsChild(pids, childPid) {
  const set = new Set(pids);
  return set.size === 1 && set.has(childPid);
}

/** The child's whole environment, built from nothing: no key or value of the parent's passes except PATH. */
export function gatewayEnv({ home, decoy, path }) {
  return {
    PATH: path,
    MCP_GATEWAY_TEST_HOME_DIR: home,
    HOME: decoy,
    USERPROFILE: decoy,
    XDG_CONFIG_HOME: join(home, '.config'),
    XDG_DATA_HOME: join(home, '.local', 'share'),
    XDG_CACHE_HOME: join(home, '.cache'),
    APPDATA: join(home, 'AppData', 'Roaming'),
    LOCALAPPDATA: join(home, 'AppData', 'Local'),
    MCP_GATEWAY_SECRETS__STORE: 'files',
    DO_NOT_TRACK: '1',
  };
}

/** The Activity row of one call, by the trace id its own response carried; never "any row for that tool". */
export function activityRowFor(rows, traceId) {
  return (rows || []).find((row) => traceId && row.trace_id === traceId) ?? null;
}

// Characters a bare (unquoted) word of the start command may hold; anything else outside quotes is refused.
const BARE = /[A-Za-z0-9_./:@%+=,-]/;

/**
 * Splits the start command the gateway shows (`'<exe>' serve --config '<config>'`, restart_advice.rs) into words
 * with no shell (R6). A word is bare characters and single-quoted runs; the only escape is the gateway's own `'\''`
 * apostrophe between two quoted runs. Throws, naming the problem, on an unbalanced quote, any other backslash, or
 * any character a shell would act on (`$`, `;`, `&`, `|`, a backtick, a double quote, a newline ...).
 */
export function parseStartCommand(text) {
  const words = [];
  let word = null;
  let closedRun = false; // the previous character closed a quoted run, so `\'` may follow
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i];
    if (c === ' ' || c === '\t') {
      if (word !== null) words.push(word);
      word = null;
      closedRun = false;
    } else if (c === "'") {
      const end = text.indexOf("'", i + 1);
      if (end < 0) throw new Error(`unbalanced quote at column ${i + 1}: ${text}`);
      word = (word ?? '') + text.slice(i + 1, end);
      i = end;
      closedRun = true;
    } else if (c === '\\') {
      if (!closedRun || text[i + 1] !== "'" || text[i + 2] !== "'") {
        throw new Error(`refused backslash at column ${i + 1}: only the gateway's '\\'' apostrophe form is accepted`);
      }
      word += "'";
      i += 1; // the next turn reads the opening quote of the following run
      closedRun = false;
    } else if (BARE.test(c)) {
      word = (word ?? '') + c;
      closedRun = false;
    } else {
      throw new Error(`refused character ${JSON.stringify(c)} outside quotes at column ${i + 1}`);
    }
  }
  if (word !== null) words.push(word);
  if (words.length === 0) throw new Error('no command to run');
  return words;
}

/**
 * The C-H1 check of a parsed start command: exactly the gateway's four words [<exe>, serve, --config, <config>],
 * <exe> an absolute path whose real path is this test's binary, <config>'s real path this test's config. Returns the
 * binary's real path, which is what gets spawned (never the word as written). Throws, naming the token, otherwise.
 */
export function checkStartArgv(argv, { bin, configPath }) {
  const real = (p) => { try { return realpathSync(p); } catch { return null; } };
  if (argv.length !== 4) throw new Error(`the command has ${argv.length} words, not the gateway's four: ${JSON.stringify(argv)}`);
  const [exe, sub, flag, config] = argv;
  if (!isAbsolute(exe)) throw new Error(`"${exe}" is not an absolute path`);
  const exeReal = real(exe);
  if (!exeReal || exeReal !== real(bin)) throw new Error(`"${exe}" is not this test's gateway binary`);
  if (sub !== 'serve') throw new Error(`"${sub}" where the gateway writes "serve"`);
  if (flag !== '--config') throw new Error(`"${flag}" where the gateway writes "--config"`);
  const configReal = real(config);
  if (!configReal || configReal !== real(configPath)) throw new Error(`"${config}" is not this test's config`);
  return exeReal;
}

async function freePort() {
  const s = net.createServer();
  await new Promise((done) => s.listen(0, '127.0.0.1', done));
  const { port } = s.address();
  await new Promise((done) => s.close(done));
  return port;
}

/** True when something accepts a TCP connection on 127.0.0.1:port. */
export function answers(port) {
  return new Promise((resolve) => {
    const c = net.connect(port, '127.0.0.1');
    c.once('connect', () => { c.destroy(); resolve(true); });
    c.once('error', () => resolve(false));
  });
}

function listenerPids(port) {
  const r = spawnSync('lsof', ['-nP', `-iTCP:${port}`, '-sTCP:LISTEN', '-t'], { encoding: 'utf8' });
  return r.stdout.split('\n').map((s) => Number(s.trim())).filter((n) => n > 0);
}

async function fingerprint(dir) {
  const out = {};
  async function walk(d) {
    for (const e of await readdir(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) await walk(p);
      else out[relative(dir, p)] = createHash('sha256').update(await readFile(p)).digest('hex');
    }
  }
  await walk(dir);
  return JSON.stringify(out, Object.keys(out).sort());
}

/** init's bearer: `bearer_token: "file:<path>"` in the config, the secret in that file. */
async function bearerFrom(configPath) {
  const m = (await readFile(configPath, 'utf8')).match(/bearer_token:\s*"file:([^"]+)"/);
  if (!m) throw new Error(`${configPath} holds no files-store bearer_token`);
  const at = isAbsolute(m[1]) ? m[1] : join(dirname(configPath), m[1]);
  const secret = (await readFile(at, 'utf8')).trim();
  if (!secret) throw new Error(`the bearer secret at ${at} is empty`);
  return secret;
}

function runInit(bin, env, configPath) {
  const r = spawnSync(bin, ['init', '-o', configPath, '--with-examples=false'], { env, encoding: 'utf8', timeout: 30_000 });
  if (r.status !== 0) throw new Error(`mcp-gateway init failed (exit ${r.status}): ${r.stderr || r.stdout}`);
}

/** init writes `  port: 39400` under `server:`; the test's port replaces it, so every start reads it from the config. */
async function setPort(configPath, port) {
  const text = await readFile(configPath, 'utf8');
  if (!/^ {2}port: 39400$/m.test(text)) throw new Error(`${configPath} has no init "port: 39400" line to put the test's port in`);
  await writeFile(configPath, text.replace(/^ {2}port: 39400$/m, `  port: ${port}`), { mode: 0o600 });
}

/** Polls `probe` until it returns something truthy (returned) or `deadline` passes (throws `what`). A probe that
 * throws counts as "not yet", unless its error is marked `fatal`. Shared by the fixture, the seeds and the rows. */
export async function until(deadline, what, probe) {
  for (;;) {
    const got = await probe().catch((e) => { if (e?.fatal) throw e; return null; });
    if (got) return got;
    if (Date.now() > deadline) throw new Error(what);
    await new Promise((done) => setTimeout(done, 200));
  }
}

/**
 * Starts one gateway for one test and proves it is that test's own child reading only its own home.
 * Rejects with the harness's own diagnostic (and the gateway log as error.gatewayLog) on any failure.
 * `port` and `onSpawn` exist for the harness's own rows (a taken port; counting spawns).
 */
async function start({ seed, port, onSpawn }, owned) {
  const bin = await gatewayBinary();
  requireLsof();
  const t0 = Date.now();
  const home = await mkdtemp(join(tmpdir(), 'jh-home-'));
  const decoy = await mkdtemp(join(tmpdir(), 'jh-decoy-'));
  owned.homes = [home, decoy];
  const path = process.env.PATH;
  const env = gatewayEnv({ home, decoy, path });
  const configPath = join(home, 'gateway.yaml');

  // D: a whole gateway home of its own (its own init key) plus a planted client config. Nothing of it may reach the gateway: no
  // discovery entry, no accepted key, no changed file (design 6d). A read that shows none of these is not detected.
  runInit(bin, gatewayEnv({ home: decoy, decoy, path }), join(decoy, 'gateway.yaml'));
  await mkdir(join(decoy, '.cursor'), { recursive: true });
  await writeFile(join(decoy, '.cursor', 'mcp.json'), JSON.stringify({ mcpServers: { 'decoy-planted': { command: 'npx', args: ['decoy'] } } }));
  const decoyKey = await bearerFrom(join(decoy, 'gateway.yaml'));
  const decoyPrint = await fingerprint(decoy);

  // H: the seed. Every seed starts from init's starter config (design ITEM P1); the marker exists only here.
  runInit(bin, env, configPath);
  const adminKey = await bearerFrom(configPath);
  if (adminKey === decoyKey) throw new Error('the decoy key equals the test key: the decoy check would prove nothing');
  const marker = `jh-${randomBytes(6).toString('hex')}`;
  await mkdir(join(home, '.config', 'mcp'), { recursive: true });
  await writeFile(join(home, '.config', 'mcp', 'h-planted.json'), JSON.stringify({ mcpServers: { 'h-planted': { command: 'npx', args: ['h'] } } }));
  // The port lives in the config: the start command the gateway shows names none (part C, C-H1).
  const chosen = port ?? await freePort();
  await setPort(configPath, chosen);
  const seeded = await applySeed(seed ?? 'fresh', { home, configPath, marker });
  const seedMs = Date.now() - t0;

  if (await answers(chosen)) throw new Error(`port ${chosen} already has a listener: refusing to start (a journey never attaches to a gateway it did not start)`);
  const logPath = join(home, 'gateway.log');
  const exe = realpathSync(bin);
  let child = null;
  let exited = null;
  // One gateway process for this home: its absolute real path, no shell and so no PATH lookup, output appended.
  const launch = (args) => {
    const out = openSync(logPath, 'a');
    const proc = spawn(exe, args, { env, detached: true, stdio: ['ignore', out, out] });
    closeSync(out);
    onSpawn?.();
    child = proc;
    exited = null;
    live.add(proc.pid);
    proc.on('exit', (code, signal) => { live.delete(proc.pid); if (child === proc) exited = { code, signal }; });
  };
  const t1 = Date.now();
  launch(['serve', '--config', configPath]);

  const origin = `http://127.0.0.1:${chosen}`;
  const api = (p, { key = adminKey } = {}) => fetch(origin + p, { signal: AbortSignal.timeout(REQUEST_MS), headers: key ? { Authorization: `Bearer ${key}` } : {} });
  const handle = {
    origin, port: chosen, get pid() { return child.pid; }, home, decoy, marker, configPath, adminKey, decoyKey, logPath,
    stubs: seeded.stubs ?? [], api,
    mcp: (request) => mcpExchange(origin, request),
    // C-H1: restarts this test's own gateway and keeps its home. With `argv` (parseStartCommand of the command the
    // page shows) it runs only the gateway's four words naming this test's binary and config, spawning the binary's
    // real path; a refusal throws before anything stops or runs. Re-proves identity as the first start does and
    // writes no timing line (the p95 bar is start+seed only).
    restart: async ({ argv } = {}) => {
      if (argv !== undefined) checkStartArgv(argv, { bin, configPath });
      await handle.kill();
      launch(argv === undefined ? ['serve', '--config', configPath] : argv.slice(1));
      await prove();
    },
    listenerPids: () => listenerPids(chosen),
    stubLog: (name) => readFile(join(home, `stub-${name}.log`), 'utf8').catch(() => ''),
    // C-H4: makes stub `name` stop answering (it still logs what reaches it), or answer again.
    silence: (name, on = true) => (on ? writeFile(join(home, `stub-${name}.silent`), '')
      : rm(join(home, `stub-${name}.silent`), { force: true })),
    // Harness-internal (restart and stop use it): ends the current child and proves its port refuses again.
    kill: async () => {
      if (!exited) {
        try { process.kill(-child.pid, 'SIGTERM'); } catch { /* gone */ }
        const end = Date.now() + STOP_MS;
        while (!exited && Date.now() < end) await new Promise((done) => setTimeout(done, 100));
        if (!exited) { try { process.kill(-child.pid, 'SIGKILL'); } catch { /* gone */ } }
        // SIGKILL is delivered asynchronously: wait for the exit before judging the port.
        const reaped = Date.now() + STOP_MS;
        while (!exited && Date.now() < reaped) await new Promise((done) => setTimeout(done, 100));
      }
      live.delete(child.pid);
      if (await answers(chosen)) throw new Error(`port ${chosen} still answers after the gateway was stopped`);
    },
    stop: async () => {
      await handle.kill();
      const after = await fingerprint(decoy);
      await rm(home, { recursive: true, force: true });
      await rm(decoy, { recursive: true, force: true });
      if (after !== decoyPrint) throw new Error('the decoy home changed while the gateway ran');
    },
  };
  owned.handle = handle;

  const fail = async (why) => {
    const gatewayLog = await readFile(logPath, 'utf8').catch(() => '');
    await handle.stop().catch(() => {});
    const err = new Error(why);
    err.gatewayLog = gatewayLog;
    throw err;
  };

  // The running child is up, serves this test's marker, is the only listener and reads H (design 6a-6d). The first
  // start and every restart run it; it throws the harness's own diagnostic.
  const prove = async () => {
  const since = Date.now();
  try {
    await until(since + HEALTH_MS, `gateway not healthy within ${HEALTH_MS} ms`, async () => {
      if (exited) throw Object.assign(new Error('exited'), { fatal: true });
      return (await fetch(`${origin}/health`, { signal: AbortSignal.timeout(REQUEST_MS) })).status === 200;
    });
  } catch (e) {
    throw new Error(exited ? `gateway exited before it was healthy (${JSON.stringify(exited)}); gateway not healthy within ${HEALTH_MS} ms` : e.message);
  }
  const served = await (await api('/ui/api/gateway')).json().catch(() => ({}));
  if (served?.environment?.name !== marker) throw new Error(`the gateway does not serve this test's marker ${marker} (got ${JSON.stringify(served?.environment)})`);
  const pids = listenerPids(chosen);
  if (!listenerIsChild(pids, child.pid)) throw new Error(`the listener on ${chosen} is ${JSON.stringify(pids)}, not the child ${child.pid}`);
  await until(Date.now() + SETTLE_MS, 'the gateway never listed h-planted: it is not reading the test home', async () =>
      JSON.stringify(await (await api('/ui/api/discovery')).json()).includes('h-planted'));
  };
  try { await prove(); } catch (e) { return fail(e.message); }
  const seen = JSON.stringify(await (await api('/ui/api/discovery')).json()) + JSON.stringify(await (await api('/ui/api/backends')).json());
  if (seen.includes('decoy-planted')) return fail('the gateway read the decoy home: decoy-planted is listed');
  if ((await api('/ui/api/status', { key: decoyKey })).status !== 401) return fail('the decoy home\'s key is accepted');
  if ((await api('/ui/api/status')).status !== 200) return fail('the test home\'s own key is refused');
  try { await seeded.ready?.(handle, Date.now() + SETTLE_MS); } catch (e) { return fail(`seed ${seed} not ready: ${e.message}`); }

  const startMs = Date.now() - t1;
  await mkdir(dirname(TIMING_FILE), { recursive: true });
  await appendFile(TIMING_FILE, `${JSON.stringify({ jh_timing: { seed_ms: seedMs, start_ms: startMs, marker } })}\n`);
  return handle;
}

/** Any rejection, a check's own or an unexpected one (a refused fetch, a disk error), stops the child and removes
 * both homes, so a failed start leaves nothing behind for the next test in this worker. */
export async function startGateway(opts = {}) {
  const owned = {};
  try {
    return await start(opts, owned);
  } catch (e) {
    if (owned.handle) await owned.handle.stop().catch(() => {});
    for (const dir of owned.homes ?? []) await rm(dir, { recursive: true, force: true });
    throw e;
  }
}

export const test = base.extend({
  seed: ['fresh', { option: true }],
  gw: async ({ seed }, use, testInfo) => {
    const gw = await startGateway({ seed }).catch(async (e) => {
      if (e.gatewayLog) await testInfo.attach('gateway.log', { body: e.gatewayLog });
      throw e;
    });
    try {
      await use(gw);
    } finally {
      if (testInfo.status !== testInfo.expectedStatus) {
        await testInfo.attach('gateway.log', { path: gw.logPath }).catch(() => {});
        for (const name of gw.stubs) await testInfo.attach(`stub-${name}.log`, { body: await gw.stubLog(name) });
      }
      await gw.stop();
    }
  },
  baseURL: async ({ gw }, use) => { await use(gw.origin); },
});

