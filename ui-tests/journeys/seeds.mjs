// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Seed classes (HARNESS.4). Every seed starts from `mcp-gateway init`'s starter config, which the harness
// has already written (design ITEM P1), and appends what its class needs. Each returns the stub servers it started
// and, where the state needs the gateway running, a `ready(gw, deadline)` that proves the state exists.
import { appendFile, readFile, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { until } from './gateway.mjs';

export const STUB = join(dirname(fileURLToPath(import.meta.url)), 'stub-mcp.mjs');

/** One stdio stub server per name; each logs every request to <home>/stub-<name>.log. */
function backends(home, names) {
  const lines = names.map((n) => `  ${n}:\n    command: "${process.execPath} ${STUB} ${join(home, `stub-${n}.log`)}"\n`);
  return `\nbackends:\n${lines.join('')}`;
}

const SEEDS = {
  // A fresh install: init's starter config and nothing else.
  fresh: async ({ configPath, marker }) => {
    await appendFile(configPath, `\nenvironment: ${marker}\n`);
    return { stubs: [] };
  },
  // A populated gateway: two stub MCP servers this test starts.
  populated: async ({ home, configPath, marker }) => {
    const stubs = ['tide', 'harbour'];
    await appendFile(configPath, `\nenvironment: ${marker}\n${backends(home, stubs)}`);
    return { stubs };
  },
  // J4 (part C): a populated gateway whose health checks are off, so it learns that a stub stopped answering
  // (gw.silence) only from a failing call. init writes no failsafe block; if it ever does, this fails loudly.
  silentStub: async (ctx) => {
    const seeded = await SEEDS.populated(ctx);
    if (/^failsafe:/m.test(await readFile(ctx.configPath, 'utf8'))) {
      throw new Error('init\'s starter config now has a failsafe block: set health_check inside it instead of appending one');
    }
    await appendFile(ctx.configPath, '\nfailsafe:\n  health_check:\n    enabled: false\n');
    // tide's calls time out at 2 s, not the 30 s default: three failed calls (the health tracker's "unhealthy")
    // then fit well inside a test, and each fails inside the gateway before gw.mcp's own 5 s limit.
    const text = await readFile(ctx.configPath, 'utf8');
    const tide = /^ {2}tide:\n {4}command: .*\n/m;
    if (!tide.test(text)) throw new Error('the populated seed wrote no tide backend block to set its timeout in');
    await writeFile(ctx.configPath, text.replace(tide, (block) => `${block}    timeout: 2s\n`), { mode: 0o600 });
    return seeded;
  },
  // J1 (part C): init's starter config and a client config file in the home naming two stub servers that are not
  // backends, which discovery turns into adopt entries (h-planted is listed too: rows count their own servers).
  firstRun: async ({ home, configPath, marker }) => {
    await appendFile(configPath, `\nenvironment: ${marker}\n`);
    const stubs = ['ebb', 'flood'];
    const mcpServers = Object.fromEntries(stubs.map((n) => [n, { command: process.execPath, args: [STUB, join(home, `stub-${n}.log`)] }]));
    await writeFile(join(home, '.config', 'mcp', 'first-run.json'), JSON.stringify({ mcpServers }));
    return {
      stubs,
      ready: async (gw, deadline) => until(deadline, 'discovery never offered ebb and flood to adopt', async () => {
        const answer = await gw.api('/ui/api/decisions');
        if (answer.status !== 200) return false;
        const adopt = JSON.stringify((await answer.json()).decisions.filter((d) => d.kind === 'adopt'));
        return stubs.every((n) => adopt.includes(n));
      }),
    };
  },
  // J3 (part C): populated plus one more stub, ready to add and not in the config; data.add is its name and the
  // command line a user would type.
  addable: async (ctx) => {
    const seeded = await SEEDS.populated(ctx);
    const command = `${process.execPath} ${STUB} ${join(ctx.home, 'stub-drift.log')}`;
    return { stubs: [...seeded.stubs, 'drift'], data: { add: { name: 'drift', command } } };
  },
  // J9 (part C): populated plus two configured API keys; data.keys holds each name and secret. Ready when both are
  // accepted (exactly 200 on GET /ui/api/status).
  twoKeys: async (ctx) => {
    const seeded = await SEEDS.populated(ctx);
    const keys = [newKey(ctx.bin, 'north'), newKey(ctx.bin, 'south')];
    await addKeys(ctx.configPath, keys);
    return { ...seeded, data: { keys }, ready: keysAccepted(keys) };
  },
  // J8 (part C): populated, cost governance on with a default cost per call (turning it on needs a restart, so it is
  // in the seed), and one configured key whose real calls are charged to it; ready when the costs read shows it.
  spend: async (ctx) => {
    const seeded = await SEEDS.populated(ctx);
    if (/^cost_governance:/m.test(await readFile(ctx.configPath, 'utf8'))) {
      throw new Error('init\'s starter config now has a cost_governance block: set it there instead of appending one');
    }
    const key = newKey(ctx.bin, 'spender');
    await addKeys(ctx.configPath, [key]);
    await appendFile(ctx.configPath, '\ncost_governance:\n  enabled: true\n  default_cost: 0.25\n');
    return {
      ...seeded,
      data: { key },
      ready: async (gw, deadline) => {
        await keysAccepted([key])(gw, deadline);
        for (let i = 0; i < 2; i += 1) {
          const charged = await gw.invoke('tide', 'tide_table', { key: key.secret });
          if (charged.status !== 200) throw new Error(`a charged call was refused (${charged.status})`);
        }
        await until(deadline, 'GET /ui/api/costs shows no spend for the spender key', async () =>
          JSON.stringify((await (await gw.api('/ui/api/costs')).json()).by_key ?? {}).includes('spender'));
      },
    };
  },
  // J10 (part C): populated, an HTTP backend `signin` with OAuth on, whose provider metadata a local stub serves and
  // for which no token is stored (so it reads never_signed_in), then a restart-only change made while it runs.
  needsYou: async (ctx) => signInSeed(ctx, { provider: 'up' }),
  // For the harness's own row O1 only: the same backend with its provider stopped before the start.
  'needsYou-provider-down': async (ctx) => signInSeed(ctx, { provider: 'down' }),
  // For the harness's own row H11 only: a config the gateway refuses, so it never becomes healthy.
  'refused-config': async ({ configPath }) => {
    await writeFile(configPath, 'server: [unterminated\n', { mode: 0o600 });
    return { stubs: [] };
  },
  // A populated gateway with a pending decision: an unmanaged server in a client config file in the home, which
  // client-config discovery turns into an "adopt" decision (written before the start: discovery scans at start).
  pendingDecision: async (ctx) => {
    const seeded = await SEEDS.populated(ctx);
    await writeFile(join(ctx.home, '.config', 'mcp', 'pending.json'),
      JSON.stringify({ mcpServers: { 'pending-adopt': { command: 'npx', args: ['pending-adopt'] } } }));
    return {
      ...seeded,
      ready: async (gw, deadline) => until(deadline, 'no adopt decision for pending-adopt', async () => {
        const reply = await gw.api('/ui/api/decisions');
        if (reply.status !== 200) return false; // 503 until every decision source is ready
        const { decisions } = await reply.json();
        return decisions.some((d) => d.kind === 'adopt' && JSON.stringify(d).includes('pending-adopt'));
      }),
    };
  },
  // A populated gateway with a blocked call in its history, made by a real MCP request that a rule stops.
  blockedCall: async (ctx) => {
    const seeded = await SEEDS.populated(ctx);
    const text = await readFile(ctx.configPath, 'utf8');
    if (!/^security:\n/m.test(text)) throw new Error('init\'s starter config has no security block to add the rule to');
    await writeFile(ctx.configPath, text.replace(/^security:\n/m, 'security:\n  tool_policy:\n    deny:\n      - tide_secret\n'),
      { mode: 0o600 });
    return {
      ...seeded,
      ready: async (gw, deadline) => {
        const reply = await gw.invoke('tide', 'tide_secret');
        if (reply.status < 200 || reply.status > 299) {
          throw new Error(`the seeding MCP call was refused (${reply.status}): ${JSON.stringify(reply.body).slice(0, 300)}`);
        }
        await until(deadline, 'no blocked tide_secret call in Activity', async () => {
          const { rows } = await (await gw.api('/ui/api/activity?server=tide')).json();
          return rows.some((r) => r.tool === 'tide_secret' && r.outcome === 'blocked');
        });
      },
    };
  },
};

/**
 * One MCP client exchange on POST /mcp (part C, C-H2; gw.mcp): initialize (keeping its mcp-session-id),
 * notifications/initialized, then `method`, each with `Authorization: Bearer <key>` (none when `key` is omitted).
 * Resolves to the { status, body } of the first answer that is not 2xx, else of the request's own answer: a refusal
 * is a status the caller reads, never a throw. Not a key-acceptance read: /mcp is public on init's starter config.
 */
export async function mcpExchange(origin, { key, method, params }) {
  const headers = { 'content-type': 'application/json', accept: 'application/json, text/event-stream' };
  if (key) headers.authorization = `Bearer ${key}`;
  const post = async (body, extra = {}) => {
    const res = await fetch(`${origin}/mcp`, { method: 'POST', headers: { ...headers, ...extra }, body: JSON.stringify(body),
      signal: AbortSignal.timeout(5_000) });
    return { res, reply: { status: res.status, body: rpcBody(await res.text()) } };
  };
  const init = await post({ jsonrpc: '2.0', id: 1, method: 'initialize',
    params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'journey-seed', version: '1' } } });
  if (!init.res.ok) return init.reply;
  const session = init.res.headers.get('mcp-session-id');
  const withSession = session ? { 'mcp-session-id': session } : {};
  const noted = await post({ jsonrpc: '2.0', method: 'notifications/initialized' }, withSession);
  if (!noted.res.ok) return noted.reply;
  return (await post({ jsonrpc: '2.0', id: 2, method, ...(params === undefined ? {} : { params }) }, withSession)).reply;
}

/** The JSON-RPC message of an MCP answer: the body itself, or the last `data:` line of an event stream; else the text. */
function rpcBody(text) {
  const json = text.trimStart().startsWith('{') ? text
    : text.split('\n').filter((line) => line.startsWith('data:')).map((line) => line.slice(5)).pop();
  try { return JSON.parse(json); } catch { return text; }
}

/** One configured API key: a fresh secret and its digest from the gateway's own `hash-key` (never re-implemented). */
function newKey(bin, name) {
  const secret = `jh-${name}-${randomBytes(16).toString('hex')}`;
  const r = spawnSync(bin, ['hash-key'], { input: secret, encoding: 'utf8', env: { PATH: process.env.PATH }, timeout: 30_000 });
  const digest = (r.stdout ?? '').trim();
  if (r.status !== 0 || !/^sha256:[0-9a-f]{64}$/.test(digest)) throw new Error(`mcp-gateway hash-key failed (exit ${r.status}): ${r.stderr}`);
  return { name, secret, digest };
}

/** Adds API keys to init's auth block after its `single_user: true` line; a missing line fails loudly. */
async function addKeys(configPath, keys) {
  const text = await readFile(configPath, 'utf8');
  const anchor = /^ {2}single_user: true\n/m;
  if (!anchor.test(text)) throw new Error('init\'s starter config has no "single_user: true" line to add API keys after');
  const entries = keys.map((k) => `    - name: ${k.name}\n      key_sha256: "${k.digest}"\n      backends: ["*"]\n`).join('');
  await writeFile(configPath, text.replace(anchor, (line) => `${line}  api_keys:\n${entries}`), { mode: 0o600 });
}

/** A ready(): every key answers exactly 200 on GET /ui/api/status; the error names the last status each got. */
function keysAccepted(keys) {
  return async (gw, deadline) => {
    const last = {};
    await until(deadline, 'a seeded key is not accepted', async () => {
      for (const k of keys) last[k.name] = (await gw.api('/ui/api/status', { key: k.secret })).status;
      return keys.every((k) => last[k.name] === 200);
    }).catch((e) => { throw new Error(`${e.message}: ${JSON.stringify(last)}`); });
  };
}

/** A local OAuth provider: only the authorization-server metadata, every other path 404 (the gateway's discovery
 * then takes the origin as the issuer). The fixture owns it through ctx.own. */
async function oauthProvider() {
  const server = createServer((req, res) => {
    const origin = `http://127.0.0.1:${server.address().port}`;
    if (req.method !== 'GET' || req.url !== '/.well-known/oauth-authorization-server') { res.writeHead(404).end(); return; }
    res.writeHead(200, { 'content-type': 'application/json' })
      .end(JSON.stringify({ issuer: origin, authorization_endpoint: `${origin}/authorize`, token_endpoint: `${origin}/token` }));
  });
  await new Promise((done) => server.listen(0, '127.0.0.1', done));
  const { port } = server.address();
  return { port, close: () => new Promise((done) => { server.closeAllConnections(); server.close(() => done()); }) };
}

/** The sign-in state of server `name` in GET /ui/api/status (its row's sign_in and needs_sign_in), or null. */
export async function signInOf(gw, name) {
  const { servers } = await (await gw.api('/ui/api/status')).json();
  const row = (servers ?? []).find((s) => s.name === name);
  return row ? { status: row.sign_in?.status ?? null, needsSignIn: row.needs_sign_in } : null;
}

async function signInSeed(ctx, { provider }) {
  const seeded = await SEEDS.populated(ctx);
  if (!/\n {2}harbour:\n {4}command: .*\n$/.test(await readFile(ctx.configPath, 'utf8'))) {
    throw new Error('the populated seed\'s backends block is not the end of the config: nowhere to add the signin backend');
  }
  const oauth = await oauthProvider();
  ctx.own(oauth);
  if (provider === 'down') await oauth.close();
  await appendFile(ctx.configPath, `  signin:\n    http_url: "http://127.0.0.1:${oauth.port}/mcp"\n    oauth:\n      enabled: true\n`);
  if (provider === 'down') return seeded;
  return {
    ...seeded,
    ready: async (gw, deadline) => {
      await until(deadline, 'signin never read never_signed_in', async () => (await signInOf(gw, 'signin'))?.status === 'never_signed_in');
      if (/^cost_governance:/m.test(await readFile(ctx.configPath, 'utf8'))) {
        throw new Error('init\'s starter config now has a cost_governance block: toggle another restart-only field');
      }
      await appendFile(ctx.configPath, '\ncost_governance:\n  enabled: true\n');
      await until(deadline, 'no restart is pending after a restart-only change', async () =>
        ((await (await gw.api('/ui/api/gateway')).json()).pending_restart?.fields ?? []).length > 0);
    },
  };
}

export async function applySeed(name, ctx) {
  const seed = SEEDS[name];
  if (!seed) throw new Error(`unknown seed class ${name}: one of ${Object.keys(SEEDS).join(', ')}`);
  return seed(ctx);
}
