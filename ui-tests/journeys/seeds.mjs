// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Seed classes (HARNESS.4). Every seed starts from `mcp-gateway init`'s starter config, which the harness
// has already written (design ITEM P1), and appends what its class needs. Each returns the stub servers it started
// and, where the state needs the gateway running, a `ready(gw, deadline)` that proves the state exists.
import { appendFile, readFile, writeFile } from 'node:fs/promises';
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
    return seeded;
  },
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
        const reply = await gw.mcp({ key: gw.adminKey, method: 'tools/call',
          params: { name: 'gateway_invoke', arguments: { server: 'tide', tool: 'tide_secret', arguments: {} } } });
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

export async function applySeed(name, ctx) {
  const seed = SEEDS[name];
  if (!seed) throw new Error(`unknown seed class ${name}: one of ${Object.keys(SEEDS).join(', ')}`);
  return seed(ctx);
}
