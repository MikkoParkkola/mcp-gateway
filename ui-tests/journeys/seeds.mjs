// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Seed classes (HARNESS.4). Every seed starts from `mcp-gateway init`'s starter config, which the harness
// has already written (design ITEM P1), and appends what its class needs. Each returns the stub servers it started
// and, where the state needs the gateway running, a `ready(gw, deadline)` that proves the state exists.
import { appendFile, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const STUB = join(dirname(fileURLToPath(import.meta.url)), 'stub-mcp.mjs');

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
        await mcpCall(gw.origin, { server: 'tide', tool: 'tide_secret', arguments: {} });
        await until(deadline, 'no blocked tide_secret call in Activity', async () => {
          const { rows } = await (await gw.api('/ui/api/activity?server=tide')).json();
          return rows.some((r) => r.tool === 'tide_secret' && r.outcome === 'blocked');
        });
      },
    };
  },
};

/** One real MCP client exchange on POST /mcp: initialize, initialized, then gateway_invoke of the given call. */
async function mcpCall(origin, call) {
  const headers = { 'content-type': 'application/json', accept: 'application/json, text/event-stream' };
  const post = (body, extra = {}) => fetch(`${origin}/mcp`, { method: 'POST', headers: { ...headers, ...extra }, body: JSON.stringify(body) });
  const init = await post({ jsonrpc: '2.0', id: 1, method: 'initialize',
    params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'journey-seed', version: '1' } } });
  const session = init.headers.get('mcp-session-id');
  const withSession = session ? { 'mcp-session-id': session } : {};
  await post({ jsonrpc: '2.0', method: 'notifications/initialized' }, withSession);
  await post({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'gateway_invoke', arguments: call } }, withSession);
}

async function until(deadline, what, probe) {
  for (;;) {
    if (await probe().catch(() => false)) return;
    if (Date.now() > deadline) throw new Error(what);
    await new Promise((done) => setTimeout(done, 250));
  }
}

export async function applySeed(name, ctx) {
  const seed = SEEDS[name];
  if (!seed) throw new Error(`unknown seed class ${name}: one of ${Object.keys(SEEDS).join(', ')}`);
  return seed(ctx);
}
