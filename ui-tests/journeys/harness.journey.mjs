// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The journey harness's own rows (spec rows J-h and the seed classes): every test here starts the REAL
// gateway binary named by JOURNEYS_GATEWAY_BIN in a private home and proves it is talking to that child.
// H3 marker, H4 listener pid, H5 a taken port, H6 two tests never share, H11 a gateway that never comes up,
// S1 the fresh-install seed (init's starter config), S2 the populated seed.
import net from 'node:net';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { test, expect, startGateway } from './gateway.mjs';

test.describe('harness identity', () => {
  test.use({ seed: 'fresh' });

  test('H3 the gateway serves back the marker written only into this test home', async ({ gw }) => {
    const reply = await gw.api('/ui/api/gateway');
    expect(reply.status).toBe(200);
    expect((await reply.json()).environment?.name).toBe(gw.marker);
  });

  test('H4 the only process listening on the port is the child this test started', async ({ gw }) => {
    expect(await gw.listenerPids()).toEqual([gw.pid]);
  });
});

test.describe('two tests never share a gateway or a home', () => {
  // One worker, in order: a worker-scoped gateway would then be seen by both.
  test.describe.configure({ mode: 'serial' });
  test.use({ seed: 'fresh' });
  const seen = [];

  test('H6 first', async ({ gw }) => { seen.push({ port: gw.port, pid: gw.pid, home: gw.home, decoy: gw.decoy }); });

  test('H6 second differs from the first in port, pid, home and decoy', async ({ gw }) => {
    const [first] = seen;
    expect(first, 'the first H6 test did not run in this worker').toBeTruthy();
    expect(gw.port).not.toBe(first.port);
    expect(gw.pid).not.toBe(first.pid);
    expect(gw.home).not.toBe(first.home);
    expect(gw.decoy).not.toBe(first.decoy);
  });
});

test('H5 a listener already on the chosen port fails the start, and no gateway is spawned', async () => {
  const squatter = net.createServer();
  await new Promise((done) => squatter.listen(0, '127.0.0.1', done));
  const { port } = squatter.address();
  try {
    let spawned = 0;
    await expect(startGateway({ seed: 'fresh', port, onSpawn: () => { spawned += 1; } }))
      .rejects.toThrow(`port ${port} already has a listener`);
    expect(spawned).toBe(0);
  } finally {
    await new Promise((done) => squatter.close(done));
  }
});

test('H11 a gateway that never comes up fails with the harness diagnostic and its log', async () => {
  test.setTimeout(60_000);
  const started = Date.now();
  const error = await startGateway({ seed: 'refused-config' }).then(() => null, (e) => e);
  expect(error, 'a gateway with a config it refuses must not start').toBeTruthy();
  expect(error.message).toContain('gateway not healthy within 20000 ms');
  expect(error.gatewayLog, 'the failure carries the gateway log').toBeTruthy();
  expect(Date.now() - started).toBeLessThan(60_000);
});

test.describe('seeds', () => {
  test.describe('fresh', () => {
    test.use({ seed: 'fresh' });
    test('S1 the fresh seed is init\'s starter config: auth on, transparency log on, files-store bearer', async ({ gw }) => {
      const yaml = await readFile(gw.configPath, 'utf8');
      expect(yaml).toMatch(/^auth:\n(?:\s+.*\n)*?\s+enabled: true/m);
      expect(yaml).toMatch(/bearer_token: "file:/);
      expect(yaml).toMatch(/^\s+transparency_log:\n\s+enabled: true/m);
      expect((await gw.api('/ui/api/status')).status).toBe(200);
      expect((await gw.api('/ui/api/status', { key: null })).status).toBe(401);
    });
  });

  test.describe('populated', () => {
    test.use({ seed: 'populated' });
    test('S2 the populated seed lists its stub servers', async ({ gw }) => {
      const names = JSON.stringify(await gw.serverNames());
      for (const stub of gw.stubs) expect(names).toContain(stub);
    });
  });

  test.describe('pendingDecision', () => {
    test.use({ seed: 'pendingDecision' });
    test('S3 the decisions list holds one adopt item for the planted server', async ({ gw }) => {
      const { decisions } = await (await gw.api('/ui/api/decisions')).json();
      const adopt = decisions.filter((d) => d.kind === 'adopt' && JSON.stringify(d).includes('pending-adopt'));
      expect(adopt).toHaveLength(1);
    });
  });

  test.describe('blockedCall', () => {
    test.use({ seed: 'blockedCall' });
    test('S4 Activity holds the blocked real call, and its receipt names the tool_policy rule', async ({ gw }) => {
      const { rows } = await (await gw.api('/ui/api/activity?server=tide')).json();
      const blocked = rows.filter((r) => r.tool === 'tide_secret' && r.outcome === 'blocked');
      expect(blocked.length, 'no blocked tide_secret call in Activity').toBeGreaterThan(0);
      const receipt = await (await gw.api(`/ui/api/activity/${encodeURIComponent(blocked[0].id)}`)).json();
      expect(JSON.stringify(receipt.decision ?? {})).toContain('tool_policy');
    });
  });
});

test.describe('the gateway reads only the test home', () => {
  test.use({ seed: 'fresh' });

  test('H7 it lists the test home\'s discovery entry and never the decoy\'s', async ({ gw }) => {
    const seen = JSON.stringify(await (await gw.api('/ui/api/discovery')).json());
    expect(seen).toContain('h-planted');
    expect(seen).not.toContain('decoy-planted');
    expect(await gw.serverNames()).not.toContain('decoy-planted');
  });

  // From gpt r3's MEDIUM (init does write the store-backed bearer: cli_support/init.rs:22-86), these controls make
  // the decoy key's 401 mean "the gateway never read D's store", not "the decoy key was malformed".
  test('H8 the decoy home\'s real key is refused while the test home\'s is accepted', async ({ gw }) => {
    expect(gw.decoyKey.length, 'the decoy secret is empty').toBeGreaterThan(0);
    expect(gw.decoyKey).not.toBe(gw.adminKey);
    expect((await gw.api('/ui/api/status')).status).toBe(200);
    expect((await gw.api('/ui/api/status', { key: gw.decoyKey })).status).toBe(401);
  });
});

/** The child's real environment, read from the OS: /proc on Linux, ps -E on macOS. */
function childEnvironment(pid) {
  if (process.platform === 'linux') return readFileSync(`/proc/${pid}/environ`, 'utf8').split('\0').join('\n');
  return spawnSync('ps', ['-wwE', '-p', String(pid), '-o', 'command='], { encoding: 'utf8' }).stdout;
}

test('H9 nothing from the parent environment reaches the gateway', async () => {
  process.env.JH_PARENT_SENTINEL = 'jh-parent-only-value';
  const gw = await startGateway({ seed: 'fresh' });
  try {
    const env = childEnvironment(gw.pid);
    expect(env, 'could not read the child environment').toContain('MCP_GATEWAY_TEST_HOME_DIR');
    expect(env).not.toContain('JH_PARENT_SENTINEL');
    expect(env).not.toContain('jh-parent-only-value');
  } finally {
    delete process.env.JH_PARENT_SENTINEL;
    await gw.stop();
  }
});

test('H10 after a passing test the gateway is gone and its port refuses', async () => {
  const gw = await startGateway({ seed: 'fresh' });
  await gw.stop();
  expect(() => process.kill(gw.pid, 0), 'the gateway process is still alive').toThrow();
  const answered = await new Promise((resolve) => {
    const c = net.connect(gw.port, '127.0.0.1');
    c.once('connect', () => { c.destroy(); resolve(true); });
    c.once('error', () => resolve(false));
  });
  expect(answered, 'the port still answers').toBe(false);
});
