// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The journey harness's own rows (spec rows J-h and the seed classes): every test here starts the REAL
// gateway binary named by JOURNEYS_GATEWAY_BIN in a private home and proves it is talking to that child.
// H3 marker, H4 listener pid, H5 a taken port, H6 two tests never share, H11 a gateway that never comes up,
// S1 the fresh-install seed (init's starter config), S2 the populated seed.
import net from 'node:net';
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
      const backends = await (await gw.api('/ui/api/backends')).json();
      const names = JSON.stringify(backends);
      for (const stub of gw.stubs) expect(names).toContain(stub);
    });
  });
});
