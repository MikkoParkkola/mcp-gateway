// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Part C's harness rows (part C design, "The harness contract"): the additions the journeys use, each proved here
// where no journey row proves it yet. M1 gw.mcp and the key-acceptance read (C-H2); R1-R5 and R3b restart (C-H1;
// R6 and the command check also run as units in startcmd.test.mjs); Q1 stub silent mode (C-H4); S5 the J4 seed.
import { readFileSync, realpathSync } from 'node:fs';
import { mkdtemp, readFile, rm, symlink } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { test, expect, answers, parseStartCommand, startGateway, TIMING_FILE, until } from './gateway.mjs';

const BIN = process.env.JOURNEYS_GATEWAY_BIN;

/** The path the child was spawned by (its argv[0]), read from the OS: /proc on Linux, ps on macOS. */
function spawnedAs(pid) {
  if (process.platform === 'linux') return readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0')[0];
  return spawnSync('ps', ['-ww', '-o', 'args=', '-p', String(pid)], { encoding: 'utf8' }).stdout.trim().split(' ')[0];
}

/** How many timing lines this test's own gateway wrote (other workers append to the same file). */
async function timingLines(marker) {
  const text = await readFile(TIMING_FILE, 'utf8').catch(() => '');
  return text.split('\n').filter((l) => l.includes(`"marker":"${marker}"`)).length;
}

test.describe('restart (C-H1)', () => {
  test('R1 R1b R2 a refused command stops nothing and spawns nothing', async () => {
    let spawned = 0;
    const gw = await startGateway({ seed: 'fresh', onSpawn: () => { spawned += 1; } });
    try {
      const first = gw.pid;
      const refused = [
        [[process.execPath, 'serve', '--config', gw.configPath], /not this test's gateway binary/],
        [[relative(process.cwd(), BIN), 'serve', '--config', gw.configPath], /not an absolute path/],
        [[BIN, 'serve', '--config', gw.configPath, '--extra'], /5 words/],
        [[BIN, 'serve', '--config', join(gw.decoy, 'gateway.yaml')], /not this test's config/],
      ];
      for (const [argv, why] of refused) await expect(gw.restart({ argv })).rejects.toThrow(why);
      // R6: a command with anything after the words never reaches restart at all.
      expect(() => parseStartCommand(`'${BIN}' serve --config '${gw.configPath}'; rm x`)).toThrow(/";"/);
      expect(spawned, 'a refused command spawned a gateway').toBe(1);
      expect(gw.pid).toBe(first);
      expect(gw.listenerPids()).toEqual([first]);
    } finally {
      await gw.stop();
    }
  });

  test('R3 R4 a restart with the shown command replaces the child, keeps the home, and writes no timing line', async () => {
    const gw = await startGateway({ seed: 'fresh' });
    try {
      const old = gw.pid;
      expect(await timingLines(gw.marker)).toBe(1);
      await gw.restart({ argv: parseStartCommand(`'${BIN}' serve --config '${gw.configPath}'`) });
      expect(gw.pid).not.toBe(old);
      expect(() => process.kill(old, 0), 'the old gateway is still alive').toThrow();
      expect(gw.listenerPids()).toEqual([gw.pid]);
      expect((await (await gw.api('/ui/api/gateway')).json()).environment?.name).toBe(gw.marker);
      expect(await timingLines(gw.marker), 'the restart wrote a timing line').toBe(1);
    } finally {
      await gw.stop();
    }
  });

  test('R3b a symlink alias of the binary is spawned as its real path', async () => {
    const gw = await startGateway({ seed: 'fresh' });
    const dir = await mkdtemp(join(tmpdir(), 'jh-alias-'));
    try {
      const alias = join(dir, 'gateway-alias');
      await symlink(BIN, alias);
      await gw.restart({ argv: [alias, 'serve', '--config', gw.configPath] });
      expect(spawnedAs(gw.pid)).toBe(realpathSync(BIN));
    } finally {
      await gw.stop();
      await rm(dir, { recursive: true, force: true });
    }
  });

  test('R5 teardown after a restart leaves no gateway and the port refuses', async () => {
    const gw = await startGateway({ seed: 'fresh' });
    const first = gw.pid;
    try {
      await gw.restart();
    } finally {
      await gw.stop();
    }
    for (const pid of [first, gw.pid]) expect(() => process.kill(pid, 0), `gateway ${pid} is still alive`).toThrow();
    expect(await answers(gw.port), 'the port still answers').toBe(false);
  });
});

test.describe('stub silent mode (C-H4)', () => {
  test.use({ seed: 'populated' });

  test('Q1 a call answers; with the stub silenced the same call reaches its log and gets no answer', async ({ gw }) => {
    const call = { key: gw.adminKey, method: 'tools/call',
      params: { name: 'gateway_invoke', arguments: { server: 'tide', tool: 'tide_table', arguments: {} } } };
    const calls = async () => (await gw.stubLog('tide')).split('\n').filter((l) => l.includes('"tools/call"')).length;
    const answered = await gw.mcp(call);
    expect(JSON.stringify(answered.body), 'the unsilenced call did not answer').toContain('tide-answered');
    const mark = await calls();
    await gw.silence('tide');
    // The silent stub never answers, so the gateway's wait outlasts gw.mcp's 5 s request limit: a rejection is expected.
    const silent = await gw.mcp(call).catch((error) => ({ error }));
    expect(JSON.stringify(silent.body ?? null), 'a silenced stub answered').not.toContain('tide-answered');
    await until(Date.now() + 10_000, 'the silenced stub never logged the call', async () => (await calls()) > mark);
  });
});

test.describe('seed silentStub (C-H3, J4)', () => {
  test.use({ seed: 'silentStub' });

  test('S5 the J4 seed turns health checks off in init\'s config and the gateway serves both stubs with it', async ({ gw }) => {
    expect(await readFile(gw.configPath, 'utf8')).toMatch(/^failsafe:\n {2}health_check:\n {4}enabled: false$/m);
    const servers = JSON.stringify(await (await gw.api('/ui/api/backends')).json());
    for (const name of ['tide', 'harbour']) expect(servers).toContain(name);
  });
});

test.describe('keyed reads', () => {
  test.use({ seed: 'fresh' });

  test('M1 the admin key lists tools on /mcp; GET /ui/api/status takes only an accepted key', async ({ gw }) => {
    const listed = await gw.mcp({ key: gw.adminKey, method: 'tools/list' });
    expect(listed.status, JSON.stringify(listed.body)).toBe(200);
    expect(listed.body?.error, 'tools/list answered with a protocol error').toBeUndefined();
    expect(Array.isArray(listed.body?.result?.tools), JSON.stringify(listed.body)).toBe(true);
    // Accepted is exactly 200; 401 is the refusal; any other status fails the read (design C-H2).
    expect((await gw.api('/ui/api/status')).status).toBe(200);
    expect((await gw.api('/ui/api/status', { key: 'jh-not-a-key' })).status).toBe(401);
    expect((await gw.api('/ui/api/status', { key: null })).status).toBe(401);
    // Nothing here about a wrong key on /mcp: that behaviour is under triage and no row may pin it yet.
  });
});
