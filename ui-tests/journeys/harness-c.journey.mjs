// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Part C's harness rows (part C design, "The harness contract"): the additions the journeys use, each proved here
// where no journey row proves it yet. M1 gw.mcp and the key-acceptance read (C-H2); R1-R5 and R3b restart (C-H1;
// R6 and the command check also run as units in startcmd.test.mjs); Q1 stub silent mode (C-H4); S5 the J4 seed;
// S6-S9 the J1, J3, J9 and J8 seeds; O1 and S10 the J10 seed and its OAuth provider stub.
import { readFileSync, realpathSync } from 'node:fs';
import { mkdtemp, readFile, rm, symlink } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { test, expect, answers, parseStartCommand, startGateway, TIMING_FILE, until } from './gateway.mjs';
import { signInOf } from './seeds.mjs';

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
    const calls = async () => (await gw.stubLog('tide')).split('\n').filter((l) => l.includes('"tools/call"')).length;
    const answered = await gw.invoke('tide', 'tide_table');
    expect(JSON.stringify(answered.body), 'the unsilenced call did not answer').toContain('tide-answered');
    const mark = await calls();
    await gw.silence('tide');
    // The silent stub never answers, so the gateway's wait outlasts gw.mcp's 5 s request limit: a rejection is expected.
    const silent = await gw.invoke('tide', 'tide_table').catch((error) => ({ error }));
    expect(JSON.stringify(silent.body ?? null), 'a silenced stub answered').not.toContain('tide-answered');
    await until(Date.now() + 10_000, 'the silenced stub never logged the call', async () => (await calls()) > mark);
  });
});

test.describe('seed silentStub (C-H3, J4)', () => {
  test.use({ seed: 'silentStub' });

  test('S5 the J4 seed turns health checks off in init\'s config and the gateway serves both stubs with it', async ({ gw }) => {
    expect(await readFile(gw.configPath, 'utf8')).toMatch(/^failsafe:\n {2}health_check:\n {4}enabled: false$/m);
    expect(await readFile(gw.configPath, 'utf8')).toMatch(/^ {2}tide:\n {4}command: .*\n {4}timeout: 2s$/m);
    const servers = await gw.serverNames();
    for (const name of ['tide', 'harbour']) expect(servers).toContain(name);
  });
});

test.describe('seed firstRun (C-H3, J1)', () => {
  test.use({ seed: 'firstRun' });
  test('S6 discovery offers ebb and flood to adopt, and neither is a backend yet', async ({ gw }) => {
    const adopt = JSON.stringify((await (await gw.api('/ui/api/decisions')).json()).decisions.filter((d) => d.kind === 'adopt'));
    const backends = await gw.serverNames();
    for (const name of ['ebb', 'flood']) {
      expect(adopt).toContain(name);
      expect(backends).not.toContain(name);
    }
  });
});

test.describe('seed addable (C-H3, J3)', () => {
  test.use({ seed: 'addable' });
  test('S7 drift is ready to add: its command names its own stub, and the gateway does not know it', async ({ gw }) => {
    expect(gw.data.add.command).toContain('stub-drift.log');
    expect(await readFile(gw.configPath, 'utf8')).not.toContain('drift');
    expect(await gw.serverNames()).not.toContain('drift');
  });
});

test.describe('seed twoKeys (C-H3, J9)', () => {
  test.use({ seed: 'twoKeys' });
  test('S8 both configured keys are accepted and a wrong one is refused', async ({ gw }) => {
    for (const k of gw.data.keys) expect((await gw.api('/ui/api/status', { key: k.secret })).status, k.name).toBe(200);
    expect((await gw.api('/ui/api/status', { key: `${gw.data.keys[0].secret}x` })).status).toBe(401);
  });
});

test.describe('seed spend (C-H3, J8)', () => {
  test.use({ seed: 'spend' });
  test('S9 the costs read holds spend charged to the spender key', async ({ gw }) => {
    const costs = await (await gw.api('/ui/api/costs')).json();
    expect(JSON.stringify(costs.by_key ?? {}), JSON.stringify(costs)).toContain('spender');
  });
});

test.describe('seed needsYou (C-H3, J10)', () => {
  test.use({ seed: 'needsYou' });
  test('O1 S10 with its provider stub up, signin needs signing in, and a restart-only change is pending', async ({ gw }) => {
    expect(await signInOf(gw, 'signin')).toEqual({ status: 'never_signed_in', needsSignIn: true });
    // The OAuth start asked the system to open the provider's authorization page: the stand-in took it, so no
    // browser ran on the host (and the decoy check at teardown proves nothing wrote into D).
    expect(await gw.browserOpens()).toContain('/authorize');
    const { pending_restart: pending } = await (await gw.api('/ui/api/gateway')).json();
    expect(JSON.stringify(pending?.fields ?? []), JSON.stringify(pending)).toContain('cost_governance');
  });
});

test.describe('seed needsYou, provider down (C-H3, O1 control)', () => {
  test.use({ seed: 'needsYou-provider-down' });
  test('O1 with its provider stopped before the start, signin stays not yet checked and needs no one', async ({ gw }) => {
    await until(Date.now() + 10_000, 'the status read never listed signin', async () => (await signInOf(gw, 'signin')) !== null);
    // An absence: give discovery the time it took in the provider-up row, then read again.
    await new Promise((done) => setTimeout(done, 3000));
    expect(await signInOf(gw, 'signin')).toEqual({ status: 'not_yet_checked', needsSignIn: false });
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
