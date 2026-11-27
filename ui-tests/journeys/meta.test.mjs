// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Run-level rows for the journey harness: what must make a whole `--project=journeys` run fail, never
// skip. Each nested run is the real project on one harness row; a companion run with the real binary must pass,
// so a failure is the variable's doing, not a broken project. Needs JOURNEYS_GATEWAY_BIN set to the real binary.
// H1 unset, H1b missing or not executable, H2 lsof absent; H4's listener comparison as a unit.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import net from 'node:net';
import { chmod, mkdtemp, readFile, writeFile, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gatewayEnv, listenerIsChild } from './gateway.mjs';

const UI_TESTS = dirname(dirname(fileURLToPath(import.meta.url)));
const REAL_BIN = process.env.JOURNEYS_GATEWAY_BIN;

function journeysRun(env) {
  const r = spawnSync('npx', ['playwright', 'test', '--project=journeys', 'journeys/harness.journey.mjs', '-g', 'H3'],
    { cwd: UI_TESTS, env: { ...process.env, ...env }, encoding: 'utf8', timeout: 240_000 });
  return { status: r.status, out: `${r.stdout}\n${r.stderr}` };
}

function assertFailedWith(run, diagnostic) {
  assert.notEqual(run.status, 0, `the run passed:\n${run.out}`);
  assert.match(run.out, diagnostic, `the harness's own diagnostic is missing:\n${run.out}`);
  assert.doesNotMatch(run.out, /\bskipped\b/i, `the run skipped instead of failing:\n${run.out}`);
}

test('the companion run with the real binary passes', () => {
  assert.ok(REAL_BIN, 'meta needs JOURNEYS_GATEWAY_BIN set to the real gateway binary');
  const run = journeysRun({ JOURNEYS_GATEWAY_BIN: REAL_BIN });
  assert.equal(run.status, 0, run.out);
});

test('H1 an unset JOURNEYS_GATEWAY_BIN fails the run', () => {
  const env = { ...process.env };
  delete env.JOURNEYS_GATEWAY_BIN;
  const r = spawnSync('npx', ['playwright', 'test', '--project=journeys', 'journeys/harness.journey.mjs', '-g', 'H3'],
    { cwd: UI_TESTS, env, encoding: 'utf8', timeout: 240_000 });
  assertFailedWith({ status: r.status, out: `${r.stdout}\n${r.stderr}` }, /JOURNEYS_GATEWAY_BIN is not set/);
});

test('H1b a missing or non-executable binary fails the run', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'jh-meta-'));
  const missing = join(dir, 'no-such-gateway');
  assertFailedWith(journeysRun({ JOURNEYS_GATEWAY_BIN: missing }), /does not exist/);
  const plain = join(dir, 'not-executable');
  await writeFile(plain, '#!/bin/sh\n');
  await chmod(plain, 0o644);
  assertFailedWith(journeysRun({ JOURNEYS_GATEWAY_BIN: plain }), /not executable/);
});

test('H2 a PATH without lsof fails the run; the same PATH with lsof passes', async () => {
  // A PATH holding only node, npx and the shell tools, so lsof is the one difference between the two runs.
  const bin = await mkdtemp(join(tmpdir(), 'jh-path-'));
  const which = (name) => spawnSync('sh', ['-c', `command -v ${name}`], { encoding: 'utf8' }).stdout.trim();
  for (const tool of ['node', 'npx', 'sh', 'env', 'uname', 'ps']) {
    const at = which(tool);
    if (at) await symlink(at, join(bin, tool));
  }
  assertFailedWith(journeysRun({ JOURNEYS_GATEWAY_BIN: REAL_BIN, PATH: bin }), /lsof is required/);
  await symlink(which('lsof'), join(bin, 'lsof'));
  const run = journeysRun({ JOURNEYS_GATEWAY_BIN: REAL_BIN, PATH: bin });
  assert.equal(run.status, 0, run.out);
});

test('H4 the listener check accepts only exactly the child', () => {
  assert.equal(listenerIsChild([4242], 4242), true);
  assert.equal(listenerIsChild([4242, 999], 4242), false);
  assert.equal(listenerIsChild([999], 4242), false);
  assert.equal(listenerIsChild([], 4242), false);
  assert.equal(listenerIsChild([4242, 4242], 4242), true);
});

test('H9 the child environment is built from nothing but PATH', () => {
  process.env.JH_PARENT_SENTINEL = 'jh-parent-only-value';
  try {
    const env = gatewayEnv({ home: '/h', decoy: '/d', path: '/usr/bin' });
    assert.equal(Object.hasOwn(env, 'JH_PARENT_SENTINEL'), false);
    assert.equal(Object.values(env).includes('jh-parent-only-value'), false);
    for (const key of Object.keys(process.env)) {
      if (!['PATH', 'HOME', 'USERPROFILE', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'APPDATA', 'LOCALAPPDATA',
        'MCP_GATEWAY_TEST_HOME_DIR', 'MCP_GATEWAY_SECRETS__STORE', 'DO_NOT_TRACK'].includes(key)) {
        assert.equal(Object.hasOwn(env, key), false, `${key} leaked from the parent`);
      }
    }
    assert.equal(env.HOME, '/d');
    assert.equal(env.MCP_GATEWAY_TEST_HOME_DIR, '/h');
  } finally {
    delete process.env.JH_PARENT_SENTINEL;
  }
});

test('H10 a failing test and a timed-out test both leave no gateway behind', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'jh-plant-'));
  const record = join(dir, 'gateways.jsonl');
  const r = spawnSync('npx', ['playwright', 'test', '-c', 'journeys/planted/planted.config.mjs'],
    { cwd: UI_TESTS, env: { ...process.env, JOURNEYS_GATEWAY_BIN: REAL_BIN, JH_PLANT_RECORD: record },
      encoding: 'utf8', timeout: 300_000 });
  assert.notEqual(r.status, 0, 'the planted run must fail (one test fails, one times out)');
  const started = (await readFile(record, 'utf8')).split('\n').filter(Boolean).map((l) => JSON.parse(l));
  assert.equal(started.length, 2, `both planted tests must have started a gateway:\n${r.stdout}\n${r.stderr}`);
  for (const { pid, port } of started) {
    assert.throws(() => process.kill(pid, 0), `gateway ${pid} is still alive`);
    const answered = await new Promise((resolve) => {
      const c = net.connect(port, '127.0.0.1');
      c.once('connect', () => { c.destroy(); resolve(true); });
      c.once('error', () => resolve(false));
    });
    assert.equal(answered, false, `port ${port} still answers`);
  }
});
