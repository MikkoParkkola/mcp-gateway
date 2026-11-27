// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Units for the coverage check (waiting.mjs) and the run's one check over its JSON report (outcomes.mjs): the harness
// smoke is one real test, each journey id ran XOR waits, and everything that ran passed with nothing skipped. Each red
// row changes one thing from today's clean set. Stdlib only, no gateway: node --test journeys/waiting.test.mjs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JOURNEYS, WAITING, idOf, checkCoverage } from './waiting.mjs';
import { checkOutcomes } from './outcomes.mjs';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const OUTCOMES_CLI = join(dirname(fileURLToPath(import.meta.url)), 'outcomes.mjs');

const real = (title) => title;
const TODAY = [real('harness smoke: try a tool'), real('J4 diagnose: x'), real('H3 harness row: y')];
const check = (over = {}) => checkCoverage({ titles: TODAY, waiting: WAITING, ...over });
const without = (id) => WAITING.filter((w) => w.id !== id);
// A problem names its id (or file) first, then a colon ("J10: ..." is never taken as being about J1), then its kind;
// both are matched, so a red row cannot pass on a different problem about the same id.
const named = (problems, id, kind) => problems.some((p) => p.startsWith(`${id}:`) && p.includes(kind));

test('today: the smoke and J4 are real, every other journey waits, and the check is clean', () => {
  assert.deepEqual(check(), []);
  assert.deepEqual(new Set([...WAITING.map((w) => w.id), 'J4']), new Set(JOURNEYS));
});

test('idOf reads the id a title starts with, by its delimiter', () => {
  assert.equal(idOf('harness smoke: try a tool'), 'harness smoke');
  assert.equal(idOf('harness smokey: a lookalike'), null);
  assert.equal(idOf('J10 maintenance: x'), 'J10');
  assert.equal(idOf('J1 first run: x'), 'J1');
  assert.equal(idOf('J5a decision list: x'), 'J5a');
  assert.equal(idOf('J11 something: x'), 'J11');
  assert.equal(idOf('JOURNEY.7 coverage: y'), null);
});

test('a journey neither real nor waiting is reported', () => {
  assert.ok(named(check({ waiting: without('J6') }), 'J6', 'neither a real test nor waiting'));
});

test('a journey both real and waiting is reported', () => {
  assert.ok(named(check({ titles: [...TODAY, real('J6 blocked: x')] }), 'J6', 'both a real test and waiting'));
});

test('two real tests with one id are reported', () => {
  assert.ok(named(check({ titles: [...TODAY, real('J4 again: x')] }), 'J4', '2 real tests'));
});

test('two waiting entries with one id are reported', () => {
  const twice = [...WAITING, WAITING.find((w) => w.id === 'J6')];
  assert.ok(named(check({ waiting: twice }), 'J6', '2 waiting entries'));
});

test('a waiting id that is not a journey is reported', () => {
  assert.ok(named(check({ waiting: [...WAITING, { id: 'J12', waitsFor: 'x', release: 'v4.0.0' }] }), 'J12', 'waiting, but it is not a journey'));
});

test('a real test with an unknown journey id is reported (J11, and J5 once J5 is split)', () => {
  assert.ok(named(check({ titles: [...TODAY, real('J11 something: x')] }), 'J11', 'has an id that is not a journey'));
  assert.ok(named(check({ titles: [...TODAY, real('J5 approve: x')] }), 'J5', 'has an id that is not a journey'));
});

test('J10 never counts as J1, nor J1 as J10', () => {
  const j10Real = check({ titles: [...TODAY, real('J10 maintenance: x')], waiting: without('J10') });
  assert.deepEqual(j10Real, []);
  assert.ok(named(check({ titles: [...TODAY, real('J10 maintenance: x')], waiting: without('J1') }), 'J1', 'neither a real test nor waiting'));
});

test('each half counts on its own', () => {
  assert.deepEqual(check({ titles: [...TODAY, real('J5a list: x')], waiting: without('J5a') }), []);
  assert.ok(named(check({ titles: [...TODAY, real('J5a list: x')], waiting: without('J5a').filter((w) => w.id !== 'J5b') }), 'J5b', 'neither a real test nor waiting'));
});

test('a waiting entry needs a reason and a vN.N.N release', () => {
  const j6 = WAITING.find((w) => w.id === 'J6');
  assert.ok(named(check({ waiting: [...without('J6'), { ...j6, waitsFor: ' ' }] }), 'J6', 'waiting with no reason'));
  assert.ok(named(check({ waiting: [...without('J6'), { ...j6, release: '4.0.0' }] }), 'J6', 'is not vN.N.N'));
});

test('the smoke is required, once, and can never wait', () => {
  assert.ok(named(check({ titles: TODAY.filter((t) => !t.startsWith('harness')) }), 'harness smoke', '0 real tests'));
  assert.ok(named(check({ titles: [...TODAY, real('harness smoke: again')] }), 'harness smoke', '2 real tests'));
  const waits = check({ waiting: [...WAITING, { id: 'harness smoke', waitsFor: 'x', release: 'v4.0.0' }] });
  assert.ok(named(waits, 'harness smoke', 'can never wait'));
});

// outcomes.mjs: the run's report. One reported test = its spec title, overall status and each attempt's status.
const spec = (title, status = 'expected', attempts = ['passed']) => ({
  title, tests: [{ projectName: 'journeys', status, results: attempts.map((s) => ({ status: s })) }],
});
const report = (specs, { skipped = 0, suites = [] } = {}) => ({
  stats: { expected: specs.length, unexpected: 0, flaky: 0, skipped },
  suites: [{ title: 'journeys', specs, suites }],
});
const ran = () => TODAY.map((t) => spec(t));
const swapJ4 = (status, attempts) => ran().map((s) => (s.title.startsWith('J4') ? spec(s.title, status, attempts) : s));

test('outcomes: a clean run is clean', () => {
  assert.deepEqual(checkOutcomes(report(ran())), []);
});

test('outcomes: a skip anywhere in the run is reported, even in a row with no journey id', () => {
  assert.ok(named(checkOutcomes(report(ran(), { skipped: 1 })), 'run', 'skipped'));
});

for (const [why, status, attempts] of [['skipped', 'skipped', []], ['expected to fail (test.fail)', 'expected', ['failed']],
  ['flaky (passed on a retry)', 'flaky', ['failed', 'passed']], ['failed', 'unexpected', ['failed']]]) {
  test(`outcomes: a journey that ${why} is reported`, () => {
    assert.ok(named(checkOutcomes(report(swapJ4(status, attempts))), 'J4', 'did not pass as expected'));
  });
}

test('outcomes: coverage comes from what ran: a missing J4, a waiting J6 that ran, no smoke', () => {
  assert.ok(named(checkOutcomes(report(ran().filter((s) => !s.title.startsWith('J4')))), 'J4', 'neither a real test nor waiting'));
  assert.ok(named(checkOutcomes(report([...ran(), spec('J6 blocked: x')])), 'J6', 'both a real test and waiting'));
  assert.ok(named(checkOutcomes(report(ran().filter((s) => !s.title.startsWith('harness')))), 'harness smoke', '0 real tests'));
});

test('outcomes: the smoke is held to the same rule, and an expected test with no attempt is not a pass', () => {
  const smokeAs = (status, attempts) => ran().map((s) => (s.title.startsWith('harness') ? spec(s.title, status, attempts) : s));
  assert.ok(named(checkOutcomes(report(smokeAs('unexpected', ['failed']))), 'harness smoke', 'did not pass as expected'));
  assert.ok(named(checkOutcomes(report(smokeAs('skipped', []))), 'harness smoke', 'did not pass as expected'));
  assert.ok(named(checkOutcomes(report(swapJ4('expected', []))), 'J4', 'did not pass as expected'));
});

test('outcomes: a journey inside a nested describe suite is found', () => {
  const outer = ran().filter((s) => !s.title.startsWith('J4'));
  assert.deepEqual(checkOutcomes(report(outer, { suites: [{ title: 'a group', specs: [spec('J4 diagnose: x')], suites: [] }] })), []);
});

/** The CLI over `body` in a temp file (or over `args` as given): { status, out }. */
function outcomesCli(body, args) {
  const dir = mkdtempSync(join(tmpdir(), 'jh-outcomes-'));
  try {
    const file = join(dir, 'journeys.json');
    if (body !== undefined) writeFileSync(file, body);
    const r = spawnSync(process.execPath, [OUTCOMES_CLI, ...(args ?? [file])], { encoding: 'utf8', env: { ...process.env, JH_FAULT: '' } });
    return { status: r.status, out: `${r.stdout}${r.stderr}` };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('outcomes CLI: an unknown JOURNEY7 fault is refused with exit 2', () => {
  const dir = mkdtempSync(join(tmpdir(), 'jh-outcomes-'));
  try {
    const file = join(dir, 'journeys.json');
    writeFileSync(file, JSON.stringify(report(ran())));
    const r = spawnSync(process.execPath, [OUTCOMES_CLI, file], { encoding: 'utf8', env: { ...process.env, JH_FAULT: 'JOURNEY7:drop-J9' } });
    assert.equal(r.status, 2, `${r.stdout}${r.stderr}`);
    assert.match(`${r.stdout}${r.stderr}`, /is not an outcomes fault/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('outcomes CLI: 0 on a clean report; 1 with each problem; 2 on no argument, a missing file or malformed JSON', () => {
  assert.equal(outcomesCli(JSON.stringify(report(ran()))).status, 0);
  const failing = outcomesCli(JSON.stringify(report(ran().filter((s) => !s.title.startsWith('J4')))));
  assert.equal(failing.status, 1);
  assert.match(failing.out, /J4: neither a real test nor waiting/);
  for (const [r, why] of [[outcomesCli(undefined, []), /usage/], [outcomesCli(undefined), /cannot read/], [outcomesCli('{ not json'), /not JSON/], [outcomesCli('null'), /not a Playwright JSON report/],
    [outcomesCli('{}'), /not a Playwright JSON report/]]) {
    assert.equal(r.status, 2, r.out);
    assert.match(r.out, why);
  }
});

