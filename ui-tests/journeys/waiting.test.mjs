// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Units for the coverage check (waiting.mjs): the harness smoke is one runnable real test, and each journey id is a
// runnable real test or a waiting entry, never both and never neither. Each red row changes one thing from today's
// clean set. Stdlib only, no gateway: node --test journeys/waiting.test.mjs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JOURNEYS, WAITING, idOf, checkCoverage } from './waiting.mjs';

const real = (title, runnable = true) => ({ title, runnable });
const TODAY = [real('harness smoke: try a tool'), real('J4 diagnose: x'), real('JOURNEY.7 coverage: y')];
const CLEAN_SOURCES = { 'j04-diagnose.journey.mjs': "test('J4 diagnose: x', async () => {});" };
const check = (over = {}) => checkCoverage({ tests: TODAY, waiting: WAITING, sources: CLEAN_SOURCES, ...over });
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
  assert.ok(named(check({ tests: [...TODAY, real('J6 blocked: x')] }), 'J6', 'both a real test and waiting'));
});

test('two real tests with one id are reported', () => {
  assert.ok(named(check({ tests: [...TODAY, real('J4 again: x')] }), 'J4', '2 real tests'));
});

test('two waiting entries with one id are reported', () => {
  const twice = [...WAITING, WAITING.find((w) => w.id === 'J6')];
  assert.ok(named(check({ waiting: twice }), 'J6', '2 waiting entries'));
});

test('a waiting id that is not a journey is reported', () => {
  assert.ok(named(check({ waiting: [...WAITING, { id: 'J12', waitsFor: 'x', release: 'v4.0.0' }] }), 'J12', 'waiting, but it is not a journey'));
});

test('a real test with an unknown journey id is reported (J11, and J5 once J5 is split)', () => {
  assert.ok(named(check({ tests: [...TODAY, real('J11 something: x')] }), 'J11', 'has an id that is not a journey'));
  assert.ok(named(check({ tests: [...TODAY, real('J5 approve: x')] }), 'J5', 'has an id that is not a journey'));
});

test('J10 never counts as J1, nor J1 as J10', () => {
  const j10Real = check({ tests: [...TODAY, real('J10 maintenance: x')], waiting: without('J10') });
  assert.deepEqual(j10Real, []);
  assert.ok(named(check({ tests: [...TODAY, real('J10 maintenance: x')], waiting: without('J1') }), 'J1', 'neither a real test nor waiting'));
});

test('each half counts on its own', () => {
  assert.deepEqual(check({ tests: [...TODAY, real('J5a list: x')], waiting: without('J5a') }), []);
  assert.ok(named(check({ tests: [...TODAY, real('J5a list: x')], waiting: without('J5a').filter((w) => w.id !== 'J5b') }), 'J5b', 'neither a real test nor waiting'));
});

test('a waiting entry needs a reason and a vN.N.N release', () => {
  const j6 = WAITING.find((w) => w.id === 'J6');
  assert.ok(named(check({ waiting: [...without('J6'), { ...j6, waitsFor: ' ' }] }), 'J6', 'waiting with no reason'));
  assert.ok(named(check({ waiting: [...without('J6'), { ...j6, release: '4.0.0' }] }), 'J6', 'is not vN.N.N'));
});

test('the smoke is required, once, and can never wait', () => {
  assert.ok(named(check({ tests: TODAY.filter((t) => !t.title.startsWith('harness')) }), 'harness smoke', '0 real tests'));
  assert.ok(named(check({ tests: [...TODAY, real('harness smoke: again')] }), 'harness smoke', '2 real tests'));
  const waits = check({ waiting: [...WAITING, { id: 'harness smoke', waitsFor: 'x', release: 'v4.0.0' }] });
  assert.ok(named(waits, 'harness smoke', 'can never wait'));
});

test('a listed test that is not runnable (declared skipped or expected to fail) is reported', () => {
  const swapped = TODAY.map((t) => (t.title.startsWith('J4') ? real(t.title, false) : t));
  assert.ok(named(check({ tests: swapped }), 'J4', 'skipped or expected to fail'));
});

for (const call of ['test.skip(', 'test.fixme(', 'test.fail(', 'test.describe.skip(', 'testInfo.skip(', 'test.info().fail(',
  'testInfo.skip /* why */ (', "testInfo['skip'](", 'test\n    .skip(']) {
  test(`a journey file calling ${JSON.stringify(call)} is reported`, () => {
    const sources = { 'j04-diagnose.journey.mjs': `${CLEAN_SOURCES['j04-diagnose.journey.mjs']}\n  ${call}true, 'later');` };
    assert.ok(named(check({ sources }), 'j04-diagnose.journey.mjs', 'calls a skip'));
  });
}

test('a skip named only in a comment is not a call', () => {
  const sources = { 'j04-diagnose.journey.mjs': `${CLEAN_SOURCES['j04-diagnose.journey.mjs']}\n  // never test.skip(here)\n  /* nor test.skip( */` };
  assert.deepEqual(check({ sources }), []);
});
