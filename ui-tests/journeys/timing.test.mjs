// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Row T1 (the ticket's fail-fast): the start-and-seed gate. Each journey test writes one line
// {"jh_timing": {"seed_ms": n, "start_ms": n}}; the gate takes the p95 of seed_ms + start_ms and fails above
// 10 s. A missing or unparsable timing line fails too: no data is not a pass.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { gate, p95 } from './timing.mjs';

const line = (seed, start) => JSON.stringify({ jh_timing: { seed_ms: seed, start_ms: start } });

test('p95 is the nearest-rank 95th percentile, not the mean', () => {
  const totals = Array.from({ length: 20 }, (_, i) => (i + 1) * 1000);
  assert.equal(p95(totals), 19000);
  assert.equal(p95([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 50]), 1);
});

test('the gate passes at or under 10 s and fails over it', () => {
  assert.equal(gate([line(2000, 8000)]).ok, true);
  const slow = gate(Array.from({ length: 20 }, () => line(4000, 7000)));
  assert.equal(slow.ok, false);
  assert.match(slow.reason, /p95 11000 ms > 10000 ms/);
});

test('one slow test in twenty does not fail the gate, two do', () => {
  const fast = Array.from({ length: 19 }, () => line(1000, 2000));
  assert.equal(gate([...fast, line(20000, 20000)]).ok, true);
  const twoSlow = [...fast.slice(1), line(20000, 20000), line(20000, 20000)];
  assert.equal(gate(twoSlow).ok, false);
});

test('exactly 10 000 ms passes; an average under 10 s with a p95 over it fails', () => {
  assert.equal(gate([line(4000, 6000)]).ok, true);
  const mixed = [...Array.from({ length: 18 }, () => line(1000, 1000)), line(15000, 15000), line(15000, 15000)];
  assert.equal(gate(mixed).ok, false);
});

test('no timing lines, or a line that does not parse, fails', () => {
  assert.equal(gate([]).ok, false);
  assert.equal(gate(['not json']).ok, false);
  assert.equal(gate([JSON.stringify({ jh_timing: { seed_ms: 1 } })]).ok, false);
});
