// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The start-and-seed gate (fail-fast): the nearest-rank p95 of seed_ms + start_ms over every journey
// test of the run must be at most 10 s. Run as a script after the project: node journeys/timing.mjs.
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { TIMING_FILE } from './gateway.mjs';

export const LIMIT_MS = 10_000;

/** Nearest-rank 95th percentile. */
export function p95(values) {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.ceil(0.95 * sorted.length) - 1];
}

/** { ok, reason } for the timing lines; a missing or bad line fails, since no data is not a pass. */
export function gate(lines) {
  const totals = [];
  for (const line of lines) {
    let t;
    try { t = JSON.parse(line).jh_timing; } catch { return { ok: false, reason: `unparsable timing line: ${line}` }; }
    if (!Number.isFinite(t?.seed_ms) || !Number.isFinite(t?.start_ms)) return { ok: false, reason: `incomplete timing line: ${line}` };
    totals.push(t.seed_ms + t.start_ms);
  }
  if (totals.length === 0) return { ok: false, reason: 'no timing lines: no journey test started a gateway' };
  const p = p95(totals);
  return p > LIMIT_MS
    ? { ok: false, reason: `start+seed p95 ${p} ms > ${LIMIT_MS} ms over ${totals.length} tests` }
    : { ok: true, reason: `start+seed p95 ${p} ms <= ${LIMIT_MS} ms over ${totals.length} tests` };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const text = await readFile(TIMING_FILE, 'utf8').catch(() => '');
  const result = gate(text.split('\n').filter(Boolean));
  console.log(`jh-timing: ${result.reason}`);
  process.exit(result.ok ? 0 : 1);
}
