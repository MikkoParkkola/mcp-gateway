// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// JOURNEY.7, the coverage row: the journeys project fails unless it holds the harness smoke and every journey, each
// journey a runnable real test or a waiting entry (waiting.mjs), never both and never neither. The tests come from
// Playwright's own listing of this project (no fixture runs, so no gateway starts); the journey files' text is checked
// for skips the listing cannot see. Planted fault (D-F1, faults.test.mjs): JH_FAULT=JOURNEY7:drop-J4 drops J4's listed
// test before the check, which must then report J4 missing.
import { test, expect } from '@playwright/test';
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { journeysRun } from './nested.mjs';
import { WAITING, checkCoverage, idOf } from './waiting.mjs';

const JOURNEYS_DIR = dirname(fileURLToPath(import.meta.url));

/** Every journeys-project test in the JSON listing, as { title, runnable }. */
function listedTests(report) {
  const found = [];
  const walk = (suite) => {
    for (const spec of suite.specs ?? []) {
      for (const t of spec.tests ?? []) {
        if (t.projectName === 'journeys') found.push({ title: spec.title, runnable: t.expectedStatus === 'passed' });
      }
    }
    (suite.suites ?? []).forEach(walk);
  };
  (report.suites ?? []).forEach(walk);
  return found;
}

test('JOURNEY.7 coverage: the project holds the harness smoke and every journey, real or waiting', () => {
  const dir = mkdtempSync(join(tmpdir(), 'jh-list-'));
  let run;
  let report;
  try {
    run = journeysRun(['--list', '--reporter=json'], { PLAYWRIGHT_JSON_OUTPUT_NAME: join(dir, 'list.json'), JH_FAULT: '' });
    report = JSON.parse(readFileSync(join(dir, 'list.json'), 'utf8'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  expect(run.status, `the listing failed:\n${run.out}`).toBe(0);
  let tests = listedTests(report);
  if (process.env.JH_FAULT === 'JOURNEY7:drop-J4') tests = tests.filter((t) => idOf(t.title) !== 'J4');
  else if ((process.env.JH_FAULT ?? '') !== '') throw new Error(`JH_FAULT=${process.env.JH_FAULT} is not a coverage fault`);
  const sources = Object.fromEntries(readdirSync(JOURNEYS_DIR).filter((f) => f.endsWith('.journey.mjs'))
    .map((f) => [f, readFileSync(join(JOURNEYS_DIR, f), 'utf8')]));
  const problems = checkCoverage({ tests, waiting: WAITING, sources });
  expect(problems, `JOURNEY7: the project does not cover the smoke and every journey:\n${problems.join('\n')}`).toEqual([]);
});
