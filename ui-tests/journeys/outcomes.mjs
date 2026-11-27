// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The journeys run's one check (JOURNEY.7 with decision D-W1), over the run's own JSON report: nothing was skipped,
// the smoke and every journey that ran passed as expected on its only attempt, and each journey id ran XOR waits
// (waiting.mjs). What ran is the authority, so a skip of any kind, decided in the code or at runtime, is seen. Run as
// a step after the project, as timing.mjs is; its non-zero exit fails the job:
//   node journeys/outcomes.mjs test-results/journeys.json   (0 clean, 1 problems, 2 no usable report)
// Planted fault (D-F1, faults.test.mjs): JH_FAULT=JOURNEY7:drop-J4 drops J4's tests from the report before checking.
import { readFileSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { WAITING, checkCoverage, idOf } from './waiting.mjs';

/** Every journeys-project test in the report, nested suites included: { title, status, attempts }. */
function reportTests(report) {
  const found = [];
  const walk = (suite) => {
    for (const s of suite.specs ?? []) {
      for (const t of s.tests ?? []) {
        if (t.projectName === 'journeys') found.push({ title: s.title, status: t.status, attempts: (t.results ?? []).map((r) => r.status) });
      }
    }
    (suite.suites ?? []).forEach(walk);
  };
  (report.suites ?? []).forEach(walk);
  return found;
}

/** Every problem in the run, each starting with its id (or "run"); empty when the run is clean. */
export function checkOutcomes(report, waiting = WAITING) {
  const tests = reportTests(report);
  const problems = [];
  const skipped = report.stats?.skipped;
  if (skipped !== 0) problems.push(`run: ${skipped ?? 'an unknown number of'} tests skipped; a journey that waits goes on WAITING`);
  for (const t of tests) {
    const id = idOf(t.title);
    if (id === null) continue;
    if (t.status !== 'expected' || t.attempts.length !== 1 || t.attempts[0] !== 'passed') {
      problems.push(`${id}: "${t.title}" did not pass as expected (status ${t.status}, attempts ${t.attempts.join(',') || 'none'})`);
    }
  }
  return [...problems, ...checkCoverage({ titles: tests.map((t) => t.title), waiting })];
}

function main(argv) {
  const file = argv[2];
  if (!file) return { code: 2, lines: ['usage: node journeys/outcomes.mjs <journeys report.json>'] };
  let text;
  try { text = readFileSync(file, 'utf8'); } catch (e) { return { code: 2, lines: [`jh-outcomes: cannot read ${file}: ${e.message}`] }; }
  let report;
  try { report = JSON.parse(text); } catch (e) { return { code: 2, lines: [`jh-outcomes: ${file} is not JSON: ${e.message}`] }; }
  const fault = process.env.JH_FAULT ?? '';
  if (fault === 'JOURNEY7:drop-J4') {
    const drop = (suite) => ({ ...suite, specs: (suite.specs ?? []).filter((s) => idOf(s.title) !== 'J4'), suites: (suite.suites ?? []).map(drop) });
    report = { ...report, suites: (report.suites ?? []).map(drop) };
  } else if (fault !== '' && fault.startsWith('JOURNEY7:')) {
    return { code: 2, lines: [`jh-outcomes: JH_FAULT=${fault} is not an outcomes fault`] };
  }
  const problems = checkOutcomes(report);
  if (problems.length > 0) return { code: 1, lines: problems };
  const ran = reportTests(report).filter((t) => idOf(t.title) !== null).length;
  return { code: 0, lines: [`jh-outcomes: clean: ${ran} smoke/journey tests passed, ${WAITING.length} journeys waiting, 0 skipped`] };
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  const { code, lines } = main(process.argv);
  (code === 0 ? console.log : console.error)(lines.join('\n'));
  process.exitCode = code;
}
