// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// One verdict per mutant leg, from Playwright's JSON report:
//   node judge.mjs <report.json> <spec file name> <killing line>
// KILLED: the named row ran, and every result that did not pass failed on an
// expect() whose location is <spec>:<line>. SURVIVED: it ran and every result
// passed. INVALID: nothing ran, or a failure came from anywhere else (another
// line, a timeout, a thrown error), which proves nothing about the mutant.
import { readFileSync } from 'node:fs';

const [reportPath, spec, lineArg] = process.argv.slice(2);
const want = Number(lineArg);
const report = JSON.parse(readFileSync(reportPath, 'utf8'));

const results = [];
const walk = (suite) => {
  for (const s of suite.specs ?? []) for (const t of s.tests ?? []) for (const r of t.results ?? []) results.push({ title: s.title, r });
  for (const child of suite.suites ?? []) walk(child);
};
for (const s of report.suites ?? []) walk(s);

const at = (e) => e?.location && e.location.file.endsWith(`/${spec}`) && e.location.line === want;
const isExpect = (e) => /expect\(/.test(e?.message ?? '');
let verdict;
const notes = [];
if (results.length === 0) {
  verdict = 'INVALID';
  notes.push('no row ran (the -g pattern matched nothing)');
} else {
  const bad = results.filter(({ r }) => r.status !== 'passed' && r.status !== 'skipped');
  if (bad.length === 0) {
    verdict = 'SURVIVED';
  } else {
    const ok = bad.every(({ r }) => r.status === 'failed' && (r.errors ?? []).some((e) => at(e) && isExpect(e)));
    verdict = ok ? 'KILLED' : 'INVALID';
    for (const { title, r } of bad) {
      const e = (r.errors ?? [])[0];
      notes.push(`${title}: ${r.status} at ${e?.location ? `${e.location.file.split('/').pop()}:${e.location.line}` : 'no location'}`);
    }
  }
}
console.log(`VERDICT ${verdict} (${results.length} result(s); killing line ${spec}:${want})`);
for (const n of notes) console.log(`  ${n}`);
