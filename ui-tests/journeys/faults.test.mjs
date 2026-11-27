// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// D-F1 (part C): each journey's planted fault turns it red with its own message, at its named line. A row runs the
// real journeys project on one journey with JH_FAULT set (nested.mjs). Needs JOURNEYS_GATEWAY_BIN.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { journeysRun } from './nested.mjs';

const JOURNEYS = dirname(fileURLToPath(import.meta.url));

/** Every error object the JSON report holds, in report order (tests' results carry `errors`). */
function reportErrors(node, found = []) {
  if (Array.isArray(node)) node.forEach((n) => reportErrors(n, found));
  else if (node && typeof node === 'object') {
    if (Array.isArray(node.errors)) found.push(...node.errors.filter((e) => e && typeof e === 'object'));
    Object.entries(node).forEach(([k, v]) => { if (k !== 'errors') reportErrors(v, found); });
  }
  return found;
}

/**
 * The fault run of `file` with `fault` planted fails, skipping nothing, and its FIRST error is the row's own: the
 * message carries `message` and the location is the line holding it (an expect spread over two lines is reported at
 * its first line, the one before the message). Read from Playwright's structured JSON report, never from printed
 * text, whose source excerpts could quote the message beside an unrelated error.
 */
function redAt(file, fault, message) {
  const dir = mkdtempSync(join(tmpdir(), 'jh-fault-'));
  let run;
  let json;
  try {
    run = journeysRun([`journeys/${file}`, '--reporter=json'], { JH_FAULT: fault, PLAYWRIGHT_JSON_OUTPUT_NAME: join(dir, 'report.json') });
    json = JSON.parse(readFileSync(join(dir, 'report.json'), 'utf8'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  assert.notEqual(run.status, 0, `the fault run passed:\n${run.out}`);
  assert.equal(json.stats?.skipped, 0, `the fault run skipped:\n${JSON.stringify(json.stats)}`);
  assert.equal(json.stats?.unexpected, 1, `the fault run did not fail exactly one test:\n${JSON.stringify(json.stats)}`);
  const [first] = reportErrors(json.suites);
  assert.ok(first, `the report holds no error:\n${run.out}`);
  assert.ok(String(first.message).includes(message), `the first error is not the row's own:\n${first.message}`);
  const at = readFileSync(join(JOURNEYS, file), 'utf8').split('\n').findIndex((l) => l.includes(message)) + 1;
  assert.ok(at > 0, `${file} has no line holding "${message}"`);
  assert.ok(String(first.location?.file).endsWith(`/${file}`) && [at - 1, at].includes(first.location?.line),
    `the first error is at ${first.location?.file}:${first.location?.line}, not ${file}:${at}`);
}

test('J4:retry, a Retry answered but never forwarded, fails at the stub-log read', () => {
  redAt('j04-diagnose.journey.mjs', 'J4:retry', 'J4-retry: the stub log gained no connection after Retry');
});

test('J4:remove, a Remove answered but never forwarded, fails at the config read', () => {
  redAt('j04-diagnose.journey.mjs', 'J4:remove', 'J4-remove: the config file still names tide');
});

test('JOURNEY7:drop-J4, a journey missing from the project, fails the coverage row', () => {
  redAt('coverage.journey.mjs', 'JOURNEY7:drop-J4', 'JOURNEY7: the project does not cover the smoke and every journey');
});
