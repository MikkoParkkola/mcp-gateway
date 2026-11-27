// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// D-F1 (part C): each journey's planted fault turns it red with its own message, at its named line. A row runs the
// real journeys project on one journey with JH_FAULT set (nested.mjs). Needs JOURNEYS_GATEWAY_BIN.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { journeysRun, assertFailedWith } from './nested.mjs';

const JOURNEYS = dirname(fileURLToPath(import.meta.url));
const escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * The fault run of `file` with `fault` planted fails with `message`, at the line holding it (an expect spread over
 * two lines is reported at its first line, the one before the message).
 */
function redAt(file, fault, message) {
  const run = journeysRun([`journeys/${file}`, '--reporter=list'], { JH_FAULT: fault });
  assertFailedWith(run, new RegExp(escape(message)));
  const at = readFileSync(join(JOURNEYS, file), 'utf8').split('\n').findIndex((l) => l.includes(message)) + 1;
  assert.ok(at > 0, `${file} has no line holding "${message}"`);
  assert.match(run.out, new RegExp(`${escape(file)}:(${at - 1}|${at}):`), `the failure is not at ${file}:${at}:\n${run.out}`);
}

test('J4:retry, a Retry answered but never forwarded, fails at the stub-log read', () => {
  redAt('j04-diagnose.journey.mjs', 'J4:retry', 'J4-retry: the stub log gained no connection after Retry');
});

test('J4:remove, a Remove answered but never forwarded, fails at the config read', () => {
  redAt('j04-diagnose.journey.mjs', 'J4:remove', 'J4-remove: the config file still names tide');
});
