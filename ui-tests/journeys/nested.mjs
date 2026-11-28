// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Nested runs of the journeys project, shared by the run-level rows (meta.test.mjs) and the fault runner: a run
// that must fail has to fail with the harness's own diagnostic, never skip.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const UI_TESTS = dirname(dirname(fileURLToPath(import.meta.url)));

/** Runs `npx playwright test --project=journeys <args>` with `env` over this process's environment. */
export function journeysRun(args, env) {
  const r = spawnSync('npx', ['playwright', 'test', '--project=journeys', ...args],
    { cwd: UI_TESTS, env: { ...process.env, ...env }, encoding: 'utf8', timeout: 240_000 });
  return { status: r.status, out: `${r.stdout}\n${r.stderr}` };
}

/** The run failed, printed `diagnostic`, and skipped nothing. */
export function assertFailedWith(run, diagnostic) {
  assert.notEqual(run.status, 0, `the run passed:\n${run.out}`);
  assert.match(run.out, diagnostic, `the harness's own diagnostic is missing:\n${run.out}`);
  assert.doesNotMatch(run.out, /\bskipped\b/i, `the run skipped instead of failing:\n${run.out}`);
}
