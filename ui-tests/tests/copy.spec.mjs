// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Rows C1, C2, C2b and C6 of the tooltip test plan: the two-way copy check
// on the shipped files, the same check going red on planted faults, and the
// copy asset served with its hash and named by the shell script.
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, expect } from './base.mjs';
import { checkCopy } from './copy-check.mjs';

const SHELL = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'src', 'gateway', 'ui', 'shell');
const files = readdirSync(SHELL);
const copyFile = files.find((f) => /^tips\.[0-9a-f]{12}\.json$/.test(f));
const scripts = files.filter((f) => f.endsWith('.js')).map((f) => readFileSync(join(SHELL, f), 'utf8'));

test('C1 the shipped copy and the shipped screens agree both ways', () => {
  expect(copyFile, 'a content-hashed tips asset exists').toBeTruthy();
  const copy = JSON.parse(readFileSync(join(SHELL, copyFile), 'utf8'));
  expect(checkCopy(copy, scripts)).toEqual([]);
});

test('C2 C2b the check goes red on each planted fault', () => {
  const copy = { _pending: { servers: ['servers.status.paused'] }, 'servers.status.paused': { title: 'Paused', text: 't' } };
  const ok = 'shell.tip("servers.status.paused")';
  expect(checkCopy(copy, [''])).toEqual([]);
  expect(checkCopy(copy, [ok])).toEqual([]);
  const cases = [
    [{ ...copy, 'servers.status.extra': { title: 'x', text: 'y' } }, [''], 'orphan copy'],
    [copy, ['tip("servers.status.nope")'], 'used without copy'],
    [copy, ["register('servers', {})"], 'pending under a built page'],
    [copy, ['tip(someVar)'], 'non-literal'],
    [{ ...copy, 'Servers.Status.X': { title: 'x', text: 'y' }, _pending: { servers: ['servers.status.paused', 'Servers.Status.X'] } }, [''], 'malformed id'],
    [{ ...copy, _pending: { servers: ['servers.status.paused', 'servers.status.ghost'] } }, [''], 'pending without copy'],
  ];
  for (const [c, s, want] of cases) {
    const found = checkCopy(c, s);
    expect(found.some((p) => p.includes(want)), `${want}: ${JSON.stringify(found)}`).toBe(true);
  }
});

test('C6 the copy asset is named by the shell script and served with an immutable cache', async ({ request }) => {
  expect(scripts.some((s) => s.includes(`/ui/assets/${copyFile}`))).toBe(true);
  const reply = await request.get(`/ui/assets/${copyFile}`);
  expect(reply.status()).toBe(200);
  expect(reply.headers()['content-type']).toContain('application/json');
  expect(reply.headers()['cache-control']).toContain('immutable');
});
