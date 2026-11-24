// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Hot Reload's advice line, checked on the shipped classic HTML: while a
// restart is pending the reload answer brings restart_advice (and, on Unix,
// start_command), or start_refusal alone when the config a restart would boot
// is refused. Every string a row checks is this file's own.
import { readFileSync } from 'node:fs';
import { test, expect } from './base.mjs';

const PAGE_HTML = readFileSync(new URL('../../src/gateway/ui/index.html', import.meta.url), 'utf8');

const PENDING = 'reload summary from the mock, with fields x.y pending';
const ADVICE = 'guidance words the mock chose';
const COMMAND = "'/opt/mock bin/gw' serve --config '/srv/mock.yaml'";
const REFUSED = 'refusal words the mock chose.';

/** Open Configuration on the shipped page; each Hot Reload gets the next of `replies` (the last repeats). */
async function openConfig(page, replies) {
  const queue = [...replies];
  let last = queue[0];
  const table = {
    'GET /ui/classic': () => ({ html: PAGE_HTML }),
    'GET /ui/api/status': () => ({ json: { auth: { signed_in: true, admin: true, enabled: true } } }),
    'POST /ui/api/reload': () => {
      if (queue.length) last = queue.shift();
      return { json: last };
    },
  };
  await page.route(/\/ui\/(classic|api\/)/, (route) => {
    const req = route.request();
    const made = (table[`${req.method()} ${new URL(req.url()).pathname}`] ?? (() => ({ json: {} })))();
    return made.html === undefined
      ? route.fulfill({ json: made.json })
      : route.fulfill({ contentType: 'text/html', headers: { 'cache-control': 'no-store' }, body: made.html });
  });
  await page.goto('/ui/classic#config');
}

const hotReload = (page) => page.getByRole('button', { name: 'Hot Reload' }).click();
const statusLine = (page) => page.locator('#reload-status');
const guidance = (page) => page.locator('#reload-advice');
const startCmd = (page) => page.locator('#reload-command');

const ADVISED = { status: 'ok', changes: PENDING, restart_required: true, restart_advice: ADVICE, start_command: COMMAND };
const REFUSAL = { status: 'ok', changes: `${PENDING} plus a warning`, restart_required: true, start_refusal: REFUSED };

test('C1 a pending restart shows the summary as sent, the guidance, and the start command', async ({ page }) => {
  await openConfig(page, [ADVISED]);
  await hotReload(page);
  await expect(statusLine(page)).toContainText(PENDING);
  await expect(guidance(page)).toHaveText(ADVICE);
  await expect(startCmd(page)).toHaveText(COMMAND);
});

test('C2 with no start command the guidance shows alone', async ({ page }) => {
  const { start_command: _gone, ...guidanceOnly } = ADVISED;
  await openConfig(page, [guidanceOnly]);
  await hotReload(page);
  await expect(guidance(page)).toHaveText(ADVICE);
  await expect(startCmd(page)).toBeHidden();
});

test('C3 a refused restart shows the refusal alone: no "restart required", no guidance, no command', async ({ page }) => {
  await openConfig(page, [REFUSAL]);
  await hotReload(page);
  await expect(statusLine(page)).toHaveText(REFUSED);
  await expect(page.locator('#page-config')).not.toContainText('restart required');
  await expect(guidance(page)).toBeHidden();
  await expect(startCmd(page)).toBeHidden();
});

test('C4 nothing pending keeps the plain line and shows no advice', async ({ page }) => {
  await openConfig(page, [{ status: 'ok', changes: 'mock reload, nothing pending', restart_required: false }]);
  await hotReload(page);
  await expect(statusLine(page)).toContainText('mock reload, nothing pending');
  await expect(guidance(page)).toBeHidden();
  await expect(startCmd(page)).toBeHidden();
});

test('C5 a refusal after an advice leaves no stale guidance or command', async ({ page }) => {
  await openConfig(page, [ADVISED, REFUSAL]);
  await hotReload(page);
  await expect(startCmd(page)).toHaveText(COMMAND);
  await hotReload(page);
  await expect(statusLine(page)).toHaveText(REFUSED);
  await expect(guidance(page)).toBeHidden();
  await expect(startCmd(page)).toBeHidden();
});

test('C6 nothing pending after an advice clears the guidance and the command, and shows its own line', async ({ page }) => {
  const calm = { status: 'ok', changes: 'second mock reload, nothing waits', restart_required: false };
  await openConfig(page, [ADVISED, calm]);
  await hotReload(page);
  await expect(startCmd(page)).toHaveText(COMMAND);
  await hotReload(page);
  await expect(statusLine(page)).toContainText(calm.changes);
  await expect(guidance(page)).toBeHidden();
  await expect(startCmd(page)).toBeHidden();
});

test('C7 a failed reload after an advice leaves no stale guidance or command and Hot Reload works again', async ({ page }) => {
  await openConfig(page, [ADVISED]);
  const failures = {
    'an HTTP refusal': (route) => route.fulfill({ status: 500, json: { error: 'mock refusal' } }),
    'a network failure': (route) => route.abort(),
    'an answer that is not JSON': (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '{not json' }),
  };
  for (const [what, fail] of Object.entries(failures)) {
    await page.unroute('**/ui/api/reload');
    await hotReload(page);
    await expect(startCmd(page), `advised before ${what}`).toHaveText(COMMAND);
    // Routes added later win, so this answer replaces the mock's for the next press.
    await page.route('**/ui/api/reload', fail);
    await hotReload(page);
    await expect(statusLine(page), what).toContainText('Failed');
    await expect(guidance(page), what).toBeHidden();
    await expect(startCmd(page), what).toBeHidden();
    await expect(page.getByRole('button', { name: 'Hot Reload' }), what).toBeEnabled();
  }
});
