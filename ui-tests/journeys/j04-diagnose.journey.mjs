// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// J4 (part C): a server stops answering; through the UI only, find it, retry it, then remove it.
// Outside the browser: the stub's own log shows the retry reached it (exactly one new connection, none before the
// click), and after the removal the config file and the gateway's status read no longer hold it.
// Faults (D-F1, run by faults.test.mjs): JH_FAULT=J4:retry answers the retry as revived without forwarding it and
// must fail at the line tagged J4-retry; JH_FAULT=J4:remove answers the removal without forwarding it and must fail
// at the line tagged J4-remove.
import { readFile } from 'node:fs/promises';
import { test, expect, until, signIn } from './gateway.mjs';

test.use({ seed: 'silentStub' });

const FAULT = process.env.JH_FAULT ?? '';
/** How many initialize requests reached the stub: each log line parsed as a JSON-RPC message, never a text match. */
const initializes = (log) => log.split('\n').filter((l) => {
  try { return JSON.parse(l).method === 'initialize'; } catch { return false; }
}).length;
const tideState = async (gw) => {
  const { servers } = await (await gw.api('/ui/api/status')).json();
  return servers.find((s) => s.name === 'tide')?.state ?? null;
};
const pause = (ms) => new Promise((resolve) => { setTimeout(resolve, ms); });

/** Plant a fault at the request boundary (D-P1): the page gets the answer; the gateway never sees the request. */
async function plant(page) {
  if (FAULT === 'J4:retry') {
    await page.route('**/ui/api/backends/tide/revive', (route) => route.fulfill({
      status: 200, contentType: 'application/json', body: JSON.stringify({ backend: 'tide', status: 'revived' }) }));
  } else if (FAULT === 'J4:remove') {
    await page.route('**/ui/api/backends/tide', (route) => (route.request().method() === 'DELETE'
      ? route.fulfill({ status: 204, body: '' }) : route.fallback()));
  } else if (FAULT !== '') {
    throw new Error(`JH_FAULT=${FAULT} is not a J4 fault`);
  }
}

test('J4 diagnose: a silent server is found, retried and removed', async ({ page, gw }) => {
  await plant(page);

  // Tide answers first, so it is connected before it goes silent.
  const first = await gw.invoke('tide', 'tide_table');
  expect(JSON.stringify(first.body), 'tide did not answer before it was silenced').toContain('tide-answered');

  // Health checks are off (the seed), so the gateway learns tide stopped answering only from failing calls.
  // At most 5 calls within 60 s; each attempt and the state read after it are logged (T3).
  await gw.silence('tide');
  const drive = Date.now() + 60_000;
  let state = await tideState(gw);
  for (let attempt = 1; attempt <= 5 && !['unhealthy', 'paused'].includes(state) && Date.now() < drive; attempt += 1) {
    const r = await gw.invoke('tide', 'tide_table').catch((error) => ({ error: String(error?.message ?? error) }));
    state = await tideState(gw);
    console.log(`J4 drive attempt ${attempt}: call ${r.error ? `rejected (${r.error})` : `status ${r.status}`}; tide state ${state}`);
  }
  expect(['unhealthy', 'paused'], `stop and report: the status read never showed tide failing (last state ${state})`).toContain(state);

  // Tide recovers before the click (Retry reconnects it, and a silent stub would leave that unanswered). With health
  // checks off, nothing may reconnect it on its own: the quiet window.
  await gw.silence('tide', false);
  const mark = initializes(await gw.stubLog('tide'));
  await pause(3_000);
  expect(initializes(await gw.stubLog('tide')), 'stop and report: tide reconnected before any click (health checks on?)')
    .toBe(mark);

  // Through the UI only: find tide in the Servers list, open its Actions, retry through the confirm.
  await signIn(page, gw.adminKey);
  await page.getByRole('link', { name: 'Servers' }).first().click();
  await page.locator('#content').getByRole('link', { name: 'tide', exact: true }).click();
  await page.locator('nav.tabs').getByRole('link', { name: 'Actions', exact: true }).click();
  const retry = /^(Restart|Retry now) tide$/;
  await page.locator('#content').getByRole('button', { name: retry }).click();
  // The count starts at the confirm: anything the navigation caused would show here, not be credited to Retry.
  expect(initializes(await gw.stubLog('tide')), 'stop and report: tide reconnected while the pages loaded').toBe(mark);
  await page.locator('dialog.confirm').getByRole('button', { name: retry }).click();
  // The confirm's own done title (shell: `p.done-title`, "✓ <notice>"); the page may repeat the notice beside a status line.
  await expect(page.locator('p.done-title', { hasText: 'tide was restarted.' })).toHaveText('✓ tide was restarted.');

  // Outside the browser: the stub's own log gained exactly one connection after the click.
  await expect.poll(async () => initializes(await gw.stubLog('tide')) - mark,
    { message: 'J4-retry: the stub log gained no connection after Retry', timeout: 10_000 }).toBeGreaterThanOrEqual(1);
  await pause(1_000);
  expect(initializes(await gw.stubLog('tide')) - mark, 'J4-retry: one Retry made more than one connection').toBe(1);

  // Remove through the confirm.
  await page.locator('nav.tabs').getByRole('link', { name: 'Actions', exact: true }).click();
  await page.locator('#content').getByRole('button', { name: 'Remove tide' }).click();
  await page.locator('dialog.confirm').getByRole('button', { name: 'Remove tide' }).click();
  await expect(page.locator('p.done-title', { hasText: 'tide was removed.' })).toHaveText(/^✓ tide was removed\./);

  // Outside the browser: the config file no longer names tide, and the gateway's status read does not list it.
  await expect.poll(async () => /^ {2}tide:$/m.test(await readFile(gw.configPath, 'utf8')),
    { message: 'J4-remove: the config file still names tide', timeout: 10_000 }).toBe(false);
  await until(Date.now() + 10_000, 'J4-remove: the status read still lists tide', async () => !(await gw.serverNames()).includes('tide'));
});
