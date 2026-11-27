// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Row K1, the harness smoke (not J1): through the UI only, sign in with the seed's admin key, open Tools, try
// tide_table, and see its answer; then two reads outside the browser prove the call really happened: the gateway's
// Activity row carrying the trace id this call's own response returned, and the stub server's own log.
import { test, expect, activityRowFor, signIn } from './gateway.mjs';

test.use({ seed: 'populated' });

test('harness smoke: try a tool', async ({ page, gw }) => {
  await signIn(page, gw.adminKey);
  await page.getByRole('link', { name: 'Tools' }).first().click();
  // Tools opens on its Status tab; trying a tool is on the Actions tab (/ui/tools/actions).
  await page.getByRole('navigation', { name: 'Tabs' }).getByRole('link', { name: 'Actions' }).click();

  const picker = page.locator('#try-tool');
  // Each stub's tools carry its server's name; the option label is "<tool> <server> · ...", so pick tide's own.
  const label = await picker.locator('option').filter({ hasText: /^tide_table tide · / }).textContent();
  await picker.selectOption({ label: label.trim() });
  const tideCalls = async () => (await gw.stubLog('tide')).split('\n')
    .filter((l) => l.includes('"tools/call"') && l.includes('tide_table')).length;
  const before = await tideCalls();
  // The stub's tools carry no read-only hint, so the shell treats them as able to change things and asks first
  // ("Run tide_table? tide_table can change things."): Run opens that confirm, and its own Run sends the call.
  await page.getByRole('button', { name: 'Run tide_table' }).click();
  const [response] = await Promise.all([
    page.waitForResponse((r) => r.url().endsWith('/ui/api/tools/call') && r.request().method() === 'POST'),
    page.getByRole('dialog').getByRole('button', { name: 'Run tide_table' }).click(),
  ]);
  expect(response.status()).toBe(200);
  const traceId = (await response.json()).receipt;
  expect(traceId, 'the call answer carries its receipt').toBeTruthy();
  await expect(page.locator('.tools-try-answer')).toContainText('tide-answered');

  // Outside the browser, 1: the gateway's Activity holds THIS call (by its trace id), answered.
  const rows = (await (await gw.api('/ui/api/activity?server=tide')).json()).rows;
  const row = activityRowFor(rows, traceId);
  expect(row, `no Activity row with trace id ${traceId}`).toBeTruthy();
  expect(row.tool).toBe('tide_table');
  expect(row.outcome).toBe('ok');

  // Outside the browser, 2: the stub's own log gained a tools/call for tide_table with this click.
  expect(await tideCalls(), 'the stub never received the tools/call').toBeGreaterThan(before);
});
