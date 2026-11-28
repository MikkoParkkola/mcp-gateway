// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Row K1, the harness smoke (not J1): through the UI only, sign in with the seed's admin key, open Tools, try
// tide_table, and see its answer; then two reads outside the browser prove the call really happened: the gateway's
// Activity row carrying the trace id this call's own response returned, and the stub server's own log.
import { test, expect, activityRowFor } from './gateway.mjs';

test.use({ seed: 'populated' });

test('harness smoke: try a tool', async ({ page, gw }) => {
  // The 4.0 shell lives under /ui/<route> (routes.rs UI_SHELL); /ui itself still serves the classic page until the
  // cutover. A page without the shell's sign-in fails here, by name, not at a fill that waits out the test.
  await page.goto('/ui/overview/status');
  await page.locator('#signin').waitFor({ state: 'visible', timeout: 15_000 });
  await page.locator('#signin-form input').first().fill(gw.adminKey);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByRole('link', { name: 'Tools' }).first().click();
  // Tools opens on its Status tab; trying a tool is on the Actions tab (/ui/tools/actions).
  await page.getByRole('navigation', { name: 'Tabs' }).getByRole('link', { name: 'Actions' }).click();

  const picker = page.locator('#try-tool');
  // Both stubs serve tide_table; the option label is "<tool> <server> · ...", so pick tide's own.
  const label = await picker.locator('option').filter({ hasText: /^tide_table tide · / }).textContent();
  await picker.selectOption({ label: label.trim() });
  const tideCalls = async () => (await gw.stubLog('tide')).split('\n')
    .filter((l) => l.includes('"tools/call"') && l.includes('tide_table')).length;
  const before = await tideCalls();
  // Each step below follows the shell's own spec, ui-tests/tests/tools-try.spec.mjs (cited by line). The stub's tools
  // carry no read-only hint, so the shell treats tide_table as able to change things (a write: W1, W2).
  const panel = page.locator('section.tools-try'); // :22
  const run = panel.getByRole('button', { name: 'Run tide_table', exact: true }); // :23
  const ask = page.getByRole('dialog', { name: 'Run tide_table?' }); // :40
  await run.click(); // W1 :806: a write's Run asks first and sends nothing
  await expect(ask).toBeVisible(); // :44
  await expect(ask.getByRole('listitem')).toHaveText(['tide_table can change things.']); // :45
  expect(await tideCalls(), 'Run sent the call before the confirm').toBe(before);
  const [response] = await Promise.all([ // W2 :828: the confirm's own Run sends it, with confirm_write true (:829)
    page.waitForResponse((r) => r.url().endsWith('/ui/api/tools/call') && r.request().method() === 'POST'),
    ask.getByRole('button', { name: 'Run tide_table', exact: true }).click(), // :41
  ]);
  expect(response.status()).toBe(200); // a 409 re-ask (W3 :843-874) would come only for a send without confirm_write
  const traceId = (await response.json()).receipt;
  expect(traceId, 'the call answer carries its receipt').toBeTruthy();
  await expect(ask).toHaveCount(0); // W2 :831: the confirm closes
  await expect(panel).toContainText('Answered in'); // W2 :832 (tools.js "Answered in ${latency} ms")
  await expect(panel).toContainText('tide-answered'); // W2 :833: the answer is drawn in the panel

  // Outside the browser, 1: the gateway's Activity holds THIS call (by its trace id), answered.
  const rows = (await (await gw.api('/ui/api/activity?server=tide')).json()).rows;
  const row = activityRowFor(rows, traceId);
  expect(row, `no Activity row with trace id ${traceId}`).toBeTruthy();
  expect(row.tool).toBe('tide_table');
  expect(row.outcome).toBe('ok');

  // Outside the browser, 2: the stub's own log gained a tools/call for tide_table with this click.
  expect(await tideCalls(), 'the stub never received the tools/call').toBeGreaterThan(before);
});
