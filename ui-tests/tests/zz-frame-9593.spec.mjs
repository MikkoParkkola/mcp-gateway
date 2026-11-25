// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Throwaway branch only (never merged): screenshots of Gateway › Actions' Reload
// section for the review-carried frame-26 comparison (R-FRAME), at the two widths,
// idle and after a reload whose answer carries restart advice and a start command.
import { test, expect } from './base.mjs';
import { shellReady, signedInAdmin } from './shell.mjs';

const ANSWER = {
  status: 'ok', changes: 'server address changed (restart required)', restart_required: true,
  restart_reason: 'server_address_changed', restart_advice: 'Restart the gateway to apply this.',
  start_command: "'/opt/mcp gateway/mcp-gateway' serve --config '/etc/mcp/gateway.yaml'",
};

for (const width of [1440, 390]) {
  test(`frame-26 shots at ${width}`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.emulateMedia({ colorScheme: 'dark' });
    await signedInAdmin(page);
    await page.route('**/ui/api/reload', (r) => r.fulfill({ json: ANSWER }));
    await page.goto('/ui/gateway/actions');
    await shellReady(page);
    const section = page.locator('#content #reload');
    await expect(section).toBeVisible();
    // Not under test-results/: Playwright empties that folder at the start of every run.
    await page.screenshot({ path: `frame-out/${width}-idle.png`, fullPage: true });
    await section.getByRole('button', { name: 'Reload now' }).click();
    await expect(section.locator('code.start-command')).toBeVisible();
    await page.screenshot({ path: `frame-out/${width}-advice.png`, fullPage: true });
  });
}
