// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Panes of the classic page that scroll (a tool's schema, the OpenAPI import
// list, the config view) must be reachable and scrollable from the keyboard,
// and pass axe while they overflow. The real page is served with answers
// large enough to make each pane overflow.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, expect, WIDTHS, blockingViolations, scrollsFromKeyboard } from './base.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const INDEX = readFileSync(join(HERE, '..', '..', 'src', 'gateway', 'ui', 'index.html'), 'utf8');

// A schema far taller than the pane's 300 px.
const SCHEMA = {
  type: 'object',
  properties: Object.fromEntries(Array.from({ length: 60 }, (_, i) => [`field_${i}`, { type: 'string', description: `Field ${i}` }])),
};
const OPERATIONS = Array.from({ length: 60 }, (_, i) => ({ name: `operation_${i}`, description: `Operation ${i}` }));
// One unbreakable token, so the config view is wider than any screen.
const CONFIG = { backends: { alpha: { url: `https://alpha.example.test/${'x'.repeat(400)}` } } };

async function classicPage(page) {
  await page.route('**/ui/classic', (route) => route.fulfill({
    status: 200,
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-cache, no-store, must-revalidate' },
    body: INDEX,
  }));
  await page.route('**/ui/api/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    const body = {
      '/ui/api/status': { auth: { enabled: true, signed_in: true, admin: true }, servers: [], version: 'test' },
      '/ui/api/tools': { tools: [{ server: 'alpha', name: 'wide_tool', description: 'Takes many fields', schema: SCHEMA }] },
      '/ui/api/capabilities': { capabilities: [] },
      '/ui/api/import/openapi/preview': { tools: OPERATIONS },
      '/ui/api/config': CONFIG,
    }[path] ?? {};
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
  });
  await page.goto('/ui/classic#dashboard');
  await expect(page.locator('#d-version')).toHaveText('vtest');
}

for (const width of WIDTHS) {
  test.describe(`at ${width} px`, () => {
    test.beforeEach(async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await classicPage(page);
    });

    test('a tool opens from the keyboard and its long schema scrolls', async ({ page }) => {
      await page.evaluate(() => { location.hash = 'tools'; });
      const toggle = page.getByRole('button', { name: 'wide_tool' });
      await expect(toggle).toHaveAttribute('aria-expanded', 'false');
      await toggle.focus();
      await page.keyboard.press('Enter');
      await expect(toggle).toHaveAttribute('aria-expanded', 'true');
      const schema = page.getByRole('region', { name: 'Input schema of wide_tool' });
      await expect(schema).toBeVisible();
      await scrollsFromKeyboard(page, { from: toggle, region: schema, key: 'ArrowDown', axis: 'y' });
      expect(await blockingViolations(page)).toEqual([]);
    });

    test('each activation of a tool name toggles its detail exactly once', async ({ page }) => {
      await page.evaluate(() => { location.hash = 'tools'; });
      const toggle = page.getByRole('button', { name: 'wide_tool' });
      const detail = page.locator('#td-0');
      // Tab reaches it in page order: from the search box, past the filter.
      await page.locator('#tool-search').focus();
      await page.keyboard.press('Tab');
      await page.keyboard.press('Tab');
      await expect(toggle).toBeFocused();
      for (const [how, open] of [['Space', true], ['Enter', false], ['click', true], ['click', false]]) {
        if (how === 'click') await toggle.click(); else await page.keyboard.press(how);
        await expect(toggle, how).toHaveAttribute('aria-expanded', String(open));
        await expect(detail, how).toBeVisible({ visible: open });
      }
      // A click on the row outside the name still toggles, as before.
      await page.locator('.tool-row td').nth(1).click();
      await expect(toggle).toHaveAttribute('aria-expanded', 'true');
    });

    test('a long OpenAPI import list scrolls from the keyboard', async ({ page }) => {
      await page.evaluate(() => { location.hash = 'capabilities'; });
      await page.getByRole('button', { name: 'Import OpenAPI' }).click();
      await page.locator('#import-url').fill('https://specs.example.test/openapi.json');
      await page.locator('#preview-btn').click();
      await expect(page.locator('.import-check')).toHaveCount(OPERATIONS.length);
      await scrollsFromKeyboard(page, { from: page.locator('#preview-btn'), region: page.getByRole('region', { name: 'Operations in the spec' }), key: 'ArrowDown', axis: 'y' });
      expect(await blockingViolations(page)).toEqual([]);
    });

    test('a config wider than the screen scrolls from the keyboard', async ({ page }) => {
      await page.evaluate(() => { location.hash = 'config'; });
      const view = page.getByRole('region', { name: 'Current configuration' });
      await expect(view).toContainText('alpha.example.test');
      await scrollsFromKeyboard(page, { from: page.locator('#reload-btn'), region: view, key: 'ArrowRight', axis: 'x' });
      expect(await blockingViolations(page)).toEqual([]);
    });
  });
}
