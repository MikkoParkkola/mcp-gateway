// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// axe over the whole classic page (src/gateway/ui/index.html), served as the
// gateway serves it, in every tab and in the Add Server and OpenAPI import
// states, at both widths. /ui/api answers are mocked for a signed-in admin.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, expect, WIDTHS, blockingViolations } from './base.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const INDEX = readFileSync(join(HERE, '..', '..', 'src', 'gateway', 'ui', 'index.html'), 'utf8');

const STATUS = {
  auth: { enabled: true, signed_in: true, admin: true },
  server_count: 1,
  tool_count: 1,
  version: 'test',
  servers: [{ name: 'alpha', status: 'healthy', circuit_state: 'closed', transport: 'http', tool_count: 1, request_count: 3, failure_count: 0, latency_p50_ms: 4, latency_p95_ms: 9 }],
};

async function classicPage(page) {
  await page.route('**/ui/classic', (route) => route.fulfill({
    status: 200,
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-cache, no-store, must-revalidate' },
    body: INDEX,
  }));
  await page.route('**/ui/api/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    const body = {
      '/ui/api/status': STATUS,
      '/ui/api/registry': { servers: [] },
      '/ui/api/tools': { tools: [{ server: 'alpha', name: 'read_a', description: 'Reads a thing' }] },
      '/ui/api/capabilities': { capabilities: [] },
    }[path] ?? {};
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
  });
  await page.goto('/ui/classic#dashboard');
  await expect(page.locator('#d-version')).toHaveText('vtest');
}

const TABS = ['dashboard', 'tools', 'servers', 'control-plane', 'capabilities', 'config', 'costs'];

for (const width of WIDTHS) {
  test.describe(`at ${width} px`, () => {
    test.beforeEach(async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await classicPage(page);
    });

    for (const tab of TABS) {
      test(`axe finds no blocking violation on the ${tab} tab`, async ({ page }) => {
        await page.evaluate((t) => { location.hash = t; }, tab);
        await expect(page.locator(`#page-${tab}`)).toHaveClass(/active/);
        expect(await blockingViolations(page)).toEqual([]);
      });
    }

    for (const mode of ['registry', 'custom']) {
      test(`axe finds no blocking violation in the Add Server form, ${mode} mode`, async ({ page }) => {
        await page.evaluate(() => { location.hash = 'servers'; });
        await page.getByRole('button', { name: '+ Add Server' }).click();
        await page.locator(`#mode-${mode}`).click();
        expect(await blockingViolations(page)).toEqual([]);
      });
    }

    test('axe finds no blocking violation in the OpenAPI import dialog', async ({ page }) => {
      await page.evaluate(() => { location.hash = 'capabilities'; });
      await page.getByRole('button', { name: 'Import OpenAPI' }).click();
      await expect(page.locator('#import-modal')).toHaveClass(/open/);
      expect(await blockingViolations(page)).toEqual([]);
    });
  });
}
