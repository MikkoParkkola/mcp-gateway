// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// axe over the whole classic page (src/gateway/ui/index.html), served as the
// gateway serves it, in every tab and in the Add Server and OpenAPI import
// states, at both widths. /ui/api answers are mocked for a signed-in admin.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, expect, WIDTHS, blockingViolations, scrollsFromKeyboard } from './base.mjs';

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
      '/ui/api/registry': { entries: [{ name: 'filesystem', description: 'Files on this host', login: 'none' }] },
      '/ui/api/tools': { tools: [{ server: 'alpha', name: 'read_a', description: 'Reads a thing' }] },
      '/ui/api/capabilities': { capabilities: [{ name: 'weather_lookup', description: 'Looks up weather' }] },
      '/ui/api/capabilities/weather_lookup': { name: 'weather_lookup', content: 'name: weather_lookup\n' },
      '/ui/api/import/openapi/preview': { tools: [{ name: 'list_pets', description: 'Lists pets' }] },
      // A digest wide enough that its table scrolls sideways on a phone.
      '/ui/api/control-plane': { view: { servers: [{ name: 'alpha' }], trust_cards: [{ server_id: 'alpha', trust_card_digest_sha256: 'a'.repeat(64), schema_version: '1' }] } },
    }[path] ?? {};
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
  });
  await page.goto('/ui/classic#dashboard');
  await expect(page.locator('#d-version')).toHaveText('vtest');
}

// Read from the page itself: a new tab gets an axe row below on its own, and a
// new dialog fails here until it has one, instead of shipping unscanned.
const ids = (pattern) => [...INDEX.matchAll(pattern)].map((m) => m[1]).sort();
const TABS = ids(/id="page-([a-z-]+)"/g);
const DIALOGS = ids(/id="([a-z-]+)"[^>]*role="dialog"/g);

test('every classic tab and dialog in the page has an axe row', () => {
  // A reader that silently finds nothing would scan nothing.
  expect(TABS).toEqual(expect.arrayContaining(['capabilities', 'config', 'control-plane', 'costs', 'dashboard', 'servers', 'tools']));
  // Each dialog named here has its own axe test below; a new one needs a test, then a name.
  expect(DIALOGS).toEqual(['import-modal']);
  expect(INDEX.match(/role="dialog"/g)).toHaveLength(DIALOGS.length);
});

for (const width of WIDTHS) {
  test.describe(`at ${width} px`, () => {
    test.beforeEach(async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await classicPage(page);
    });

    test('a Control Plane table wider than the screen scrolls from the keyboard', async ({ page }) => {
      test.skip(width > 600, 'the table fits at desktop width');
      await page.evaluate(() => { location.hash = 'control-plane'; });
      const region = page.getByRole('region', { name: 'TrustCards' });
      await expect(region).toContainText('a'.repeat(64));
      // The Runtime Health region comes just before it in tab order.
      await scrollsFromKeyboard(page, { from: page.getByRole('region', { name: 'Runtime Health' }), region, key: 'ArrowRight', axis: 'x' });
    });

    for (const tab of TABS) {
      test(`axe finds no blocking violation on the ${tab} tab`, async ({ page }) => {
        await page.evaluate((t) => { location.hash = t; }, tab);
        await expect(page.locator(`#page-${tab}`)).toHaveClass(/active/);
        expect(await blockingViolations(page)).toEqual([]);
      });
    }

    test('axe finds no blocking violation in the Add Server form, registry mode with an entry picked', async ({ page }) => {
      await page.evaluate(() => { location.hash = 'servers'; });
      // Type once the registry is loaded, as a person would.
      const loaded = page.waitForResponse((r) => r.url().endsWith('/ui/api/registry'));
      await page.getByRole('button', { name: '+ Add Server' }).click();
      await loaded;
      await page.locator('#reg-search-input').fill('file');
      await page.locator('#reg-dropdown .reg-opt').first().click();
      await expect(page.locator('#reg-name-override')).toBeVisible();
      expect(await blockingViolations(page)).toEqual([]);
    });

    for (const transport of ['stdio', 'http']) {
      test(`axe finds no blocking violation in the Add Server form, custom ${transport} with an env row`, async ({ page }) => {
        await page.evaluate(() => { location.hash = 'servers'; });
        await page.getByRole('button', { name: '+ Add Server' }).click();
        await page.locator('#mode-custom').click();
        await page.locator('#custom-transport').selectOption(transport);
        await page.locator('#server-custom-fields').getByRole('button', { name: '+ Add' }).click();
        await expect(page.locator(transport === 'http' ? '#custom-url' : '#custom-command')).toBeVisible();
        await expect(page.locator('#env-rows input')).toHaveCount(2);
        expect(await blockingViolations(page)).toEqual([]);
      });
    }

    test('axe finds no blocking violation with a capability open in the editor', async ({ page }) => {
      await page.evaluate(() => { location.hash = 'capabilities'; });
      await page.locator('[data-action="toggle-cap"][data-value="weather_lookup"]').click();
      await expect(page.locator('#cap-editor-weather_lookup')).toBeVisible();
      expect(await blockingViolations(page)).toEqual([]);
    });

    test('axe finds no blocking violation in the OpenAPI import dialog, before and after a preview', async ({ page }) => {
      await page.evaluate(() => { location.hash = 'capabilities'; });
      await page.getByRole('button', { name: 'Import OpenAPI' }).click();
      await expect(page.locator('#import-modal')).toHaveClass(/open/);
      expect(await blockingViolations(page)).toEqual([]);
      await page.locator('#import-url').fill('https://specs.example.test/openapi.json');
      await page.locator('#preview-btn').click();
      await expect(page.getByRole('checkbox', { name: 'list_pets' })).toBeChecked();
      expect(await blockingViolations(page)).toEqual([]);
    });
  });
}
