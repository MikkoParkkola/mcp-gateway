// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The classic page's OpenAPI import dialog end to end: preview a spec,
// untick an operation, import the rest, and close the dialog by Escape and
// by the backdrop. The real page is served with mocked /ui/api answers.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, expect } from './base.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const INDEX = readFileSync(join(HERE, '..', '..', 'src', 'gateway', 'ui', 'index.html'), 'utf8');
const SPEC_URL = 'https://specs.example.test/openapi.json';

async function capabilitiesPage(page) {
  const seen = { previews: [], imports: [], listReads: 0 };
  await page.route('**/ui/classic', (route) => route.fulfill({
    status: 200,
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-cache, no-store, must-revalidate' },
    body: INDEX,
  }));
  await page.route('**/ui/api/**', (route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname;
    const json = (body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
    if (path === '/ui/api/status') return json({ auth: { enabled: true, signed_in: true, admin: true }, servers: [], version: 'test' });
    if (path === '/ui/api/import/openapi/preview') {
      seen.previews.push(req.postDataJSON());
      return json({ tools: [{ name: 'list_pets', description: 'Lists pets' }, { name: 'delete_pet', description: 'Deletes a pet' }] });
    }
    if (path === '/ui/api/import/openapi') {
      seen.imports.push(req.postDataJSON());
      return json({ imported: 1 });
    }
    if (path === '/ui/api/capabilities') seen.listReads++;
    return json({ capabilities: [] });
  });
  await page.goto('/ui/classic#capabilities');
  await page.getByRole('button', { name: 'Import OpenAPI' }).click();
  await expect(page.locator('#import-modal')).toHaveClass(/open/);
  return seen;
}

test('preview, untick and import send the selected operations only', async ({ page }) => {
  const seen = await capabilitiesPage(page);
  await expect(page.locator('#import-url')).toBeFocused();
  await page.locator('#import-url').fill(SPEC_URL);
  await page.locator('#preview-btn').click();
  await expect(page.locator('#import-count')).toHaveText('2 / 2 selected');
  await page.getByRole('checkbox', { name: 'delete_pet' }).uncheck();
  await expect(page.locator('#import-count')).toHaveText('1 / 2 selected');
  const readsBefore = seen.listReads;
  await page.getByRole('button', { name: 'Import Selected' }).click();
  await expect(page.locator('#import-modal')).not.toHaveClass(/open/);
  // The list is read again so the imported capability shows.
  await expect.poll(() => seen.listReads).toBeGreaterThan(readsBefore);
  expect(seen.previews).toEqual([{ url: SPEC_URL }]);
  expect(seen.imports).toEqual([{ url: SPEC_URL, selected_tools: ['list_pets'] }]);
});

test('nothing selected is refused with a message and sends nothing', async ({ page }) => {
  const seen = await capabilitiesPage(page);
  await page.locator('#import-url').fill(SPEC_URL);
  await page.locator('#preview-btn').click();
  await expect(page.locator('#import-count')).toHaveText('2 / 2 selected');
  await page.locator('.import-check').evaluateAll((boxes) => boxes.forEach((b) => b.click()));
  await page.getByRole('button', { name: 'Import Selected' }).click();
  await expect(page.locator('#import-msg')).toHaveText('Select at least one tool.');
  await expect(page.locator('#import-msg')).toHaveClass(/err/);
  expect(seen.imports).toEqual([]);
});

test('Escape and the backdrop close the dialog and reset it', async ({ page }) => {
  await capabilitiesPage(page);
  await page.locator('#import-url').fill(SPEC_URL);
  await page.locator('#preview-btn').click();
  await expect(page.locator('.import-check')).toHaveCount(2);
  await page.keyboard.press('Escape');
  await expect(page.locator('#import-modal')).not.toHaveClass(/open/);
  await expect(page.locator('.import-check')).toHaveCount(0);
  await expect(page.locator('#import-btn')).toBeDisabled();
  await page.getByRole('button', { name: 'Import OpenAPI' }).click();
  await page.locator('#import-modal').click({ position: { x: 5, y: 5 } });
  await expect(page.locator('#import-modal')).not.toHaveClass(/open/);
});
