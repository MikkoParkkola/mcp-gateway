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
const OTHER_URL = 'https://specs.example.test/other.json';
const DIGEST = 'd'.repeat(64);
const CHANGED = 'The address now serves a different document.';

// `opts.importStatus`: the status the import mock answers (409 with an
// error sentence when not 200). `opts.held`: when set, each preview waits
// for `held.release(ok)` and answers success (true) or an error (false).
async function capabilitiesPage(page, opts = {}) {
  const seen = { previews: [], imports: [], listReads: 0 };
  await page.route('**/ui/classic', (route) => route.fulfill({
    status: 200,
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-cache, no-store, must-revalidate' },
    body: INDEX,
  }));
  await page.route('**/ui/api/**', async (route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname;
    const json = (body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
    if (path === '/ui/api/status') return json({ auth: { enabled: true, signed_in: true, admin: true }, servers: [], version: 'test' });
    if (path === '/ui/api/import/openapi/preview') {
      seen.previews.push(req.postDataJSON());
      const ok = opts.held ? await new Promise((release) => { opts.held.release = release; }) : true;
      if (!ok) return json({ error: 'fetch failed' }, 502);
      return json({ tools: [{ name: 'list_pets', description: 'Lists pets' }, { name: 'delete_pet', description: 'Deletes a pet' }], digest: DIGEST });
    }
    if (path === '/ui/api/import/openapi') {
      seen.imports.push(req.postDataJSON());
      if (opts.importStatus && opts.importStatus !== 200) return json({ error: CHANGED }, opts.importStatus);
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
  // The import carries the previewed URL and the digest its preview answered.
  expect(seen.imports).toEqual([{ url: SPEC_URL, digest: DIGEST, selected_tools: ['list_pets'] }]);
});

test('a 409 import shows its sentence and Import waits for a new preview', async ({ page }) => {
  const seen = await capabilitiesPage(page, { importStatus: 409 });
  await page.locator('#import-url').fill(SPEC_URL);
  await page.locator('#preview-btn').click();
  await expect(page.locator('#import-count')).toHaveText('2 / 2 selected');
  await page.getByRole('button', { name: 'Import Selected' }).click();
  await expect(page.locator('#import-msg')).toHaveText('Import failed: ' + CHANGED);
  await expect(page.locator('#import-btn')).toBeDisabled();
  expect(seen.imports).toHaveLength(1);
  // A new preview offers Import again.
  await page.locator('#preview-btn').click();
  await expect(page.locator('#import-btn')).toBeEnabled();
});

test('editing the URL after a preview disables Import until a new preview', async ({ page }) => {
  await capabilitiesPage(page);
  await page.locator('#import-url').fill(SPEC_URL);
  await page.locator('#preview-btn').click();
  await expect(page.locator('#import-btn')).toBeEnabled();
  await page.locator('#import-url').fill(OTHER_URL);
  await expect(page.locator('#import-btn')).toBeDisabled();
  await page.locator('#preview-btn').click();
  await expect(page.locator('#import-btn')).toBeEnabled();
});

for (const ok of [true, false]) {
  test(`a preview answer (${ok ? 'success' : 'error'}) after a URL edit is dropped`, async ({ page }) => {
    const held = {};
    const seen = await capabilitiesPage(page, { held });
    await page.locator('#import-url').fill(SPEC_URL);
    await page.locator('#preview-btn').click();
    await expect.poll(() => seen.previews.length).toBe(1);
    await expect.poll(() => typeof held.release).toBe('function');
    await page.locator('#import-url').fill(OTHER_URL);
    held.release(ok);
    await expect(page.locator('#preview-btn')).toBeEnabled();
    // Nothing drawn from the stale answer, and nothing kept to import with.
    await expect(page.locator('.import-check')).toHaveCount(0);
    await expect(page.locator('#import-msg')).toHaveText('');
    await expect(page.locator('#import-btn')).toBeDisabled();
    expect(seen.imports).toEqual([]);
  });
}

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
