// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Per-route screens: the shell document names its screens in a manifest
// instead of loading them all, so a first paint carries the shell plus the
// current route's screen only. The rest load at idle, or when the palette opens.
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { test, expect } from './base.mjs';
import { shellReady } from './shell.mjs';

const SHELL_DIR = fileURLToPath(new URL('../../src/gateway/ui/shell/', import.meta.url));
const SHELL_RS = fileURLToPath(new URL('../../src/gateway/ui/shell.rs', import.meta.url));

/** A hashed asset's path, read from the shell directory at run time. */
function asset(stem, ext) {
  const name = readdirSync(SHELL_DIR).find((f) => new RegExp(`^${stem}\\.[0-9a-f]{12}\\.${ext}$`).test(f));
  if (!name) throw new Error(`no ${stem}.<hash>.${ext} in src/gateway/ui/shell`);
  return `/ui/assets/${name}`;
}

/** Every hashed stylesheet and module that is neither the shell's nor the tooltip's: the screens. */
const SCREEN_ASSETS = readdirSync(SHELL_DIR)
  .filter((f) => /^[a-z-]+\.[0-9a-f]{12}\.(js|css)$/.test(f) && !/^(shell|tooltip)\./.test(f))
  .map((f) => `/ui/assets/${f}`);

/** A signed-in admin and a short tools list, so the Tools screen has data. */
async function toolsApi(page) {
  await page.route('**/ui/api/status', (r) => r.fulfill({ json: { auth: { enabled: true, signed_in: true, admin: true } } }));
  await page.route('**/ui/api/tools**', (r) => r.fulfill({ json: { tools: [{ name: 'echo', server: 'alpha', description: 'Echoes', schema: { type: 'object' }, class: 'read', class_source: 'declared' }], total: 1 } }));
}

const toolRows = (page) => page.locator('#content table.t tbody tr.tool');

test('R1 the first load of /ui/overview/status asks for no screen before its first paint', async ({ page }) => {
  expect(SCREEN_ASSETS.length).toBeGreaterThan(0);
  await page.goto('/ui/overview/status');
  await shellReady(page);
  const early = await page.evaluate(async () => {
    while (!performance.getEntriesByName('first-contentful-paint').length) await new Promise((ok) => requestAnimationFrame(ok));
    const fcp = performance.getEntriesByName('first-contentful-paint')[0].startTime;
    return performance.getEntriesByType('resource').filter((r) => r.startTime < fcp).map((r) => new URL(r.name).pathname);
  });
  // The shell's own reads of /ui/api may start first; its assets are the shell's and the fonts.
  for (const name of early.filter((n) => n.startsWith('/ui/assets/'))) {
    expect(name, `requested before first paint: ${early.join(', ')}`).toMatch(/^\/ui\/assets\/(shell\.[0-9a-f]{12}\.(js|css)|[\w-]+\.[0-9a-f]{12}\.woff2)$/);
  }
});

test('R2 /ui/tools/status asks for the Tools screen and renders it', async ({ page }) => {
  await toolsApi(page);
  const asked = [];
  page.on('request', (r) => asked.push(new URL(r.url()).pathname));
  await page.goto('/ui/tools/status');
  await expect(toolRows(page)).toHaveCount(1);
  expect(asked).toContain(asset('tools', 'js'));
  expect(asked).toContain(asset('tools', 'css'));
});

test('R3 the palette lists the Tools screen entries when opened before idle loading finished', async ({ page }) => {
  let release;
  const gate = new Promise((ok) => { release = ok; });
  await page.route(`**${asset('tools', 'js')}`, async (r) => { await gate; return r.continue(); });
  await page.goto('/ui/overview/status');
  await shellReady(page);
  await page.keyboard.press('Control+KeyK');
  await expect(page.locator('dialog.palette')).toBeVisible();
  release();
  await expect(page.locator('dialog.palette [role="option"]', { hasText: 'All tools' })).toHaveCount(1);
});

test('R4 a screen module that fails to load shows the error state, and Retry loads it', async ({ page }) => {
  await toolsApi(page);
  let fail = true;
  await page.route(`**${asset('tools', 'js')}*`, (r) => (fail ? r.fulfill({ status: 500, body: '' }) : r.continue()));
  await page.goto('/ui/tools/status');
  const error = page.locator('#content [data-state="error"]');
  await expect(error).toBeVisible();
  const retry = error.getByRole('button', { name: 'Retry' });
  await expect(retry).toBeVisible();
  fail = false;
  await retry.click();
  await expect(toolRows(page)).toHaveCount(1);
  await expect(error).toHaveCount(0);
});

test('R5 the screen manifest names only files in the asset table, and the head loads no screen', () => {
  const doc = readFileSync(`${SHELL_DIR}index.html`, 'utf8');
  const block = doc.match(/<script type="application\/json" id="screens">([\s\S]*?)<\/script>/);
  expect(block, 'index.html carries the screen manifest').not.toBeNull();
  const manifest = JSON.parse(block[1]);
  const table = new Set([...readFileSync(SHELL_RS, 'utf8').matchAll(/"([^"]+)",\s*include_bytes!/g)].map((m) => m[1]));
  expect(Object.keys(manifest)).toContain('tools');
  for (const [id, entry] of Object.entries(manifest)) {
    expect(Object.keys(entry).sort(), id).toEqual(['css', 'js']);
    for (const path of [entry.js, entry.css]) {
      expect(path, id).toMatch(/^\/ui\/assets\//);
      expect(table.has(path.slice('/ui/assets/'.length)), `${path} is in ASSETS`).toBe(true);
    }
  }
  // Outside the manifest, the document names the shell's own files only.
  const outside = doc.replace(block[0], '');
  for (const m of outside.matchAll(/\/ui\/assets\/([^"'\s)]+)/g)) expect(m[1]).toMatch(/^shell\./);
});
