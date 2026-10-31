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

test('R4b retrying a screen whose module failed keeps one copy of its loaded stylesheet', async ({ page }) => {
  await toolsApi(page);
  let fail = true;
  await page.route(`**${asset('tools', 'js')}*`, (r) => (fail ? r.fulfill({ status: 500, body: '' }) : r.continue()));
  await page.goto('/ui/tools/status');
  const error = page.locator('#content [data-state="error"]');
  await expect(error).toBeVisible();
  fail = false;
  await error.getByRole('button', { name: 'Retry' }).click();
  await expect(toolRows(page)).toHaveCount(1);
  await expect(page.locator(`head link[rel="stylesheet"][href="${asset('tools', 'css')}"]`)).toHaveCount(1);
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

test('R6 a stylesheet that fails while its module loads shows Retry, and Retry links it once', async ({ page }) => {
  await toolsApi(page);
  let fail = true;
  await page.route(`**${asset('tools', 'css')}*`, (r) => (fail ? r.fulfill({ status: 500, body: '' }) : r.continue()));
  await page.goto('/ui/tools/status');
  const error = page.locator('#content [data-state="error"]');
  await expect(error).toBeVisible();
  fail = false;
  await error.getByRole('button', { name: 'Retry' }).click();
  await expect(toolRows(page)).toHaveCount(1);
  await expect(page.locator(`head link[rel="stylesheet"][href="${asset('tools', 'css')}"]`)).toHaveCount(1);
});

test('R7 a screen is not drawn while its stylesheet is held, even after its module registered', async ({ page }) => {
  await toolsApi(page);
  let release;
  const gate = new Promise((ok) => { release = ok; });
  await page.route(`**${asset('tools', 'css')}*`, async (r) => { await gate; return r.continue(); });
  const moduleIn = page.waitForResponse((r) => r.url().endsWith(asset('tools', 'js')));
  // The held stylesheet holds the load event, so wait for the document only.
  await page.goto('/ui/tools/status', { waitUntil: 'domcontentloaded' });
  await moduleIn;
  await page.click('nav.route-nav a[data-page="overview"]');
  await expect(page.locator('.head .plate')).toHaveText('Overview');
  await page.click('nav.route-nav a[data-page="tools"]');
  await expect(page.locator('.head .plate')).toHaveText('Tools');
  // Held: the content is the unmarked loading body, never the screen.
  await expect(page.locator('#content [data-rendered]')).toHaveCount(0);
  await expect(toolRows(page)).toHaveCount(0);
  release();
  await expect(toolRows(page)).toHaveCount(1);
});

test('R8 a manifest entry outside /ui/assets/ is refused as a load error and never fetched', async ({ page, baseURL }) => {
  await toolsApi(page);
  const js = asset('tools', 'js');
  const css = asset('tools', 'css');
  const host = new URL(baseURL).host;
  await page.route('**/ui/tools/status', async (r) => {
    const res = await r.fetch();
    const body = (await res.text()).replace(`"${js}"`, `"//${host}${js}"`).replace(`"${css}"`, '"/ui/assets/../x.css"');
    return r.fulfill({ response: res, body });
  });
  const asked = [];
  page.on('request', (r) => asked.push(new URL(r.url()).pathname));
  await page.goto('/ui/tools/status');
  await expect(page.locator('#content [data-state="error"]')).toBeVisible();
  expect(asked).not.toContain(js);
  await expect(page.locator('head link[href*="x.css"]')).toHaveCount(0);
  await expect(toolRows(page)).toHaveCount(0);
});

test('R9 a screen that arrives after the user moved on draws nothing into the page shown', async ({ page }) => {
  await toolsApi(page);
  let release;
  const gate = new Promise((ok) => { release = ok; });
  await page.route(`**${asset('tools', 'js')}`, async (r) => { await gate; return r.continue(); });
  await page.goto('/ui/tools/status');
  await expect(page.locator('.head .plate')).toHaveText('Tools');
  await page.click('nav.route-nav a[data-page="overview"]');
  await expect(page.locator('.head .plate')).toHaveText('Overview');
  release();
  // The palette lists the screen once it has registered: the load has settled.
  await page.keyboard.press('Control+KeyK');
  await expect(page.locator('dialog.palette [role="option"]', { hasText: 'All tools' })).toHaveCount(1);
  await page.keyboard.press('Escape');
  await expect(page).toHaveURL('/ui/overview');
  await expect(page.locator('.head .plate')).toHaveText('Overview');
  await expect(page.locator('#content [data-state="not-built"]')).toBeVisible();
  await expect(page.locator('#content table.t')).toHaveCount(0);
});

test('R10 with idle loading suppressed, opening the palette loads the screens it lists', async ({ page }) => {
  await page.addInitScript(() => { window.requestIdleCallback = () => 0; });
  await page.goto('/ui/overview/status');
  await shellReady(page);
  await page.keyboard.press('Control+KeyK');
  await expect(page.locator('dialog.palette [role="option"]', { hasText: 'All tools' })).toHaveCount(1);
});

test('R12 the screen preload asks for idle time with a two-second deadline, so a page that never idles still preloads', async ({ page }) => {
  // Record every idle request's options, then pass it on to the browser. This
  // pins the deadline the shell configures; it does not starve the page.
  await page.addInitScript(() => {
    window.idleOptions = [];
    const ask = window.requestIdleCallback.bind(window);
    window.requestIdleCallback = (fn, options) => {
      window.idleOptions.push(options ?? null);
      return ask(fn, options);
    };
  });
  const preload = page.waitForRequest((r) => r.url().endsWith(asset('tools', 'js')));
  await page.goto('/ui/overview/status');
  await shellReady(page);
  await preload;
  const asked = await page.evaluate(() => window.idleOptions);
  expect(asked.length, 'the preload asks for idle time').toBeGreaterThan(0);
  for (const options of asked) {
    expect(options?.timeout, `a deadline on ${JSON.stringify(options)}`).toBe(2000);
  }
});

for (const [name, init] of [
  ['without PerformanceObserver', () => { delete window.PerformanceObserver; }],
  ['when observing paint throws', () => {
    window.PerformanceObserver = class { observe() { throw new TypeError('no paint'); } disconnect() {} };
  }],
]) {
  test(`R11 ${name}, the idle preload still runs after the first render and boot finishes`, async ({ page }) => {
    await page.addInitScript(init);
    const preload = page.waitForRequest((r) => r.url().endsWith(asset('tools', 'js')));
    const counts = page.waitForRequest((r) => r.url().includes('/ui/api/decisions/count'));
    await page.goto('/ui/overview/status');
    await shellReady(page);
    await preload;
    await counts;
  });
}
