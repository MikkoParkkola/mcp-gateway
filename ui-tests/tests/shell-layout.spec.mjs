// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The shell holds its layout from first paint: rows L1, L2, L2b.
// L1: the tab row and the subtitle line take their height before the status
// answer and the page's data arrive, so neither moves the content.
// L2: data drawn while the loading state still holds its minimum stays hidden
// until the state goes, then appears where the state was.
// L2b: the copy saved for an error banner is the visible page, not the hidden one.
// The loading state's 300 ms delay (a fast page never shows it) is G2's row.
import { test, expect } from './base.mjs';
import { withFixturePages } from './shell.mjs';

const PROBE = '**/ui/api/page-probe*';
const loading = (page) => page.locator('#content [data-state="loading"]');

/** A route answer held until `release()`. */
function held() {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  return { release, gate };
}

/**
 * Record every layout shift with its sources, named by element, from before
 * the first paint. Only shifts without recent input count, as CLS counts them.
 */
async function recordShifts(page) {
  await page.addInitScript(() => {
    window.__shifts = [];
    const name = (n) => {
      if (!n || !n.tagName) return String(n && n.nodeName);
      if (n.id) return `${n.tagName.toLowerCase()}#${n.id}`;
      const cls = typeof n.className === 'string' && n.className.trim() ? `.${n.className.trim().split(/\s+/).join('.')}` : '';
      const inContent = n.closest && n.closest('#content') ? ' in #content' : '';
      return `${n.tagName.toLowerCase()}${cls}${inContent}`;
    };
    new PerformanceObserver((list) => {
      for (const e of list.getEntries()) {
        if (e.hadRecentInput) continue;
        window.__shifts.push({ t: e.startTime, sources: (e.sources || []).map((s) => name(s.node)) });
      }
    }).observe({ type: 'layout-shift', buffered: true });
  });
}

/** Two frames, so a shift caused by the last change is reported before reading. */
async function settle(page) {
  await page.evaluate(() => new Promise((done) => requestAnimationFrame(() => requestAnimationFrame(done))));
}

/**
 * Shifts after `after` that moved the shell's frame: the title, the subtitle, the tab row or the
 * content area. With `inside`, also anything inside the content area.
 */
async function shellShifts(page, { after = 0, inside = false } = {}) {
  return page.evaluate(([from, deep]) => window.__shifts
    .filter((s) => s.t >= from)
    .filter((s) => s.sources.some((n) => /^(main#content|nav\.tabs|p\.sub|h1)$/.test(n) || (deep && n.endsWith(' in #content')))),
  [after, inside]);
}

const contentTop = (page) => page.locator('#content').evaluate((e) => e.getBoundingClientRect().top);

test('L1 the tab row and the subtitle line hold their height from first paint: nothing moves the content', async ({ page }) => {
  // Tools, a screen whose module loads after the first paint: its tab row and
  // its subtitle (the catalogue count) arrive late, as on a real gateway.
  await recordShifts(page);
  const module = held();
  const catalogue = held();
  const tools = [
    { name: 'alpha_read', server: 'alpha', description: 'Reads', schema: { type: 'object' }, class: 'read', class_source: 'declared' },
    { name: 'bravo_write', server: 'bravo', description: 'Writes', schema: { type: 'object' }, class: 'write', class_source: 'declared' },
  ];
  await page.route('**/ui/api/status', (r) => r.fulfill({ json: { auth: { enabled: true, signed_in: true, admin: true } } }));
  await page.route(/\/ui\/assets\/tools\.[0-9a-f]{12}\.js$/, async (r) => { await module.gate; await r.continue(); });
  await page.route('**/ui/api/tools**', async (r) => { await catalogue.gate; await r.fulfill({ json: { tools, total: tools.length } }); });
  await page.goto('/ui/tools/status');
  await expect(page.locator('#content')).toBeVisible();
  await expect(page.locator('nav.tabs a'), 'the premise: no tab before the module loads').toHaveCount(0);
  const boot = await contentTop(page);

  module.release();
  await expect(page.locator('nav.tabs a')).toHaveText(['Status']);
  await settle(page);
  const rendered = await contentTop(page);

  // Released once the loading state has outlived its 400 ms minimum, so the
  // state goes in the same task the data is drawn: only the tab row and the
  // subtitle line can move the content in this row (L2 is the other case).
  await expect(loading(page)).toBeVisible();
  await page.waitForFunction(() => {
    const shown = performance.getEntriesByName('ui-loading-shown', 'mark').at(-1);
    return shown && performance.now() - shown.startTime > 450;
  });
  catalogue.release();
  await expect(page.locator('.head .sub')).toHaveText('2 tools from 2 servers. Agents find them through search and invoke.');
  await expect(loading(page)).toHaveCount(0);
  await settle(page);
  const drawn = await contentTop(page);

  expect([rendered, drawn], 'the content stays where it first painted').toEqual([boot, boot]);
  // Inside Tools, its load note can nudge the server select sideways: a screen detail, not the shell's.
  expect(await shellShifts(page), 'no shift moved the title, the subtitle, the tabs or the content').toEqual([]);
});

test('L2 data that arrives while the loading state holds its minimum stays hidden, then appears where the state was', async ({ page }) => {
  await recordShifts(page);
  const probe = held();
  await page.route(PROBE, async (r) => { await probe.gate; await r.fulfill({ json: { value: 1 } }); });
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/policies/status');
  await expect(loading(page)).toBeVisible();
  const stateTop = await loading(page).evaluate((e) => e.getBoundingClientRect().top);
  const shownAt = await page.evaluate(() => performance.getEntriesByName('ui-loading-shown', 'mark')[0].startTime);

  probe.release();
  // The data is in the page while the state still holds its 400 ms minimum.
  await page.waitForFunction(() => document.getElementById('probe-link'));
  const during = await page.evaluate(() => ({
    state: Boolean(document.querySelector('#content [data-state="loading"]')),
    linkVisible: document.getElementById('probe-link').checkVisibility(),
  }));
  expect(during.state, 'the premise: the state is still up when the data is drawn').toBe(true);
  expect(during.linkVisible, 'the drawn data stays hidden under the held state').toBe(false);

  await expect(loading(page)).toHaveCount(0);
  await expect(page.locator('#probe-link')).toBeVisible();
  const dataTop = await page.locator('#content [data-rendered]').evaluate((e) => e.getBoundingClientRect().top);
  expect(dataTop, 'the data appears where the state was').toBe(stateTop);
  await settle(page);
  expect(await shellShifts(page, { after: shownAt, inside: true }), 'no shift once the state showed').toEqual([]);
});

test('L2c focus a screen gives what it drew under the held state is there when the data shows', async ({ page }) => {
  const probe = held();
  await page.route(PROBE, async (r) => { await probe.gate; await r.fulfill({ json: { value: 'focus' } }); });
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/policies/status');
  await expect(loading(page)).toBeVisible();
  probe.release();
  await expect(loading(page)).toHaveCount(0);
  await expect(page.locator('#probe-link')).toBeVisible();
  await expect(page.locator('#probe-link')).toBeFocused();
});

test('L2b the copy an error banner shows is the page as it was seen, not a hidden one', async ({ page }) => {
  const probe = held();
  let fail = false;
  await page.route(PROBE, async (r) => {
    if (fail) return r.fulfill({ status: 500, json: { error: 'down' } });
    await probe.gate;
    return r.fulfill({ json: { value: 1 } });
  });
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/policies/status');
  // Drawn under a held loading state: the case that hides the body for a moment.
  await expect(loading(page)).toBeVisible();
  probe.release();
  await expect(page.locator('#probe-link')).toBeVisible();

  fail = true;
  await page.locator('nav.route-nav a[href="/ui/servers"]').click();
  await expect(page.locator('#content')).toContainText('servers - status');
  await page.locator('nav.route-nav a[href="/ui/policies"]').click();
  const before = page.getByRole('region', { name: 'Data from before the error', exact: true });
  await expect(before).toContainText('value 1');
  await expect(before.getByText('value 1')).toBeVisible();
});
