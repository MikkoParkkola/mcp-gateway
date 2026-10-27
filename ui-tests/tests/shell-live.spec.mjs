// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// One polite live region: page banners, Retry recovery and To do count
// changes are announced through it, and nothing else in the shell is live.
// Rows L1-L7.
import { test, expect, WIDTHS, blockingViolations } from './base.mjs';
import { withFixturePages, shellReady, shellModuleUrl } from './shell.mjs';

const PROBE = '**/ui/api/page-probe*';
const COUNT = '**/ui/api/decisions/count';

/** Record every non-empty text the announcer is given, from first paint. */
async function recordAnnouncements(page) {
  await page.addInitScript(() => {
    window.__announced = [];
    addEventListener('DOMContentLoaded', () => {
      const region = document.getElementById('announcer');
      if (!region) return;
      new MutationObserver(() => {
        const text = region.textContent.trim();
        if (text) window.__announced.push(text);
      }).observe(region, { childList: true, characterData: true, subtree: true });
    });
  });
}

const announced = (page) => page.evaluate(() => window.__announced ?? []);

/** Call an export of the shell module inside the page. */
async function callShell(page, name, ...args) {
  const url = await shellModuleUrl(page);
  await page.evaluate(async ([u, n, a]) => { const m = await import(u); await m[n](...a); }, [url, name, args]);
}

/** Wait two frames, so a coalesced announcement has been written. */
const frames = (page) => page.evaluate(() => new Promise((done) => requestAnimationFrame(() => requestAnimationFrame(done))));

test('L1 the shell has exactly one live region, polite and atomic', async ({ page }) => {
  await withFixturePages(page);
  await page.goto('/ui/overview/status');
  await shellReady(page);
  const live = await page.evaluate(() => [...document.querySelectorAll(
    '[aria-live], [role="status"], [role="alert"], [role="log"], [role="marquee"], [role="timer"]',
  )].filter((node) => !node.closest('#signin')).map((node) => node.id || node.className));
  expect(live).toEqual(['announcer']);
  const region = page.locator('#announcer');
  await expect(region).toHaveAttribute('aria-live', 'polite');
  await expect(region).toHaveAttribute('aria-atomic', 'true');
});

test('L2 a page error is announced once, and its banner is not itself live', async ({ page }) => {
  await recordAnnouncements(page);
  await page.route(PROBE, (r) => r.fulfill({ status: 500, json: {} }));
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/policies/status');
  await expect(page.locator('#content [data-state="error"]')).toBeVisible();
  await frames(page);
  const said = await announced(page);
  expect(said.filter((t) => t.includes('The gateway answered with an error'))).toHaveLength(1);
  await expect(page.locator('#content [data-state="error"]')).not.toHaveAttribute('role', /.+/);
});

test('L3 a forbidden page is announced', async ({ page }) => {
  await recordAnnouncements(page);
  await page.route('**/ui/api/forbidden-probe', (r) => r.fulfill({ status: 403, json: {} }));
  await withFixturePages(page);
  await page.goto('/ui/access/status');
  await expect(page.locator('#content [data-state="forbidden"]')).toBeVisible();
  await frames(page);
  expect((await announced(page)).some((t) => t.includes('Not available to this key'))).toBe(true);
});

test('L4 a Retry that succeeds announces the page is back', async ({ page }) => {
  await recordAnnouncements(page);
  let ok = false;
  await page.route(PROBE, (r) => (ok ? r.fulfill({ json: { value: 2 } }) : r.fulfill({ status: 503, json: {} })));
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/policies/status');
  await expect(page.locator('#content [data-state="error"]')).toBeVisible();
  ok = true;
  await page.locator('#content [data-state="error"] button').click();
  await expect(page.locator('#content')).toContainText('value 2');
  await frames(page);
  expect(await announced(page)).toContain('Policies is back.');
});

test('L5 the To do count is announced when it changes, and only then', async ({ page }) => {
  await recordAnnouncements(page);
  let count = 3;
  await page.route(COUNT, (r) => r.fulfill({ json: { count } }));
  await page.goto('/ui/overview/status');
  await shellReady(page);
  await expect(page.locator('nav.route-nav .count')).toHaveText('3');
  await frames(page);
  expect((await announced(page)).filter((t) => t.includes('decide'))).toEqual([]);
  count = 5;
  await callShell(page, 'refreshCounts');
  await frames(page);
  expect((await announced(page)).filter((t) => t.includes('decide'))).toEqual(['5 to decide']);
  await callShell(page, 'refreshCounts');
  await frames(page);
  expect((await announced(page)).filter((t) => t.includes('decide'))).toEqual(['5 to decide']);
  count = 0;
  await callShell(page, 'refreshCounts');
  await frames(page);
  expect((await announced(page)).filter((t) => t.includes('decide'))).toEqual(['5 to decide', 'Nothing to decide']);
});

test('L6 the same message twice is announced twice', async ({ page }) => {
  await recordAnnouncements(page);
  await page.goto('/ui/overview/status');
  await shellReady(page);
  await callShell(page, 'announce', 'Saved.');
  await frames(page);
  await callShell(page, 'announce', 'Saved.');
  await frames(page);
  expect((await announced(page)).filter((t) => t === 'Saved.')).toHaveLength(2);
});

test('L7 a screen announces through the render context', async ({ page }) => {
  await recordAnnouncements(page);
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/gateway/status');
  await shellReady(page);
  await frames(page);
  expect(await announced(page)).toContain('Gateway status read.');
});

for (const width of WIDTHS) {
  test(`L8 axe at ${width} px with an announced page error`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.route(PROBE, (r) => r.fulfill({ status: 500, json: {} }));
    await withFixturePages(page, { probes: true });
    await page.goto('/ui/policies/status');
    await expect(page.locator('#content [data-state="error"]')).toBeVisible();
    expect(await blockingViolations(page)).toEqual([]);
  });
}
