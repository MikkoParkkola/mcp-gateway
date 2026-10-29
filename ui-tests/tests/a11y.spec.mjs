// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The accessibility gate (rows A1-A4): axe at WCAG 2.2 AA on every page and
// tab, with and without the fixture pages, at 390 and 1440 px, dark and light.
// On a built page and tab whose screen draws a tooltip, one is opened first. In the
// fixture runs every page is a fixture screen that draws none, so those runs check
// the pages bare; A2 covers a tooltip open on a fixture page.
// Also: a tooltip open on a fixture page (A2), a planted violation (A3), and a
// keyboard walk that reaches every focusable control (A4).
// blockingViolations() fails on serious or critical, and on any contrast, name
// or alt rule at any impact.
import { test, expect, WIDTHS, blockingViolations } from './base.mjs';
import { PAGES, TABS, withFixturePages, shellReady, tooltipModuleUrl } from './shell.mjs';
import { readScreens, scanScreens } from './copy-check.mjs';

const THEMES = ['dark', 'light'];
const TOOLS = [
  { name: 'list_dir', server: 'filesystem', description: 'List a folder inside the allowed paths' },
  { name: 'search', server: 'web', description: 'Search the web' },
];
// Built page and tab -> the first tooltip id its screen draws, from the same static scan as C1 and C9.
const FIRST_TIP = {};
for (const id of scanScreens(readScreens()).drawn) {
  const [page, tab] = id.split('.');
  FIRST_TIP[`${page}.${tab}`] ??= id;
}

async function tipsSettled(page) {
  await page.evaluate(async (url) => (await import(url)).tipsSettled(), tooltipModuleUrl());
}

// Each A1 case walks 27 addresses; give it room on a slow runner.
test.describe.configure({ timeout: 180_000 });

for (const width of WIDTHS) {
  for (const theme of THEMES) {
    for (const fixtures of [false, true]) {
      test(`A1 axe on every page and tab at ${width} px, ${theme}, ${fixtures ? 'with' : 'without'} fixture screens`, async ({ page }) => {
        await page.setViewportSize({ width, height: 900 });
        await page.emulateMedia({ colorScheme: theme });
        if (fixtures) await withFixturePages(page);
        // The fixture server has no tool list, so the built Tools screen gets one here and draws its toolbar.
        await page.route('**/ui/api/tools**', (r) => r.fulfill({ json: { tools: TOOLS } }));
        const found = [];
        for (const [id] of PAGES) {
          for (const tab of TABS) {
            await page.goto(`/ui/${id}/${tab}`);
            await shellReady(page);
            const tip = fixtures ? null : FIRST_TIP[`${id}.${tab}`];
            if (tip) {
              await tipsSettled(page);
              await page.locator(`.has-tip[data-tip="${tip}"] button`).focus();
              await expect(page.locator('.tip.open'), `/ui/${id}/${tab} opens ${tip}`).toHaveCount(1);
              await expect(page.locator(`.has-tip[data-tip="${tip}"] .tip`)).toHaveClass(/open/);
              // axe measures colour as drawn: wait out the fade-in, or a half-faded title reads as low contrast.
              await page.evaluate(() => Promise.all(document.getAnimations().map((x) => x.finished)));
            }
            for (const v of await blockingViolations(page)) found.push(`/ui/${id}/${tab}: ${v}`);
          }
        }
        expect(found).toEqual([]);
      });
    }

    test(`A2 axe with a tooltip open on a fixture page at ${width} px, ${theme}`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await page.emulateMedia({ colorScheme: theme });
      await withFixturePages(page);
      await page.goto('/ui/overview/status');
      await shellReady(page);
      await page.evaluate(async (url) => {
        const tips = await import(url);
        await tips.tipsSettled();
        const p = document.createElement('p');
        p.append('Tools ', tips.tip('tools.status.load-11-tools-and-reach'));
        document.getElementById('content').append(p);
      }, tooltipModuleUrl());
      await expect(page.locator('.tip-i')).toHaveCount(1);
      await page.locator('.has-tip button').focus();
      await expect(page.locator('.tip.open')).toHaveCount(1);
      await page.evaluate(() => Promise.all(document.getAnimations().map((x) => x.finished))); // as in A1
      expect(await blockingViolations(page)).toEqual([]);
    });
  }
}

test('A3 the gate reports a planted violation', async ({ page }) => {
  await page.goto('/ui/overview/status');
  await shellReady(page);
  await page.evaluate(() => document.getElementById('content').append(document.createElement('button')));
  expect((await blockingViolations(page)).some((v) => v.startsWith('button-name'))).toBe(true);
});

test('A4 Tab reaches every focusable control on every page and tab', async ({ page }) => {
  await withFixturePages(page);
  const sel = 'a[href], button, input, select, textarea, [tabindex]:not([tabindex="-1"]), summary';
  const missed = [];
  for (const [id] of PAGES) {
    for (const tab of TABS) {
      await page.goto(`/ui/${id}/${tab}`);
      await shellReady(page);
      await tipsSettled(page);
      const total = await page.evaluate((sel) => [...document.querySelectorAll(sel)].filter((e) => e.checkVisibility() && !e.disabled).length, sel);
      expect(total, `/ui/${id}/${tab} has controls`).toBeGreaterThan(0);
      for (let i = 0; i < total + 3; i++) {
        await page.keyboard.press('Tab');
        await page.evaluate(() => { const e = document.activeElement; if (e && e !== document.body) e.dataset.walk = '1'; });
      }
      const unreached = await page.evaluate((sel) => [...document.querySelectorAll(sel)]
        .filter((e) => e.checkVisibility() && !e.disabled && !e.dataset.walk).map((e) => e.outerHTML.slice(0, 60)), sel);
      for (const u of unreached) missed.push(`/ui/${id}/${tab}: ${u}`);
    }
  }
  expect(missed).toEqual([]);
});

test('A4b Tab reaches every focusable control on the real Tools screen, its tooltip included', async ({ page }) => {
  await page.route('**/ui/api/tools**', (r) => r.fulfill({ json: { tools: TOOLS } }));
  await page.goto('/ui/tools/status');
  await shellReady(page);
  await expect(page.locator('.tools-load .tip-i')).toBeVisible();
  const sel = 'a[href], button, input, select, textarea, [tabindex]:not([tabindex="-1"]), summary';
  const total = await page.evaluate((sel) => [...document.querySelectorAll(sel)].filter((e) => e.checkVisibility() && !e.disabled).length, sel);
  for (let i = 0; i < total + 3; i++) {
    await page.keyboard.press('Tab');
    await page.evaluate(() => { const e = document.activeElement; if (e && e !== document.body) e.dataset.walk = '1'; });
  }
  const unreached = await page.evaluate((sel) => [...document.querySelectorAll(sel)]
    .filter((e) => e.checkVisibility() && !e.disabled && !e.dataset.walk).map((e) => e.outerHTML.slice(0, 60)), sel);
  expect(unreached).toEqual([]);
});
