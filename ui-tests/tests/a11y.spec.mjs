// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The accessibility gate (rows A1-A4): axe at WCAG 2.2 AA on every page and
// tab, with and without the fixture pages, at 390 and 1440 px, dark and
// light; again with a tooltip open; and a keyboard walk that reaches every
// focusable control. blockingViolations() fails on serious or critical, and
// on any contrast, name or alt rule at any impact.
import { test, expect, WIDTHS, blockingViolations } from './base.mjs';
import { PAGES, TABS, withFixturePages, shellModuleUrl, shellReady } from './shell.mjs';

const THEMES = ['dark', 'light'];

// Each A1 case walks 27 addresses; give it room on a slow runner.
test.describe.configure({ timeout: 180_000 });

for (const width of WIDTHS) {
  for (const theme of THEMES) {
    for (const fixtures of [false, true]) {
      test(`A1 axe on every page and tab at ${width} px, ${theme}, ${fixtures ? 'with' : 'without'} screens`, async ({ page }) => {
        await page.setViewportSize({ width, height: 900 });
        await page.emulateMedia({ colorScheme: theme });
        if (fixtures) await withFixturePages(page);
        const found = [];
        for (const [id] of PAGES) {
          for (const tab of TABS) {
            await page.goto(`/ui/${id}/${tab}`);
            await shellReady(page);
            for (const v of await blockingViolations(page)) found.push(`/ui/${id}/${tab}: ${v}`);
          }
        }
        expect(found).toEqual([]);
      });
    }

    test(`A2 axe with a tooltip open at ${width} px, ${theme}`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await page.emulateMedia({ colorScheme: theme });
      await page.goto('/ui/overview/status');
      await shellReady(page);
      const url = await shellModuleUrl(page);
      const ok = await page.evaluate(async (url) => {
        const shell = await import(url);
        await shell.tipsReady();
        const t = shell.tip('gateway.actions.configuration-versions');
        if (!t) return false;
        document.getElementById('content').append(t);
        return true;
      }, url);
      expect(ok).toBe(true);
      await page.locator('.has-tip button').focus();
      await expect(page.locator('.has-tip .tip')).toHaveClass(/open/);
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
  const missed = [];
  for (const [id] of PAGES) {
    for (const tab of TABS) {
      await page.goto(`/ui/${id}/${tab}`);
      await shellReady(page);
      const result = await page.evaluate(async () => {
        const sel = 'a[href], button, input, select, textarea, [tabindex]:not([tabindex="-1"]), summary';
        const all = [...document.querySelectorAll(sel)].filter((e) => e.checkVisibility() && !e.disabled);
        return all.length;
      });
      const seen = new Set();
      for (let i = 0; i < result + 3; i++) {
        await page.keyboard.press('Tab');
        seen.add(await page.evaluate(() => {
          const e = document.activeElement;
          if (!e || e === document.body) return '';
          e.dataset.walk = e.dataset.walk || String(Math.random());
          return e.dataset.walk;
        }));
      }
      const unreached = await page.evaluate(() => {
        const sel = 'a[href], button, input, select, textarea, [tabindex]:not([tabindex="-1"]), summary';
        return [...document.querySelectorAll(sel)].filter((e) => e.checkVisibility() && !e.disabled && !e.dataset.walk).map((e) => e.outerHTML.slice(0, 60));
      });
      for (const u of unreached) missed.push(`/ui/${id}/${tab}: ${u}`);
    }
  }
  expect(missed).toEqual([]);
});
