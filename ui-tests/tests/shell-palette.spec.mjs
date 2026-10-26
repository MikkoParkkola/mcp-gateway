// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The command palette, the segmented control and the phone menu's
// decisions count. Rows P1-P7 of the shell test plan.
import { test, expect, WIDTHS, blockingViolations } from './base.mjs';
import { PAGES, withFixturePages, shellModuleUrl, shellReady } from './shell.mjs';

const TODO = PAGES[1][0];

async function openWithKeys(page, mod) {
  await page.keyboard.press(`${mod}+KeyK`);
  await expect(page.locator('dialog.palette')).toBeVisible();
}

test.describe('palette', () => {
  test('P1 Ctrl+K, Meta+K and the search button open the palette', async ({ page }) => {
    await page.goto('/ui/overview/status');
    await shellReady(page);
    for (const mod of ['Control', 'Meta']) {
      await openWithKeys(page, mod);
      await page.keyboard.press('Escape');
      await expect(page.locator('dialog.palette')).toHaveCount(0);
    }
    await page.locator('button.search').click();
    await expect(page.locator('dialog.palette input')).toBeFocused();
  });

  test('P2 it lists the pages with no screens registered', async ({ page }) => {
    await page.goto('/ui/overview/status');
    await shellReady(page);
    await openWithKeys(page, 'Control');
    const labels = await page.locator('dialog.palette [role="option"] span:first-child').allTextContents();
    for (const [, label] of PAGES) expect(labels).toContain(label);
  });

  test('P2 it lists every visible tab and the declared actions and settings, in their groups', async ({ page }) => {
    await withFixturePages(page);
    await page.goto('/ui/overview/status');
    await shellReady(page);
    await openWithKeys(page, 'Control');
    const options = page.locator('dialog.palette [role="option"]');
    // 9 pages + 26 visible tabs + 9 declared entries
    await expect(options).toHaveCount(44);
    await expect(page.locator('dialog.palette [role="option"][data-path="/ui/servers/actions"]')).toContainText('Servers › Actions');
    await expect(page.locator('dialog.palette .palette-group')).toHaveText(['Go to', 'Actions, opens the Actions tab', 'Settings']);
  });

  test('P2 typing filters and Enter goes to the active entry', async ({ page }) => {
    await withFixturePages(page);
    await page.goto('/ui/overview/status');
    await shellReady(page);
    await openWithKeys(page, 'Control');
    await page.keyboard.type('costs');
    const options = page.locator('dialog.palette [role="option"]');
    expect(await options.count()).toBeGreaterThan(0);
    for (const text of await options.allTextContents()) expect(text.toLowerCase()).toContain('costs');
    await page.keyboard.press('ArrowDown');
    const chosen = await page.locator('dialog.palette [role="option"][aria-selected="true"]').getAttribute('data-path');
    await page.keyboard.press('Enter');
    await expect(page.locator('dialog.palette')).toHaveCount(0);
    expect(new URL(page.url()).pathname).toBe(chosen.split('#')[0].replace(/^\/ui\/costs$/, '/ui/costs/status'));
  });

  test('P2 a search with no match says so', async ({ page }) => {
    await page.goto('/ui/overview/status');
    await shellReady(page);
    await openWithKeys(page, 'Control');
    await page.keyboard.type('zzzz-nothing');
    await expect(page.locator('dialog.palette [role="option"]')).toHaveCount(0);
    await expect(page.locator('dialog.palette')).toContainText('No page, action or setting matches.');
  });

  test('P3 choosing every entry only changes the address, and entries are plain data', async ({ page }) => {
    await withFixturePages(page);
    await page.goto('/ui/overview/status');
    await shellReady(page);
    const url = await shellModuleUrl(page);
    const shapes = await page.evaluate(async (url) => {
      const { entries } = await import(url);
      return entries().map((e) => Object.entries(e).map(([k, v]) => `${k}:${typeof v}`).sort().join(','));
    }, url);
    expect(new Set(shapes)).toEqual(new Set(['kind:string,label:string,path:string']));
    const writes = [];
    page.on('request', (r) => { if (r.method() !== 'GET' && r.method() !== 'HEAD') writes.push(`${r.method()} ${r.url()}`); });
    const paths = await page.evaluate(async (url) => (await import(url)).entries().map((e) => e.path), url);
    for (const path of paths) {
      await openWithKeys(page, 'Control');
      await page.locator(`dialog.palette [role="option"][data-path="${path}"]`).first().click();
      await expect(page.locator('dialog.palette')).toHaveCount(0);
      expect(new URL(page.url()).pathname.startsWith('/ui/')).toBe(true);
    }
    expect(writes).toEqual([]);
  });

  test('P4 Esc closes the palette and focus returns to its opener', async ({ page }) => {
    await page.goto('/ui/overview/status');
    await shellReady(page);
    const opener = page.locator('button.search');
    await opener.focus();
    await page.keyboard.press('Enter');
    await expect(page.locator('dialog.palette input')).toBeFocused();
    await page.keyboard.press('Escape');
    await expect(page.locator('dialog.palette')).toHaveCount(0);
    await expect(opener).toBeFocused();
  });

  for (const width of WIDTHS) {
    test(`P7 axe at ${width} px with the palette open`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await withFixturePages(page);
      await page.goto('/ui/overview/status');
      await shellReady(page);
      await openWithKeys(page, 'Control');
      expect(await blockingViolations(page)).toEqual([]);
    });
  }
});

test.describe('phone menu count', () => {
  test.use({ viewport: { width: 390, height: 844 } });
  test('P5 the phone menu shows the decisions count', async ({ page }) => {
    await page.route('**/ui/api/decisions/count', (r) => r.fulfill({ json: { count: 4 } }));
    await page.goto('/ui/overview/status');
    await shellReady(page);
    await page.locator('button.menu').click();
    await expect(page.locator(`nav.route-nav a[href="/ui/${TODO}"] .count`)).toHaveText('4');
  });

  test('P7 axe at 390 px with the menu open', async ({ page }) => {
    await page.goto('/ui/overview/status');
    await shellReady(page);
    await page.locator('button.menu').click();
    expect(await blockingViolations(page)).toEqual([]);
  });
});

test('P6 segmented() presses exactly one button, by click and by Space', async ({ page }) => {
  await page.goto('/ui/overview/status');
  await shellReady(page);
  const url = await shellModuleUrl(page);
  await page.evaluate(async (url) => {
    const { segmented } = await import(url);
    window.picked = [];
    document.getElementById('content').append(segmented({
      label: 'Range',
      options: [['1h', '1 h'], ['24h', '24 h'], ['7d', '7 d']],
      value: '24h',
      onChange: (v) => window.picked.push(v),
    }));
  }, url);
  const group = page.getByRole('group', { name: 'Range' });
  await expect(group.locator('button[aria-pressed="true"]')).toHaveText('24 h');
  await group.getByRole('button', { name: '1 h' }).click();
  await expect(group.locator('button[aria-pressed="true"]')).toHaveText('1 h');
  await group.getByRole('button', { name: '7 d' }).focus();
  await page.keyboard.press('Space');
  await expect(group.locator('button[aria-pressed="true"]')).toHaveText('7 d');
  await expect(group.locator('button[aria-pressed="true"]')).toHaveCount(1);
  expect(await page.evaluate(() => window.picked)).toEqual(['1h', '7d']);
});
