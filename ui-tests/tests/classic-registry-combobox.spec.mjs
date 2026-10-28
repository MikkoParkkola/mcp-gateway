// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The Add Server registry search as a WAI-ARIA APG combobox with a listbox
// popup: focus stays in the box, the arrow keys move the active option,
// Enter picks it and Escape closes the list. Run against the real classic
// page with 30 registry entries that all match the query.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, expect, WIDTHS, blockingViolations } from './base.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const INDEX = readFileSync(join(HERE, '..', '..', 'src', 'gateway', 'ui', 'index.html'), 'utf8');
const ENTRIES = Array.from({ length: 30 }, (_, i) => ({
  name: `server-${String(i + 1).padStart(2, '0')}`,
  description: `Catalogue server ${i + 1}`,
  login: 'none',
}));

async function addServerForm(page) {
  const seen = { adds: [] };
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
    if (path === '/ui/api/registry') return json({ entries: ENTRIES });
    if (path === '/ui/api/backends' && req.method() === 'POST') {
      seen.adds.push(req.postDataJSON());
      return json({ name: 'x', enabled: true, notes: [] }, 201);
    }
    return json({});
  });
  await page.goto('/ui/classic#servers');
  const loaded = page.waitForResponse((r) => r.url().endsWith('/ui/api/registry'));
  await page.getByRole('button', { name: '+ Add Server' }).click();
  await loaded;
  return seen;
}

const box = (page) => page.getByRole('combobox', { name: 'Search Registry' });
const list = (page) => page.getByRole('listbox', { name: 'Registry servers' });
const add = (page) => page.locator('#add-server-form').getByRole('button', { name: 'Add Server', exact: true }).click();

/** Type the query that matches every entry, leaving the list open with no active option. */
async function search(page) {
  await box(page).fill('server');
  await expect(list(page)).toBeVisible();
}

test('C1: the search box is a combobox that controls a listbox of options', async ({ page }) => {
  await addServerForm(page);
  await expect(box(page)).toHaveAttribute('aria-expanded', 'false');
  await expect(box(page)).toHaveAttribute('aria-autocomplete', 'list');
  await search(page);
  await expect(box(page)).toHaveAttribute('aria-expanded', 'true');
  expect(await box(page).getAttribute('aria-controls')).toBe(await list(page).getAttribute('id'));
  await expect(list(page).getByRole('option')).toHaveCount(30);
  await expect(box(page)).not.toHaveAttribute('aria-activedescendant', /./);
});

test('C2: ArrowDown to the 15th option keeps it in view, and Enter picks it', async ({ page }) => {
  const seen = await addServerForm(page);
  await search(page);
  for (let i = 0; i < 15; i++) await page.keyboard.press('ArrowDown');
  const active = list(page).getByRole('option').nth(14);
  await expect(box(page)).toHaveAttribute('aria-activedescendant', await active.getAttribute('id'));
  await expect(active).toHaveAttribute('aria-selected', 'true');
  await expect(list(page).locator('[aria-selected="true"]')).toHaveCount(1);
  const inView = await active.evaluate((el) => {
    const o = el.getBoundingClientRect();
    const l = el.parentElement.getBoundingClientRect();
    return o.top >= l.top - 1 && o.bottom <= l.bottom + 1;
  });
  expect(inView).toBe(true);
  await page.keyboard.press('Enter');
  await expect(box(page)).toHaveValue('server-15');
  await expect(box(page)).toBeFocused();
  await expect(box(page)).toHaveAttribute('aria-expanded', 'false');
  await expect(page.locator('#reg-name-override')).toBeVisible();
  await add(page);
  await expect.poll(() => seen.adds.length).toBe(1);
  expect(seen.adds[0]).toEqual({ name: 'server-15', registry: 'server-15' });
});

test('C3: ArrowUp from closed opens on the last option, and ArrowDown wraps to the first', async ({ page }) => {
  await addServerForm(page);
  await box(page).fill('server');
  await page.keyboard.press('Escape');
  await expect(box(page)).toHaveAttribute('aria-expanded', 'false');
  await page.keyboard.press('ArrowUp');
  await expect(box(page)).toHaveAttribute('aria-expanded', 'true');
  const options = list(page).getByRole('option');
  await expect(box(page)).toHaveAttribute('aria-activedescendant', await options.nth(29).getAttribute('id'));
  await page.keyboard.press('ArrowDown');
  await expect(box(page)).toHaveAttribute('aria-activedescendant', await options.nth(0).getAttribute('id'));
  await page.keyboard.press('ArrowUp');
  await expect(box(page)).toHaveAttribute('aria-activedescendant', await options.nth(29).getAttribute('id'));
});

test('C4: Escape closes and keeps the text and focus; Tab away closes too', async ({ page }) => {
  await addServerForm(page);
  await search(page);
  await page.keyboard.press('ArrowDown');
  await page.keyboard.press('Escape');
  await expect(list(page)).toBeHidden();
  await expect(box(page)).toHaveAttribute('aria-expanded', 'false');
  await expect(box(page)).not.toHaveAttribute('aria-activedescendant', /./);
  await expect(box(page)).toHaveValue('server');
  await expect(box(page)).toBeFocused();
  await page.keyboard.press('ArrowDown');
  await expect(list(page)).toBeVisible();
  await page.keyboard.press('Tab');
  await expect(list(page)).toBeHidden();
  await expect(box(page)).toHaveAttribute('aria-expanded', 'false');
});

test('C5: editing the text after a pick clears the pick', async ({ page }) => {
  const seen = await addServerForm(page);
  await search(page);
  await page.keyboard.press('ArrowDown');
  await page.keyboard.press('Enter');
  await expect(page.locator('#reg-name-override')).toBeVisible();
  await page.keyboard.type('x');
  await expect(page.locator('#reg-name-override')).toBeHidden();
  await add(page);
  await expect(page.locator('#add-server-msg')).toHaveText('Select a server from the registry first.');
  expect(seen.adds).toEqual([]);
});

test('C6: a mouse click on an option still picks it', async ({ page }) => {
  const seen = await addServerForm(page);
  await search(page);
  await list(page).getByRole('option').nth(2).click();
  await expect(box(page)).toHaveValue('server-03');
  await expect(list(page)).toBeHidden();
  await add(page);
  await expect.poll(() => seen.adds.length).toBe(1);
  expect(seen.adds[0]).toEqual({ name: 'server-03', registry: 'server-03' });
});

test('C8: Enter with no active option does nothing, and Alt+ArrowDown opens with none active', async ({ page }) => {
  const seen = await addServerForm(page);
  await search(page);
  await page.keyboard.press('Enter');
  await expect(list(page)).toBeVisible();
  await expect(page.locator('#reg-name-override')).toBeHidden();
  await page.keyboard.press('Escape');
  await page.keyboard.press('Alt+ArrowDown');
  await expect(box(page)).toHaveAttribute('aria-expanded', 'true');
  await expect(box(page)).not.toHaveAttribute('aria-activedescendant', /./);
  expect(seen.adds).toEqual([]);
});

test('C9: Tab and Shift+Tab close the open list and move focus on', async ({ page }) => {
  await addServerForm(page);
  await search(page);
  await page.keyboard.press('ArrowDown');
  await page.keyboard.press('Tab');
  await expect(box(page)).toHaveAttribute('aria-expanded', 'false');
  await expect(page.locator('#add-server-form').getByRole('button', { name: 'Add Server', exact: true })).toBeFocused();
  await box(page).focus();
  await page.keyboard.press('ArrowDown');
  await expect(list(page)).toBeVisible();
  await page.keyboard.press('Shift+Tab');
  await expect(box(page)).toHaveAttribute('aria-expanded', 'false');
  await expect(page.locator('#mode-custom')).toBeFocused();
});

test('C10: keys that belong to an input method composition are left alone', async ({ page }) => {
  await addServerForm(page);
  await search(page);
  const composing = (key) => box(page).evaluate((el, k) => el.dispatchEvent(new KeyboardEvent('keydown', {
    key: k, isComposing: true, keyCode: 229, bubbles: true, cancelable: true,
  })), key);
  // dispatchEvent answers false when a handler cancelled the event.
  expect(await composing('ArrowDown')).toBe(true);
  await expect(box(page)).not.toHaveAttribute('aria-activedescendant', /./);
  await page.keyboard.press('ArrowDown');
  await expect(box(page)).toHaveAttribute('aria-activedescendant', /./);
  expect(await composing('Enter')).toBe(true);
  await expect(page.locator('#reg-name-override')).toBeHidden();
});

test('C11: after a mouse pick the box keeps focus and the list stays closed', async ({ page }) => {
  await addServerForm(page);
  await search(page);
  await list(page).getByRole('option').nth(4).click();
  await expect(box(page)).toBeFocused();
  await expect(box(page)).toHaveValue('server-05');
  await expect(list(page)).toBeHidden();
  await expect(box(page)).toHaveAttribute('aria-expanded', 'false');
});

test('C12: the caret keys clear the active option and keep the list open', async ({ page }) => {
  await addServerForm(page);
  await search(page);
  for (const key of ['ArrowLeft', 'ArrowRight', 'Home', 'End']) {
    await page.keyboard.press('ArrowDown');
    await expect(box(page), key).toHaveAttribute('aria-activedescendant', /./);
    await page.keyboard.press(key);
    await expect(box(page), key).not.toHaveAttribute('aria-activedescendant', /./);
    await expect(list(page).locator('[aria-selected="true"]'), key).toHaveCount(0);
    await expect(list(page), key).toBeVisible();
  }
});

test('C13: filtering, no match, an outside click and a reopened form each leave a consistent state', async ({ page }) => {
  await addServerForm(page);
  await search(page);
  for (let i = 0; i < 3; i++) await page.keyboard.press('ArrowDown');
  await page.keyboard.type('-1');
  await expect(list(page).getByRole('option')).toHaveCount(10);
  await expect(box(page)).not.toHaveAttribute('aria-activedescendant', /./);
  await page.keyboard.press('ArrowDown');
  const first = await list(page).getByRole('option').first().getAttribute('id');
  await expect(box(page)).toHaveAttribute('aria-activedescendant', first);
  await expect(page.locator(`#${first}`)).toHaveText(/server-10/);
  await box(page).fill('no-such-server');
  await expect(list(page)).toBeHidden();
  await expect(box(page)).toHaveAttribute('aria-expanded', 'false');
  await search(page);
  await page.locator('#page-servers h1').click();
  await expect(list(page)).toBeHidden();
  await expect(box(page)).toHaveAttribute('aria-expanded', 'false');
  await search(page);
  await page.keyboard.press('ArrowDown');
  await page.keyboard.press('Enter');
  await page.locator('#add-server-form').getByRole('button', { name: 'Cancel' }).click();
  await page.getByRole('button', { name: '+ Add Server' }).click();
  await expect(box(page)).toHaveValue('');
  await expect(box(page)).toHaveAttribute('aria-expanded', 'false');
  await expect(box(page)).not.toHaveAttribute('aria-activedescendant', /./);
  await expect(page.locator('#reg-name-override')).toBeHidden();
});

for (const width of WIDTHS) {
  test(`C7: axe finds no blocking violation with the list open and an option active at ${width} px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await addServerForm(page);
    await search(page);
    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('ArrowDown');
    expect(await blockingViolations(page)).toEqual([]);
  });
}
