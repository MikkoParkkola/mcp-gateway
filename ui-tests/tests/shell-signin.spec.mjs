// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Sign-in (frame 32): when it shows, the key held in memory only, the
// destination kept through sign-in, and a refused key. Rows S1-S5 of the
// shell test plan. The fixture status answers per test through page.route.
import { test, expect, WIDTHS, blockingViolations } from './base.mjs';
import { withFixturePages } from './shell.mjs';

const KEY = 'mcpg_fixture_key_0123456789';

/** Status answers signed in only for requests carrying KEY as a bearer. */
async function gate(page, { reject = false } = {}) {
  const seen = [];
  await page.route('**/ui/api/status', (route) => {
    const auth = route.request().headers().authorization ?? '';
    seen.push(auth);
    const signedIn = !reject && auth === `Bearer ${KEY}`;
    return route.fulfill({ json: { version: '4.0.0', auth: { enabled: true, signed_in: signedIn, admin: signedIn } } });
  });
  return seen;
}

test('S1 auth on and nobody signed in shows the sign-in view at the same address', async ({ page }) => {
  await gate(page);
  await page.goto('/ui/servers/status');
  await expect(page.locator('#signin')).toBeVisible();
  await expect(page).toHaveURL('/ui/servers/status');
  await expect(page.locator('nav.route-nav')).toBeHidden();
  await expect(page.locator('#signin-key')).toBeFocused();
  await expect(page.locator('#signin')).toContainText('Open the sign-in link the terminal printed');
});

test('S1 a 401 from any API shows the sign-in view too', async ({ page }) => {
  await page.route('**/ui/api/forbidden-probe', (r) => r.fulfill({ status: 401, json: {} }));
  await withFixturePages(page);
  await page.goto('/ui/access/status');
  await expect(page.locator('#signin')).toBeVisible();
  await expect(page.locator('#content [data-state="error"]')).toHaveCount(0);
});

test('S2 a key is sent as a bearer and kept in memory only; a reload asks again', async ({ page }) => {
  const seen = await gate(page);
  await page.goto('/ui/overview/status');
  await page.locator('#signin-key').fill(KEY);
  await page.keyboard.press('Enter');
  await expect(page.locator('#signin')).toBeHidden();
  await expect(page.locator('.top .who')).toHaveText('Signed in · admin');
  expect(seen).toContain(`Bearer ${KEY}`);
  const stored = await page.evaluate(() => JSON.stringify({ l: { ...localStorage }, s: { ...sessionStorage }, c: document.cookie, u: location.href }));
  expect(stored).not.toContain(KEY);
  expect(await page.locator('#signin-key').inputValue()).toBe('');
  await page.reload();
  await expect(page.locator('#signin')).toBeVisible();
  await expect(page.locator('#signin')).toContainText('a reload asks for it again');
});

test('S3 a deep link opened signed out renders that page and tab after sign-in', async ({ page }) => {
  await gate(page);
  await withFixturePages(page);
  await page.goto('/ui/servers/github/actions');
  await page.locator('#signin-key').fill(KEY);
  await page.locator('#signin button[type="submit"]').click();
  await expect(page).toHaveURL('/ui/servers/github/actions');
  await expect(page.locator('#content')).toContainText('servers github actions');
  await expect(page.locator('#signin')).toBeHidden();
  await expect(page.locator('nav.route-nav')).toBeVisible();
  await expect(page.locator('#content')).toBeFocused();
});

test('S4 a refused key keeps the sign-in view, says so, and is not kept', async ({ page }) => {
  const seen = await gate(page, { reject: true });
  await page.goto('/ui/overview/status');
  await page.locator('#signin-key').fill('mcpg_wrong');
  await page.keyboard.press('Enter');
  await expect(page.locator('.signin-error')).toHaveText('That key was not accepted.');
  await expect(page.locator('#signin')).toBeVisible();
  const before = seen.length;
  // The next API call carries no bearer: the refused key was dropped.
  await page.locator('#signin-key').fill('');
  await page.keyboard.press('Enter');
  await expect(page.locator('.signin-error')).toHaveText('Paste an API key, or use the sign-in link.');
  expect(seen.length).toBe(before);
});

for (const width of WIDTHS) {
  test(`S5 axe and the keyboard on the sign-in view at ${width} px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await gate(page);
    await page.goto('/ui/overview/status');
    await expect(page.locator('#signin')).toBeVisible();
    expect(await blockingViolations(page)).toEqual([]);
    await expect(page.locator('#signin-key')).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(page.locator('#signin button[type="submit"]')).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(page.locator('#signin a[href="/dashboard/handoff"]')).toBeFocused();
  });
}
