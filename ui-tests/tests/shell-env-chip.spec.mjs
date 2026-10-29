// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The environment chip in the top bar: an admin key sees the gateway's
// environment name on every page at every width; any other key sees nothing,
// and no error. The name comes from GET /ui/api/gateway (fixtures/api/gateway.json,
// overridden per test).
import { test, expect, blockingViolations } from './base.mjs';
import { shellReady } from './shell.mjs';

const chip = (page) => page.locator('.top .env');
const gateway = (page, environment) => page.route('**/ui/api/gateway', (r) => r.fulfill({ json: { environment } }));

/** True when neither the top bar nor the page scrolls sideways. */
const fits = (page) => page.evaluate(() => {
  const top = document.querySelector('.top');
  return top.scrollWidth <= innerWidth && top.scrollWidth <= top.clientWidth && document.documentElement.scrollWidth <= innerWidth;
});

for (const width of [390, 820, 1440]) {
  test(`E1 an admin sees the environment chip at ${width} px and the top bar fits`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    for (const path of ['/ui/overview/status', '/ui/tools/status']) {
      await page.goto(path);
      await shellReady(page);
      await expect(chip(page)).toBeVisible();
      await expect(chip(page)).toHaveText('home');
      await expect(page.getByRole('img', { name: 'Environment: home' })).toBeVisible();
      expect(await fits(page), `${path} at ${width} px`).toBe(true);
    }
    // A set name is not a fallback: no tooltip beside it.
    await expect(page.locator('.top .has-tip')).toHaveCount(0);
    expect(await blockingViolations(page)).toEqual([]);
  });
}

test('E2 a name taken from the hostname says so in its tooltip', async ({ page }) => {
  await gateway(page, { name: 'build-host-07', source: 'hostname' });
  await page.goto('/ui/overview/status');
  await shellReady(page);
  await expect(chip(page)).toHaveText('build-host-07');
  const trigger = page.locator('.top .has-tip button');
  await trigger.focus();
  await expect(page.locator('.top .has-tip .tip')).toHaveClass(/open/);
  await expect(page.locator('.top .has-tip .tip')).toContainText('Named after this machine');
  expect(await blockingViolations(page)).toEqual([]);
});

test('E3 a default name says no environment name is set', async ({ page }) => {
  await gateway(page, { name: 'gateway', source: 'default' });
  await page.goto('/ui/overview/status');
  await shellReady(page);
  await expect(chip(page)).toHaveText('gateway');
  await page.locator('.top .has-tip button').focus();
  await expect(page.locator('.top .has-tip .tip')).toHaveClass(/open/);
  await expect(page.locator('.top .has-tip .tip')).toContainText('No environment name set');
});

test('E4 a key that is not admin sees no chip and no error', async ({ page }) => {
  await page.route('**/ui/api/status', (r) => r.fulfill({ json: { auth: { enabled: true, signed_in: true, admin: false }, servers: [] } }));
  const asked = [];
  await page.route('**/ui/api/gateway', (r) => { asked.push(r.request().url()); return r.fulfill({ status: 403, body: '' }); });
  await page.goto('/ui/overview/status');
  await shellReady(page);
  await expect(page.locator('.top .who')).toHaveText('Signed in');
  await expect(chip(page)).toHaveCount(0);
  await expect(page.locator('.top .has-tip')).toHaveCount(0);
  await expect(page.locator('#content [data-state="error"], #content [data-state="forbidden"], [role="alert"]')).toHaveCount(0);
  await expect(page.locator('#announcer')).toBeEmpty();
  expect(asked, 'the admin-only route is never asked for by another key').toEqual([]);
});

test('E4b an admin whose gateway answers 403 or 404 sees no chip and no error', async ({ page }) => {
  for (const status of [403, 404]) {
    await page.route('**/ui/api/gateway', (r) => r.fulfill({ status, body: '' }));
    await page.goto('/ui/overview/status');
    await shellReady(page);
    await expect(page.locator('.top .who')).toHaveText('Signed in · admin');
    await expect(chip(page)).toHaveCount(0);
    await expect(page.locator('#content [data-state="error"], #content [data-state="forbidden"], [role="alert"]')).toHaveCount(0);
    await expect(page.locator('#announcer')).toBeEmpty();
    await page.unroute('**/ui/api/gateway');
  }
});

test('E5 a name with markup renders as literal text', async ({ page }) => {
  await gateway(page, { name: '<b>x</b>', source: 'config' });
  await page.goto('/ui/overview/status');
  await shellReady(page);
  await expect(chip(page)).toHaveText('<b>x</b>');
  await expect(chip(page).locator('b')).toHaveCount(0);
  await expect(page.getByRole('img', { name: 'Environment: <b>x</b>' })).toBeVisible();
});

test('E6 a 64-character name is clipped at 390 px and named in full', async ({ page }) => {
  const name = 'staging-eu-west-1-'.padEnd(64, 'x');
  expect(name).toHaveLength(64);
  await page.setViewportSize({ width: 390, height: 844 });
  await gateway(page, { name, source: 'config' });
  await page.goto('/ui/overview/status');
  await shellReady(page);
  await expect(chip(page)).toBeVisible();
  const box = await chip(page).evaluate((el) => {
    const s = getComputedStyle(el);
    return { clipped: el.scrollWidth > el.clientWidth, overflow: s.textOverflow, wrap: s.whiteSpace };
  });
  expect(box).toEqual({ clipped: true, overflow: 'ellipsis', wrap: 'nowrap' });
  await expect(page.getByRole('img', { name: `Environment: ${name}` })).toBeVisible();
  expect(await fits(page)).toBe(true);
});

test('E6b a clipped name keeps the full name in its native title', async ({ page }) => {
  const name = 'staging-eu-west-1-'.padEnd(64, 'x');
  await page.setViewportSize({ width: 390, height: 844 });
  await gateway(page, { name, source: 'config' });
  await page.goto('/ui/overview/status');
  await shellReady(page);
  await expect(chip(page)).toHaveAttribute('title', name);
  await expect(chip(page)).toHaveAttribute('aria-label', `Environment: ${name}`);
});
