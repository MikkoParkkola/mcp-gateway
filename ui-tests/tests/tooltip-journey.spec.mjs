// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The tooltip journeys on what the built UI draws today: Tools › Status's load
// note, and the environment chip's note in the top bar. Each opens the way a
// user does (hover after 300 ms, keyboard focus, Enter, a tap on touch), shows
// the copy the asset holds for its id, and closes on Esc or a tap outside. The
// expected words come from the copy asset, not from the module under test.
import { test, expect } from './base.mjs';
import { readCopy } from './copy-check.mjs';
import { shellReady } from './shell.mjs';

const COPY = readCopy();
const LOAD = 'tools.status.load-11-tools-and-reach';
const FROM_HOST = 'gateway.status.environment-from-hostname';
const NOT_SET = 'gateway.status.environment-not-set';

const holder = (page, id) => page.locator(`.has-tip[data-tip="${id}"]`);
const tipOf = (page, id) => holder(page, id).locator('.tip');
const triggerOf = (page, id) => holder(page, id).locator('button');
const pauseClock = async (page) => page.clock.pauseAt(await page.evaluate(() => Date.now() + 5000));
const gateway = (page, environment) => page.route('**/ui/api/gateway', (r) => r.fulfill({ json: { environment } }));
/** Tools › Status as a signed-in admin with one tool, so the screen draws its load note. */
async function toolsScreen(page) {
  await page.route('**/ui/api/status', (r) => r.fulfill({ json: { auth: { enabled: true, signed_in: true, admin: true } } }));
  const tools = [{ name: 'search', server: 'alpha', description: 'Searches', schema: { type: 'object' }, class: 'read', class_source: 'declared' }];
  await page.route('**/ui/api/tools**', (r) => r.fulfill({ json: { tools, total: tools.length } }));
}

test('J1 Tools › Status: the load note opens on hover after 300 ms, shows its copy, and Esc closes it', async ({ page }) => {
  await page.clock.install();
  await toolsScreen(page);
  await page.goto('/ui/tools/status');
  await shellReady(page);
  await expect(triggerOf(page, LOAD), 'Tools › Status draws its load note').toBeVisible();
  await pauseClock(page);
  const tip = tipOf(page, LOAD);
  await triggerOf(page, LOAD).hover();
  await page.clock.runFor(200);
  await expect(tip).not.toHaveClass(/open/);
  await page.clock.runFor(150);
  await expect(tip).toHaveClass(/open/);
  await expect(tip).toContainText(COPY[LOAD].title);
  await expect(tip).toContainText(COPY[LOAD].text);
  await page.keyboard.press('Escape');
  await expect(tip).not.toHaveClass(/open/);
});

test('J1b Tools › Status: by keyboard the load note opens at once, Enter keeps it open, Esc closes it and keeps focus', async ({ page }) => {
  await toolsScreen(page);
  await page.goto('/ui/tools/status');
  await shellReady(page);
  await expect(triggerOf(page, LOAD), 'Tools › Status draws its load note').toBeVisible();
  const tip = tipOf(page, LOAD);
  const trigger = triggerOf(page, LOAD);
  await trigger.focus();
  await expect(tip).toHaveClass(/open/);
  await page.keyboard.press('Enter');
  await expect(tip).toHaveClass(/open/);
  await page.keyboard.press('Escape');
  await expect(tip).not.toHaveClass(/open/);
  await expect(trigger).toBeFocused();
});

test('J2 the environment chip with no name set: keyboard opens the not-set note, Esc closes it', async ({ page }) => {
  await gateway(page, { name: 'gateway', source: 'default' });
  await page.goto('/ui/gateway/status');
  await shellReady(page);
  await expect(holder(page, FROM_HOST)).toHaveCount(0);
  const tip = tipOf(page, NOT_SET);
  await triggerOf(page, NOT_SET).focus();
  await expect(tip).toHaveClass(/open/);
  await expect(tip).toContainText(COPY[NOT_SET].text);
  await page.keyboard.press('Escape');
  await expect(tip).not.toHaveClass(/open/);
});

test.describe('touch', () => {
  test.use({ hasTouch: true, isMobile: true, viewport: { width: 390, height: 844 } });

  test('J1c Tools › Status: a tap opens the load note and a tap outside closes it', async ({ page }) => {
    await toolsScreen(page);
    await page.goto('/ui/tools/status');
    await shellReady(page);
    await expect(triggerOf(page, LOAD), 'Tools › Status draws its load note').toBeVisible();
    const tip = tipOf(page, LOAD);
    await triggerOf(page, LOAD).tap();
    await expect(tip).toHaveClass(/open/);
    await expect(tip).toContainText(COPY[LOAD].text);
    await page.locator('h1').tap();
    await expect(tip).not.toHaveClass(/open/);
  });

  test('J2b the environment chip named from the hostname: a tap opens that note and a tap outside closes it', async ({ page }) => {
    await gateway(page, { name: 'build-host-07', source: 'hostname' });
    await page.goto('/ui/gateway/status');
    await shellReady(page);
    await expect(holder(page, NOT_SET)).toHaveCount(0);
    const tip = tipOf(page, FROM_HOST);
    await triggerOf(page, FROM_HOST).tap();
    await expect(tip).toHaveClass(/open/);
    await expect(tip).toContainText(COPY[FROM_HOST].text);
    await page.locator('h1').tap();
    await expect(tip).not.toHaveClass(/open/);
  });
});
