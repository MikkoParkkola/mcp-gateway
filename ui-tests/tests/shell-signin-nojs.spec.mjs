// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The sign-in form works without JavaScript: the card, the posted
// key, a refused key, and the scripted path that stays in the tab. Rows N.
// shell-signin.spec.mjs owns S1-S18.
import { test, expect } from './base.mjs';

const KEY = 'mcpg_fixture_key_0123456789';

/**
 * The sign-in log for this test. The fixture-signin cookie only names the
 * channel on the fixture server; it is test plumbing, not a session.
 */
async function openSigninLog(page, request, testInfo) {
  const name = testInfo.testId.replace(/[^\w-]/g, '-');
  expect((await request.post(`/__signin/${name}/reset`)).status()).toBe(204);
  const url = `http://127.0.0.1:${process.env.UI_TESTS_PORT ?? 4173}`;
  await page.context().addCookies([{ name: 'fixture-signin', value: name, url }]);
  return async () => {
    const reply = await request.get(`/__signin/${name}/log`);
    expect(reply.status()).toBe(200);
    return reply.json();
  };
}

/** Cookies the response set. Drops the channel cookie before the count. */
async function productCookies(page) {
  await page.context().clearCookies({ name: 'fixture-signin' });
  return page.context().cookies();
}

/**
 * The script's ready class: the shell script adds `ready` to the document
 * element once it has loaded; the CSS keys the no-JavaScript card on its absence.
 */
function ready(page) {
  return page.evaluate(() => document.documentElement.classList.contains('ready'));
}

test.describe('script off', () => {
  test.use({ javaScriptEnabled: false });

  test('N1 with script off the sign-in card is visible and the form posts to /ui/signin; signed in, it stays hidden', async ({ page, browser, baseURL }) => {
    const on = await browser.newContext({ baseURL, javaScriptEnabled: true });
    try {
      const signedIn = await on.newPage();
      const status = signedIn.waitForResponse((r) => new URL(r.url()).pathname === '/ui/api/status');
      await signedIn.goto('/ui/overview/status');
      expect((await status).status()).toBe(200);
      await expect(signedIn.locator('#signin')).toBeHidden();
    } finally {
      await on.close();
    }

    await page.goto('/ui/overview/status');
    await expect(page.locator('#signin')).toBeVisible();
    await expect(page.locator('#signin-form')).toHaveAttribute('method', 'post');
    await expect(page.locator('#signin-form')).toHaveAttribute('action', '/ui/signin');
    await expect(page.locator('#signin-key')).toHaveAttribute('name', 'key');
  });

  test('N2 with script off the fixture key signs in on the dashboard and sets one Strict HttpOnly cookie', async ({ page, request, baseURL }, testInfo) => {
    const read = await openSigninLog(page, request, testInfo);
    const origin = new URL(baseURL).origin;
    await page.goto('/ui/overview/status');
    const field = page.locator('#signin-key');
    await field.fill(KEY, { force: true });
    await field.press('Enter', { force: true });
    await expect(page).toHaveURL(`${origin}/dashboard`);
    await expect(page.getByText('Signed in', { exact: true })).toBeVisible();
    const log = await read();
    expect(log).toHaveLength(1);
    expect(log[0].method).toBe('POST');
    expect(log[0].origin).toBe(origin);
    expect(log[0].body).toBe('key=mcpg_fixture_key_0123456789');
    const cookies = await productCookies(page);
    expect(cookies).toHaveLength(1);
    expect(cookies[0].name).toBe('mcp_gateway_session');
    expect(cookies[0].httpOnly).toBe(true);
    expect(cookies[0].sameSite).toBe('Strict');
    expect(cookies[0].secure).toBe(false);
  });

  test('N3 with script off a wrong key shows the refused line only at the fixed address, and sets no cookie', async ({ page, baseURL }) => {
    const origin = new URL(baseURL).origin;
    const line = page.getByText('That key was not accepted.', { exact: true });
    await page.goto('/ui/overview/status');
    await expect(line).toBeHidden();

    const field = page.locator('#signin-key');
    await field.fill('mcpg_wrong', { force: true });
    await field.press('Enter', { force: true });
    await expect(page).toHaveURL(`${origin}/ui/overview/status#signin-refused`);
    await expect(line).toBeVisible();
    expect(await page.context().cookies()).toEqual([]);
  });

  test('N12 script off shows the no-JavaScript note and not the tab-only note; script on, the reverse', async ({ page, browser, baseURL }) => {
    const on = await browser.newContext({ baseURL, javaScriptEnabled: true });
    try {
      const signedOut = await on.newPage();
      await signedOut.route('**/ui/api/status', (route) => route.fulfill({
        json: { version: '4.0.0', auth: { enabled: true, signed_in: false, admin: false } },
      }));
      await signedOut.goto('/ui/overview/status');
      await expect(signedOut.getByText('A key stays in this tab only; a reload asks for it again.', { exact: true })).toBeVisible();
      await expect(signedOut.getByText('Without JavaScript, signing in sets a session cookie in this browser and opens the dashboard page.', { exact: true })).toBeHidden();
    } finally {
      await on.close();
    }

    await page.goto('/ui/overview/status');
    await expect(page.getByText('Without JavaScript, signing in sets a session cookie in this browser and opens the dashboard page.', { exact: true })).toBeVisible();
    await expect(page.getByText('A key stays in this tab only; a reload asks for it again.', { exact: true })).toBeHidden();
  });
});

test('N10 once the shell is ready, submitting sends no POST and no cookie, and checks the key once', async ({ page, request }, testInfo) => {
  const read = await openSigninLog(page, request, testInfo);
  const checks = [];
  await page.route('**/ui/api/status', (route) => {
    const auth = route.request().headers().authorization ?? '';
    if (route.request().method() === 'GET' && auth === `Bearer ${KEY}`) checks.push(route.request().url());
    const signedIn = auth === `Bearer ${KEY}`;
    return route.fulfill({ json: { version: '4.0.0', auth: { enabled: true, signed_in: signedIn, admin: signedIn } } });
  });
  await page.goto('/ui/overview/status');
  await expect.poll(() => ready(page)).toBe(true);
  await expect(page.locator('#signin')).toBeVisible();
  await page.locator('#signin-key').fill(KEY);
  await page.locator('#signin-key').press('Enter');
  expect(await read()).toEqual([]);
  expect(await productCookies(page)).toEqual([]);
  expect(checks, 'GET /ui/api/status with the bearer').toHaveLength(1);
});

test('N11b a same-origin read carries the shell URL as Referer, and an outbound link carries none', async ({ page, baseURL }) => {
  const shellUrl = `${new URL(baseURL).origin}/ui/overview/status`;
  await page.route('https://stub.example/**', (route) => route.fulfill({
    status: 200,
    contentType: 'text/html',
    body: '<!doctype html><title>stub</title><p>stub</p>',
  }));
  const status = page.waitForRequest((r) => r.method() === 'GET' && new URL(r.url()).pathname === '/ui/api/status');
  await page.goto('/ui/overview/status');
  expect((await status).headers().referer).toBe(shellUrl);

  await page.evaluate(() => {
    const a = document.createElement('a');
    a.href = 'https://stub.example/out';
    a.textContent = 'Out';
    document.body.append(a);
  });
  const outbound = page.waitForRequest('https://stub.example/out');
  await page.getByRole('link', { name: 'Out' }).click();
  expect(Object.hasOwn((await outbound).headers(), 'referer')).toBe(false);
});

test('N13 before the shell script loads, the no-JavaScript note shows and a submit opens the dashboard; releasing it posts nothing more', async ({ page, request, baseURL }, testInfo) => {
  const read = await openSigninLog(page, request, testInfo);
  const origin = new URL(baseURL).origin;
  let release = () => {};
  const held = new Promise((resolve) => { release = resolve; });
  let sawScript = false;
  await page.route('**/ui/assets/shell.*.js', async (route) => {
    sawScript = true;
    await held;
    try { await route.continue(); } catch { /* the document navigated while the script was held */ }
  });
  try {
    await page.goto('/ui/overview/status', { waitUntil: 'commit' });
    await page.locator('#signin').waitFor({ state: 'attached' });
    await expect.poll(() => sawScript).toBe(true);
    expect(await ready(page)).toBe(false);
    await expect(page.getByText('Without JavaScript, signing in sets a session cookie in this browser and opens the dashboard page.', { exact: true })).toBeVisible();
    await page.locator('#signin-key').fill(KEY);
    await page.locator('#signin-key').press('Enter');
    await expect(page).toHaveURL(`${origin}/dashboard`);
    expect(await read()).toHaveLength(1);
    release();
    expect((await read()).filter((entry) => entry.method === 'POST')).toHaveLength(1);
  } finally {
    release();
  }
});
