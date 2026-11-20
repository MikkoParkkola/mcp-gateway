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
    // Exposed to assistive technology, not only drawn, although the markup
    // carries `hidden`: role and label queries read the accessibility tree.
    await expect(page.getByRole('heading', { name: 'mcp-gateway' })).toBeVisible();
    await expect(page.getByLabel('API key')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
    await expect(page.locator('#signin-form')).toHaveAttribute('method', 'post');
    await expect(page.locator('#signin-form')).toHaveAttribute('action', '/ui/signin');
    await expect(page.locator('#signin-key')).toHaveAttribute('name', 'key');
  });

  test('N2 with script off the fixture key signs in on the dashboard and sets one Strict HttpOnly cookie', async ({ page, request, baseURL }, testInfo) => {
    const read = await openSigninLog(page, request, testInfo);
    const origin = new URL(baseURL).origin;
    await page.goto('/ui/overview/status');
    const field = page.locator('#signin-key');
    await field.fill(KEY);
    await field.press('Enter');
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

  test('N2b on a phone-sized screen with script off, a tap on Sign in posts the key and opens the dashboard', async ({ page, request, baseURL }, testInfo) => {
    const read = await openSigninLog(page, request, testInfo);
    const origin = new URL(baseURL).origin;
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto('/ui/overview/status');
    await page.getByLabel('API key').fill(KEY);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page).toHaveURL(`${origin}/dashboard`);
    const log = await read();
    expect(log).toHaveLength(1);
    expect(log[0].method).toBe('POST');
    expect(log[0].body).toBe('key=mcpg_fixture_key_0123456789');
    expect(await productCookies(page)).toHaveLength(1);
  });

  test('N3 with script off a wrong key shows the refused line only at the fixed address, and sets no cookie', async ({ page, baseURL }) => {
    const origin = new URL(baseURL).origin;
    const line = page.getByText('That key was not accepted.', { exact: true });
    await page.goto('/ui/overview/status');
    await expect(line).toBeHidden();

    const field = page.locator('#signin-key');
    await field.fill('mcpg_wrong');
    await field.press('Enter');
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

test('N10 once the script shows the card, submitting sends no POST and no cookie, and checks the key once', async ({ page, request }, testInfo) => {
  const read = await openSigninLog(page, request, testInfo);
  const checks = [];
  await page.route('**/ui/api/status', (route) => {
    const auth = route.request().headers().authorization ?? '';
    if (route.request().method() === 'GET' && auth === `Bearer ${KEY}`) checks.push(route.request().url());
    const signedIn = auth === `Bearer ${KEY}`;
    return route.fulfill({ json: { version: '4.0.0', auth: { enabled: true, signed_in: signedIn, admin: signedIn } } });
  });
  await page.goto('/ui/overview/status');
  // The markup hides the card and nothing unhides it with script on, so a
  // visible card is the script's: the precondition this row submits under.
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

test('N13 with script on, the card stays hidden until the shell script shows it, and nothing is posted', async ({ page, request }, testInfo) => {
  const read = await openSigninLog(page, request, testInfo);
  await page.route('**/ui/api/status', (route) => route.fulfill({
    json: { version: '4.0.0', auth: { enabled: true, signed_in: false, admin: false } },
  }));
  const assets = [];
  page.on('request', (r) => {
    const path = new URL(r.url()).pathname;
    if (path.startsWith('/ui/assets/')) assets.push(path);
  });
  let release = () => {};
  const held = new Promise((resolve) => { release = resolve; });
  let sawScript = false;
  await page.route('**/ui/assets/shell.*.js', async (route) => {
    sawScript = true;
    await held;
    await route.continue();
  });
  try {
    await page.goto('/ui/overview/status', { waitUntil: 'commit' });
    await page.locator('#signin').waitFor({ state: 'attached' });
    await expect.poll(() => sawScript).toBe(true);
    // In the window: the shell script was requested and is held.
    await expect(page.locator('#signin')).toBeHidden();
    expect(assets.filter((p) => p.startsWith('/ui/assets/shell.') && p.endsWith('.js'))).toHaveLength(1);
    expect(assets.filter((p) => p.startsWith('/ui/assets/shell.nojs.'))).toEqual([]);
    expect(await read()).toEqual([]);
    release();
    // Released, signed out: the script shows the card, and still nothing was posted.
    await expect(page.locator('#signin')).toBeVisible();
    expect(await read()).toEqual([]);
  } finally {
    release();
  }
});
