// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Sign-in (frame 32): when it shows, the key held in memory only, the
// destination kept through sign-in, and a refused key. Rows S1-S5 of the
// shell test plan. The fixture status answers per test through page.route.
import { test, expect, WIDTHS, blockingViolations } from './base.mjs';
import { withFixturePages } from './shell.mjs';

const KEY = 'mcpg_fixture_key_0123456789';
const UNCONFIRMED = "Signed out here, but the gateway did not confirm the session ended, so this browser may still be signed in. Reload and sign out again, or clear this site's cookies.";

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

test('S6 with a cookie session already present, a wrong key is still refused and not kept', async ({ page, context, baseURL }) => {
  const auths = [];
  await page.route('**/ui/api/status', (route) => {
    const req = route.request();
    const auth = req.headers().authorization ?? '';
    const cookie = req.headers().cookie ?? '';
    auths.push(auth);
    // The worst case: a server that falls back to the cookie session when
    // the bearer is not valid. The shell must check a key on its own.
    const signedIn = auth === `Bearer ${KEY}` || cookie.includes('session=fixture');
    return route.fulfill({ json: { auth: { enabled: true, signed_in: signedIn, admin: signedIn } } });
  });
  await page.goto('/ui/overview/status');
  await expect(page.locator('#signin')).toBeVisible();
  // The link or the handoff completes in another tab: the cookie arrives.
  await context.addCookies([{ name: 'session', value: 'fixture', url: baseURL }]);
  await page.locator('#signin-key').fill('mcpg_wrong');
  await page.keyboard.press('Enter');
  await expect(page.locator('.signin-error')).toHaveText('That key was not accepted.');
  await expect(page.locator('#signin')).toBeVisible();
  // No later call carries the refused key.
  const count = auths.length;
  await page.evaluate(() => fetch('/ui/api/status', { credentials: 'same-origin' }));
  await page.evaluate(async () => (await import(document.querySelector('script[type="module"][src^="/ui/assets/"]').src)).api('/ui/api/status').catch(() => null));
  expect(auths.slice(count).every((a) => a === '')).toBe(true);
  // A valid key still works with the cookie present, sent on its own.
  await page.locator('#signin-key').fill(KEY);
  await page.keyboard.press('Enter');
  await expect(page.locator('#signin')).toBeHidden();
});

test('S7 a network failure while checking the key says the gateway could not be reached', async ({ page }) => {
  await page.route('**/ui/api/status', (route) => {
    if (route.request().headers().authorization) return route.abort('connectionfailed');
    return route.fulfill({ json: { auth: { enabled: true, signed_in: false, admin: false } } });
  });
  await page.goto('/ui/overview/status');
  await page.locator('#signin-key').fill(KEY);
  await page.keyboard.press('Enter');
  await expect(page.locator('.signin-error')).toHaveText('Could not reach the gateway. Try again.');
  await expect(page.locator('#signin-key')).toHaveValue(KEY);
});

test('S8 a second submit while the key is being checked sends no second check', async ({ page }) => {
  let checks = 0;
  let release;
  const held = new Promise((ok) => { release = ok; });
  await page.route('**/ui/api/status', async (route) => {
    const auth = route.request().headers().authorization ?? '';
    if (auth) {
      checks++;
      await held;
    }
    return route.fulfill({ json: { auth: { enabled: true, signed_in: auth === `Bearer ${KEY}`, admin: false } } });
  });
  await page.goto('/ui/overview/status');
  await page.locator('#signin-key').fill(KEY);
  await page.keyboard.press('Enter');
  const button = page.locator('#signin button[type="submit"]');
  await expect(button).toBeDisabled();
  await page.keyboard.press('Enter');
  await page.evaluate(() => document.getElementById('signin-form').requestSubmit());
  release();
  await expect(page.locator('#signin')).toBeHidden();
  expect(checks).toBe(1);
});

test('S9 a 401 to a request sent before sign-in does not reopen the sign-in view', async ({ page }) => {
  let release;
  const held = new Promise((ok) => { release = ok; });
  await gate(page);
  // Access › Status reads this probe; hold its anonymous answer until after sign-in.
  await page.route('**/ui/api/forbidden-probe', async (route) => {
    if (!route.request().headers().authorization) {
      await held;
      return route.fulfill({ status: 401, json: {} });
    }
    return route.fulfill({ json: {} });
  });
  await withFixturePages(page);
  await page.goto('/ui/access/status');
  await expect(page.locator('#signin')).toBeVisible();
  await page.locator('#signin-key').fill(KEY);
  await page.keyboard.press('Enter');
  await expect(page.locator('#signin')).toBeHidden();
  const stale = page.waitForResponse((r) => r.url().endsWith('/ui/api/forbidden-probe') && r.status() === 401);
  release();
  await stale;
  await page.evaluate(() => new Promise((ok) => requestAnimationFrame(() => requestAnimationFrame(ok))));
  await expect(page.locator('#signin')).toBeHidden();
});

test('S10 sign-in closes an open palette, and the palette stays shut while signed out', async ({ page }) => {
  await page.route('**/ui/api/status', (r) => r.fulfill({ json: { auth: { enabled: false, signed_in: false, admin: false } } }));
  await page.route('**/ui/api/probe-401', (r) => r.fulfill({ status: 401, json: {} }));
  // Auth off at first, so the shell renders and the palette can open.
  await page.goto('/ui/overview/status');
  await page.locator('#content [data-rendered]').waitFor();
  await page.keyboard.press('Control+KeyK');
  await expect(page.locator('dialog.palette')).toBeVisible();
  // Something answers 401 now: sign-in takes over and the palette goes.
  await page.evaluate(async () => (await import(document.querySelector('script[type="module"][src^="/ui/assets/"]').src)).api('/ui/api/probe-401').catch(() => null));
  await expect(page.locator('#signin')).toBeVisible();
  await expect(page.locator('dialog.palette')).toHaveCount(0);
  await page.keyboard.press('Control+KeyK');
  await expect(page.locator('dialog.palette')).toHaveCount(0);
  await expect(page.locator('#signin-key')).toBeFocused();
});

test.describe('sign-in on a touch screen', () => {
  test.use({ isMobile: true, hasTouch: true, viewport: { width: 390, height: 844 } });
  test('S11 the sign-in button is at least 44 px tall', async ({ page }) => {
    await gate(page);
    await page.goto('/ui/overview/status');
    const h = await page.locator('#signin button[type="submit"]').evaluate((b) => b.getBoundingClientRect().height);
    expect(h).toBeGreaterThanOrEqual(44);
  });
});

test('S12 a key check that never answers gives up and frees the button', async ({ page }) => {
  await page.clock.install();
  await page.route('**/ui/api/status', async (route) => {
    if (route.request().headers().authorization) return; // never answered
    return route.fulfill({ json: { auth: { enabled: true, signed_in: false, admin: false } } });
  });
  await page.goto('/ui/overview/status');
  await page.locator('#signin-key').fill(KEY);
  await page.keyboard.press('Enter');
  const button = page.locator('#signin button[type="submit"]');
  await expect(button).toBeDisabled();
  await page.clock.runFor(10_500);
  await expect(page.locator('.signin-error')).toHaveText('Could not reach the gateway. Try again.');
  await expect(button).toBeEnabled();
});

test('S13 the key check says Checking… and marks the form busy while it runs', async ({ page }) => {
  let release;
  const held = new Promise((ok) => { release = ok; });
  await page.route('**/ui/api/status', async (route) => {
    const auth = route.request().headers().authorization ?? '';
    if (auth) await held;
    return route.fulfill({ json: { auth: { enabled: true, signed_in: auth === `Bearer ${KEY}`, admin: false } } });
  });
  await page.goto('/ui/overview/status');
  await page.locator('#signin-key').fill(KEY);
  await page.keyboard.press('Enter');
  const button = page.locator('#signin button[type="submit"]');
  await expect(button).toHaveText('Checking…');
  await expect(page.locator('#signin-form')).toHaveAttribute('aria-busy', 'true');
  release();
  await expect(page.locator('#signin')).toBeHidden();
  await expect(button).toHaveText('Sign in');
  await expect(page.locator('#signin-form')).not.toHaveAttribute('aria-busy', 'true');
});

test('S14 a valid key the gateway does not let in (403) gets its own message', async ({ page }) => {
  await page.route('**/ui/api/status', (route) => {
    if (route.request().headers().authorization) return route.fulfill({ status: 403, json: {} });
    return route.fulfill({ json: { auth: { enabled: true, signed_in: false, admin: false } } });
  });
  await page.goto('/ui/overview/status');
  await page.locator('#signin-key').fill(KEY);
  await page.keyboard.press('Enter');
  await expect(page.locator('.signin-error')).toHaveText('That key is valid, but it is not allowed into the web UI. Ask an admin for access.');
  await expect(page.locator('#signin')).toBeVisible();
});

test('S15 sign-out drops the key, ends the cookie session and shows sign-in at the same address', async ({ page }) => {
  const seen = await gate(page);
  const logouts = [];
  await page.route('**/dashboard/logout', (route) => {
    logouts.push(route.request().method());
    return route.fulfill({ status: 303, headers: { location: '/ui' } });
  });
  await withFixturePages(page);
  await page.goto('/ui/servers/status');
  await page.locator('#signin-key').fill(KEY);
  await page.keyboard.press('Enter');
  await expect(page.locator('#signin')).toBeHidden();
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.locator('#signin')).toBeVisible();
  await expect(page).toHaveURL('/ui/servers/status');
  expect(logouts).toEqual(['POST']);
  await expect(page.locator('.signin-error')).toBeHidden();
  await expect(page.locator('.signin-notice')).toBeHidden();
  await expect(page.locator('.top .who')).toHaveText('');
  await expect(page.locator('#signin-key')).toBeFocused();
  // The key is gone without a reload: the next read from this page carries no bearer.
  const before = seen.length;
  await page.evaluate(async () => (await import(document.querySelector('script[type="module"][src^="/ui/assets/"]').src)).api('/ui/api/status').catch(() => null));
  expect(seen.length).toBeGreaterThan(before);
  expect(seen.slice(before)).not.toContain(`Bearer ${KEY}`);
});

test('S18 a sign-out the gateway does not confirm says the session may still be open', async ({ page }) => {
  await gate(page);
  await page.route('**/dashboard/logout', (route) => route.fulfill({ status: 500, json: {} }));
  await page.goto('/ui/overview/status');
  await page.locator('#signin-key').fill(KEY);
  await page.keyboard.press('Enter');
  await expect(page.locator('#signin')).toBeHidden();
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.locator('#signin')).toBeVisible();
  await expect(page.locator('.signin-notice')).toBeVisible();
  await expect(page.locator('.signin-notice')).toHaveText(UNCONFIRMED);
});

test('S18 an unreachable gateway at sign-out says the same', async ({ page }) => {
  await gate(page);
  await page.route('**/dashboard/logout', (route) => route.abort('failed'));
  await page.goto('/ui/overview/status');
  await page.locator('#signin-key').fill(KEY);
  await page.keyboard.press('Enter');
  await expect(page.locator('#signin')).toBeHidden();
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.locator('.signin-notice')).toBeVisible();
  await expect(page.locator('.signin-notice')).toHaveText(UNCONFIRMED);
});

test('S16 sign-out is offered only to a signed-in session', async ({ page }) => {
  await gate(page);
  await page.goto('/ui/overview/status');
  await expect(page.locator('#signin')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Sign out' })).toBeHidden();
  await page.locator('#signin-key').fill(KEY);
  await page.keyboard.press('Enter');
  await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
});

/** Sign in with KEY at the current viewport. */
async function signedIn(page) {
  await gate(page);
  await page.route('**/dashboard/logout', (route) => route.fulfill({ status: 303, headers: { location: '/ui' } }));
  await page.goto('/ui/overview/status');
  await page.locator('#signin-key').fill(KEY);
  await page.keyboard.press('Enter');
  await expect(page.locator('#signin')).toBeHidden();
}

test.describe('sign-out on a phone', () => {
  test.use({ viewport: { width: 390, height: 844 } });
  test('S17 at 390 px sign-out is the menu\'s last row, not in the top bar', async ({ page }) => {
    await signedIn(page);
    await expect(page.locator('.top .signout')).toBeHidden();
    await page.locator('button.menu').click();
    const inMenu = page.locator('#pages').getByRole('button', { name: 'Sign out' });
    await expect(inMenu).toBeVisible();
    await inMenu.click();
    await expect(page.locator('#signin')).toBeVisible();
    await expect(page.locator('#signin-key')).toBeFocused();
  });
});

for (const [width, inTopBar] of [[640, false], [641, true]]) {
  test.describe(`sign-out at ${width} px`, () => {
    test.use({ viewport: { width, height: 900 } });
    test(`S17 at ${width} px sign-out is ${inTopBar ? 'in the top bar' : 'in the menu'}`, async ({ page }) => {
      await signedIn(page);
      if (inTopBar) {
        await expect(page.locator('.top .signout')).toBeVisible();
        await expect(page.locator('#pages .signout')).toBeHidden();
      } else {
        await expect(page.locator('.top .signout')).toBeHidden();
        await page.locator('button.menu').click();
        await expect(page.locator('#pages .signout')).toBeVisible();
      }
    });
  });
}

test.describe('sign-out on a desktop', () => {
  test.use({ viewport: { width: 1440, height: 900 } });
  test('S17 at 1440 px sign-out is in the top bar, not in the sidebar', async ({ page }) => {
    await signedIn(page);
    await expect(page.locator('.top').getByRole('button', { name: 'Sign out' })).toBeVisible();
    await expect(page.locator('#pages').getByRole('button', { name: 'Sign out' })).toBeHidden();
  });
});

test('S16 with authentication off there is no session, so no sign-out', async ({ page }) => {
  await page.route('**/ui/api/status', (r) => r.fulfill({ json: { auth: { enabled: false, signed_in: false, admin: false } } }));
  await page.goto('/ui/overview/status');
  await page.locator('#content [data-rendered]').waitFor();
  await expect(page.locator('.top .signout')).toBeHidden();
  await expect(page.locator('#pages .signout')).toBeHidden();
});

test('S18 a logout that never answers shows the pending notice, then the warning', async ({ page }) => {
  await page.clock.install();
  await gate(page);
  await page.route('**/dashboard/logout', () => {}); // never answered
  await page.goto('/ui/overview/status');
  await page.locator('#signin-key').fill(KEY);
  await page.keyboard.press('Enter');
  await expect(page.locator('#signin')).toBeHidden();
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.locator('.signin-notice')).toBeVisible();
  await expect(page.locator('.signin-notice')).toHaveText('Ending the session on the gateway…');
  await page.clock.runFor(10_500);
  await expect(page.locator('.signin-notice')).toHaveText(UNCONFIRMED);
});

test('S18 a late logout failure never writes over a session signed in since', async ({ page }) => {
  let release;
  const held = new Promise((ok) => { release = ok; });
  await gate(page);
  await page.route('**/dashboard/logout', async (route) => { await held; return route.fulfill({ status: 500, json: {} }); });
  await page.route('**/ui/api/probe-401', (r) => r.fulfill({ status: 401, json: {} }));
  await page.goto('/ui/overview/status');
  await page.locator('#signin-key').fill(KEY);
  await page.keyboard.press('Enter');
  await expect(page.locator('#signin')).toBeHidden();
  await page.getByRole('button', { name: 'Sign out' }).click();
  await page.locator('#signin-key').fill(KEY);
  await page.keyboard.press('Enter');
  await expect(page.locator('#signin')).toBeHidden();
  const failed = page.waitForResponse((r) => r.url().endsWith('/dashboard/logout'));
  release();
  await failed;
  await page.evaluate(() => new Promise((ok) => requestAnimationFrame(() => requestAnimationFrame(ok))));
  // A later 401 shows sign-in again: the old sign-out's warning must not be on it.
  await page.evaluate(async () => (await import(document.querySelector('script[type="module"][src^="/ui/assets/"]').src)).api('/ui/api/probe-401').catch(() => null));
  await expect(page.locator('#signin')).toBeVisible();
  await expect(page.locator('.signin-notice')).toBeHidden();
});

test('S18 a key refused while the logout is pending keeps both messages', async ({ page }) => {
  let release;
  const held = new Promise((ok) => { release = ok; });
  await gate(page);
  await page.route('**/dashboard/logout', async (route) => { await held; return route.fulfill({ status: 500, json: {} }); });
  await page.goto('/ui/overview/status');
  await page.locator('#signin-key').fill(KEY);
  await page.keyboard.press('Enter');
  await expect(page.locator('#signin')).toBeHidden();
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.locator('.signin-notice')).toHaveText('Ending the session on the gateway…');
  await page.locator('#signin-key').fill('mcpg_wrong');
  await page.keyboard.press('Enter');
  await expect(page.locator('.signin-error')).toHaveText('That key was not accepted.');
  await expect(page.locator('.signin-notice')).toBeVisible();
  const failed = page.waitForResponse((r) => r.url().endsWith('/dashboard/logout'));
  release();
  await failed;
  await expect(page.locator('.signin-notice')).toHaveText(UNCONFIRMED);
  await expect(page.locator('.signin-error')).toHaveText('That key was not accepted.');
});

test('S20 a rate-limited key check says how long to wait and keeps the key', async ({ page }) => {
  await page.route('**/ui/api/status', (route) => {
    if (route.request().headers().authorization) {
      return route.fulfill({ status: 429, headers: { 'retry-after': '60' }, json: { error: { code: -32000, message: 'rate limited' } } });
    }
    return route.fulfill({ json: { auth: { enabled: true, signed_in: false, admin: false } } });
  });
  await page.goto('/ui/overview/status');
  await page.locator('#signin-key').fill(KEY);
  await page.keyboard.press('Enter');
  await expect(page.locator('.signin-error')).toBeVisible();
  await expect(page.locator('.signin-error')).toHaveText('The gateway is limiting sign-in attempts. Wait 60 seconds, then try again.');
  await expect(page.locator('#signin-key')).toHaveValue(KEY);
});

test('S20 a rate limit without a usable wait says a minute', async ({ page }) => {
  await page.route('**/ui/api/status', (route) => {
    if (route.request().headers().authorization) return route.fulfill({ status: 429, headers: { 'retry-after': 'soon' }, json: {} });
    return route.fulfill({ json: { auth: { enabled: true, signed_in: false, admin: false } } });
  });
  await page.goto('/ui/overview/status');
  await page.locator('#signin-key').fill(KEY);
  await page.keyboard.press('Enter');
  await expect(page.locator('.signin-error')).toHaveText('The gateway is limiting sign-in attempts. Wait a minute, then try again.');
});

for (const [header, wait] of [['1', '1 second'], [null, 'a minute'], ['Wed, 21 Oct 2026 07:28:00 GMT', 'a minute']]) {
  test(`S20 Retry-After ${header ?? 'absent'} reads as ${wait}`, async ({ page }) => {
    await page.route('**/ui/api/status', (route) => {
      if (!route.request().headers().authorization) return route.fulfill({ json: { auth: { enabled: true, signed_in: false, admin: false } } });
      return route.fulfill({ status: 429, headers: header === null ? {} : { 'retry-after': header }, json: {} });
    });
    await page.goto('/ui/overview/status');
    await page.locator('#signin-key').fill(KEY);
    await page.keyboard.press('Enter');
    await expect(page.locator('.signin-error')).toHaveText(`The gateway is limiting sign-in attempts. Wait ${wait}, then try again.`);
  });
}

test('S20 the kept key signs in on the next try once the limit lifts', async ({ page }) => {
  let limited = true;
  await page.route('**/ui/api/status', (route) => {
    const auth = route.request().headers().authorization ?? '';
    if (auth && limited) return route.fulfill({ status: 429, headers: { 'retry-after': '60' }, json: {} });
    return route.fulfill({ json: { auth: { enabled: true, signed_in: auth === `Bearer ${KEY}`, admin: false } } });
  });
  await page.goto('/ui/overview/status');
  await page.locator('#signin-key').fill(KEY);
  await page.keyboard.press('Enter');
  await expect(page.locator('.signin-error')).toBeVisible();
  limited = false;
  await page.keyboard.press('Enter');
  await expect(page.locator('#signin')).toBeHidden();
});

const LINK_REFUSED = 'That sign-in link or code did not work. It may be wrong, already used or expired. Run `mcp-gateway dashboard-link` on the gateway’s machine for a new one.';

test('S19 a refused sign-in link lands on sign-in with the reason, and the hint leaves the address', async ({ page }) => {
  await gate(page);
  await page.goto('/ui/overview/status?signin=link-refused');
  await expect(page.locator('#signin')).toBeVisible();
  await expect(page.locator('.signin-error')).toBeVisible();
  await expect(page.locator('.signin-error')).toHaveText(LINK_REFUSED);
  await expect(page).toHaveURL('/ui/overview/status');
});

test('S19 any other hint value changes nothing', async ({ page }) => {
  await gate(page);
  await page.goto('/ui/overview/status?signin=<b>x</b>');
  await expect(page.locator('#signin')).toBeVisible();
  await expect(page.locator('.signin-error')).toBeHidden();
});

test('S19 a session already signed in drops the hint and shows nothing', async ({ page }) => {
  await page.route('**/ui/api/status', (r) => r.fulfill({ json: { auth: { enabled: true, signed_in: true, admin: true } } }));
  await page.goto('/ui/overview/status?signin=link-refused');
  await page.locator('#content [data-rendered]').waitFor();
  await expect(page).toHaveURL('/ui/overview/status');
  await expect(page.locator('#signin')).toBeHidden();
});

test('S19 a slow startup check never writes over a key check that has started', async ({ page }) => {
  let release;
  const held = new Promise((ok) => { release = ok; });
  await page.route('**/ui/api/status', async (route) => {
    if (route.request().headers().authorization) {
      return route.fulfill({ status: 429, headers: { 'retry-after': '60' }, json: {} });
    }
    await held; // the startup check answers late
    return route.fulfill({ json: { auth: { enabled: true, signed_in: false, admin: false } } });
  });
  await page.route('**/ui/api/probe-401', (r) => r.fulfill({ status: 401, json: {} }));
  await page.goto('/ui/overview/status?signin=link-refused');
  // Sign-in shows before the startup check answers (a 401 elsewhere opens it).
  await page.evaluate(async () => (await import(document.querySelector('script[type="module"][src^="/ui/assets/"]').src)).api('/ui/api/probe-401').catch(() => null));
  await expect(page.locator('#signin')).toBeVisible();
  await page.locator('#signin-key').fill(KEY);
  await page.keyboard.press('Enter');
  await expect(page.locator('.signin-error')).toHaveText('The gateway is limiting sign-in attempts. Wait 60 seconds, then try again.');
  const late = page.waitForResponse((r) => r.url().endsWith('/ui/api/status') && !r.request().headers().authorization);
  release();
  await late;
  await page.evaluate(() => new Promise((ok) => requestAnimationFrame(() => requestAnimationFrame(ok))));
  await expect(page.locator('.signin-error')).toHaveText('The gateway is limiting sign-in attempts. Wait 60 seconds, then try again.');
});
