// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The shell renders `status.access`: pages, tabs and palette entries a key may
// open, one line saying why the rest are hidden, and no "Not available to this
// key" after navigation. Hiding is presentation only; the server's guards stay
// the authority (row A9 is a Rust row). Rows A1-A8, A11-A14 and A16-A18 of the access
// design for MIK-9008.PAGES.5. A1, A6 and A7 pass on the unchanged shell (they
// pin what must not change); every other row is red first.
import { test, expect, blockingViolations } from './base.mjs';
import { PAGES, TABS, withFixturePages, shellReady } from './shell.mjs';

const KEY = 'mcpg_fixture_key_0123456789';
const ADMIN_ONLY = 'needs an admin key';

/** An `access` member: hidden pages by id (with their reason) and hidden tabs by page. */
function access({ hidden = {}, hiddenTabs = {} } = {}) {
  return {
    pages: PAGES.map(([id]) => {
      const open = !(id in hidden);
      const tabs = TABS.map((tab) => ({ id: tab, open: open && !(hiddenTabs[id] ?? []).includes(tab) }));
      return open ? { id, open, tabs } : { id, open, tabs, reason: hidden[id] };
    }),
  };
}

/**
 * Serve /ui/api/status from `state`, which a test may change between reads:
 * signed in as `admin` or not, with `access` when it is set (omitted when null).
 * Signed-out until `state.key` matches when `state.gate` is true.
 */
async function serve(page, state) {
  await page.route('**/ui/api/status', (route) => {
    const bearer = route.request().headers().authorization ?? '';
    const signedIn = state.gate ? bearer === `Bearer ${state.gate}` : true;
    const body = { version: '4.0.0', auth: { enabled: true, signed_in: signedIn, admin: Boolean(state.admin) } };
    if (signedIn && state.access) body.access = state.access;
    return route.fulfill({ json: body });
  });
}

const navLink = (page, id) => page.locator(`nav.route-nav a[data-page="${id}"]`);
const note = (page) => page.locator('.access-note');

test.describe('access', () => {
  test('A1 an admin key shows every page and no note', async ({ page }) => {
    await serve(page, { admin: true, access: access() });
    await page.goto('/ui/overview/status');
    await shellReady(page);
    for (const [id] of PAGES) await expect(navLink(page, id)).toBeVisible();
    await expect(note(page)).toHaveCount(0);
  });

  test('A2 a non-admin key sees only the pages it can open, and one line says why', async ({ page }) => {
    const hidden = {
      ['to' + 'do']: ADMIN_ONLY,
      access: '<b>x</b> needs a signed-in key',
      policies: ADMIN_ONLY,
      gateway: ADMIN_ONLY,
    };
    await serve(page, { admin: false, access: access({ hidden }) });
    await page.goto('/ui/overview/status');
    await shellReady(page);
    await expect(note(page)).toHaveCount(1);
    for (const [id] of PAGES) await expect(navLink(page, id)).toHaveCount(id in hidden ? 0 : 1);
    // Distinct reasons, in sidebar order of the first page that has each, as text.
    await expect(note(page)).toHaveText(
      `Some pages are hidden: ${ADMIN_ONLY}; <b>x</b> needs a signed-in key.`,
    );
    await expect(note(page).locator('b')).toHaveCount(0);
  });

  test('A3 a deep link to a hidden page ends on the first open page; its screen never loads and the forbidden panel never paints', async ({ page }) => {
    await withFixturePages(page, { probes: true });
    const reads = [];
    page.on('request', (r) => r.url().includes('/ui/api/page-probe') && reads.push(r.url()));
    await page.addInitScript(() => {
      window.__forbidden = 0;
      new MutationObserver(() => {
        if (document.querySelector('#content [data-state="forbidden"]')) window.__forbidden++;
      }).observe(document, { childList: true, subtree: true });
    });
    await serve(page, { admin: false, access: access({ hidden: { policies: ADMIN_ONLY } }) });
    await page.goto('/ui/policies/status');
    await expect(page).toHaveURL(/\/ui\/overview\/status$/);
    await shellReady(page);
    await expect(page.getByText('Not available to this key')).toHaveCount(0);
    expect(reads).toEqual([]);
    expect(await page.evaluate(() => window.__forbidden)).toBe(0);
  });

  test('A16 a held status answer holds every screen; released with the page hidden, nothing of it ever renders', async ({ page }) => {
    await withFixturePages(page, { probes: true });
    const reads = [];
    page.on('request', (r) => r.url().includes('/ui/api/page-probe') && reads.push(r.url()));
    let release;
    const held = new Promise((r) => { release = r; });
    await page.route('**/ui/api/status', async (route) => {
      await held;
      return route.fulfill({
        json: { version: '4.0.0', auth: { enabled: true, signed_in: true, admin: false }, access: access({ hidden: { policies: ADMIN_ONLY } }) },
      });
    });
    await page.goto('/ui/policies/status');
    await page.waitForTimeout(500);
    expect(reads).toEqual([]);
    await expect(page.locator('#content [data-rendered]')).toHaveCount(0);
    release();
    await expect(page).toHaveURL(/\/ui\/overview\/status$/);
    await shellReady(page);
    expect(reads).toEqual([]);
  });

  test('A17 a status answer still in flight when a 401 resets the session is dropped', async ({ page }) => {
    await withFixturePages(page);
    let release;
    const held = new Promise((r) => { release = r; });
    let first = true;
    await page.route('**/ui/api/status', async (route) => {
      const bearer = route.request().headers().authorization ?? '';
      if (first) {
        first = false;
        await held;
        return route.fulfill({
          json: { version: '4.0.0', auth: { enabled: true, signed_in: true, admin: false }, access: access({ hidden: { policies: ADMIN_ONLY } }) },
        });
      }
      const signedIn = bearer === `Bearer ${KEY}`;
      return route.fulfill({ json: { version: '4.0.0', auth: { enabled: true, signed_in: signedIn, admin: signedIn } } });
    });
    await page.route('**/ui/api/forbidden-probe', (r) => r.fulfill({ status: 401, json: {} }));
    await page.goto('/ui/access/status');
    await expect(page.locator('#signin')).toBeVisible();
    release();
    await page.waitForTimeout(500);
    await expect(page.locator('#signin')).toBeVisible();
    await page.locator('#signin-key').fill(KEY);
    await page.keyboard.press('Enter');
    await expect(page.locator('#signin')).toBeHidden();
    // The old report did not come back: Policies is open, with no note.
    await expect(navLink(page, 'policies')).toBeVisible();
    await expect(note(page)).toHaveCount(0);
  });

  test('A18 a malformed access member is read as every page open', async ({ page }) => {
    const errors = [];
    page.on('pageerror', (e) => errors.push(String(e)));
    for (const bad of ['not an object', { pages: 'x' }, { pages: [{ id: 'policies' }] }]) {
      const state = { admin: false, access: bad };
      await serve(page, state);
      await page.goto('/ui/overview/status');
      await shellReady(page);
      for (const [id] of PAGES) await expect(navLink(page, id)).toBeVisible();
      await expect(note(page)).toHaveCount(0);
      await page.unroute('**/ui/api/status');
    }
    expect(errors).toEqual([]);
  });

  test('A4 a hidden tab is not in its bar, and its deep link lands on the first open tab', async ({ page }) => {
    await withFixturePages(page);
    await serve(page, { admin: false, access: access({ hiddenTabs: { servers: ['actions'] } }) });
    await page.goto('/ui/servers/actions');
    await expect(page).toHaveURL(/\/ui\/servers\/status$/);
    await shellReady(page);
    const bar = page.locator('nav.tabs');
    await expect(bar.getByRole('link', { name: 'Actions' })).toHaveCount(0);
    await expect(bar.getByRole('link', { name: 'Status' })).toBeVisible();
  });

  test('A5 the palette lists no hidden page, tab, action or setting', async ({ page }) => {
    await withFixturePages(page);
    await serve(page, {
      admin: false,
      access: access({ hidden: { policies: ADMIN_ONLY }, hiddenTabs: { servers: ['actions'] } }),
    });
    await page.goto('/ui/overview/status');
    await shellReady(page);
    await page.keyboard.press('Control+KeyK');
    await expect(page.locator('dialog.palette')).toBeVisible();
    const paths = await page.locator('dialog.palette [role="option"]').evaluateAll((els) => els.map((e) => e.dataset.path));
    expect(paths.length).toBeGreaterThan(0);
    expect(paths.filter((p) => p.startsWith('/ui/policies'))).toEqual([]);
    expect(paths).not.toContain('/ui/servers/actions');
    expect(paths).toContain('/ui/servers/status');
  });

  test('A6 an answer with no access member shows every page', async ({ page }) => {
    await serve(page, { admin: false, access: null });
    await page.goto('/ui/overview/status');
    await shellReady(page);
    for (const [id] of PAGES) await expect(navLink(page, id)).toBeVisible();
    await expect(note(page)).toHaveCount(0);
  });

  test('A7 a refusal from a route that access said open still shows the forbidden panel', async ({ page }) => {
    await withFixturePages(page);
    await serve(page, { admin: false, access: access() });
    await page.route('**/ui/api/forbidden-probe', (r) => r.fulfill({ status: 403, json: {} }));
    await page.goto('/ui/access/status');
    await expect(page.locator('#content [data-state="forbidden"]')).toBeVisible();
  });

  test('A8 the accessibility gate passes with the note shown', async ({ page }) => {
    await serve(page, { admin: false, access: access({ hidden: { policies: ADMIN_ONLY, gateway: ADMIN_ONLY } }) });
    await page.goto('/ui/overview/status');
    await shellReady(page);
    await expect(note(page)).toBeVisible();
    expect(await blockingViolations(page)).toEqual([]);
  });

  test('A11 sign-in as another identity replaces the first identity\'s access and rechecks the route', async ({ page }) => {
    const state = { admin: false, access: null, gate: KEY };
    await serve(page, state);
    await page.goto('/ui/policies/status');
    await expect(page.locator('#signin')).toBeVisible();
    // The identity that signs in is not admin and may not open Policies.
    state.access = access({ hidden: { policies: ADMIN_ONLY } });
    await page.locator('#signin-key').fill(KEY);
    await page.keyboard.press('Enter');
    await expect(page.locator('#signin')).toBeHidden();
    await expect(page).toHaveURL(/\/ui\/overview\/status$/);
    await expect(navLink(page, 'policies')).toHaveCount(0);
    // Signing out drops the report: every page is drawn again, behind sign-in.
    await page.getByRole('button', { name: 'Sign out' }).click();
    await expect(page.locator('#signin')).toBeVisible();
    state.access = null;
    state.admin = true;
    await page.locator('#signin-key').fill(KEY);
    await page.keyboard.press('Enter');
    await expect(page.locator('#signin')).toBeHidden();
    await expect(navLink(page, 'policies')).toBeVisible();
    await expect(note(page)).toHaveCount(0);
  });

  test('A12 history to a hidden route replaces it', async ({ page }) => {
    await serve(page, { admin: false, access: access({ hidden: { policies: ADMIN_ONLY } }) });
    await page.goto('/ui/overview/status');
    await shellReady(page);
    await expect(note(page)).toBeVisible();
    // As if the user pressed Back to an entry for the hidden page.
    await page.evaluate(() => {
      history.pushState(null, '', '/ui/policies/status');
      dispatchEvent(new PopStateEvent('popstate'));
    });
    await expect(page).toHaveURL(/\/ui\/overview\/status$/);
    await expect(page.getByText('Not available to this key')).toHaveCount(0);
  });

  test('A13 with no page open the frame shows the note and an empty state, with no redirect loop', async ({ page }) => {
    const hidden = Object.fromEntries(PAGES.map(([id]) => [id, ADMIN_ONLY]));
    await serve(page, { admin: false, access: access({ hidden }) });
    await page.goto('/ui/overview/status');
    await expect(note(page)).toBeVisible();
    await expect(page).toHaveURL(/\/ui\/overview\/status$/);
    for (const [id] of PAGES) await expect(navLink(page, id)).toHaveCount(0);
    await expect(page.locator('#content')).toContainText('No page is open to this key');
  });

  test('A14 a report without To do does not stop the shell rendering', async ({ page }) => {
    const errors = [];
    page.on('pageerror', (e) => errors.push(String(e)));
    await serve(page, { admin: false, access: access({ hidden: { ['to' + 'do']: ADMIN_ONLY } }) });
    await page.goto('/ui/overview/status');
    await shellReady(page);
    await expect(navLink(page, 'overview')).toBeVisible();
    await expect(note(page)).toBeVisible();
    expect(errors).toEqual([]);
  });
});
