// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// A server's own page, its Status tab, the list's links to it,
// and how the page follows the live status (T1, T2 of the frozen test plan).
import { test, expect, blockingViolations, WIDTHS } from './base.mjs';
import { countListeners, shellReady } from './shell.mjs';
import { entry, fullView, fakeServerGateway, statusEvent, shellCall, gate } from './server-page.mjs';

test.use({ timezoneId: 'UTC' });

const content = (page) => page.locator('#content');
const word = (page, state) => shellCall(page, (m, s) => m.stateWord(s), state);
const banner = (page, server) => shellCall(page, (m, s) => m.serverBanner(s)?.querySelector('h2')?.textContent ?? null, server);
const goTo = (page, path) => shellCall(page, (m, p) => m.go(p), path);
// One macrotask after an answer lands, so a late callback has had its turn before a row looks.
const settle = (page) => page.evaluate(() => new Promise((ok) => setTimeout(ok, 50)));
async function open(page, path) {
  await page.goto(path);
  await shellReady(page);
}

test.describe('T1 a server has its own page', () => {
  test('T1a the Status tab draws its badge, banner, facts and Activity link', async ({ page }) => {
    const paused = entry('my server', 'paused', { calls_24h: null, tools_cached: 9, transport: 'streamable-http', running: false });
    const seen = await fakeServerGateway(page, { status: fullView(paused, entry('other', 'running')) });
    await open(page, '/ui/servers/my%20server/status');
    const c = content(page);
    await expect(page.getByRole('heading', { level: 1, name: 'my server', exact: true })).toBeVisible();
    await expect(c.locator('.lb').first()).toContainText(await word(page, 'paused'));
    await expect(c.locator('[data-state="server"] h2')).toHaveText(await banner(page, paused));
    const facts = c.locator('dl.sp-facts');
    await expect(facts.locator('dt')).toHaveText(['Transport', 'Running', 'Tools', 'Calls, last 24 h']);
    await expect(facts.locator('dd')).toHaveText(['streamable-http', 'No', '9', 'not known']);
    await expect(c.getByText('This server accepted credentials in cleartext.')).toHaveCount(0);
    await expect(c.getByRole('link', { name: 'Its calls in Activity' })).toHaveAttribute('href', '/ui/activity?server=my%20server');
    expect(seen.status).toBe(1);
  });

  test('T1a the cleartext line shows only when cleartext credentials were accepted', async ({ page }) => {
    await fakeServerGateway(page, { status: fullView(entry('svc', 'running', { cleartext_credentials_accepted: true })) });
    await open(page, '/ui/servers/svc/status');
    await expect(content(page).getByText('This server accepted credentials in cleartext.')).toHaveCount(1);
  });

  test('T1a the gateway reason shows for a state the list trusts it for, never for a refused server', async ({ page }) => {
    const sick = entry('sick', 'unhealthy', { reason: 'rsn-sentinel-trusted' });
    const refused = entry('nope', 'refused', { reason: 'rsn-sentinel-refused', running: false });
    await fakeServerGateway(page, { status: fullView(sick, refused) });
    await open(page, '/ui/servers/sick/status');
    await expect(content(page).getByText('rsn-sentinel-trusted')).toHaveCount(1);
    await goTo(page, '/ui/servers/nope/status');
    await expect(page.getByRole('heading', { level: 1, name: 'nope', exact: true })).toBeVisible();
    await expect(content(page).locator('.lb').first()).toContainText(await word(page, 'refused'));
    await expect(content(page).locator('[data-state="server"] h2')).toHaveText(await banner(page, refused));
    await expect(page.getByText('rsn-sentinel-refused')).toHaveCount(0);
  });

  for (const tab of ['status', 'actions']) {
    test(`T1b ${tab}: an unknown name is the empty state with a link to the list, and reads nothing else`, async ({ page }) => {
      const seen = await fakeServerGateway(page, { status: fullView(entry('github', 'running')) });
      await open(page, `/ui/servers/ghost/${tab}`);
      const empty = content(page).locator('[data-state="empty"]');
      await expect(empty.locator('h2')).toHaveText('No server named ghost');
      await expect(empty.getByRole('link', { name: 'Back to the servers' })).toHaveAttribute('href', '/ui/servers/status');
      expect([seen.status, seen.config, seen.keys]).toEqual([1, 0, 0]);
    });

    test(`T1b ${tab}: a key with no servers list gets the forbidden state, and reads nothing else`, async ({ page }) => {
      const seen = await fakeServerGateway(page, { status: { server_count: 2, healthy_count: 2, degraded_count: 0 } });
      await open(page, `/ui/servers/github/${tab}`);
      await expect(page).toHaveURL(new RegExp(`/ui/servers/github/${tab}$`));
      await expect(content(page).locator('[data-state="forbidden"]')).toHaveCount(1);
      expect([seen.status, seen.config, seen.keys]).toEqual([1, 0, 0]);
    });
  }

  test('T1c a server named like a tab is reached with its tab spelled out', async ({ page }) => {
    await fakeServerGateway(page, { status: fullView(entry('actions', 'running')) });
    await open(page, '/ui/servers/actions/status');
    await expect(page.getByRole('heading', { level: 1, name: 'actions', exact: true })).toBeVisible();
    await expect(content(page).locator('dl.sp-facts')).toHaveCount(1);
  });

  test('T1d the list links each name to its Status tab; . and .. stay plain text', async ({ page }) => {
    await fakeServerGateway(page, { status: fullView(entry('github', 'running'), entry('my server', 'running'), entry('.', 'running'), entry('..', 'running')) });
    await open(page, '/ui/servers/status?open=other');
    const c = content(page);
    await expect(c.getByRole('link', { name: 'github', exact: true })).toHaveAttribute('href', '/ui/servers/github/status');
    await expect(c.getByRole('link', { name: 'my server', exact: true })).toHaveAttribute('href', '/ui/servers/my%20server/status');
    for (const odd of ['.', '..']) {
      await expect(c.getByRole('rowheader', { name: odd, exact: true })).toHaveCount(1);
      await expect(c.getByRole('link', { name: odd, exact: true })).toHaveCount(0);
    }
  });

  test('T1d the path helper is never asked for the address of . or ..', async ({ page }) => {
    // The served helper, with its serverPath wrapped to record each name it is asked for.
    await page.route(/\/ui\/assets\/server-paths\.[0-9a-f]{12}\.js$/, async (route) => {
      const real = await (await route.fetch()).text();
      const spied = real.replace('export const serverPath = ', 'const unspiedServerPath = ')
        + '\nexport const serverPath = (name, tab) => { (globalThis.__askedFor ??= []).push(name); return unspiedServerPath(name, tab); };\n';
      await route.fulfill({ status: 200, contentType: 'text/javascript', body: spied });
    });
    await fakeServerGateway(page, { status: fullView(entry('github', 'running'), entry('.', 'running'), entry('..', 'running')) });
    await open(page, '/ui/servers/status?open=other');
    await expect(content(page).getByRole('link', { name: 'github', exact: true })).toHaveCount(1);
    const asked = await page.evaluate(() => globalThis.__askedFor ?? []);
    expect(asked).toContain('github');
    expect(asked.filter((n) => n === '.' || n === '..')).toEqual([]);
  });
});

test.describe('T2 the page follows the live status', () => {
  test('S3 the shell tab bar still links an object page by the encoded address', async ({ page }) => {
    await fakeServerGateway(page, { status: fullView(entry('a b', 'running')) });
    await open(page, '/ui/servers/a%20b/status');
    await expect(page.locator('a[href="/ui/servers/a%20b/actions"]').first()).toBeVisible();
    await expect(page.locator('a[href="/ui/servers/a%20b/settings"]').first()).toBeVisible();
  });
  test('T2a a status event redraws from its own body, with no new read', async ({ page }) => {
    const seen = await fakeServerGateway(page, { status: fullView(entry('svc', 'paused', { running: false })) });
    await open(page, '/ui/servers/svc/status');
    await expect(content(page).locator('.lb').first()).toContainText(await word(page, 'paused'));
    await statusEvent(page, fullView(entry('svc', 'running')));
    await expect(content(page).locator('.lb').first()).toContainText(await word(page, 'running'));
    expect(seen.status).toBe(1);
  });

  test('T2b a listener belongs to one render', async ({ page }) => {
    await countListeners(page, ['gateway-status']);
    await fakeServerGateway(page, { status: fullView(entry('a', 'running'), entry('b', 'running')) });
    await open(page, '/ui/servers/a/status');
    await goTo(page, '/ui/servers/b/status');
    await expect(page.getByRole('heading', { level: 1, name: 'b', exact: true })).toBeVisible();
    expect(await page.evaluate(() => window.__listeners('gateway-status'))).toBe(1);
    expect(await page.evaluate(() => window.__listenerCalls('gateway-status'))).toEqual({ add: 2, delete: 1 });
    await statusEvent(page, fullView(entry('a', 'paused', { running: false }), entry('b', 'running')));
    await expect(content(page).locator('.lb').first()).toContainText(await word(page, 'running'));
    await statusEvent(page, fullView(entry('a', 'running'), entry('b', 'paused', { running: false })));
    await expect(content(page).locator('.lb').first()).toContainText(await word(page, 'paused'));
    await goTo(page, '/ui/servers/b/actions');
    await expect(content(page).locator('dl.sp-facts')).toHaveCount(0);
    expect(await page.evaluate(() => window.__listeners('gateway-status'))).toBe(0);
    const before = await content(page).innerHTML();
    await statusEvent(page, fullView(entry('a', 'running'), entry('b', 'running')));
    expect(await content(page).innerHTML()).toBe(before);
  });

  test('T2c a status read answered after the user left adds no listener', async ({ page }) => {
    await countListeners(page, ['gateway-status']);
    const hold = gate();
    const reads = [];
    page.on('request', (r) => { if (r.url().endsWith('/ui/api/status')) reads.push(r); });
    const late = { code: 200, body: fullView(entry('svc', 'running')), hold: hold.shut };
    const seen = await fakeServerGateway(page, { status: (n) => (n === 1 ? late : fullView(entry('svc', 'running'))) });
    await page.goto('/ui/servers/svc/status');
    await expect.poll(() => seen.status).toBe(1);
    await goTo(page, '/ui/overview/status');
    await shellReady(page);
    const adds = await page.evaluate(() => window.__listenerCalls('gateway-status').add);
    hold.open();
    await reads[1].response();
    await settle(page);
    expect(await page.evaluate(() => window.__listenerCalls('gateway-status').add)).toBe(adds);
  });

  test('T2c the first event after the page has gone takes its listener away', async ({ page }) => {
    await countListeners(page, ['gateway-status']);
    await fakeServerGateway(page, { status: fullView(entry('svc', 'running')) });
    await open(page, '/ui/servers/svc/status');
    await goTo(page, '/ui/overview/status');
    await shellReady(page);
    const live = await page.evaluate(() => window.__listeners('gateway-status'));
    await statusEvent(page, fullView(entry('svc', 'running')));
    expect(await page.evaluate(() => window.__listeners('gateway-status'))).toBe(live - 1);
  });

  test('T2d a redraw keeps keyboard focus on the Activity link', async ({ page }) => {
    await fakeServerGateway(page, { status: fullView(entry('svc', 'unhealthy')) });
    await open(page, '/ui/servers/svc/status');
    const link = content(page).getByRole('link', { name: 'Its calls in Activity' });
    await link.focus();
    await statusEvent(page, fullView(entry('svc', 'running')));
    await expect(content(page).locator('.lb').first()).toContainText(await word(page, 'running'));
    await expect(link).toBeFocused();
  });

  test('T2d a list refresh keeps keyboard focus on a server-name link', async ({ page }) => {
    const seen = await fakeServerGateway(page, { status: fullView(entry('github', 'running'), entry('svc', 'unhealthy')) });
    await open(page, '/ui/servers/status?open=other');
    const link = content(page).getByRole('link', { name: 'github', exact: true });
    await link.focus();
    const reads = seen.status;
    await statusEvent(page, {});
    await expect.poll(() => seen.status).toBe(reads + 1);
    await settle(page);
    await expect(link).toBeFocused();
  });

  test('T2e a server gone from a status event gets the not-found state, and its listener goes', async ({ page }) => {
    await countListeners(page, ['gateway-status']);
    await fakeServerGateway(page, { status: fullView(entry('svc', 'unhealthy'), entry('other', 'running')) });
    await open(page, '/ui/servers/svc/status');
    await statusEvent(page, fullView(entry('other', 'running')));
    await expect(content(page).locator('[data-state="empty"] h2')).toHaveText('No server named svc');
    await expect(content(page).locator('dl.sp-facts')).toHaveCount(0);
    await expect(content(page).locator('[data-state="server"]')).toHaveCount(0);
    expect(await page.evaluate(() => window.__listeners('gateway-status'))).toBe(0);
  });
});

test.describe('T11 accessibility of the Status and Actions tabs', () => {
  for (const tab of ['status', 'actions']) {
    for (const scheme of ['light', 'dark']) {
      for (const width of WIDTHS) {
        test(`T11 ${tab} at ${width} px, ${scheme}: no blocking violations`, async ({ page }) => {
          await page.emulateMedia({ colorScheme: scheme });
          await page.setViewportSize({ width, height: 900 });
          await fakeServerGateway(page, { status: fullView(entry('svc', 'paused', { running: false, sign_in: { state: 'signed_in' } })) });
          await open(page, `/ui/servers/svc/${tab}`);
          await expect(page.getByRole('heading', { level: 1, name: 'svc', exact: true })).toBeVisible();
          expect(await blockingViolations(page)).toEqual([]);
        });
      }
    }
  }
});
