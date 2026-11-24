// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The restart banner: while gateway.yaml holds API keys that only a restart
// puts into use, an admin sees one standing region under the top bar on every
// page. It names the waiting keys, says which changes still apply, and gives
// the start command (or the guidance line, or the file's start refusal). It
// is as of its last read of GET /ui/api/gateway, and says when that was.
import { test, expect, blockingViolations, WIDTHS } from './base.mjs';
import { PAGES, shellReady, shellModuleUrl } from './shell.mjs';

const ENV = { name: 'home', source: 'config' };
// Fixture lines: the banner shows whatever the gateway sends in these keys.
const ADVICE = 'Use the start command below once this process has stopped.';
const COMMAND = "/opt/mcp-gateway/bin/mcp-gateway --config '/etc/mcp-gateway/gateway.yaml'";
const REFUSAL = 'A restart would not start: server.replicas is above 1 without a shared store. Fix the config file first.';

const block = (keys, restart) => ({ fields: ['auth.api_keys'], frozen: true, waiting_keys: keys, ...restart });
const ONE = block(['first'], { restart_advice: ADVICE, start_command: COMMAND });
const TWO = block(['first', 'second'], { restart_advice: ADVICE, start_command: COMMAND });
const NO_COMMAND = block(['first'], { restart_advice: ADVICE });
const BROKEN = block(['first'], { start_refusal: REFUSAL });
/** A restart pending for another field: nothing waits, so no banner. */
const NOT_FROZEN = { fields: ['server.port'] };

const HEAD_ONE = 'A restart finishes adding the API key first.';
const HEAD_TWO = 'A restart finishes adding the API keys first and second.';
const KEEP_ONE = 'No change to gateway.yaml that keeps the key is applied; one that takes it out is: revoke it, or restore a revision without it.';
const KEEP_TWO = 'No change to gateway.yaml that keeps these keys is applied; one that takes all of them out is: restore a revision without them, or edit gateway.yaml by hand.';
const HEAD_BROKEN = 'The API key first waits in gateway.yaml, but a start from that file would be refused.';

const banner = (page) => page.locator('[data-state="restart-pending"]');
const lines = (page) => banner(page).locator(':scope > *').evaluateAll((ns) => ns.map((n) => n.innerText.trim()));

/** Every GET /ui/api/gateway answers `pending_restart: state.block`; while `state.held` is an array, reads wait in it. */
async function gatewayRoute(page, first) {
  const state = { block: first, held: null, asked: 0 };
  await page.route('**/ui/api/gateway', (route) => {
    state.asked += 1;
    if (state.held) {
      state.held.push((b) => route.fulfill({ json: { environment: ENV, pending_restart: b } }));
      return undefined;
    }
    return route.fulfill({ json: { environment: ENV, pending_restart: state.block } });
  });
  return state;
}

/** A write through the shell's own api(), as a screen makes one. */
async function write(page, method, path) {
  await page.evaluate(async ([url, m, p]) => (await import(url)).api(p, { method: m, body: '{}' }),
    [await shellModuleUrl(page), method, path]);
}

/** Move to `path` the way a sidebar link does: no page load. */
async function go(page, path) {
  await page.evaluate(async ([url, p]) => (await import(url)).go(p), [await shellModuleUrl(page), path]);
  await page.waitForURL(`**${path}`);
}

/** Resolves when the next gateway read has its answer. */
const gatewayAnswer = (page) => page.waitForResponse((r) => new URL(r.url()).pathname === '/ui/api/gateway');

/** The banner's check time, to the millisecond: every drawn read changes it. */
const checkedAt = (page) => banner(page).locator('time').getAttribute('datetime');

/** Resolves once a read newer than `before` has been drawn into the banner. */
const drawnAfter = (page, before) => expect.poll(() => checkedAt(page)).not.toBe(before);

/**
 * Two frames: time for an answer that has arrived to be dropped. Only where
 * nothing is drawn (an absent banner, a dropped answer), so no signal exists.
 */
const settle = (page) => page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));

async function open(page, path = '/ui/overview/status') {
  await page.goto(path);
  await shellReady(page);
}

/** The keys routes the writes use: a created key, a revoked key. */
async function keyRoutes(page) {
  await page.route('**/ui/api/keys', (r) => r.fulfill({ status: 201, json: {} }));
  await page.route('**/ui/api/keys/first', (r) => r.fulfill({ status: 200, json: {} }));
}

test('B1 an admin sees the banner on every page, naming each waiting key, in order, with the command and Copy', async ({ page }) => {
  for (const [shown, head, keep] of [[ONE, HEAD_ONE, KEEP_ONE], [TWO, HEAD_TWO, KEEP_TWO]]) {
    await page.unroute('**/ui/api/gateway');
    await gatewayRoute(page, shown);
    for (const [id] of PAGES) {
      await open(page, `/ui/${id}/status`);
      await expect(banner(page), id).toHaveCount(1);
      const got = await lines(page);
      expect(got.length, `${id}: ${got}`).toBe(5);
      expect(got.slice(0, 3), id).toEqual([head, keep, ADVICE]);
      expect(got[4], id).toMatch(/^Checked at \S/);
      await expect(banner(page).locator('code')).toHaveText(COMMAND);
      await expect(banner(page).getByRole('button', { name: 'Copy' })).toBeVisible();
      // Under the top bar, above the page's own heading.
      const order = await page.evaluate(() => {
        const b = document.querySelector('[data-state="restart-pending"]');
        const top = document.querySelector('.top');
        const head = document.querySelector('.head');
        return [top.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING, b.compareDocumentPosition(head) & Node.DOCUMENT_POSITION_FOLLOWING];
      });
      expect(order.every(Boolean), id).toBe(true);
    }
  }
});

test('B2 the banner appears after a create without a page load, and goes after the revoke', async ({ page }) => {
  await keyRoutes(page);
  const state = await gatewayRoute(page, null);
  await open(page);
  await page.evaluate(() => { window.__sameLoad = true; });
  await expect(banner(page)).toHaveCount(0);
  state.block = ONE;
  await write(page, 'POST', '/ui/api/keys');
  await expect(banner(page)).toHaveCount(1);
  state.block = null;
  await write(page, 'DELETE', '/ui/api/keys/first');
  await expect(banner(page)).toHaveCount(0);
  expect(await page.evaluate(() => window.__sameLoad)).toBe(true);
  // A restart pending for another field alone draws nothing: starting from a
  // drawn banner, that answer must take it away, so the check waits on a
  // real change rather than on time.
  state.block = ONE;
  await go(page, '/ui/tools/status');
  await expect(banner(page)).toHaveCount(1);
  state.block = NOT_FROZEN;
  await go(page, '/ui/servers/status');
  await expect(banner(page)).toHaveCount(0);
});

test('B3 with no start command the banner gives the guidance line and no copy button', async ({ page }) => {
  await gatewayRoute(page, NO_COMMAND);
  await open(page);
  expect(await lines(page)).toEqual([HEAD_ONE, KEEP_ONE, ADVICE, expect.stringMatching(/^Checked at \S/)]);
  await expect(banner(page).locator('code')).toHaveCount(0);
  await expect(banner(page).getByRole('button')).toHaveCount(0);
});

test('B3b a file whose start would be refused: the keys, the refusal and the same exception; no restart claim, no command', async ({ page }) => {
  await gatewayRoute(page, BROKEN);
  await open(page);
  expect(await lines(page)).toEqual([HEAD_BROKEN, REFUSAL, KEEP_ONE, expect.stringMatching(/^Checked at \S/)]);
  await expect(banner(page)).not.toContainText('A restart finishes');
  await expect(banner(page).locator('code')).toHaveCount(0);
  await expect(banner(page).getByRole('button')).toHaveCount(0);
});

test('B4 a page error and the restart banner are both shown, each once', async ({ page }) => {
  await gatewayRoute(page, ONE);
  await page.route('**/ui/api/overview', (r) => r.fulfill({ status: 500, json: { error: 'internal', message: 'broken' } }));
  await open(page);
  await expect(page.locator('#content [data-state="error"]')).toHaveCount(1);
  await expect(banner(page)).toHaveCount(1);
  // Away and back: each route change reads the banner again and redraws the page.
  // Counted only once the read on the way back is drawn, so a second copy
  // drawn by that read is seen.
  const start = await checkedAt(page);
  await go(page, '/ui/tools/status');
  await drawnAfter(page, start);
  const away = await checkedAt(page);
  await go(page, '/ui/overview/status');
  await drawnAfter(page, away);
  await expect(page.locator('#content [data-state="error"]')).toHaveCount(1);
  await expect(banner(page)).toHaveCount(1);
});

test('B5 the banner is announced once across three reads', async ({ page }) => {
  await page.addInitScript(() => {
    window.__said = [];
    addEventListener('DOMContentLoaded', () => {
      new MutationObserver((records) => {
        for (const r of records) for (const n of r.addedNodes) window.__said.push(n.textContent ?? '');
      }).observe(document.getElementById('announcer'), { childList: true, subtree: true, characterData: true });
    });
  });
  await gatewayRoute(page, ONE);
  await open(page);
  await expect(banner(page)).toHaveCount(1);
  // Two more reads, each answered and drawn before the count.
  for (const path of ['/ui/tools/status', '/ui/servers/status']) {
    const before = await checkedAt(page);
    await go(page, path);
    await drawnAfter(page, before);
  }
  await page.evaluate(async (url) => (await import(url)).announcerIdle(), await shellModuleUrl(page));
  const said = await page.evaluate(() => window.__said.join(' '));
  expect(said.split(HEAD_ONE).length - 1, said).toBe(1);
});

for (const width of WIDTHS) {
  for (const theme of ['dark', 'light']) {
    test(`B6 the banner passes axe at ${width} px, ${theme}`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await page.emulateMedia({ colorScheme: theme });
      await gatewayRoute(page, TWO);
      await open(page);
      await expect(banner(page)).toHaveCount(1);
      expect(await blockingViolations(page)).toEqual([]);
      // Nothing scrolls sideways.
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    });
  }
}

test('B7 the copy button comes after the top bar in the tab order and confirms in words', async ({ page }) => {
  await page.addInitScript(() => {
    window.__copied = [];
    Object.defineProperty(navigator, 'clipboard', { value: { writeText: async (t) => { window.__copied.push(t); } }, configurable: true });
  });
  await gatewayRoute(page, ONE);
  await open(page);
  await page.locator('.top .search').focus();
  let inTop = true;
  for (let i = 0; i < 8 && inTop; i += 1) {
    await page.keyboard.press('Tab');
    inTop = await page.evaluate(() => Boolean(document.activeElement.closest('.top')));
  }
  const copy = banner(page).getByRole('button', { name: 'Copy' });
  await expect(copy).toBeFocused();
  await page.keyboard.press('Enter');
  const button = banner(page).getByRole('button');
  await expect(button).toHaveText('Copied');
  expect(await page.evaluate(() => window.__copied)).toEqual([COMMAND]);
  // A read with the same content keeps the button, and the focus on it.
  await keyRoutes(page);
  const before = await checkedAt(page);
  await write(page, 'POST', '/ui/api/keys');
  await drawnAfter(page, before);
  await expect(button).toBeFocused();
});

test('B7b where the clipboard refuses, the command is selected and the button says so', async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(navigator, 'clipboard', { value: { writeText: () => Promise.reject(new Error('denied')) }, configurable: true });
  });
  await gatewayRoute(page, ONE);
  await open(page);
  await banner(page).getByRole('button', { name: 'Copy' }).click();
  await expect(banner(page).getByRole('button')).toHaveText('Selected: copy it with your keyboard');
  expect(await page.evaluate(() => getSelection().toString())).toBe(COMMAND);
});

test('B8 a member and an auditor see no banner and no error, and never ask for the read', async ({ page }) => {
  const member = { auth: { enabled: true, signed_in: true, admin: false }, servers: [],
    access: { pages: PAGES.map(([id]) => ({ id, open: id !== 'gateway', tabs: [{ id: 'status', open: true }] })) } };
  const auditor = { auth: { enabled: true, signed_in: true, admin: false }, servers: [] };
  for (const status of [member, auditor]) {
    await page.unroute('**/ui/api/status');
    await page.unroute('**/ui/api/gateway');
    await page.route('**/ui/api/status', (r) => r.fulfill({ json: status }));
    const state = await gatewayRoute(page, ONE);
    await open(page);
    // A route change, to a page that needs no answer of its own (not built yet).
    await go(page, '/ui/costs/status');
    await settle(page);
    await expect(page.locator('.top .who')).toHaveText('Signed in');
    await expect(banner(page)).toHaveCount(0);
    await expect(page.locator('#content [data-state="error"], [role="alert"]')).toHaveCount(0);
    expect(state.asked, 'the admin-only read is never asked for by another key').toBe(0);
  }
});

test('B10 an admin whose session ends on a write (401) loses the banner and sends no further read', async ({ page }) => {
  const state = await gatewayRoute(page, ONE);
  await page.route('**/ui/api/keys', (r) => r.fulfill({ status: 401, json: { error: 'unauthorized' } }));
  await open(page);
  await expect(banner(page)).toHaveCount(1);
  const asked = state.asked;
  await write(page, 'POST', '/ui/api/keys').catch(() => {}); // api() throws on the 401
  await expect(page.locator('#signin')).toBeVisible();
  await expect(banner(page)).toHaveCount(0);
  await settle(page);
  expect(state.asked, 'a read was sent after the session ended').toBe(asked);
});

test('B9 reads answered out of order: the newer answer wins, across a create and a revoke', async ({ page }) => {
  await keyRoutes(page);
  const state = await gatewayRoute(page, null);
  await open(page);
  await expect(banner(page)).toHaveCount(0);
  for (const [older, newer, method, path, count] of [
    [null, ONE, 'POST', '/ui/api/keys', 1],
    [ONE, null, 'DELETE', '/ui/api/keys/first', 0],
  ]) {
    state.held = [];
    await go(page, path === '/ui/api/keys' ? '/ui/tools/status' : '/ui/servers/status');
    await write(page, method, path);
    await expect.poll(() => state.held.length).toBe(2);
    const [first, second] = state.held;
    state.held = null;
    await second(newer);
    await expect(banner(page)).toHaveCount(count);
    const late = gatewayAnswer(page);
    await first(older);
    await late;
    await settle(page);
    await expect(banner(page), 'the older answer was applied over the newer').toHaveCount(count);
  }
});

test.describe('L9 the check time', () => {
  test.use({ locale: 'en-GB', timezoneId: 'Europe/Helsinki' });

  test('L9 the banner ends with the time of the read that drew it, in the page\'s time zone', async ({ page }) => {
    await page.clock.setFixedTime(new Date('2026-11-24T06:05:00Z'));
    await gatewayRoute(page, ONE);
    await open(page);
    expect((await lines(page)).at(-1)).toBe('Checked at 08:05');
    await page.clock.setFixedTime(new Date('2026-11-24T06:17:00Z'));
    await go(page, '/ui/tools/status');
    await expect.poll(async () => (await lines(page)).at(-1)).toBe('Checked at 08:17');
  });
});
