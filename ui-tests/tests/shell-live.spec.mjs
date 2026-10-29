// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// One polite live region: page banners, sign-in messages, stale data and
// To do count changes are announced through it, and nothing else in the
// shell is live. Rows L1-L13.
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { test, expect, WIDTHS, blockingViolations } from './base.mjs';
import { PAGES, withFixturePages, shellReady, shellModuleUrl } from './shell.mjs';

const PROBE = '**/ui/api/page-probe*';
const COUNT = '**/ui/api/decisions/count';
const LIVE = '[aria-live], [role="status"], [role="alert"], [role="log"], [role="marquee"], [role="timer"], output';

/** Record the text of every entry added to the announcer, from first paint. */
async function recordAnnouncements(page) {
  await page.addInitScript(() => {
    window.__writes = [];
    addEventListener('DOMContentLoaded', () => {
      const region = document.getElementById('announcer');
      if (!region) return;
      new MutationObserver((records) => {
        for (const r of records) for (const n of r.addedNodes) window.__writes.push((n.textContent ?? '').trim());
      }).observe(region, { childList: true });
    });
  });
}

const writes = (page) => page.evaluate(() => window.__writes ?? []);
const announced = async (page) => (await writes(page)).filter(Boolean);

/** Call an export of the shell module inside the page. */
async function callShell(page, name, ...args) {
  const url = await shellModuleUrl(page);
  await page.evaluate(async ([u, n, a]) => { const m = await import(u); await m[n](...a); }, [url, name, args]);
}

/** Wait until the announcer has written everything queued (it pauses between writes). */
const drained = (page) => callShell(page, 'announcerIdle');

/** The ids or classes of every live region in the document, but the announcer. */
const otherLive = (page) => page.evaluate((sel) => [...document.querySelectorAll(sel)]
  .filter((node) => node.id !== 'announcer')
  .map((node) => node.id || node.className || node.tagName), LIVE);

test('L1 the shell has exactly one live region, on every page and view', async ({ page }) => {
  await withFixturePages(page);
  for (const [id] of PAGES) {
    await page.goto(`/ui/${id}/status`);
    await shellReady(page);
    expect(await otherLive(page), id).toEqual([]);
  }
  await expect(page.getByRole('status', { includeHidden: false })).toHaveCount(1);
  await expect(page.locator('#announcer')).toHaveAttribute('role', 'status');
  expect(await page.locator('#announcer').evaluate((n) => getComputedStyle(n).display)).not.toBe('none');
  await page.keyboard.press('Control+k');
  await expect(page.locator('dialog.palette')).toBeVisible();
  expect(await otherLive(page), 'palette').toEqual([]);
  await page.keyboard.press('Escape');
  await page.setViewportSize({ width: 390, height: 844 });
  await page.locator('button.menu').click();
  expect(await otherLive(page), 'menu').toEqual([]);
});

test('L2 a page error is announced once, by its title', async ({ page }) => {
  await recordAnnouncements(page);
  await page.route(PROBE, (r) => r.fulfill({ status: 500, json: {} }));
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/policies/status');
  await expect(page.locator('#content [data-state="error"]')).toBeVisible();
  await drained(page);
  expect((await announced(page)).filter((t) => t.includes('The gateway answered with an error'))).toEqual(['The gateway answered with an error.']);
});

test('L3 a forbidden page is announced', async ({ page }) => {
  await recordAnnouncements(page);
  await page.route('**/ui/api/forbidden-probe', (r) => r.fulfill({ status: 403, json: {} }));
  await withFixturePages(page);
  await page.goto('/ui/access/status');
  await expect(page.locator('#content [data-state="forbidden"]')).toBeVisible();
  await drained(page);
  expect(await announced(page)).toContain('Not available to this key.');
});

test('L4 a Retry that succeeds says nothing; focus moves into the content', async ({ page }) => {
  await recordAnnouncements(page);
  let ok = false;
  await page.route(PROBE, (r) => (ok ? r.fulfill({ json: { value: 2 } }) : r.fulfill({ status: 503, json: {} })));
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/policies/status');
  await expect(page.locator('#content [data-state="error"]')).toBeVisible();
  await drained(page);
  const before = (await announced(page)).length;
  ok = true;
  await page.locator('#content [data-state="error"] button').click();
  await expect(page.locator('#content')).toContainText('value 2');
  await drained(page);
  expect((await announced(page)).length).toBe(before);
  expect(await page.evaluate(() => !!document.activeElement?.closest('#content'))).toBe(true);
});

test('L5 the To do count is announced when a known value changes, and only then', async ({ page }) => {
  await recordAnnouncements(page);
  let count = 3;
  await page.route(COUNT, (r) => (count === null ? r.fulfill({ status: 500, json: {} }) : r.fulfill({ json: { count } })));
  await page.goto('/ui/overview/status');
  await shellReady(page);
  await expect(page.locator('nav.route-nav .count')).toHaveText('3');
  const said = async () => (await announced(page)).filter((t) => t.includes('decide'));
  await drained(page);
  expect(await said()).toEqual([]);
  count = 5;
  await callShell(page, 'refreshCounts');
  await drained(page);
  expect(await said()).toEqual(['5 to decide.']);
  await callShell(page, 'refreshCounts');
  await drained(page);
  expect(await said()).toEqual(['5 to decide.']);
  count = 0;
  await callShell(page, 'refreshCounts');
  await drained(page);
  expect(await said()).toEqual(['5 to decide.', 'Nothing to decide.']);
  count = null;
  await callShell(page, 'refreshCounts');
  await drained(page);
  expect(await said()).toEqual(['5 to decide.', 'Nothing to decide.']);
});

test('L5b of two count refreshes, the older answer arriving last is dropped', async ({ page }) => {
  await recordAnnouncements(page);
  let calls = 0;
  let releaseFirst;
  const first = new Promise((resolve) => { releaseFirst = resolve; });
  await page.route(COUNT, async (r) => {
    calls += 1;
    if (calls === 1) return r.fulfill({ json: { count: 3 } });
    if (calls === 2) { await first; return r.fulfill({ json: { count: 9 } }); }
    return r.fulfill({ json: { count: 4 } });
  });
  await page.goto('/ui/overview/status');
  await expect(page.locator('nav.route-nav .count')).toHaveText('3');
  const url = await shellModuleUrl(page);
  await page.evaluate(async (u) => {
    const m = await import(u);
    window.__older = m.refreshCounts();
    await m.refreshCounts();
  }, url);
  releaseFirst();
  await page.evaluate(() => window.__older);
  await drained(page);
  await expect(page.locator('nav.route-nav .count')).toHaveText('4');
  expect((await announced(page)).filter((t) => t.includes('decide'))).toEqual(['4 to decide.']);
});

test('L6 the same message twice is said twice, as two entries', async ({ page }) => {
  await recordAnnouncements(page);
  await page.goto('/ui/overview/status');
  await shellReady(page);
  await callShell(page, 'announce', 'Saved.');
  await drained(page);
  await callShell(page, 'announce', 'Saved.');
  await drained(page);
  expect((await announced(page)).filter((t) => t === 'Saved.')).toHaveLength(2);
});

test('L7 a screen announces through the render context', async ({ page }) => {
  await recordAnnouncements(page);
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/gateway/status');
  await shellReady(page);
  await drained(page);
  expect(await announced(page)).toContain('Gateway status read.');
});

for (const width of WIDTHS) {
  test(`L8 axe at ${width} px with an announced page error`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.route(PROBE, (r) => r.fulfill({ status: 500, json: {} }));
    await withFixturePages(page, { probes: true });
    await page.goto('/ui/policies/status');
    await expect(page.locator('#content [data-state="error"]')).toBeVisible();
    expect(await blockingViolations(page)).toEqual([]);
  });
}

const KEY = 'mcpg_fixture_key_0123456789';

/** Auth on: status answers signed in only for KEY as a bearer. */
async function gate(page) {
  await page.route('**/ui/api/status', (route) => {
    const signedIn = (route.request().headers().authorization ?? '') === `Bearer ${KEY}`;
    return route.fulfill({ json: { version: '4.0.0', auth: { enabled: true, signed_in: signedIn, admin: signedIn } } });
  });
  await page.route('**/dashboard/logout', (r) => r.fulfill({ status: 204, body: '' }));
}

async function signIn(page, key = KEY) {
  await page.locator('#signin-key').fill(key);
  await page.keyboard.press('Enter');
}

test('L5c a new identity\'s first count is not announced', async ({ page }) => {
  await recordAnnouncements(page);
  await gate(page);
  let count = 3;
  await page.route(COUNT, (r) => r.fulfill({ json: { count } }));
  await page.goto('/ui/overview/status');
  await signIn(page);
  await expect(page.locator('nav.route-nav .count')).toHaveText('3');
  count = 7;
  await page.locator('.top .signout').click();
  await expect(page.locator('#signin')).toBeVisible();
  await drained(page);
  expect(await announced(page)).toContain('Signed out.');
  await signIn(page);
  await expect(page.locator('nav.route-nav .count')).toHaveText('7');
  await drained(page);
  expect((await announced(page)).filter((t) => t.includes('decide'))).toEqual([]);
});

test('L9 a refused key is announced through the one region and tied to the field', async ({ page }) => {
  await recordAnnouncements(page);
  await gate(page);
  await page.goto('/ui/overview/status');
  await signIn(page, 'mcpg_wrong_key_000000000000');
  const error = page.locator('.signin-error');
  await expect(error).toBeVisible();
  await drained(page);
  const text = (await error.textContent()).trim();
  expect(await announced(page)).toContain(text);
  const field = page.locator('#signin-key');
  await expect(field).toHaveAttribute('aria-invalid', 'true');
  const errorId = await error.getAttribute('id');
  expect(errorId).toBeTruthy();
  await expect(field).toHaveAttribute('aria-describedby', new RegExp(`\\b${errorId}\\b`));
  expect(await otherLive(page)).toEqual([]);
});

test('L10 no shell source makes a live region but the announcer, or inserts a banner state directly', () => {
  const dir = fileURLToPath(new URL('../../src/gateway/ui/shell/', import.meta.url));
  const files = readdirSync(dir).filter((f) => /\.(js|html)$/.test(f));
  const live = /aria-live|role(?:=|:\s*)['"](?:status|alert|log|marquee|timer)['"]|<output\b/g;
  const found = [];
  let modals = 0;
  for (const file of files) {
    const source = readFileSync(dir + file, 'utf8');
    for (const line of source.split('\n')) {
      if (line.match(live) && !line.includes('id="announcer"')) found.push(`${file}: ${line.trim()}`);
    }
    if (file.endsWith('.js')) {
      for (const m of source.match(/state\(\s*'(error|forbidden|stale)'/g) ?? []) found.push(`${file}: ${m}`);
      for (const m of source.matchAll(/\.showModal\(/g)) {
        modals += 1;
        // A modal makes the page inert, the announcer with it, unless it moves in right after.
        if (!source.slice(m.index, m.index + 300).includes('moveAnnouncer(')) found.push(`${file}: showModal() without moveAnnouncer`);
      }
    }
  }
  // The palette and the confirmation (UI1.19) are the two modals; never both at once (D7).
  expect(modals, 'showModal() sites').toBe(2);
  expect(found).toEqual([]);
});

test('L11 a page message queued before navigating away is never said', async ({ page }) => {
  await recordAnnouncements(page);
  await withFixturePages(page);
  await page.goto('/ui/overview/status');
  await shellReady(page);
  const url = await shellModuleUrl(page);
  await page.evaluate(async (u) => {
    const m = await import(u);
    m.announce('Old page news.', { subject: 'page' });
    history.pushState(null, '', '/ui/servers/status');
    dispatchEvent(new PopStateEvent('popstate'));
  }, url);
  await drained(page);
  expect(await announced(page)).not.toContain('Old page news.');
});

test('L12 messages about different things in one tick are all said, in one write', async ({ page }) => {
  await recordAnnouncements(page);
  await page.goto('/ui/overview/status');
  await shellReady(page);
  const url = await shellModuleUrl(page);
  await page.evaluate(async (u) => {
    const m = await import(u);
    m.announce('Page news.', { subject: 'page' });
    m.announce('Count news.', { subject: 'count' });
  }, url);
  await drained(page);
  // One write carries both: an atomic region may merge separate writes.
  expect(await announced(page)).toContain('Page news. Count news.');
});

test('L13 stale data is announced, and so is its recovery', async ({ page }) => {
  await recordAnnouncements(page);
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/activity/status');
  await shellReady(page);
  await expect(page.locator('#content [data-state="stale"]')).toHaveCount(0);
  await drained(page);
  // Both are said, in order: the first is written at once, the second after the dwell.
  // The stale title (UI1.22) is "Updates stopped · reconnecting", or with its time.
  const said = (await announced(page)).join(' ');
  expect(said.split('Updates stopped').length - 1, 'said once, though shown twice').toBe(1);
  expect(said.indexOf('Updates resumed.')).toBeGreaterThan(said.indexOf('Updates stopped'));
});

test('L14 while the palette is open the region is inside it, and back after', async ({ page }) => {
  await recordAnnouncements(page);
  await page.goto('/ui/overview/status');
  await shellReady(page);
  await page.keyboard.press('Control+k');
  await expect(page.locator('dialog.palette')).toBeVisible();
  await expect(page.locator('dialog.palette #announcer')).toHaveCount(1);
  await expect(page.getByRole('status')).toHaveCount(1);
  await callShell(page, 'announce', 'While the palette is open.');
  await drained(page);
  expect(await announced(page)).toContain('While the palette is open.');
  await page.keyboard.press('Escape');
  await expect(page.locator('body > #announcer')).toHaveCount(1);
});

test('L5d an older count failure arriving after a newer success changes nothing', async ({ page }) => {
  await recordAnnouncements(page);
  let calls = 0;
  let releaseFirst;
  const first = new Promise((resolve) => { releaseFirst = resolve; });
  await page.route(COUNT, async (r) => {
    calls += 1;
    if (calls === 1) return r.fulfill({ json: { count: 3 } });
    if (calls === 2) { await first; return r.fulfill({ status: 500, json: {} }); }
    return r.fulfill({ json: { count: 4 } });
  });
  await page.goto('/ui/overview/status');
  await expect(page.locator('nav.route-nav .count')).toHaveText('3');
  const url = await shellModuleUrl(page);
  await page.evaluate(async (u) => {
    const m = await import(u);
    window.__older = m.refreshCounts();
    await m.refreshCounts();
  }, url);
  releaseFirst();
  await page.evaluate(() => window.__older);
  await drained(page);
  await expect(page.locator('nav.route-nav .count')).toHaveText('4');
});

test('L6b a message queued before a sign-in change is dropped', async ({ page }) => {
  await recordAnnouncements(page);
  await gate(page);
  await page.goto('/ui/overview/status');
  await signIn(page);
  await expect(page.locator('#signin')).toBeHidden();
  await callShell(page, 'announce', 'Saved.');
  await drained(page);
  const url = await shellModuleUrl(page);
  await page.evaluate(async (u) => {
    const m = await import(u);
    m.announce('Saved.', { subject: 'page' });
    document.querySelector('.top .signout').click();
  }, url);
  await expect(page.locator('#signin')).toBeVisible();
  await drained(page);
  expect((await announced(page)).filter((t) => t.includes('Saved.'))).toHaveLength(1);
});

test('L9b a key check that gets no answer is announced, and the field is not marked invalid', async ({ page }) => {
  await recordAnnouncements(page);
  await page.route('**/ui/api/status', (route) => (route.request().headers().authorization
    ? route.abort('connectionrefused')
    : route.fulfill({ json: { version: '4.0.0', auth: { enabled: true, signed_in: false, admin: false } } })));
  await page.goto('/ui/overview/status');
  await signIn(page);
  const error = page.locator('.signin-error');
  await expect(error).toBeVisible();
  await drained(page);
  expect(await announced(page)).toContain((await error.textContent()).trim());
  await expect(page.locator('#signin-key')).not.toHaveAttribute('aria-invalid', 'true');
});

test('L15 a screen\'s announce kept past navigation says nothing', async ({ page }) => {
  await recordAnnouncements(page);
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/gateway/status');
  await shellReady(page);
  await drained(page);
  await page.locator('nav.route-nav a[href="/ui/servers"]').click();
  await expect(page.locator('#content')).toContainText('servers - status');
  await page.evaluate(() => window.gatewayAnnounce('Late gateway news.'));
  await drained(page);
  expect(await announced(page)).not.toContain('Late gateway news.');
});

test('L16 a message queued as the session expires is not said over sign-in', async ({ page }) => {
  await recordAnnouncements(page);
  await gate(page);
  await page.route(PROBE, (r) => r.fulfill({ status: 401, json: {} }));
  await page.goto('/ui/overview/status');
  await signIn(page);
  await expect(page.locator('#signin')).toBeHidden();
  const url = await shellModuleUrl(page);
  await page.evaluate(async (u) => {
    const m = await import(u);
    // Written at once; the next message then waits out the pause, so it is still
    // queued when the 401 below signs the session out.
    m.announce('First news.');
    await new Promise((done) => setTimeout(done, 50));
    m.announce('Count news.', { subject: 'count' });
    await m.api('/ui/api/page-probe').catch(() => {});
  }, url);
  await expect(page.locator('#signin')).toBeVisible();
  await drained(page);
  expect(await announced(page)).not.toContain('Count news.');
});
