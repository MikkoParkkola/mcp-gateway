// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The Activity stream: Activity › Status lists the gateway's rows in answer
// order, filters by outcome, search, range, server and key, and opens a row
// from the keyboard. The shell document is served as the gateway serves it;
// /ui/api answers are mocked. The clock is paused before the page loads so
// from/to are exact UTC seconds.
import { test, expect } from './base.mjs';
import { shellReady } from './shell.mjs';

test.use({ timezoneId: 'UTC' });

const AT = '2026-11-15T12:00:00Z';
const FROM_24H = '2026-11-14T12:00:00Z';
const FROM_1H = '2026-11-15T11:00:00Z';
const FROM_7D = '2026-11-08T12:00:00Z';
const TO = '2026-11-15T12:00:00Z';
const HOSTILE = '<img src=x onerror="window.__pwned=1">';
const EMPTY_LINE = 'Calls, caught calls, decisions and changes appear here as they happen. Widen the range, or connect a client.';

const call = (id, timestamp, account, tool, outcome) => ({
  id,
  kind: 'call',
  timestamp,
  outcome,
  who: { credential_kind: 'api_key', account, authority: 'https://issuer.example', subject: `sub-${id}` },
  server: 'docs',
  tool,
});

const ROWS = [
  call('c-1', '2026-11-15T08:05:05Z', 'ana', 'create_issue', 'ok'),
  call('c-2', '2026-11-15T08:01:01Z', 'support-agent', 'web.fetch', 'failed'),
  call('c-3', '2026-11-15T08:04:04Z', 'deploy-bot', 'kb.search', 'blocked'),
  call('c-4', '2026-11-15T08:02:02Z', 'ana', 'tickets.get', 'ok'),
  call('c-5', '2026-11-15T08:03:03Z', 'ci', 'tickets.update', 'failed'),
];

const SHOWN = [
  '08:05:05 ana create_issue ok',
  '08:01:01 support-agent web.fetch failed',
  '08:04:04 deploy-bot kb.search blocked',
  '08:02:02 ana tickets.get ok',
  '08:03:03 ci tickets.update failed',
];

const rowLinks = (page) => page.locator('#content a[href^="/ui/activity/"][href$="/status"]:not([href="/ui/activity/status"])');

function filters(url) {
  const q = new URL(url).searchParams;
  return {
    outcome: q.get('outcome'),
    server: q.get('server'),
    caller: q.get('caller'),
    q: q.get('q'),
    from: q.get('from'),
    to: q.get('to'),
    cursor: q.get('cursor'),
  };
}

/** The row link's own text, without a tooltip trigger nested inside it. */
async function shownRows(page) {
  return rowLinks(page).evaluateAll((els) => els.map((el) => {
    const clone = el.cloneNode(true);
    for (const tip of clone.querySelectorAll('.has-tip')) tip.remove();
    return {
      href: el.getAttribute('href'),
      text: (clone.textContent ?? '').replace(/\s+/g, ' ').trim(),
    };
  }));
}

/**
 * Mock status and the activity list. `admin` may be a boolean or a function
 * read on each status request. The clock is installed before the caller navigates.
 */
async function install(page, { admin = true, answer }) {
  const urls = [];
  const adminNow = () => (typeof admin === 'function' ? admin() : admin);
  // Installed early, then paused at AT: Date.now() reads AT and no timer fires
  // until a row runs the clock (setFixedTime alone keeps timers running).
  await page.clock.install({ time: Date.parse(AT) - 60_000 });
  await page.clock.pauseAt(Date.parse(AT));
  await page.route('**/ui/api/status', (r) => r.fulfill({
    json: { auth: { enabled: true, signed_in: true, admin: adminNow() } },
  }));
  await page.route('**/ui/api/activity**', (r) => {
    const url = r.request().url();
    if (new URL(url).pathname !== '/ui/api/activity') return r.continue();
    urls.push(url);
    return r.fulfill({ json: answer(url) });
  });
  return urls;
}

async function open(page, urls, path) {
  await page.goto(path);
  await shellReady(page);
  await expect.poll(() => urls.length).toBeGreaterThan(0);
}

const list = (rows, next = null) => ({ rows, next_cursor: next });

// Named for what the API's q matches: a tool name, or a call's exact trace id.
const searchBox = (page) => {
  const name = { name: 'Tool or trace id', exact: true };
  return page.getByRole('searchbox', name).or(page.getByRole('textbox', name));
};

/** The shell's empty state (`state('empty')`), the one that carries this title. */
const emptyState = (page, title) => page.locator('#content [data-state="empty"]').filter({
  has: page.getByRole('heading', { name: title, exact: true }),
});

/** The text of the line that holds a tooltip trigger, tips themselves excluded. */
async function lineWithTip(page, id, want) {
  return page.locator(`#content .has-tip[data-tip="${id}"]`).evaluate((el, want) => {
    const textOf = (node) => {
      if (!node) return '';
      const clone = node.cloneNode(true);
      for (const tip of clone.querySelectorAll('.has-tip')) tip.remove();
      return (clone.textContent ?? '').replace(/\s+/g, ' ').trim();
    };
    if (textOf(el.previousElementSibling) === want) return want;
    let node = el.parentElement;
    while (node && node.id !== 'content') {
      if (textOf(node) === want) return want;
      node = node.parentElement;
    }
    return textOf(el.parentElement);
  }, want);
}

test('A1 landing: the last 24 h, five rows in answer order', async ({ page }) => {
  const urls = await install(page, { answer: () => list(ROWS) });
  await open(page, urls, '/ui/activity/status');
  await expect.poll(() => urls.length).toBe(1);
  const sent = filters(urls[0]);
  expect(sent.from).toBe(FROM_24H);
  expect(sent.to).toBe(TO);
  expect(sent.outcome).toBeNull();
  expect(sent.server).toBeNull();
  expect(sent.caller).toBeNull();
  expect(sent.q).toBeNull();
  expect(sent.cursor).toBeNull();
  await expect(page.locator('nav.tabs a')).toHaveText(['Status']);
  await expect.poll(() => shownRows(page)).toEqual(ROWS.map((row, i) => ({
    href: `/ui/activity/${row.id}/status`,
    text: SHOWN[i],
  })));
  // The blocked tooltip sits beside the outcome filter's "blocked" choice, never
  // inside a row: a row is one link and holds nothing else a keyboard can reach.
  await expect(page.locator('#content .has-tip[data-tip="activity.status.blocked"] button')).toHaveCount(1);
  await expect(rowLinks(page).locator('a, button, input, select, [tabindex]')).toHaveCount(0);
});

test('A2 outcome: blocked sends outcome=blocked, All sends none', async ({ page }) => {
  const urls = await install(page, { answer: () => list(ROWS) });
  await open(page, urls, '/ui/activity/status');
  const outcome = page.getByRole('group', { name: 'Outcome' });
  await expect(outcome.getByRole('button')).toHaveText(['All', 'ok', 'failed', 'blocked']);
  await expect(page.locator('#content .has-tip[data-tip="activity.status.outcome"] button')).toBeVisible();
  await outcome.getByRole('button', { name: 'blocked', exact: true }).click();
  await expect.poll(() => filters(urls.at(-1)).outcome).toBe('blocked');
  expect(filters(urls.at(-1)).from).toBe(FROM_24H);
  expect(filters(urls.at(-1)).to).toBe(TO);
  await expect.poll(() => new URL(page.url()).searchParams.get('outcome')).toBe('blocked');
  await outcome.getByRole('button', { name: 'All', exact: true }).click();
  await expect.poll(() => filters(urls.at(-1)).outcome).toBeNull();
  await expect.poll(() => new URL(page.url()).searchParams.has('outcome')).toBe(false);
});

test('A3 search: web.fetch is one request after typing stops, and q is in the URL', async ({ page }) => {
  const urls = await install(page, { answer: () => list(ROWS) });
  await open(page, urls, '/ui/activity/status');
  const before = urls.length;
  const box = searchBox(page);
  await box.focus();
  // 100 ms between keys: a wait that a key does not restart would end during the
  // typing (300 ms after the first key) and ask for a prefix.
  for (const key of 'web.fetch') {
    await box.press(key);
    await page.clock.runFor(100);
  }
  expect(urls.length).toBe(before);
  // The wait is 300 ms after the last key (100 ms have passed): nothing at 250 ms,
  // one request by 350 ms.
  // The search commits by writing q into the address, synchronously in its timer,
  // so the address read inside the page tells whether the wait has ended.
  const committedQ = () => page.evaluate(() => new URLSearchParams(location.search).get('q'));
  await page.clock.runFor(150);
  expect(await committedQ()).toBeNull();
  expect(urls.length).toBe(before);
  await page.clock.runFor(100);
  expect(await committedQ()).toBe('web.fetch');
  await expect.poll(() => urls.length).toBe(before + 1);
  // Still one once every timer has had its turn.
  await page.clock.runFor(1000);
  expect(urls.length).toBe(before + 1);
  expect(filters(urls.at(-1)).q).toBe('web.fetch');
  // A filter change takes its window when it commits: 1.2 s after landing (nine keys
  // 100 ms apart, then the 300 ms wait), so to is one second on.
  expect(filters(urls.at(-1)).from).toBe('2026-11-14T12:00:01Z');
  expect(filters(urls.at(-1)).to).toBe('2026-11-15T12:00:01Z');
  await expect.poll(() => new URL(page.url()).searchParams.get('q')).toBe('web.fetch');
});

test('A4 range: Last 1 h sends that window; the first request was 24 h', async ({ page }) => {
  const urls = await install(page, { answer: () => list(ROWS) });
  await open(page, urls, '/ui/activity/status');
  expect(filters(urls[0]).from).toBe(FROM_24H);
  expect(filters(urls[0]).to).toBe(TO);
  await page.getByRole('button', { name: 'Last 1 h', exact: true }).click();
  await expect.poll(() => filters(urls.at(-1)).from).toBe(FROM_1H);
  expect(filters(urls.at(-1)).to).toBe(TO);
});

test('A5 keyboard: Tab from the search reaches the first row, Enter opens it', async ({ page }) => {
  const urls = await install(page, { answer: () => list(ROWS) });
  await open(page, urls, '/ui/activity/status');
  await expect.poll(() => shownRows(page)).toHaveLength(5);
  await searchBox(page).focus();
  await page.keyboard.press('Tab');
  const first = rowLinks(page).first();
  await expect(first).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL('/ui/activity/c-1/status');
});

test('A6 deep links: server=github and key=support-agent', async ({ page }) => {
  // Neither value appears in a row, so the visible word is the active filter.
  const quiet = [
    call('c-1', '2026-11-15T08:05:05Z', 'ana', 'create_issue', 'ok'),
    call('c-2', '2026-11-15T08:01:01Z', 'deploy-bot', 'web.fetch', 'failed'),
  ];
  const urls = await install(page, { answer: () => list(quiet) });
  await open(page, urls, '/ui/activity/status?server=github');
  expect(filters(urls[0]).server).toBe('github');
  expect(filters(urls[0]).caller).toBeNull();
  expect(filters(urls[0]).from).toBe(FROM_24H);
  expect(filters(urls[0]).to).toBe(TO);
  await expect(page.locator('#content').getByText('github', { exact: true })).toBeVisible();
  expect(new URL(page.url()).searchParams.get('server')).toBe('github');
  const at = urls.length;
  await page.goto('/ui/activity/status?key=support-agent');
  await shellReady(page);
  await expect.poll(() => urls.length).toBeGreaterThan(at);
  const sent = filters(urls.at(-1));
  expect(sent.caller).toBe('support-agent');
  expect(sent.server).toBeNull();
  expect(sent.from).toBe(FROM_24H);
  expect(sent.to).toBe(TO);
  await expect(page.locator('#content').getByText('support-agent', { exact: true })).toBeVisible();
  const url = new URL(page.url());
  expect(url.searchParams.get('key')).toBe('support-agent');
  expect(url.searchParams.has('caller')).toBe(false);
});

test('A7 more: next_cursor c2 loads the next page after the first', async ({ page }) => {
  const first = [
    call('p-1', '2026-11-15T08:01:01Z', 'ana', 'alpha.one', 'ok'),
    call('p-2', '2026-11-15T08:02:02Z', 'ana', 'bravo.two', 'ok'),
    call('p-3', '2026-11-15T08:03:03Z', 'ana', 'charlie.three', 'ok'),
  ];
  const second = [
    call('p-4', '2026-11-15T08:04:04Z', 'ana', 'delta.four', 'ok'),
    call('p-5', '2026-11-15T08:05:05Z', 'ana', 'echo.five', 'failed'),
  ];
  const urls = await install(page, {
    answer: (url) => (new URL(url).searchParams.get('cursor') === 'c2'
      ? list(second)
      : list(first, 'c2')),
  });
  await open(page, urls, '/ui/activity/status');
  expect(filters(urls[0]).cursor).toBeNull();
  await expect(rowLinks(page).first()).toBeVisible();
  await rowLinks(page).last().scrollIntoViewIfNeeded();
  await page.evaluate(() => {
    const nodes = [document.scrollingElement, document.querySelector('#content')];
    for (const el of document.querySelectorAll('#content *')) nodes.push(el);
    for (const el of nodes) {
      if (el && el.scrollHeight > el.clientHeight) el.scrollTop = el.scrollHeight;
    }
  });
  // Intersection observers are delivered on a frame; the clock is paused.
  await page.clock.runFor(100);
  await expect.poll(() => urls.filter((u) => filters(u).cursor === 'c2').length).toBe(1);
  const more = urls.find((u) => filters(u).cursor === 'c2');
  expect(filters(more).from).toBe(FROM_24H);
  expect(filters(more).to).toBe(TO);
  await expect.poll(async () => (await shownRows(page)).map((row) => row.text)).toEqual([
    '08:01:01 ana alpha.one ok',
    '08:02:02 ana bravo.two ok',
    '08:03:03 ana charlie.three ok',
    '08:04:04 ana delta.four ok',
    '08:05:05 ana echo.five failed',
  ]);
});

test('A8 empty: the 24 h empty state, then Last 7 days removes the button', async ({ page }) => {
  const urls = await install(page, { answer: () => list([]) });
  await open(page, urls, '/ui/activity/status');
  const day = emptyState(page, 'No calls in the last 24 h');
  await expect(day).toBeVisible();
  await expect(day).toContainText(EMPTY_LINE);
  await expect(day.getByRole('button')).toHaveText(['Last 7 days']);
  await day.getByRole('button', { name: 'Last 7 days', exact: true }).click();
  await expect.poll(() => filters(urls.at(-1)).from).toBe(FROM_7D);
  expect(filters(urls.at(-1)).to).toBe(TO);
  const week = emptyState(page, 'No calls in the last 7 days');
  await expect(week).toBeVisible();
  await expect(week).toContainText(EMPTY_LINE);
  await expect(week.getByRole('button')).toHaveCount(0);
});

test('A9 member: the line follows the list\'s own access, not the status admin flag', async ({ page }) => {
  // admin is false throughout: an auditor reads false there too and is served everyone's
  // calls, so only the list answer's access says whose calls these are.
  let access = 'own';
  const urls = await install(page, { admin: false, answer: () => ({ ...list(ROWS), access }) });
  await open(page, urls, '/ui/activity/status');
  const trigger = page.locator('#content .has-tip[data-tip="activity.status.calls-made-with-your-key"]');
  await expect(trigger.locator('button')).toBeVisible();
  expect(await lineWithTip(page, 'activity.status.calls-made-with-your-key', 'Showing only calls made with your key. Members see their own calls.')).toBe('Showing only calls made with your key. Members see their own calls.');
  await expect.poll(() => shownRows(page)).toHaveLength(5);
  const lineBox = await trigger.boundingBox();
  const rowBox = await rowLinks(page).first().boundingBox();
  expect(lineBox.y).toBeLessThan(rowBox.y);
  for (const other of ['all', 'scoped']) {
    access = other;
    const at = urls.length;
    await page.goto('/ui/activity/status');
    await shellReady(page);
    await expect.poll(() => urls.length).toBeGreaterThan(at);
    await expect.poll(() => shownRows(page)).toHaveLength(5);
    // The line itself, which is always in the page: the trigger may not be mounted
    // yet, and hidden is true of nothing, so the count pins that it is there.
    const line = page.locator('#content .activity-member');
    await expect(line, other).toHaveCount(1);
    await expect(line, other).toBeHidden();
  }
});

test('A10 hostile: a tool and a key render as text', async ({ page }) => {
  const rows = [call('h-1', '2026-11-15T08:01:01Z', HOSTILE, HOSTILE, 'ok')];
  const urls = await install(page, { answer: () => list(rows) });
  await open(page, urls, '/ui/activity/status');
  await expect.poll(() => shownRows(page)).toEqual([{
    href: '/ui/activity/h-1/status',
    text: `08:01:01 ${HOSTILE} ${HOSTILE} ok`,
  }]);
  await expect(page.locator('#content img')).toHaveCount(0);
  expect(await page.evaluate(() => window.__pwned)).toBeUndefined();
});

test('A11 search left mid-wait: the next page keeps its own address, and no list request goes out', async ({ page }) => {
  const urls = await install(page, { answer: () => list(ROWS) });
  await open(page, urls, '/ui/activity/status');
  await expect.poll(() => shownRows(page)).toHaveLength(5);
  const before = urls.length;
  // Typed, then a row opened before the 300 ms wait ends (the clock is paused).
  await searchBox(page).pressSequentially('web.fetch');
  await rowLinks(page).first().click();
  await expect(page).toHaveURL('/ui/activity/c-1/status');
  await page.clock.runFor(400);
  // The wait ending must not write the list's filters into this page's address.
  expect(await page.evaluate(() => `${location.pathname}${location.search}`)).toBe('/ui/activity/c-1/status');
  expect(urls.length).toBe(before);
});

test('A12 columns: time, key, tool and outcome each start at the same place on every row', async ({ page }) => {
  const urls = await install(page, { answer: () => list(ROWS) });
  await open(page, urls, '/ui/activity/status');
  await expect.poll(() => shownRows(page)).toHaveLength(5);
  const cells = await rowLinks(page).evaluateAll((els) => els.map((el) => [...el.children]
    .map((c) => {
      const r = c.getBoundingClientRect();
      return { text: (c.textContent ?? '').trim(), x: Math.round(r.left), mid: Math.round(r.top + r.height / 2) };
    })));
  // One element per column, in order, holding exactly the row's words.
  expect(cells.map((row) => row.map((c) => c.text))).toEqual(SHOWN.map((s) => s.split(' ')));
  // The keys differ in length (ana, support-agent, deploy-bot, ci): words run
  // together would start each tool and outcome at a different place.
  for (let k = 0; k < 4; k += 1) {
    expect(new Set(cells.map((row) => row[k].x)).size, `column ${k}`).toBe(1);
  }
  // Side by side on one line, in column order: cells stacked in one column would
  // also share a left edge.
  for (const row of cells) {
    expect(new Set(row.map((c) => c.mid)).size).toBe(1);
    for (let k = 1; k < 4; k += 1) expect(row[k].x).toBeGreaterThan(row[k - 1].x);
  }
});

/** Scroll every scroller to its end and run a frame, so the list's end is in view (as A7 does). */
async function reachEnd(page) {
  await rowLinks(page).last().scrollIntoViewIfNeeded().catch(() => {});
  await page.evaluate(() => {
    const nodes = [document.scrollingElement, document.querySelector('#content')];
    for (const el of document.querySelectorAll('#content *')) nodes.push(el);
    for (const el of nodes) {
      if (el && el.scrollHeight > el.clientHeight) el.scrollTop = el.scrollHeight;
    }
  });
  // Intersection observers are delivered on a frame; the clock is paused.
  await page.clock.runFor(100);
}

const PAGE_ONE = [
  call('p-1', '2026-11-15T08:01:01Z', 'ana', 'alpha.one', 'ok'),
  call('p-2', '2026-11-15T08:02:02Z', 'ana', 'bravo.two', 'ok'),
  call('p-3', '2026-11-15T08:03:03Z', 'ana', 'charlie.three', 'ok'),
];
const PAGE_TWO = [
  call('p-4', '2026-11-15T08:04:04Z', 'ana', 'delta.four', 'ok'),
  call('p-5', '2026-11-15T08:05:05Z', 'ana', 'echo.five', 'failed'),
];
const TEXT_ONE = ['08:01:01 ana alpha.one ok', '08:02:02 ana bravo.two ok', '08:03:03 ana charlie.three ok'];
const TEXT_TWO = ['08:04:04 ana delta.four ok', '08:05:05 ana echo.five failed'];
const texts = async (page) => (await shownRows(page)).map((row) => row.text);
const byCursor = (url) => new URL(url).searchParams.get('cursor');

test('A13 a first page with no rows but a cursor is not the empty state: the next page is read and shown', async ({ page }) => {
  // A sparse filter: the server's scan ran out before it found a match, and says where to go on.
  const urls = await install(page, { answer: (url) => (byCursor(url) === 'c2' ? list(PAGE_TWO) : list([], 'c2')) });
  // Page two is held, so the screen is read while only the empty first page is in.
  let release;
  const held = new Promise((r) => { release = r; });
  let c2Seen = false;
  await page.route('**/ui/api/activity**', async (r) => {
    if (byCursor(r.request().url()) === 'c2') {
      c2Seen = true;
      await held;
    }
    return r.fallback();
  });
  await open(page, urls, '/ui/activity/status');
  await page.clock.runFor(100);
  await expect.poll(() => c2Seen).toBe(true);
  await expect(page.locator('#content [data-state="empty"]')).toHaveCount(0);
  release();
  await expect.poll(() => texts(page)).toEqual(TEXT_TWO);
  await expect(page.locator('#content [data-state="empty"]')).toHaveCount(0);
});

test('A13b the empty state comes once the cursor runs out with no rows, and only then', async ({ page }) => {
  const urls = await install(page, { answer: (url) => (byCursor(url) === 'c2' ? list([]) : list([], 'c2')) });
  await open(page, urls, '/ui/activity/status');
  await page.clock.runFor(100);
  await expect(emptyState(page, 'No calls in the last 24 h')).toBeVisible();
  expect(urls.map(byCursor)).toEqual([null, 'c2']);
});

test('A14 a next page that fails keeps the rows, says so, and Retry asks for the same cursor', async ({ page }) => {
  let failNext = true;
  const urls = await install(page, { answer: (url) => (byCursor(url) === 'c2' ? list(PAGE_TWO) : list(PAGE_ONE, 'c2')) });
  // Registered after install, so it runs first: the first c2 request fails, later ones go on to install's handler.
  await page.route('**/ui/api/activity**', (r) => {
    if (byCursor(r.request().url()) === 'c2' && failNext) {
      failNext = false;
      return r.fulfill({ status: 500, json: { error: 'boom' } });
    }
    return r.fallback();
  });
  await open(page, urls, '/ui/activity/status');
  await expect.poll(() => texts(page)).toEqual(TEXT_ONE);
  await reachEnd(page);
  const retry = page.locator('#content').getByRole('button', { name: 'Retry', exact: true });
  await expect(retry).toBeVisible();
  await expect(page.locator('#content')).toContainText('More calls could not be read.');
  await page.clock.runFor(2000);
  await expect.poll(() => page.locator('#announcer').textContent()).toContain('More calls could not be read.');
  expect(await texts(page)).toEqual(TEXT_ONE);
  await retry.click();
  await expect.poll(() => texts(page)).toEqual([...TEXT_ONE, ...TEXT_TWO]);
  expect(urls.filter((u) => byCursor(u) === 'c2')).toHaveLength(1);
  await expect(retry).toHaveCount(0);
});

test('A15 a next page keeps the first page\'s window, though the clock has moved on', async ({ page }) => {
  const urls = await install(page, { answer: (url) => (byCursor(url) === 'c2' ? list(PAGE_TWO) : list(PAGE_ONE, 'c2')) });
  // Page one's answer is held while the clock moves a minute, so page two is asked for a minute later.
  let release;
  const held = new Promise((r) => { release = r; });
  let firstSeen = false;
  await page.route('**/ui/api/activity**', async (r) => {
    if (byCursor(r.request().url()) === null && !firstSeen) {
      firstSeen = true;
      await held;
    }
    return r.fallback();
  });
  await page.goto('/ui/activity/status');
  await shellReady(page);
  await expect.poll(() => firstSeen).toBe(true);
  await page.clock.runFor(60_000);
  release();
  await expect.poll(() => texts(page)).toEqual([...TEXT_ONE, ...TEXT_TWO]);
  expect(urls.filter((u) => byCursor(u) === 'c2')).toHaveLength(1);
  const more = urls.find((u) => byCursor(u) === 'c2');
  expect([filters(more).from, filters(more).to]).toEqual([FROM_24H, TO]);
});

test('A16 an answer that says its cursor was reset replaces the list instead of adding to it', async ({ page }) => {
  const urls = await install(page, {
    answer: (url) => (byCursor(url) === 'c2' ? { rows: PAGE_TWO, next_cursor: null, cursor_reset: true } : list(PAGE_ONE, 'c2')),
  });
  await open(page, urls, '/ui/activity/status');
  await reachEnd(page);
  await expect.poll(() => urls.filter((u) => byCursor(u) === 'c2').length).toBe(1);
  // Only the reset answer's rows: page one's are gone, none twice.
  await expect.poll(() => texts(page)).toEqual(TEXT_TWO);
});

test('A17 a tooltip module that never loads blocks nothing: the list loads and a filter click works', async ({ page }) => {
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  const urls = await install(page, { answer: () => list(ROWS) });
  // Held forever: the screen must not wait for its (i) triggers.
  await page.route('**/ui/assets/tooltip.*.js', () => {});
  await page.goto('/ui/activity/status');
  await expect.poll(() => urls.length).toBeGreaterThan(0);
  await expect.poll(() => shownRows(page)).toHaveLength(5);
  await page.getByRole('button', { name: 'blocked', exact: true }).click();
  await expect.poll(() => filters(urls.at(-1)).outcome).toBe('blocked');
  expect(errors).toEqual([]);
});

test.describe('in Amsterdam', () => {
  test.use({ timezoneId: 'Europe/Amsterdam' });

  test('A19 times are the browser\'s local clock, and a filter change adds no history entry', async ({ page }) => {
    const urls = await install(page, { answer: () => list(ROWS) });
    await open(page, urls, '/ui/activity/status');
    // 08:05:05Z is 09:05:05 in Amsterdam in November (UTC+1).
    await expect.poll(async () => (await texts(page))[0]).toBe('09:05:05 ana create_issue ok');
    const before = await page.evaluate(() => history.length);
    await page.getByRole('button', { name: 'blocked', exact: true }).click();
    await expect.poll(() => filters(urls.at(-1)).outcome).toBe('blocked');
    await expect(page).toHaveURL(/[?&]outcome=blocked/);
    expect(await page.evaluate(() => history.length)).toBe(before);
  });
});

test('A20 a next page says how many calls it added, through the live region', async ({ page }) => {
  const urls = await install(page, { answer: (url) => (byCursor(url) === 'c2' ? list(PAGE_TWO) : list(PAGE_ONE, 'c2')) });
  await open(page, urls, '/ui/activity/status');
  await reachEnd(page);
  await expect.poll(() => texts(page)).toEqual([...TEXT_ONE, ...TEXT_TWO]);
  // The announcer writes after its dwell; the clock is paused.
  await page.clock.runFor(2000);
  await expect.poll(() => page.locator('#announcer').textContent()).toContain('2 more calls.');
});

test('A21 no kind tab is named Firewall: the Outcome filter is the route to blocked calls', async ({ page }) => {
  // Operator decision 2026-11-19: the Firewall kind tab is cut. The premises: the page drew its tabs and its filter.
  const urls = await install(page, { answer: () => list(ROWS) });
  await open(page, urls, '/ui/activity/status');
  await expect(page.getByRole('group', { name: 'Outcome' }).getByRole('button', { name: 'blocked', exact: true })).toBeVisible();
  const tabs = await page.locator('nav.tabs a').allTextContents();
  expect(tabs.length, 'the premise: the page tabs are drawn').toBeGreaterThan(0);
  expect(tabs.filter((t) => /firewall/i.test(t)), tabs.join(', ')).toEqual([]);
  const content = page.locator('#content');
  for (const role of ['tab', 'link', 'button']) {
    await expect(content.getByRole(role, { name: /^firewall/i }), `a ${role} named Firewall`).toHaveCount(0);
  }
});
