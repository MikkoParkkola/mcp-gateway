// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The Overview's flow map: callers, the gateway and servers drawn from the one
// overview read, folded to a fixed number of rows, kept by key across updates.
import { test, expect } from './base.mjs';
import { serve, open, axeRows, tabStops } from './overview.mjs';
import { SMALL, big, flowBody, edge, srv, callers, servers } from './flowmap.mjs';

const map = (page) => page.locator('#content [data-panel="flow-map"]');
const agentRows = (page) => map(page).locator('ol.ov-agents > li');
const serverRows = (page) => map(page).locator('ol.ov-servers > li');
const names = (rows) => rows.locator('.ov-row-name');
const callsOf = (rows) => rows.locator('.ov-row-calls');
/** Open the Overview on `body` and wait for the map. */
async function showMap(page, body, width) {
  await serve(page, { body });
  await open(page, width);
  await expect(map(page).locator('.ov-map')).toHaveCount(1);
}

test.use({ timezoneId: 'UTC', locale: 'en-GB' });

test('M1 the map draws callers, the gateway and servers from the overview read', async ({ page }) => {
  const reads = [];
  page.on('request', (r) => { if (new URL(r.url()).pathname === '/ui/api/overview') reads.push(r.url()); });
  await showMap(page, SMALL);
  await expect(names(agentRows(page))).toHaveText(['alice', 'bob', 's1']);
  await expect(callsOf(agentRows(page))).toHaveText(['120', '80', '40']);
  // A server that is not running comes first, with its state in words.
  await expect(names(serverRows(page))).toHaveText(['jira', 'github', 'stripe', 'linear']);
  await expect(serverRows(page).first()).toContainText('Paused');
  await expect(map(page).locator('svg.ov-lines path')).toHaveCount(7);
  await expect(map(page).locator('svg.ov-lines path.ov-dashed')).toHaveCount(1);
  await expect(map(page).locator('.ov-hub')).toHaveText('4 servers, 12 tools');
  expect(reads).toHaveLength(1);
});

test('M2 140 servers fold to "+N more", and the flows not drawn are said', async ({ page }) => {
  await showMap(page, big());
  await expect(serverRows(page)).toHaveCount(11);
  const fold = serverRows(page).last();
  await expect(fold.locator('.ov-row-name')).toHaveText('+130 more');
  await expect(fold.locator('.ov-row-sub')).toHaveText('124 answering, 6 not answering');
  await expect(fold.locator('a')).toHaveAttribute('href', '/ui/servers/status');
  await expect(agentRows(page)).toHaveCount(6);
  await expect(names(agentRows(page)).last()).toHaveText('+4 more agents');
  await expect(map(page).locator('.ov-map-note')).toHaveText('12 smaller flows with 345 calls are not drawn.');
  // Calls no flow kept are a clause of their own, never added into the flows' calls.
  for (const [overflow, words] of [[7, '12 smaller flows with 345 calls are not drawn, and 7 more calls were not attributed to a flow.'],
    [0, '12 smaller flows with 345 calls are not drawn.']]) {
    const body = big();
    body.edges.more.overflow_calls = overflow;
    await page.unrouteAll({ behavior: 'ignoreErrors' });
    await showMap(page, body);
    await expect(map(page).locator('.ov-map-note'), `${overflow}`).toHaveText(words);
  }
});

test('M3 exactly 11 servers and exactly 6 callers fold nothing', async ({ page }) => {
  await showMap(page, flowBody({ edges: callers(6), servers: servers(11) }));
  await expect(serverRows(page)).toHaveCount(11);
  await expect(agentRows(page)).toHaveCount(6);
  await expect(map(page).locator('.ov-fold')).toHaveCount(0);
});

test('M3b one over: 7 callers and 12 servers fold the rest, and nothing is counted twice or lost', async ({ page }) => {
  const edges = callers(7, (i) => i);
  const rows = [...servers(11), srv('s12', { state: 'paused', calls: 0 })];
  await showMap(page, flowBody({ edges, servers: rows }));
  await expect(agentRows(page)).toHaveCount(6);
  // The fold holds the two smallest callers: 20 + 10 calls, 5 + 6 blocked.
  const agentFold = agentRows(page).last();
  await expect(agentFold.locator('.ov-row-name')).toHaveText('+2 more agents');
  await expect(agentFold.locator('.ov-row-calls')).toHaveText('30');
  await expect(agentFold).toContainText('11 blocked');
  const drawnCalls = (await callsOf(agentRows(page)).allTextContents()).reduce((a, s) => a + Number(s.replace(/,/g, '')), 0);
  expect(drawnCalls).toBe(edges.reduce((a, e) => a + e.calls, 0));
  // The paused server comes first; ten rows, then "+2 more" with their answering counts.
  await expect(serverRows(page)).toHaveCount(11);
  await expect(names(serverRows(page)).first()).toHaveText('s12');
  await expect(names(serverRows(page)).last()).toHaveText('+2 more');
  await expect(serverRows(page).last().locator('.ov-row-sub')).toHaveText('2 answering, 0 not answering');
  const answering = await serverRows(page).evaluateAll((ls) => ls.filter((l) => l.dataset.up === 'true').length);
  expect(answering + 2).toBe(rows.filter((r) => r.up).length);
});

test('M3c a server with no calls number shows none, at the neutral width', async ({ page }) => {
  const rows = [srv('a', { calls: 90 }), srv('b'), srv('c', { calls: null }), srv('d', { calls: 30 })];
  await showMap(page, flowBody({ edges: [edge('key:k', 'a', 5)], servers: rows }));
  await expect(callsOf(serverRows(page))).toHaveText(['90', '', '', '30']);
  const widths = await map(page).locator('svg.ov-lines path[data-side="servers"]').evaluateAll((ps) => ps.map((p) => p.getAttribute('stroke-width')));
  expect(widths[1]).toBe('1');
  expect(widths[2]).toBe('1');
  expect(Number(widths[0])).toBeGreaterThan(Number(widths[3]));
  await expect(map(page)).not.toContainText('undefined');
  await expect(map(page)).not.toContainText('NaN');
  // The fold row of a fleet past 11 has no calls number and the neutral width too.
  await page.unrouteAll({ behavior: 'ignoreErrors' });
  await showMap(page, big());
  await expect(serverRows(page).last().locator('.ov-row-calls')).toHaveText('');
  expect(await map(page).locator('svg.ov-lines path[data-side="servers"]').last().getAttribute('stroke-width')).toBe('1');
});

test('O1 the map takes its place in the one panel order', async ({ page }) => {
  await showMap(page, SMALL);
  const order = await page.locator('#content .ov > [data-panel]').evaluateAll((ss) => ss.map((s) => s.dataset.panel));
  expect(order.filter((p) => ['kpis', 'flow-map', 'needs-you', 'calls-chart'].includes(p))).toEqual(['kpis', 'flow-map', 'needs-you', 'calls-chart']);
});

/** The DOM order of the two lists inside the map. */
const listOrder = (page) => map(page).locator('.ov-map > ol').evaluateAll((ls) => ls.map((l) => l.className));

test('M4 ranked lists on a phone: servers first on screen, in the page and in the Tab order', async ({ page }) => {
  await showMap(page, SMALL, 390);
  await expect(map(page).locator('svg.ov-lines')).toBeHidden();
  await expect(map(page).locator('.ov-hub')).toBeHidden();
  await expect.poll(() => listOrder(page)).toEqual(['ov-servers', 'ov-agents']);
  const top = (l) => l.evaluate((e) => e.getBoundingClientRect().top);
  expect(await top(map(page).locator('ol.ov-servers'))).toBeLessThan(await top(map(page).locator('ol.ov-agents')));
  // Tab from the map's heading: a server's link comes before a caller's.
  const stops = [];
  await map(page).locator('h2').evaluate((e) => { e.tabIndex = -1; e.focus(); });
  stops.push(...await tabStops(page, 6));
  const firstServer = stops.findIndex((s) => s.startsWith('/ui/servers/'));
  const firstCaller = stops.findIndex((s) => s.startsWith('/ui/activity/'));
  expect(firstServer).toBeGreaterThanOrEqual(0);
  expect(firstCaller === -1 || firstServer < firstCaller).toBe(true);
  // Across the breakpoint both ways every row keeps its node, once, in the same ranking.
  await map(page).locator('li.ov-row').evaluateAll((ls) => ls.forEach((l, i) => { l.dataset.probe = String(i); }));
  for (const width of [1440, 390, 1440]) {
    await page.setViewportSize({ width, height: 1100 });
    await expect.poll(() => listOrder(page), `${width}`).toEqual(width < 640 ? ['ov-servers', 'ov-agents'] : ['ov-agents', 'ov-servers']);
    await expect(map(page).locator('li.ov-row[data-probe]'), `${width}`).toHaveCount(7);
    await expect(names(agentRows(page))).toHaveText(['alice', 'bob', 's1']);
    await expect(names(serverRows(page))).toHaveText(['jira', 'github', 'stripe', 'linear']);
  }
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  // A blocked caller's dot reads as words in its own row on a phone, inside that row's box.
  await page.unrouteAll({ behavior: 'ignoreErrors' });
  await showMap(page, WITH_DOT, 390);
  const dot = dotOf(page, 'x');
  await expect(dot).toBeVisible();
  await expect(dot).toHaveText('2 blocked');
  const inRow = await dot.evaluate((d) => { const a = d.getBoundingClientRect(); const b = d.closest('li').getBoundingClientRect(); return a.left >= b.left && a.right <= b.right && a.top >= b.top && a.bottom <= b.bottom; });
  expect(inRow).toBe(true);
});

test('S1 states: not counted, first run, calls not attributed, twin names, markup as text', async ({ page }) => {
  const words = (page) => map(page).locator('.ov-map-empty');
  const say = async (body, text) => {
    await page.unrouteAll({ behavior: 'ignoreErrors' });
    await serve(page, { body });
    await open(page);
    await expect(words(page)).toHaveText(text);
    await expect(map(page).locator('.ov-map')).toBeHidden();
  };
  const noEdges = flowBody({ servers: [srv('a')] });
  delete noEdges.edges;
  await say(noEdges, 'Not available yet');
  await say(flowBody({ servers: [srv('a')] }), 'The live map appears here after the first call.');
  await say(flowBody({ servers: [srv('a')], edgesMore: { count: 0, calls: 0, overflow_calls: 5 } }), '5 calls were not attributed to a flow.');
  // Two servers whose served names are equal (a clipped 256-byte prefix) stay two rows across an update.
  const twin = 'x'.repeat(256);
  await page.unrouteAll({ behavior: 'ignoreErrors' });
  await showMap(page, flowBody({ edges: [edge('key:k', twin, 3)], servers: [srv(twin, { calls: 2 }), srv(twin, { calls: 1 })] }));
  await expect(serverRows(page)).toHaveCount(2);
  // A caller name with markup reads as text.
  await page.unrouteAll({ behavior: 'ignoreErrors' });
  await showMap(page, flowBody({ edges: [edge('key:<img src=x>', 'a', 3)], servers: [srv('a')] }));
  await expect(names(agentRows(page))).toHaveText('<img src=x>');
  await expect(map(page).locator('img')).toHaveCount(0);
});

const dotOf = (page, name) => agentRows(page).filter({ has: page.locator('.ov-row-name', { hasText: name }) }).locator('.ov-dot');
/** A query's parameters as [name, value] pairs. */
const paramsOf = (href) => [...new URL(href, 'http://x').searchParams];

test('D1 a dot only on callers with blocked calls, linking to their calls by account', async ({ page }) => {
  await showMap(page, flowBody({ edges: [edge('key:a1', 's', 30, 0), edge('key:b2', 's', 20, 3), edge('key:c3', 's', 10, 0)], servers: [srv('s')] }));
  await expect(map(page).locator('a.ov-dot:visible')).toHaveCount(1);
  const dot = dotOf(page, 'b2');
  await expect(dot).toHaveAccessibleName('3 blocked');
  await expect(dot).toHaveAttribute('href', '/ui/activity/status?key=b2');

  // Every caller form: four kinds carry an account, the rest (and cut labels) read as text.
  const cut = (prefix, fill, size) => `${prefix}${fill.repeat(Math.ceil((size - prefix.length - 9) / new TextEncoder().encode(fill).length))}`;
  const label128 = (() => { let s = cut('key:', 'a', 128); while (new TextEncoder().encode(`${s}~0123abcd`).length > 128) s = s.slice(0, -1); return `${s}~0123abcd`; })();
  const label126 = (() => { let s = cut('key:a', 'é', 126); while (new TextEncoder().encode(`${s}~0123abcd`).length > 126) s = s.slice(0, -1); return `${s}~0123abcd`; })();
  const plain128 = 'key:' + 'b'.repeat(124);
  // The cut cases at their exact sizes (one ASCII byte evens out the two-byte characters).
  for (const [label, size] of [[label128, 128], [label126, 126], [plain128, 128]]) expect(new TextEncoder().encode(label).length).toBe(size);
  const forms = ['oidc:u1', 'session:s1', 'token:t1', 'bearer', 'local', 'anonymous', 'key:', label128, label126, plain128, 'key:a&b#c%d é', 'key:alice', 'oidc:alice'];
  await page.unrouteAll({ behavior: 'ignoreErrors' });
  await showMap(page, flowBody({ edges: forms.slice(0, 6).map((f, i) => edge(f, 's', 60 - i, 1)), servers: [srv('s')] }));
  for (const [i, account] of [[0, 'u1'], [1, 's1'], [2, 't1']]) {
    expect(paramsOf(await agentRows(page).nth(i).locator('a.ov-dot').getAttribute('href'))).toEqual([['key', account]]);
  }
  for (const i of [3, 4, 5]) {
    await expect(agentRows(page).nth(i).locator('a.ov-dot')).toHaveCount(0);
    await expect(agentRows(page).nth(i).locator('.ov-dot')).toHaveText('1 blocked');
  }
  await page.unrouteAll({ behavior: 'ignoreErrors' });
  await showMap(page, flowBody({ edges: forms.slice(6, 10).map((f, i) => edge(f, 's', 60 - i, 1)), servers: [srv('s')] }));
  await expect(agentRows(page).nth(0).locator('a.ov-dot')).toHaveCount(0); // key: with an empty account
  await expect(agentRows(page).nth(1).locator('a.ov-dot')).toHaveCount(0); // cut, 128 bytes
  await expect(agentRows(page).nth(2).locator('a.ov-dot')).toHaveCount(0); // cut, 126 bytes of two-byte characters
  expect(paramsOf(await agentRows(page).nth(3).locator('a.ov-dot').getAttribute('href'))).toEqual([['key', 'b'.repeat(124)]]);
  // An account with &, #, % and a space is one value of one parameter; two kinds named alice each get a dot.
  await page.unrouteAll({ behavior: 'ignoreErrors' });
  await showMap(page, flowBody({ edges: forms.slice(10).map((f, i) => edge(f, 's', 60 - i, i + 1)), servers: [srv('s')] }));
  expect(paramsOf(await agentRows(page).nth(0).locator('a.ov-dot').getAttribute('href'))).toEqual([['key', 'a&b#c%d é']]);
  await expect(agentRows(page).nth(1).locator('a.ov-dot')).toHaveText('2 blocked');
  await expect(agentRows(page).nth(2).locator('a.ov-dot')).toHaveText('3 blocked');
  for (const i of [1, 2]) expect(paramsOf(await agentRows(page).nth(i).locator('a.ov-dot').getAttribute('href'))).toEqual([['key', 'alice']]);
  // A fold row's blocked calls are text, never a link.
  await page.unrouteAll({ behavior: 'ignoreErrors' });
  await showMap(page, flowBody({ edges: callers(8, (i) => (i > 5 ? 2 : 0)), servers: [srv('github')] }));
  await expect(agentRows(page).last().locator('.ov-dot')).toHaveText('4 blocked');
  await expect(agentRows(page).last().locator('a')).toHaveCount(0);
  // A caller named a"]b\c keeps its row across two reads (its probe survives).
  await page.unrouteAll({ behavior: 'ignoreErrors' });
  const odd = (calls) => flowBody({ edges: [edge('key:a"]b\\c', 's', calls, 1)], servers: [srv('s')] });
  const live = await liveMap(page, odd(9));
  await probe(page);
  live.body = odd(12);
  await readAgain(page, live, 2);
  await expect(callsOf(agentRows(page))).toHaveText(['12']);
  expect(await probes(agentRows(page))).toEqual(['a"]b\\c']);
});

for (const width of [1440, 390]) test(`D2 the dot is 44 px under a coarse pointer, ${width} px`, async ({ browser }) => {
  const context = await browser.newContext({ hasTouch: true, viewport: { width, height: 1100 } });
  const page = await context.newPage();
  expect(await page.evaluate(() => matchMedia('(pointer: coarse)').matches), 'a coarse pointer in this context').toBe(true);
  await serve(page, { body: flowBody({ edges: [edge('key:b2', 's', 20, 3)], servers: [srv('s')] }) });
  await open(page, width);
  const box = await map(page).locator('a.ov-dot').boundingBox();
  expect(box.width).toBeGreaterThanOrEqual(44);
  expect(box.height).toBeGreaterThanOrEqual(44);
  // The target is 44 px (its padding inside it, so the painted dot stays small) and clears its row's number.
  // Wide the dot is a dot, so its target is 44 px; narrow it is words, as wide as they are.
  if (width >= 640) expect(box.width, 'a 44 px target').toBeLessThanOrEqual(46);
  const calls = await map(page).locator('.ov-row-calls').first().boundingBox();
  expect(box.x, 'the target starts after its row\'s number').toBeGreaterThanOrEqual(calls.x + calls.width);
  await context.close();
});

test('D3 following the dot opens that caller in Activity without a page load', async ({ page }) => {
  for (const [label, account] of [['key:k1', 'k1'], ['oidc:o1', 'o1'], ['session:s1', 's1'], ['token:t1', 't1']]) {
    await page.unrouteAll({ behavior: 'ignoreErrors' });
    const asked = [];
    await page.route('**/ui/api/activity**', (r) => { asked.push(new URL(r.request().url())); return r.fulfill({ json: { rows: [], complete: true } }); });
    await showMap(page, flowBody({ edges: [edge(label, 's', 20, 3)], servers: [srv('s')] }));
    await page.evaluate(() => { window.__sameDocument = true; });
    await map(page).locator('a.ov-dot').click();
    await expect(page).toHaveURL(new RegExp(`/ui/activity/status\\?key=${account}$`));
    await expect.poll(() => asked.length, label).toBeGreaterThan(0);
    expect(asked.at(-1).searchParams.get('caller'), label).toBe(account);
    expect(asked.at(-1).searchParams.has('outcome'), label).toBe(false);
    expect(await page.evaluate(() => window.__sameDocument), `${label}: no full page load`).toBe(true);
  }
});

const T0 = Date.UTC(2026, 10, 19, 14, 0);
/**
 * Open the Overview on a paused clock with an overview read the row can change and hold: `live.body`
 * is answered, `live.hold` (a promise) delays the answer, `live.status` answers that status instead.
 * `live.reads` counts overview reads.
 */
async function liveMap(page, body) {
  const live = { body, hold: null, status: 0, reads: 0 };
  await page.clock.install({ time: T0 - 60_000 });
  await page.clock.pauseAt(T0);
  await serve(page, { body });
  await page.route('**/ui/api/overview', async (r) => {
    live.reads += 1;
    if (live.hold) await live.hold;
    return live.status ? r.fulfill({ status: live.status, json: { error: 'no' } }) : r.fulfill({ json: live.body });
  });
  await open(page);
  await expect(map(page).locator('.ov-map')).toHaveCount(1);
  return live;
}
const fire = (page, name = 'gateway-status') => page.evaluate((e) => dispatchEvent(new CustomEvent(e)), name);
/** A status event, then the paused clock runs on until the overview has been read `n` times. */
async function readAgain(page, live, n, name) {
  await fire(page, name);
  await expect.poll(async () => { await page.clock.runFor(300); return live.reads; }).toBe(n);
}
const probe = (page) => map(page).locator('li.ov-row').evaluateAll((ls) => ls.forEach((l) => { l.dataset.probe = l.querySelector('.ov-row-name').textContent; }));
const probes = (rows) => rows.evaluateAll((ls) => ls.map((l) => l.dataset.probe ?? ''));

test('L1 a status event re-reads once and updates the rows in place', async ({ page }) => {
  const live = await liveMap(page, SMALL);
  await probe(page);
  live.body = flowBody({ edges: [edge('key:alice', 'github', 300), edge('oidc:bob', 'github', 80), edge('session:s1', 'linear', 40)], servers: SMALL.servers.rows, kpi: { servers_total: 5, tools_total: 20 } });
  await fire(page);
  await page.clock.runFor(50);
  await fire(page);
  await page.clock.runFor(1100);
  await expect(callsOf(agentRows(page)).first()).toHaveText('300');
  await expect(map(page).locator('.ov-hub')).toHaveText('5 servers, 20 tools');
  expect(live.reads).toBe(2);
  expect(await probes(map(page).locator('li.ov-row'))).not.toContain('');
  // One caller gone and one new: that row's nodes go, one comes, the others keep theirs.
  live.body = flowBody({ edges: [edge('key:alice', 'github', 300), edge('oidc:bob', 'github', 80), edge('token:new', 'linear', 40)], servers: SMALL.servers.rows });
  await fire(page);
  await page.clock.runFor(1100);
  await expect(names(agentRows(page))).toHaveText(['alice', 'bob', 'new']);
  expect(await probes(agentRows(page))).toEqual(['alice', 'bob', '']);
  // Ranks swap and a running server pauses: the same nodes move to their new places.
  live.body = flowBody({ edges: [edge('key:alice', 'github', 10), edge('oidc:bob', 'github', 80), edge('token:new', 'linear', 40)],
    servers: [srv('github', { state: 'paused', calls: 150 }), srv('stripe', { calls: 50 }), srv('linear', { calls: 40 }), srv('jira', { state: 'paused', calls: 0 })] });
  await fire(page);
  await page.clock.runFor(1100);
  await expect(names(agentRows(page))).toHaveText(['bob', 'new', 'alice']);
  expect(await probes(agentRows(page))).toEqual(['bob', '', 'alice']);
  expect(await probes(serverRows(page))).toEqual(['github', 'jira', 'stripe', 'linear']);
  // A dot comes when a caller's blocks go from 0 to 2 and goes when they return to 0.
  live.body = flowBody({ edges: [edge('key:alice', 'github', 10, 2), edge('oidc:bob', 'github', 80)], servers: SMALL.servers.rows });
  await fire(page);
  await page.clock.runFor(1100);
  await expect(dotOf(page, 'alice')).toHaveText('2 blocked');
  live.body = flowBody({ edges: [edge('key:alice', 'github', 10, 0), edge('oidc:bob', 'github', 80)], servers: SMALL.servers.rows });
  await fire(page);
  await page.clock.runFor(1100);
  await expect(map(page).locator('.ov-dot:visible')).toHaveCount(0);
  // The stream's reload event reads again too.
  await readAgain(page, live, live.reads + 1, 'gateway-reload');
});

test('L1c steady events do not put the read off for ever', async ({ page }) => {
  // Each overview fetch is stamped with the page's (paused) clock, so the timing is the page's own.
  await page.addInitScript(() => {
    window.__reads = [];
    const real = window.fetch;
    window.fetch = (input, init) => {
      if (new URL(typeof input === 'string' ? input : input.url, location.href).pathname === '/ui/api/overview') window.__reads.push(Date.now());
      return real(input, init);
    };
  });
  await liveMap(page, SMALL);
  const start = await page.evaluate(() => Date.now());
  for (let ms = 0; ms <= 3000; ms += 200) {
    await fire(page);
    await page.clock.runFor(200);
  }
  const reads = await page.evaluate(() => window.__reads);
  const again = reads.slice(1);
  expect(again.length, 'a re-read starts while events still arrive').toBeGreaterThan(0);
  expect(again[0] - start).toBeLessThanOrEqual(1200);
  expect(again.length).toBeLessThanOrEqual(3);
});

test('L1b one read at a time', async ({ page }) => {
  const live = await liveMap(page, SMALL);
  let release;
  live.hold = new Promise((r) => { release = r; });
  await fire(page);
  await page.clock.runFor(1100);
  await expect.poll(() => live.reads).toBe(2);
  for (let i = 0; i < 3; i += 1) { await fire(page); await page.clock.runFor(1100); }
  expect(live.reads).toBe(2);
  live.hold = null;
  release();
  // The held answer lands in real time; the clock runs on until the one waiting read goes out.
  await expect.poll(async () => { await page.clock.runFor(300); return live.reads; }).toBe(3);
  await page.clock.runFor(2500);
  expect(live.reads).toBe(3);
});

test('L2 once the map has left the page, its reads stop', async ({ page }) => {
  const thrown = [];
  page.on('pageerror', (e) => thrown.push(e.message));
  const leave = () => page.evaluate(() => document.querySelector('#content [data-panel="flow-map"]').remove());
  // Left with the timer running.
  const live = await liveMap(page, SMALL);
  // Counted in the page as each read is asked for: the paused clock fires the timer inside runFor,
  // and a read started there may not reach the route before the count below is taken.
  await page.evaluate(() => {
    window.__asked = 0;
    const real = window.fetch;
    window.fetch = (req, ...rest) => {
      if (new URL(req.url ?? req, location.href).pathname === '/ui/api/overview') window.__asked += 1;
      return real(req, ...rest);
    };
  });
  await fire(page);
  await leave();
  await page.clock.runFor(2500);
  expect(await page.evaluate(() => window.__asked)).toBe(0);
  expect(live.reads).toBe(1);
  expect(thrown).toEqual([]);
});

test('L2b a read answered after the map left changes nothing', async ({ page }) => {
  const thrown = [];
  page.on('pageerror', (e) => thrown.push(e.message));
  const held = await liveMap(page, SMALL);
  let release;
  held.hold = new Promise((r) => { release = r; });
  await readAgain(page, held, 2);
  await page.evaluate(() => document.querySelector('#content [data-panel="flow-map"]').remove());
  release();
  await page.clock.runFor(2500);
  expect(held.reads).toBe(2);
  await expect(map(page)).toHaveCount(0);
  expect(thrown).toEqual([]);
});

test('L3 a failed re-read says so under the map, and the next good one clears it', async ({ page }) => {
  const live = await liveMap(page, SMALL);
  live.status = 500;
  await readAgain(page, live, 2);
  await expect(map(page).locator('.ov-map-stale')).toHaveText('Not updated since 14:00');
  // Said when it happens, without moving focus.
  await expect(map(page).locator('.ov-map-stale')).toHaveAttribute('role', 'status');
  await expect(map(page).locator('.ov-map-stale')).toBeVisible();
  await expect(callsOf(agentRows(page))).toHaveText(['120', '80', '40']);
  live.status = 0;
  await readAgain(page, live, 3);
  await expect(map(page).locator('.ov-map-stale')).toBeHidden();
});

test('S1b two servers with one served name stay two rows across an update', async ({ page }) => {
  const twin = 'x'.repeat(256);
  const body = (a, b) => flowBody({ edges: [edge('key:k', twin, 3)], servers: [srv(twin, { calls: a }), srv(twin, { calls: b })] });
  const live = await liveMap(page, body(2, 1));
  await serverRows(page).evaluateAll((ls) => ls.forEach((l, i) => { l.dataset.probe = String(i); }));
  live.body = body(5, 4);
  await readAgain(page, live, 2);
  await expect(callsOf(serverRows(page))).toHaveText(['5', '4']);
  expect(await probes(serverRows(page))).toEqual(['0', '1']);
});

/** Callers c1..cN, each with `blocks(i)` blocked calls. */
const blocked = (count, blocks) => flowBody({ edges: callers(count, blocks).map((e, i) => ({ ...e, caller: `key:d${i}` })), servers: [srv('github')] });

test('R1 nothing moves with reduced motion, and at most three dots pulse at once', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  const still = await liveMap(page, blocked(5, () => 0));
  await map(page).evaluate((card) => {
    window.__moved = 0;
    for (const t of ['animationstart', 'transitionrun']) card.addEventListener(t, () => { window.__moved += 1; });
  });
  still.body = blocked(5, (i) => (i === 0 ? 2 : 0));
  still.body.edges.rows[1].calls = 1;
  await readAgain(page, still, 2);
  await expect(map(page).locator('.ov-dot:visible')).toHaveCount(1);
  // The rule itself, read from the computed style: motion events alone can miss a pulse or a line.
  expect(await map(page).evaluate((card) => ({
    pulse: getComputedStyle(card.querySelector('.ov-dot.ov-pulse') ?? card.querySelector('.ov-dot:not(.ov-dot-off)'), '::before').animationName,
    line: getComputedStyle(card.querySelector('svg.ov-lines path')).transitionProperty,
  }))).toEqual({ pulse: 'none', line: 'none' });
  await page.clock.runFor(500);
  expect(await page.evaluate(() => ({ moved: window.__moved, running: document.getAnimations().length }))).toEqual({ moved: 0, running: 0 });

  // Without it: five new dots, at most three pulse, each pulse a finite animation; three more a second
  // later still leave at most three pulsing.
  await page.emulateMedia({ reducedMotion: 'no-preference' });
  still.body = blocked(6, (i) => (i < 5 ? 1 : 0));
  await readAgain(page, still, 3);
  await expect(map(page).locator('.ov-dot:visible')).toHaveCount(5);
  const pulsing = () => map(page).locator('.ov-pulse').count();
  expect(await pulsing()).toBeLessThanOrEqual(3);
  expect(await map(page).locator('.ov-pulse').first().evaluate((d) => getComputedStyle(d, '::before').animationIterationCount)).not.toBe('infinite');
  await page.clock.runFor(1000);
  still.body = blocked(9, () => 1);
  await readAgain(page, still, 4);
  expect(await pulsing()).toBeLessThanOrEqual(3);
});

/** The small map plus one caller with blocked calls, so a dot is in every audit and Tab row. */
const WITH_DOT = flowBody({ edges: [...SMALL.edges.rows, edge('key:x', 'github', 5, 2)], servers: SMALL.servers.rows });
axeRows('A1 axe on the flow map', (page, width) => showMap(page, WITH_DOT, width));

test('Z1 a long server name at 200% text is cut, kept whole in its title, and overlaps nothing', async ({ page }) => {
  const long = `${'very-long-server-name-'.repeat(14)}end`;
  await page.addInitScript(() => addEventListener('DOMContentLoaded', () => { document.documentElement.style.fontSize = '200%'; }));
  await showMap(page, flowBody({ edges: [edge('key:k', long, 3)], servers: [srv(long, { calls: 1234 }), srv('b', { calls: 5 })] }));
  const row = serverRows(page).first();
  await expect(row.locator('.ov-row-name')).toHaveAttribute('title', long);
  const fit = await row.evaluate((li) => {
    const [name, sub, calls] = ['.ov-row-name', '.ov-row-sub', '.ov-row-calls'].map((s) => li.querySelector(s));
    const r = (e) => e.getBoundingClientRect();
    const apart = (a, b) => r(a).right <= r(b).left || r(b).right <= r(a).left || r(a).bottom <= r(b).top || r(b).bottom <= r(a).top;
    const box = r(li.querySelector('.ov-row-go'));
    return {
      cut: name.scrollWidth > name.clientWidth,
      apart: apart(name, calls) && apart(sub, calls) && apart(name, sub),
      inside: [name, sub, calls].every((e) => r(e).top >= box.top - 1 && r(e).bottom <= box.bottom + 1),
    };
  });
  expect(fit).toEqual({ cut: true, apart: true, inside: true });
});

test('A2 Tab reaches every row link and dot of the map, in page order', async ({ page }) => {
  await showMap(page, WITH_DOT);
  const links = await map(page).locator('a:visible').evaluateAll((as) => as.map((a) => a.getAttribute('href')));
  expect(links.length).toBeGreaterThan(5);
  await map(page).locator('h2').evaluate((e) => { e.tabIndex = -1; e.focus(); });
  expect(await tabStops(page, links.length)).toEqual(links);
});

const LONE = flowBody({ edges: [edge('key:x', 'github', 5, 2)], servers: [srv('github')] });
for (const [where, body, width] of [['a low row', WITH_DOT, 1440], ['a lone caller, level with the hub', LONE, 1440], ['a lone caller at the narrowest wide layout', LONE, 700]]) test(`G1 on a wide screen the dot sits on its line's midpoint, covered by nothing and overlapping nothing: ${where}`, async ({ page }) => {
  await showMap(page, body, width);
  const off = await map(page).locator('.ov-map').evaluate((box) => {
    const rows = [...box.querySelectorAll('ol.ov-agents > li')];
    const i = rows.findIndex((li) => li.querySelector('.ov-dot:not(.ov-dot-off)'));
    const dot = rows[i].querySelector('.ov-dot');
    // A low row can sit below the window, where nothing is hit: brought into view before measuring.
    dot.scrollIntoView({ block: 'center' });
    const m = box.getBoundingClientRect();
    const d = dot.getBoundingClientRect();
    const y = ((i + 0.5) / rows.length) * 100;
    const cx = d.left + d.width / 2;
    const cy = d.top + d.height / 2;
    // The line's midpoint (spec): x halfway from the callers' edge (37.5) to the hub (50), y halfway to 50.
    return { x: cx - (m.left + m.width * 0.4375), y: cy - (m.top + (m.height * (y + 50)) / 200), top: document.elementFromPoint(cx, cy)?.closest('.ov-dot') === dot,
      // The dot's whole box, not only its centre, stays off the hub and off its row's number.
      clear: [box.querySelector('.ov-hub'), rows[i].querySelector('.ov-row-calls')].every((e) => {
        const r = e.getBoundingClientRect();
        return r.right <= d.left || r.left >= d.right || r.bottom <= d.top || r.top >= d.bottom;
      }) };
  });
  expect(Math.abs(off.x), 'across').toBeLessThanOrEqual(2);
  expect(Math.abs(off.y), 'down').toBeLessThanOrEqual(2);
  expect(off.top, 'nothing covers the dot').toBe(true);
  expect(off.clear, 'the dot overlaps neither the hub nor its row\'s number').toBe(true);
});

test('G2 no line is wider than 8 px, the callers fold row included', async ({ page }) => {
  await showMap(page, big());
  const widths = await map(page).locator('svg.ov-lines path[data-side="agents"]').evaluateAll((ps) => ps.map((p) => Number(p.getAttribute('stroke-width'))));
  expect(widths).toHaveLength(6);
  expect(Math.max(...widths)).toBe(8);
  expect(Math.min(...widths)).toBeGreaterThanOrEqual(1);
});

test('G3 a caller that arrives with blocked calls pulses', async ({ page }) => {
  const live = await liveMap(page, SMALL);
  live.body = flowBody({ edges: [...SMALL.edges.rows, edge('key:new', 'github', 200, 3)], servers: SMALL.servers.rows });
  await readAgain(page, live, 2);
  await expect(names(agentRows(page)).first()).toHaveText('new');
  await expect(agentRows(page).first().locator('.ov-dot')).toHaveClass(/ov-pulse/);
});

test('G4 a focused row keeps focus when an update moves it', async ({ page }) => {
  const live = await liveMap(page, SMALL);
  await agentRows(page).nth(2).locator('a.ov-row-go').focus();
  live.body = flowBody({ edges: [...SMALL.edges.rows.filter((e) => e.caller !== 'session:s1'), edge('session:s1', 'linear', 500)], servers: SMALL.servers.rows });
  await readAgain(page, live, 2);
  await expect(names(agentRows(page)).first()).toHaveText('s1');
  await expect(agentRows(page).first().locator('a.ov-row-go')).toBeFocused();
});

// Wide, the dot's padding is its target (axe alone passes a small dot with room around it); narrow, its words.
for (const width of [390, 1440]) test(`G5 with a mouse the dot is still a 24 px target, ${width} px`, async ({ page }) => {
  await showMap(page, WITH_DOT, width);
  const box = await map(page).locator('a.ov-dot:visible').boundingBox();
  expect(box.height).toBeGreaterThanOrEqual(24);
  expect(box.width).toBeGreaterThanOrEqual(24);
});
