// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The Overview's six KPI tiles (design: the tiles slice of the Overview), at
// 1440 and 390 px. Every read is answered here, with small literal bodies, so
// each expected value in a row is written out, never computed from a fixture.
import { test, expect } from './base.mjs';

const H = (hh, mm = 0) => Date.UTC(2026, 10, 19, hh, mm) / 1000;

/** The overview body: every field the tiles read, with a slowest server named. */
function overview(over = {}) {
  return {
    kpi: {
      servers_total: 28, servers_up: 24, tools_total: 1284, uptime_secs: 3600, version: '4.0.0',
      calls_24h: 4812, calls_prev_24h: 4415, blocks_24h: 3, blocks_prev_24h: 1, errors_24h: 0, errors_prev_24h: 0,
      counting_since: H(9, 15),
      ...over.kpi,
    },
    latency: 'latency' in over ? over.latency : {
      from: H(14), to: H(15),
      servers: [{ name: 'kubernetes', p95_ms: 2100, calls: 12 }, { name: 'github', p95_ms: 1900, calls: 300 }],
      more: { count: 0 },
      slowest: { name: 'github', p95_ms: 1900, calls: 300 },
    },
    ...('degraded' in over ? { degraded: over.degraded } : {}),
  };
}

// Four half-hour buckets; the last is in progress and left out of the cache sums.
const T = [H(13), H(13, 30), H(14), H(14, 30)];
const points = (vs) => vs.map((v, i) => ({ t: T[i], v }));
/** A series body as GET /ui/api/metrics/series answers it. */
const series = (metric, vs) => ({
  metric, window: '24h', bucket_secs: 1800, day_basis: null, zone: 'UTC', since: T[0], folded: false,
  points: points(vs), previous: points(vs.map(() => 0)), previous_complete: true,
});
const SERIES = {
  calls: series('calls', [100, 200, 0, 50]),
  blocks: series('blocks', [1, 0, 2, 0]),
  cache_hits: series('cache_hits', [10, 50, 0, 40]),
};

/**
 * Answer the overview and the three series reads. `reads` maps a metric to a body, a status
 * number, 'abort' (a network failure) or a promise that settles with one of those (a held read).
 */
async function serve(page, { body = overview(), reads = {} } = {}) {
  await page.route('**/ui/api/status', (r) => r.fulfill({ json: { auth: { enabled: true, signed_in: true, admin: true } } }));
  await page.route('**/ui/api/overview', (r) => r.fulfill({ json: body }));
  await page.route('**/ui/api/metrics/series**', async (r) => {
    const metric = new URL(r.request().url()).searchParams.get('metric');
    const given = await (reads[metric] ?? SERIES[metric]);
    if (given === 'abort') return r.abort('failed');
    if (typeof given === 'number') return r.fulfill({ status: given, json: { error: 'no' } });
    return r.fulfill({ json: given });
  });
}

/** Open the Overview at `width` and wait for the tiles' first paint. */
async function open(page, width = 1440) {
  await page.setViewportSize({ width, height: width < 640 ? 844 : 1100 });
  await page.goto('/ui/overview/status');
  await expect(page.locator('#content [data-overview-painted]')).toHaveCount(1);
}

const tile = (page, id) => page.locator(`#content [data-tile="${id}"]`);
const num = (page, id) => tile(page, id).locator('.ov-num');
const ctx = (page, id) => tile(page, id).locator('.ov-ctx');
const link = (page, id) => tile(page, id).locator('a.ov-go');

test.use({ timezoneId: 'UTC', locale: 'en-GB' });

// [tile, label, value, context, href or null]
const TILES = [
  ['calls', 'Calls, last 24 h', '4,812', '↗ 9% vs the 24 h before', '/ui/activity/status'],
  ['blocks', 'Firewall, last 24 h', '3', '↗ 2 more than the 24 h before', '/ui/activity/status?outcome=blocked'],
  ['cache', 'From cache, last 24 h', '20%', '60 of 300 calls', null],
  ['p95', 'Slowest 5%, last hour', '1.9 s', 'github, slowest 14:00–15:00 (300 calls)', '/ui/servers/github/status'],
  ['tools', 'Tools available', '1,284', 'across 28 servers', '/ui/tools/status'],
  ['spend', 'Spend', 'Not available yet', '', null],
];

test('T1 each tile shows its value, context and link; only From cache and Spend have none', async ({ page }) => {
  await serve(page);
  await open(page);
  for (const [id, label, value, context, href] of TILES) {
    await expect(tile(page, id).locator('.ov-label'), id).toHaveText(label);
    await expect(num(page, id), id).toHaveText(value);
    await expect(ctx(page, id), id).toHaveText(context);
    if (href) await expect(link(page, id), id).toHaveAttribute('href', href);
    else await expect(link(page, id), id).toHaveCount(0);
  }
  await expect(page.locator('#content [data-tile] a.ov-go')).toHaveCount(4);
  // A value with a unit is a figure, not a sentence: it keeps the large number style.
  await expect(num(page, 'p95')).not.toHaveClass(/ov-words/);
  await expect(num(page, 'spend')).toHaveClass(/ov-words/);
});

test('T1 with no slowest server named, the Slowest 5% tile has no link either', async ({ page }) => {
  await serve(page, { body: overview({ latency: { from: H(14), to: H(15), servers: [{ name: 'kubernetes', p95_ms: 2100, calls: 12 }], more: { count: 0 }, slowest: null } }) });
  await open(page);
  await expect(link(page, 'p95')).toHaveCount(0);
  await expect(page.locator('#content [data-tile] a.ov-go')).toHaveCount(3);
});

test('T2 comparison words: up, down, same, none before, counting since', async ({ page }) => {
  const cases = [
    [{ calls_24h: 4000, calls_prev_24h: 5000 }, 'calls', '↘ 20% vs the 24 h before'],
    [{ calls_24h: 100, calls_prev_24h: 100 }, 'calls', 'same as the 24 h before'],
    [{ calls_24h: 5, calls_prev_24h: 0 }, 'calls', 'none the 24 h before'],
    [{ calls_24h: 5, calls_prev_24h: undefined }, 'calls', 'counting since 19 Nov, 09:15'],
    [{ blocks_24h: 1, blocks_prev_24h: 3 }, 'blocks', '↘ 2 fewer than the 24 h before'],
  ];
  for (const [kpi, id, words] of cases) {
    await page.unrouteAll();
    await serve(page, { body: overview({ kpi }) });
    await open(page);
    await expect(ctx(page, id), JSON.stringify(kpi)).toHaveText(words);
  }
});

test('T3 the Slowest 5% tile in each latency state', async ({ page }) => {
  const lat = (slowest, servers = [{ name: 'github', p95_ms: 340, calls: 300 }]) => ({ from: H(14), to: H(15), servers, more: { count: 0 }, slowest });
  const cases = [
    [{ latency: lat({ name: 'github', p95_ms: 340, calls: 300 }) }, '340 ms', 'github, slowest 14:00–15:00 (300 calls)'],
    [{ latency: lat(null) }, 'Not enough calls yet', 'a server needs 21 timed calls in an hour to be named'],
    [{ latency: lat(null, []) }, 'No timed calls in the last hour', ''],
    [{ latency: undefined }, 'Not available yet', ''],
    [{ latency: undefined, degraded: ['latency'] }, "Not available right now: the counter clock can't be read", ''],
  ];
  for (const [over, value, context] of cases) {
    const body = overview(over);
    if (over.latency === undefined) delete body.latency;
    await page.unrouteAll();
    await serve(page, { body });
    await open(page);
    await expect(num(page, 'p95'), value).toHaveText(value);
    await expect(ctx(page, 'p95'), value).toHaveText(context);
  }
});

test('T4 a possibly cut or folded server name links to the collection; others to their own page', async ({ page }) => {
  const a = (n) => 'a'.repeat(n);
  const cases = [
    [a(252), `/ui/servers/${a(252)}/status`],
    [a(253), '/ui/servers/status'],
    [`${a(248)}😀`, `/ui/servers/${a(248)}%F0%9F%98%80/status`],
    [`${a(249)}😀`, '/ui/servers/status'],
    ['a/b?c#d%e', '/ui/servers/a%2Fb%3Fc%23d%25e/status'],
    ['.', '/ui/servers/status'],
    ['..', '/ui/servers/status'],
  ];
  for (const [name, href] of cases) {
    const slow = { name, p95_ms: 1900, calls: 300 };
    await page.unrouteAll();
    await serve(page, { body: overview({ latency: { from: H(14), to: H(15), servers: [slow], more: { count: 0 }, slowest: slow } }) });
    await open(page);
    await expect(link(page, 'p95'), name.slice(0, 12)).toHaveAttribute('href', href);
  }
  await link(page, 'p95').click();
  await expect(page).toHaveURL(/\/ui\/servers\/status$/);
});

test('T4 a name with reserved characters opens that server', async ({ page }) => {
  const slow = { name: 'a/b?c#d%e', p95_ms: 1900, calls: 300 };
  await serve(page, { body: overview({ latency: { from: H(14), to: H(15), servers: [slow], more: { count: 0 }, slowest: slow } }) });
  await open(page);
  await link(page, 'p95').click();
  await expect(page).toHaveURL(/\/ui\/servers\/a%2Fb%3Fc%23d%25e\/status$/);
});

const strip = (page) => page.locator('#content [data-tile]:not(details [data-tile])');
const folded = (page) => page.locator('#content details.ov-more [data-tile]');

test('T5 on a phone: Calls, Firewall, From cache, then More numbers (3) holding the rest', async ({ page }) => {
  await serve(page);
  await open(page, 390);
  await expect(strip(page)).toHaveCount(3);
  expect(await strip(page).evaluateAll((ts) => ts.map((t) => t.dataset.tile))).toEqual(['calls', 'blocks', 'cache']);
  await expect(page.locator('#content details.ov-more > summary')).toHaveText('More numbers (3)');
  expect(await folded(page).evaluateAll((ts) => ts.map((t) => t.dataset.tile))).toEqual(['p95', 'tools', 'spend']);
  for (const id of ['p95', 'tools', 'spend']) await expect(tile(page, id)).toBeHidden();
  await page.locator('#content details.ov-more > summary').click();
  for (const id of ['p95', 'tools', 'spend']) await expect(tile(page, id)).toBeVisible();
});

test('T5 at 1440 all six show and there is no disclosure; resizing keeps each tile once, filled', async ({ page }) => {
  await serve(page);
  await open(page);
  await expect(strip(page)).toHaveCount(6);
  await expect(page.locator('#content details.ov-more')).toHaveCount(0);
  const ALL = ['calls', 'blocks', 'cache', 'p95', 'tools', 'spend'];
  // The DOM's own check: it counts a tile inside a closed disclosure as not shown even when the tile
  // still holds a box from an earlier layout (Playwright's box test would read that as visible).
  const seen = (id) => tile(page, id).evaluate((el) => el.checkVisibility());
  const shown = async (ids, hidden, why) => {
    for (const id of ids) await expect.poll(() => seen(id), `${why} ${id}`).toBe(true);
    for (const id of hidden) await expect.poll(() => seen(id), `${why} ${id}`).toBe(false);
  };
  for (const [w, openIt] of [[390, true], [1440, false], [390, false], [1440, false]]) {
    await page.setViewportSize({ width: w, height: 900 });
    const summary = page.locator('#content details.ov-more > summary');
    // Settled first: the regrouping follows the breakpoint's change event.
    await expect(page.locator('#content details.ov-more'), `${w}`).toHaveCount(w === 390 ? 1 : 0);
    if (w === 390 && !(await page.locator('#content details.ov-more[open]').count())) {
      await shown(['calls', 'blocks', 'cache'], ['p95', 'tools', 'spend'], `${w} closed`);
    }
    if (openIt) {
      await summary.click();
      await shown(ALL, [], `${w} open`);
    }
    if (w === 1440) await shown(ALL, [], `${w}`);
    await expect(page.locator('#content [data-tile]'), `${w}`).toHaveCount(6);
    await expect(num(page, 'calls'), `${w}`).toHaveText('4,812');
    await expect(num(page, 'cache'), `${w}`).toHaveText('20%');
    await expect(tile(page, 'calls').locator('svg.ov-spark'), `${w}`).toHaveCount(1);
  }
});

test('T6 absent, degraded and uncounted words on the counter tiles', async ({ page }) => {
  const cases = [
    [{ kpi: { calls_24h: undefined, calls_prev_24h: undefined } }, 'calls', 'Not available yet'],
    [{ kpi: { calls_24h: undefined }, degraded: ['kpi.calls_24h'] }, 'calls', "Not available right now: the counter clock can't be read"],
    [{ kpi: { blocks_24h: undefined }, degraded: ['kpi.blocks_24h'] }, 'blocks', "Not available right now: the counter clock can't be read"],
    [{ kpi: { blocks_24h: undefined }, degraded: ['kpi.calls_24h'] }, 'cache', "Not available right now: the counter clock can't be read"],
  ];
  for (const [over, id, words] of cases) {
    await page.unrouteAll();
    await serve(page, { body: overview(over) });
    await open(page);
    await expect(num(page, id), words).toHaveText(words);
    await expect(ctx(page, id), words).toHaveText('');
  }
  // Another counter field present (errors only) means a store exists: the missing ones are not yet, not uncounted.
  const errorsOnly = overview({ kpi: { calls_24h: undefined, calls_prev_24h: undefined, blocks_24h: undefined, blocks_prev_24h: undefined } });
  delete errorsOnly.latency;
  await page.unrouteAll();
  await serve(page, { body: errorsOnly });
  await open(page);
  await expect(num(page, 'calls'), 'errors only').toHaveText('Not available yet');
  const none = { calls_24h: undefined, calls_prev_24h: undefined, blocks_24h: undefined, blocks_prev_24h: undefined, errors_24h: undefined, errors_prev_24h: undefined, counting_since: undefined };
  const body = overview({ kpi: none });
  delete body.latency;
  await page.unrouteAll();
  await serve(page, { body, reads: { calls: 503, blocks: 503, cache_hits: 503 } });
  await open(page);
  for (const id of ['calls', 'blocks', 'cache', 'p95']) await expect(num(page, id), id).toHaveText('Not counted on this gateway');
  await expect(page.locator('#content .ov-trend-off')).toHaveCount(0);
});

/** A read held until `release(body)` is called. */
function held() {
  let release;
  const promise = new Promise((resolve) => { release = resolve; });
  return { promise, release };
}

test('T7 numbers paint before the series; the cache tile waits for both of its reads', async ({ page }) => {
  const calls = held();
  const hits = held();
  const blocks = held();
  await serve(page, { reads: { calls: calls.promise, cache_hits: hits.promise, blocks: blocks.promise } });
  await open(page);
  await expect(num(page, 'calls')).toHaveText('4,812');
  await expect(num(page, 'blocks')).toHaveText('3');
  await expect(page.locator('#content svg.ov-spark')).toHaveCount(0);
  await expect(num(page, 'cache')).toHaveText('…');
  calls.release(SERIES.calls);
  await expect(tile(page, 'calls').locator('svg.ov-spark')).toHaveCount(1);
  await expect(num(page, 'cache')).toHaveText('…');
  hits.release(SERIES.cache_hits);
  await expect(num(page, 'cache')).toHaveText('20%');
  blocks.release(SERIES.blocks);
  await expect(tile(page, 'blocks').locator('svg.ov-spark')).toHaveCount(1);
});

test('T8 a failed series read: trend words in place of the sparkline, the number kept', async ({ page }) => {
  const own = { calls: 'calls', blocks: 'blocks' };
  for (const metric of ['calls', 'blocks', 'cache_hits']) {
    for (const failure of ['abort', 500]) {
      const label = `${metric} ${failure}`;
      await page.unrouteAll();
      await serve(page, { reads: { [metric]: failure } });
      await open(page);
      await expect(num(page, 'calls'), label).toHaveText('4,812');
      await expect(num(page, 'blocks'), label).toHaveText('3');
      if (own[metric]) {
        await expect(tile(page, own[metric]).locator('.ov-trend-off'), label).toHaveText('Trend unavailable right now');
        await expect(tile(page, own[metric]).locator('svg.ov-spark'), label).toHaveCount(0);
      }
      await expect(num(page, 'cache'), label).toHaveText(metric === 'blocks' ? '20%' : 'Not available right now: a read failed');
    }
  }
  await page.unrouteAll();
  await serve(page);
  await page.goto('/ui/overview/status');
  await expect(tile(page, 'calls').locator('svg.ov-spark')).toHaveCount(1);
  await expect(page.locator('#content .ov-trend-off')).toHaveCount(0);
  await expect(num(page, 'cache')).toHaveText('20%');
});

/** Coordinate pairs plotted in a tile's sparkline, across all its lines. */
const plotted = (page, id) => tile(page, id).locator('svg.ov-spark polyline')
  .evaluateAll((ls) => ls.reduce((n, l) => n + l.getAttribute('points').trim().split(/\s+/).length, 0));

test('T9 the cache tile: one case per row of its table', async ({ page }) => {
  const only = (vs) => series('x', vs);
  const one = { ...series('cache_hits', [10, 50, 0, 40]), points: points([10, 50, 0, 40]).filter((p) => p.t !== T[1]) };
  const cases = [
    ['row 8, ratio over completed buckets', SERIES.calls, SERIES.cache_hits, '20%', '60 of 300 calls'],
    ['row 5, a bucket in one series only', SERIES.calls, one, 'Not available right now: the reads disagree', ''],
    ['row 5, hits above calls', SERIES.calls, { ...only([150, 200, 0, 0]), metric: 'cache_hits' }, 'Not available right now: the reads disagree', ''],
    ['row 8, hits equal to calls', SERIES.calls, { ...only([100, 200, 0, 0]), metric: 'cache_hits' }, '100%', '300 of 300 calls'],
    ['row 6, no completed buckets', { ...SERIES.calls, points: points([5]).map((p) => ({ ...p, t: T[3] })) }, { ...SERIES.cache_hits, points: [{ t: T[3], v: 1 }] }, 'Not available yet', ''],
    ['row 7, zero calls', { ...only([0, 0, 0, 5]), metric: 'calls' }, { ...only([0, 0, 0, 1]), metric: 'cache_hits' }, 'No calls in the last 24 h', ''],
  ];
  for (const [name, calls, hits, value, context] of cases) {
    await page.unrouteAll();
    await serve(page, { reads: { calls, cache_hits: hits } });
    await open(page);
    await expect(num(page, 'cache'), name).toHaveText(value);
    await expect(ctx(page, 'cache'), name).toHaveText(context);
  }
  await page.unrouteAll();
  await serve(page);
  await open(page);
  expect(await plotted(page, 'cache')).toBe(2);
  // A 0-call bucket between two runs splits the line: two lines, never one across the gap.
  await page.unrouteAll();
  await serve(page, { reads: { calls: series('calls', [100, 0, 200, 5]), cache_hits: series('cache_hits', [10, 0, 50, 1]) } });
  await open(page);
  await expect(tile(page, 'cache').locator('svg.ov-spark polyline')).toHaveCount(2);
});

test('T10 the Firewall tile opens Activity filtered to blocked calls without reloading the page', async ({ page }) => {
  await serve(page);
  await open(page);
  await page.evaluate(() => { window.__sameDocument = true; });
  await link(page, 'blocks').click();
  await expect(page).toHaveURL(/\/ui\/activity\/status\?outcome=blocked$/);
  expect(await page.evaluate(() => window.__sameDocument === true)).toBe(true);
  await expect(page.locator('#content')).toBeFocused();
});

// The rows above find sparklines by tag name, which an element in the wrong namespace also matches
// while drawing nothing; this one checks the namespace the script computes at load.
test('T11 a sparkline and its lines are SVG elements, so they draw', async ({ page }) => {
  await serve(page);
  await open(page);
  const spark = tile(page, 'calls').locator('svg.ov-spark');
  await expect(spark).toHaveCount(1);
  const spaces = await spark.evaluate((s) => [s, ...s.querySelectorAll('polyline')].map((e) => e.namespaceURI));
  expect(spaces.length).toBeGreaterThan(1);
  expect(new Set(spaces)).toEqual(new Set(['http://www.w3.org/2000/svg']));
});
