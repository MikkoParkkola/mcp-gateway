// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The Overview's 24 h calls chart and the shared chart module it draws with.
// Rows on the panel answer the two reads the tab already makes;
// rows on the module import it by its hashed name and call it directly.
import { readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { test, expect, blockingViolations } from './base.mjs';
import { overview, serve, open, series, points, T } from './overview.mjs';

const SHELL_DIR = fileURLToPath(new URL('../../src/gateway/ui/shell/', import.meta.url));
/** The chart module's file name, or '' while none exists. */
const chartFile = () => readdirSync(SHELL_DIR).find((f) => /^chart\.[0-9a-f]{12}\.js$/.test(f)) ?? '';
const DAY = 86_400;
const UNIT = 'calls per 30 min';

/** The calls series with `prev` as its previous period, stamped as the API stamps it: a day earlier. */
function calls(vs, prev, complete = true) {
  return { ...series('calls', vs), previous: points(prev).map((p) => ({ ...p, t: p.t - DAY })), previous_complete: complete };
}
const chartPanel = (page) => page.locator('#content [data-panel="calls-chart"]');
const plot = (page) => chartPanel(page).locator('svg.chart-plot');
/** The x of each point of a polyline. */
const xs = (pts) => pts.trim().split(/\s+/).map((p) => Number(p.split(',')[0]));

/** Open the Overview with `markers` in its body and `callsBody` as the calls read. */
async function showChart(page, { markers = { rows: [], more: { count: 0 } }, callsBody = calls([100, 200, 0, 50], [10, 20, 30, 40]), width } = {}) {
  await serve(page, { body: { ...overview(), markers }, reads: { calls: callsBody } });
  await open(page, width);
  await expect(chartPanel(page).locator('figure.chart, .chart-failed, .chart-uncounted')).toHaveCount(1);
}

/** The chart module's URL; a row fails here while the module does not exist. */
function chartSrc() {
  const file = chartFile();
  expect(file, 'a chart.<hash>.js asset in the shell folder').not.toBe('');
  return `/ui/assets/${file}`;
}

test.use({ timezoneId: 'UTC', locale: 'en-GB' });

test('K0 the chart and the sparkline refuse to draw without a unit', async ({ page }) => {
  await serve(page);
  await open(page);
  const out = await page.evaluate(async ([src, unitWords]) => {
    const { chart, spark } = await import(src);
    const base = { caption: 'Calls per 30 min', series: [{ name: 'a', role: 'main', points: [{ t: 0, v: 1 }, { t: 1800, v: 2 }] }], x: String, y: String, summary: 's' };
    const err = (f) => { try { f(); return 'no error'; } catch (e) { return `${e.constructor.name}: ${e.message}`; } };
    const unit = { words: unitWords };
    const fig = chart({ ...base, unit });
    const sp = spark([1, 2], { label: 'x', unit });
    return {
      refused: [err(() => chart(base)), err(() => chart({ ...base, unit: {} })), err(() => chart({ ...base, unit: { words: '' } })),
        err(() => spark([1, 2], { label: 'x' })), err(() => spark([1, 2], { label: 'x', unit: { words: '' } }))],
      figUnit: fig.dataset.unit,
      sparkHidden: sp.querySelector('.sr-only')?.textContent ?? '',
    };
  }, [chartSrc(), UNIT]);
  for (const r of out.refused) expect(r).toMatch(/^TypeError: .*\bunit\b/);
  expect(out.figUnit).toBe(UNIT);
  expect(out.sparkHidden).toContain(UNIT);
  // On the Overview, the chart and the Calls sparkline carry one phrase, and the caption names it.
  await showChart(page);
  const fig = chartPanel(page).locator('figure.chart');
  await expect(fig).toHaveAttribute('data-unit', UNIT);
  await expect(page.locator('#content [data-tile="calls"] .chart-spark')).toHaveAttribute('data-unit', UNIT);
  expect((await fig.locator('.chart-caption').textContent()).toLowerCase()).toContain(UNIT);
});

test('K1 the chart draws the last 24 h over the 24 h before, each point at its time', async ({ page }) => {
  const markers = { rows: [{ t: T[2], kind: 'upgrade', subject: '4.0.0' }, { t: T[0] - 3600, kind: 'pause', subject: 'github' }], more: { count: 0 } };
  await showChart(page, { markers });
  const fig = chartPanel(page).locator('figure.chart');
  await expect(fig.locator('.chart-caption')).toHaveText('Calls per 30 min');
  await expect(fig.locator('.chart-legend li')).toHaveText(['Last 24 h', '24 h before']);
  await expect(fig.locator('.chart-y span')).toHaveText(['200', '100', '0']);
  await expect(plot(page)).toHaveAttribute('viewBox', '0 0 4 100');
  await expect(plot(page)).toHaveAccessibleName(/350.*100/);
  const lines = plot(page).locator('polyline');
  await expect(lines).toHaveCount(2);
  for (const role of ['main', 'previous']) {
    expect(xs(await plot(page).locator(`polyline[data-role="${role}"]`).getAttribute('points')), role).toEqual([0.5, 1.5, 2.5, 3.5]);
  }
  // The marker inside the day draws at its bucket; the one before it is listed but not drawn.
  const marks = plot(page).locator('line.chart-mark');
  await expect(marks).toHaveCount(1);
  await expect(marks).toHaveAttribute('x1', '2.5');
  await expect(fig.locator('.chart-markers li')).toHaveCount(2);

  // The module places by time: a previous period left a day early never reaches the plot.
  const unshifted = await page.evaluate(async ([src, t, day]) => {
    const { chart } = await import(src);
    const pts = (vs, shift = 0) => vs.map((v, i) => ({ t: t[i] - shift, v }));
    const fig = chart({ caption: 'c', unit: { words: 'u' }, x: String, y: String, summary: 's',
      series: [{ name: 'now', role: 'main', points: pts([100, 200, 0, 50]) }, { name: 'before', role: 'previous', points: pts([10, 20, 30, 40], day) }] });
    return { main: fig.querySelectorAll('polyline[data-role="main"]').length, previous: fig.querySelectorAll('polyline[data-role="previous"]').length };
  }, [chartSrc(), T, DAY]);
  expect(unshifted).toEqual({ main: 1, previous: 0 });
});

const FAILED = 'Not available right now: a read failed';
const UNCOUNTED = 'Not counted on this gateway';
const MARKS = { rows: [{ t: T[1], kind: 'pause', subject: 'github' }], more: { count: 0 } };

test('K2 the chart asks for no series of its own', async ({ page }) => {
  const asked = [];
  page.on('request', (r) => { if (r.url().includes('/ui/api/metrics/series') && r.url().includes('metric=calls')) asked.push(r.url()); });
  await showChart(page);
  await expect(chartPanel(page).locator('figure.chart')).toHaveCount(1);
  expect(asked).toHaveLength(1);
});

test('K3 a previous day not fully counted is left out, and the panel says since when', async ({ page }) => {
  await showChart(page, { callsBody: calls([100, 200, 0, 50], [10, 20, 30, 40], false) });
  const fig = chartPanel(page).locator('figure.chart');
  await expect(plot(page).locator('polyline')).toHaveCount(1);
  await expect(fig.locator('.chart-legend li')).toHaveText(['Last 24 h']);
  await expect(chartPanel(page).locator('.chart-since')).toHaveCount(1);
  await expect(chartPanel(page).locator('.chart-since')).toContainText('counting since');
  await expect(fig).not.toContainText('counting since');
});

test('K3b the chart draws once, with its markers, whichever read answers last', async ({ page }) => {
  for (const held of ['overview', 'series']) {
    await page.unrouteAll({ behavior: 'ignoreErrors' });
    let release;
    const gate = new Promise((r) => { release = r; });
    const body = { ...overview(), markers: MARKS };
    await serve(page, { body, reads: held === 'series' ? { calls: gate.then(() => calls([1, 2, 3, 4], [1, 1, 1, 1])) } : {} });
    if (held === 'overview') await page.route('**/ui/api/overview', async (r) => { await gate; await r.fulfill({ json: body }); });
    await page.setViewportSize({ width: 1440, height: 1100 });
    const callsAnswered = held === 'overview' ? page.waitForResponse((r) => r.url().includes('metric=calls')) : null;
    await page.goto('/ui/overview/status');
    if (callsAnswered) await callsAnswered;
    else await expect(chartPanel(page)).toHaveCount(1);
    await expect(chartPanel(page).locator('figure.chart'), held).toHaveCount(0);
    release();
    await expect(chartPanel(page).locator('figure.chart'), held).toHaveCount(1);
    await expect(chartPanel(page).locator('.chart-markers li'), held).toHaveCount(1);
  }
});

test('K4 a failed calls read says so in the panel, and the tiles still draw', async ({ page }) => {
  await showChart(page, { callsBody: 500 });
  await expect(chartPanel(page).locator('.chart-failed')).toHaveText(FAILED);
  await expect(page.locator('#content [data-tile]')).toHaveCount(6);
});

test('K4b a calls read with malformed points reads as failed, with no page error', async ({ page }) => {
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  for (const bad of [[{ t: 'x', v: 1 }], [{ t: T[0], v: '1' }]]) {
    await page.unrouteAll({ behavior: 'ignoreErrors' });
    await showChart(page, { callsBody: { ...series('calls', [1]), points: bad } });
    await expect(chartPanel(page).locator('.chart-failed')).toHaveText(FAILED);
    await expect(page.locator('#content [data-tile]')).toHaveCount(6);
  }
  expect(errors).toEqual([]);
});

test('K5 with no counter store the panel says not counted', async ({ page }) => {
  await serve(page, { body: { kpi: { servers_total: 2, tools_total: 3 } }, reads: { calls: 503 } });
  await open(page);
  await expect(chartPanel(page).locator('.chart-uncounted')).toHaveText(UNCOUNTED);
});

test('K6 markers read as text, oldest first, each with its time', async ({ page }) => {
  // Sent newest first; an unknown kind reads in fixed words, never as its code.
  const rows = [{ t: T[3], kind: 'zz', subject: null }, { t: T[2], kind: 'pause', subject: 'github' },
    { t: T[1], kind: 'switch_off', subject: 'stripe' }, { t: T[0], kind: 'upgrade', subject: '4.0.0' }];
  await showChart(page, { markers: { rows, more: { count: 3 } } });
  const fig = chartPanel(page).locator('figure.chart');
  await expect(fig.locator('.chart-markers li')).toHaveText(['↻ 13:00 upgraded to 4.0.0', '⚠ 13:30 stripe off', '⏸ 14:00 github paused', '• 14:30 a gateway event']);
  await expect(page.locator('#content')).not.toContainText('zz');
  await expect(plot(page).locator('line.chart-mark')).toHaveCount(4);
  await expect(chartPanel(page).locator('.chart-more')).toHaveText('and 3 earlier');
  await expect(fig.locator('.chart-more')).toHaveCount(0);
});

test('K7 a marker subject is text, never markup', async ({ page }) => {
  await showChart(page, { markers: { rows: [{ t: T[1], kind: 'pause', subject: '<img src=x>' }], more: { count: 0 } } });
  await expect(chartPanel(page).locator('.chart-markers li')).toHaveText('⏸ 13:30 <img src=x> paused');
  await expect(chartPanel(page).locator('img')).toHaveCount(0);
});

test('K8 nothing in the chart animates', async ({ page }) => {
  for (const motion of ['no-preference', 'reduce']) {
    await page.emulateMedia({ reducedMotion: motion });
    await page.unrouteAll({ behavior: 'ignoreErrors' });
    await showChart(page, { markers: MARKS });
    const still = await page.evaluate(() => {
      const fig = document.querySelector('#content [data-panel="calls-chart"] figure.chart');
      const moving = [fig, ...fig.querySelectorAll('*')].filter((e) => {
        const s = getComputedStyle(e);
        return s.animationName !== 'none' || s.transitionDuration.split(',').some((d) => parseFloat(d) !== 0);
      });
      return { animations: document.getAnimations().length, moving: moving.map((e) => e.tagName) };
    });
    expect(still, motion).toEqual({ animations: 0, moving: [] });
  }
});

/** A calls read of `count` half hours from T[0], with no previous day. */
const long = (count) => ({ ...series('calls', [1]), points: Array.from({ length: count }, (_, i) => ({ t: T[0] + i * 1800, v: i })), previous: [], previous_complete: false });

test('K9 on a 390 px phone the chart fits and shows three time labels', async ({ page }) => {
  for (const [count, want] of [[48, ['13:00', '00:30', '12:30']], [13, ['13:00', '16:00', '19:00']], [4, ['13:00', '13:30', '14:30']]]) {
    await page.unrouteAll({ behavior: 'ignoreErrors' });
    await showChart(page, { callsBody: count === 4 ? calls([100, 200, 0, 50], [10, 20, 30, 40]) : long(count), width: 390 });
    const fig = chartPanel(page).locator('figure.chart');
    const box = await fig.boundingBox();
    expect(box.x + box.width, `${count}`).toBeLessThanOrEqual(390);
    await expect(fig.locator('.chart-x span:visible'), `${count}`).toHaveText(want);
  }
});

for (const scheme of ['dark', 'light']) {
  for (const width of [390, 1440]) {
    test(`K10 axe on the chart, ${scheme} at ${width}`, async ({ page }) => {
      await page.emulateMedia({ colorScheme: scheme });
      await showChart(page, { markers: MARKS, width });
      expect(await blockingViolations(page)).toEqual([]);
    });
  }
}

test('K11 a gap is never bridged, a quiet series lies on the baseline, and an empty one draws nothing', async ({ page }) => {
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await serve(page);
  await open(page);
  const out = await page.evaluate(async ([src, t]) => {
    const { chart } = await import(src);
    const draw = (vs) => chart({ caption: 'c', unit: { words: 'u' }, x: String, y: String, summary: 's',
      series: [{ name: 'now', role: 'main', points: vs.map((v, i) => ({ t: t[i], v })) }] });
    const runs = (fig) => [...fig.querySelectorAll('polyline')].map((l) => l.getAttribute('points').trim().split(/\s+/).map((p) => p.split(',').map(Number)));
    const gap = draw([100, null, 50, 60]);
    const quiet = draw([0, 0, 0, 0]);
    const empties = [draw([]), draw([null, null, null, null])].map((f) => ({ svg: f.querySelectorAll('svg').length, text: f.querySelector('.chart-empty')?.textContent ?? '' }));
    return { gap: runs(gap), quiet: runs(quiet), quietTicks: [...quiet.querySelectorAll('.chart-y span')].map((s) => s.textContent), empties };
  }, [chartSrc(), T]);
  expect(out.gap).toHaveLength(2);
  // No point of either run lies in the null bucket (x from 1 to 2).
  expect(out.gap.flat().filter(([x]) => x > 1 && x < 2)).toEqual([]);
  expect(out.gap[1].map(([x]) => x)).toEqual([2.5, 3.5]);
  expect(out.quiet).toHaveLength(1);
  expect(new Set(out.quiet[0].map(([, y]) => y))).toEqual(new Set([100]));
  expect(out.quietTicks).toEqual(['1', '0.5', '0']);
  for (const e of out.empties) expect(e).toEqual({ svg: 0, text: 'Nothing counted in this period yet' });
  expect(errors).toEqual([]);
});

test('K12 the two days differ by stroke pattern, not only by colour', async ({ page }) => {
  await showChart(page);
  const dash = (loc) => loc.evaluate((e) => getComputedStyle(e).strokeDasharray);
  const fig = chartPanel(page).locator('figure.chart');
  const main = await dash(plot(page).locator('polyline[data-role="main"]'));
  const previous = await dash(plot(page).locator('polyline[data-role="previous"]'));
  expect(main).toBe('none');
  expect(previous).not.toBe('none');
  expect(await dash(fig.locator('.chart-legend li[data-role="main"] line'))).toBe(main);
  expect(await dash(fig.locator('.chart-legend li[data-role="previous"] line'))).toBe(previous);
});

test('K13 the half-hour values are a table, closed until asked for', async ({ page }) => {
  await showChart(page);
  const numbers = chartPanel(page).locator('figure.chart details.chart-numbers');
  await expect(numbers.locator('summary')).toHaveText('The numbers');
  await expect(numbers).not.toHaveAttribute('open', /.*/);
  await expect(numbers.locator('thead th')).toHaveText(['Time', `Last 24 h (${UNIT})`, `24 h before (${UNIT})`]);
  await expect(numbers.locator('tbody tr')).toHaveText([/13:00\s*100\s*10/, /13:30\s*200\s*20/, /14:00\s*0\s*30/, /14:30\s*50\s*40/]);
  const missing = await page.evaluate(async ([src, t]) => {
    const { chart } = await import(src);
    const fig = chart({ caption: 'c', unit: { words: 'u' }, x: String, y: String, summary: 's',
      series: [{ name: 'now', role: 'main', points: [{ t: t[0], v: 5 }, { t: t[1], v: null }] }] });
    return [...fig.querySelectorAll('details tbody td')].map((c) => c.textContent);
  }, [chartSrc(), T]);
  expect(missing).toEqual(['5', 'not counted']);
});

test('K14 the module alone: a second series, a limit, and a day across a clock change', async ({ page }) => {
  await serve(page);
  await open(page);
  const src = chartSrc();
  const out = await page.evaluate(async ([src, t, day]) => {
    const { chart } = await import(src);
    const pts = (vs, at = t) => vs.map((v, i) => ({ t: at[i], v }));
    const unit = { words: '$ per day', symbol: '$' };
    const host = document.querySelector('#content');
    const dash = (fig, sel) => getComputedStyle(fig.querySelector(sel)).strokeDasharray;
    const costs = chart({ caption: 'Spend per day', unit, x: String, y: String, summary: 's', limit: { value: 150, words: 'daily limit' },
      series: [{ name: 'spent', role: 'main', points: pts([10, 90, 30, 60]) }, { name: 'other', role: 'second', points: pts([5, 6, 7, 8]) }] });
    const both = chart({ caption: 'c', unit, x: String, y: String, summary: 's',
      series: [{ name: 'now', role: 'main', points: pts([1, 2, 3, 4]) }, { name: 'before', role: 'previous', points: pts([1, 2, 3, 4]) }] });
    host.append(costs, both);
    // 48 half hours from midnight in Amsterdam on 25 Oct 2026, when the clocks go back; the day
    // before, stamped a day earlier and moved forward by exactly a day, as the Overview does.
    const start = Date.UTC(2026, 9, 24, 22) / 1000;
    const at = Array.from({ length: 48 }, (_, i) => start + i * 1800);
    const ones = at.map(() => 1);
    const shifted = pts(ones, at.map((s) => s - day)).map((p) => ({ ...p, t: p.t + day }));
    const change = chart({ caption: 'c', unit, x: String, y: String, summary: 's',
      series: [{ name: 'now', role: 'main', points: pts(ones, at) }, { name: 'before', role: 'previous', points: shifted }] });
    const xsOf = (sel) => change.querySelector(sel).getAttribute('points').trim().split(/\s+/).map((p) => p.split(',')[0]);
    const result = {
      patterns: [dash(costs, 'polyline[data-role="main"]'), dash(costs, 'polyline[data-role="second"]'), dash(costs, 'line.chart-limit'), dash(both, 'polyline[data-role="previous"]')],
      ticks: [...costs.querySelectorAll('.chart-y span')].map((s) => s.textContent),
      limitWords: costs.querySelector('figcaption .chart-limit')?.textContent ?? '',
      svgText: costs.querySelector('svg').textContent,
      aligned: JSON.stringify(xsOf('polyline[data-role="main"]')) === JSON.stringify(xsOf('polyline[data-role="previous"]')),
    };
    costs.remove();
    both.remove();
    return result;
  }, [src, T, DAY]);
  expect(new Set(out.patterns).size).toBe(4);
  expect(out.ticks).toEqual(['$200', '$100', '$0']);
  expect(out.limitWords).toContain('daily limit');
  expect(out.limitWords).toContain('$150');
  expect(out.svgText.trim()).toBe('');
  expect(out.aligned).toBe(true);
});
