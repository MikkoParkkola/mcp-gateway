// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The flow map's update budget (motion spec: under 4 ms at 140 servers), one
// row per profile, plus the rows that show the measure can fail. Each sample
// times updateMap(root, flowModel(body)) and the style and layout flush it
// causes (a getBoundingClientRect after the call); paint and compositing are
// not in the number, which this suite cannot measure. Run with one worker, as
// the CI step does.
import { test, expect } from '../tests/base.mjs';
import { serve, open } from '../tests/overview.mjs';
import { big } from '../tests/flowmap.mjs';

const BUDGET_MS = 4;
const SAMPLES = 50;

/** The nearest-rank 95th percentile; NaN for no samples, so an unmeasured number is a miss. */
function p95(samples) {
  const sorted = samples.filter(Number.isFinite).sort((a, b) => a - b);
  return sorted.length === SAMPLES ? sorted[Math.ceil(0.95 * sorted.length) - 1] : NaN;
}
/** The budget's miss, as text, or null: a p95 that was not measured misses. */
function miss(samples) {
  const p = p95(samples);
  if (!Number.isFinite(p)) return `p95 was not measured (${samples.length} of ${SAMPLES} samples)`;
  return p < BUDGET_MS ? null : `p95 ${p.toFixed(2)} ms is not under ${BUDGET_MS} ms`;
}

/** The phone profile throttles the CPU 4x on a phone-sized viewport; desktop is plain. */
async function profileOn(page, profile) {
  if (profile === 'desktop') return page.setViewportSize({ width: 1440, height: 900 });
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('Emulation.setCPUThrottlingRate', { rate: 4 });
  await page.setViewportSize({ width: 412, height: 823 });
  return cdp;
}

/**
 * In the page: SAMPLES timed calls of `slowOn(i) ? update + a 5 ms spin : update`, alternating the two
 * bodies. The update imports the screen module named in the document's manifest.
 */
async function sample(page, bodies, slow = 'none') {
  return page.evaluate(async ([pair, n, plant]) => {
    const screens = JSON.parse(document.getElementById('screens').textContent);
    const { flowModel, updateMap } = await import(screens.overview.js);
    const root = document.querySelector('#content [data-panel="flow-map"]');
    const spin = (ms) => { const end = performance.now() + ms; while (performance.now() < end); };
    const slowOn = (i) => plant === 'every' || (plant === 'five' && i % 10 === 3) || (plant === 'two' && i % 25 === 7);
    const out = [];
    for (let i = 0; i < n; i += 1) {
      const t = performance.now();
      updateMap(root, flowModel(pair[i % 2]));
      if (slowOn(i)) spin(5);
      root.getBoundingClientRect();
      out.push(performance.now() - t);
    }
    return out;
  }, [bodies, SAMPLES, slow]);
}

test.describe.configure({ mode: 'default', timeout: 120_000 });

for (const profile of ['phone', 'desktop']) {
  test(`F1 a flow map update at 140 servers stays under 4 ms, ${profile}`, async ({ page }) => {
    await serve(page, { body: big(0) });
    await open(page);
    await expect(page.locator('#content [data-panel="flow-map"] .ov-map')).toHaveCount(1);
    const cdp = await profileOn(page, profile);
    const samples = await sample(page, [big(0), big(1)]);
    console.log(`F1 ${profile}: p95 ${p95(samples).toFixed(3)} ms, max ${Math.max(...samples).toFixed(3)} ms`);
    expect(miss(samples), 'the update budget').toBeNull();
    if (cdp) await cdp.send('Emulation.setCPUThrottlingRate', { rate: 1 });
  });
}

test('F2 a planted slow update misses the budget, two slow samples in fifty do not', async ({ page }) => {
  await serve(page, { body: big(0) });
  await open(page);
  await expect(page.locator('#content [data-panel="flow-map"] .ov-map')).toHaveCount(1);
  const verdicts = {};
  for (const plant of ['every', 'five', 'two']) verdicts[plant] = miss(await sample(page, [big(0), big(1)], plant));
  expect(verdicts.every, 'slow on every call').not.toBeNull();
  expect(verdicts.five, 'slow on 5 of 50').not.toBeNull();
  expect(verdicts.two, 'slow on 2 of 50 (the allowance)').toBeNull();
  // An unmeasured number is a miss, never a pass.
  expect(miss([])).not.toBeNull();
});

test('DIAG where the phone update time goes', async ({ page }) => {
  await serve(page, { body: big(0) });
  await open(page);
  await expect(page.locator('#content [data-panel="flow-map"] .ov-map')).toHaveCount(1);
  await profileOn(page, 'phone');
  const parts = await page.evaluate(async ([a, b, bSameDots]) => {
    const screens = JSON.parse(document.getElementById('screens').textContent);
    const { flowModel, updateMap } = await import(screens.overview.js);
    const root = document.querySelector('#content [data-panel="flow-map"]');
    const p95 = (xs) => xs.sort((x, y) => x - y)[Math.ceil(0.95 * xs.length) - 1].toFixed(2);
    const run = (pair) => {
      const m = []; const u = []; const f = [];
      for (let i = 0; i < 50; i += 1) {
        const t0 = performance.now(); const model = flowModel(pair[i % 2]);
        const t1 = performance.now(); updateMap(root, model);
        const t2 = performance.now(); root.getBoundingClientRect();
        const t3 = performance.now();
        m.push(t1 - t0); u.push(t2 - t1); f.push(t3 - t2);
      }
      return { model: p95(m), update: p95(u), flush: p95(f) };
    };
    const flushOnly = [];
    for (let i = 0; i < 50; i += 1) { root.style.setProperty('--diag', String(i)); const t = performance.now(); root.getBoundingClientRect(); flushOnly.push(performance.now() - t); }
    const changing = run([a, b]);
    const same = run([a, a]);
    root.querySelectorAll('.ov-lines path').forEach((p) => { p.style.transition = 'none'; });
    const noTransition = run([a, b]);
    // Same bodies, but no dot comes or goes between them.
    const noDotChurn = run([a, bSameDots]);
    // The pulse switched off.
    const calm = new CSSStyleSheet();
    calm.replaceSync('.ov-dot.ov-pulse { animation: none !important; }');
    document.adoptedStyleSheets = [...document.adoptedStyleSheets, calm];
    const noPulse = run([a, b]);
    document.adoptedStyleSheets = document.adoptedStyleSheets.filter((s) => s !== calm);
    const changingAgain = run([a, b]);
    return { changing, same, noTransition, noDotChurn, noPulse, changingAgain, flushOnly: p95(flushOnly) };
  }, [big(0), big(1), (() => { const b = big(1); const a = big(0); b.edges.rows.forEach((r, i) => { r.blocks = a.edges.rows[i].blocks; }); return b; })()]);
  console.log(`DIAG phone ${JSON.stringify(parts)}`);
});
