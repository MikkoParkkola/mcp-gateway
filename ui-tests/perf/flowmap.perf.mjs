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
import { readFileSync } from 'node:fs';

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
    // The bodies differ in a drawn row's key (the spec's shape): every sample makes a row and lets one go.
    const keys = await page.evaluate(async (pair) => {
      const { flowModel } = await import(JSON.parse(document.getElementById('screens').textContent).overview.js);
      return pair.map((b) => flowModel(b).agents.map((r) => r.key).join(' '));
    }, [big(0), big(1)]);
    expect(keys[0], 'the two bodies draw a different caller').not.toBe(keys[1]);
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

test('DIAG the fold against the code before it, phone, in one run', async ({ page }) => {
  // The code before the fold, and the fold with one change undone each (built by sed from its blob).
  const variants = ['before', 'noMove', 'noFoldMax', 'noBox'];
  const code = Object.fromEntries(variants.map((v) => [v, readFileSync(new URL(`./diag-${v}.js`, import.meta.url), 'utf8')]));
  await page.route('**/ui/assets/overview.diag-*.js', (r) => r.fulfill({ body: code[/diag-(\w+)\.js$/.exec(r.request().url())[1]], contentType: 'text/javascript' }));
  await serve(page, { body: big(0) });
  await open(page);
  await expect(page.locator('#content [data-panel="flow-map"] .ov-map')).toHaveCount(1);
  await profileOn(page, 'phone');
  const out = await page.evaluate(async ([a, b, names]) => {
    const screens = JSON.parse(document.getElementById('screens').textContent);
    const mods = { now: await import(screens.overview.js) };
    for (const v of names) mods[v] = await import(`/ui/assets/overview.diag-${v}.js`);
    const keys = Object.keys(mods);
    // A fresh card for each module, so all start the same way (none knows it is on a phone).
    const fresh = () => { const s = document.createElement('section'); s.className = 'tk ov-panel ov-flow'; document.querySelector('#content .ov').append(s); return s; };
    const roots = Object.fromEntries(keys.map((k) => [k, fresh()]));
    for (const k of keys) mods[k].updateMap(roots[k], mods[k].flowModel(a));
    const times = Object.fromEntries(keys.map((k) => [k, []]));
    // Six rounds of 50 each, the order reversed every other round, so drift falls on all alike.
    for (let round = 0; round < 6; round += 1) {
      for (const k of round % 2 ? [...keys].reverse() : keys) {
        for (let i = 0; i < 50; i += 1) {
          const t = performance.now();
          mods[k].updateMap(roots[k], mods[k].flowModel(i % 2 ? b : a));
          roots[k].getBoundingClientRect();
          times[k].push(performance.now() - t);
        }
      }
    }
    const at = (xs, q) => [...xs].sort((x, y) => x - y)[Math.ceil(q * xs.length) - 1].toFixed(2);
    return Object.fromEntries(Object.entries(times).map(([k, xs]) => [k, { p50: at(xs, 0.5), p95: at(xs, 0.95) }]));
  }, [big(0), big(1), variants]);
  console.log(`DIAG A/B phone ${JSON.stringify(out)}`);
});
