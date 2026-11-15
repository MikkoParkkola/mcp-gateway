// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// LCP and CLS for the sign-in view and the Status tab of every built screen,
// under a phone profile and a desktop profile. One test per page and profile,
// so a screen added to BUILT is measured without a new row here. The phone
// profile's network numbers are DevTools' Fast 4G preset for the Chrome this
// Playwright ships, not a remembered table.
//
// Run this file with one worker: `--workers=1` on the command line. CI passes
// that, and so does anyone running it by hand. One worker keeps the phone
// profile's CPU throttle off a core the rows would otherwise share. The suite
// is not serial, so a failing row does not skip the others.
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { test, expect } from '../tests/base.mjs';
import { BUILT, shellReady } from '../tests/shell.mjs';

const RESULTS = fileURLToPath(new URL('../test-results/', import.meta.url));
const PERF_DIR = `${RESULTS}perf/`;

const LCP_BUDGET_MS = 2500;
const CLS_BUDGET = 0.1;
const LOADS = Number(process.env.PERF_LOADS ?? 5);
const SETTLE_MS = 1000;

// Chrome for Testing 156.0.8078.4 (Playwright 1.64.1 browsers.json) is chromium
// tag 156.0.8078.4, whose DEPS pins devtools-frontend
// 2d671c506c4e5f8958b027e26047deb0acfbd7f9. Fast 4G is Fast4GConditions in
// front_end/core/sdk/NetworkManager.ts at that commit:
//   download 9 * 1000 * 1000 / 8 * .9   (9 Mbps, adjusted)
//   upload   1.5 * 1000 * 1000 / 8 * .9 (1.5 Mbps, adjusted)
//   latency  60 * 2.75                  (60 ms RTT, adjusted)
// DevTools sends connectionType from the preset title "Fast 4G", which matches
// the "4g" entry and becomes cellular4g.
const FAST_4G = {
  offline: false,
  latency: 60 * 2.75,
  downloadThroughput: 9 * 1000 * 1000 / 8 * 0.9,
  uploadThroughput: 1.5 * 1000 * 1000 / 8 * 0.9,
  connectionType: 'cellular4g',
};

// The same catalogue the Tools screen spec serves, so this row paints that
// screen. Schemas stay in the payload because the page parses them on load.
const SERVERS = ['alpha', 'bravo', 'charlie', 'delta'];
const TOOLS = SERVERS.flatMap((server) => Array.from({ length: 10 }, (_, i) => ({
  name: `${String.fromCharCode(106 - i)}_${server}_tool`,
  server,
  description: `Does thing ${i} on ${server}`,
  schema: { type: 'object', properties: Object.fromEntries(Array.from({ length: 120 }, (_, k) => [`field_${k}`, { type: 'string', description: `Field number ${k}` }])) },
  class: i % 2 ? 'write' : 'read',
  class_source: i % 3 ? 'inferred' : 'declared',
})));

// Rank in the sorted list. p75 is index ceil(0.75 * n) - 1. p50 is index ceil(0.5 * n) - 1.
function rank(sorted, fraction) {
  return sorted[Math.ceil(fraction * sorted.length) - 1];
}

function spread(values) {
  const sorted = [...values].sort((a, b) => a - b);
  return { loads: sorted.length, p50: rank(sorted, 0.5), p75: rank(sorted, 0.75), max: sorted.at(-1) };
}

/**
 * Phone throttles CPU and the network and emulates a phone viewport. Desktop
 * only sets the viewport: a fresh page has no throttle, and clearing one that
 * was never set would look like the two profiles share a session.
 * The CDP session is returned because dropping it can drop the emulation
 * before the navigation finishes.
 */
async function applyProfile(page, profile) {
  if (profile === 'desktop') {
    await page.setViewportSize({ width: 1440, height: 900 });
    return null;
  }
  const client = await page.context().newCDPSession(page);
  await client.send('Emulation.setCPUThrottlingRate', { rate: 4 });
  await client.send('Network.emulateNetworkConditions', FAST_4G);
  // setViewportSize has no scale and no mobile flag. The phone profile needs both.
  await client.send('Emulation.setDeviceMetricsOverride', {
    width: 412,
    height: 823,
    deviceScaleFactor: 1.75,
    mobile: true,
  });
  return client;
}

/** Record LCP and CLS before any paint, then read them after `ready` and a settle. */
async function measure(page, url, profile, ready) {
  const session = await applyProfile(page, profile);
  await page.addInitScript(() => {
    const vitals = { lcp: 0, cls: 0 };
    window.__vitals = vitals;
    // The last entry is the largest paint so far; later entries replace it.
    new PerformanceObserver((list) => {
      const last = list.getEntries().at(-1);
      if (last) vitals.lcp = last.startTime;
    }).observe({ type: 'largest-contentful-paint', buffered: true });
    new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        if (!entry.hadRecentInput) vitals.cls += entry.value;
      }
    }).observe({ type: 'layout-shift', buffered: true });
  });
  // Commit, not load: the status answer can hide the document before load,
  // and ready() has to observe the row's own condition.
  await page.goto(url, { waitUntil: 'commit' });
  await ready(page);
  await new Promise((resolve) => setTimeout(resolve, SETTLE_MS));
  const vitals = await page.evaluate(() => window.__vitals);
  if (!vitals) throw new Error('the vitals observer did not run');
  void session;
  return { lcp: vitals.lcp, cls: vitals.cls };
}

/** Signed out, no key: the sign-in spec's status answer when the bearer is absent. */
async function signedOut(page) {
  await page.route('**/ui/api/status', (route) => route.fulfill({
    json: { version: '4.0.0', auth: { enabled: true, signed_in: false, admin: false } },
  }));
}

/** Signed in the way the screen specs are: an admin status, plus that screen's own answers. */
async function signedIn(page, id, { holdMs = 0 } = {}) {
  await page.route('**/ui/api/status', (route) => route.fulfill({
    json: { auth: { enabled: true, signed_in: true, admin: true } },
  }));
  if (id === 'tools') {
    await page.route('**/ui/api/tools**', async (route) => {
      // Held in this process, so the phone's CPU throttle does not stretch the wait.
      if (holdMs) await new Promise((resolve) => setTimeout(resolve, holdMs));
      await route.fulfill({ json: { tools: TOOLS, total: TOOLS.length } });
    });
  }
}

/** Sign-in is ready when its form is on screen. The content under it stays hidden. */
async function readySignIn(page) {
  await expect(page.locator('#signin')).toBeVisible();
}

/**
 * A built screen is ready when the shell has rendered it and that screen's own
 * content is there. Tools waits for the catalogue line it already checked
 * ("tools from"). That line is the header subtitle, set with the catalogue;
 * the content area lists the tools and does not repeat it.
 */
function readyBuilt(id) {
  return async (page) => {
    await shellReady(page);
    if (id === 'tools') await expect(page.locator('.head .sub')).toContainText('tools from');
  };
}

const ROWS = [
  { page: 'sign-in', url: '/ui/overview/status', prepare: signedOut, ready: readySignIn },
  ...BUILT.map((id) => ({
    page: id,
    url: `/ui/${id}/status`,
    prepare: (p, opts) => signedIn(p, id, opts),
    ready: readyBuilt(id),
  })),
];

// Default, not serial: one row failing must leave the others running. One
// worker is `--workers=1` on the command line (see the top of this file).
test.describe.configure({ mode: 'default', timeout: 180_000 });

function writeRow(result) {
  mkdirSync(PERF_DIR, { recursive: true });
  writeFileSync(`${PERF_DIR}${result.page}-${result.profile}.json`, `${JSON.stringify(result)}\n`);
}

for (const row of ROWS) {
  for (const profile of ['phone', 'desktop']) {
    test(`${row.page} ${profile}: lcp p75 under 2500 ms, cls p75 under 0.1`, async ({ page }) => {
      const readings = [];
      for (let i = 0; i < LOADS; i++) {
        // A fresh page: an init script and a CDP session left on a reused page
        // would record the next load twice and keep the previous throttle.
        const fresh = await page.context().newPage();
        try {
          await row.prepare(fresh);
          readings.push(await measure(fresh, row.url, profile, row.ready));
        } finally {
          await fresh.close();
        }
      }
      const lcp = spread(readings.map((r) => r.lcp));
      const cls = spread(readings.map((r) => r.cls));
      const result = {
        page: row.page,
        profile,
        lcp: { ...lcp, budget: LCP_BUDGET_MS },
        cls: { ...cls, budget: CLS_BUDGET },
      };
      // On disk before the budget assertions, so a miss still reaches the summary.
      writeRow(result);
      console.log(JSON.stringify({ page: row.page, profile, lcp, cls }));
      expect(lcp.p75).toBeLessThan(LCP_BUDGET_MS);
      expect(cls.p75).toBeLessThan(CLS_BUDGET);
    });
  }
}

test('the phone profile is applied', async ({ page }) => {
  // Separate pages so each burn is cold, and sequential so one burn is not
  // the other's load. The band is around the 4x CPU rate.
  const desktop = await page.context().newPage();
  const phone = await page.context().newPage();
  try {
    const holdDesktop = await applyProfile(desktop, 'desktop');
    const holdPhone = await applyProfile(phone, 'phone');
    const burn = (p) => p.evaluate(() => {
      // A multiply the compiler does not fold away, timed after one warm run
      // so the ratio is the throttle and not the optimiser's first pass.
      const loop = (n) => {
        let x = 0;
        for (let i = 0; i < n; i++) x = Math.imul(x + i, 1664525);
        return x;
      };
      loop(2e6);
      const start = performance.now();
      const x = loop(2e7);
      return { ms: performance.now() - start, x };
    });
    const desktopRun = await burn(desktop);
    const phoneRun = await burn(phone);
    const ratio = phoneRun.ms / desktopRun.ms;
    console.log(JSON.stringify({ check: 'phone-profile', desktopMs: desktopRun.ms, phoneMs: phoneRun.ms, ratio }));
    expect(desktopRun.x).not.toBe(0);
    expect(ratio).toBeGreaterThanOrEqual(3);
    expect(ratio).toBeLessThanOrEqual(5);
    void holdDesktop;
    void holdPhone;
  } finally {
    await desktop.close();
    await phone.close();
  }
});

test('tools status held 3s reports lcp over 2500', async ({ page }) => {
  // The catalogue is the largest paint. Held past the budget, a reader that
  // stops on the shell's own first text still has to fail.
  await signedIn(page, 'tools', { holdMs: 3000 });
  const reading = await measure(page, '/ui/tools/status', 'desktop', readyBuilt('tools'));
  console.log(JSON.stringify({ check: 'lcp-can-fail', ...reading }));
  expect(reading.lcp).toBeGreaterThan(LCP_BUDGET_MS);
});

test('a block inserted above the content reports cls over 0.1', async ({ page }) => {
  await signedIn(page, 'tools');
  // After load, the catalogue is on screen. A block above it then moves that
  // paint; inserted earlier it would land in an empty page and shift nothing.
  await page.addInitScript(() => {
    addEventListener('load', () => {
      setTimeout(() => {
        const block = document.createElement('div');
        block.style.height = '200px';
        document.getElementById('content').before(block);
      }, 500);
    });
  });
  const reading = await measure(page, '/ui/tools/status', 'desktop', readyBuilt('tools'));
  console.log(JSON.stringify({ check: 'cls-can-fail', ...reading }));
  expect(reading.cls).toBeGreaterThan(CLS_BUDGET);
});

test.afterAll(() => {
  // Playwright empties test-results at the start of a run, so a file here was
  // written by this run. A worker restart keeps the files; an in-memory list
  // would not. Each file is one (page, profile) row.
  const summary = {};
  let names = [];
  try {
    names = readdirSync(PERF_DIR).filter((name) => name.endsWith('.json'));
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
  }
  for (const name of names.sort()) {
    const row = JSON.parse(readFileSync(`${PERF_DIR}${name}`, 'utf8'));
    summary[row.page] ??= {};
    summary[row.page][row.profile] = { lcp: row.lcp, cls: row.cls };
  }
  const path = `${RESULTS}perf-summary.json`;
  mkdirSync(RESULTS, { recursive: true });
  writeFileSync(path, `${JSON.stringify(summary, null, 2)}\n`);
  console.log(`summary ${path}`);
});
