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

// Which budgets fail a row (and the CI step). LCP blocks: its spread on the CI
// runner (20 loads per row) cleared the budget by 2x or more with max - p50 of
// 44 ms or less. CLS is reported only until the shell holds its layout from
// first paint; that change turns it on with its own before and after numbers.
const BLOCKING = { lcp: true, cls: false };

/**
 * The budgets a row misses, as text, split by whether they block. A p75 at or
 * over its budget is a miss; under it is not. A p75 that was never measured is
 * a miss too: a gate must not pass on a number it does not have.
 */
function misses(row, blocking = BLOCKING) {
  const found = { blocking: [], reported: [] };
  const check = (metric, p75, budget, unit) => {
    const side = blocking[metric] ? 'blocking' : 'reported';
    if (!Number.isFinite(p75)) found[side].push(`${metric} p75 was not measured`);
    else if (p75 >= budget) found[side].push(`${metric} p75 ${p75}${unit} is not under ${budget}${unit}`);
  };
  check('lcp', row.lcp.p75, LCP_BUDGET_MS, ' ms');
  check('cls', row.cls.p75, CLS_BUDGET, '');
  return found;
}
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

/** Fast 4G transfer time in ms: the preset's latency plus the body at its download rate. */
function fast4gTransferMs(bytes) {
  return FAST_4G.latency + (bytes / FAST_4G.downloadThroughput) * 1000;
}

// A body of this size, served by the fixture server as image/png. That type is
// under compression.json's never-gzip prefixes, so the bytes on the wire are
// this length. fetch() would inflate a gzipped body and the bar below would
// describe a transfer that never happened.
const PROBE_BYTES = 200_000;

// Rank in the sorted list. p75 is index ceil(0.75 * n) - 1. p50 is index ceil(0.5 * n) - 1.
function rank(sorted, fraction) {
  return sorted[Math.ceil(fraction * sorted.length) - 1];
}

function spread(values) {
  if (values.length === 0) return { loads: 0, p50: null, p75: null, max: null };
  const sorted = [...values].sort((a, b) => a - b);
  return { loads: sorted.length, p50: rank(sorted, 0.5), p75: rank(sorted, 0.75), max: sorted.at(-1) };
}

/**
 * Viewport for a cold context. Phone also sets the scale and the mobile flag
 * here: Playwright reapplies the context's device metrics on navigation, which
 * would otherwise put the scale back to 1 over a CDP override.
 */
function loadContextOptions(profile) {
  const baseURL = test.info().project.use.baseURL;
  if (profile === 'phone') {
    return {
      baseURL,
      viewport: { width: 412, height: 823 },
      deviceScaleFactor: 1.75,
      isMobile: true,
    };
  }
  return { baseURL, viewport: { width: 1440, height: 900 } };
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

/**
 * Record LCP and CLS before any paint, then read them after `ready` and a settle.
 * CLS is the largest session window: shifts without recent input, grouped so a
 * window ends after a 1 s gap from the previous shift or at 5 s from its first.
 * The lifetime sum is not the metric. A missing LCP entry is a failed load.
 */
async function measure(page, url, profile, ready) {
  const session = await applyProfile(page, profile);
  await page.addInitScript(() => {
    const vitals = { lcp: null, cls: 0 };
    window.__vitals = vitals;
    // The last entry is the largest paint so far; later entries replace it.
    new PerformanceObserver((list) => {
      const last = list.getEntries().at(-1);
      if (last) vitals.lcp = last.startTime;
    }).observe({ type: 'largest-contentful-paint', buffered: true });
    // Session windows, as the CLS metric defines them. A window ends when the
    // next shift is 1 s or more after the previous one, or 5 s or more after
    // the window's first shift. CLS is the largest window's sum.
    const GAP_MS = 1000;
    const WINDOW_MS = 5000;
    let sessionValue = 0;
    let sessionStart = 0;
    let sessionLast = 0;
    new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        if (entry.hadRecentInput) continue;
        const inWindow = sessionValue
          && entry.startTime - sessionLast < GAP_MS
          && entry.startTime - sessionStart < WINDOW_MS;
        if (inWindow) sessionValue += entry.value;
        else {
          sessionValue = entry.value;
          sessionStart = entry.startTime;
        }
        sessionLast = entry.startTime;
        if (sessionValue > vitals.cls) vitals.cls = sessionValue;
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
  if (vitals.lcp === null) throw new Error('no largest-contentful-paint entry');
  void session;
  return { lcp: vitals.lcp, cls: vitals.cls };
}

/**
 * page.route fulfill answers from this process (Fetch.fulfillRequest) and never
 * enters Chrome's network throttler, so Network.emulateNetworkConditions does
 * not slow these bodies. The fixture server answers GET /ui/api/<path> from
 * fixtures/api/<path>.json. status.json is the signed-in answer, and there is
 * no signed-out status and no tools catalogue, so the phone profile waits the
 * Fast 4G transfer time before fulfilling.
 */
async function fulfillApi(route, profile, payload) {
  const body = JSON.stringify(payload);
  if (profile === 'phone') {
    await new Promise((resolve) => setTimeout(resolve, fast4gTransferMs(Buffer.byteLength(body))));
  }
  await route.fulfill({ contentType: 'application/json', body });
}

/** Signed out, no key: the sign-in spec's status answer when the bearer is absent. */
async function signedOut(page, { profile = 'desktop' } = {}) {
  await page.route('**/ui/api/status', (route) => fulfillApi(route, profile, {
    version: '4.0.0', auth: { enabled: true, signed_in: false, admin: false },
  }));
}

/** Signed in the way the screen specs are: an admin status, plus that screen's own answers. */
async function signedIn(page, id, { holdMs = 0, profile = 'desktop' } = {}) {
  await page.route('**/ui/api/status', (route) => fulfillApi(route, profile, {
    auth: { enabled: true, signed_in: true, admin: true },
  }));
  if (id === 'tools') {
    await page.route('**/ui/api/tools**', async (route) => {
      // Held in this process, so the phone's CPU throttle does not stretch the wait.
      if (holdMs) await new Promise((resolve) => setTimeout(resolve, holdMs));
      await fulfillApi(route, profile, { tools: TOOLS, total: TOOLS.length });
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
    const says = (metric, budget) => `${metric} p75 under ${budget} ${BLOCKING[metric] ? 'blocks' : 'is reported'}`;
    test(`${row.page} ${profile}: ${says('lcp', '2500 ms')}, ${says('cls', '0.1')}`, async ({ browser }) => {
      const readings = [];
      const errors = [];
      // A load that failed once and then measured on its retry. Kept in the row,
      // so a runner that keeps dropping loads shows in the summary.
      const retried = [];
      let loadsAttempted = 0;
      let loadsMeasured = 0;
      // A fresh context per load, closed before the next one. A new page in
      // a shared context would reuse the previous load's HTTP cache and storage.
      const once = async () => {
        let context;
        try {
          context = await browser.newContext(loadContextOptions(profile));
          const fresh = await context.newPage();
          await row.prepare(fresh, { profile });
          return await measure(fresh, row.url, profile, row.ready);
        } finally {
          if (context) await context.close().catch(() => {});
        }
      };
      const message = (err) => (err instanceof Error ? err.message : String(err));
      for (let i = 0; i < LOADS; i++) {
        loadsAttempted += 1;
        // One retry: the job blocks on this row, and one dropped load on a shared
        // runner is not a budget miss. A load that fails twice fails the row.
        try {
          readings.push(await once());
          loadsMeasured += 1;
        } catch (first) {
          try {
            readings.push(await once());
            loadsMeasured += 1;
            retried.push(message(first));
          } catch (second) {
            // Both errors: the first may carry the cause the retry only repeats.
            errors.push(`${message(first)} (retry: ${message(second)})`);
          }
        }
      }
      const lcp = spread(readings.map((r) => r.lcp));
      const cls = spread(readings.map((r) => r.cls));
      const result = {
        page: row.page,
        profile,
        loadsAttempted,
        loadsMeasured,
        errors,
        retried,
        lcp: { ...lcp, budget: LCP_BUDGET_MS, blocks: BLOCKING.lcp },
        cls: { ...cls, budget: CLS_BUDGET, blocks: BLOCKING.cls },
      };
      const missed = misses(result);
      result.blocking = missed.blocking;
      result.reported = missed.reported;
      // On disk before the assertions, so a miss or a partial run still reaches the summary.
      writeRow(result);
      console.log(JSON.stringify({ page: row.page, profile, loadsAttempted, loadsMeasured, errors, retried, lcp, cls, blocking: missed.blocking, reported: missed.reported }));
      // A load that failed twice fails the row: a budget judged on fewer loads than asked is not judged.
      if (errors.length) throw new Error(errors.join('\n'));
      expect(missed.blocking, 'a blocking budget missed').toEqual([]);
    });
  }
}

test('the phone profile is applied', async ({ browser }) => {
  // Separate contexts so each burn is cold, and sequential so one burn is not
  // the other's load. No route on these contexts: a fulfilled or continued
  // route bypasses the network throttler this check has to observe.
  // The band is around the 4x CPU rate.
  const desktopContext = await browser.newContext(loadContextOptions('desktop'));
  const phoneContext = await browser.newContext(loadContextOptions('phone'));
  const desktop = await desktopContext.newPage();
  const phone = await phoneContext.newPage();
  try {
    const holdDesktop = await applyProfile(desktop, 'desktop');
    const holdPhone = await applyProfile(phone, 'phone');
    // The shell document, not the classic stand-in. Classic has no viewport
    // meta, so a mobile emulation lays it out at the 980px fallback and
    // innerWidth is not the profile width. The shell sets width=device-width.
    // Load finishes before the probe, so that request is the timed transfer.
    await desktop.goto('/ui/overview/status', { waitUntil: 'load' });
    await phone.goto('/ui/overview/status', { waitUntil: 'load' });
    const metrics = await phone.evaluate(() => ({
      innerWidth: window.innerWidth,
      devicePixelRatio: window.devicePixelRatio,
    }));
    const probe = `/__compression?type=${encodeURIComponent('image/png')}&len=${PROBE_BYTES}`;
    const timeTransfer = (p) => p.evaluate(async (path) => {
      const start = performance.now();
      const res = await fetch(path, { cache: 'no-store' });
      const buf = await res.arrayBuffer();
      return { ms: performance.now() - start, bytes: buf.byteLength, status: res.status };
    }, probe);
    const desktopNet = await timeTransfer(desktop);
    const phoneNet = await timeTransfer(phone);
    const transferMs = fast4gTransferMs(PROBE_BYTES);
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
    console.log(JSON.stringify({
      check: 'phone-profile',
      innerWidth: metrics.innerWidth,
      devicePixelRatio: metrics.devicePixelRatio,
      desktopMs: desktopNet.ms,
      phoneMs: phoneNet.ms,
      transferMs,
      bytes: phoneNet.bytes,
      cpuDesktopMs: desktopRun.ms,
      cpuPhoneMs: phoneRun.ms,
      ratio,
    }));
    expect(metrics.innerWidth).toBe(412);
    expect(metrics.devicePixelRatio).toBe(1.75);
    expect(desktopNet.status).toBe(200);
    expect(phoneNet.status).toBe(200);
    expect(desktopNet.bytes).toBe(PROBE_BYTES);
    expect(phoneNet.bytes).toBe(PROBE_BYTES);
    // At least the Fast 4G transfer time, so a run with no network throttle
    // (the desktop figure beside it) fails this bar.
    expect(phoneNet.ms).toBeGreaterThanOrEqual(transferMs);
    expect(desktopNet.ms).toBeLessThan(transferMs);
    expect(desktopRun.x).not.toBe(0);
    expect(ratio).toBeGreaterThanOrEqual(3);
    expect(ratio).toBeLessThanOrEqual(5);
    void holdDesktop;
    void holdPhone;
  } finally {
    await desktopContext.close();
    await phoneContext.close();
  }
});

test('the gate: a blocking budget missed fails the row, a reported one does not', () => {
  const row = (lcpP75, clsP75) => ({ lcp: { p75: lcpP75 }, cls: { p75: clsP75 } });
  // Both sides of each budget: at the budget is a miss, just under is not.
  expect(misses(row(2500, 0.05))).toEqual({ blocking: ['lcp p75 2500 ms is not under 2500 ms'], reported: [] });
  expect(misses(row(2499, 0.05))).toEqual({ blocking: [], reported: [] });
  // CLS over its budget is reported and does not block while BLOCKING says so.
  expect(BLOCKING).toEqual({ lcp: true, cls: false });
  expect(misses(row(900, 0.1137))).toEqual({ blocking: [], reported: ['cls p75 0.1137 is not under 0.1'] });
  // The same reading blocks once CLS is turned on: the flag decides, not the number.
  expect(misses(row(900, 0.1137), { lcp: true, cls: true })).toEqual({ blocking: ['cls p75 0.1137 is not under 0.1'], reported: [] });
  // A p75 that was never measured is a miss on its side: a blocking gate never passes on a missing number.
  expect(misses(row(null, null))).toEqual({ blocking: ['lcp p75 was not measured'], reported: ['cls p75 was not measured'] });
  expect(misses(row(Number.NaN, 0.05)).blocking).toEqual(['lcp p75 was not measured']);
});

test('tools status held 3s reports lcp over 2500', async ({ page }) => {
  // The catalogue is the largest paint. Held past the budget, a reader that
  // stops on the shell's own first text still has to fail.
  await signedIn(page, 'tools', { holdMs: 3000 });
  const reading = await measure(page, '/ui/tools/status', 'desktop', readyBuilt('tools'));
  console.log(JSON.stringify({ check: 'lcp-can-fail', ...reading }));
  expect(reading.lcp).toBeGreaterThan(LCP_BUDGET_MS);
});

test('a block inserted above the sign-in reports cls over 0.1', async ({ browser }) => {
  // The sign-in view's own CLS is about 0. The same view with a 200px block
  // 500 ms after load must clear 0.1, and without the block must stay under
  // it, so a pass is this shift. The body is a row and the section fills the
  // viewport; the block stacks above that section or the section does not
  // move. Inserted earlier, the block lands in an empty page and shifts nothing.
  const open = async () => {
    const context = await browser.newContext(loadContextOptions('desktop'));
    const page = await context.newPage();
    await signedOut(page);
    return { context, page };
  };
  const quiet = await open();
  const shifted = await open();
  try {
    await shifted.page.addInitScript(() => {
      addEventListener('load', () => {
        setTimeout(() => {
          const block = document.createElement('div');
          block.dataset.clsBlock = '';
          block.style.cssText = 'height:200px;width:100%;flex:0 0 200px';
          document.body.style.flexDirection = 'column';
          document.getElementById('signin').before(block);
        }, 500);
      });
    });
    const baseline = await measure(quiet.page, '/ui/overview/status', 'desktop', readySignIn);
    const reading = await measure(shifted.page, '/ui/overview/status', 'desktop', async (page) => {
      await readySignIn(page);
      await page.waitForSelector('[data-cls-block]');
    });
    console.log(JSON.stringify({ check: 'cls-can-fail', baseline, shifted: reading }));
    expect(baseline.cls).toBeLessThan(CLS_BUDGET);
    expect(reading.cls).toBeGreaterThan(CLS_BUDGET);
  } finally {
    await quiet.context.close();
    await shifted.context.close();
  }
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
    const errors = row.errors ?? [];
    summary[row.page][row.profile] = {
      lcp: row.lcp,
      cls: row.cls,
      loadsAttempted: row.loadsAttempted,
      loadsMeasured: row.loadsMeasured,
      errors,
      // Misses: those that failed the row, and those of budgets that do not block yet (BLOCKING).
      blocking: row.blocking ?? [],
      reported: row.reported ?? [],
      retried: row.retried ?? [],
      incomplete: row.loadsMeasured !== row.loadsAttempted || errors.length > 0,
    };
  }
  const path = `${RESULTS}perf-summary.json`;
  mkdirSync(RESULTS, { recursive: true });
  const text = JSON.stringify(summary, null, 2);
  writeFileSync(path, `${text}\n`);
  console.log(`summary ${path}`);
  console.log(text);
});
