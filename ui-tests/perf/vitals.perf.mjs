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
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { test, expect } from '../tests/base.mjs';
import { BUILT, shellReady } from '../tests/shell.mjs';
import {
  applyProfile, fast4gTransferMs, loadContextOptions, readRows, signedIn, signedOut, spread, writeRow,
} from './profile.mjs';

const RESULTS = fileURLToPath(new URL('../test-results/', import.meta.url));
const PERF_DIR = `${RESULTS}perf/`;

const LCP_BUDGET_MS = 2500;
const CLS_BUDGET = 0.1;

// Which budgets fail a row (and the CI step). LCP blocks: its spread on the CI
// runner (20 loads per row) cleared the budget by 2x or more with max - p50 of
// 44 ms or less. CLS blocks since the shell holds its layout from first paint:
// Tools p75 desktop 0.0995 -> 0.0019 and phone 0.0453 -> 0.0209 (20 loads per row,
// max before 0.1130 and 0.1151; CI measured desktop 0.1137 before), every row
// now far under 0.1.
const BLOCKING = { lcp: true, cls: true };

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

// A body of this size, served by the fixture server as image/png. That type is
// under compression.json's never-gzip prefixes, so the bytes on the wire are
// this length. fetch() would inflate a gzipped body and the bar below would
// describe a transfer that never happened.
const PROBE_BYTES = 200_000;

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
      writeRow(PERF_DIR, result);
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
  // Both budgets block: CLS over its budget fails the row.
  expect(BLOCKING).toEqual({ lcp: true, cls: true });
  expect(misses(row(900, 0.1137))).toEqual({ blocking: ['cls p75 0.1137 is not under 0.1'], reported: [] });
  expect(misses(row(900, 0.0999))).toEqual({ blocking: [], reported: [] });
  // The flag decides, not the number: the same reading is only reported when CLS does not block.
  expect(misses(row(900, 0.1137), { lcp: true, cls: false })).toEqual({ blocking: [], reported: ['cls p75 0.1137 is not under 0.1'] });
  // A p75 that was never measured is a miss on its side: a blocking gate never passes on a missing number.
  expect(misses(row(null, null))).toEqual({ blocking: ['lcp p75 was not measured', 'cls p75 was not measured'], reported: [] });
  expect(misses(row(Number.NaN, 0.05)).blocking).toEqual(['lcp p75 was not measured']);
});

test('the moved profile helpers send, write and fold exactly what they did before the move', async () => {
  // Fixed inputs; every expected value is a literal taken from the pre-move code.
  const sent = [];
  const viewports = [];
  const fakePage = {
    setViewportSize: async (size) => viewports.push(size),
    context: () => ({ newCDPSession: async () => ({ send: async (method, params) => sent.push([method, params]) }) }),
  };
  expect(await applyProfile(fakePage, 'desktop')).toBe(null);
  expect(viewports).toEqual([{ width: 1440, height: 900 }]);
  expect(sent).toEqual([]);
  expect(await applyProfile(fakePage, 'phone')).not.toBe(null);
  expect(sent).toEqual([
    ['Emulation.setCPUThrottlingRate', { rate: 4 }],
    ['Network.emulateNetworkConditions', {
      offline: false, latency: 165, downloadThroughput: 1012500, uploadThroughput: 168750, connectionType: 'cellular4g',
    }],
    ['Emulation.setDeviceMetricsOverride', { width: 412, height: 823, deviceScaleFactor: 1.75, mobile: true }],
  ]);
  const dir = `${mkdtempSync(`${tmpdir()}/perf-move-`)}/`;
  const row = (page, profile, loadsMeasured) => ({
    page, profile, loadsAttempted: 2, loadsMeasured, errors: loadsMeasured === 2 ? [] : ['no largest-contentful-paint entry'],
    retried: [], lcp: { loads: loadsMeasured, p50: 900, p75: 950, max: 990, budget: 2500, blocks: true },
    cls: { loads: loadsMeasured, p50: 0, p75: 0.01, max: 0.02, budget: 0.1, blocks: true }, blocking: [], reported: [],
  });
  writeRow(dir, row('tools', 'phone', 1));
  writeRow(dir, row('gateway', 'desktop', 2));
  expect(readFileSync(`${dir}tools-phone.json`, 'utf8')).toBe('{"page":"tools","profile":"phone","loadsAttempted":2,"loadsMeasured":1,"errors":["no largest-contentful-paint entry"],"retried":[],"lcp":{"loads":1,"p50":900,"p75":950,"max":990,"budget":2500,"blocks":true},"cls":{"loads":1,"p50":0,"p75":0.01,"max":0.02,"budget":0.1,"blocks":true},"blocking":[],"reported":[]}\n');
  expect(foldSummary(readRows(dir))).toEqual({
    gateway: { desktop: {
      lcp: { loads: 2, p50: 900, p75: 950, max: 990, budget: 2500, blocks: true },
      cls: { loads: 2, p50: 0, p75: 0.01, max: 0.02, budget: 0.1, blocks: true },
      loadsAttempted: 2, loadsMeasured: 2, errors: [], blocking: [], reported: [], retried: [], incomplete: false,
    } },
    tools: { phone: {
      lcp: { loads: 1, p50: 900, p75: 950, max: 990, budget: 2500, blocks: true },
      cls: { loads: 1, p50: 0, p75: 0.01, max: 0.02, budget: 0.1, blocks: true },
      loadsAttempted: 2, loadsMeasured: 1, errors: ['no largest-contentful-paint entry'], blocking: [], reported: [],
      retried: [], incomplete: true,
    } },
  });
  // The ranks the rows report: p50 index ceil(0.5n)-1, p75 index ceil(0.75n)-1.
  expect(spread([5, 1, 4, 2, 3])).toEqual({ loads: 5, p50: 3, p75: 4, max: 5 });
  expect(spread([])).toEqual({ loads: 0, p50: null, p75: null, max: null });
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

/** The run's rows, folded by page then profile into the summary the CI step prints. */
function foldSummary(rows) {
  const summary = {};
  for (const row of rows) {
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
  return summary;
}

test.afterAll(() => {
  // Each row file is one (page, profile) row this run wrote (profile.mjs readRows).
  const summary = foldSummary(readRows(PERF_DIR));
  const path = `${RESULTS}perf-summary.json`;
  mkdirSync(RESULTS, { recursive: true });
  const text = JSON.stringify(summary, null, 2);
  writeFileSync(path, `${text}\n`);
  console.log(`summary ${path}`);
  console.log(text);
});
