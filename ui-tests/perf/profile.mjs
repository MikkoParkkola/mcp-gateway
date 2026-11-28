// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// What every perf file shares: the two device profiles (Fast 4G and the 4x CPU
// throttle on phone), the fixture answers the measured pages need, the ranks a
// row reports, and the row files a run leaves for its summary. Moved here from
// vitals.perf.mjs so the interaction rows measure under the same profiles.
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { test } from '../tests/base.mjs';

// Chrome for Testing 156.0.8078.4 (Playwright 1.64.1 browsers.json) is chromium
// tag 156.0.8078.4, whose DEPS pins devtools-frontend
// 2d671c506c4e5f8958b027e26047deb0acfbd7f9. Fast 4G is Fast4GConditions in
// front_end/core/sdk/NetworkManager.ts at that commit:
//   download 9 * 1000 * 1000 / 8 * .9   (9 Mbps, adjusted)
//   upload   1.5 * 1000 * 1000 / 8 * .9 (1.5 Mbps, adjusted)
//   latency  60 * 2.75                  (60 ms RTT, adjusted)
// DevTools sends connectionType from the preset title "Fast 4G", which matches
// the "4g" entry and becomes cellular4g.
export const FAST_4G = {
  offline: false,
  latency: 60 * 2.75,
  downloadThroughput: 9 * 1000 * 1000 / 8 * 0.9,
  uploadThroughput: 1.5 * 1000 * 1000 / 8 * 0.9,
  connectionType: 'cellular4g',
};

// The same catalogue the Tools screen spec serves, so this row paints that
// screen. Schemas stay in the payload because the page parses them on load.
export const SERVERS = ['alpha', 'bravo', 'charlie', 'delta'];
export const TOOLS = SERVERS.flatMap((server) => Array.from({ length: 10 }, (_, i) => ({
  name: `${String.fromCharCode(106 - i)}_${server}_tool`,
  server,
  description: `Does thing ${i} on ${server}`,
  schema: { type: 'object', properties: Object.fromEntries(Array.from({ length: 120 }, (_, k) => [`field_${k}`, { type: 'string', description: `Field number ${k}` }])) },
  class: i % 2 ? 'write' : 'read',
  class_source: i % 3 ? 'inferred' : 'declared',
})));

/** Fast 4G transfer time in ms: the preset's latency plus the body at its download rate. */
export function fast4gTransferMs(bytes) {
  return FAST_4G.latency + (bytes / FAST_4G.downloadThroughput) * 1000;
}

// Rank in the sorted list. p75 is index ceil(0.75 * n) - 1. p50 is index ceil(0.5 * n) - 1.
export function rank(sorted, fraction) {
  return sorted[Math.ceil(fraction * sorted.length) - 1];
}

export function spread(values) {
  if (values.length === 0) return { loads: 0, p50: null, p75: null, max: null };
  const sorted = [...values].sort((a, b) => a - b);
  return { loads: sorted.length, p50: rank(sorted, 0.5), p75: rank(sorted, 0.75), max: sorted.at(-1) };
}

/**
 * Viewport for a cold context. Phone also sets the scale and the mobile flag
 * here: Playwright reapplies the context's device metrics on navigation, which
 * would otherwise put the scale back to 1 over a CDP override.
 */
export function loadContextOptions(profile) {
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
export async function applyProfile(page, profile) {
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
 * page.route fulfill answers from this process (Fetch.fulfillRequest) and never
 * enters Chrome's network throttler, so Network.emulateNetworkConditions does
 * not slow these bodies. The fixture server answers GET /ui/api/<path> from
 * fixtures/api/<path>.json. status.json is the signed-in answer, and there is
 * no signed-out status and no tools catalogue, so the phone profile waits the
 * Fast 4G transfer time before fulfilling.
 */
export async function fulfillApi(route, profile, payload) {
  const body = JSON.stringify(payload);
  if (profile === 'phone') {
    await new Promise((resolve) => setTimeout(resolve, fast4gTransferMs(Buffer.byteLength(body))));
  }
  await route.fulfill({ contentType: 'application/json', body });
}

/** Signed out, no key: the sign-in spec's status answer when the bearer is absent. */
export async function signedOut(page, { profile = 'desktop' } = {}) {
  await page.route('**/ui/api/status', (route) => fulfillApi(route, profile, {
    version: '4.0.0', auth: { enabled: true, signed_in: false, admin: false },
  }));
}

/** Signed in the way the screen specs are: an admin status, plus that screen's own answers. */
export async function signedIn(page, id, { holdMs = 0, profile = 'desktop' } = {}) {
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

/** One (page, profile) result, as `<dir><page>-<profile>.json`, one JSON line. */
export function writeRow(dir, result) {
  mkdirSync(dir, { recursive: true });
  writeFileSync(`${dir}${result.page}-${result.profile}.json`, `${JSON.stringify(result)}\n`);
}

/**
 * Every row file this run left in `dir`, parsed, in file-name order. Playwright
 * empties test-results when a run starts, so each file is this run's; a worker
 * restart keeps them where an in-memory list would not. No folder means no rows.
 */
export function readRows(dir) {
  let names = [];
  try {
    names = readdirSync(dir).filter((name) => name.endsWith('.json'));
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
  }
  return names.sort().map((name) => JSON.parse(readFileSync(`${dir}${name}`, 'utf8')));
}
