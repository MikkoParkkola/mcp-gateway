// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Helpers for the shell specs. Test-only page registrations go through the
// shell module the page itself loaded (same URL, so the same module
// instance); nothing test-only ships in the shell.
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { expect } from './base.mjs';

/** The sidebar's pages, in order: id and label. */
export const PAGES = [
  ['overview', 'Overview'],
  ['to' + 'do', 'To do'],
  ['servers', 'Servers'],
  ['tools', 'Tools'],
  ['activity', 'Activity'],
  ['costs', 'Costs'],
  ['access', 'Access'],
  ['policies', 'Policies'],
  ['gateway', 'Gateway'],
];

export const TABS = ['status', 'actions', 'settings'];

/** Sidebar pages whose screen is built; every other page shows the not-built state. */
export const BUILT = ['overview', 'servers', 'tools', 'gateway', 'activity'];

/** The fixture page that hides a tab, and the tab it hides. */
export const HIDDEN = { page: 'tools', tab: 'settings' };

/** The URL of the shell's ES module, read from the document. */
export async function shellModuleUrl(page) {
  const url = await page.evaluate(
    () => document.querySelector('script[type="module"][src^="/ui/assets/"]')?.src ?? null,
  );
  if (!url) throw new Error('the shell document loads no module from /ui/assets/');
  return url;
}

/**
 * Ask the fixture server to inject fixtures/fixture-pages.mjs into the shell
 * document: real tabs for every sidebar page, except that HIDDEN.page has no
 * HIDDEN.tab. Set before navigation, so the shell's cold start sees them.
 * With `probes`, Policies › Status and Costs › Status read the page-error
 * probes instead (see fixtures/fixture-pages.mjs).
 */
export async function withFixturePages(page, { title, probes } = {}) {
  const url = `http://127.0.0.1:${process.env.UI_TESTS_PORT ?? 4173}`;
  const cookies = [{ name: 'fixture-pages', value: '1', url }];
  if (title) cookies.push({ name: 'fixture-title', value: encodeURIComponent(title), url });
  if (probes) cookies.push({ name: 'fixture-probes', value: '1', url });
  await page.context().addCookies(cookies);
}

/** The tooltip module's hashed asset path, read from the shell directory; throws while none exists. */
export function tooltipModuleUrl() {
  const dir = fileURLToPath(new URL('../../src/gateway/ui/shell/', import.meta.url));
  const name = readdirSync(dir).find((f) => /^tooltip\.[0-9a-f]{12}\.js$/.test(f));
  if (!name) throw new Error('no tooltip module (tooltip.<hash>.js) in src/gateway/ui/shell');
  return `/ui/assets/${name}`;
}

/** The tooltip stylesheet's hashed asset path; the module links it itself when it loads. */
export function tooltipCssUrl() {
  const dir = fileURLToPath(new URL('../../src/gateway/ui/shell/', import.meta.url));
  const name = readdirSync(dir).find((f) => /^tooltip\.[0-9a-f]{12}\.css$/.test(f));
  if (!name) throw new Error('no tooltip stylesheet (tooltip.<hash>.css) in src/gateway/ui/shell');
  return `/ui/assets/${name}`;
}

// clock.install() leaves virtual time running with the wall clock, so a slow
// step between hover() and runFor() can fire a timer early. Pausing makes
// runFor() the only thing that moves time. The pause lands 5 s ahead because
// the clock still runs between reading it and pausing; it is called right
// after mount, before anything arms a timer, so the jump fires nothing.
export const pauseClock = async (page) => page.clock.pauseAt(await page.evaluate(() => Date.now() + 5000));

// A runFor() only fires the timers that exist when it starts. A timer the page arms
// after some answer comes back (a retry wait, a reconnect backoff) may not exist yet
// when the test has seen the request go out, and then the advance moves time past
// nothing. trackTimers() lets a test wait for that one timer first (advanceArmed).
//
// It wraps whichever setTimeout and clearTimeout the page has when its init script runs.
// A test with a fake clock calls it after page.clock.install(), so the fake timers are
// the ones wrapped; called first, the clock would replace the wrapper and nothing would be
// seen, and advanceArmed() fails loudly. A test on real timers (pendingFrom) needs no clock.
export async function trackTimers(page) {
  await page.addInitScript(() => {
    const pending = new Map();
    const arm = window.setTimeout;
    const disarm = window.clearTimeout;
    window.setTimeout = function (fn, ms, ...rest) {
      if (typeof fn !== 'function') return arm.call(this, fn, ms, ...rest);
      const entry = { ms: Number(ms) || 0, stack: new Error().stack ?? '' };
      // A plain function, so the callback gets whatever receiver the clock calls it with.
      const id = arm.call(this, function (...a) { pending.delete(id); return Reflect.apply(fn, this, a); }, ms, ...rest);
      pending.set(id, entry);
      return id;
    };
    window.clearTimeout = function (id) {
      pending.delete(id);
      return disarm.call(this, id);
    };
    window.__pendingTimers = () => [...pending.values()];
  });
}

/** The function names on a recorded stack, below the tracker's own frame. */
function callersOf(stack) {
  return stack.split('\n').slice(2)
    .map((line) => line.match(/^\s*at (?:async )?(.+?) \(/)?.[1] ?? '<anonymous>');
}

/**
 * Wait, in real time, until the page has a pending timer of exactly `ms` that was armed
 * from the function named `from`; only then run the clock for `by` (default `ms`).
 * Delay alone is not enough to know it is the right timer: other timers in the shell
 * share delays (the announcer's 500 ms dwell, the 2000 ms refusal body). On a timeout it
 * throws with every pending timer listed, and the clock has not moved.
 */
export async function advanceArmed(page, ms, from, by = ms) {
  if (await page.evaluate(() => typeof window.__pendingTimers !== 'function')) {
    throw new Error('advanceArmed needs trackTimers(page), called after page.clock.install()');
  }
  let pending = [];
  let broke = null; // a failure of the read itself (a closed page, a thrown evaluate)
  const armed = async () => {
    try {
      const timers = await page.evaluate(() => window.__pendingTimers());
      pending = timers.map((t) => ({ ms: t.ms, callers: callersOf(t.stack) }));
      broke = null;
    } catch (err) {
      broke = err;
      throw err;
    }
    return pending.some((t) => t.ms === ms && t.callers.includes(from));
  };
  try {
    await expect.poll(armed).toBe(true);
  } catch {
    if (broke) throw broke; // its own error, not "no timer armed"
    const list = pending.map((t) => `${t.ms} ms from ${t.callers.slice(0, 3).join(' < ')}`).join('; ') || 'none';
    throw new Error(`no ${ms} ms timer armed from ${from}; pending: ${list}`);
  }
  await page.clock.runFor(by);
}

/**
 * The delays of the page's pending timers that were armed from the function named
 * `from` (needs trackTimers). Keying on the arming function, not on the delay alone,
 * keeps another part of the shell that happens to use the same delay out of the count.
 * A function run as an event handler shows on the stack with its receiver in front
 * ("HTMLButtonElement.start"), so that form counts as `from` too.
 */
export async function pendingFrom(page, from) {
  const timers = await page.evaluate(() => window.__pendingTimers());
  const named = (c) => c === from || c.endsWith(`.${from}`);
  return timers.filter((t) => callersOf(t.stack).some(named)).map((t) => t.ms);
}

/** Wait until the shell has rendered something into its content area. */
export async function shellReady(page) {
  await page.waitForSelector('#content [data-rendered]');
}

/**
 * The screens' placement check: open the tooltip for a copy id by focusing its
 * trigger, and return every visible focusable control it covers. A screen's
 * journey test expects it to be empty for each trigger it draws:
 *   expect(await tooltipCoversNothing(page, 'servers.status.paused')).toEqual([]);
 *
 * The rule (lead rulings 2026-10-26 and 2026-10-28), whose purpose is that a
 * tooltip never hides the next action or the thing it explains:
 * - a discrete control (a link, button, input, select, textarea, summary) is
 *   covered on any intersection, including one inside a larger container;
 * - a large focusable container (a region, or any other tabindex element bigger
 *   than the popup) is covered when the popup hides its centre point, and also
 *   when it hides more than half of its visible area.
 * Controls inside the tooltip itself do not count.
 */
export async function tooltipCoversNothing(page, id) {
  await page.locator(`.has-tip[data-tip="${id}"] button`).focus();
  return page.evaluate(async (id) => {
    await Promise.all(document.getAnimations().map((a) => a.finished));
    const wrap = document.querySelector(`.has-tip[data-tip="${id}"]`);
    const pop = wrap.querySelector('.tip').getBoundingClientRect();
    const discrete = 'a[href], button, input, select, textarea, summary';
    const sel = `${discrete}, [tabindex]:not([tabindex="-1"])`;
    const overlap = (r) => Math.max(0, Math.min(r.right, pop.right) - Math.max(r.left, pop.left))
      * Math.max(0, Math.min(r.bottom, pop.bottom) - Math.max(r.top, pop.top));
    const visible = (r) => Math.max(0, Math.min(r.right, innerWidth) - Math.max(r.left, 0))
      * Math.max(0, Math.min(r.bottom, innerHeight) - Math.max(r.top, 0));
    const popArea = pop.width * pop.height;
    return [...document.querySelectorAll(sel)]
      .filter((e) => !wrap.contains(e) && e.checkVisibility() && !e.disabled)
      .filter((e) => {
        const r = e.getBoundingClientRect();
        if (overlap(r) === 0) return false;
        const container = !e.matches(discrete) && (e.getAttribute('role') === 'region' || r.width * r.height > popArea);
        if (!container) return true;
        const cx = (r.left + r.right) / 2;
        const cy = (r.top + r.bottom) / 2;
        const centre = cx >= pop.left && cx <= pop.right && cy >= pop.top && cy <= pop.bottom;
        return centre || overlap(r) > visible(r) / 2;
      })
      .map((e) => `${e.tagName.toLowerCase()} "${(e.getAttribute('aria-label') ?? e.textContent).trim().slice(0, 40)}"`);
  }, id);
}

/** The ServerState variants, read from the gateway's own source, in snake_case. */
export function serverStates() {
  const file = fileURLToPath(new URL('../../src/backend/server_state.rs', import.meta.url));
  const source = readFileSync(file, 'utf8');
  const head = source.slice(0, source.indexOf('pub enum ServerState {'));
  // The wire names are the variants in snake_case only while nothing renames them.
  expect(head.slice(head.lastIndexOf('#[derive')), 'ServerState keeps rename_all = "snake_case"').toContain('rename_all = "snake_case"');
  const body = source.slice(source.indexOf('pub enum ServerState {'));
  const block = body.slice(body.indexOf('{') + 1, body.indexOf('\n}'));
  expect(block, 'no ServerState variant is renamed one by one').not.toMatch(/\b(rename|alias)\b/);
  // Every line must be a unit variant, a comment, an attribute or blank: a form this
  // reader does not know fails here instead of being skipped.
  const variants = [];
  let inAttr = 0;
  for (const raw of block.split('\n')) {
    const line = raw.trim();
    if (inAttr > 0 || line.startsWith('#[')) {
      inAttr += (line.match(/[[(]/g) ?? []).length - (line.match(/[\])]/g) ?? []).length;
      continue;
    }
    if (line === '' || line.startsWith('//')) continue;
    const unit = line.match(/^([A-Z][A-Za-z]+),$/);
    expect(unit, `a ServerState line this test cannot read: ${line}`).not.toBeNull();
    variants.push(unit[1]);
  }
  return variants.map((v) => v.replace(/[A-Z]/g, (c, i) => (i ? '_' : '') + c.toLowerCase()));
}

/**
 * A held stream for this test. The fixture-stream cookie only names the
 * channel on the fixture server; it is test plumbing, not a session.
 */
export async function heldStream(page, request, testInfo, setup = {}) {
  const name = testInfo.testId.replace(/[^\w-]/g, '-');
  await request.post(`/__stream/${name}/setup`, { data: setup });
  const url = `http://127.0.0.1:${process.env.UI_TESTS_PORT ?? 4173}`;
  await page.context().addCookies([{ name: 'fixture-stream', value: name, url }]);
  const log = async () => (await request.get(`/__stream/${name}/log`)).json();
  return {
    log,
    connects: async () => (await log()).length,
    send: (text) => request.post(`/__stream/${name}/send`, { data: text, headers: { 'content-type': 'text/plain' } }),
    end: () => request.post(`/__stream/${name}/end`),
  };
}

/** One SSE frame as the gateway writes it (conn.rs); hello carries a retry hint and no id. */
export function frame(event, data, id = null) {
  const head = event === 'hello' ? 'retry: 3000\n' : '';
  return `${head}event: ${event}\n${id ? `id: ${id}\n` : ''}data: ${JSON.stringify(data)}\n\n`;
}

/** From before the shell loads, keep a count of live gateway-status listeners as window.__statusListeners(). */
export const countListeners = (page) => page.addInitScript(() => {
  const fns = new Set();
  for (const [name, op] of [['addEventListener', 'add'], ['removeEventListener', 'delete']]) {
    const real = window[name];
    window[name] = function (type, fn, ...more) {
      if (type === 'gateway-status') fns[op](fn);
      return real.call(this, type, fn, ...more);
    };
  }
  window.__statusListeners = () => fns.size;
});
