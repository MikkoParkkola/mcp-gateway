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
export const BUILT = ['tools'];

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
