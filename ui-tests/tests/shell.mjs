// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Helpers for the shell specs. Test-only page registrations go through the
// shell module the page itself loaded (same URL, so the same module
// instance); nothing test-only ships in the shell.
import { readFileSync } from 'node:fs';
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

/** Wait until the shell has rendered something into its content area. */
export async function shellReady(page) {
  await page.waitForSelector('#content [data-rendered]');
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
