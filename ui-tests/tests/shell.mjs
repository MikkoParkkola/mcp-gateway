// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Helpers for the shell specs. Test-only page registrations go through the
// shell module the page itself loaded (same URL, so the same module
// instance); nothing test-only ships in the shell.

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
 */
export async function withFixturePages(page, { title } = {}) {
  const url = `http://127.0.0.1:${process.env.UI_TESTS_PORT ?? 4173}`;
  const cookies = [{ name: 'fixture-pages', value: '1', url }];
  if (title) cookies.push({ name: 'fixture-title', value: encodeURIComponent(title), url });
  await page.context().addCookies(cookies);
}

/** Wait until the shell has rendered something into its content area. */
export async function shellReady(page) {
  await page.waitForSelector('#content [data-rendered]');
}
