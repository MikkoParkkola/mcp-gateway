// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// A page waiting more than about 300 ms shows a loading state, and the frame
// never waits on any /ui/api answer (tooltip copy included): rows G1-G5.
// One state glossary, kept in step with the gateway's ServerState: rows W1-W3.
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { test, expect } from './base.mjs';
import { withFixturePages, shellReady, shellModuleUrl } from './shell.mjs';

const PROBE = '**/ui/api/page-probe*';
const loading = (page) => page.locator('#content [data-state="loading"]');

/** Record every entry added to the announcer. */
async function recordAnnouncements(page) {
  await page.addInitScript(() => {
    window.__writes = [];
    addEventListener('DOMContentLoaded', () => {
      const region = document.getElementById('announcer');
      if (!region) return;
      new MutationObserver((records) => {
        for (const r of records) for (const n of r.addedNodes) window.__writes.push((n.textContent ?? '').trim());
      }).observe(region, { childList: true });
    });
  });
}

/** Note whether a loading state was ever inserted into the content. */
async function watchLoading(page) {
  await page.addInitScript(() => {
    window.__sawLoading = false;
    addEventListener('DOMContentLoaded', () => {
      new MutationObserver(() => {
        if (document.querySelector('#content [data-state="loading"]')) window.__sawLoading = true;
      }).observe(document.getElementById('content'), { childList: true, subtree: true });
    });
  });
}

async function shellCall(page, name, ...args) {
  const url = await shellModuleUrl(page);
  return page.evaluate(async ([u, n, a]) => { const m = await import(u); return m[n](...a); }, [url, name, args]);
}

/** A probe that answers `value` once `release()` is called. */
function heldProbe() {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  return { release, answer: async (r) => { await gate; return r.fulfill({ json: { value: 1 } }); } };
}

test('G1 a slow page shows the loading state after about 300 ms, says so once, and drops it with the data', async ({ page }) => {
  await recordAnnouncements(page);
  const probe = heldProbe();
  await page.route(PROBE, probe.answer);
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/policies/status');
  await expect(loading(page)).toBeVisible();
  await shellCall(page, 'announcerIdle');
  expect((await page.evaluate(() => window.__writes)).filter((t) => t.startsWith('Loading'))).toEqual(['Loading Policies.']);
  probe.release();
  await expect(page.locator('#content')).toContainText('value 1');
  await expect(loading(page)).toHaveCount(0);
});

test('G2 a page that answers quickly never shows the loading state', async ({ page }) => {
  await watchLoading(page);
  await page.route(PROBE, (r) => r.fulfill({ json: { value: 1 } }));
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/policies/status');
  await expect(page.locator('#content')).toContainText('value 1');
  await page.evaluate(() => new Promise((done) => setTimeout(done, 400)));
  expect(await page.evaluate(() => window.__sawLoading)).toBe(false);
});

test('G3 the frame paints while every API request is still open (tooltip copy is pinned in its own ticket)', async ({ page }) => {
  await page.route('**/ui/api/**', () => {}); // never answered
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/policies/status');
  await expect(page.locator('nav.route-nav a')).toHaveCount(9);
  await expect(page.locator('.head .plate')).toHaveText('Policies');
  await expect(page.locator('nav.tabs a')).toHaveCount(3);
  await expect(loading(page)).toBeVisible();
});

test('G4 a slow page left before 300 ms shows and says nothing on the next one', async ({ page }) => {
  await recordAnnouncements(page);
  await watchLoading(page);
  const probe = heldProbe();
  await page.route(PROBE, probe.answer);
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/policies/status');
  await page.locator('nav.route-nav a[href="/ui/servers"]').click();
  await expect(page.locator('#content')).toContainText('servers - status');
  await page.evaluate(() => new Promise((done) => setTimeout(done, 450)));
  await shellCall(page, 'announcerIdle');
  expect(await page.evaluate(() => window.__sawLoading)).toBe(false);
  expect((await page.evaluate(() => window.__writes)).filter((t) => t.startsWith('Loading'))).toEqual([]);
  probe.release();
});

test('G5 a slow Retry shows the loading state under the banner, and the banner stays', async ({ page }) => {
  let calls = 0;
  const probe = heldProbe();
  await page.route(PROBE, async (r) => {
    calls += 1;
    if (calls === 1) return r.fulfill({ status: 500, json: {} });
    return probe.answer(r);
  });
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/policies/status');
  const banner = page.locator('#content [data-state="error"]');
  await expect(banner).toBeVisible();
  await banner.getByRole('button', { name: /Retry/ }).click();
  await expect(loading(page)).toBeVisible();
  await expect(banner).toBeVisible();
  probe.release();
  await expect(page.locator('#content')).toContainText('value 1');
  await expect(loading(page)).toHaveCount(0);
});

/** The ServerState variants, read from the gateway's own source, in snake_case. */
function serverStates() {
  const file = fileURLToPath(new URL('../../src/backend/server_state.rs', import.meta.url));
  const source = readFileSync(file, 'utf8');
  const head = source.slice(0, source.indexOf('pub enum ServerState {'));
  // The wire names are the variants in snake_case only while nothing renames them.
  expect(head.slice(head.lastIndexOf('#[derive')), 'ServerState keeps rename_all = "snake_case"').toContain('rename_all = "snake_case"');
  const body = source.slice(source.indexOf('pub enum ServerState {'));
  const block = body.slice(body.indexOf('{') + 1, body.indexOf('\n}'));
  expect(block, 'no ServerState variant is renamed one by one').not.toMatch(/serde\(\s*(rename|alias)/);
  return [...block.matchAll(/^\s{4}([A-Z][A-Za-z]+),/gm)].map(([, v]) => v.replace(/[A-Z]/g, (c, i) => (i ? '_' : '') + c.toLowerCase()));
}

test('W1 the glossary has one word for each ServerState, and no word twice', async ({ page }) => {
  await page.goto('/ui/overview/status');
  await shellReady(page);
  const url = await shellModuleUrl(page);
  const glossary = await page.evaluate(async (u) => (await import(u)).GLOSSARY, url);
  expect(Object.keys(glossary.server).sort()).toEqual(serverStates().sort());
  const words = [...Object.values(glossary.server), ...Object.values(glossary.stream)];
  expect(new Set(words).size).toBe(words.length);
});

test('W2 every server state reads its glossary word, and an unlisted one never shows its code', async ({ page }) => {
  await page.goto('/ui/overview/status');
  await shellReady(page);
  const url = await shellModuleUrl(page);
  const glossary = await page.evaluate(async (u) => (await import(u)).GLOSSARY, url);
  for (const [value, word] of Object.entries(glossary.server)) {
    expect(await shellCall(page, 'stateWord', value), value).toBe(word);
  }
  expect(await shellCall(page, 'stateWord', 'running')).toBe('Running');
  expect(await shellCall(page, 'stateWord', 'needs_sign_in')).toBe('Needs sign-in');
  for (const odd of ['warming_up', '', null]) {
    expect(await shellCall(page, 'stateWord', odd), String(odd)).toBe('Unknown state');
  }
});

test('W3 a dropped stream reads Updates stopped, and no state word is spelled outside the glossary', async ({ page }) => {
  await page.goto('/ui/overview/status');
  await shellReady(page);
  const url = await shellModuleUrl(page);
  const stale = await page.evaluate(async (u) => (await import(u)).state('stale').querySelector('h2').textContent, url);
  expect(stale).toBe('Updates stopped');
  const dir = fileURLToPath(new URL('../../src/gateway/ui/shell/', import.meta.url));
  const file = readdirSync(dir).find((f) => /^shell\.[0-9a-f]+\.js$/.test(f));
  const source = readFileSync(dir + file, 'utf8');
  const glossary = source.slice(source.indexOf('export const GLOSSARY'), source.indexOf('\n};', source.indexOf('export const GLOSSARY')));
  const rest = source.replace(glossary, '');
  expect(rest.match(/'Paused'|"Paused"|\banswering\b|\bANSWERED\b|'[Rr]eady'/g) ?? []).toEqual([]);
});

test('G1b a render that settles while the loading message waits its turn is never said', async ({ page }) => {
  await recordAnnouncements(page);
  const probe = heldProbe();
  await page.route(PROBE, probe.answer);
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/policies/status');
  // Something said just before 300 ms keeps the region in its pause when the loading message queues.
  await page.evaluate(() => new Promise((done) => setTimeout(done, 250)));
  await shellCall(page, 'announce', 'Earlier news.');
  await expect(loading(page)).toBeVisible();
  probe.release();
  await expect(page.locator('#content')).toContainText('value 1');
  await shellCall(page, 'announcerIdle');
  expect((await page.evaluate(() => window.__writes)).filter((t) => t.startsWith('Loading'))).toEqual([]);
});

test('G4b leaving after the loading state shows takes it away, and says nothing more', async ({ page }) => {
  await recordAnnouncements(page);
  const probe = heldProbe();
  await page.route(PROBE, probe.answer);
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/policies/status');
  await expect(loading(page)).toBeVisible();
  await page.locator('nav.route-nav a[href="/ui/servers"]').click();
  await expect(page.locator('#content')).toContainText('servers - status');
  await expect(loading(page)).toHaveCount(0);
  probe.release();
  await shellCall(page, 'announcerIdle');
  expect((await page.evaluate(() => window.__writes)).filter((t) => t.startsWith('Loading')).length).toBeLessThanOrEqual(1);
});

for (const [status, ending] of [[500, 'error'], [403, 'forbidden'], [401, 'sign-in']]) {
  test(`G6 a slow page that ends in ${status} leaves no loading state`, async ({ page }) => {
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    await page.route(PROBE, async (r) => { await gate; return r.fulfill({ status, json: {} }); });
    await withFixturePages(page, { probes: true });
    await page.goto('/ui/policies/status');
    await expect(loading(page)).toBeVisible();
    release();
    if (ending === 'sign-in') await expect(page.locator('#signin')).toBeVisible();
    else await expect(page.locator(`#content [data-state="${ending}"]`)).toBeVisible();
    await expect(loading(page)).toHaveCount(0);
  });
}
