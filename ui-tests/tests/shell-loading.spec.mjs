// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// A page waiting more than about 300 ms shows a loading state, and the frame
// never waits on any /ui/api answer (tooltip copy included): rows G1-G5.
// One state glossary, kept in step with the gateway's ServerState: rows W1-W3.
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { test, expect } from './base.mjs';
import { withFixturePages, shellReady, shellModuleUrl, serverStates } from './shell.mjs';

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
  return { release, gate, answer: async (r) => { await gate; return r.fulfill({ json: { value: 1 } }); } };
}

test('G1 a slow page shows the loading state after about 300 ms, says so once, and drops it with the data', async ({ page }) => {
  await recordAnnouncements(page);
  const probe = heldProbe();
  await page.route(PROBE, probe.answer);
  await withFixturePages(page, { probes: true });
  // When the tab's body and the loading state enter the page, by the page's own clock,
  // so a loaded machine cannot make the test's timing disagree with the page's.
  await page.addInitScript(() => {
    // Watched from the start: the shell puts the body in before DOMContentLoaded listeners run.
    window.__times = {};
    new MutationObserver(() => {
      const now = performance.now();
      if (!window.__times.body && document.querySelector('#content > .body[data-rendered]')) window.__times.body = now;
      if (!window.__times.loading && document.querySelector('#content [data-state="loading"]')) window.__times.loading = now;
    }).observe(document, { childList: true, subtree: true });
  });
  await page.goto('/ui/policies/status');
  await expect(loading(page)).toBeVisible();
  const times = await page.evaluate(() => window.__times);
  expect(times.loading - times.body, 'not before about 300 ms').toBeGreaterThanOrEqual(295);
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
  // Leave from inside the page in the same task that put the slow tab's body in, so
  // the user has left long before 300 ms however loaded the machine is.
  await page.addInitScript(() => {
    const watch = new MutationObserver(() => {
      if (location.pathname !== '/ui/policies/status' || !document.querySelector('#content > .body[data-rendered]')) return;
      watch.disconnect();
      history.pushState(null, '', '/ui/servers/status');
      dispatchEvent(new PopStateEvent('popstate'));
    });
    watch.observe(document, { childList: true, subtree: true });
  });
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/policies/status');
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
  // Banner, then the loading state, then the Retry's stage, in that order.
  const order = await page.evaluate(() => [...document.getElementById('content').children]
    .map((n) => (n.matches('[data-state="loading"]') ? 'loading' : n.classList.contains('staging') ? 'stage' : n.querySelector('[data-state="error"]') ? 'banner' : n.className)));
  expect(order).toEqual(['banner', 'loading', 'stage']);
  probe.release();
  await expect(page.locator('#content')).toContainText('value 1');
  await expect(loading(page)).toHaveCount(0);
});

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
  // No string literal outside the glossary is itself a state word, in any case or quote style.
  const words = await page.evaluate(async (u) => {
    const { GLOSSARY } = await import(u);
    return [...Object.values(GLOSSARY.server), ...Object.values(GLOSSARY.stream)].map((w) => w.toLowerCase());
  }, url);
  const literals = [...rest.matchAll(/(['"`])((?:\\.|(?!\1)[^\\])*)\1/g)].map(([, , text]) => text.trim().toLowerCase());
  expect(literals.filter((text) => words.includes(text))).toEqual([]);
});

test('G1b a render that settles while the loading message waits its turn is never said', async ({ page }) => {
  // The page's clock is paused from before it loads and moved only by runFor, so no
  // step depends on how long the host takes between two of them.
  await page.clock.install({ time: 0 });
  await page.clock.pauseAt(60_000); // far ahead of any stall since install
  await recordAnnouncements(page);
  const probe = heldProbe();
  await page.route(PROBE, probe.answer);
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/policies/status');
  // Something said at once, with a long pause after it, keeps the loading message queued.
  const url = await shellModuleUrl(page);
  await page.evaluate(async (u) => {
    const m = await import(u);
    m.announcerTiming.dwellMs = 5000;
    m.announce('Earlier news.');
  }, url);
  await page.clock.runFor(1); // the earlier news is written
  await page.clock.runFor(300); // the onset: the loading state shows, its message queues
  await expect(loading(page)).toBeVisible();
  probe.release();
  await expect(page.locator('#content')).toContainText('value 1');
  await page.clock.runFor(400); // the minimum: the loading state goes
  await expect(loading(page)).toHaveCount(0);
  await page.evaluate(async (u) => { (await import(u)).announcerTiming.dwellMs = 500; }, url);
  await page.clock.runFor(5000);
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

test('G7 an error just after the loading state appears waits out its minimum, then shows, said once', async ({ page }) => {
  await recordAnnouncements(page);
  // When the loading state and the error banner each enter the page, by the page's own clock.
  await page.addInitScript(() => {
    window.__times = {};
    addEventListener('DOMContentLoaded', () => {
      new MutationObserver(() => {
        const now = performance.now();
        if (!window.__times.loading && document.querySelector('#content [data-state="loading"]')) window.__times.loading = now;
        if (!window.__times.error && document.querySelector('#content [data-state="error"]')) window.__times.error = now;
      }).observe(document.getElementById('content'), { childList: true, subtree: true });
    });
  });
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  await page.route(PROBE, async (r) => { await gate; return r.fulfill({ status: 500, json: {} }); });
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/policies/status');
  await expect(loading(page)).toBeVisible();
  release();
  await expect(page.locator('#content [data-state="error"]')).toBeVisible();
  await expect(loading(page)).toHaveCount(0);
  const times = await page.evaluate(() => window.__times);
  expect(times.error - times.loading, 'the error waited out the loading state\'s minimum').toBeGreaterThanOrEqual(395);
  await shellCall(page, 'announcerIdle');
  expect((await page.evaluate(() => window.__writes)).filter((t) => t.includes('The gateway answered with an error'))).toHaveLength(1);
});

const content = (page) => page.locator('#content');

/** A paused clock, so busy is read between the render's start and the 300 ms onset. */
async function pausedClock(page) {
  await page.clock.install({ time: 0 });
  await page.clock.pauseAt(60_000); // far ahead of any stall since install
}

test('G8 a first render is aria-busy from its start, before the onset, and not after it settles', async ({ page }) => {
  await pausedClock(page);
  const probe = heldProbe();
  await page.route(PROBE, probe.answer);
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/policies/status');
  await expect(content(page)).toHaveAttribute('aria-busy', 'true');
  await expect(loading(page)).toHaveCount(0); // before the onset
  await page.clock.runFor(300);
  await expect(loading(page)).toBeVisible();
  await expect(content(page)).toHaveAttribute('aria-busy', 'true');
  probe.release();
  await expect(content(page)).toContainText('value 1');
  await expect(content(page), 'busy stays while the loading state still covers the data').toHaveAttribute('aria-busy', 'true');
  await page.clock.runFor(400);
  await expect(loading(page)).toHaveCount(0);
  await expect(content(page)).not.toHaveAttribute('aria-busy', /.*/);
});

test('G8c busy clears after a first-load error, after an empty completion and after leaving mid-load', async ({ page }) => {
  await pausedClock(page);
  const answers = [{ status: 500, json: {} }, { json: { value: 'empty' } }];
  const probe = heldProbe();
  await page.route(PROBE, async (r) => {
    const next = answers.shift();
    if (!next) return probe.answer(r);
    return r.fulfill(next);
  });
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/policies/status');
  await expect(page.locator('#content [data-state="error"]')).toBeVisible();
  await expect(content(page)).not.toHaveAttribute('aria-busy', /.*/);
  await page.evaluate(async (u) => (await import(u)).render(), await shellModuleUrl(page));
  await expect(content(page)).not.toHaveAttribute('aria-busy', /.*/);
  await expect(page.locator('#content .body[data-rendered]')).toBeAttached();
  await page.evaluate(async (u) => (await import(u)).render(), await shellModuleUrl(page));
  await expect(content(page)).toHaveAttribute('aria-busy', 'true'); // third read is held
  await page.evaluate(() => { history.pushState(null, '', '/ui/servers/status'); dispatchEvent(new PopStateEvent('popstate')); });
  await expect(content(page)).toContainText('servers - status');
  await expect(content(page)).not.toHaveAttribute('aria-busy', /.*/);
  probe.release();
});

const retryButton = (page) => page.locator('#content [data-state="error"]').getByRole('button', { name: /Retry/ });

test('G5b a Retry that is rejected again shows the error again, with aria-busy cleared', async ({ page }) => {
  let calls = 0;
  const second = heldProbe();
  await page.route(PROBE, async (r) => {
    calls += 1;
    if (calls === 1) return r.fulfill({ status: 500, json: {} });
    await second.gate;
    return r.fulfill({ status: 500, json: {} });
  });
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/policies/status');
  await retryButton(page).click();
  await expect.poll(() => calls, 'the Retry sent its own request').toBe(2);
  await expect(page.locator('#content')).toHaveAttribute('aria-busy', 'true');
  second.release();
  await expect(page.locator('#content [data-state="error"]')).toBeVisible();
  await expect(retryButton(page)).toBeEnabled();
  await expect(page.locator('#content')).not.toHaveAttribute('aria-busy', /.*/);
  await expect(loading(page)).toHaveCount(0);
  expect(calls).toBe(2);
});

test('G5c leaving during a Retry leaves no loading state or aria-busy on the new page', async ({ page }) => {
  await pausedClock(page);
  let calls = 0;
  let served = false;
  const probe = heldProbe();
  await page.route(PROBE, async (r) => {
    calls += 1;
    if (calls === 1) return r.fulfill({ status: 500, json: {} });
    await probe.answer(r); // the abandoned Retry's read, held until released
    served = true;
  });
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/policies/status');
  await retryButton(page).click();
  await page.clock.runFor(300);
  await expect(loading(page)).toBeVisible();
  await expect(page.locator('#content')).toHaveAttribute('aria-busy', 'true');
  await page.evaluate(() => {
    history.pushState(null, '', '/ui/servers/status');
    dispatchEvent(new PopStateEvent('popstate'));
  });
  await expect(page.locator('#content')).toContainText('servers - status');
  probe.release();
  await expect.poll(() => served, 'the abandoned Retry completed').toBe(true);
  await page.evaluate(() => Promise.resolve()); // its handlers have run
  await page.clock.runFor(400); // and its loading cleanup
  await expect(loading(page)).toHaveCount(0);
  await expect(page.locator('#content')).not.toHaveAttribute('aria-busy', /.*/);
  await expect(page.locator('#content')).toContainText('servers - status');
  await expect(page.locator('#content')).not.toContainText('value 1');
});

/**
 * Walk the loading thresholds on a paused clock, after `start` began an attempt whose
 * answer is held: no loading state at 299 ms, one at 300 ms; with the answer already
 * settled, still there 399 ms later, gone at 400 ms.
 */
async function walkThresholds(page, probe) {
  await page.clock.runFor(299);
  await expect(loading(page), 'not before the onset').toHaveCount(0);
  await page.clock.runFor(1);
  await expect(loading(page), 'at the onset').toBeVisible();
  probe.release();
  await expect(page.locator('#content')).toContainText('value 1');
  await page.evaluate(() => Promise.resolve()); // the settled attempt has run its handlers
  await page.clock.runFor(399);
  await expect(loading(page), 'just before the minimum').toBeVisible();
  await page.clock.runFor(1);
  await expect(loading(page), 'at the minimum').toHaveCount(0);
}

test('G5d a slow Retry shows loading after the same onset as a first render, and keeps it the same minimum', async ({ page }) => {
  await pausedClock(page);
  let calls = 0;
  const held = [heldProbe(), heldProbe()];
  await page.route(PROBE, (r) => {
    calls += 1;
    if (calls === 1) return held[0].answer(r); // a first render
    if (calls === 2) return r.fulfill({ status: 500, json: {} }); // the next page's first read fails
    return held[1].answer(r); // its Retry
  });
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/policies/status');
  await walkThresholds(page, held[0]);
  await page.goto('/ui/policies/status');
  await retryButton(page).click();
  await walkThresholds(page, held[1]);
});

test('G8b a sign-out during a slow first load leaves no aria-busy behind', async ({ page }) => {
  await page.route('**/ui/api/status', (r) => r.fulfill({ json: { auth: { enabled: true, signed_in: true, admin: true } } }));
  await page.route('**/dashboard/logout', (r) => r.fulfill({ status: 204 }));
  const probe = heldProbe();
  await page.route(PROBE, probe.answer);
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/policies/status');
  await expect(page.locator('#content')).toHaveAttribute('aria-busy', 'true');
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.locator('#signin')).toBeVisible();
  await expect(page.locator('#content')).not.toHaveAttribute('aria-busy', /.*/);
  probe.release();
});
