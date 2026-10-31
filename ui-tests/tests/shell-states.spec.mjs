// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// One server-state table: every state the gateway reports has a word, glyph,
// tone, banner and next step; no raw policy code reaches the page; stale data
// carries its time with its numbers dimmed; a failed To do count reads "?".
// Rows T1-T8.
import { test, expect, WIDTHS, blockingViolations } from './base.mjs';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { withFixturePages, shellReady, shellModuleUrl, serverStates } from './shell.mjs';

const COUNT = '**/ui/api/decisions/count';

/**
 * Run `fn(shellModule, arg)` in the page and return its result. The shell's CSP
 * forbids eval in the page, so the call goes in as an expression Playwright
 * evaluates over the DevTools protocol, which the page's CSP does not cover.
 */
async function inShell(page, fn, arg) {
  const url = await shellModuleUrl(page);
  await page.evaluate(async (u) => { window.__shell = await import(u); }, url);
  return page.evaluate(`(${fn.toString()})(window.__shell, ${JSON.stringify(arg ?? null)})`);
}

async function open(page) {
  await page.goto('/ui/overview/status');
  await shellReady(page);
}

test('T1 the table has exactly the gateway\'s server states, each with a word, glyph and tone', async ({ page }) => {
  await open(page);
  // The word is the glossary's (UI1.24), so the table holds glyph, tone and copy only.
  const table = await inShell(page, (m) => Object.fromEntries(Object.entries(m.SERVER_STATES)
    .map(([state, row]) => [state, { glyph: row.glyph, tone: row.tone, word: m.stateWord(state) }])));
  expect(Object.keys(table).sort()).toEqual(serverStates().sort());
  for (const [state, row] of Object.entries(table)) {
    expect(row.word, state).toBeTruthy();
    expect(['✓', '⚠', '⊘', '⏸', 'ⓘ'], state).toContain(row.glyph);
    expect(['success', 'warning', 'danger', 'neutral'], state).toContain(row.tone);
  }
  expect(table.running.word).toBe('Running');
  expect(table.paused.glyph).toBe('⏸');
  expect(table.refused.tone).toBe('danger');
});

/** Every state and condition, with the exact banner and next step the table gives. */
const ROWS = [
  { server: { state: 'running', running: true }, tone: 'success', glyph: '✓', banner: null, next: null },
  { server: { state: 'slow', running: true }, tone: 'warning', glyph: '⚠',
    banner: 'github still works, but far slower than its usual.', next: 'Open Activity and filter by this server.' },
  { server: { state: 'paused', circuit_state: 'open', next_retry_at: 'SOON' }, tone: 'neutral', glyph: '⏸',
    banner: 'Calls to github are held back after failures. The gateway lets calls try it again from HHMM.', next: 'To retry now, use the Actions tab.' },
  { server: { state: 'paused', circuit_state: 'open', next_retry_at: null }, tone: 'neutral', glyph: '⏸',
    banner: 'Calls to github are held back after failures. The gateway lets calls try it again after a short wait.', next: 'To retry now, use the Actions tab.' },
  { server: { state: 'paused', circuit_state: 'half_open', next_retry_at: null }, tone: 'neutral', glyph: '⏸',
    banner: 'The gateway is letting calls through to github to see if it has recovered.', next: null },
  { server: { state: 'paused', circuit_state: 'open', next_retry_at: 'not a time' }, tone: 'neutral', glyph: '⏸',
    banner: 'Calls to github are held back after failures. The gateway lets calls try it again after a short wait.', next: 'To retry now, use the Actions tab.' },
  { server: { state: 'dormant', running: false }, tone: 'neutral', glyph: 'ⓘ', banner: null, next: null },
  { server: { state: 'unhealthy', running: true }, tone: 'warning', glyph: '⚠',
    banner: 'github is failing; calls still go through.', next: 'Open Activity and filter by this server.' },
  { server: { state: 'unhealthy', running: false }, tone: 'warning', glyph: '⚠',
    banner: 'github is failing; the next call tries to start it again.', next: 'Open Activity and filter by this server.' },
  { server: { state: 'refused', reason: 'Refused by the runtime policy: shell_exec, net_egress.' }, tone: 'danger', glyph: '⊘',
    banner: 'The gateway cannot start github with its current runtime configuration.', next: "Check this server's runtime profile and the runtime policy." },
  { server: { state: 'needs_sign_in' }, tone: 'warning', glyph: '⚠',
    banner: 'github is waiting for someone to sign in.', next: 'Sign in from its Actions tab.' },
  { server: { state: 'unmanaged' }, tone: 'neutral', glyph: 'ⓘ',
    banner: 'github is on this machine but not behind the gateway.', next: 'Add it from the Servers Actions tab.' },
  { server: { state: 'warming_up' }, tone: 'warning', glyph: '⚠',
    banner: 'github is in a state this page does not recognise.', next: 'Open Activity and filter by this server.' },
];

test('T2 every state and condition gets its exact badge, banner and next step', async ({ page }) => {
  await open(page);
  const got = await inShell(page, (m, rows) => {
    const soon = new Date(Date.now() + 60_000);
    const hhmm = soon.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const colour = (value) => {
      const probe = document.createElement('span');
      probe.style.color = value;
      document.body.append(probe);
      const c = getComputedStyle(probe).color;
      probe.remove();
      return c;
    };
    return rows.map(({ server }) => {
      const s = { name: 'github', reason: '', ...server, next_retry_at: server.next_retry_at === 'SOON' ? soon.toISOString() : server.next_retry_at ?? null };
      const badge = m.serverBadge(s.state);
      const plain = m.serverBadge(s.state, { plain: true });
      document.body.append(badge, plain);
      const glyph = badge.querySelector('[aria-hidden="true"]');
      const tone = ['success', 'warning', 'danger', 'neutral'].find((t) => badge.classList.contains(t));
      const out = {
        state: s.state,
        word: badge.textContent.replace(glyph?.textContent ?? '', '').trim(),
        expectedWord: m.stateWord(s.state),
        glyph: glyph?.textContent ?? null,
        tone,
        glyphColour: glyph ? getComputedStyle(glyph).color : null,
        toneColour: tone ? colour(`var(--color-status-${tone}-fg)`) : null,
        // .plain keeps the border's box but makes it transparent.
        framed: getComputedStyle(badge).borderTopColor !== 'rgba(0, 0, 0, 0)',
        plainFramed: getComputedStyle(plain).borderTopColor !== 'rgba(0, 0, 0, 0)',
        banner: null,
        next: null,
        html: '',
      };
      const node = m.serverBanner(s);
      if (node) {
        out.banner = node.querySelector('h2')?.textContent ?? null;
        out.next = node.querySelector('p')?.textContent ?? null;
        document.getElementById('content').append(node);
      }
      // The whole page with this row's badge (and banner, if any) in it.
      out.html = document.documentElement.outerHTML;
      node?.remove();
      badge.remove();
      plain.remove();
      out.banner = out.banner?.replace(hhmm, 'HHMM') ?? null;
      return out;
    });
  }, ROWS);
  ROWS.forEach((row, i) => {
    const g = got[i];
    const at = `${row.server.state} ${JSON.stringify(row.server)}`;
    expect(g.word, at).toBe(g.expectedWord);
    expect(g.glyph, at).toBe(row.glyph);
    expect(g.tone, at).toBe(row.tone);
    expect(g.glyphColour, at).toBe(g.toneColour);
    expect(g.framed, at).toBe(true);
    expect(g.plainFramed, at).toBe(false);
    expect(g.banner, at).toBe(row.banner);
    expect(g.next, at).toBe(row.next);
    // No policy code and no raw reason, ever.
    expect(g.html, at).not.toContain('shell_exec');
    expect(g.html, at).not.toContain('net_egress');
    expect(g.html, at).not.toContain('Refused by the runtime policy');
    expect(g.html, at).not.toContain('warming_up');
  });
});

test('T6 stale data reads its time and dims the numbers until it clears', async ({ page }) => {
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/tools/status');
  const stale = page.locator('#content [data-state="stale"]');
  await expect(stale).toBeVisible();
  const hhmm = await page.evaluate(() => {
    const at = new Date();
    at.setHours(14, 2, 0, 0);
    return at.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  });
  await expect(stale.locator('h2')).toHaveText(`Updates stopped at ${hhmm} · reconnecting`);
  const colour = () => page.locator('#content .num').evaluate((n) => getComputedStyle(n).color);
  const muted = await page.evaluate(() => {
    const probe = document.createElement('span');
    probe.style.color = 'var(--color-text-secondary)';
    document.body.append(probe);
    const c = getComputedStyle(probe).color;
    probe.remove();
    return c;
  });
  expect(await colour()).toBe(muted);
  const cell = () => page.locator('#content .t .n').evaluate((n) => getComputedStyle(n).color);
  expect(await cell()).toBe(muted);
  await page.evaluate(() => window.toolsShow(null));
  await expect(stale).toHaveCount(0);
  expect(await colour()).not.toBe(muted);
  expect(await cell()).not.toBe(muted);
  // A stop before today carries its date too.
  const [title, date] = await inShell(page, (m) => {
    const since = new Date(Date.now() - 86_400_000);
    return [m.staleTitle(since), since.toLocaleDateString()];
  });
  expect(title).toContain(date);
  expect(title).toMatch(/^Updates stopped at .+ · reconnecting$/);
});

test('T7 a failed To do count reads "?", a 404 reads "?" too, and a known count replaces "?"', async ({ page }) => {
  let reply = { status: 500, json: {} };
  await page.route(COUNT, (r) => r.fulfill(reply));
  await open(page);
  const badge = page.locator('nav.route-nav a[data-page="to' + 'do"] .count');
  await expect(badge).toHaveText('?');
  await expect(page.locator('nav.route-nav a[data-page="to' + 'do"] .count-words')).toHaveText(' count unavailable');
  reply = { json: { count: 2 } };
  await inShell(page, (m) => m.refreshCounts());
  await expect(badge).toHaveText('2');
  reply = { json: { total: 3 } }; // an answer without a whole-number count
  await inShell(page, (m) => m.refreshCounts());
  await expect(badge).toHaveText('?');
  reply = { json: { count: 2 } };
  await inShell(page, (m) => m.refreshCounts());
  await expect(badge).toHaveText('2');
  // The count route ships with the queue: a 404 is now a failure like any other.
  reply = { status: 404, json: {} };
  await inShell(page, (m) => m.refreshCounts());
  await expect(badge).toHaveText('?');
});

for (const width of WIDTHS) {
  test(`T8 axe at ${width} px on every badge and a banner`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await open(page);
    await inShell(page, (m) => {
      const box = document.createElement('div');
      for (const state of Object.keys(m.SERVER_STATES)) box.append(m.serverBadge(state), ' ');
      box.append(m.serverBanner({ name: 'github', state: 'unhealthy', reason: '', next_retry_at: null }));
      document.getElementById('content').append(box);
    });
    expect(await blockingViolations(page)).toEqual([]);
  });
}

test('T9 the half-open breaker value the paused copy reads is the gateway\'s own wire value', () => {
  const file = fileURLToPath(new URL('../../src/failsafe/circuit_breaker.rs', import.meta.url));
  const source = readFileSync(file, 'utf8');
  expect(source).toMatch(/Self::HalfOpen\s*=>\s*"half_open"/);
});

test('T10 an unlisted state warns once, without its value', async ({ page }) => {
  const warnings = [];
  page.on('console', (msg) => { if (msg.type() === 'warning') warnings.push(msg.text()); });
  await open(page);
  await inShell(page, (m) => { m.serverBadge('warming_up'); m.serverBadge('warming_up'); m.stateWord('warming_up'); });
  const ours = warnings.filter((w) => w.includes('does not recognise'));
  expect(ours).toHaveLength(1);
  expect(ours[0]).not.toContain('warming_up');
});

test('T7b a negative count reads "?"', async ({ page }) => {
  await page.route(COUNT, (r) => r.fulfill({ json: { count: -1 } }));
  await open(page);
  await expect(page.locator('nav.route-nav a[data-page="to' + 'do"] .count')).toHaveText('?');
});

test('T11 a server banner shown through the page context is said once and taken away by show(null)', async ({ page }) => {
  await page.addInitScript(() => {
    window.__writes = [];
    addEventListener('DOMContentLoaded', () => {
      const region = document.getElementById('announcer');
      new MutationObserver((records) => {
        for (const r of records) for (const n of r.addedNodes) window.__writes.push((n.textContent ?? '').trim());
      }).observe(region, { childList: true });
    });
  });
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/servers/status');
  const banner = page.locator('#content .banner[data-banner]');
  await expect(banner).toContainText('The gateway cannot start github with its current runtime configuration.');
  await expect(page.locator('#content')).not.toContainText('shell_exec');
  await inShell(page, (m) => m.announcerIdle());
  const said = await page.evaluate(() => window.__writes);
  expect(said.filter((t) => t.includes('cannot start github'))).toHaveLength(1);
  await page.evaluate(() => window.serversShow(null));
  await expect(banner).toHaveCount(0);
});
