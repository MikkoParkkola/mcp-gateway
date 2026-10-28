// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// One server-state table: every state the gateway reports has a word, glyph,
// tone, banner and next step; no raw policy code reaches the page; stale data
// carries its time with its numbers dimmed; a failed To do count reads "?".
// Rows T1-T8.
import { test, expect, WIDTHS, blockingViolations } from './base.mjs';
import { withFixturePages, shellReady, shellModuleUrl, serverStates } from './shell.mjs';

const COUNT = '**/ui/api/decisions/count';

/** Run `fn(shellModule, arg)` in the page and return its result. */
async function inShell(page, fn, arg) {
  const url = await shellModuleUrl(page);
  return page.evaluate(async ([u, src, a]) => {
    const m = await import(u);
    // eslint-disable-next-line no-new-func
    return new Function('m', 'a', `return (${src})(m, a);`)(m, a);
  }, [url, fn.toString(), arg]);
}

async function open(page) {
  await page.goto('/ui/overview/status');
  await shellReady(page);
}

test('T1 the table has exactly the gateway\'s server states, each with a word, glyph and tone', async ({ page }) => {
  await open(page);
  const table = await inShell(page, (m) => m.SERVER_STATES);
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

test('T2 a badge shows its glyph and word in its tone; the glyph is hidden from screen readers', async ({ page }) => {
  await open(page);
  const badges = await inShell(page, (m) => Object.keys(m.SERVER_STATES).map((state) => {
    const framed = m.serverBadge(state);
    const plain = m.serverBadge(state, { plain: true });
    const glyph = framed.querySelector('[aria-hidden="true"]');
    return {
      state,
      text: framed.textContent,
      glyph: glyph?.textContent ?? null,
      word: m.SERVER_STATES[state].word,
      tone: m.SERVER_STATES[state].tone,
      classes: framed.className,
      plain: plain.classList.contains('plain'),
    };
  }));
  for (const b of badges) {
    expect(b.text, b.state).toContain(b.word);
    expect(b.glyph, b.state).toBeTruthy();
    expect(b.classes, b.state).toContain(`tone-${b.tone}`);
    expect(b.plain, b.state).toBe(true);
  }
});

test('T3 a refused server never shows the policy codes in its reason', async ({ page }) => {
  await open(page);
  const html = await inShell(page, (m) => {
    const banner = m.serverBanner({
      name: 'github',
      state: 'refused',
      reason: 'Refused by the runtime policy: shell_exec, net_egress.',
      next_retry_at: null,
    });
    document.getElementById('content').append(banner);
    return document.body.innerHTML;
  });
  expect(html).toContain('The runtime policy refuses to start github.');
  expect(html).toContain('Policies shows the rule that refuses it.');
  expect(html).not.toContain('shell_exec');
  expect(html).not.toContain('net_egress');
  expect(html).not.toContain('Refused by the runtime policy');
});

test('T4 a paused server says when the gateway retries, and what to do now', async ({ page }) => {
  await open(page);
  const [timed, untimed, hhmm] = await inShell(page, (m) => {
    const at = new Date(Date.now() + 60_000);
    const text = (s) => m.serverBanner(s).textContent;
    return [
      text({ name: 'github', state: 'paused', reason: '', next_retry_at: at.toISOString() }),
      text({ name: 'github', state: 'paused', reason: '', next_retry_at: null }),
      at.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    ];
  });
  expect(timed).toContain(`The gateway retries at ${hhmm}.`);
  expect(timed).toContain('To retry now, use the Actions tab.');
  expect(untimed).toContain('retries it on its own');
});

test('T5 an unlisted state shows the glossary\'s fallback word, never its code', async ({ page }) => {
  await open(page);
  const text = await inShell(page, (m) => m.serverBadge('warming_up').textContent);
  expect(text).toContain('Unknown state');
  expect(text).not.toContain('warming_up');
  expect(await inShell(page, (m) => m.serverBanner({ name: 'x', state: 'warming_up', reason: '', next_retry_at: null }))).toBeNull();
});

test('T6 stale data reads its time and dims the numbers until it clears', async ({ page }) => {
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/tools/status');
  const stale = page.locator('#content [data-state="stale"]');
  await expect(stale).toBeVisible();
  const hhmm = await page.evaluate(() => new Date(2026, 9, 28, 14, 2).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
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
  await page.evaluate(() => window.toolsShow(null));
  await expect(stale).toHaveCount(0);
  expect(await colour()).not.toBe(muted);
});

test('T7 a failed To do count reads "?", a route not shipped shows nothing, and a known count replaces "?"', async ({ page }) => {
  let reply = { status: 500, json: {} };
  await page.route(COUNT, (r) => r.fulfill(reply));
  await open(page);
  const badge = page.locator('nav.route-nav a[data-page="to' + 'do"] .count');
  await expect(badge).toHaveText('?');
  await expect(page.locator('nav.route-nav a[data-page="to' + 'do"] .count-words')).toHaveText(' count unavailable');
  reply = { json: { count: 2 } };
  await inShell(page, (m) => m.refreshCounts());
  await expect(badge).toHaveText('2');
  reply = { status: 404, json: {} };
  await inShell(page, (m) => m.refreshCounts());
  await expect(badge).toHaveCount(0);
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
