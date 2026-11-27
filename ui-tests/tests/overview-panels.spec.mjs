// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The Overview's panels below the tiles: Needs you, Last actions and the
// first-run checklist, all drawn from the one overview read. Each row answers
// that read with a literal body and writes out every string it expects.
import { test, expect, blockingViolations } from './base.mjs';
import { overview, serve, open } from './overview.mjs';

/** The overview body with the panels' fields; the checklist is done unless a row says otherwise. */
function body(over = {}) {
  return {
    ...overview(),
    needs_you: { rows: [], more: { count: 0 } },
    checklist: { has_key: true, tool_tried: true, client_seen: false },
    ...over,
  };
}
const panel = (page, id) => page.locator(`#content [data-panel="${id}"]`);
const nyRows = (page) => panel(page, 'needs-you').locator('.ny-row');
const laRows = (page) => panel(page, 'last-actions').locator('.la-row');
const show = async (page, over, width) => { await serve(page, { body: body(over) }); await open(page, width); };

test.use({ timezoneId: 'UTC', locale: 'en-GB' });

const at = '2026-11-19T10:00:00Z';
const CONFIG_BAD = { kind: 'invalid_config', subject: 'config', detail: { cause: 'Line 4 holds a tab', fix: 'Indent line 4 with spaces', at, repeats: 1 } };
const SERVER_REFUSED = { kind: 'refused', subject: 'inventory', detail: { code: 'plain_http_key', cause: 'Its address sends a key in clear text', fix: 'Give it an https address', at } };
const EDIT_REFUSED = { kind: 'refused', subject: 'config', detail: { code: 'edit', cause: 'The last edit broke a reference', fix: 'Undo the last edit', at } };
const limit = (name, percent, scope = 'key') => ({ kind: 'limit_80', subject: name, detail: { scope, name, spent_usd: 21.6, limit_usd: 25, percent } });

test('P1 each kind reads as its own row, with its link', async ({ page }) => {
  await show(page, { needs_you: { rows: [CONFIG_BAD, SERVER_REFUSED, EDIT_REFUSED, limit('ci-bot', 86.4)], more: { count: 2 } } });
  await expect(panel(page, 'needs-you').locator('.ny-count')).toHaveText('6');
  const rows = nyRows(page);
  await expect(rows).toHaveCount(4);
  expect(await rows.evaluateAll((rs) => rs.map((r) => r.dataset.kind))).toEqual(['invalid_config', 'refused', 'refused', 'limit_80']);
  await expect(rows.nth(0)).toHaveAttribute('href', '/ui/gateway/status');
  await expect(rows.nth(1)).toHaveAttribute('href', '/ui/servers/inventory/status');
  await expect(rows.nth(2)).toHaveAttribute('href', '/ui/gateway/status');
  await expect(rows.nth(3)).toHaveAttribute('href', '/ui/access/ci-bot/status');
  for (const [i, row] of [[0, CONFIG_BAD], [1, SERVER_REFUSED], [2, EDIT_REFUSED]]) {
    await expect(rows.nth(i)).toContainText(row.detail.cause);
    await expect(rows.nth(i)).toContainText(row.detail.fix);
  }
  await expect(rows.nth(1).locator('.ny-title')).toHaveText('inventory was not started');
  await expect(rows.nth(3).locator('.ny-title')).toHaveText('ci-bot is at 86% of its $25.00 limit');
  await expect(rows.nth(3).locator('.ny-line')).toHaveCount(0);
  await expect(panel(page, 'needs-you').locator('.ny-more')).toHaveText('and 2 more');
});

test('P1b a name that cannot address one page links to a list or is encoded', async ({ page }) => {
  const refused = (subject) => ({ ...SERVER_REFUSED, subject });
  await show(page, { needs_you: { rows: [refused('.'), refused('..'), refused('n'.repeat(253)), limit('a/b c?d#e', 81),
    limit('.', 81), limit('..', 81), limit('k'.repeat(253), 81)], more: { count: 0 } } });
  const rows = nyRows(page);
  for (const i of [0, 1, 2]) await expect(rows.nth(i)).toHaveAttribute('href', '/ui/servers/status');
  for (const i of [4, 5, 6]) await expect(rows.nth(i)).toHaveAttribute('href', '/ui/access/status');
  const keyPage = `/ui/access/${encodeURIComponent('a/b c?d#e')}/status`;
  await expect(rows.nth(3)).toHaveAttribute('href', keyPage);
  await rows.nth(3).click();
  await expect(page).toHaveURL((u) => u.pathname === keyPage);
});

test('P1c a percent is cut to a whole number, never rounded up', async ({ page }) => {
  await show(page, { needs_you: { rows: [limit('k1', 86.4), limit('k2', 86.9), limit('k3', 99.9)], more: { count: 0 } } });
  await expect(nyRows(page).locator('.ny-title')).toHaveText([
    'k1 is at 86% of its $25.00 limit', 'k2 is at 86% of its $25.00 limit', 'k3 is at 99% of its $25.00 limit']);
});

test('P2 a kind this page does not know is shown in fixed words, never its code', async ({ page }) => {
  await show(page, { needs_you: { rows: [{ kind: 'zz_new', subject: 'x' }], more: { count: 0 } } });
  const row = nyRows(page);
  await expect(row).toHaveCount(1);
  await expect(row).not.toHaveAttribute('href', /./);
  await expect(row.locator('.ny-line')).toHaveText('x');
  await expect(row.locator('.ny-title')).not.toBeEmpty();
  await expect(page.locator('#content')).not.toContainText('zz_new');

  // A kind named like an Object built-in is just as unknown, and the page still paints.
  await show(page, { needs_you: { rows: [{ kind: 'constructor', subject: 'c' }, { kind: '__proto__', subject: 'p' }], more: { count: 0 } } });
  await expect(nyRows(page)).toHaveCount(2);
  const unknown = 'This page does not recognise this item yet';
  await expect(nyRows(page).locator('.ny-title')).toHaveText([unknown, unknown]);
});

test('P3 nothing to do keeps the panel and says so', async ({ page }) => {
  await show(page, {});
  await expect(panel(page, 'needs-you')).toHaveCount(1);
  await expect(panel(page, 'needs-you').locator('.ny-count')).toHaveText('0');
  await expect(panel(page, 'needs-you').locator('.ny-empty')).toBeVisible();
  await expect(nyRows(page)).toHaveCount(0);
});

test.describe('P1d the alert channel row', () => {
  test.use({ timezoneId: 'Europe/Helsinki' });
  const titles = {
    not_running: 'Alerts may not go out: the alert channel is not fully running',
    suspended: 'No alerts are going out: the channel was suspended after repeated failures',
    failing: 'The latest alerts could not be delivered',
    other: 'The alert channel has a problem',
    toString: 'The alert channel has a problem',
  };
  for (const [state, title] of Object.entries(titles)) {
    test(`P1d ${state}`, async ({ page }) => {
      const last = state === 'suspended' ? null : '2026-11-20T08:15:00Z';
      const fix = `Fix for ${state}: check the webhook address under Gateway settings`;
      const alert = { kind: 'alert_failed', subject: 'webhook', detail: { state, last_error: 'timeout', last_delivery_at: last, fix } };
      await show(page, { needs_you: { rows: [CONFIG_BAD, alert, SERVER_REFUSED], more: { count: 0 } } });
      const row = nyRows(page).nth(1);
      await expect(row).toHaveAttribute('data-kind', 'alert_failed');
      await expect(row.locator('.ny-title')).toHaveText(title);
      await expect(row.locator('.ny-line').nth(0)).toHaveText(fix);
      if (last) await expect(row.locator('.ny-line').nth(1)).toContainText('10:15');
      else await expect(row.locator('.ny-line').nth(1)).toHaveText('No alert has been delivered yet');
      await expect(row).toHaveAttribute('href', '/ui/gateway/status');
      await expect(row).not.toContainText('timeout');
    });
  }
});

test('N1 a sign-in row links to the server, or to the list when its name was cut', async ({ page }) => {
  const rows = [
    { kind: 'sign_in', subject: 'gmail', detail: {} },
    { kind: 'sign_in', subject: 'linear-very-long', detail: { clipped: true } },
  ];
  await show(page, { needs_you: { rows, more: { count: 0 } } });
  await expect(nyRows(page).nth(0).locator('.ny-title')).toHaveText('gmail needs sign-in');
  await expect(nyRows(page).nth(0)).toHaveAttribute('href', '/ui/servers/gmail/actions');
  await expect(nyRows(page).nth(1)).toHaveAttribute('href', '/ui/servers/status');
});

test('N2 folded sign-ins get their own line and link', async ({ page }) => {
  await show(page, { needs_you: { rows: [], more: { count: 4, by_kind: { sign_in: 3, refused: 1 } } } });
  const line = panel(page, 'needs-you').locator('a.ny-signins');
  await expect(line).toHaveText('and 3 more servers wait for a sign-in');
  await expect(line).toHaveAttribute('href', '/ui/servers/status');
  await expect(panel(page, 'needs-you').locator('.ny-more')).toHaveText('and 4 more');
});

const TO_DO = `/ui/${'to'}${'do'}/status`;
test('D1 open decisions read as one row linked to To do', async ({ page }) => {
  await show(page, { needs_you: { rows: [{ kind: 'decisions', subject: 'decisions', detail: { count: 3, revision: 9 } }], more: { count: 0 } } });
  const row = nyRows(page);
  await expect(row.locator('.ny-title')).toHaveText('3 decisions in To do');
  await expect(row).toHaveAttribute('href', TO_DO);
});

test('D2 an unreadable decision count says the read failed', async ({ page }) => {
  await show(page, { degraded: ['needs_you.decisions'] });
  const row = nyRows(page);
  await expect(row).toHaveCount(1);
  await expect(row).toHaveAttribute('data-kind', 'decisions');
  await expect(row.locator('.ny-title')).toHaveText('Not available right now: a read failed');
});

test('P4 every server-supplied string is text, never markup', async ({ page }) => {
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  const S = '<img src=x onerror=window.__pwned=1>';
  const rows = [
    { ...CONFIG_BAD, detail: { ...CONFIG_BAD.detail, cause: `cause ${S}`, fix: `fix ${S}` } },
    { ...SERVER_REFUSED, subject: `srv ${S}` },
    limit(`key ${S}`, 82),
  ];
  const actions = [
    { at, route: `/ui/api/${S}`, method: 'POST', outcome: 'ok', who: { account: `acct ${S}` } },
    { at, route: '/ui/api/settings', method: 'POST', outcome: 'ok', who: { subject: `subj ${S}` } },
  ];
  await show(page, { needs_you: { rows, more: { count: 0 } }, last_actions: { rows: actions, complete: true } });
  for (const text of [`cause ${S}`, `fix ${S}`, `srv ${S}`, `key ${S}`, `acct ${S}`, `subj ${S}`]) {
    await expect(page.locator('#content')).toContainText(text);
  }
  await expect(page.locator('#content')).not.toContainText(`/ui/api/${S}`);
  await expect(page.locator('#content img')).toHaveCount(0);
  expect(await page.evaluate(() => window.__pwned)).toBeUndefined();
  expect(errors).toEqual([]);
});

const action = (over = {}) => ({ at, route: '/ui/api/settings', method: 'POST', outcome: 'ok', who: { account: 'mikko' }, ...over });

test('P5 a last action shows its time, its words and who did it', async ({ page }) => {
  const rows = [
    action({ at: '2026-11-19T14:33:00Z' }),
    action({ at: 'not a time', route: '/ui/api/zz', who: { subject: 'svc-7' } }),
  ];
  await show(page, { last_actions: { rows, complete: true } });
  const shown = laRows(page);
  await expect(shown.nth(0).locator('.la-what')).toHaveText('Settings saved by mikko');
  await expect(shown.nth(0).locator('.la-time')).toContainText('14:33');
  await expect(shown.nth(1).locator('.la-what')).toHaveText('Admin action by svc-7');
  await expect(shown.nth(1).locator('.la-time')).toHaveText('');
  await expect(panel(page, 'last-actions')).not.toContainText('Invalid Date');
  await expect(page.locator('#content')).not.toContainText('/ui/api/zz');
  await expect(panel(page, 'last-actions').locator('a.la-all')).toHaveAttribute('href', '/ui/activity/status');
});

test('P6 Last actions: absent without a log, failed words when degraded, older may exist', async ({ page }) => {
  await show(page, {});
  await expect(panel(page, 'last-actions')).toHaveCount(0);

  await show(page, { degraded: ['last_actions'] });
  await expect(panel(page, 'last-actions')).toContainText('Not available right now: a read failed');

  await show(page, { last_actions: { rows: [action()], complete: false } });
  await expect(panel(page, 'last-actions').locator('.la-older')).toBeVisible();
  await expect(panel(page, 'last-actions').locator('.la-older a')).toHaveAttribute('href', '/ui/activity/status');
});

test('P7 an action that did not go through says so', async ({ page }) => {
  const outcomes = ['ok', 'denied', 'invalid', 'error', undefined, 'tool_error', 'zz_word'];
  const rows = outcomes.map((outcome) => action({ outcome }));
  await show(page, { last_actions: { rows: rows.slice(0, 5), complete: true } });
  await expect(laRows(page).locator('.la-what')).toHaveText([
    'Settings saved by mikko', 'Settings saved by mikko, refused', 'Settings saved by mikko, not accepted',
    'Settings saved by mikko, failed', 'Settings saved by mikko, failed']);
  await show(page, { last_actions: { rows: rows.slice(5), complete: true } });
  await expect(laRows(page).locator('.la-what')).toHaveText(['Settings saved by mikko, failed', 'Settings saved by mikko, failed']);
});

const step = (page, n) => panel(page, 'checklist').locator(`li[data-step="${n}"]`);
/** The checklist for `servers` registered servers and the given checklist fields. */
const setup = (servers, checklist) => ({ kpi: { ...overview().kpi, servers_total: servers }, checklist });
/** Asserts step `n` is done (a ✓, no link) or open (its number, the link `href` or the wait line). */
async function expectStep(page, n, { done, href, waits }) {
  const s = step(page, n);
  await expect(s.locator('.ck-mark')).toHaveText(done ? '✓' : String(n));
  if (done || waits) await expect(s.locator('a')).toHaveCount(0);
  else await expect(s.locator('a.ck-go')).toHaveAttribute('href', href);
  if (waits) await expect(s).toContainText('Opens after step 1.');
}

test('C1 nothing set up: 0 of 3, and steps 2 and 3 wait for step 1', async ({ page }) => {
  await show(page, setup(0, { has_key: false, tool_tried: false, client_seen: false }));
  await expect(panel(page, 'checklist').locator('h2')).toContainText('Get started');
  await expect(panel(page, 'checklist').locator('.ck-count')).toHaveText('0 of 3');
  await expectStep(page, 1, { href: '/ui/servers/settings' });
  await expectStep(page, 2, { waits: true });
  await expectStep(page, 3, { waits: true });
});

test('C2 servers in: 1 of 3', async ({ page }) => {
  await show(page, setup(3, { has_key: false, tool_tried: false, client_seen: false }));
  await expect(panel(page, 'checklist').locator('.ck-count')).toHaveText('1 of 3');
  await expectStep(page, 1, { done: true });
  await expectStep(page, 2, { href: '/ui/tools/actions' });
  await expectStep(page, 3, { href: '/ui/gateway/settings' });
});

test('C3 a tool tried: 2 of 3', async ({ page }) => {
  await show(page, setup(3, { has_key: false, tool_tried: true, client_seen: false }));
  await expect(panel(page, 'checklist').locator('.ck-count')).toHaveText('2 of 3');
  await expectStep(page, 1, { done: true });
  await expectStep(page, 2, { done: true });
  await expectStep(page, 3, { href: '/ui/gateway/settings' });
});

test('C4 all three done: the checklist is gone', async ({ page }) => {
  await show(page, setup(3, { has_key: true, tool_tried: true, client_seen: false }));
  await expect(panel(page, 'needs-you')).toHaveCount(1);
  await expect(panel(page, 'checklist')).toHaveCount(0);
});

test('C6 no key but a client seen also finishes step 3', async ({ page }) => {
  await show(page, setup(3, { has_key: false, tool_tried: true, client_seen: true }));
  await expect(panel(page, 'needs-you')).toHaveCount(1);
  await expect(panel(page, 'checklist')).toHaveCount(0);
  await show(page, setup(3, { has_key: false, tool_tried: true, client_seen: false }));
  await expect(panel(page, 'checklist').locator('.ck-count')).toHaveText('2 of 3');
});

test('C5 no counter store: step 2 says it is not counted and stays open', async ({ page }) => {
  const kpi = { servers_total: 3, servers_up: 3, tools_total: 9, uptime_secs: 60, version: '4.0.0' };
  await serve(page, { body: { ...body({ kpi, checklist: { has_key: true, client_seen: false } }), latency: undefined } });
  await open(page);
  await expect(panel(page, 'checklist').locator('.ck-count')).toHaveText('2 of 3');
  await expectStep(page, 2, { href: '/ui/tools/actions' });
  await expect(step(page, 2)).toContainText('Not counted on this gateway');
  await expectStep(page, 3, { done: true });
});

const top = (loc) => loc.evaluate((e) => Math.round(e.getBoundingClientRect().top));
const BOTH = { needs_you: { rows: [{ ...SERVER_REFUSED, subject: 'n'.repeat(200) }], more: { count: 0 } }, last_actions: { rows: [action()], complete: true } };

test('L1 side by side when wide, stacked on a phone, and the tiles keep their arrangement', async ({ page }) => {
  await show(page, BOTH, 1440);
  await expect(panel(page, 'needs-you')).toHaveCount(1);
  await expect(panel(page, 'last-actions')).toHaveCount(1);
  // Layout settles after a resize: poll, never read once. Needs you shares its row with one panel when
  // wide (whichever the page order puts beside it) and with none on a phone.
  const beside = () => page.evaluate(() => {
    const top = (s) => s.getBoundingClientRect().top;
    const all = [...document.querySelectorAll('#content .ov > .ov-panel')];
    const ny = all.find((s) => s.dataset.panel === 'needs-you');
    return all.filter((s) => s !== ny && top(s) === top(ny)).length;
  });
  await expect.poll(beside).toBe(1);
  await expect(page.locator('#content .ov-strip [data-tile]')).toHaveCount(6);

  await page.setViewportSize({ width: 390, height: 844 });
  await expect.poll(beside).toBe(0);
  await expect(page.locator('#content .ov-strip [data-tile]')).toHaveCount(3);
  await expect(page.locator('#content details.ov-more summary')).toHaveText('More numbers (3)');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);

  await page.setViewportSize({ width: 1440, height: 1100 });
  await expect(page.locator('#content .ov-strip [data-tile]')).toHaveCount(6);
  await expect(page.locator('#content [data-tile]')).toHaveCount(6);
});

test('L2 one panel order, whichever panel arrives first', async ({ page }) => {
  for (const first of ['stand-ins', 'panels']) {
    await show(page, { ...BOTH, ...setup(3, { has_key: false, tool_tried: false, client_seen: false }) }, 1440);
    const order = await page.evaluate(async (standInsFirst) => {
      const url = performance.getEntriesByType('resource').map((e) => e.name).find((n) => /\/ui\/assets\/overview\.[0-9a-f]+\.js$/.test(n));
      const { place } = await import(url);
      const root = document.querySelector('#content .ov');
      // The real map and chart step aside for their stand-ins, so the order holds one of each.
      root.querySelectorAll(':scope > [data-panel="flow-map"], :scope > [data-panel="calls-chart"]').forEach((s) => s.remove());
      const made = ['flow-map', 'calls-chart'].map((id) => Object.assign(document.createElement('section'), { className: 'tk' }));
      made.forEach((s, i) => { s.dataset.panel = ['flow-map', 'calls-chart'][i]; s.style.minHeight = '40px'; });
      const mine = [...root.querySelectorAll('[data-panel="needs-you"], [data-panel="last-actions"]')];
      if (standInsFirst) { mine.forEach((s) => s.remove()); made.forEach((s) => place(root, s)); mine.forEach((s) => place(root, s)); }
      else made.forEach((s) => place(root, s));
      return [...root.querySelectorAll(':scope > [data-panel]')].map((s) => s.dataset.panel);
    }, first === 'stand-ins');
    expect(order).toEqual(['kpis', 'checklist', 'flow-map', 'needs-you', 'calls-chart', 'last-actions']);
    expect(await top(panel(page, 'flow-map'))).toBe(await top(panel(page, 'needs-you')));
    expect(await top(panel(page, 'calls-chart'))).toBe(await top(panel(page, 'last-actions')));
  }
});

for (const scheme of ['dark', 'light']) {
  for (const width of [390, 1440]) {
    test(`A1 axe with every panel drawn, ${scheme} at ${width}`, async ({ page }) => {
      await page.emulateMedia({ colorScheme: scheme });
      await show(page, { ...BOTH, ...setup(3, { has_key: false, tool_tried: false, client_seen: false }) }, width);
      await expect(panel(page, 'checklist')).toHaveCount(1);
      expect(await blockingViolations(page)).toEqual([]);
    });
  }
}

test('A2 Tab from the last tile link reaches every panel link in page order', async ({ page }) => {
  await show(page, { ...BOTH, ...setup(3, { has_key: false, tool_tried: false, client_seen: false }) }, 1440);
  await expect(panel(page, 'calls-chart').locator('figure.chart')).toHaveCount(1);
  const want = await page.locator('#content [data-panel]:not([data-panel="kpis"]) :is(a, summary)').evaluateAll((es) => es.map((e) => e.getAttribute('href') ?? e.textContent));
  // The checklist's two open steps, the one Needs you row, the chart's numbers toggle, then All in Activity.
  expect(want).toEqual(['/ui/tools/actions', '/ui/gateway/settings', `/ui/servers/${'n'.repeat(200)}/status`, 'The numbers', '/ui/activity/status']);
  await page.locator('#content [data-tile="tools"] a').focus();
  const got = [];
  for (let i = 0; i < want.length; i += 1) {
    await page.keyboard.press('Tab');
    got.push(await page.evaluate(() => document.activeElement?.getAttribute('href') ?? document.activeElement?.textContent ?? null));
  }
  expect(got).toEqual(want);
});
