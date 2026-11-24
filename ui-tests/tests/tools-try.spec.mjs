// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Tools › Actions, Try a tool. Fixture routes stand in for the gateway.
// Every expected string is written in the row. The screen under test is a
// stub: each row sees the marker, then fails on its own check.
import { test, expect, blockingViolations } from './base.mjs';
import { shellReady, shellModuleUrl, trackTimers, advanceArmed } from './shell.mjs';

const HOSTILE = '<img src=x onerror="window.__pwned=1">';

const tool = (name, server, cls, schema) => ({
  name,
  server,
  class: cls,
  ...(schema === undefined ? {} : { schema }),
});

const READ = tool('web.search', 'search', 'read', { type: 'object', properties: {} });

const norm = (s) => s.replace(/\s+/g, ' ').trim();
const panel = (page) => page.locator('section.tools-try');
const runOf = (page, name) => panel(page).getByRole('button', { name: `Run ${name}`, exact: true });
/** How long an absence waits for a send that would follow the action, before it is read. */
const SETTLE_MS = 300;
/**
 * Run `action`, then hold until it has sent exactly `delta` more calls. A request
 * reaches its route only after the action that sent it resolves, so a count read
 * at once can miss a send: a "sent" check would then fail a right screen, and a
 * "nothing sent" check would pass a wrong one. Absence waits SETTLE_MS first.
 */
async function sends(bag, delta, action) {
  const before = bag.calls.length;
  await action();
  if (delta > 0) await expect.poll(() => bag.calls.length, { message: `${delta} more call(s) sent` }).toBe(before + delta);
  else await new Promise((resolve) => setTimeout(resolve, SETTLE_MS));
  expect(bag.calls.length, delta > 0 ? 'calls sent' : 'no call sent').toBe(before + delta);
}
/** The shell's one confirmation (UI1.19): its title, its one consequence, its two buttons. */
const ask = (page, name) => page.getByRole('dialog', { name: `Run ${name}?` });
const askRun = (page, name) => ask(page, name).getByRole('button', { name: `Run ${name}`, exact: true });
const askKeep = (page, name) => ask(page, name).getByRole('button', { name: `Cancel ${name}`, exact: true });
async function asked(page, name) {
  await expect(ask(page, name)).toBeVisible();
  await expect(ask(page, name).getByRole('listitem')).toHaveText([`${name} can change things.`]);
}
/** Every live-region form, as shell-live reads it: the panel has none of its own. */
const LIVE = '[aria-live], [role="status"], [role="alert"], [role="log"], [role="marquee"], [role="timer"], output';
/** Record the text of every entry added to the shell's announcer, from first paint. */
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
/** Whether the panel itself, or any node in it, is a live region. */
const liveInPanel = (page) => panel(page).evaluate((n, sel) => n.matches(sel) || n.querySelector(sel) !== null, LIVE);
const announced = async (page) => (await page.evaluate(() => window.__writes ?? [])).filter(Boolean);
/** Wait until the announcer has written everything queued (it pauses between writes). */
async function drained(page) {
  const url = await shellModuleUrl(page);
  await page.evaluate(async (u) => { const m = await import(u); await m.announcerIdle(); }, url);
}
const pauseClock = async (page) => page.clock.pauseAt(await page.evaluate(() => Date.now() + 5000));

function ran({ text = 'done', error = false, receipt, latency = 212, content } = {}) {
  const body = {
    result: { content: content ?? [{ type: 'text', text }], isError: error },
    is_error: error,
    latency_ms: latency,
    disposition: 'ran',
  };
  if (receipt) body.receipt = receipt;
  return body;
}

function callRow({ id, trace, account, name = 'web.search' }) {
  return { id, kind: 'call', trace_id: trace, tool: name, who: { account } };
}

function receiptOf({
  id,
  account,
  rule = 'allow-read',
  decided = 'allowed',
  effect = 'delivered',
  findings = ['quoted shell'],
  findingsListed = 1,
  line = null,
}) {
  return {
    id,
    who: { account },
    decision: { rule, decided, effect, findings },
    answer: {
      line: line ?? `effect: ${effect}; findings: ${findingsListed} listed`,
      records: [{ findings_listed: findingsListed }],
    },
  };
}

/** Listing returns the decoy first, then the call row. The receipt is that row only. */
function lookup(cfg, { trace = 't-abc', id = 'row-1', account = 'mikko', decoy = false, receipt } = {}) {
  cfg.onListing = (route, rec) => {
    if (rec.q !== trace) return route.fulfill({ json: { rows: [] } });
    const rows = [];
    if (decoy) rows.push(callRow({ id: 'row-9', trace: 't-zzz', account: 'other' }));
    rows.push(callRow({ id, trace, account }));
    return route.fulfill({ json: { rows } });
  };
  cfg.onReceipt = (route, rec) => {
    rec.status = rec.id === id ? 200 : 404;
    if (rec.id !== id) return route.fulfill({ status: 404, json: {} });
    return route.fulfill({ json: receipt ?? receiptOf({ id, account }) });
  };
}

async function install(page, cfg) {
  const bag = { calls: [], listings: [], receipts: [] };
  await page.route('**/ui/api/**', async (route) => {
    const req = route.request();
    const url = new URL(req.url());
    const path = url.pathname;
    if (path === '/ui/api/status') {
      return route.fulfill({ json: { auth: { enabled: true, signed_in: true, admin: true } } });
    }
    if (path === '/ui/api/tools') {
      if (cfg.toolsHold) await cfg.toolsHold;
      const status = cfg.toolsStatus ?? 200;
      if (status !== 200) return route.fulfill({ status, json: { error: 'refused' } });
      const tools = cfg.tools ?? [READ];
      return route.fulfill({ json: { tools, total: tools.length } });
    }
    if (path === '/ui/api/tools/call' && req.method() === 'POST') {
      let body = null;
      try {
        body = req.postDataJSON();
      } catch {
        body = req.postData();
      }
      const rec = { body };
      bag.calls.push(rec);
      if (cfg.onCall) return cfg.onCall(route, rec);
      return route.fulfill({ json: cfg.callJson ?? ran() });
    }
    if (path === '/ui/api/activity/export') return route.continue();
    const receipt = path.match(/^\/ui\/api\/activity\/([^/]+)$/);
    if (receipt && req.method() === 'GET') {
      const rec = { id: decodeURIComponent(receipt[1]), path, status: 200 };
      bag.receipts.push(rec);
      if (cfg.onReceipt) return cfg.onReceipt(route, rec);
      return route.fulfill({ json: { id: rec.id } });
    }
    if (path === '/ui/api/activity' && req.method() === 'GET') {
      const rec = { q: url.searchParams.get('q'), path: path + url.search, status: 200 };
      bag.listings.push(rec);
      if (cfg.onListing) return cfg.onListing(route, rec);
      return route.fulfill({ json: { rows: [] } });
    }
    return route.continue();
  });
  return bag;
}

async function open(page, cfg, { clock = false } = {}) {
  if (clock) {
    await page.clock.install();
    await trackTimers(page);
  }
  const bag = await install(page, cfg);
  await page.goto('/ui/tools/actions');
  await shellReady(page);
  const section = page.locator('section.tools-try[data-try-stub]');
  await expect(section).toBeVisible();
  await expect(section.getByRole('heading', { name: 'Try a tool' })).toBeVisible();
  return bag;
}

async function markedRequired(locator) {
  return locator.evaluate((el) => {
    if (el.getAttribute('aria-required') === 'true' || el.required) return true;
    const id = el.id;
    const label = id ? document.querySelector(`label[for="${CSS.escape(id)}"]`) : el.closest('label');
    return /required/i.test(`${label?.textContent ?? ''} ${el.getAttribute('aria-label') ?? ''}`);
  });
}

const three = [{ type: 'text', text: 'one' }, { type: 'text', text: 'two' }, { type: 'text', text: 'three' }];

test('F1 picker lists name, server and class in API order', async ({ page }) => {
  const cfg = {
    tools: [
      tool('web.search', 'search', 'read', { type: 'object', properties: {} }),
      tool('notes.list', 'notes', 'write', { type: 'object', properties: {} }),
    ],
  };
  await open(page, cfg);
  const options = panel(page).getByRole('option');
  await expect(options.first()).toBeAttached();
  expect((await options.allTextContents()).map(norm)).toEqual([
    'web.search search · reads only',
    'notes.list notes · writes',
  ]);
  const chosen = await panel(page).getByRole('combobox').first().evaluate((el) => (
    el.selectedOptions?.[0]?.textContent ?? el.textContent
  ));
  expect(norm(chosen)).toBe('web.search search · reads only');
});

test('F2 two servers with one tool name: the second sends its server', async ({ page }) => {
  const cfg = {
    tools: [
      tool('web.search', 'alpha', 'read', { type: 'object', properties: {} }),
      tool('web.search', 'bravo', 'read', { type: 'object', properties: {} }),
    ],
  };
  const bag = await open(page, cfg);
  const options = panel(page).getByRole('option');
  await expect(options.nth(1)).toBeAttached();
  expect((await options.allTextContents()).map(norm)).toEqual([
    'web.search alpha · reads only',
    'web.search bravo · reads only',
  ]);
  await panel(page).getByRole('combobox').first().selectOption({ index: 1 });
  await sends(bag, 1, () => runOf(page, 'web.search').click());
  expect(bag.calls).toHaveLength(1);
  expect(bag.calls[0].body).toEqual({
    server: 'bravo',
    tool: 'web.search',
    arguments: {},
    confirm_write: false,
  });
});

test('F3 string, number, enum and required boolean', async ({ page }) => {
  const cfg = {
    tools: [tool('web.search', 'search', 'read', {
      type: 'object',
      required: ['query', 'limit', 'mode', 'agree'],
      properties: {
        query: { type: 'string' },
        limit: { type: 'integer' },
        mode: { type: 'string', enum: ['fast', 'deep'] },
        agree: { type: 'boolean' },
      },
    })],
  };
  await open(page, cfg);
  const query = page.getByLabel('query');
  await expect(query).toBeVisible();
  await expect(query).toHaveAttribute('type', 'text');
  await expect(page.getByLabel('limit')).toHaveAttribute('type', 'number');
  expect((await page.getByLabel('mode').locator('option').allTextContents()).map(norm)).toEqual(['fast', 'deep']);
  await expect(page.getByLabel('agree')).toHaveRole('checkbox');
});

test('F4 a default is a placeholder and is sent only once typed', async ({ page }) => {
  const cfg = {
    tools: [tool('web.search', 'search', 'read', {
      type: 'object',
      properties: { query: { type: 'string', default: 'helsinki' } },
    })],
  };
  const bag = await open(page, cfg);
  const query = page.getByLabel('query');
  await expect(query).toBeVisible();
  await expect(query).toHaveAttribute('placeholder', 'helsinki');
  await expect(query.locator('..')).toContainText('default');
  await expect(query).toHaveValue('');
  const run = runOf(page, 'web.search');
  await sends(bag, 1, () => run.click());
  expect(bag.calls[0].body.arguments).toEqual({});
  await query.fill('tampere');
  await sends(bag, 1, () => run.click());
  expect(bag.calls[1].body.arguments).toEqual({ query: 'tampere' });
});

test('F5 optional enum and optional boolean: default is left out', async ({ page }) => {
  const cfg = {
    tools: [tool('web.search', 'search', 'read', {
      type: 'object',
      properties: {
        mode: { type: 'string', enum: ['fast', 'deep'] },
        notify: { type: 'boolean' },
      },
    })],
  };
  const bag = await open(page, cfg);
  const mode = page.getByLabel('mode');
  await expect(mode).toBeVisible();
  expect((await mode.locator('option').allTextContents()).map(norm)).toEqual(['default', 'fast', 'deep']);
  await expect(mode.locator('option:checked')).toHaveText('default');
  const notify = page.getByLabel('notify');
  expect((await notify.locator('option').allTextContents()).map(norm)).toEqual(['default', 'true', 'false']);
  const run = runOf(page, 'web.search');
  await sends(bag, 1, () => run.click());
  expect(bag.calls.at(-1).body.arguments).toEqual({});
  await mode.selectOption({ label: 'fast' });
  await sends(bag, 1, () => run.click());
  expect(bag.calls.at(-1).body.arguments).toEqual({ mode: 'fast' });
  await mode.selectOption({ label: 'default' });
  await notify.selectOption({ label: 'false' });
  await sends(bag, 1, () => run.click());
  expect(bag.calls.at(-1).body.arguments).toEqual({ notify: false });
  await notify.selectOption({ label: 'true' });
  await sends(bag, 1, () => run.click());
  expect(bag.calls.at(-1).body.arguments).toEqual({ notify: true });
  await notify.selectOption({ label: 'default' });
  await sends(bag, 1, () => run.click());
  expect(bag.calls.at(-1).body.arguments).toEqual({});
});

test('F12 a boolean and an enum default show beside the control and are left out', async ({ page }) => {
  const cfg = {
    tools: [tool('web.search', 'search', 'read', {
      type: 'object',
      required: ['must'],
      properties: {
        notify: { type: 'boolean', default: true },
        mode: { type: 'string', enum: ['fast', 'deep'], default: 'fast' },
        must: { type: 'boolean', default: true },
      },
    })],
  };
  const bag = await open(page, cfg);
  const must = panel(page).getByLabel('must', { exact: true });
  // A required boolean is a checkbox: it starts at its default, and the default sits beside it.
  await expect(must).toBeChecked();
  await expect(must.locator('..').locator('span.muted')).toHaveText('true');
  const notify = panel(page).getByLabel('notify', { exact: true });
  const mode = panel(page).getByLabel('mode', { exact: true });
  await expect(notify).toBeVisible();
  // The option list already says "true" and "fast". The default sits beside the control.
  await expect(notify.locator('..').locator('span.muted')).toHaveText('true');
  await expect(mode.locator('..').locator('span.muted')).toHaveText('fast');
  await expect(notify.locator('option:checked')).toHaveText('default');
  await expect(mode.locator('option:checked')).toHaveText('default');
  await sends(bag, 1, () => runOf(page, 'web.search').click());
  expect(bag.calls[0].body.arguments).toEqual({ must: true });
});

test('F6 an empty required number blocks Run and names the field', async ({ page }) => {
  const cfg = {
    tools: [tool('web.search', 'search', 'read', {
      type: 'object',
      required: ['count'],
      properties: { count: { type: 'integer' } },
    })],
  };
  const bag = await open(page, cfg);
  const count = page.getByLabel('count');
  await expect(count).toBeVisible();
  expect(await markedRequired(count)).toBe(true);
  await sends(bag, 0, () => runOf(page, 'web.search').click({ timeout: 5000 }));
  expect(bag.calls).toHaveLength(0);
  await expect(count).toHaveAttribute('aria-invalid', 'true');
});

test('F7 object, array, $ref and oneOf are JSON fields', async ({ page }) => {
  const cfg = {
    tools: [tool('web.search', 'search', 'read', {
      type: 'object',
      required: ['need'],
      properties: {
        meta: { type: 'object' },
        tags: { type: 'array' },
        refd: { $ref: '#/$defs/Thing' },
        choice: { oneOf: [{ type: 'string' }] },
        need: { type: 'object' },
      },
    })],
  };
  const bag = await open(page, cfg);
  const meta = page.getByLabel('meta');
  await expect(meta).toBeVisible();
  await expect(page.getByLabel('tags')).toBeVisible();
  await expect(page.getByLabel('refd')).toBeVisible();
  await expect(page.getByLabel('choice')).toBeVisible();
  const need = page.getByLabel('need');
  await expect(need).toBeVisible();
  const run = runOf(page, 'web.search');
  await meta.fill('{');
  await sends(bag, 0, () => run.click({ timeout: 5000 }));
  expect(bag.calls).toHaveLength(0);
  await expect(meta).toHaveAttribute('aria-invalid', 'true');
  await meta.fill('');
  await sends(bag, 0, () => run.click({ timeout: 5000 }));
  expect(bag.calls).toHaveLength(0);
  await expect(need).toHaveAttribute('aria-invalid', 'true');
  await need.fill('{"ok":true}');
  await sends(bag, 1, () => run.click());
  expect(bag.calls.at(-1).body.arguments).toEqual({ need: { ok: true } });
  await page.getByLabel('tags').fill('[1,2]');
  await sends(bag, 1, () => run.click());
  expect(bag.calls.at(-1).body.arguments.tags).toEqual([1, 2]);
  await page.getByLabel('refd').fill('{"r":1}');
  await sends(bag, 1, () => run.click());
  expect(bag.calls.at(-1).body.arguments.refd).toEqual({ r: 1 });
  await page.getByLabel('choice').fill('"left"');
  await sends(bag, 1, () => run.click());
  expect(bag.calls.at(-1).body.arguments.choice).toBe('left');
  await meta.fill('{"a":1}');
  await sends(bag, 1, () => run.click());
  expect(bag.calls.at(-1).body.arguments.meta).toEqual({ a: 1 });
  // Invalid JSON as the only blocker: every other field is valid now, so a screen that
  // marks the field but still sends its text fails here, not only one that skips the mark.
  await meta.fill('{');
  await sends(bag, 0, () => run.click({ timeout: 5000 }));
  await expect(meta).toHaveAttribute('aria-invalid', 'true');
});

test('F7b a blank required text sends an empty string; a blank optional is left out', async ({ page }) => {
  const cfg = {
    tools: [tool('web.search', 'search', 'read', {
      type: 'object',
      required: ['q'],
      properties: { q: { type: 'string' }, note: { type: 'string' } },
    })],
  };
  const bag = await open(page, cfg);
  const q = page.getByLabel('q');
  await expect(q).toBeVisible();
  const run = runOf(page, 'web.search');
  await sends(bag, 1, () => run.click());
  expect(bag.calls[0].body.arguments).toEqual({ q: '' });
  await q.fill('y');
  await page.getByLabel('note').fill('x');
  await sends(bag, 1, () => run.click());
  expect(bag.calls[1].body.arguments).toEqual({ q: 'y', note: 'x' });
});

test('F3b an integer enum sends an integer, and an empty-string enum sends ""', async ({ page }) => {
  const cfg = {
    tools: [tool('web.search', 'search', 'read', {
      type: 'object',
      required: ['n', 'empty'],
      properties: {
        n: { type: 'integer', enum: [1, 2] },
        empty: { type: 'string', enum: ['', 'none'] },
      },
    })],
  };
  const bag = await open(page, cfg);
  // Exact, inside the section: a page-wide label of "n" also matches the shell's
  // "Environment" chip, so the field would never be the only match.
  const n = panel(page).getByLabel('n', { exact: true });
  await expect(n).toBeVisible();
  expect((await n.locator('option').allTextContents()).map(norm)).toEqual(['1', '2']);
  const empty = panel(page).getByLabel('empty', { exact: true });
  expect((await empty.locator('option').allTextContents()).map(norm)).toEqual(['', 'none']);
  await n.selectOption({ label: '2' });
  await empty.selectOption({ index: 0 });
  await sends(bag, 1, () => runOf(page, 'web.search').click());
  expect(bag.calls[0].body.arguments).toEqual({ n: 2, empty: '' });
  expect(typeof bag.calls[0].body.arguments.n).toBe('number');
});

test('F9 changing the picked tool clears the drawn answer', async ({ page }) => {
  const cfg = {
    tools: [
      tool('web.search', 'search', 'read', { type: 'object', properties: {} }),
      tool('notes.list', 'notes', 'read', { type: 'object', properties: {} }),
    ],
    callJson: ran({ text: 'from the first' }),
  };
  await open(page, cfg);
  const run = runOf(page, 'web.search');
  await expect(run).toBeVisible();
  await run.click();
  await expect(panel(page)).toContainText('from the first');
  await panel(page).getByRole('combobox').first().selectOption({ index: 1 });
  await expect(panel(page)).not.toContainText('from the first');
});

test('F10 loading, a failed tools list, and an empty list', async ({ page }) => {
  let release = () => {};
  const cfg = { toolsHold: new Promise((res) => { release = res; }), tools: [READ] };
  try {
    await open(page, cfg);
    await expect(panel(page).getByText('Reading tools…', { exact: true })).toBeVisible();
    release();
    await expect(runOf(page, 'web.search')).toBeVisible();
    cfg.toolsHold = null;
    cfg.toolsStatus = 500;
    await page.reload();
    await shellReady(page);
    await expect(page.locator('section.tools-try[data-try-stub]')).toBeVisible();
    await expect(panel(page).getByText('Tools could not be read', { exact: true })).toBeVisible();
    await expect(panel(page).getByRole('button', { name: /^Run / })).toHaveCount(0);
    cfg.toolsStatus = 200;
    cfg.tools = [];
    await page.reload();
    await shellReady(page);
    await expect(panel(page).getByText('No tools yet', { exact: true })).toBeVisible();
    await expect(panel(page).locator('a[href="/ui/servers/status"]')).toBeVisible();
  } finally {
    release();
  }
});

test('F11 a property named __proto__ is sent as its own key', async ({ page }) => {
  const cfg = {
    tools: [tool('web.search', 'search', 'read', {
      type: 'object',
      properties: { ['__proto__']: { type: 'string' } },
    })],
  };
  const bag = await open(page, cfg);
  const field = panel(page).getByLabel('__proto__', { exact: true });
  await expect(field).toBeVisible();
  await field.fill('owned');
  await sends(bag, 1, () => runOf(page, 'web.search').click());
  const args = bag.calls[0].body.arguments;
  expect(Object.prototype.hasOwnProperty.call(args, '__proto__')).toBe(true);
  expect(args).toEqual({ ['__proto__']: 'owned' });
});

test('F8 a root the form cannot model is one JSON field; none sends {}', async ({ page }) => {
  const cfg = {
    tools: [
      tool('one.of', 's', 'read', { oneOf: [{ type: 'object' }] }),
      tool('ref.tool', 's', 'read', { $ref: '#/Thing' }),
      tool('no.schema', 's', 'read'),
      tool('empty.schema', 's', 'read', {}),
    ],
  };
  const bag = await open(page, cfg);
  const box = panel(page).getByRole('textbox');
  await expect(box).toBeVisible();
  await box.fill('{"q":1}');
  await sends(bag, 1, () => runOf(page, 'one.of').click());
  expect(bag.calls.at(-1).body).toEqual({
    server: 's', tool: 'one.of', arguments: { q: 1 }, confirm_write: false,
  });
  await panel(page).getByRole('combobox').first().selectOption({ index: 1 });
  await panel(page).getByRole('textbox').fill('{"z":true}');
  await sends(bag, 1, () => runOf(page, 'ref.tool').click());
  expect(bag.calls.at(-1).body).toEqual({
    server: 's', tool: 'ref.tool', arguments: { z: true }, confirm_write: false,
  });
  await panel(page).getByRole('combobox').first().selectOption({ index: 2 });
  await expect(panel(page).getByRole('textbox')).toHaveCount(0);
  await sends(bag, 1, () => runOf(page, 'no.schema').click());
  expect(bag.calls.at(-1).body.arguments).toEqual({});
  await panel(page).getByRole('combobox').first().selectOption({ index: 3 });
  await expect(panel(page).getByRole('textbox')).toHaveCount(0);
  await sends(bag, 1, () => runOf(page, 'empty.schema').click());
  expect(bag.calls.at(-1).body.arguments).toEqual({});
});

test('F8b a whole-arguments value that is not an object blocks Run, and an allOf root is one JSON field', async ({ page }) => {
  const cfg = {
    tools: [
      tool('one.of', 's', 'read', { oneOf: [{ type: 'object' }] }),
      // Root properties too, so only the allOf rule sends this root to the JSON field.
      tool('all.of', 's', 'read', {
        type: 'object',
        properties: { b: { type: 'string' } },
        allOf: [{ type: 'object', properties: { a: { type: 'string' } } }, { required: ['a'] }],
      }),
    ],
  };
  const bag = await open(page, cfg);
  const box = panel(page).getByRole('textbox');
  await expect(box).toBeVisible();
  const run = runOf(page, 'one.of');
  for (const bad of ['[1,2]', '"text"', '5']) {
    await box.fill(bad);
    await sends(bag, 0, () => run.click({ timeout: 5000 }));
    await expect(box).toHaveAttribute('aria-invalid', 'true');
  }
  expect(bag.calls).toHaveLength(0);
  await panel(page).getByRole('combobox').first().selectOption({ index: 1 });
  await expect(panel(page).getByRole('textbox')).toBeVisible();
  await expect(panel(page).getByLabel('a', { exact: true })).toHaveCount(0);
  // The root's own property is not drawn as a field either: the whole root is one JSON field.
  await expect(panel(page).getByLabel('b', { exact: true })).toHaveCount(0);
});

test('R1 Run sends the exact body, typed', async ({ page }) => {
  const cfg = {
    tools: [tool('web.search', 'search', 'read', {
      type: 'object',
      required: ['limit', 'agree'],
      properties: { limit: { type: 'integer' }, agree: { type: 'boolean' } },
    })],
  };
  const bag = await open(page, cfg);
  const run = runOf(page, 'web.search');
  await expect(run).toBeVisible();
  await page.getByLabel('limit').fill('5');
  await page.getByLabel('agree').check();
  await sends(bag, 1, () => run.click());
  const body = bag.calls[0].body;
  expect(Object.keys(body).sort()).toEqual(['arguments', 'confirm_write', 'server', 'tool']);
  expect(body).toEqual({
    server: 'search',
    tool: 'web.search',
    arguments: { limit: 5, agree: true },
    confirm_write: false,
  });
  expect(body).not.toHaveProperty('key');
  expect(body).not.toHaveProperty('principal');
});

test('R2 a successful answer names the time and the result', async ({ page }) => {
  const cfg = { callJson: ran({ text: 'Helsinki in November', latency: 212 }) };
  await open(page, cfg);
  const run = runOf(page, 'web.search');
  await expect(run).toBeVisible();
  await run.click();
  await expect(panel(page)).toContainText('Answered in 212 ms');
  await expect(panel(page)).toContainText('Helsinki in November');
});

test('R4 empty content draws structured content as text', async ({ page }) => {
  const cfg = {};
  cfg.onCall = (route) => route.fulfill({
    json: {
      result: { content: [], structuredContent: { rows: 3 } },
      is_error: false,
      latency_ms: 212,
      disposition: 'ran',
    },
  });
  await open(page, cfg);
  const run = runOf(page, 'web.search');
  await expect(run).toBeVisible();
  await run.click();
  await expect(panel(page)).toContainText('Answered in 212 ms');
  await expect(panel(page)).toContainText('"rows": 3');
});

test('R2b an error result is not an answer', async ({ page }) => {
  const cfg = { callJson: ran({ text: 'backend failed', error: true, latency: 212 }) };
  await open(page, cfg);
  const run = runOf(page, 'web.search');
  await expect(run).toBeVisible();
  await run.click();
  await expect(panel(page)).toContainText('The tool answered with an error');
  await expect(panel(page)).toContainText('212 ms');
  await expect(panel(page)).toContainText('backend failed');
  await expect(panel(page)).not.toContainText('Answered in');
});

test('R3 the receipt lookup skips a decoy row', async ({ page }) => {
  const cfg = { callJson: ran({ text: 'Helsinki in November', receipt: 't-abc' }) };
  lookup(cfg, { decoy: true });
  const bag = await open(page, cfg);
  const run = runOf(page, 'web.search');
  await expect(run).toBeVisible();
  await run.click();
  await expect(panel(page)).toContainText('Recorded in Activity as a call by mikko');
  await expect(panel(page).locator('a[href="/ui/activity/row-1/status"]')).toBeVisible();
  expect(bag.listings.map((l) => l.path)).toEqual(['/ui/api/activity?q=t-abc']);
  expect(bag.receipts.map((r) => r.path)).toEqual(['/ui/api/activity/row-1']);
});

test('S1 the receipt draws rule, decided, effect and the two counts', async ({ page }) => {
  const cfg = { callJson: ran({ receipt: 't-abc', content: three }) };
  // Two request findings, one caught in the answer: N, M and the request count all differ.
  lookup(cfg, { receipt: receiptOf({ id: 'row-1', account: 'mikko', findings: ['quoted shell', 'path escape'], findingsListed: 1 }) });
  await open(page, cfg);
  const run = runOf(page, 'web.search');
  await expect(run).toBeVisible();
  await run.click();
  await expect(panel(page)).toContainText('allow-read');
  await expect(panel(page)).toContainText('allowed');
  await expect(panel(page)).toContainText('delivered');
  await expect(panel(page)).toContainText('3 results · 1 caught');
});

test('S2 a late record is read on the third try', async ({ page }) => {
  const cfg = { callJson: ran({ receipt: 't-abc', content: three }) };
  let n = 0;
  cfg.onListing = (route, rec) => {
    n += 1;
    rec.status = 200;
    if (n < 3) return route.fulfill({ json: { rows: [] } });
    return route.fulfill({ json: { rows: [callRow({ id: 'row-1', trace: 't-abc', account: 'mikko' })] } });
  };
  cfg.onReceipt = (route) => route.fulfill({ json: receiptOf({ id: 'row-1', account: 'mikko' }) });
  const bag = await open(page, cfg, { clock: true });
  const run = runOf(page, 'web.search');
  await expect(run).toBeVisible();
  await pauseClock(page);
  await run.click();
  await expect.poll(() => bag.listings.length).toBe(1);
  expect(bag.listings.map((l) => l.path)).toEqual(['/ui/api/activity?q=t-abc']);
  await advanceArmed(page, 500, 'wait');
  await expect.poll(() => bag.listings.length).toBe(2);
  expect(bag.listings.map((l) => l.path)).toEqual(['/ui/api/activity?q=t-abc', '/ui/api/activity?q=t-abc']);
  await advanceArmed(page, 500, 'wait');
  await expect.poll(() => bag.listings.length).toBe(3);
  expect(bag.listings.map((l) => l.path)).toEqual([
    '/ui/api/activity?q=t-abc',
    '/ui/api/activity?q=t-abc',
    '/ui/api/activity?q=t-abc',
  ]);
  await expect(panel(page)).toContainText('allow-read');
  await page.clock.runFor(500);
  expect(bag.listings).toHaveLength(3);
});

test('S3 a record that never arrives stops after the fourth try', async ({ page }) => {
  const cfg = { callJson: ran({ receipt: 't-abc' }) };
  cfg.onListing = (route) => route.fulfill({ json: { rows: [] } });
  const bag = await open(page, cfg, { clock: true });
  const run = runOf(page, 'web.search');
  await expect(run).toBeVisible();
  await pauseClock(page);
  await run.click();
  await expect.poll(() => bag.listings.length).toBe(1);
  await advanceArmed(page, 500, 'wait');
  await expect.poll(() => bag.listings.length).toBe(2);
  await advanceArmed(page, 500, 'wait');
  await expect.poll(() => bag.listings.length).toBe(3);
  expect(await panel(page).innerText()).not.toContain('Firewall steps not recorded yet');
  await advanceArmed(page, 500, 'wait');
  await expect.poll(() => bag.listings.length).toBe(4);
  await expect(panel(page)).toContainText('Firewall steps not recorded yet');
  await expect(panel(page)).toContainText('t-abc');
  await page.clock.runFor(1500);
  expect(bag.listings).toHaveLength(4);
});

test('S4 a listing that fails, and one failure then the row', async ({ page }) => {
  const cfg = { callJson: ran({ receipt: 't-abc', content: three }) };
  let mode = 'all-fail';
  cfg.onListing = (route, rec) => {
    const fail = mode === 'all-fail' || (mode === 'one-then-row' && !cfg.failedOnce);
    if (mode === 'one-then-row') cfg.failedOnce = true;
    if (fail) {
      rec.status = 500;
      return route.fulfill({ status: 500, json: { error: 'down' } });
    }
    rec.status = 200;
    return route.fulfill({ json: { rows: [callRow({ id: 'row-1', trace: 't-abc', account: 'mikko' })] } });
  };
  cfg.onReceipt = (route) => route.fulfill({ json: receiptOf({ id: 'row-1', account: 'mikko' }) });
  const bag = await open(page, cfg);
  const run = runOf(page, 'web.search');
  await expect(run).toBeVisible();
  await run.click();
  await expect(panel(page)).toContainText('Firewall steps could not be read', { timeout: 8000 });
  expect(bag.listings).toHaveLength(4);
  expect(bag.listings.every((l) => l.status === 500)).toBe(true);
  mode = 'one-then-row';
  const before = bag.listings.length;
  await run.click();
  await expect(panel(page)).toContainText('allow-read', { timeout: 8000 });
  await expect(panel(page)).not.toContainText('Firewall steps could not be read');
  const added = bag.listings.slice(before);
  expect(added[0].status).toBe(500);
  expect(added.some((l) => l.status === 200)).toBe(true);
});

test('S5 a receipt fetch that fails is a miss', async ({ page }) => {
  const cfg = { callJson: ran({ receipt: 't-abc' }) };
  cfg.onListing = (route) => route.fulfill({
    json: { rows: [callRow({ id: 'row-1', trace: 't-abc', account: 'mikko' })] },
  });
  cfg.onReceipt = (route, rec) => {
    rec.status = 500;
    return route.fulfill({ status: 500, json: { error: 'down' } });
  };
  const bag = await open(page, cfg);
  const run = runOf(page, 'web.search');
  await expect(run).toBeVisible();
  await run.click();
  await expect(panel(page)).toContainText('Firewall steps could not be read', { timeout: 8000 });
  await expect(panel(page)).toContainText('t-abc');
  expect(bag.receipts).toHaveLength(4);
  expect(bag.receipts.every((r) => r.status === 500)).toBe(true);
});

test('S6 an unscanned answer replaces the caught count', async ({ page }) => {
  const cfg = { callJson: ran({ receipt: 't-abc', content: three }) };
  lookup(cfg, {
    receipt: receiptOf({
      id: 'row-1',
      account: 'mikko',
      findingsListed: 1,
      line: 'effect: delivered; the answer was not scanned',
    }),
  });
  await open(page, cfg);
  const run = runOf(page, 'web.search');
  await expect(run).toBeVisible();
  await run.click();
  await expect(panel(page)).toContainText('the answer was not scanned');
  await expect(panel(page)).not.toContainText('caught');
});

test('W1 a write tool asks before it sends', async ({ page }) => {
  const cfg = { tools: [tool('fs.write', 'fs', 'write', { type: 'object', properties: {} })] };
  const bag = await open(page, cfg);
  const run = runOf(page, 'fs.write');
  await expect(run).toBeVisible();
  await sends(bag, 0, () => run.click());
  await asked(page, 'fs.write');
  await expect(askRun(page, 'fs.write')).toBeVisible();
  await expect(askKeep(page, 'fs.write')).toBeVisible();
  expect(bag.calls).toHaveLength(0);
});

test('W2 confirm sends confirm_write true and draws the answer in the panel; Esc sends nothing and keeps the form', async ({ page }) => {
  const cfg = {
    tools: [tool('fs.write', 'fs', 'write', {
      type: 'object',
      properties: { path: { type: 'string' } },
    })],
    callJson: ran({ text: 'wrote it' }),
  };
  const bag = await open(page, cfg);
  const run = runOf(page, 'fs.write');
  await expect(run).toBeVisible();
  await page.getByLabel('path').fill('/tmp/kept');
  await sends(bag, 0, () => run.click());
  await asked(page, 'fs.write');
  expect(bag.calls).toHaveLength(0);
  await sends(bag, 1, () => askRun(page, 'fs.write').click());
  expect(bag.calls[0].body.confirm_write).toBe(true);
  expect(bag.calls[0].body.arguments).toEqual({ path: '/tmp/kept' });
  await expect(ask(page, 'fs.write')).toHaveCount(0);
  await expect(panel(page)).toContainText('Answered in 212 ms');
  await expect(panel(page)).toContainText('wrote it');
  await expect(run, 'focus back on Run after the confirm closes').toBeFocused();
  await run.click();
  await asked(page, 'fs.write');
  await sends(bag, 0, () => page.keyboard.press('Escape'));
  await expect(ask(page, 'fs.write')).toHaveCount(0);
  expect(bag.calls).toHaveLength(1);
  await expect(page.getByLabel('path')).toHaveValue('/tmp/kept');
});

test('W3 a 409 asks again and confirm resends the same arguments', async ({ page }) => {
  const cfg = {
    tools: [tool('web.search', 'search', 'read', {
      type: 'object',
      properties: { query: { type: 'string' }, limit: { type: 'integer' } },
    })],
  };
  cfg.onCall = (route, rec) => {
    if (!rec.body.confirm_write) {
      return route.fulfill({
        status: 409,
        json: { error: 'confirm_write_required', message: 'confirm the write', disposition: 'not_run' },
      });
    }
    return route.fulfill({ json: ran({ text: 'wrote' }) });
  };
  const bag = await open(page, cfg);
  const run = runOf(page, 'web.search');
  await expect(run).toBeVisible();
  await page.getByLabel('query').fill('helsinki');
  await page.getByLabel('limit').fill('5');
  await sends(bag, 1, () => run.click());
  await asked(page, 'web.search');
  await sends(bag, 1, () => askRun(page, 'web.search').click());
  expect(bag.calls).toHaveLength(2);
  const [first, second] = bag.calls.map((c) => c.body);
  expect(first.confirm_write).toBe(false);
  expect(second.confirm_write).toBe(true);
  expect({ ...second, confirm_write: false }).toEqual(first);
  expect(first.arguments).toEqual({ query: 'helsinki', limit: 5 });
  await expect(panel(page)).toContainText('wrote');
});

test('W4 cancel after a 409 sends nothing more and keeps the form', async ({ page }) => {
  const cfg = {
    tools: [tool('web.search', 'search', 'read', {
      type: 'object',
      properties: { query: { type: 'string' } },
    })],
  };
  cfg.onCall = (route) => route.fulfill({
    status: 409,
    json: { error: 'confirm_write_required', message: 'confirm the write', disposition: 'not_run' },
  });
  const bag = await open(page, cfg);
  const run = runOf(page, 'web.search');
  await expect(run).toBeVisible();
  await page.getByLabel('query').fill('helsinki');
  await sends(bag, 1, () => run.click());
  await asked(page, 'web.search');
  await sends(bag, 0, () => page.keyboard.press('Escape'));
  await expect(ask(page, 'web.search')).toHaveCount(0);
  expect(bag.calls).toHaveLength(1);
  await expect(page.getByLabel('query')).toHaveValue('helsinki');
  await expect(run, 'focus back on Run after the confirm closes').toBeFocused();
});

test('W5 focus starts on Cancel: Enter and Esc keep, only the dialog\'s Run sends', async ({ page }) => {
  const cfg = {
    tools: [tool('fs.write', 'fs', 'write', {
      type: 'object',
      properties: { path: { type: 'string' } },
    })],
  };
  const bag = await open(page, cfg);
  const run = runOf(page, 'fs.write');
  await expect(run).toBeVisible();
  await page.getByLabel('path').fill('/tmp/kept');
  await run.click();
  await asked(page, 'fs.write');
  await expect(askKeep(page, 'fs.write')).toBeFocused();
  await sends(bag, 0, () => page.keyboard.press('Enter'));
  await expect(ask(page, 'fs.write')).toHaveCount(0);
  await run.click();
  await asked(page, 'fs.write');
  await sends(bag, 0, () => page.keyboard.press('Escape'));
  await expect(ask(page, 'fs.write')).toHaveCount(0);
  expect(bag.calls).toHaveLength(0);
  await expect(page.getByLabel('path')).toHaveValue('/tmp/kept');
  await run.click();
  await asked(page, 'fs.write');
  await sends(bag, 1, () => askRun(page, 'fs.write').click());
  expect(bag.calls[0].body.confirm_write).toBe(true);
});

test('W6 the write confirm\'s Cancel button sends nothing and keeps the form', async ({ page }) => {
  const cfg = {
    tools: [tool('fs.write', 'fs', 'write', {
      type: 'object',
      properties: { path: { type: 'string' } },
    })],
  };
  const bag = await open(page, cfg);
  const run = runOf(page, 'fs.write');
  await expect(run).toBeVisible();
  await page.getByLabel('path').fill('/tmp/kept');
  await sends(bag, 0, () => run.click());
  await asked(page, 'fs.write');
  await sends(bag, 0, () => askKeep(page, 'fs.write').click());
  await expect(ask(page, 'fs.write')).toHaveCount(0);
  expect(bag.calls).toHaveLength(0);
  await expect(page.getByLabel('path')).toHaveValue('/tmp/kept');
  await expect(run).toBeEnabled();
  await expect(run, 'focus back on Run after the confirm closes').toBeFocused();
});

test('W7 a 409 after opening Status shows no confirm and sends nothing more', async ({ page }) => {
  let release = () => {};
  let started = () => {};
  const entered = new Promise((res) => { started = res; });
  const cfg = {
    tools: [tool('web.search', 'search', 'read', {
      type: 'object',
      properties: { query: { type: 'string' } },
    })],
  };
  cfg.onCall = async (route) => {
    started();
    await new Promise((res) => { release = res; });
    return route.fulfill({
      status: 409,
      json: { error: 'confirm_write_required', message: 'confirm the write', disposition: 'not_run' },
    });
  };
  try {
    const bag = await open(page, cfg);
    const run = runOf(page, 'web.search');
    await expect(run).toBeVisible();
    await page.getByLabel('query').fill('helsinki');
    await run.click();
    await entered;
    expect(bag.calls).toHaveLength(1);
    await page.locator('nav.tabs').getByRole('link', { name: 'Status', exact: true }).click();
    await expect(page).toHaveURL(/\/ui\/tools\/status$/);
    await expect(panel(page)).toHaveCount(0);
    await sends(bag, 0, () => release());
    await expect(page.getByRole('dialog')).toHaveCount(0);
    expect(bag.calls).toHaveLength(1);
  } finally {
    release();
  }
});

test('W8 a confirmed write that is blocked closes the confirm and draws Blocked in the panel', async ({ page }) => {
  const cfg = {
    tools: [tool('fs.write', 'fs', 'write', { type: 'object', properties: {} })],
    onCall: (route) => route.fulfill({
      status: 403,
      json: { error: 'refused', message: 'the firewall rule denied this call', disposition: 'not_run' },
    }),
  };
  const bag = await open(page, cfg);
  const run = runOf(page, 'fs.write');
  await expect(run).toBeVisible();
  await run.click();
  await asked(page, 'fs.write');
  await sends(bag, 1, () => askRun(page, 'fs.write').click());
  await expect(ask(page, 'fs.write')).toHaveCount(0);
  await expect(panel(page)).toContainText('Blocked');
  await expect(panel(page)).toContainText('the firewall rule denied this call');
});

test('W9 a confirmed write with no answer stays in the confirm; once closed, the panel says so and Run stays off', async ({ page }) => {
  const cfg = {
    tools: [tool('fs.write', 'fs', 'write', { type: 'object', properties: {} })],
    onCall: (route) => route.abort('failed'),
  };
  const bag = await open(page, cfg);
  const run = runOf(page, 'fs.write');
  await expect(run).toBeVisible();
  await run.click();
  await asked(page, 'fs.write');
  await sends(bag, 1, () => askRun(page, 'fs.write').click());
  await expect(ask(page, 'fs.write')).toContainText('The gateway did not confirm the outcome.');
  await expect(ask(page, 'fs.write')).toContainText('Reload to see whether fs.write changed.');
  await expect(panel(page)).not.toContainText('No answer from the gateway');
  await ask(page, 'fs.write').getByRole('button', { name: 'Close', exact: true }).click();
  await expect(ask(page, 'fs.write')).toHaveCount(0);
  await expect(panel(page)).toContainText('fs.write may have run; the gateway did not confirm it');
  await expect(panel(page)).toContainText('Reload the page before running it again.');
  await expect(run).toBeDisabled();
  await sends(bag, 0, () => run.click({ force: true, timeout: 5000 }));
  await expect(page.getByRole('dialog')).toHaveCount(0);
});

test('W10 an unconfirmed write keeps that tool off after leaving the screen and coming back, until a reload', async ({ page }) => {
  const cfg = {
    tools: [tool('fs.write', 'fs', 'write', { type: 'object', properties: {} })],
    onCall: (route) => route.abort('failed'),
  };
  const bag = await open(page, cfg);
  const run = runOf(page, 'fs.write');
  await expect(run).toBeVisible();
  await run.click();
  await asked(page, 'fs.write');
  await sends(bag, 1, () => askRun(page, 'fs.write').click());
  await expect(ask(page, 'fs.write')).toContainText('The gateway did not confirm the outcome.');
  await ask(page, 'fs.write').getByRole('button', { name: 'Close', exact: true }).click();
  await expect(run).toBeDisabled();
  await page.locator('nav.tabs').getByRole('link', { name: 'Status', exact: true }).click();
  await expect(page).toHaveURL(/\/ui\/tools\/status$/);
  await page.locator('nav.tabs').getByRole('link', { name: 'Actions', exact: true }).click();
  await expect(page).toHaveURL(/\/ui\/tools\/actions$/);
  const again = runOf(page, 'fs.write');
  await expect(again).toBeVisible();
  await expect(again, 'still off after coming back').toBeDisabled();
  await sends(bag, 0, () => again.click({ force: true, timeout: 5000 }));
  await expect(page.getByRole('dialog')).toHaveCount(0);
});

test('E1 a refused call with a receipt says Blocked and links the receipt', async ({ page }) => {
  const cfg = {};
  cfg.onCall = (route) => route.fulfill({
    status: 403,
    json: {
      error: 'refused',
      message: 'the firewall rule denied this call',
      disposition: 'not_run',
      receipt: 't-abc',
    },
  });
  lookup(cfg, { decoy: true });
  await open(page, cfg);
  const run = runOf(page, 'web.search');
  await expect(run).toBeVisible();
  await run.click();
  await expect(panel(page)).toContainText('Blocked');
  await expect(panel(page)).toContainText('the firewall rule denied this call');
  await expect(panel(page).locator('a[href="/ui/activity/row-1/status"]')).toBeVisible();
});

test('E1b the admin guard says Not run and does not look up a receipt', async ({ page }) => {
  const cfg = {};
  cfg.onCall = (route) => route.fulfill({
    status: 403,
    json: { error: 'Admin authentication required' },
  });
  const bag = await open(page, cfg);
  const run = runOf(page, 'web.search');
  await expect(run).toBeVisible();
  await run.click();
  await expect(panel(page)).toContainText('Not run');
  await expect(panel(page)).toContainText('Admin authentication required');
  await expect(panel(page).locator('a[href^="/ui/activity/"]')).toHaveCount(0);
  expect(bag.listings).toHaveLength(0);
});

test('E1c a refused call whose receipt is not listed says Blocked and does not link it', async ({ page }) => {
  const cfg = {};
  cfg.onCall = (route) => route.fulfill({
    status: 403,
    json: {
      error: 'refused',
      message: 'the firewall rule denied this call',
      disposition: 'not_run',
      receipt: 't-nolog',
    },
  });
  cfg.onListing = (route) => route.fulfill({ json: { rows: [] } });
  const bag = await open(page, cfg);
  const run = runOf(page, 'web.search');
  await expect(run).toBeVisible();
  await run.click();
  await expect.poll(() => bag.listings.length).toBe(4);
  expect(bag.listings.map((l) => l.q)).toEqual(['t-nolog', 't-nolog', 't-nolog', 't-nolog']);
  await expect(panel(page)).toContainText('Blocked');
  await expect(panel(page)).toContainText('Firewall steps not recorded yet');
  await expect(panel(page).locator('a[href^="/ui/activity/"]')).toHaveCount(0);
  expect(bag.receipts).toHaveLength(0);
});

test('E2 a failed call that may have run', async ({ page }) => {
  const cfg = {};
  cfg.onCall = (route) => route.fulfill({
    status: 500,
    json: {
      error: 'failed',
      message: 'the call failed after it was sent',
      disposition: 'may_have_run',
    },
  });
  await open(page, cfg);
  const run = runOf(page, 'web.search');
  await expect(run).toBeVisible();
  await run.click();
  await expect(panel(page)).toContainText('The tool may have run');
  await expect(panel(page)).toContainText('the call failed after it was sent');
  await expect(panel(page)).not.toContainText('Answered');
  await expect(panel(page)).not.toContainText('Not run');
});

test('E3 a deadline says the tool may still be running', async ({ page }) => {
  const cfg = {};
  cfg.onCall = (route) => route.fulfill({
    status: 504,
    json: {
      error: 'deadline',
      message: 'no answer in time; the tool may still be running',
      disposition: 'may_have_run',
    },
  });
  await open(page, cfg);
  const run = runOf(page, 'web.search');
  await expect(run).toBeVisible();
  await run.click();
  await expect(panel(page)).toContainText('Timed out; the tool may still be running');
});

test('E3b a 504 that did not run says Not run and never Timed out', async ({ page }) => {
  const cfg = {};
  cfg.onCall = (route) => route.fulfill({
    status: 504,
    json: {
      error: 'deadline',
      message: 'no answer in time; nothing was run',
      disposition: 'not_run',
    },
  });
  await open(page, cfg);
  const run = runOf(page, 'web.search');
  await expect(run).toBeVisible();
  await run.click();
  await expect(panel(page)).toContainText('Not run');
  await expect(panel(page)).toContainText('no answer in time; nothing was run');
  await expect(panel(page)).not.toContainText('Timed out');
});

test('E4 audit down before the call says Not run', async ({ page }) => {
  const cfg = {};
  cfg.onCall = (route) => route.fulfill({
    status: 503,
    json: { error: 'audit_unavailable', message: 'the audit log is down', disposition: 'not_run' },
  });
  await open(page, cfg);
  const run = runOf(page, 'web.search');
  await expect(run).toBeVisible();
  await run.click();
  await expect(panel(page)).toContainText('Not run');
  await expect(panel(page)).toContainText('the audit log is down');
});

test('E5 audit down after the call may have run', async ({ page }) => {
  const cfg = {};
  cfg.onCall = (route) => route.fulfill({
    status: 503,
    json: { error: 'audit_unavailable', message: 'the audit log is down', disposition: 'may_have_run' },
  });
  await open(page, cfg);
  const run = runOf(page, 'web.search');
  await expect(run).toBeVisible();
  await run.click();
  await expect(panel(page)).toContainText('The tool may have run');
  await expect(panel(page)).toContainText('the audit log is down');
  await expect(panel(page)).not.toContainText('Not run');
});

test('E9 a 5xx with no disposition says the tool may have run', async ({ page }) => {
  const replies = [
    {
      status: 503,
      json: { error: 'audit log unavailable; the call may have run but its result is withheld' },
    },
    { status: 500, json: { error: 'upstream is down' } },
  ];
  const cfg = { onCall: (route) => route.fulfill(replies.shift()) };
  await open(page, cfg);
  const run = runOf(page, 'web.search');
  await expect(run).toBeVisible();
  await run.click();
  await expect(panel(page)).toContainText('The tool may have run');
  await expect(panel(page)).toContainText('audit log unavailable; the call may have run but its result is withheld');
  await expect(panel(page)).not.toContainText('Not run');
  await run.click();
  await expect(panel(page)).toContainText('upstream is down');
  await expect(panel(page)).toContainText('The tool may have run');
  await expect(panel(page)).not.toContainText('Not run');
  await expect(panel(page)).not.toContainText('audit log unavailable; the call may have run but its result is withheld');
});

test('E6 no answer from the gateway leaves the form usable', async ({ page }) => {
  const cfg = {
    tools: [tool('web.search', 'search', 'read', {
      type: 'object',
      properties: { query: { type: 'string' } },
    })],
  };
  cfg.onCall = (route) => route.abort('failed');
  await open(page, cfg);
  const run = runOf(page, 'web.search');
  await expect(run).toBeVisible();
  await page.getByLabel('query').fill('helsinki');
  await run.click();
  await expect(panel(page)).toContainText('No answer from the gateway; the tool may have run');
  await expect(run).toBeEnabled();
  await page.getByLabel('query').fill('still here');
  await expect(page.getByLabel('query')).toHaveValue('still here');
});

test('E7 a 400 and a 404 with no disposition say Not run', async ({ page }) => {
  const replies = [
    { status: 400, json: { error: 'bad_request', message: 'limit must be a number' } },
    { status: 404, json: { error: 'not_found', message: 'no such tool' } },
  ];
  const cfg = { onCall: (route) => route.fulfill(replies.shift()) };
  await open(page, cfg);
  const run = runOf(page, 'web.search');
  await expect(run).toBeVisible();
  await run.click();
  await expect(panel(page)).toContainText('Not run');
  await expect(panel(page)).toContainText('limit must be a number');
  await run.click();
  await expect(panel(page)).toContainText('no such tool');
  await expect(panel(page)).toContainText('Not run');
  await expect(panel(page)).not.toContainText('limit must be a number');
});

test('E8 a second Run while one is in flight sends nothing', async ({ page }) => {
  let release = () => {};
  let started = () => {};
  const entered = new Promise((res) => { started = res; });
  const cfg = {};
  cfg.onCall = async (route) => {
    started();
    await new Promise((res) => { release = res; });
    return route.fulfill({ json: ran({ text: 'done' }) });
  };
  try {
    const bag = await open(page, cfg);
    const run = runOf(page, 'web.search');
    await expect(run).toBeVisible();
    await run.click();
    await entered;
    await expect(run).toBeDisabled();
    expect(bag.calls).toHaveLength(1);
    release();
    await expect(run).toBeEnabled();
  } finally {
    release();
  }
});

test('E8b another tool\'s Run stays disabled while a call is in flight and clicking it sends nothing', async ({ page }) => {
  let release = () => {};
  let started = () => {};
  const entered = new Promise((res) => { started = res; });
  const cfg = {
    tools: [
      tool('web.search', 'search', 'read', { type: 'object', properties: {} }),
      tool('notes.list', 'notes', 'read', { type: 'object', properties: {} }),
    ],
  };
  cfg.onCall = async (route) => {
    started();
    await new Promise((res) => { release = res; });
    return route.fulfill({ json: ran({ text: 'done' }) });
  };
  try {
    const bag = await open(page, cfg);
    const run = runOf(page, 'web.search');
    await expect(run).toBeVisible();
    await run.click();
    await entered;
    await panel(page).getByRole('combobox').first().selectOption({ index: 1 });
    const next = runOf(page, 'notes.list');
    await expect(next).toBeVisible();
    await expect(next).toBeDisabled();
    await sends(bag, 0, () => next.click({ force: true, timeout: 5000 }));
    expect(bag.calls).toHaveLength(1);
    release();
    await expect(next).toBeEnabled();
  } finally {
    release();
  }
});

test('E8c while a confirmed write runs in the confirm, Run stays disabled until the answer is drawn', async ({ page }) => {
  let release = () => {};
  let started = () => {};
  const entered = new Promise((res) => { started = res; });
  const cfg = {
    tools: [
      tool('fs.write', 'fs', 'write', { type: 'object', properties: {} }),
      tool('notes.list', 'notes', 'read', { type: 'object', properties: {} }),
    ],
  };
  cfg.onCall = async (route) => {
    started();
    await new Promise((res) => { release = res; });
    return route.fulfill({ json: ran({ text: 'wrote it' }) });
  };
  try {
    const bag = await open(page, cfg);
    const run = runOf(page, 'fs.write');
    await expect(run).toBeVisible();
    await run.click();
    await asked(page, 'fs.write');
    await askRun(page, 'fs.write').click();
    await entered;
    await expect(run).toBeDisabled();
    expect(bag.calls).toHaveLength(1);
    release();
    await expect(ask(page, 'fs.write')).toHaveCount(0);
    await expect(panel(page)).toContainText('wrote it');
    await expect(run).toBeEnabled();
  } finally {
    release();
  }
});

test('G1 a newer run drops the older lookup', async ({ page }) => {
  const held = [];
  const cfg = {};
  let receipt = 't-a';
  cfg.onCall = (route) => {
    const mine = receipt;
    receipt = 't-b';
    const text = mine === 't-a' ? 'answer A' : 'answer B';
    return route.fulfill({ json: ran({ text, receipt: mine }) });
  };
  cfg.onListing = (route, rec) => {
    if (rec.q === 't-a') {
      held.push(route);
      return undefined;
    }
    if (rec.q === 't-b') {
      return route.fulfill({ json: { rows: [callRow({ id: 'row-b', trace: 't-b', account: 'bea' })] } });
    }
    return route.fulfill({ json: { rows: [] } });
  };
  cfg.onReceipt = (route, rec) => {
    if (rec.id === 'row-b') return route.fulfill({ json: receiptOf({ id: 'row-b', account: 'bea', rule: 'rule-b' }) });
    return route.fulfill({ json: receiptOf({ id: rec.id, account: 'ann', rule: 'rule-a' }) });
  };
  try {
    const bag = await open(page, cfg, { clock: true });
    const run = runOf(page, 'web.search');
    await expect(run).toBeVisible();
    await pauseClock(page);
    await run.click();
    await expect.poll(() => bag.listings.filter((l) => l.q === 't-a').length).toBe(1);
    await expect(panel(page)).toContainText('answer A');
    await expect(run).toBeEnabled();
    await run.click();
    await expect(panel(page)).toContainText('answer B');
    await expect(panel(page)).toContainText('Recorded in Activity as a call by bea');
    await expect(panel(page).locator('a[href="/ui/activity/row-b/status"]')).toBeVisible();
    await expect(panel(page)).toContainText('rule-b');
    await held[0].fulfill({ json: { rows: [callRow({ id: 'row-a', trace: 't-a', account: 'ann' })] } });
    held.shift();
    await page.clock.runFor(500);
    expect(bag.receipts.map((r) => r.id)).not.toContain('row-a');
    await expect(panel(page)).not.toContainText('ann');
    await expect(panel(page)).not.toContainText('rule-a');
    await expect(panel(page).locator('a[href="/ui/activity/row-a/status"]')).toHaveCount(0);
    await expect(panel(page)).toContainText('Recorded in Activity as a call by bea');
  } finally {
    for (const route of held) {
      try {
        await route.fulfill({ json: { rows: [] } });
      } catch {
        // already answered
      }
    }
  }
});

test('G2 an answer for an older run is not drawn', async ({ page }) => {
  // Run A, then change the picked tool before that call answers. E8 keeps Run
  // disabled while the call is in flight, so the switch is the picker.
  let release = () => {};
  let started = () => {};
  const entered = new Promise((res) => { started = res; });
  const cfg = {
    tools: [
      tool('web.search', 'search', 'read', { type: 'object', properties: {} }),
      tool('notes.list', 'notes', 'read', { type: 'object', properties: {} }),
    ],
  };
  cfg.onCall = async (route) => {
    started();
    await new Promise((res) => { release = res; });
    return route.fulfill({ json: ran({ text: 'answer A', receipt: 't-a' }) });
  };
  try {
    const bag = await open(page, cfg);
    const run = runOf(page, 'web.search');
    await expect(run).toBeVisible();
    await run.click();
    await entered;
    const listing = page.waitForRequest((req) => {
      const url = new URL(req.url());
      return url.pathname === '/ui/api/activity' && url.searchParams.get('q') === 't-a';
    }, { timeout: 1000 }).then(() => true, () => false);
    await panel(page).getByRole('combobox').first().selectOption({ index: 1 });
    const answer = panel(page).locator('.tools-try-answer');
    const before = (await answer.count()) ? norm(await answer.innerText()) : '';
    release();
    expect(await listing).toBe(false);
    await expect(panel(page)).not.toContainText('answer A');
    const after = (await answer.count()) ? norm(await answer.innerText()) : '';
    expect(after).toBe(before);
    expect(after).not.toContain('answer A');
    expect(bag.listings.filter((l) => l.q === 't-a')).toHaveLength(0);
  } finally {
    release();
  }
});

test('X1 tool text is text, never markup', async ({ page }) => {
  const cfg = {
    tools: [tool(HOSTILE, 'search', 'read', {
      type: 'object',
      required: ['mode'],
      properties: { mode: { type: 'string', enum: [HOSTILE] } },
    })],
    callJson: ran({ text: HOSTILE, receipt: 't-abc' }),
  };
  lookup(cfg, {
    receipt: receiptOf({ id: 'row-1', account: 'mikko', findings: [HOSTILE] }),
  });
  await open(page, cfg);
  await expect(panel(page)).toContainText(HOSTILE);
  const before = (await panel(page).evaluate((el) => el.textContent)).split(HOSTILE).length - 1;
  await page.getByLabel('mode').selectOption({ label: HOSTILE });
  await runOf(page, HOSTILE).click();
  await expect(panel(page)).toContainText('Recorded in Activity as a call by mikko');
  const after = (await panel(page).evaluate((el) => el.textContent)).split(HOSTILE).length - 1;
  // The name and the enum are already in the form. The result and the finding add two.
  expect(after).toBeGreaterThanOrEqual(before + 2);
  await expect(page.locator('img')).toHaveCount(0);
  expect(await page.evaluate(() => window.__pwned)).toBeUndefined();
});

const answerStates = [
  ['ran', { json: ran({ text: 'Helsinki in November' }) }, 'Helsinki in November'],
  ['is_error', { json: ran({ text: 'backend failed', error: true }) }, 'The tool answered with an error'],
  ['blocked', {
    status: 403,
    json: { error: 'refused', message: 'the firewall rule denied this call', disposition: 'not_run' },
  }, 'Blocked'],
  ['bad request', { status: 400, json: { error: 'bad_request', message: 'limit must be a number' } }, 'limit must be a number'],
  ['missing', { status: 404, json: { error: 'not_found', message: 'no such tool' } }, 'no such tool'],
  ['failed', {
    status: 500,
    json: { error: 'failed', message: 'the call failed after it was sent', disposition: 'may_have_run' },
  }, 'the call failed after it was sent'],
  ['deadline', {
    status: 504,
    json: { error: 'deadline', message: 'no answer in time; the tool may still be running', disposition: 'may_have_run' },
  }, 'Timed out; the tool may still be running'],
  ['audit not run', {
    status: 503,
    json: { error: 'audit_unavailable', message: 'the audit log is down', disposition: 'not_run' },
  }, 'Not run'],
  ['audit may', {
    status: 503,
    json: { error: 'audit_unavailable', message: 'the audit log is down', disposition: 'may_have_run' },
  }, 'The tool may have run'],
];

/** The headline each answer state says through the announcer, written out. */
const HEADLINES = {
  ran: 'Answered in 212 ms.',
  is_error: 'The tool answered with an error.',
  blocked: 'Blocked.',
  'bad request': 'Not run.',
  missing: 'Not run.',
  failed: 'The tool may have run.',
  deadline: 'Timed out; the tool may still be running.',
  'audit not run': 'Not run.',
  'audit may': 'The tool may have run.',
};

test('L1 every answer links Connect a client', async ({ page }) => {
  const queue = answerStates.map(([, reply]) => reply);
  const cfg = {
    onCall: (route) => {
      const reply = queue.shift();
      if (!reply) return route.abort('failed');
      if (reply.abort) return route.abort('failed');
      return route.fulfill(reply);
    },
  };
  await open(page, cfg);
  const run = runOf(page, 'web.search');
  await expect(run).toBeVisible();
  const link = panel(page).getByRole('link', { name: 'Connect a client' });
  for (const [name, , shown] of answerStates) {
    await run.click();
    await expect(panel(page), name).toContainText(shown);
    await expect(link, name).toHaveAttribute('href', '/ui/gateway/settings');
  }
  cfg.onCall = (route) => route.abort('failed');
  await run.click();
  await expect(panel(page)).toContainText('No answer from the gateway; the tool may have run');
  await expect(link).toHaveAttribute('href', '/ui/gateway/settings');
});

test('A1 axe passes on the form and on each answer; the panel has no live region and each answer\'s headline is said through the announcer', async ({ page }) => {
  // An axe scan per answer, under CPU starvation. With the whole suite under a 2-core
  // quota, three runs in twenty stalled past the default 30 s (worst 33.9 s); with the
  // timeout raised, no run in eighty went past 18.5 s. 60 s is that worst stall x 1.5,
  // rounded up to 10 s. Lower it once the stall is traced.
  test.setTimeout(60_000);
  await recordAnnouncements(page);
  const queue = answerStates.map(([, reply]) => reply);
  const cfg = { onCall: (route) => route.fulfill(queue.shift()) };
  await open(page, cfg);
  expect(await liveInPanel(page), 'the panel or a node in it is a live region').toBe(false);
  expect(await blockingViolations(page)).toEqual([]);
  const run = runOf(page, 'web.search');
  for (const [name, , shown] of answerStates) {
    await drained(page);
    const before = (await announced(page)).length;
    await run.click();
    await expect(panel(page), name).toContainText(shown);
    await drained(page);
    expect((await announced(page)).slice(before).join(' '), name).toBe(HEADLINES[name]);
    expect(await liveInPanel(page), name).toBe(false);
    expect(await blockingViolations(page), name).toEqual([]);
  }
  cfg.onCall = (route) => route.abort('failed');
  await drained(page);
  const before = (await announced(page)).length;
  await run.click();
  await expect(panel(page)).toContainText('No answer from the gateway; the tool may have run');
  await drained(page);
  expect((await announced(page)).slice(before).join(' ')).toBe('No answer from the gateway; the tool may have run.');
  expect(await blockingViolations(page)).toEqual([]);
});

test('A2 the steps line is said once it is drawn, after the headline', async ({ page }) => {
  await recordAnnouncements(page);
  const cfg = { callJson: ran({ receipt: 't-abc' }) };
  lookup(cfg);
  await open(page, cfg);
  const run = runOf(page, 'web.search');
  await expect(run).toBeVisible();
  await drained(page);
  const before = (await announced(page)).length;
  await run.click();
  await expect(panel(page)).toContainText('Recorded in Activity as a call by mikko');
  await drained(page);
  expect((await announced(page)).slice(before).join(' '))
    .toBe('Answered in 212 ms. Recorded in Activity as a call by mikko.');
});
