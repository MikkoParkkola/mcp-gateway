// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Tools › Actions, Try a tool. Fixture routes stand in for the gateway.
// Every expected string is written in the row. The screen under test is a
// stub: each row sees the marker, then fails on its own check.
import { test, expect, blockingViolations } from './base.mjs';
import { shellReady } from './shell.mjs';

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
  if (clock) await page.clock.install();
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
  await runOf(page, 'web.search').click();
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
  await run.click();
  expect(bag.calls[0].body.arguments).toEqual({});
  await query.fill('tampere');
  await run.click();
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
  await run.click();
  expect(bag.calls.at(-1).body.arguments).toEqual({});
  await mode.selectOption({ label: 'fast' });
  await run.click();
  expect(bag.calls.at(-1).body.arguments).toEqual({ mode: 'fast' });
  await mode.selectOption({ label: 'default' });
  await notify.selectOption({ label: 'false' });
  await run.click();
  expect(bag.calls.at(-1).body.arguments).toEqual({ notify: false });
  await notify.selectOption({ label: 'true' });
  await run.click();
  expect(bag.calls.at(-1).body.arguments).toEqual({ notify: true });
  await notify.selectOption({ label: 'default' });
  await run.click();
  expect(bag.calls.at(-1).body.arguments).toEqual({});
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
  await runOf(page, 'web.search').click({ timeout: 5000 });
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
  await run.click({ timeout: 5000 });
  expect(bag.calls).toHaveLength(0);
  await expect(meta).toHaveAttribute('aria-invalid', 'true');
  await meta.fill('');
  await run.click({ timeout: 5000 });
  expect(bag.calls).toHaveLength(0);
  await expect(need).toHaveAttribute('aria-invalid', 'true');
  await need.fill('{"ok":true}');
  await run.click();
  expect(bag.calls.at(-1).body.arguments).toEqual({ need: { ok: true } });
  await page.getByLabel('tags').fill('[1,2]');
  await run.click();
  expect(bag.calls.at(-1).body.arguments.tags).toEqual([1, 2]);
  await page.getByLabel('refd').fill('{"r":1}');
  await run.click();
  expect(bag.calls.at(-1).body.arguments.refd).toEqual({ r: 1 });
  await page.getByLabel('choice').fill('"left"');
  await run.click();
  expect(bag.calls.at(-1).body.arguments.choice).toBe('left');
  await meta.fill('{"a":1}');
  await run.click();
  expect(bag.calls.at(-1).body.arguments.meta).toEqual({ a: 1 });
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
  await run.click();
  expect(bag.calls[0].body.arguments).toEqual({ q: '' });
  await q.fill('y');
  await page.getByLabel('note').fill('x');
  await run.click();
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
  await runOf(page, 'web.search').click();
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
  await runOf(page, 'one.of').click();
  expect(bag.calls.at(-1).body).toEqual({
    server: 's', tool: 'one.of', arguments: { q: 1 }, confirm_write: false,
  });
  await panel(page).getByRole('combobox').first().selectOption({ index: 1 });
  await panel(page).getByRole('textbox').fill('{"z":true}');
  await runOf(page, 'ref.tool').click();
  expect(bag.calls.at(-1).body).toEqual({
    server: 's', tool: 'ref.tool', arguments: { z: true }, confirm_write: false,
  });
  await panel(page).getByRole('combobox').first().selectOption({ index: 2 });
  await expect(panel(page).getByRole('textbox')).toHaveCount(0);
  await runOf(page, 'no.schema').click();
  expect(bag.calls.at(-1).body.arguments).toEqual({});
  await panel(page).getByRole('combobox').first().selectOption({ index: 3 });
  await expect(panel(page).getByRole('textbox')).toHaveCount(0);
  await runOf(page, 'empty.schema').click();
  expect(bag.calls.at(-1).body.arguments).toEqual({});
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
  await run.click();
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
  await page.clock.runFor(500);
  await expect.poll(() => bag.listings.length).toBe(2);
  expect(bag.listings.map((l) => l.path)).toEqual(['/ui/api/activity?q=t-abc', '/ui/api/activity?q=t-abc']);
  await page.clock.runFor(500);
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
  await page.clock.runFor(500);
  await expect.poll(() => bag.listings.length).toBe(2);
  await page.clock.runFor(500);
  await expect.poll(() => bag.listings.length).toBe(3);
  expect(await panel(page).innerText()).not.toContain('Firewall steps not recorded yet');
  await page.clock.runFor(500);
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
  await run.click();
  await expect(page.getByText('fs.write can change things. Run it?', { exact: true })).toBeVisible();
  expect(bag.calls).toHaveLength(0);
});

test('W2 confirm sends confirm_write true; cancel sends nothing and keeps the form', async ({ page }) => {
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
  await expect(page.getByText('fs.write can change things. Run it?', { exact: true })).toBeVisible();
  expect(bag.calls).toHaveLength(0);
  await page.keyboard.press('Enter');
  expect(bag.calls).toHaveLength(1);
  expect(bag.calls[0].body.confirm_write).toBe(true);
  expect(bag.calls[0].body.arguments).toEqual({ path: '/tmp/kept' });
  await run.click();
  await expect(page.getByText('fs.write can change things. Run it?', { exact: true })).toBeVisible();
  await page.keyboard.press('Escape');
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
  await run.click();
  await expect(page.getByText('web.search can change things. Run it?', { exact: true })).toBeVisible();
  await page.keyboard.press('Enter');
  expect(bag.calls).toHaveLength(2);
  const [first, second] = bag.calls.map((c) => c.body);
  expect(first.confirm_write).toBe(false);
  expect(second.confirm_write).toBe(true);
  expect({ ...second, confirm_write: false }).toEqual(first);
  expect(first.arguments).toEqual({ query: 'helsinki', limit: 5 });
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
  await run.click();
  await expect(page.getByText('web.search can change things. Run it?', { exact: true })).toBeVisible();
  expect(bag.calls).toHaveLength(1);
  await page.keyboard.press('Escape');
  expect(bag.calls).toHaveLength(1);
  await expect(page.getByLabel('query')).toHaveValue('helsinki');
});

test('W5 Enter confirms and Esc cancels', async ({ page }) => {
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
  await expect(page.getByText('fs.write can change things. Run it?', { exact: true })).toBeVisible();
  await page.keyboard.press('Escape');
  expect(bag.calls).toHaveLength(0);
  await expect(page.getByLabel('path')).toHaveValue('/tmp/kept');
  await run.click();
  await expect(page.getByText('fs.write can change things. Run it?', { exact: true })).toBeVisible();
  await page.keyboard.press('Enter');
  expect(bag.calls).toHaveLength(1);
  expect(bag.calls[0].body.confirm_write).toBe(true);
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
    const answer = panel(page).locator('[aria-live]').first();
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
  ['ran', { json: ran({ text: 'Helsinki in November' }) }],
  ['is_error', { json: ran({ text: 'backend failed', error: true }) }],
  ['blocked', {
    status: 403,
    json: { error: 'refused', message: 'the firewall rule denied this call', disposition: 'not_run' },
  }],
  ['bad request', { status: 400, json: { error: 'bad_request', message: 'limit must be a number' } }],
  ['missing', { status: 404, json: { error: 'not_found', message: 'no such tool' } }],
  ['failed', {
    status: 500,
    json: { error: 'failed', message: 'the call failed after it was sent', disposition: 'may_have_run' },
  }],
  ['deadline', {
    status: 504,
    json: { error: 'deadline', message: 'no answer in time; the tool may still be running', disposition: 'may_have_run' },
  }],
  ['audit not run', {
    status: 503,
    json: { error: 'audit_unavailable', message: 'the audit log is down', disposition: 'not_run' },
  }],
  ['audit may', {
    status: 503,
    json: { error: 'audit_unavailable', message: 'the audit log is down', disposition: 'may_have_run' },
  }],
];

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
  for (const [name] of answerStates) {
    await run.click();
    await expect(link, name).toHaveAttribute('href', '/ui/gateway/settings');
  }
  cfg.onCall = (route) => route.abort('failed');
  await run.click();
  await expect(link).toHaveAttribute('href', '/ui/gateway/settings');
});

test('A1 axe passes on the form and on each answer, and the answer is a live region', async ({ page }) => {
  const queue = answerStates.map(([, reply]) => reply);
  const cfg = { onCall: (route) => route.fulfill(queue.shift()) };
  await open(page, cfg);
  const live = page.locator('section.tools-try[aria-live], section.tools-try [aria-live]');
  await expect(live.first()).toBeVisible();
  expect(['polite', 'assertive']).toContain(await live.first().getAttribute('aria-live'));
  expect(await blockingViolations(page)).toEqual([]);
  const run = runOf(page, 'web.search');
  for (const [name] of answerStates) {
    await run.click();
    await expect(live.first(), name).toBeVisible();
    expect(await blockingViolations(page), name).toEqual([]);
  }
  cfg.onCall = (route) => route.abort('failed');
  await run.click();
  await expect(live.first()).toBeVisible();
  expect(await blockingViolations(page)).toEqual([]);
});
