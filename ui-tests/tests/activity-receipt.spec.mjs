// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Rows for one Activity entry opened on its own page (/ui/activity/<id>/status):
// how its answer is fetched, the states it can end in, its rule link, the phone
// width, the keyboard, and text that must stay text. A field is found by its
// data-field attribute, the Rust key path of the value it shows, so these rows
// do not fix the screen's words. The field lists themselves are rows of their own.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { test, expect, blockingViolations } from './base.mjs';
import { shellReady, heldStream, frame } from './shell.mjs';

test.use({ timezoneId: 'UTC' });

const AT = Date.parse('2026-11-15T12:00:00Z');
const NOT_FINAL = 'delivery not yet recorded';
const HASH = (c) => `sha256:${c.repeat(64)}`;
const ID_A = '41-0123456789abcdef';
const ID_B = '42-fedcba9876543210';
const RULE = 'team/a+b';

/** The sentence the gateway writes where no rule id was recorded, read from its Rust source. */
function ruleNotRecorded() {
  const file = fileURLToPath(new URL('../../src/security/decision_record_read.rs', import.meta.url));
  const m = readFileSync(file, 'utf8').match(/const RULE_NOT_RECORDED: &str = "([^"]+)";/);
  if (!m) throw new Error('decision_record_read.rs: RULE_NOT_RECORDED not found');
  return m[1];
}

/** A call's receipt as GET /ui/api/activity/<id> answers it; `over` replaces top-level keys. */
function callReceipt(id, over = {}) {
  const effect = over.effect ?? 'delivered';
  return {
    id,
    kind: 'call',
    counter: Number(id.split('-')[0]),
    timestamp: '2026-11-15T08:00:00Z',
    signature: 'verified',
    server: 'docs',
    tool: 'kb.search',
    route: 'mcp',
    trace_id: `trace-${id}`,
    outcome: 'ok',
    who: { credential_kind: 'api_key', account: 'ops', authority: 'https://issuer.example', subject: 'sub-1' },
    request_hash: HASH('a'),
    response_hash: HASH('b'),
    findings: [],
    effect,
    answer_findings: [],
    answer_integrity_scope: 'record signature checked, chain not walked',
    signing_anchor: 'anchored',
    chain: { counter: 41, prev_entry_hash: HASH('c'), entry_hash: HASH('d'), link: 'verified', window: 'intact', window_scope: 'chain checked across the delivery window' },
    decision: { kind: 'allow', rule: RULE, grant: 'grant-1', flags: 'none', effect: 'allow', decided: 'when the call arrived' },
    reach: 'not recorded by this gateway version',
    answer: { effect, line: `answer line for ${id}`, records: [], more: false },
    ...over,
  };
}

// The field lists, written out here (design r1 D2 as amended by r8f Part 2). A path names a value by its
// keys; "[]" marks the items of a list. The wire kind of a refusal is "call" (rows.rs:167): the receipt
// for kind "call" takes the union of the call and refusal lists, and only present keys render.
const COMMON = ['id', 'kind', 'counter', 'timestamp', 'signature', 'integrity', 'unanchored'];
const ON_RECEIPT = ['signing_anchor', 'chain.counter', 'chain.prev_entry_hash', 'chain.entry_hash', 'chain.link'];
const CALL_FIELDS = [...COMMON, ...ON_RECEIPT,
  'server', 'tool', 'route', 'trace_id', 'outcome', 'error_code',
  'who.credential_kind', 'who.account', 'who.authority', 'who.subject',
  'request_hash', 'response_hash', 'effect', 'answer_findings', 'answer_findings_total', 'answer_integrity',
  'answer_integrity_scope', 'findings[].scan_type', 'findings[].severity', 'findings[].location', 'findings_truncated',
  'chain.window', 'chain.window_scope',
  'answer.effect', 'answer.line', 'answer.records[].counter', 'answer.records[].effect', 'answer.records[].findings_listed',
  'answer.more', 'answer.search.bytes', 'answer.search.lines', 'answer.search.stopped',
  'decision.kind', 'decision.rule', 'decision.grant', 'decision.flags', 'decision.effect', 'decision.decided',
  'decision.config_revision', 'decision.running_revision', 'decision.config_revision_capabilities',
  'reach.jti', 'reach.backends', 'reach.tools', 'reach.expires_by'];
const REFUSAL_FIELDS = [...COMMON, ...ON_RECEIPT, 'server', 'tool', 'trace_id', 'outcome',
  'who.account', 'who.authority', 'who.subject',
  'decision.reason', 'decision.scope', 'decision.capability', 'decision.grant_id', 'reach'];
const CONFIG_FIELDS = [...COMMON, ...ON_RECEIPT, 'action', 'actor_id', 'target_id', 'outcome',
  'reason.recorded', 'reason.length', 'rollback_summary.recorded', 'rollback_summary.length'];
const ADMIN_FIELDS = [...COMMON, ...ON_RECEIPT, 'surface', 'route', 'method', 'http_status', 'tool', 'outcome',
  'action', 'capability', 'pin', 'who.account', 'who.authority', 'who.subject'];
/** Keys the Rust emits that the receipt never shows (r8f Part 2): CUT, or not sent on this route. */
const NOT_SHOWN = ['v', 'resolved_on'];
/** Keys that only hold other keys. */
const HOLDERS = ['who', 'chain', 'answer', 'decision', 'reach', 'search', 'records', 'reason', 'rollback_summary', 'findings'];

const ANCHORED = { signature: 'verified', integrity: 'hmac_mismatch', unanchored: true, signing_anchor: 'anchored' };
const chainOf = (counter) => ({ counter, prev_entry_hash: HASH('c'), entry_hash: HASH('d'), link: 'verified' });

/** A call receipt with every listed key present. */
function fullCall(id) {
  return callReceipt(id, {
    ...ANCHORED,
    error_code: 'E_UPSTREAM',
    answer_findings: 'answer not scanned',
    answer_findings_total: 40,
    answer_integrity: 'invalid',
    findings: [{ scan_type: 'secret', severity: 'high', location: 'arguments.query' }],
    findings_truncated: true,
    chain: { ...chainOf(41), window: 'intact', window_scope: 'chain checked across the delivery window' },
    answer: {
      effect: 'delivered',
      line: 'record found',
      records: [{ counter: 50, effect: 'delivered', findings_listed: 2 }],
      more: true,
      search: { bytes: 1024, lines: 3, stopped: 'end of the kept log' },
    },
    decision: {
      kind: 'allow', rule: RULE, grant: 'grant-1', flags: 'none', effect: 'allow', decided: 'when the call arrived',
      config_revision: 'rev-1', running_revision: 'rev-2', config_revision_capabilities: 'does not cover the capability files',
    },
    reach: { jti: 'jti-1', backends: ['docs'], tools: ['kb.search'], expires_by: '2026-11-15T09:00:00Z' },
  });
}

/** A refused call (wire kind "call", outcome blocked), every listed key present. */
function refusalReceipt(id) {
  return {
    id, kind: 'call', counter: 43, timestamp: '2026-11-15T08:00:00Z', ...ANCHORED,
    server: 'docs', tool: 'kb.search', trace_id: `trace-${id}`, outcome: 'blocked',
    decision: { reason: 'no grant covers this tool', scope: 'tool', capability: 'kb.search', grant_id: 'grant-9' },
    who: { account: 'ops', authority: 'https://issuer.example', subject: 'sub-1' },
    reach: 'not recorded by this gateway version',
    chain: chainOf(43),
  };
}

const configReceipt = (id) => ({
  id, kind: 'config', counter: 7, timestamp: '2026-11-15T08:00:00Z', ...ANCHORED,
  action: 'backend.add', actor_id: 'ops', target_id: 'docs', outcome: 'change',
  reason: { recorded: true, length: 12 }, rollback_summary: { recorded: true, length: 5 },
  chain: chainOf(7),
});

const adminReceipt = (id) => ({
  id, kind: 'admin_action', counter: 44, timestamp: '2026-11-15T08:00:00Z', ...ANCHORED,
  surface: 'ui', route: '/ui/api/backends', method: 'POST', http_status: 201, tool: 'backends.add', outcome: 'change',
  action: 'save', capability: 'billing', pin: 'updated',
  who: { account: 'ops', authority: 'https://issuer.example', subject: 'sub-1' },
  chain: chainOf(44),
});

const read = (obj, path) => path.split('.').reduce((v, k) => (v == null ? undefined : v[k]), obj);
function write(obj, path, value) {
  const keys = path.split('.');
  let at = obj;
  for (const k of keys.slice(0, -1)) at = (at[k] ??= {});
  at[keys.at(-1)] = value;
}
/** The projection the receipt must show and copy: only listed paths, built here from the test's own lists. */
function project(body, paths) {
  const out = {};
  for (const path of paths) {
    const item = path.match(/^(.+)\[\]\.([a-z_]+)$/);
    if (item) {
      const list = read(body, item[1]);
      if (!Array.isArray(list)) continue;
      const into = read(out, item[1]) ?? list.map(() => ({}));
      list.forEach((entry, i) => { if (entry && item[2] in entry) into[i][item[2]] = entry[item[2]]; });
      write(out, item[1], into);
    } else if (read(body, path) !== undefined) {
      write(out, path, read(body, path));
    }
  }
  return out;
}

/** A list row for the same entry, as the list answers it. */
const listRow = (id, tool = 'kb.search') => ({ id, kind: 'call', timestamp: '2026-11-15T08:00:00Z', outcome: 'ok', who: { account: 'ops' }, server: 'docs', tool });

const field = (page, path) => page.locator(`#content [data-field="${path}"]`);
const receiptPath = (id) => `/ui/activity/${encodeURIComponent(id)}/status`;

/**
 * Status, the list and the receipt mocked. List answers come at once from
 * `list(url)`; every receipt request is held until the row answers it.
 */
class Receipts {
  constructor(page) {
    this.page = page;
    this.lists = [];
    this.sent = [];
    this.failed = new Map();
  }

  async install({ list = () => ({ rows: [listRow(ID_A)], next_cursor: null }) } = {}) {
    const { page } = this;
    await page.clock.install({ time: AT - 60_000 });
    await page.clock.pauseAt(AT);
    await page.route('**/ui/api/status', (route) => route.fulfill({ json: { auth: { enabled: true, signed_in: true, admin: true } } }));
    await page.route((url) => url.pathname.startsWith('/ui/api/activity'), (route) => {
      const href = route.request().url();
      const { pathname } = new URL(href);
      if (pathname === '/ui/api/activity') {
        this.lists.push(new URL(href));
        return route.fulfill({ json: list(href) });
      }
      return new Promise((done) => {
        const settleWith = async (reply) => {
          await route.fulfill(reply).catch(() => {});
          done();
        };
        this.sent.push({
          href,
          id: decodeURIComponent(pathname.slice('/ui/api/activity/'.length)),
          answer: (body) => settleWith({ json: body }),
          fail: (status) => settleWith({ status, json: {} }),
        });
      });
    });
    page.on('requestfailed', (req) => {
      if (new URL(req.url()).pathname.startsWith('/ui/api/activity/')) this.failed.set(req.url(), req.failure()?.errorText ?? null);
    });
  }

  /** The `i`-th receipt request (from 0), once sent. */
  async request(i, what) {
    await expect.poll(() => this.sent.length, { message: `${what}: receipt request #${i + 1} goes out`, timeout: 5_000 }).toBeGreaterThan(i);
    return this.sent[i];
  }

  /** No receipt request beyond the first `n` in a 500 ms wait. */
  async quiet(n, what) {
    await this.page.waitForTimeout(500);
    expect(this.sent.length, `${what}: receipt requests sent`).toBe(n);
  }

  async aborted(req, what) {
    await expect.poll(() => this.failed.get(req.href) ?? 'not failed', { message: `${what}: aborted on the wire`, timeout: 5_000 }).toBe('net::ERR_ABORTED');
  }

  async open(id) {
    await this.page.goto(receiptPath(id));
    await shellReady(this.page);
  }
}

async function receiptsFor(page, options) {
  const r = new Receipts(page);
  await r.install(options);
  return r;
}

/** The receipt has drawn its answer: the tool field shows `tool`. */
const drawn = (page, what, tool = 'kb.search') => expect(field(page, 'tool'), `${what}: premise, the receipt is drawn`).toHaveText(tool);

test.describe('R receipt', () => {
  test('R4 a recorded rule id links to the list filtered by it, with a chip that clears it', async ({ page }) => {
    const r = await receiptsFor(page);
    await r.open(ID_A);
    await (await r.request(0, 'R4')).answer(callReceipt(ID_A));
    await drawn(page, 'R4');
    // The id URL-encoded, written out here: team/a+b.
    const link = page.locator('#content a[href="/ui/activity?rule=team%2Fa%2Bb"]');
    await expect(link, 'R4 the rule link').toBeVisible();
    await link.click();
    await expect.poll(() => r.lists.at(-1)?.searchParams.get('rule') ?? null, { message: 'R4 the list asks for the rule' }).toBe(RULE);
    await expect(page.locator('#content').getByText(RULE, { exact: true }), 'R4 the chip shows the rule').toBeVisible();
    const asked = r.lists.length;
    await page.locator('#content').getByRole('button', { name: /clear/i }).click();
    await expect.poll(() => r.lists.length, { message: 'R4 clearing asks the list again' }).toBeGreaterThan(asked);
    expect(r.lists.at(-1).searchParams.has('rule'), 'R4 without the rule').toBe(false);
  });

  const NO_LINK = {
    'the not-recorded sentence': () => callReceipt(ID_A, { decision: { ...callReceipt(ID_A).decision, rule: ruleNotRecorded() } }),
    'a refusal': () => refusalReceipt(ID_A),
    'the legacy string decision': () => callReceipt(ID_A, { decision: 'not recorded by this gateway version' }),
  };
  for (const [label, body] of Object.entries(NO_LINK)) {
    test(`R4 no rule link for ${label}`, async ({ page }) => {
      const r = await receiptsFor(page);
      await r.open(ID_A);
      await (await r.request(0, `R4 ${label}`)).answer(body());
      await drawn(page, `R4 ${label}`);
      await expect(page.locator('#content a[href^="/ui/activity?rule="]'), `R4 ${label}: no link`).toHaveCount(0);
    });
  }

  test('R5 at 390 the receipt wraps its long values and never scrolls sideways', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    const r = await receiptsFor(page);
    await r.open(ID_A);
    const longLine = `no delivery record for trace ${'t'.repeat(90)} in the bytes after the call`;
    await (await r.request(0, 'R5')).answer(callReceipt(ID_A, { answer: { effect: 'delivered', line: longLine, records: [], more: false } }));
    await drawn(page, 'R5');
    const sideways = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(sideways, 'R5 no horizontal overflow').toBe(0);
    for (const path of ['request_hash', 'response_hash', 'chain.entry_hash', 'answer.line']) {
      const el = field(page, path);
      await expect(el, `R5 ${path} shows`).toBeVisible();
      const box = await el.boundingBox();
      expect(box.x + box.width <= 390, `R5 ${path} stays inside 390 px (${JSON.stringify(box)})`).toBe(true);
    }
    // axe waits on timers of its own; under the paused clock they never fire.
    await page.clock.resume();
    expect(await blockingViolations(page), 'R5 axe at 390').toEqual([]);
  });

  test('R6 a not-recorded receipt says so, and check again stays usable until the record arrives', async ({ page }) => {
    const r = await receiptsFor(page);
    await r.open(ID_A);
    await (await r.request(0, 'R6 open')).answer(callReceipt(ID_A, { effect: 'no_record' }));
    await drawn(page, 'R6');
    await expect(page.locator('#content'), 'R6 the not-final words').toContainText(NOT_FINAL);
    const again = page.locator('#content').getByRole('button', { name: /check again/i });
    await expect(again, 'R6 check again shows').toBeVisible();
    await again.click();
    await (await r.request(1, 'R6 check again')).answer(callReceipt(ID_A, { effect: 'no_record' }));
    await expect(again, 'R6 usable after a pending answer').toBeEnabled();
    await again.click();
    await (await r.request(2, 'R6 check again, failing')).fail(500);
    await expect(again, 'R6 usable after a retryable error').toBeEnabled();
    await again.click();
    await (await r.request(3, 'R6 check again, recorded')).answer(callReceipt(ID_A, { effect: 'delivered' }));
    await expect(page.locator('#content'), 'R6 the recorded word').toContainText(/delivered/i);
    await expect(page.locator('#content'), 'R6 the not-final words are gone').not.toContainText(NOT_FINAL);
  });

  // A refusal or a missing entry on Check again is an answer: its own state, not the "as last read" note.
  for (const [status, state] of [['404', 'not-found'], ['403', 'forbidden']]) {
    test(`R6 a ${status} on check again shows the ${state} state`, async ({ page }) => {
      const r = await receiptsFor(page);
      await r.open(ID_A);
      await (await r.request(0, `R6 ${status}: open`)).answer(callReceipt(ID_A, { effect: 'no_record' }));
      await drawn(page, `R6 ${status}`);
      await page.locator('#content').getByRole('button', { name: /check again/i }).click();
      await (await r.request(1, `R6 ${status}: check again`)).fail(Number(status));
      await expect(page.locator(`#content [data-state="${state}"]`), `R6 ${status}: the ${state} state`).toBeVisible();
      await expect(page.locator('#content'), `R6 ${status}: no stale note`).not.toContainText(/as last read/i);
    });
  }

  const STATES = { 404: 'not-found', 401: 'signin', 403: 'forbidden', 500: 'error' };
  for (const [status, state] of Object.entries(STATES)) {
    test(`R7 a ${status} answer shows the ${state} state`, async ({ page }) => {
      const r = await receiptsFor(page);
      await r.open(ID_A);
      await (await r.request(0, `R7 ${status}`)).fail(Number(status));
      // A 401 is the shell's own sign-in, which takes over the page (as shell-loading checks).
      const shown = status === '401' ? page.locator('#signin') : page.locator(`#content [data-state="${state}"]`);
      await expect(shown, `R7 ${status}: the ${state} state`).toBeVisible();
      if (status === '500') {
        await expect(page.locator('#content').getByRole('button', { name: /retry/i }), 'R7 500: a retry').toBeVisible();
      } else {
        await page.clock.runFor(60_000);
        await r.quiet(1, `R7 ${status}: no retry loop`);
      }
    });
  }

  test('R10 the keyboard reaches copy and the rule link, and back returns focus to the row', async ({ page }) => {
    const r = await receiptsFor(page);
    await page.goto('/ui/activity/status');
    await shellReady(page);
    const row = page.locator(`#content a[href="${receiptPath(ID_A)}"]`);
    await row.focus();
    await page.keyboard.press('Enter');
    await (await r.request(0, 'R10')).answer(callReceipt(ID_A));
    await drawn(page, 'R10');
    const copy = page.locator('#content').getByRole('button', { name: /copy as json/i });
    const rule = page.locator('#content a[href^="/ui/activity?rule="]');
    // In the order Tab reaches them: the rule link sits in the field list, Copy after it.
    const reached = [];
    await page.evaluate(() => document.activeElement?.blur());
    for (let i = 0; i < 60 && reached.length < 2; i += 1) {
      await page.keyboard.press('Tab');
      if (await copy.evaluate((el) => el === document.activeElement).catch(() => false)) reached.push('copy');
      if (await rule.evaluate((el) => el === document.activeElement).catch(() => false)) reached.push('rule');
    }
    expect(reached, 'R10 Tab reaches the rule link, then copy').toEqual(['rule', 'copy']);
    await page.goBack();
    await expect(page.locator(`#content a[href="${receiptPath(ID_A)}"]`), 'R10 focus is back on the row').toBeFocused();
  });

  test('R11 a deep link opens the receipt by itself', async ({ page }) => {
    const r = await receiptsFor(page);
    await r.open(ID_A);
    const req = await r.request(0, 'R11');
    expect(new URL(req.href).pathname, 'R11 asks exactly this entry').toBe(`/ui/api/activity/${ID_A}`);
    await req.answer(callReceipt(ID_A));
    await drawn(page, 'R11');
    expect(r.lists.length, 'R11 no list request for a deep link').toBe(0);
  });

  test('R12 hostile text in the tool, rule and answer line stays text', async ({ page }) => {
    const HOSTILE = '<img src=x onerror="window.__pwned=1">';
    const r = await receiptsFor(page);
    await r.open(ID_A);
    const body = callReceipt(ID_A, { tool: HOSTILE });
    body.decision = { ...body.decision, rule: HOSTILE };
    body.answer = { ...body.answer, line: HOSTILE };
    await (await r.request(0, 'R12')).answer(body);
    await drawn(page, 'R12', HOSTILE);
    await expect(field(page, 'decision.rule'), 'R12 rule as text').toHaveText(HOSTILE);
    await expect(field(page, 'answer.line'), 'R12 line as text').toHaveText(HOSTILE);
    expect(await page.evaluate(() => window.__pwned ?? null), 'R12 nothing ran').toBeNull();
    await expect(page.locator('#content img[src="x"]'), 'R12 no image element').toHaveCount(0);
  });

  /** Move to another entry inside the page, as an in-app link does (no reload). */
  const goInApp = (page, path) => page.evaluate((p) => {
    history.pushState(null, '', p);
    dispatchEvent(new PopStateEvent('popstate'));
  }, path);

  test('R13 opening another entry aborts the first; its late answer shows nothing', async ({ page }) => {
    const r = await receiptsFor(page);
    await r.open(ID_A);
    const a = await r.request(0, 'R13 A');
    await goInApp(page, receiptPath(ID_B));
    const b = await r.request(1, 'R13 B');
    expect(b.id, 'R13 B asked').toBe(ID_B);
    await r.aborted(a, 'R13 A');
    await b.answer(callReceipt(ID_B));
    await a.answer(callReceipt(ID_A, { tool: 'late.tool' }));
    await page.waitForTimeout(500);
    await expect(field(page, 'trace_id'), 'R13 B shows').toHaveText(`trace-${ID_B}`);
    await expect(page.locator('#content'), 'R13 nothing of A').not.toContainText('late.tool');
  });

  test('R13 check again while one is out leaves exactly one in flight', async ({ page }) => {
    const r = await receiptsFor(page);
    await r.open(ID_A);
    await (await r.request(0, 'R13 again: open')).answer(callReceipt(ID_A, { effect: 'no_record' }));
    const again = page.locator('#content').getByRole('button', { name: /check again/i });
    await expect(again, 'R13 again: premise, check again shows').toBeVisible();
    await again.click();
    const first = await r.request(1, 'R13 again: first');
    await again.click();
    await r.request(2, 'R13 again: second');
    await r.aborted(first, 'R13 again: the first');
    await r.quiet(3, 'R13 again: one each');
  });

  for (const [first, second] of [['recorded', 'no_record'], ['no_record', 'recorded']]) {
    test(`R13 a ${first} entry then a ${second} one shows only the second's delivery`, async ({ page }) => {
      const effect = (s) => (s === 'recorded' ? 'delivered' : 'no_record');
      const r = await receiptsFor(page);
      await r.open(ID_A);
      await (await r.request(0, `R13 ${first}`)).answer(callReceipt(ID_A, { effect: effect(first) }));
      await drawn(page, `R13 ${first}`);
      await goInApp(page, receiptPath(ID_B));
      await (await r.request(1, `R13 ${second}`)).answer(callReceipt(ID_B, { effect: effect(second) }));
      await expect(field(page, 'trace_id'), `R13 ${second} shows`).toHaveText(`trace-${ID_B}`);
      if (second === 'no_record') {
        await expect(page.locator('#content'), 'R13 B not final').toContainText(NOT_FINAL);
        await expect(page.locator('#content'), 'R13 nothing of A\'s delivery').not.toContainText(/delivered/i);
      } else {
        await expect(page.locator('#content'), 'R13 A\'s recorded effect').toContainText(/delivered/i);
        await expect(page.locator('#content'), 'R13 not the not-final words').not.toContainText(NOT_FINAL);
      }
    });
  }

  test('R13 leaving aborts the receipt request and draws nothing late', async ({ page }) => {
    const r = await receiptsFor(page);
    await r.open(ID_A);
    const a = await r.request(0, 'R13 leave');
    await page.getByRole('link', { name: 'Tools', exact: true }).first().click();
    await expect(page, 'R13 leave: on Tools').toHaveURL(/\/ui\/tools\/status$/);
    await r.aborted(a, 'R13 leave');
    await a.answer(callReceipt(ID_A, { tool: 'late.tool' }));
    await r.quiet(1, 'R13 leave: nothing more');
    await expect(page.locator('#content'), 'R13 leave: nothing late').not.toContainText('late.tool');
  });

  test('R13 an activity frame asks for no receipt', async ({ page, request }, testInfo) => {
    const stream = await heldStream(page, request, testInfo);
    const r = await receiptsFor(page);
    await r.open(ID_A);
    await expect.poll(stream.connects, { message: 'R13 frame: the stream connects' }).toBe(1);
    await stream.send(frame('hello', { kinds: ['status', 'reload', 'activity', 'config'], head: 'b1.s1.r1' }));
    await (await r.request(0, 'R13 frame')).answer(callReceipt(ID_A, { effect: 'no_record' }));
    await drawn(page, 'R13 frame');
    await stream.send(frame('activity', listRow(ID_A), 'b1.s1.r2'));
    await r.quiet(1, 'R13 frame: still one receipt request');
  });

  const ID_G = 'g7-0123456789abcdef';
  const VARIANTS = {
    call: [ID_A, fullCall, CALL_FIELDS],
    refusal: [ID_A, refusalReceipt, REFUSAL_FIELDS],
    'config change': [ID_G, configReceipt, CONFIG_FIELDS],
    'admin action': [ID_A, adminReceipt, ADMIN_FIELDS],
  };
  const shownFields = (page) => page.locator('#content [data-field]')
    .evaluateAll((els) => [...new Set(els.map((e) => e.getAttribute('data-field')))].sort());

  for (const [label, [id, make, list]] of Object.entries(VARIANTS)) {
    test(`R1 a ${label} receipt shows exactly its field list, each with a label`, async ({ page }) => {
      const r = await receiptsFor(page);
      await r.open(id);
      await (await r.request(0, `R1 ${label}`)).answer(make(id));
      await expect(page.locator('#content [data-field]').first(), `R1 ${label}: premise, fields drawn`).toBeVisible();
      expect(await shownFields(page), `R1 ${label}: the shown field set`).toEqual([...new Set(list)].sort());
      // A field (not a list item) is a dd whose dt names it.
      const unlabelled = await page.locator('#content [data-field]').evaluateAll((els) => els
        .filter((e) => !e.dataset.field.includes('[]'))
        .filter((e) => {
          const dt = e.previousElementSibling;
          return !(dt && dt.tagName === 'DT' && dt.textContent.trim() !== '');
        })
        .map((e) => e.dataset.field));
      expect(unlabelled, `R1 ${label}: fields without a label`).toEqual([]);
    });
  }

  /** Clipboard for this page: 'ok' records the text; 'none', 'denied' and 'rejected' each fail one way. */
  async function clipboard(page, mode) {
    await page.addInitScript((m) => {
      window.__copied = [];
      let clip;
      if (m === 'ok') clip = { writeText: async (text) => { window.__copied.push(text); } };
      if (m === 'denied') clip = { writeText: () => Promise.reject(new DOMException('write denied', 'NotAllowedError')) };
      if (m === 'rejected') clip = { writeText: () => Promise.reject(new Error('write failed')) };
      Object.defineProperty(navigator, 'clipboard', { value: clip, configurable: true });
    }, mode);
  }
  const copyButton = (page) => page.locator('#content').getByRole('button', { name: /copy as json/i });
  const fallback = (page) => page.locator('#content textarea[readonly]');

  /** A full call whose top level and every listed sub-object carry a body-like extra key. */
  const BODY = (where) => `BODY-${where}-9f2`;
  function withExtras(id) {
    const b = fullCall(id);
    b.request_body = BODY('top');
    b.who.payload = BODY('who');
    b.chain.payload = BODY('chain');
    b.answer.payload = BODY('answer');
    b.answer.search.payload = BODY('search');
    b.answer.records[0].payload = BODY('record');
    b.decision.payload = BODY('decision');
    b.reach.payload = BODY('reach');
    b.findings[0].payload = BODY('finding');
    return b;
  }
  const EXTRAS = ['top', 'who', 'chain', 'answer', 'search', 'record', 'decision', 'reach', 'finding'].map(BODY);

  test('R2 body-like extra keys show nowhere: not on screen, not in the copy', async ({ page }) => {
    await clipboard(page, 'ok');
    const r = await receiptsFor(page);
    await r.open(ID_A);
    await (await r.request(0, 'R2')).answer(withExtras(ID_A));
    await drawn(page, 'R2');
    const text = await page.locator('body').innerText();
    expect(EXTRAS.filter((x) => text.includes(x)), 'R2 extras on screen').toEqual([]);
    expect((await shownFields(page)).filter((f) => /payload|request_body/.test(f)), 'R2 extra fields').toEqual([]);
    await copyButton(page).click();
    await expect.poll(() => page.evaluate(() => window.__copied.length), { message: 'R2 copied once' }).toBe(1);
    const copied = await page.evaluate(() => window.__copied[0]);
    expect(EXTRAS.filter((x) => copied.includes(x)), 'R2 extras in the copy').toEqual([]);
  });

  test('R2 body-like extra keys stay out of the copy fallback too', async ({ page }) => {
    await clipboard(page, 'rejected');
    const r = await receiptsFor(page);
    await r.open(ID_A);
    await (await r.request(0, 'R2 fallback')).answer(withExtras(ID_A));
    await drawn(page, 'R2 fallback');
    await copyButton(page).click();
    await expect(fallback(page), 'R2 fallback: the text shows').toBeVisible();
    const shown = await fallback(page).inputValue();
    expect(EXTRAS.filter((x) => shown.includes(x)), 'R2 extras in the fallback').toEqual([]);
  });

  test('R2 a config change\'s recorded-text facts show no extra key', async ({ page }) => {
    const r = await receiptsFor(page);
    await r.open(ID_G);
    const body = configReceipt(ID_G);
    body.reason.text = BODY('reason');
    body.rollback_summary.text = BODY('rollback');
    await (await r.request(0, 'R2 config')).answer(body);
    await expect(page.locator('#content [data-field]').first(), 'R2 config: premise, fields drawn').toBeVisible();
    const text = await page.locator('body').innerText();
    expect([BODY('reason'), BODY('rollback')].filter((x) => text.includes(x)), 'R2 config: extras on screen').toEqual([]);
  });

  // The design pins a few fields to one type; a value of another type is dropped, like an unlisted key.
  test('R2 a pinned field holding another type is dropped', async ({ page }) => {
    const r = await receiptsFor(page);
    await r.open(ID_A);
    const body = fullCall(ID_A);
    body.decision.grant = 7;
    body.decision.flags = true;
    body.answer.records[0].findings_listed = 1.5;
    body.reach = true;
    await (await r.request(0, 'R2 types')).answer(body);
    await drawn(page, 'R2 types');
    const PINNED = ['decision.grant', 'decision.flags', 'answer.records[].findings_listed', 'reach'];
    expect((await shownFields(page)).filter((f) => PINNED.includes(f)), 'R2 types: none of the mistyped fields').toEqual([]);
    expect(await shownFields(page), 'R2 types: the rest still shows').toContain('decision.rule');
  });

  test('R3 copy as JSON writes exactly the projection', async ({ page }) => {
    await clipboard(page, 'ok');
    const r = await receiptsFor(page);
    await r.open(ID_A);
    await (await r.request(0, 'R3')).answer(fullCall(ID_A));
    await drawn(page, 'R3');
    await copyButton(page).click();
    await expect.poll(() => page.evaluate(() => window.__copied.length), { message: 'R3 copied once' }).toBe(1);
    expect(JSON.parse(await page.evaluate(() => window.__copied[0])), 'R3 the copied JSON').toEqual(project(fullCall(ID_A), CALL_FIELDS));
  });

  for (const mode of ['none', 'denied', 'rejected']) {
    test(`R3 with the clipboard ${mode === 'none' ? 'missing' : mode}, the same JSON shows read-only and selected`, async ({ page }) => {
      await clipboard(page, mode);
      const r = await receiptsFor(page);
      await r.open(ID_A);
      await (await r.request(0, `R3 ${mode}`)).answer(fullCall(ID_A));
      await drawn(page, `R3 ${mode}`);
      await copyButton(page).click();
      await expect(fallback(page), `R3 ${mode}: the text shows`).toBeVisible();
      const value = await fallback(page).inputValue();
      expect(JSON.parse(value), `R3 ${mode}: the same projection`).toEqual(project(fullCall(ID_A), CALL_FIELDS));
      const sel = await fallback(page).evaluate((t) => [t.selectionStart, t.selectionEnd, t.value.length]);
      expect([sel[0], sel[1]], `R3 ${mode}: all of it selected`).toEqual([0, sel[2]]);
    });
  }

  test('R9 a reach string shows as text', async ({ page }) => {
    const r = await receiptsFor(page);
    await r.open(ID_A);
    await (await r.request(0, 'R9 string')).answer(callReceipt(ID_A));
    await drawn(page, 'R9 string');
    await expect(field(page, 'reach'), 'R9 the string').toHaveText('not recorded by this gateway version');
  });

  test('R9 a reach object shows exactly its four keys', async ({ page }) => {
    const r = await receiptsFor(page);
    await r.open(ID_A);
    const body = fullCall(ID_A);
    body.reach.issued_to = BODY('identity');
    await (await r.request(0, 'R9 object')).answer(body);
    await drawn(page, 'R9 object');
    expect((await shownFields(page)).filter((f) => f.startsWith('reach')), 'R9 reach fields')
      .toEqual(['reach.backends', 'reach.expires_by', 'reach.jti', 'reach.tools']);
    await expect(field(page, 'reach.backends'), 'R9 backends').toContainText('docs');
    await expect(field(page, 'reach.tools'), 'R9 tools').toContainText('kb.search');
    expect(await page.locator('body').innerText(), 'R9 no extra key').not.toContain(BODY('identity'));
  });

  test('R14 the field lists match the key names the Rust emits', () => {
    const src = (p) => readFileSync(fileURLToPath(new URL(`../../src/${p}`, import.meta.url)), 'utf8');
    const rows = src('gateway/ui/activity/rows.rs');
    const rowFn = rows.slice(rows.indexOf('pub(super) fn row('), rows.indexOf('pub(super) fn findings_value('));
    expect(rowFn.length, 'R14 premise: rows.rs row() found').toBeGreaterThan(100);
    // Every quoted name in row() is a key, except these values it writes.
    const VALUES = ['change'];
    const emitted = new Set([...rowFn.matchAll(/"([a-z_]+)"/g)].map((m) => m[1]).filter((k) => !VALUES.includes(k)));
    const KEY = /insert\(\s*"([a-z_]+)"|"([a-z_]+)":|\["([a-z_]+)"\]|\(\s*"([a-z_]+)",\s*&d\./g;
    for (const p of ['gateway/ui/activity/receipt.rs', 'gateway/ui/activity/answer.rs', 'gateway/ui/activity/receipt_scan.rs']) {
      for (const m of src(p).matchAll(KEY)) emitted.add(m.slice(1).find(Boolean));
    }
    const record = src('security/decision_record.rs');
    const finding = record.slice(record.indexOf('pub(crate) struct DecisionFinding {'));
    for (const m of finding.slice(0, finding.indexOf('}')).matchAll(/pub ([a-z_]+):/g)) emitted.add(m[1]);
    const leaves = new Set([...CALL_FIELDS, ...REFUSAL_FIELDS, ...CONFIG_FIELDS, ...ADMIN_FIELDS]
      .flatMap((p) => p.replace('[]', '').split('.')));
    const known = new Set([...leaves, ...HOLDERS, ...NOT_SHOWN]);
    expect([...emitted].filter((k) => !known.has(k)).sort(), 'R14 Rust keys no list classes').toEqual([]);
    expect([...leaves].filter((k) => !emitted.has(k)).sort(), 'R14 listed keys the Rust no longer emits').toEqual([]);
  });

  // R8 waits for the delivery-check word table; its rows land with it.
  test.skip('R8 each answer_integrity value shows through the delivery-check word table', () => {});
  test.skip('R8 an absent answer_integrity shows the table\'s unlisted badge', () => {});
  test.skip('R8 the receipt imports the table and spells none of its words', () => {});
});
