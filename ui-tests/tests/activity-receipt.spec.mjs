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
    'a refusal': () => ({ ...callReceipt(ID_A, { kind: 'refusal', outcome: 'blocked' }), decision: { reason: 'no grant', scope: 'tool', capability: 'kb.search', grant_id: null }, answer: undefined }),
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

  const STATES = { 404: 'not-found', 401: 'signin', 403: 'forbidden', 500: 'error' };
  for (const [status, state] of Object.entries(STATES)) {
    test(`R7 a ${status} answer shows the ${state} state`, async ({ page }) => {
      const r = await receiptsFor(page);
      await r.open(ID_A);
      await (await r.request(0, `R7 ${status}`)).fail(Number(status));
      await expect(page.locator(`#content [data-state="${state}"]`), `R7 ${status}: the ${state} state`).toBeVisible();
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
    const reached = new Set();
    await page.evaluate(() => document.activeElement?.blur());
    for (let i = 0; i < 60 && reached.size < 2; i += 1) {
      await page.keyboard.press('Tab');
      if (await copy.evaluate((el) => el === document.activeElement).catch(() => false)) reached.add('copy');
      if (await rule.evaluate((el) => el === document.activeElement).catch(() => false)) reached.add('rule');
    }
    expect([...reached].sort(), 'R10 Tab reaches both').toEqual(['copy', 'rule']);
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
});
