// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { test, expect } from './base.mjs';
import { shellReady, signedInAdmin } from './shell.mjs';
import { importServed } from './copy-check.mjs';

// The To do page, its rows D1-D11: the decision list and the read-only detail of each kind. Routes answer bodies
// written in this file; every sentence a row expects is taken from the page's words module (the served bytes).

test.use({ timezoneId: 'UTC' });

let wordsLoad = null;
const words = () => (wordsLoad ??= importServed(/^decisions-words\.[0-9a-f]{12}\.js$/));

const PAGE = '/ui/todo';
const T0 = '2026-11-27T10:00:00Z';
const CAP = {
  id: 'cap1', kind: 'capability_changed', backend: 'tide', tool: 'tide_table', trusted_name: true, after: { tools: 1, fields: 4 },
  before: null, before_reason: 'no_history', scan: null, scan_basis: 'inferred', scan_reason: 'unparsed', tools_off: 1,
  off_since: T0, observed_at: T0, refused_calls: null, refused_calls_reason: 'not_linked', waits_on: [],
};
const UNR = { id: 'unr1', kind: 'capability_unreadable', backend: 'harbour', tool: 'unnamed-1a2b3c4d', trusted_name: false, reason: 'no_permission', observed_at: T0, waits_on: [] };
const REQ = {
  id: 'req1', kind: 'access_request', subject: { authority: 'auth.example', id: 'alice' }, agent: 'https://agent.example',
  scope: [{ capability: 'tide_table', tool: null, grant_scope: 'call', read_only: true }], scope_digest: 'd1',
  server_tools_total: null, server_tools_total_reason: 'not_tracked', refused_calls: 3, first: T0, observed_at: T0, waits_on: ['cap1'],
  note: null, note_reason: 'not_recorded', policy: null, policy_reason: 'not_recorded', severity: null, severity_reason: 'not_rated',
};
const ADO = {
  id: 'ado1', kind: 'adopt', severity: 'low', observed_at: T0, waits_on: [],
  server: { name: 'pending-adopt', source: 'claude', config_file: 'mcp.json', transport: 'stdio', command: 'npx pending-adopt', url: null },
};
const CLI = { id: 'cli1', kind: 'client_config_unreadable', source: 'cursor', file: 'mcp.json', reason: 'did_not_parse', observed_at: T0 };
const listOf = (decisions, more = {}) => ({ decisions, revision: 1, missing_kinds: [], partial_kinds: [], ...more });
const ALL_FIVE = () => listOf([CAP, UNR, REQ, ADO, CLI]);

/**
 * A signed-in admin (shell.mjs) plus this page's two routes: the list (a body, { code, body }, or a function of the
 * read number) and the count. Returns how many times each was read.
 */
async function gatewayAnswers(page, { list = ALL_FIVE(), count = { count: 5 } } = {}) {
  await signedInAdmin(page);
  const reads = { list: 0, count: 0 };
  const send = (route, a) => {
    const { code = 200, body = a } = a && typeof a === 'object' && 'code' in a ? a : { body: a };
    return route.fulfill({ status: code, json: body });
  };
  await page.route('**/ui/api/decisions/count', (route) => { reads.count += 1; return send(route, count); });
  await page.route('**/ui/api/decisions', (route) => { reads.list += 1; return send(route, typeof list === 'function' ? list(reads.list) : list); });
  return reads;
}

async function visit(page, path = `${PAGE}/status`, answers) {
  const reads = await gatewayAnswers(page, answers);
  await page.goto(path);
  await shellReady(page);
  return reads;
}
const rowsOf = (page) => page.locator('#content ol.dl-list > li');
const detailOf = (page) => page.locator('#content .dl-detail');

test('D1 rows: five kinds in gateway order, each with summary, mark and blocked-by count', async ({ page }) => {
  const w = await words();
  const scanned = { ...CAP, scan: 'medium', scan_reason: null };
  await visit(page, undefined, { list: listOf([scanned, UNR, REQ, ADO, CLI]) });
  const rows = rowsOf(page);
  await expect(rows).toHaveCount(5);
  await expect(rows.locator('.dl-title')).toHaveText([CAP, UNR, REQ, ADO, CLI].map((d) => w.kindTitle(d.kind)));
  await expect(rows.locator('.dl-sub')).toHaveText([scanned, UNR, REQ, ADO, CLI].map((d) => w.subline(d)));
  // Marks: the changed capability's scan class and the adopt's severity; the other three kinds carry none.
  await expect(rows.nth(0).locator('.dl-mark')).toHaveText('medium');
  await expect(rows.nth(3).locator('.dl-mark')).toHaveText('low');
  for (const i of [1, 2, 4]) await expect(rows.nth(i).locator('.dl-mark')).toHaveCount(0);
  await expect(rows.nth(2).locator('.dl-waits')).toHaveText(w.WAITS_ON(1));
  for (const i of [0, 1, 3, 4]) await expect(rows.nth(i).locator('.dl-waits')).toHaveCount(0);
});

test('D2 detail: each decision opens at its own address and survives a reload', async ({ page }) => {
  const w = await words();
  await visit(page, `${PAGE}/${ADO.id}/status`);
  const d = detailOf(page);
  await expect(d.locator('h2')).toHaveText(w.kindTitle('adopt'));
  for (const fact of ['stdio', 'low', 'claude', 'mcp.json', 'npx pending-adopt']) await expect(d.locator('dd')).toContainText([fact]);
  await page.reload();
  await shellReady(page);
  await expect(detailOf(page).locator('h2')).toHaveText(w.kindTitle('adopt'));
  // Fifth kind (sidecar 1): its tool, server, reason in words.
  await page.goto(`${PAGE}/${UNR.id}/status`);
  await shellReady(page);
  for (const fact of [UNR.tool, UNR.backend, w.unreadableWords('no_permission')]) await expect(detailOf(page).locator('dd')).toContainText([fact]);
  // Desktop width, bare list address: the top decision is shown, yet no row claims to be the open one.
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(`${PAGE}/status`);
  await shellReady(page);
  await expect(detailOf(page).locator('h2')).toHaveText(w.kindTitle('capability_changed'));
  await expect(rowsOf(page).locator('[aria-current]')).toHaveCount(0);
});

test('D3 empty values: every null shows its reason in words', async ({ page }) => {
  const w = await words();
  const odd = { ...REQ, id: 'req2', note_reason: 'reason_from_a_newer_gateway', waits_on: [] };
  await visit(page, `${PAGE}/${CAP.id}/status`, { list: listOf([CAP, UNR, REQ, odd]) });
  const facts = detailOf(page).locator('dd');
  await expect(facts).toContainText([w.nullWords('unparsed'), w.nullWords('not_linked'), w.nullWords('no_history')]);
  await expect(detailOf(page)).not.toContainText(w.SCAN_INFERRED);
  await expect(rowsOf(page).nth(0).locator('.dl-mark')).toHaveCount(0);
  await page.goto(`${PAGE}/${REQ.id}/status`);
  await shellReady(page);
  await expect(detailOf(page).locator('dd')).toContainText(['not_tracked', 'not_recorded', 'not_rated'].map((r) => w.nullWords(r)));
  await page.goto(`${PAGE}/${odd.id}/status`);
  await shellReady(page);
  await expect(detailOf(page).locator('dd')).toContainText([w.NULL_UNKNOWN]);
  await page.goto(`${PAGE}/${UNR.id}/status`);
  await shellReady(page);
  await expect(detailOf(page)).toContainText(w.TOOL_STAND_IN);
  for (const dd of await detailOf(page).locator('dd').all()) expect((await dd.textContent()).trim()).not.toBe('');
});

test('D4 empty list: one line and one action, unless some kinds could not be read', async ({ page }) => {
  const w = await words();
  // A truly empty list.
  await visit(page, undefined, { list: listOf([]) });
  await expect(page.locator('#content')).toContainText(w.EMPTY_TITLE);
  await expect(page.locator('#content').getByRole('link', { name: w.EMPTY_ACTION })).toHaveCount(1);
  await page.unrouteAll();
  // Empty, but one kind was only partly read: the incomplete banner, never "all caught up", and nothing else.
  let reads = await visit(page, undefined, { list: listOf([], { partial_kinds: ['access_request'] }) });
  await expect(page.locator('#content')).toContainText(w.EMPTY_INCOMPLETE([w.kindTitle('access_request')]));
  await expect(page.locator('#content')).not.toContainText(w.EMPTY_TITLE);
  await expect(page.locator('#content .dl-incomplete')).toHaveCount(1);
  await page.unrouteAll();
  // Rows present and one kind missing: the banner once, above the list.
  await visit(page, undefined, { list: listOf([CAP], { missing_kinds: ['adopt'] }) });
  await expect(page.locator('#content .dl-incomplete')).toHaveText(w.INCOMPLETE_KINDS([w.kindTitle('adopt')]));
  await page.unrouteAll();
  // The same kind in both arrays is named once.
  await visit(page, undefined, { list: listOf([CAP], { missing_kinds: ['adopt'], partial_kinds: ['adopt'] }) });
  await expect(page.locator('#content .dl-incomplete')).toHaveText(w.INCOMPLETE_KINDS([w.kindTitle('adopt')]));
  await page.unrouteAll();
  // Empty with only a missing kind: still the incomplete line, and its retry reads the list again.
  reads = await visit(page, undefined, { list: listOf([], { missing_kinds: ['adopt'] }) });
  await expect(page.locator('#content')).toContainText(w.EMPTY_INCOMPLETE([w.kindTitle('adopt')]));
  await page.locator('#content').getByRole('button', { name: w.RETRY }).click();
  await expect.poll(() => reads.list).toBe(2);
});

test('D5 blocked decisions point at the first decision that blocks them, counted once each', async ({ page }) => {
  const w = await words();
  const A = { ...ADO, id: 'a2', waits_on: [] };
  const B = { ...CLI, id: 'b4' };
  // The plain case: the request is blocked by the changed capability at position 1.
  await visit(page, `${PAGE}/${REQ.id}/status`, { list: listOf([CAP, REQ]) });
  await expect(detailOf(page).locator('.dl-waits-line')).toHaveText(w.WAITS_ON_LINE(1, w.kindTitle('capability_changed')));
  await expect(detailOf(page).locator('a.dl-first')).toHaveAttribute('href', `${PAGE}/${CAP.id}/status`);
  await expect(detailOf(page).locator('button')).toHaveCount(0);
  await page.unrouteAll();
  // Blocked by the 4th and the 2nd item, listed 4th-first: the line names position 2 (list order wins).
  const req = { ...REQ, id: 'r', waits_on: [B.id, A.id] };
  const list = [req, A, CAP, B];
  await visit(page, `${PAGE}/r/status`, { list: listOf(list) });
  await expect(detailOf(page).locator('.dl-waits-line')).toHaveText(w.WAITS_ON_LINE(2, w.kindTitle('adopt')));
  await expect(detailOf(page).locator('.dl-more')).toHaveText(w.WAITS_ON_MORE(1));
  await expect(detailOf(page).locator('a.dl-first')).toHaveAttribute('href', `${PAGE}/${A.id}/status`);
  await expect(rowsOf(page).nth(0).locator('.dl-waits')).toHaveText(w.WAITS_ON(2));
  await page.unrouteAll();
  // One present id and one absent: counted as 1, no "more" line.
  await visit(page, `${PAGE}/r/status`, { list: listOf([{ ...req, waits_on: [A.id, 'gone'] }, A]) });
  await expect(rowsOf(page).nth(0).locator('.dl-waits')).toHaveText(w.WAITS_ON(1));
  await expect(detailOf(page).locator('.dl-more')).toHaveCount(0);
  await page.unrouteAll();
  // Only absent ids: no line, no link, no row count.
  await visit(page, `${PAGE}/r/status`, { list: listOf([{ ...req, waits_on: ['gone'] }, A]) });
  await expect(detailOf(page).locator('.dl-waits-line, a.dl-first')).toHaveCount(0);
  await expect(rowsOf(page).nth(0).locator('.dl-waits')).toHaveCount(0);
  await page.unrouteAll();
  // Repeats count once: A three times and B once is 2, the line names A at position 2.
  await visit(page, `${PAGE}/r/status`, { list: listOf([{ ...req, waits_on: [A.id, A.id, A.id, B.id] }, A, CAP, B]) });
  await expect(rowsOf(page).nth(0).locator('.dl-waits')).toHaveText(w.WAITS_ON(2));
  await expect(detailOf(page).locator('.dl-waits-line')).toHaveText(w.WAITS_ON_LINE(2, w.kindTitle('adopt')));
  await expect(detailOf(page).locator('.dl-more')).toHaveText(w.WAITS_ON_MORE(1));
  await page.unrouteAll();
  // Blocked by the fifth kind (sidecar 1): position, title, link target and count all name it.
  await visit(page, `${PAGE}/r/status`, { list: listOf([UNR, { ...req, waits_on: [UNR.id] }]) });
  await expect(detailOf(page).locator('.dl-waits-line')).toHaveText(w.WAITS_ON_LINE(1, w.kindTitle('capability_unreadable')));
  await expect(detailOf(page).locator('a.dl-first')).toHaveAttribute('href', `${PAGE}/${UNR.id}/status`);
  await expect(rowsOf(page).nth(1).locator('.dl-waits')).toHaveText(w.WAITS_ON(1));
});

test('D6 phone: list and detail are two addresses, the detail links back', async ({ page }) => {
  const w = await words();
  await page.setViewportSize({ width: 390, height: 844 });
  await visit(page);
  await expect(rowsOf(page)).toHaveCount(5);
  await expect(detailOf(page)).toBeHidden();
  await rowsOf(page).nth(3).locator('a').click();
  await expect(page).toHaveURL(new RegExp(`${PAGE}/${ADO.id}/status$`));
  await expect(detailOf(page)).toBeVisible();
  await expect(page.locator('#content ol.dl-list')).toBeHidden();
  const back = detailOf(page).locator('a.dl-back');
  await expect(back).toHaveText(w.BACK_TO_LIST(5));
  await back.click();
  await expect(page).toHaveURL(new RegExp(`${PAGE}/status$`));
});

test('D7 a kind this page does not know is listed and shown plainly, with no settle line', async ({ page }) => {
  const w = await words();
  const odd = { id: 'z1', kind: 'quorum_vote', topic: 'rotate root key', votes: 2, observed_at: T0 };
  await visit(page, `${PAGE}/z1/status`, { list: listOf([odd]) });
  await expect(rowsOf(page).locator('.dl-title')).toHaveText([w.UNKNOWN_KIND_TITLE]);
  await expect(detailOf(page).locator('dd')).toContainText(['rotate root key', '2']);
  await expect(detailOf(page).locator('.dl-where')).toHaveCount(0);
  await expect(detailOf(page).locator('button')).toHaveCount(0);
});

test('D8 unavailable: each source and its state, or a plain line, and retry reads again', async ({ page }) => {
  const w = await words();
  const down = { code: 503, body: { error: 'decisions_unavailable', sources: [{ source: 'grants', state: 'starting' }, { source: 'discovery', state: 'sideways' }] } };
  const reads = await visit(page, undefined, { list: (n) => (n === 1 ? down : listOf([CAP])) });
  await expect(page.locator('#content')).toContainText(w.UNAVAILABLE_TITLE);
  await expect(page.locator('#content')).toContainText(w.sourceLine({ source: 'grants', state: 'starting' }));
  await expect(page.locator('#content')).toContainText(`discovery ${w.SOURCE_STATE_UNKNOWN}`);
  await page.locator('#content').getByRole('button', { name: w.RETRY }).click();
  await expect.poll(() => reads.list).toBe(2);
  await expect(rowsOf(page)).toHaveCount(1);
  await page.unrouteAll();
  await visit(page, undefined, { list: { code: 503, body: { error: 'decisions_unavailable', sources: [] } } });
  await expect(page.locator('#content')).toContainText(w.SOURCES_UNKNOWN);
});

test('D9 served names are shown as text, never run as markup', async ({ page }) => {
  const sly = { ...ADO, server: { ...ADO.server, name: '<img src=x onerror="window.__pwned=1">' } };
  await visit(page, `${PAGE}/${ADO.id}/status`, { list: listOf([sly]) });
  await expect(rowsOf(page).locator('.dl-sub')).toContainText('<img src=x');
  await expect(page.locator('#content img')).toHaveCount(0);
  expect(await page.evaluate(() => window.__pwned ?? null)).toBeNull();
});

test('D10 each known kind says where it is settled and when it clears; no detail has a button', async ({ page }) => {
  const w = await words();
  await visit(page);
  for (const d of [CAP, UNR, REQ, ADO, CLI]) {
    await page.goto(`${PAGE}/${d.id}/status`);
    await shellReady(page);
    await expect(detailOf(page).locator('.dl-where')).toHaveText(w.DECIDED_WHERE[d.kind]);
    await expect(detailOf(page).locator('button')).toHaveCount(0);
  }
  // The endings (sidecar 2): the access request waits for a reload; every other kind clears by itself.
  expect(w.DECIDED_WHERE.access_request).toContain(w.LEAVES_AFTER_RELOAD);
  for (const k of ['adopt', 'capability_changed', 'capability_unreadable', 'client_config_unreadable']) expect(w.DECIDED_WHERE[k]).toContain(w.CLEARS_ON_ITS_OWN);
});

test('D11 the list and the badge are read again when the tab comes back, and never after leaving', async ({ page }) => {
  const reads = await visit(page);
  await expect(rowsOf(page)).toHaveCount(5);
  const before = { ...reads };
  await page.evaluate(() => { dispatchEvent(new Event('blur')); dispatchEvent(new Event('focus')); });
  await expect.poll(() => reads.list).toBe(before.list + 1);
  await expect.poll(() => reads.count).toBeGreaterThan(before.count);
  await page.locator('nav').getByRole('link', { name: 'Activity' }).first().click();
  const left = { ...reads };
  await page.evaluate(() => dispatchEvent(new Event('focus')));
  await page.waitForTimeout(500);
  expect(reads.list).toBe(left.list);
});
