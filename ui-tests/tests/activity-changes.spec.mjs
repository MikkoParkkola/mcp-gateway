// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// How an admin action reads in Activity. A capability save says who changed
// which capability and whether its pin moved, in the list's middle cell and as
// its receipt's heading; every other admin row reads its tool, else its method
// and route, else its surface. A name is always text. The list and receipts are
// mocked; the live stream is held quiet.
import { test, expect } from './base.mjs';
import { shellReady, heldStream, signedInAdmin } from './shell.mjs';

test.use({ timezoneId: 'UTC' });

const WHEN = '2026-11-15T08:00:00Z';
const HASH = `sha256:${'e'.repeat(64)}`;
const HOSTILE = '<img src=x onerror="window.__pwned=1">';

/** An admin action as the list answers it, by `dana`; `fields` adds or replaces keys. */
const admin = (id, fields = {}) => ({
  id, kind: 'admin_action', timestamp: WHEN, outcome: 'change', who: { account: 'dana' }, ...fields,
});
/** A capability editor's admin action. */
const edit = (id, fields = {}) => admin(id, { surface: 'capability_editor', ...fields });

/** The list (`rows`) and the receipts by id mocked for a signed-in admin; the stream held. */
async function activity(page, request, testInfo, { rows = [], receipts = {} } = {}) {
  await heldStream(page, request, testInfo);
  await signedInAdmin(page);
  await page.route((url) => url.pathname.startsWith('/ui/api/activity'), (r) => {
    const { pathname } = new URL(r.request().url());
    if (pathname === '/ui/api/activity') return r.fulfill({ json: { rows, next_cursor: null, access: 'all' } });
    const body = receipts[decodeURIComponent(pathname.slice('/ui/api/activity/'.length))];
    return body ? r.fulfill({ json: body }) : r.fulfill({ status: 404, json: {} });
  });
}

async function openList(page) {
  await page.goto('/ui/activity/status');
  await shellReady(page);
}

async function openReceipt(page, id) {
  await page.goto(`/ui/activity/${encodeURIComponent(id)}/status`);
  await shellReady(page);
}

/** Each list row's cells, spaces folded: [time, who, middle, outcome]. */
const cells = (page) => page.locator('#content .activity-rows a').evaluateAll((links) => links.map(
  (a) => [...a.querySelectorAll(':scope > span')].map((s) => s.textContent.replace(/\s+/g, ' ').trim()),
));
const row = (middle, who = 'dana') => ['08:00:00', who, middle, 'change'];

const receiptHeading = (page, name) => page.locator('#content .activity-receipt')
  .getByRole('heading', { level: 2, ...(name === undefined ? {} : { name, exact: true }) });
/** The data-field paths the receipt drew, once each, sorted. */
const drawnFields = (page) => page.locator('#content [data-field]')
  .evaluateAll((els) => [...new Set(els.map((e) => e.dataset.field))].sort());

/** A capability save's receipt, with the file hashes the field list must leave out. */
const saveReceipt = (id, capability = 'billing') => ({
  id, kind: 'admin_action', counter: 9, timestamp: WHEN, signature: 'verified',
  surface: 'capability_editor', action: 'save', capability, pin: 'updated', outcome: 'change',
  who: { account: 'dana', authority: 'https://login.example', subject: 'user-7' },
  sha256_before: HASH, sha256_after: HASH,
});

test('V1 a capability save reads as who saved what and whether it was re-pinned', async ({ page, request }, testInfo) => {
  await activity(page, request, testInfo, { rows: [
    edit('1-a', { action: 'save', capability: 'billing', pin: 'updated' }),
    edit('2-a', { action: 'create', capability: 'billing', pin: 'added' }),
    edit('3-a', { action: 'delete', capability: 'billing', pin: 'none' }),
    edit('4-a', { action: 'save', capability: 'billing', pin: 'kept' }),
    edit('5-a', { action: 'save', capability: 'billing', pin: 'none' }),
    edit('6-a', { action: 'save', capability: 'billing', pin: 'added' }),
  ] });
  await openList(page);
  await expect.poll(() => cells(page)).toEqual([
    row('Saved capability billing · re-pinned'),
    row('Created capability billing · pinned'),
    row('Deleted capability billing'),
    row('Saved capability billing'),
    row('Saved capability billing'),
    row('Saved capability billing · pinned'),
  ]);
});

test('V2 every fallback of a capability row, by exact text', async ({ page, request }, testInfo) => {
  const saved = { action: 'save', capability: 'billing', pin: 'updated' };
  await activity(page, request, testInfo, { rows: [
    admin('1-b', { surface: 'admin_ui', method: 'PATCH', route: '/ui/api/backends/{name}' }),
    edit('2-b', { action: 'save', pin: 'updated' }),
    edit('3-b', { ...saved, capability: '' }),
    edit('4-b', { capability: 'billing', pin: 'updated' }),
    edit('5-b', { action: 'rename', capability: 'billing' }),
    edit('6-b', { action: 'rename', capability: 'billing', pin: 'added' }),
    edit('7-b', { ...saved, pin: 'repinned_v2' }),
  ] });
  await openList(page);
  await expect.poll(() => cells(page)).toEqual([
    row('PATCH /ui/api/backends/{name}'),
    row('Capability file changed'),
    row('Capability file changed'),
    row('Changed capability billing · re-pinned'),
    row('Changed capability billing'),
    row('Changed capability billing · pinned'),
    row('Saved capability billing'),
  ]);
});

test('V2b every other admin surface reads its tool, its method and route, or its surface', async ({ page, request }, testInfo) => {
  await activity(page, request, testInfo, { rows: [
    admin('1-c', { surface: 'meta_tool', tool: 'gateway_invoke' }),
    admin('2-c', { surface: 'admin_ui', route: '/ui/api/tools/call', method: 'POST', tool: 'kb.search' }),
    admin('3-c', { surface: 'ui_signin' }),
    admin('4-c', { surface: 'config', action: 'added', backend: 'docs', who: { account: 'config_file' } }),
  ] });
  await openList(page);
  await expect.poll(() => cells(page)).toEqual([
    row('gateway_invoke'),
    row('kb.search'),
    row('ui_signin'),
    row('config', 'config_file'),
  ]);
});

test('V3 a capability name is text, never markup', async ({ page, request }, testInfo) => {
  const said = `Saved capability ${HOSTILE} · re-pinned`;
  await activity(page, request, testInfo, {
    rows: [edit('9-d', { action: 'save', capability: HOSTILE, pin: 'updated' })],
    receipts: { '9-d': saveReceipt('9-d', HOSTILE) },
  });
  await openList(page);
  await expect.poll(() => cells(page)).toEqual([row(said)]);
  await expect(page.locator('#content img')).toHaveCount(0);
  expect(await page.evaluate(() => window.__pwned)).toBeUndefined();
  // The receipt heading is the name's second place on the page.
  await openReceipt(page, '9-d');
  await expect(receiptHeading(page, said)).toHaveCount(1);
  await expect(page.locator('#content img')).toHaveCount(0);
  expect(await page.evaluate(() => window.__pwned)).toBeUndefined();
});

test('V4 the receipt of a capability save says the same sentence and shows its fields', async ({ page, request }, testInfo) => {
  const call = {
    id: '10-e', kind: 'call', counter: 10, timestamp: WHEN, signature: 'verified',
    server: 'docs', tool: 'kb.search', outcome: 'ok', who: { account: 'dana' },
  };
  const config = {
    id: '7-e', kind: 'config', counter: 7, timestamp: WHEN, signature: 'verified',
    action: 'backend.add', actor_id: 'ops', target_id: 'docs', outcome: 'change',
  };
  await activity(page, request, testInfo, { receipts: { '9-e': saveReceipt('9-e'), '10-e': call, '7-e': config } });
  await openReceipt(page, '9-e');
  await expect(receiptHeading(page, 'Saved capability billing · re-pinned')).toHaveCount(1);
  // The heading opens the view: it comes first, straight before the facts.
  expect(await page.locator('#content dl.activity-facts').evaluate(
    (dl) => dl.previousElementSibling?.tagName === 'H2' && dl.parentElement.firstElementChild === dl.previousElementSibling,
  )).toBe(true);
  // The fields every receipt here carries, then the capability save's own; no file hash.
  const receiptFields = ['id', 'kind', 'counter', 'timestamp', 'signature'];
  const saveFields = ['surface', 'outcome', 'action', 'capability', 'pin', 'who.account', 'who.authority', 'who.subject'];
  expect(await drawnFields(page)).toEqual([...receiptFields, ...saveFields].sort());
  await expect(page.locator('#content [data-field="pin"]')).toHaveText('updated');
  await expect(page.locator('#content [data-field="capability"]')).toHaveText('billing');
  await expect(page.locator('#content [data-field="action"]')).toHaveText('save');
  await expect(page.locator('#content [data-field="who.account"]')).toHaveText('dana');
  // No other kind of receipt gets a heading.
  for (const id of ['10-e', '7-e']) {
    await openReceipt(page, id);
    await expect(page.locator('#content [data-field="kind"]'), `${id}: premise, the receipt is drawn`).toHaveCount(1);
    await expect(receiptHeading(page), `${id}: no heading`).toHaveCount(0);
  }
});
