// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Gateway › Settings, unused secret entries: the list of entries a failed or
// rolled-back save left in a secret store, each deleted one at a time after a
// confirm. Every refusal shows the gateway's own sentence and the entry stays
// listed. The shell document is served as the gateway serves it; /ui/api
// answers are mocked for a signed-in admin.
import { test, expect, WIDTHS, blockingViolations } from './base.mjs';
import { shellReady } from './shell.mjs';

const NAME_A = 'mcp-gateway.github.1731567600000.0123456789abcdef';
const NAME_B = 'mcp-gateway.slack.1731567700000.fedcba9876543210';
const HOSTILE = '<img src=x onerror="window.__pwned=1">';

const ENTRIES = [
  { name: NAME_A, store: 'files', written_at: '2026-11-10T08:00:00+00:00' },
  { name: NAME_B, store: 'keychain', written_at: null },
];

const LIST = '**/ui/api/settings/secrets/unused';
const ENTRY = '**/ui/api/settings/secrets/unused/*';

/**
 * A signed-in admin, the list answering `list` (or `listStatus` with a body),
 * and DELETE answering `del(name, store)` -> {status, json | body}. Every
 * DELETE is recorded in the returned array.
 */
async function unusedScreen(page, { list = { entries: ENTRIES, errors: [] }, listStatus = 200, del } = {}) {
  const deletes = [];
  let current = list;
  await page.route('**/ui/api/status', (r) => r.fulfill({ json: { auth: { enabled: true, signed_in: true, admin: true } } }));
  await page.route(LIST, (r) => (listStatus === 200
    ? r.fulfill({ json: current })
    : r.fulfill({ status: listStatus, json: { error: 'unreadable', message: 'The secret stores could not be read.' } })));
  await page.route(ENTRY, async (r) => {
    const url = new URL(r.request().url());
    const name = decodeURIComponent(url.pathname.split('/').pop());
    const store = url.searchParams.get('store');
    deletes.push({ method: r.request().method(), name, store });
    const answer = del ? del(name, store) : { status: 200, json: { deleted: name, already_gone: false } };
    if (answer.status === 200 && !answer.keep) {
      current = { ...current, entries: current.entries.filter((e) => e.name !== name) };
    }
    return answer.body !== undefined
      ? r.fulfill({ status: answer.status, contentType: 'text/plain', body: answer.body })
      : r.fulfill({ status: answer.status, json: answer.json });
  });
  return deletes;
}

const section = (page) => page.locator('#content section#unused-secrets');
const rows = (page) => section(page).locator('tr.unused-entry');
const row = (page, name) => rows(page).filter({ hasText: name });
const dialog = (page) => page.locator('dialog.confirm');
const act = (page, name) => dialog(page).getByRole('button', { name: `Delete entry ${name}` });
const message = (page) => dialog(page).locator('.confirm-message');

async function open(page) {
  await page.goto('/ui/gateway/settings');
  await shellReady(page);
}

test('G1: /ui/gateway, its Status and Actions links and the sidebar all land on Settings; no empty tab is drawn', async ({ page }) => {
  await unusedScreen(page);
  for (const from of ['/ui/gateway', '/ui/gateway/status', '/ui/gateway/actions']) {
    await page.goto(from);
    await shellReady(page);
    await expect(page).toHaveURL('/ui/gateway/settings');
    await expect(page.locator('nav.tabs a')).toHaveText(['Settings']);
    await expect(section(page)).toBeVisible();
  }
  await page.goto('/ui/tools/status');
  await shellReady(page);
  await page.locator('#pages').getByRole('link', { name: 'Gateway' }).click();
  await expect(page).toHaveURL('/ui/gateway/settings');
  await expect(section(page).getByRole('heading', { level: 2 })).toHaveText('Unused secret entries');
});

test('G2: each entry shows its name, store and written time; a store that could not be read shows why', async ({ page }) => {
  await unusedScreen(page, { list: { entries: ENTRIES, errors: [{ store: 'keychain', why: 'the keychain is locked' }] } });
  await open(page);
  await expect(rows(page)).toHaveCount(2);
  await expect(row(page, NAME_A).locator('td')).toHaveText([NAME_A, 'Files', '2026-11-10 08:00 UTC', 'Delete']);
  await expect(row(page, NAME_B).locator('td')).toHaveText([NAME_B, 'Keychain', 'Not recorded', 'Delete']);
  await expect(section(page).locator('.unused-errors li')).toHaveText(['Keychain could not be read: the keychain is locked']);
});

test('G3: no entry and no error is the empty state, with no table', async ({ page }) => {
  await unusedScreen(page, { list: { entries: [], errors: [] } });
  await open(page);
  await expect(section(page).getByText('No unused entries')).toBeVisible();
  await expect(section(page).locator('table')).toHaveCount(0);
});

test('G4: a name or reason holding markup is shown as text', async ({ page }) => {
  await unusedScreen(page, { list: { entries: [{ name: HOSTILE, store: 'files', written_at: null }], errors: [{ store: 'files', why: HOSTILE }] } });
  await open(page);
  await expect(row(page, HOSTILE)).toHaveCount(1);
  await expect(section(page).locator('.unused-errors li')).toHaveText([`Files could not be read: ${HOSTILE}`]);
  expect(await page.evaluate(() => window.__pwned)).toBeUndefined();
  await expect(section(page).locator('img')).toHaveCount(0);
});

test('G5: a confirmed delete sends the name and store, and the entry leaves the list; already gone says so', async ({ page }) => {
  const deletes = await unusedScreen(page, {
    del: (name) => ({ status: 200, json: { deleted: name, already_gone: name === NAME_B } }),
  });
  await open(page);
  await row(page, NAME_A).getByRole('button', { name: `Delete ${NAME_A}` }).click();
  await expect(dialog(page)).toBeVisible();
  await act(page, NAME_A).click();
  await expect(dialog(page)).toBeHidden();
  await expect(row(page, NAME_A)).toHaveCount(0);
  await expect(page.locator('.done-notice')).toContainText(`Deleted ${NAME_A}.`);
  expect(deletes).toEqual([{ method: 'DELETE', name: NAME_A, store: 'files' }]);

  await row(page, NAME_B).getByRole('button', { name: `Delete ${NAME_B}` }).click();
  await act(page, NAME_B).click();
  await expect(row(page, NAME_B)).toHaveCount(0);
  await expect(page.locator('.done-notice')).toContainText(`${NAME_B} was already gone.`);
  expect(deletes.at(-1)).toEqual({ method: 'DELETE', name: NAME_B, store: 'keychain' });
});

test('G6: Cancel deletes nothing and keeps the entry', async ({ page }) => {
  const deletes = await unusedScreen(page);
  await open(page);
  await row(page, NAME_A).getByRole('button', { name: `Delete ${NAME_A}` }).click();
  await dialog(page).getByRole('button', { name: 'Cancel' }).click();
  await expect(dialog(page)).toBeHidden();
  await expect(row(page, NAME_A)).toHaveCount(1);
  expect(deletes).toEqual([]);
});

// The 4xx refusals of the delete route, with its own sentences.
const REFUSED = [
  [400, 'bad_name', 'the name or the store is not one this route deletes'],
  [404, 'not_listed', 'that entry is not listed'],
  [409, 'store_mismatch', 'that entry is in the other store'],
  [409, 'named', 'a source still names that entry'],
  [409, 'pending', 'a config write is still unsettled'],
  [409, 'no_keychain', 'no keychain on this platform'],
  [409, 'busy', 'a lock this delete needs is held'],
  // macOS and Windows until the late-delete fix lifts it; the screen needs no change then.
  [409, 'keychain_delete_unavailable', 'keychain entries cannot be deleted from Settings on this platform yet: the system keychain can finish a timed-out delete later, after a config may name the entry again'],
];

for (const [status, code, sentence] of REFUSED) {
  test(`G7 ${code}: a ${status} refusal shows the gateway's sentence, the entry stays, and Delete works again`, async ({ page }) => {
    const deletes = await unusedScreen(page, { del: () => ({ status, json: { error: code, message: sentence } }) });
    await open(page);
    await row(page, NAME_A).getByRole('button', { name: `Delete ${NAME_A}` }).click();
    await act(page, NAME_A).click();
    await expect(message(page)).toContainText(sentence);
    await dialog(page).getByRole('button', { name: 'Close' }).click();
    await expect(dialog(page)).toBeHidden();
    await expect(row(page, NAME_A)).toHaveCount(1);
    await row(page, NAME_A).getByRole('button', { name: `Delete ${NAME_A}` }).click();
    await expect(dialog(page)).toBeVisible();
    await act(page, NAME_A).click();
    await expect(message(page)).toContainText(sentence);
    expect(deletes).toHaveLength(2);
  });
}

// A 503 is not a refusal: the outcome is not confirmed. The headline stays, the
// gateway's sentence sits under it, Reload is offered and Try again is not.
const UNCONFIRMED = [
  ['timed_out', 'the secret store did not answer in time'],
  ['failed', 'the secret store refused the delete'],
];

for (const [code, sentence] of UNCONFIRMED) {
  test(`G10 ${code}: a 503 shows "not confirmed" with the gateway's sentence; after Close the list is read again`, async ({ page }) => {
    let reads = 0;
    await unusedScreen(page, { del: () => ({ status: 503, json: { error: code, message: sentence } }) });
    page.on('request', (r) => { if (r.url().endsWith('/ui/api/settings/secrets/unused')) reads += 1; });
    await open(page);
    const before = reads;
    await row(page, NAME_A).getByRole('button', { name: `Delete ${NAME_A}` }).click();
    await act(page, NAME_A).click();
    await expect(message(page)).toContainText('The gateway did not confirm the outcome.');
    await expect(message(page).locator('.confirm-detail')).toHaveText(sentence);
    await expect(message(page)).toContainText(`Reload to see whether entry ${NAME_A} changed.`);
    await expect(dialog(page).getByRole('button', { name: 'Try again' })).toHaveCount(0);
    await dialog(page).getByRole('button', { name: 'Close' }).click();
    await expect(dialog(page)).toBeHidden();
    await expect.poll(() => reads).toBeGreaterThan(before);
    await expect(row(page, NAME_A)).toHaveCount(1);
  });
}

test('G8: a refusal whose body is not JSON keeps the shell\'s own words', async ({ page }) => {
  await unusedScreen(page, { del: () => ({ status: 409, body: 'conflict' }) });
  await open(page);
  await row(page, NAME_A).getByRole('button', { name: `Delete ${NAME_A}` }).click();
  await act(page, NAME_A).click();
  await expect(message(page)).toContainText('changed since this page loaded.');
  await expect(message(page)).not.toContainText('conflict');
});

test('G9: a list the gateway could not read is the page error, with no table', async ({ page }) => {
  await unusedScreen(page, { listStatus: 503 });
  await page.goto('/ui/gateway/settings');
  await expect(page.getByRole('button', { name: 'Retry' })).toBeVisible();
  await expect(page.locator('#content table')).toHaveCount(0);
});

for (const width of WIDTHS) {
  test(`G11: axe finds no blocking violation on the list and the confirm at ${width} px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await unusedScreen(page, { list: { entries: ENTRIES, errors: [{ store: 'keychain', why: 'the keychain is locked' }] } });
    await open(page);
    await expect(rows(page)).toHaveCount(2);
    expect(await blockingViolations(page)).toEqual([]);
    await row(page, NAME_A).getByRole('button', { name: `Delete ${NAME_A}` }).click();
    await expect(dialog(page)).toBeVisible();
    expect(await blockingViolations(page)).toEqual([]);
  });
}

const deleteButton = (page, name) => row(page, name).getByRole('button', { name: `Delete ${name}` });

test('G12: after Cancel, and after a refusal\'s Close, focus is on that entry\'s Delete again', async ({ page }) => {
  await unusedScreen(page, { del: () => ({ status: 409, json: { error: 'named', message: 'a source still names that entry' } }) });
  await open(page);
  await deleteButton(page, NAME_B).click();
  await dialog(page).getByRole('button', { name: 'Cancel' }).click();
  await expect(deleteButton(page, NAME_B)).toBeFocused();
  await deleteButton(page, NAME_B).click();
  await act(page, NAME_B).click();
  await expect(message(page)).toContainText('a source still names that entry');
  await dialog(page).getByRole('button', { name: 'Close' }).click();
  await expect(dialog(page)).toBeHidden();
  await expect(deleteButton(page, NAME_B)).toBeFocused();
});

test('G13: a flat {error: sentence} refusal shows its sentence; a long one is cut at 500 characters', async ({ page }) => {
  const long = `${'a'.repeat(499)}bz`;
  let body = { error: 'that entry changed while you looked' };
  await unusedScreen(page, { del: () => ({ status: 409, json: body }) });
  await open(page);
  await deleteButton(page, NAME_A).click();
  await act(page, NAME_A).click();
  await expect(message(page)).toContainText('that entry changed while you looked');
  await dialog(page).getByRole('button', { name: 'Close' }).click();
  body = { error: 'named', message: long };
  await deleteButton(page, NAME_A).click();
  await act(page, NAME_A).click();
  await expect(message(page)).toContainText(`${'a'.repeat(499)}b`);
  await expect(message(page)).not.toContainText('bz');
});

test('G14: markup in a refusal\'s or a not-confirmed sentence is shown as text', async ({ page }) => {
  let status = 409;
  await unusedScreen(page, { del: () => ({ status, json: { error: 'named', message: HOSTILE } }) });
  await open(page);
  for (const s of [409, 503]) {
    status = s;
    await deleteButton(page, NAME_A).click();
    await act(page, NAME_A).click();
    await expect(message(page)).toContainText(HOSTILE);
    await expect(dialog(page).locator('img')).toHaveCount(0);
    await dialog(page).getByRole('button', { name: 'Close' }).click();
    await expect(dialog(page)).toBeHidden();
  }
  expect(await page.evaluate(() => window.__pwned)).toBeUndefined();
});
