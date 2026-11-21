// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The shared Settings save flow, as its reviewed design describes it: the
// masked diff is reviewed on the page, the shell's confirm follows, then the
// save. Each row opens /ui/gateway/settings, imports the module by its hashed
// name, runs settingsSave on a host it adds and keeps every request it sees.
// Mocked refusals use the exact bodies the routes send (settings.rs, errors.rs).
import { fileURLToPath } from 'node:url';
import { readdirSync } from 'node:fs';
import { shellReady } from './shell.mjs';
import { expect, test } from './base.mjs';

const DIFF_ROUTE = '**/ui/api/settings/diff';
const SAVE_ROUTE = '**/ui/api/settings';
const ADMIN_STATUS = { auth: { enabled: true, signed_in: true, admin: true } };
const REV1 = 'a'.repeat(64);
const REV2 = 'b'.repeat(64);
const DIFF = '--- a/gateway.yaml\n+++ b/gateway.yaml\n@@ -3 +3 @@\n-  log_level: info\n+  log_level: debug';
const DIFF2 = '--- a/gateway.yaml\n+++ b/gateway.yaml\n@@ -3 +3 @@\n-  log_level: warn\n+  log_level: debug';
const FIELDS = [{ field: 'server.log_level', value: { set: 'debug' } }];
const SECRET = 's3cr3t-canary-9236';
const SECRET_FIELDS = [
  { field: 'auth.bearer_token', value: { secret: SECRET } },
  { field: 'backends.headers', backend: 'github', index: 0, value: { set: 'x' } },
];
const PATCH = [{ op: 'set', path: 'server.log_level', code: 'anchored', reason: 'the key is an anchor' }];
const SAVED = { revision: REV2, changed: true, restart_required: [], reload: { applied: true }, comments: 'kept' };
const OBJECT = 'Gateway settings';
const HELD = "An earlier save's outcome is not confirmed. Reload the page before saving again.";
const UNCONFIRMED = 'The outcome is not confirmed. Reload the page to see what gateway.yaml holds now.';
const NEXT_409 = 'Close to keep this review; Reload page discards it.';

/** /ui/assets/ path of the hashed settingsave module, found in the shell directory. */
function moduleUrl() {
  const shellDir = fileURLToPath(new URL('../../src/gateway/ui/shell/', import.meta.url));
  const file = readdirSync(shellDir).find((f) => /^settingsave\.[0-9a-f]{12}\.js$/.test(f));
  if (!file) throw new Error('src/gateway/ui/shell has no settingsave.<hash>.js');
  return `/ui/assets/${file}`;
}

const box = (page) => page.locator('dialog.confirm');
const confirmButton = (page, verb) => box(page).getByRole('button', { name: `${verb} ${OBJECT}` });
const action = (page) => confirmButton(page, 'Save');
const keep = (page) => confirmButton(page, 'Cancel');
const host = (page, id = 'ss-a') => page.locator(`#${id}`);
const results = (page) => page.evaluate(() => window.__results);
const heard = (page) => page.evaluate(() => window.__writes.join('\n'));
const saves = (list) => list.filter((q) => q.path === '/ui/api/settings');
const diffs = (list) => list.filter((q) => q.path === '/ui/api/settings/diff');

/** Fulfil a mocked route from `a`: {status?, json}, {status?, raw} or {abort: true}; waits on `a.hold` first. */
async function reply(route, a) {
  if (a.hold) await a.hold;
  if (a.abort) return route.abort();
  if (a.raw !== undefined) return route.fulfill({ status: a.status ?? 200, contentType: 'application/json', body: a.raw });
  return route.fulfill({ status: a.status ?? 200, json: a.json });
}

/**
 * Gateway › Settings for a signed-in admin, plus two hosts (#ss-a, #ss-b) and
 * a trigger button (#ss-open). `diff` and `save` turn a request body into an
 * answer and default to success. Resolves to the list of requests seen.
 */
async function screen(page, { diff, save } = {}) {
  const seenRequests = [];
  const note = (r) => {
    const req = r.request();
    let body;
    try { body = req.postDataJSON(); } catch { body = req.postData(); }
    const one = { path: new URL(req.url()).pathname, method: req.method(), type: req.headers()['content-type'] ?? null, body };
    seenRequests.push(one);
    return one;
  };
  await page.addInitScript(() => {
    Object.assign(window, { __writes: [], __results: [] });
    document.addEventListener('DOMContentLoaded', () => {
      const live = document.querySelector('#announcer');
      const take = (list) => list.forEach((m) => m.addedNodes.forEach((node) => window.__writes.push(node.textContent?.trim() ?? '')));
      new MutationObserver(take).observe(live, { childList: true });
    });
  });
  await page.route('**/ui/api/status', (r) => r.fulfill({ json: ADMIN_STATUS }));
  await page.route(DIFF_ROUTE, (r) => reply(r, (diff ?? (() => ({ json: { revision: REV1, diff: DIFF } })))(note(r).body)));
  await page.route(SAVE_ROUTE, (r) => reply(r, (save ?? (() => ({ json: SAVED })))(note(r).body)));
  await page.goto('/ui/gateway/settings');
  await shellReady(page);
  await page.evaluate(() => {
    const content = document.getElementById('content');
    content.append(Object.assign(document.createElement('button'), { id: 'ss-open', type: 'button', textContent: 'Review changes' }));
    for (const id of ['ss-a', 'ss-b']) content.append(Object.assign(document.createElement('section'), { id }));
  });
  return seenRequests;
}

/** Run settingsSave on host `id`; whatever it resolves to is pushed to window.__results. */
async function start(page, { id = 'ss-a', fields = FIELDS, key = 'settings-test', from } = {}) {
  if (from) await page.locator(from).focus();
  await page.evaluate(async ({ url, id, fields, key }) => {
    const { settingsSave } = await import(url);
    const done = settingsSave({ host: document.getElementById(id), fields, object: 'Gateway settings', key });
    Promise.resolve(done).then((r) => window.__results.push(r ?? null));
  }, { url: moduleUrl(), id, fields, key });
}

/** A review on `id` with its Save pressed, leaving the confirm open. */
async function toConfirm(page, opts = {}) {
  await start(page, opts);
  await host(page, opts.id).getByRole('button', { name: 'Save', exact: true }).click();
  await expect(action(page)).toBeVisible();
}

/** A route answer that waits until `release()` is called. */
function gate() {
  let release;
  const hold = new Promise((resolve) => { release = resolve; });
  return { hold, release };
}

test('T1 the diff comes first: one diff request, the masked diff and the comments sentence, no save yet', async ({ page }) => {
  const seen = await screen(page);
  await start(page);
  await expect(host(page).getByRole('heading', { name: 'Review before saving' })).toBeVisible();
  await expect(host(page).getByRole('figure', { name: 'Proposed change to gateway.yaml' })).toBeVisible();
  await expect(host(page).locator('pre.diff')).toContainText('+  log_level: debug');
  await expect(host(page).getByText('Every other line and all comments in gateway.yaml stay as they are.')).toBeVisible();
  expect(diffs(seen)).toHaveLength(1);
  expect(saves(seen)).toHaveLength(0);
});

test('T2 Back clears the review and sends nothing', async ({ page }) => {
  const seen = await screen(page);
  await start(page);
  await host(page).getByRole('button', { name: 'Back' }).click();
  await expect(host(page).locator('pre.diff')).toHaveCount(0);
  expect(saves(seen)).toHaveLength(0);
  await expect.poll(() => results(page)).toEqual([{ outcome: 'back' }]);
});

test('T3 a confirmed save sends one JSON request with the reviewed revision and the fields; the diff request is JSON too', async ({ page }) => {
  const seen = await screen(page);
  await toConfirm(page, { fields: SECRET_FIELDS });
  await action(page).click();
  await expect.poll(() => saves(seen).length).toBe(1);
  const [save] = saves(seen);
  expect(save.type).toMatch(/^application\/json/);
  expect(save.body).toEqual({ base_revision: REV1, fields: SECRET_FIELDS });
  const [preview] = diffs(seen);
  expect(preview.type).toMatch(/^application\/json/);
  expect(preview.body).toEqual({
    fields: [
      { field: 'auth.bearer_token', value: { secret: true } },
      { field: 'backends.headers', backend: 'github', index: 0, value: { set: 'x' } },
    ],
  });
});

test('T4 Cancel in the confirm sends nothing', async ({ page }) => {
  const seen = await screen(page);
  await toConfirm(page);
  await keep(page).click();
  await expect(box(page)).toHaveCount(0);
  expect(saves(seen)).toHaveLength(0);
  await expect(host(page).locator('pre.diff')).toBeVisible();
});

test('T5 a patch answer: no Save, the reasons and the patch, an announced banner, and Copy puts the patch on the clipboard', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await screen(page, { diff: () => ({ json: { revision: REV1, patch: PATCH } }) });
  await start(page);
  await expect(host(page).getByText('Nothing saved: this change cannot be made in place.')).toBeVisible();
  await expect(host(page).getByRole('button', { name: 'Save', exact: true })).toHaveCount(0);
  await expect(host(page)).toContainText('the key is an anchor');
  const patchText = await host(page).locator('pre').last().textContent();
  expect(patchText).toContain('server.log_level');
  await host(page).getByRole('button', { name: 'Copy' }).click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(patchText);
  await expect.poll(() => heard(page)).toContain('Nothing saved: this change cannot be made in place.');
});

test('T6 stale with a newer diff: both buttons and words for both; after Close the newer diff, and the next save sends its revision', async ({ page }) => {
  let answered = 0;
  const seen = await screen(page, {
    save: () => (answered++ === 0
      ? { status: 409, json: { error: 'stale', current: REV2, diff: DIFF2 } }
      : { json: SAVED }),
  });
  await toConfirm(page);
  await action(page).click();
  await expect(box(page)).toContainText('gateway.yaml changed since you reviewed it.');
  await expect(box(page)).toContainText('Close to review the newer change here; Reload page discards this review.');
  await expect(box(page).getByRole('button', { name: 'Reload page' })).toBeVisible();
  await box(page).getByRole('button', { name: 'Close' }).click();
  await expect(host(page).locator('pre.diff')).toContainText('-  log_level: warn');
  await expect(host(page)).toContainText('gateway.yaml changed since you reviewed it; check this before saving again.');
  await host(page).getByRole('button', { name: 'Save', exact: true }).click();
  await action(page).click();
  await expect.poll(() => saves(seen).length).toBe(2);
  expect(saves(seen)[1].body.base_revision).toBe(REV2);
});

test('T6b stale with a patch: the confirm says the patch is next; after Close the patch view, with no Save', async ({ page }) => {
  await screen(page, { save: () => ({ status: 409, json: { error: 'stale', current: REV2, patch: PATCH } }) });
  await toConfirm(page);
  await action(page).click();
  await expect(box(page)).toContainText('Close to see the patch to copy; Reload page discards this review.');
  await box(page).getByRole('button', { name: 'Close' }).click();
  await expect(host(page).getByText('Nothing saved: this change cannot be made in place.')).toBeVisible();
  await expect(host(page).getByRole('button', { name: 'Save', exact: true })).toHaveCount(0);
});

test('T7 busy: the gateway sentence, the shared next line and both buttons; the review stays and nothing is resent', async ({ page }) => {
  const seen = await screen(page, { save: () => ({ status: 409, json: { error: 'the config is being written; retry' } }) });
  await toConfirm(page);
  await action(page).click();
  await expect(box(page)).toContainText('the config is being written; retry');
  await expect(box(page)).toContainText(NEXT_409);
  await expect(box(page).getByRole('button', { name: 'Reload page' })).toBeVisible();
  await box(page).getByRole('button', { name: 'Close' }).click();
  await expect(host(page).locator('pre.diff')).toBeVisible();
  expect(saves(seen)).toHaveLength(1);
});

test('T8 not_in_place on save: after Close the patch view, its first line announced', async ({ page }) => {
  await screen(page, { save: () => ({ status: 422, json: { error: 'not_in_place', patch: PATCH } }) });
  await toConfirm(page);
  await action(page).click();
  await expect(box(page)).toContainText('This change cannot be made in place.');
  await expect(box(page)).toContainText('Close to see the patch to copy.');
  await box(page).getByRole('button', { name: 'Close' }).click();
  await expect(host(page).getByText('Nothing saved: this change cannot be made in place.')).toBeVisible();
  await expect.poll(() => heard(page)).toContain('Nothing saved: this change cannot be made in place.');
});

const AUDIT_SENTENCE = 'saves need the audit log; turn it on, then retry';
const UNCONFIRMED_WAYS = [
  { name: 'a 500', save: () => ({ status: 500, json: { error: 'failed', message: 'the save failed' } }) },
  { name: 'a network failure', save: () => ({ abort: true }) },
  { name: 'an unreadable 200', save: () => ({ raw: 'not json' }) },
  { name: 'a 401', save: () => ({ status: 401, json: { error: 'Authentication required' } }) },
  { name: 'the time limit', save: () => ({ hold: new Promise(() => {}) }), clock: true },
  { name: 'a 503 audit_log_required', save: () => ({ status: 503, json: { error: 'audit_log_required', message: AUDIT_SENTENCE } }), sentence: AUDIT_SENTENCE },
];

for (const way of UNCONFIRMED_WAYS) {
  test(`T9 held after ${way.name}: the not-confirmed line, then every later call on any host declines at once until a reload`, async ({ page }) => {
    if (way.clock) await page.clock.install();
    const seen = await screen(page, { save: way.save });
    await toConfirm(page);
    await action(page).click();
    if (way.clock) await page.clock.runFor(30_001);
    // A 401 hands over to sign-in and the shell closes the dialog itself; every other way waits on Close.
    if (way.name === 'a 401') await expect(box(page)).toHaveCount(0);
    else await box(page).getByRole('button', { name: 'Close' }).click();
    await expect(host(page)).toContainText(UNCONFIRMED);
    if (way.sentence) await expect(host(page)).toContainText(way.sentence);
    await expect.poll(async () => (await results(page)).map((r) => r?.outcome)).toEqual(['unconfirmed']);
    const before = seen.length;
    await start(page, { id: 'ss-a' });
    await start(page, { id: 'ss-b' });
    await expect.poll(async () => (await results(page)).map((r) => r?.outcome)).toEqual(['unconfirmed', 'declined', 'declined']);
    expect(seen.length).toBe(before);
    await expect(host(page, 'ss-b')).toContainText(HELD);
    await expect(host(page, 'ss-b').locator('pre.diff')).toHaveCount(0);
    // While sign-in shows, the shell keeps only sign-in's own messages (shell.js pump), so the 401 run
    // hears the held line only after sign-in closes; T9c proves that it is heard then.
    if (way.name !== 'a 401') await expect.poll(() => heard(page)).toContain(HELD);
    await page.reload();
    await shellReady(page);
    await page.evaluate(() => document.getElementById('content').append(Object.assign(document.createElement('section'), { id: 'ss-a' })));
    await start(page);
    await expect.poll(() => diffs(seen).length).toBe(2);
  });
}

test('T9c a not-confirmed or held line shown while sign-in hides the page is heard once sign-in closes, once each', async ({ page }) => {
  await screen(page, { save: () => ({ status: 401, json: { error: 'Authentication required' } }) });
  await toConfirm(page);
  await action(page).click();
  await expect(page.locator('#signin')).toBeVisible();
  await expect(host(page)).toContainText(UNCONFIRMED);
  await start(page, { id: 'ss-b' });
  await expect(host(page, 'ss-b')).toContainText(HELD);
  expect(await heard(page)).not.toContain(UNCONFIRMED);
  await page.locator('#signin-key').fill('mcpgw_test_key');
  await page.keyboard.press('Enter');
  await expect(page.locator('#signin')).toBeHidden();
  await expect.poll(() => heard(page)).toContain(UNCONFIRMED);
  await expect.poll(() => heard(page)).toContain(HELD);
  const said = (await page.evaluate(() => window.__writes)).join('\n');
  expect(said.split(UNCONFIRMED).length - 1).toBe(1);
  expect(said.split(HELD).length - 1).toBe(1);
});

test('T9b held reaches an open review: Save on host B after host A came back unconfirmed shows the held line and sends nothing', async ({ page }) => {
  const seen = await screen(page, { save: () => ({ status: 500, json: { error: 'failed', message: 'the save failed' } }) });
  await start(page, { id: 'ss-b' });
  await expect(host(page, 'ss-b').locator('pre.diff')).toBeVisible();
  await toConfirm(page, { id: 'ss-a' });
  await action(page).click();
  await box(page).getByRole('button', { name: 'Close' }).click();
  await expect(host(page, 'ss-a')).toContainText(UNCONFIRMED);
  const before = seen.length;
  await host(page, 'ss-b').getByRole('button', { name: 'Save', exact: true }).click();
  await expect(host(page, 'ss-b')).toContainText(HELD);
  await expect(box(page)).toHaveCount(0);
  expect(seen.length).toBe(before);
  await expect.poll(() => heard(page)).toContain(HELD);
  await expect.poll(async () => (await results(page)).map((r) => r?.outcome)).toEqual(['unconfirmed', 'declined']);
  await start(page, { id: 'ss-b' });
  await expect.poll(async () => (await results(page)).map((r) => r?.outcome)).toEqual(['unconfirmed', 'declined', 'declined']);
  expect(seen.length).toBe(before);
});

const OUTCOMES = [
  { name: 'changed', answer: SAVED, line: 'Saved.' },
  { name: 'unchanged', answer: { ...SAVED, changed: false }, line: 'Nothing changed: gateway.yaml already had these values.' },
  { name: 'restart', answer: { ...SAVED, restart_required: ['server.port'] }, line: 'Takes effect after a restart: server.port' },
];

for (const o of OUTCOMES) {
  test(`T10 a save that lands (${o.name}) shows its line, announces it and resolves done with the answer`, async ({ page }) => {
    await screen(page, { save: () => ({ json: o.answer }) });
    await toConfirm(page);
    await action(page).click();
    await expect(host(page)).toContainText(o.line);
    await expect.poll(() => heard(page)).toContain(o.line);
    await expect.poll(() => results(page)).toEqual([{ outcome: 'done', answer: o.answer }]);
  });
}

for (const shown of ['diff', 'patch']) {
  test(`T11 a secret goes only in the save body: never in the diff request, the page, the ${shown} view or the clipboard`, async ({ page, context }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    const preview = shown === 'diff' ? { revision: REV1, diff: DIFF } : { revision: REV1, patch: PATCH };
    const seen = await screen(page, { diff: () => ({ json: preview }) });
    await start(page, { fields: SECRET_FIELDS });
    await expect(host(page).locator('pre')).not.toHaveCount(0);
    expect(JSON.stringify(diffs(seen)[0].body)).not.toContain(SECRET);
    expect(diffs(seen)[0].body.fields[0].value).toEqual({ secret: true });
    if (shown === 'patch') {
      await host(page).getByRole('button', { name: 'Copy' }).click();
      expect(await page.evaluate(() => navigator.clipboard.readText())).not.toContain(SECRET);
    } else {
      await host(page).getByRole('button', { name: 'Save', exact: true }).click();
      await action(page).click();
      await expect.poll(() => saves(seen).length).toBe(1);
      expect(saves(seen)[0].body.fields[0].value).toEqual({ secret: SECRET });
    }
    expect(await page.content()).not.toContain(SECRET);
  });
}

test('T12 the diff block is reachable by its name and holds the diff', async ({ page }) => {
  await screen(page);
  await start(page);
  const figure = page.getByRole('figure', { name: 'Proposed change to gateway.yaml' });
  await expect(figure).toHaveCount(1);
  await expect(figure.locator('pre.diff')).toContainText('+  log_level: debug');
});

test('T13 the confirm names the changed settings first, then that everything else stays', async ({ page }) => {
  await screen(page);
  await toConfirm(page);
  await expect(box(page).locator('li')).toHaveText([
    'Changes server.log_level in gateway.yaml.',
    'Every other line and all comments stay.',
  ]);
});

test('T14 invalid on save: after Close the review stays with the gateway sentence above it, and no patch view', async ({ page }) => {
  const sentence = 'the gateway refused the new config; nothing was written';
  await screen(page, { save: () => ({ status: 422, json: { error: 'invalid', message: sentence, fields: ['server.log_level'] } }) });
  await toConfirm(page);
  await action(page).click();
  await expect(box(page)).toContainText(sentence);
  await box(page).getByRole('button', { name: 'Close' }).click();
  await expect(host(page)).toContainText(sentence);
  await expect(host(page).locator('pre.diff')).toBeVisible();
  await expect(host(page).getByText('Nothing saved: this change cannot be made in place.')).toHaveCount(0);
});

const PREVIEW_FAILURES = [
  { name: 'a 500 with no sentence', diff: () => ({ status: 500, json: {} }), cause: 'The gateway answered with an error' },
  { name: 'a network failure', diff: () => ({ abort: true }), cause: 'Could not reach the gateway' },
];

for (const f of PREVIEW_FAILURES) {
  test(`T15 a preview failure (${f.name}) names its cause, sends no save, locks nothing`, async ({ page }) => {
    let calls = 0;
    const seen = await screen(page, { diff: () => (calls++ === 0 ? f.diff() : { json: { revision: REV1, diff: DIFF } }) });
    await start(page);
    await expect(host(page)).toContainText('Could not prepare the change.');
    await expect(host(page)).toContainText(f.cause);
    await expect(host(page)).not.toContainText('[object Object]');
    await expect(host(page)).not.toContainText('Preparing the change');
    await expect.poll(() => heard(page)).toContain('Could not prepare the change.');
    await expect(box(page)).toHaveCount(0);
    expect(saves(seen)).toHaveLength(0);
    await expect.poll(async () => (await results(page)).map((r) => r?.outcome)).toEqual(['preview_failed']);
    await toConfirm(page);
  });
}

test('T16 the diff header lines carry no add or del class; hunk, add and del lines do', async ({ page }) => {
  await screen(page);
  await start(page);
  await expect(host(page).locator('pre.diff')).toBeVisible();
  const lines = await host(page).locator('pre.diff').evaluate((pre) => [...pre.children].map((l) => [l.textContent, l.className]));
  const classOf = (text) => lines.find(([t]) => t === text)?.[1] ?? null;
  for (const header of ['--- a/gateway.yaml', '+++ b/gateway.yaml']) {
    expect(classOf(header)).not.toMatch(/\b(add|del)\b/);
  }
  expect(classOf('@@ -3 +3 @@')).toMatch(/\bhunk\b/);
  expect(classOf('+  log_level: debug')).toMatch(/\badd\b/);
  expect(classOf('-  log_level: info')).toMatch(/\bdel\b/);
});

test('T17 one flow per host: a second call while the first is open declines untouched, and the first still ends normally', async ({ page }) => {
  const seen = await screen(page);
  await start(page);
  await expect(host(page).locator('pre.diff')).toBeVisible();
  const painted = await host(page).innerHTML();
  await start(page);
  await expect.poll(async () => (await results(page)).map((r) => r?.outcome)).toEqual(['declined']);
  expect(await host(page).innerHTML()).toBe(painted);
  expect(seen).toHaveLength(1);
  await host(page).getByRole('button', { name: 'Back' }).click();
  await expect.poll(async () => (await results(page)).map((r) => r?.outcome)).toEqual(['declined', 'back']);
});

test('T17b held plus an open flow on that host: the one-flow rule wins, with no request, no held line and the review kept', async ({ page }) => {
  const seen = await screen(page, { save: () => ({ status: 500, json: { error: 'failed', message: 'the save failed' } }) });
  await start(page, { id: 'ss-b' });
  await expect(host(page, 'ss-b').locator('pre.diff')).toBeVisible();
  await toConfirm(page, { id: 'ss-a' });
  await action(page).click();
  await box(page).getByRole('button', { name: 'Close' }).click();
  await expect(host(page, 'ss-a')).toContainText(UNCONFIRMED);
  const before = seen.length;
  await start(page, { id: 'ss-b' });
  await expect.poll(async () => (await results(page)).map((r) => r?.outcome)).toEqual(['unconfirmed', 'declined']);
  expect(seen.length).toBe(before);
  await expect(host(page, 'ss-b')).not.toContainText(HELD);
  await expect(host(page, 'ss-b').locator('pre.diff')).toBeVisible();
});

const NOT_STARTED = 'Nothing was sent: the save could not start. Close any open dialog, sign in if asked, then try again.';

test('T18 the shell refuses to open a second confirm: no save request, the not-started line on that host, announced', async ({ page }) => {
  const seen = await screen(page);
  await start(page, { id: 'ss-b' });
  await expect(host(page, 'ss-b').locator('pre.diff')).toBeVisible();
  await toConfirm(page, { id: 'ss-a' });
  await page.evaluate(() => [...document.querySelectorAll('#ss-b button')].find((b) => b.textContent === 'Save').click());
  await expect(host(page, 'ss-b')).toContainText(NOT_STARTED);
  await expect.poll(() => heard(page)).toContain(NOT_STARTED);
  await expect.poll(async () => (await results(page)).map((r) => r?.outcome)).toEqual(['declined']);
  expect(saves(seen)).toHaveLength(0);
});

const focusIn = (page, id = 'ss-a') => page.evaluate((id) => {
  const active = document.activeElement;
  return active !== document.body && document.getElementById(id).contains(active);
}, id);

test('T19 focus: Back goes back to the calling button, or to the host once that button is gone; a landed save focuses inside the host', async ({ page }) => {
  await screen(page);
  await start(page, { from: '#ss-open' });
  await host(page).getByRole('button', { name: 'Back' }).click();
  await expect(page.locator('#ss-open')).toBeFocused();
  await start(page, { from: '#ss-open' });
  await page.evaluate(() => document.getElementById('ss-open').remove());
  await host(page).getByRole('button', { name: 'Back' }).click();
  await expect(host(page)).toBeFocused();
  await toConfirm(page);
  await action(page).click();
  await expect(host(page)).toContainText('Saved.');
  await expect.poll(() => focusIn(page)).toBe(true);
});

test('T19b focus lands inside the host after a newer diff and after a patch view', async ({ page }) => {
  let answered = 0;
  await screen(page, {
    save: () => (answered++ === 0
      ? { status: 409, json: { error: 'stale', current: REV2, diff: DIFF2 } }
      : { status: 422, json: { error: 'not_in_place', patch: PATCH } }),
  });
  await toConfirm(page);
  await action(page).click();
  await box(page).getByRole('button', { name: 'Close' }).click();
  await expect(host(page).locator('pre.diff')).toContainText('-  log_level: warn');
  await expect.poll(() => focusIn(page)).toBe(true);
  await host(page).getByRole('button', { name: 'Save', exact: true }).click();
  await action(page).click();
  await box(page).getByRole('button', { name: 'Close' }).click();
  await expect(host(page).getByRole('button', { name: 'Copy' })).toBeVisible();
  await expect.poll(() => focusIn(page)).toBe(true);
});

const BAD_VALUE = { error: 'bad_value', field: 'server.log_level', reason: 'not one of debug, info, warn, error' };
const BAD_VALUE_WORDS = 'server.log_level: not one of debug, info, warn, error';
const noBareCode = async (page) => {
  const text = `${await host(page).innerText()}\n${await page.locator('dialog').allInnerTexts()}`;
  for (const code of ['bad_value', 'unknown_field', 'invalid_body', 'stale']) expect(text).not.toMatch(new RegExp(`(^|\\s)${code}(\\s|$)`));
};

test('T20a a field refusal on the preview reads "<field>: <reason>", never its code', async ({ page }) => {
  await screen(page, { diff: () => ({ status: 422, json: BAD_VALUE }) });
  await start(page);
  await expect(host(page)).toContainText(BAD_VALUE_WORDS);
  await noBareCode(page);
});

test('T20b a field refusal on the save reads "<field>: <reason>" in the confirm and on the host', async ({ page }) => {
  await screen(page, { save: () => ({ status: 422, json: BAD_VALUE }) });
  await toConfirm(page);
  await action(page).click();
  await expect(box(page)).toContainText(BAD_VALUE_WORDS);
  await noBareCode(page);
  await box(page).getByRole('button', { name: 'Close' }).click();
  await expect(host(page)).toContainText(BAD_VALUE_WORDS);
});

test('T20c unknown_field names the item it points at', async ({ page }) => {
  await screen(page, { diff: () => ({ status: 422, json: { error: 'unknown_field', entry: 0 } }) });
  await start(page);
  await expect(host(page)).toContainText('server.log_level is not a setting this page can change.');
  await noBareCode(page);
});

test('T20d a bare code (invalid_body) has no sentence, so the shell default words show', async ({ page }) => {
  await screen(page, { save: () => ({ status: 422, json: { error: 'invalid_body' } }) });
  await toConfirm(page);
  await action(page).click();
  await expect(box(page)).toContainText('The gateway refused the request (HTTP 422).');
  await noBareCode(page);
});

const OTHER_409S = [
  { name: 'restarting', json: { error: 'restarting', message: 'the gateway is restarting; retry in a moment' }, sentence: 'the gateway is restarting; retry in a moment' },
  { name: 'no reload', json: { error: 'Config reload is not enabled on this gateway' }, sentence: 'Config reload is not enabled on this gateway' },
];

for (const c of OTHER_409S) {
  test(`T21 a 409 ${c.name}: the gateway sentence, the next line naming both buttons, both buttons, and no "undefined"`, async ({ page }) => {
    await screen(page, { save: () => ({ status: 409, json: c.json }) });
    await toConfirm(page);
    await action(page).click();
    await expect(box(page)).toContainText(c.sentence);
    await expect(box(page)).toContainText(NEXT_409);
    await expect(box(page).getByRole('button', { name: 'Reload page' })).toBeVisible();
    await expect(box(page).getByRole('button', { name: 'Close' })).toBeVisible();
    await expect(box(page)).not.toContainText('undefined');
    await box(page).getByRole('button', { name: 'Close' }).click();
    await expect(host(page)).not.toContainText('undefined');
  });
}
