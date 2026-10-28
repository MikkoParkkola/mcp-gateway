// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The classic page's Add Server form, previewing a server's tools and adding
// it with only the ticked ones. The real page (src/gateway/ui/index.html) is
// served at /ui/classic the way the gateway serves it: no CSP, no-store. Its
// /ui/api calls are answered here, and every add body is recorded.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, expect, WIDTHS, blockingViolations } from './base.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const INDEX = readFileSync(join(HERE, '..', '..', 'src', 'gateway', 'ui', 'index.html'), 'utf8');

const URL_SERVER = 'https://tools.example.test/mcp';

const DESCRIBED = {
  transport: 'http',
  url: URL_SERVER,
  withheld: { env: [], headers: [], oauth: false, secrets: 0, identity_propagation: false, account: false },
  publisher: { verified: false, source: null },
};

const TOOLS = [
  { name: 'read_a', description: 'Reads a thing', class: 'read', class_source: 'declared', destructive: false, selectable: true },
  { name: 'write_b', description: 'Writes a thing', class: 'write', class_source: 'inferred', destructive: true, selectable: true },
  { name: 'odd*', description: 'A name the gateway will not call', class: 'read', class_source: 'declared', destructive: false, selectable: false },
];

/**
 * Serve the real classic page with a mocked API. `tools`, `describe` and
 * `confirm` override the preview answers (a `confirm` hook that resolves to
 * anything but `true` falls through to the listing); `described` replaces the
 * describe step's preview block and `listing` adds `preview` fields and
 * `withheld_tools` to the listing; `seen.answered` counts confirmed answers; the returned object records every
 * request.
 */
async function classicPage(page, { tools = TOOLS, describe, confirm, described = DESCRIBED, listing = {} } = {}) {
  const seen = { adds: [], previews: [], answered: 0 };
  await page.route('**/ui/classic', (route) => route.fulfill({
    status: 200,
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-cache, no-store, must-revalidate' },
    body: INDEX,
  }));
  await page.route('**/ui/api/**', async (route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname;
    // Resolves to true once answered, so a hook can tell it from "not mine".
    const json = (status, body) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) }).then(() => true);
    if (path === '/ui/api/status') {
      return json(200, { auth: { enabled: true, signed_in: true, admin: true }, servers: [], server_count: 0, tool_count: 0, version: 'test' });
    }
    if (path === '/ui/api/registry') return json(200, { servers: [] });
    if (path === '/ui/api/previews' && req.method() === 'POST') {
      const body = req.postDataJSON();
      seen.previews.push(body);
      if (!body.confirm) return describe ? describe(json, body) : json(202, { confirm: 'tok-1', preview: described });
      if (confirm) {
        const answered = await confirm(json, body);
        if (answered) { seen.answered++; return; }
      }
      await json(200, { preview: { ...described, stopped: true, truncated: false, elapsed_ms: 5, ...listing.preview }, tools, withheld_tools: listing.withheld_tools ?? [] });
      seen.answered++;
      return;
    }
    if (path === '/ui/api/backends' && req.method() === 'POST') {
      seen.adds.push(req.postDataJSON());
      return json(201, { name: 'tools', enabled: true, notes: [] });
    }
    return json(200, {});
  });
  await page.goto('/ui/classic#servers');
  await page.getByRole('button', { name: '+ Add Server' }).click();
  await page.locator('#mode-custom').click();
  await page.locator('#custom-name').fill('tools');
  await page.locator('#custom-transport').selectOption('http');
  await page.locator('#custom-url').fill(URL_SERVER);
  return seen;
}

/** Preview, confirm, and wait for the tool list. */
async function preview(page) {
  await page.getByRole('button', { name: 'Preview tools' }).click();
  await page.getByRole('button', { name: 'Start preview' }).click();
  await expect(page.locator('input[data-tool="read_a"]')).toBeVisible();
}

const tick = (page, name) => page.locator(`input[data-tool="${name}"]`);
const add = (page) => page.locator('#add-server-form').getByRole('button', { name: 'Add Server', exact: true }).click();
const msg = (page) => page.locator('#add-server-msg');

test('P1: read tools start ticked, write tools unticked, an unselectable one disabled; Add sends the ticked ones', async ({ page }) => {
  const seen = await classicPage(page);
  await preview(page);
  await expect(tick(page, 'read_a')).toBeChecked();
  await expect(tick(page, 'write_b')).not.toBeChecked();
  await expect(tick(page, 'odd*')).toBeDisabled();
  await expect(tick(page, 'odd*')).not.toBeChecked();
  // The describe step's confirmation is what the start sends.
  expect(seen.previews.map((b) => b.confirm ?? null)).toEqual([null, 'tok-1']);
  expect(seen.previews[0]).toMatchObject({ name: 'tools', url: URL_SERVER });
  await add(page);
  await expect.poll(() => seen.adds.length).toBe(1);
  expect(seen.adds[0]).toEqual({ name: 'tools', url: URL_SERVER, allowed_tools: ['read_a'] });
});

test('P2: the user’s own ticks are what Add sends', async ({ page }) => {
  const seen = await classicPage(page);
  await preview(page);
  await tick(page, 'write_b').check();
  await tick(page, 'read_a').uncheck();
  await add(page);
  await expect.poll(() => seen.adds.length).toBe(1);
  expect(seen.adds[0].allowed_tools).toEqual(['write_b']);
});

test('P3: without a preview, Add sends no allowed_tools', async ({ page }) => {
  const seen = await classicPage(page);
  await add(page);
  await expect.poll(() => seen.adds.length).toBe(1);
  expect(seen.adds[0]).toEqual({ name: 'tools', url: URL_SERVER });
});

test('P4: editing the URL after a preview refuses Add', async ({ page }) => {
  const seen = await classicPage(page);
  await preview(page);
  await page.locator('#custom-url').fill('https://other.example.test/mcp');
  await add(page);
  await expect(msg(page)).toContainText('The form changed since the preview');
  expect(seen.adds).toEqual([]);
});

test('P4b: removing an env row after a preview refuses Add', async ({ page }) => {
  const seen = await classicPage(page);
  await page.locator('#server-custom-fields').getByRole('button', { name: '+ Add' }).click();
  const row = page.locator('#env-rows .env-row').first();
  await row.locator('input').nth(0).fill('REGION');
  await row.locator('input').nth(1).fill('eu');
  await preview(page);
  await row.getByRole('button', { name: 'Remove variable' }).click();
  await add(page);
  await expect(msg(page)).toContainText('The form changed since the preview');
  expect(seen.adds).toEqual([]);
});

test('P4c: after Clear preview, Add sends every tool again', async ({ page }) => {
  const seen = await classicPage(page);
  await preview(page);
  await page.getByRole('button', { name: 'Clear preview' }).click();
  await expect(tick(page, 'read_a')).toHaveCount(0);
  await add(page);
  await expect.poll(() => seen.adds.length).toBe(1);
  expect(seen.adds[0]).not.toHaveProperty('allowed_tools');
});

test('P5: with nothing ticked, Add is refused and nothing is sent', async ({ page }) => {
  const seen = await classicPage(page);
  await preview(page);
  await tick(page, 'read_a').uncheck();
  await add(page);
  await expect(msg(page)).toContainText('Tick at least one tool');
  expect(seen.adds).toEqual([]);
});

test('P6: a tool name or description with markup renders as text', async ({ page }) => {
  const hostile = '<img src=x onerror="window.__pwned=1">';
  const quoted = 'q" onfocus="window.__pwned=1';
  const tools = [{ ...TOOLS[0], name: 'read_a', description: hostile }, { ...TOOLS[1], name: `w${hostile}` }, { ...TOOLS[1], name: quoted }];
  const dialogs = [];
  page.on('dialog', (d) => { dialogs.push(d.message()); d.dismiss(); });
  const seen = await classicPage(page, { tools });
  await preview(page);
  await expect(page.locator('#add-preview img')).toHaveCount(0);
  await expect(page.locator('#add-preview [onfocus]')).toHaveCount(0);
  expect(await page.evaluate(() => window.__pwned)).toBeUndefined();
  await expect(page.locator('#add-server-form')).toContainText(hostile);
  await page.locator(`input[data-tool="w${hostile.replaceAll('"', '\\"')}"]`).check();
  await add(page);
  await expect.poll(() => seen.adds.length).toBe(1);
  expect(seen.adds[0].allowed_tools).toEqual(['read_a', `w${hostile}`]);
  expect(dialogs).toEqual([]);
});

test('P1b: nothing is started before Start preview, and a spent confirmation installs no list', async ({ page }) => {
  let confirmAnswer = (json) => json(409, { error: 'the confirmation is invalid, expired or spent' });
  const seen = await classicPage(page, {
    confirm: (json) => (confirmAnswer ? confirmAnswer(json) : null),
  });
  await page.getByRole('button', { name: 'Preview tools' }).click();
  await expect(page.getByRole('button', { name: 'Start preview' })).toBeVisible();
  expect(seen.previews.map((b) => b.confirm ?? null)).toEqual([null]);
  await page.getByRole('button', { name: 'Start preview' }).click();
  await expect(msg(page)).toContainText('the confirmation is invalid, expired or spent');
  await expect(tick(page, 'read_a')).toHaveCount(0);
  // A spent confirmation leaves no dead Start button behind.
  await expect(page.getByRole('button', { name: 'Start preview' })).toHaveCount(0);
  confirmAnswer = null;
  await preview(page);
  await expect(tick(page, 'read_a')).toBeChecked();
});

test('P8: with every tool ticked, Add still sends the list', async ({ page }) => {
  const seen = await classicPage(page);
  await preview(page);
  await tick(page, 'write_b').check();
  await add(page);
  await expect.poll(() => seen.adds.length).toBe(1);
  expect(seen.adds[0].allowed_tools).toEqual(['read_a', 'write_b']);
});

test('P9: a repeated name is one checkbox, unticked when any copy is write', async ({ page }) => {
  const tools = [TOOLS[0], { ...TOOLS[1], name: 'read_a', description: 'Second copy' }];
  await classicPage(page, { tools });
  await page.getByRole('button', { name: 'Preview tools' }).click();
  await page.getByRole('button', { name: 'Start preview' }).click();
  await expect(tick(page, 'read_a')).toHaveCount(1);
  await expect(tick(page, 'read_a')).not.toBeChecked();
  await expect(page.locator('#add-server-form')).toContainText('Second copy');
});

test('P10: a preview overtaken by Clear preview installs nothing when it answers', async ({ page }) => {
  let release;
  const held = new Promise((r) => { release = r; });
  const seen = await classicPage(page, { confirm: async (json) => { await held; return null; } });
  await page.getByRole('button', { name: 'Preview tools' }).click();
  await page.getByRole('button', { name: 'Start preview' }).click();
  await expect.poll(() => seen.previews.length).toBe(2);
  await page.getByRole('button', { name: 'Clear preview' }).click();
  const late = page.waitForResponse((r) => r.url().endsWith('/ui/api/previews') && !!r.request().postDataJSON()?.confirm);
  release();
  await late;
  await expect.poll(() => seen.answered).toBe(1);
  // Past the page's own handling of the late answer: two frames.
  await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
  await expect(tick(page, 'read_a')).toHaveCount(0);
  await add(page);
  await expect.poll(() => seen.adds.length).toBe(1);
  expect(seen.adds[0]).not.toHaveProperty('allowed_tools');
});

test('P11: a cut-short listing refuses Add', async ({ page }) => {
  const seen = await classicPage(page, { listing: { preview: { truncated: true } } });
  await preview(page);
  await expect(page.locator('#add-preview')).toContainText('The list is incomplete');
  await add(page);
  await expect(msg(page)).toContainText('The preview list is incomplete');
  expect(seen.adds).toEqual([]);
});

test('P12: Cancel and reopen leaves no listing in force', async ({ page }) => {
  const seen = await classicPage(page);
  await preview(page);
  await page.locator('#add-server-form').getByRole('button', { name: 'Cancel' }).click();
  await page.getByRole('button', { name: '+ Add Server' }).click();
  await expect(page.locator('#add-preview input[data-tool]')).toHaveCount(0);
  await page.locator('#mode-custom').click();
  await page.locator('#custom-name').fill('tools');
  await page.locator('#custom-transport').selectOption('http');
  await page.locator('#custom-url').fill(URL_SERVER);
  await add(page);
  await expect.poll(() => seen.adds.length).toBe(1);
  expect(seen.adds[0]).not.toHaveProperty('allowed_tools');
});

test('P6b: markup in the describe step and in withheld tools renders as text', async ({ page }) => {
  const hostile = '<img src=x onerror="window.__pwned=1">';
  const quoted = 'q" onfocus="window.__pwned=1';
  const described = {
    ...DESCRIBED,
    url: `https://tools.example.test/${hostile}`,
    withheld: { ...DESCRIBED.withheld, env: [quoted], headers: [hostile] },
  };
  const listing = { withheld_tools: [{ name: hostile, issues: [quoted] }] };
  await classicPage(page, { described, listing });
  await page.getByRole('button', { name: 'Preview tools' }).click();
  await expect(page.locator('#add-preview')).toContainText(`env ${quoted}`);
  await page.getByRole('button', { name: 'Start preview' }).click();
  await expect(page.locator('#add-preview')).toContainText(`Not offered: ${hostile} (${quoted})`);
  await expect(page.locator('#add-preview img')).toHaveCount(0);
  await expect(page.locator('#add-preview [onfocus], #add-preview [onerror]')).toHaveCount(0);
  expect(await page.evaluate(() => window.__pwned)).toBeUndefined();
});

test('P13: Preview tools is off while a start runs, so the listing it brings is kept', async ({ page }) => {
  let release;
  const held = new Promise((r) => { release = r; });
  await classicPage(page, { confirm: async () => { await held; return null; } });
  await page.getByRole('button', { name: 'Preview tools' }).click();
  await page.getByRole('button', { name: 'Start preview' }).click();
  await expect(page.getByRole('button', { name: 'Preview tools' })).toBeDisabled();
  // Nor Add: it would save every tool while the operator waits for the list.
  await expect(page.locator('#add-server-btn')).toBeDisabled();
  release();
  await expect(tick(page, 'read_a')).toBeChecked();
  await expect(page.getByRole('button', { name: 'Preview tools' })).toBeEnabled();
  await expect(page.locator('#add-server-btn')).toBeEnabled();
  // The focused Start button is gone; focus moves to the first tick.
  await expect(tick(page, 'read_a')).toBeFocused();
});

test('P7: a refused preview shows the server’s reason, and Add still works without a selection', async ({ page }) => {
  const reason = 'a command server cannot be previewed until the preview sandbox exists';
  const seen = await classicPage(page, { describe: (json) => json(422, { error: reason }) });
  await page.getByRole('button', { name: 'Preview tools' }).click();
  await expect(msg(page)).toContainText(reason);
  await expect(page.getByRole('button', { name: 'Start preview' })).toHaveCount(0);
  await add(page);
  await expect.poll(() => seen.adds.length).toBe(1);
  expect(seen.adds[0]).not.toHaveProperty('allowed_tools');
});

for (const width of WIDTHS) {
  test(`axe finds no blocking violation in the open tool list at ${width} px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await classicPage(page);
    await preview(page);
    // The panel only: the rest of the form's findings predate this change.
    expect(await blockingViolations(page, '#add-preview')).toEqual([]);
  });
}
