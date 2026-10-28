// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The Tools screen, first slice: Tools › Status lists every tool A to Z with
// its server and description, filters by text and server, opens a row to its
// input schema, and opens a tool's own page. The shell document is served as
// the gateway serves it; /ui/api answers are mocked for a signed-in admin.
import { test, expect, WIDTHS, blockingViolations } from './base.mjs';
import { shellReady } from './shell.mjs';

// ponytail: the same check is shared from base.mjs once the classic keyboard
// work lands on this line; then this copy goes.
async function scrollsFromKeyboard(page, { from, region, key, axis }) {
  const overflows = (el, a) => (a === 'x' ? el.scrollWidth > el.clientWidth : el.scrollHeight > el.clientHeight);
  expect(await region.evaluate(overflows, axis)).toBe(true);
  await from.focus();
  await page.keyboard.press('Tab');
  await expect(region).toBeFocused();
  await page.keyboard.press(key);
  await expect.poll(() => region.evaluate((el, a) => (a === 'x' ? el.scrollLeft : el.scrollTop), axis)).toBeGreaterThan(0);
}

const SERVERS = ['alpha', 'bravo', 'charlie', 'delta'];
// 40 tools, 10 per server, named so A-to-Z order differs from server order.
const TOOLS = SERVERS.flatMap((server, s) => Array.from({ length: 10 }, (_, i) => ({
  name: `${String.fromCharCode(106 - i)}_${server}_tool`,
  server,
  description: `Does thing ${i} on ${server}`,
  schema: { type: 'object', properties: Object.fromEntries(Array.from({ length: 30 }, (_, k) => [`field_${k}`, { type: 'string' }])) },
  class: i % 2 ? 'write' : 'read',
  class_source: i % 3 ? 'inferred' : 'declared',
})));
const HOSTILE = '<img src=x onerror="window.__pwned=1">';
TOOLS[0].description = HOSTILE;

async function toolsScreen(page, { tools = TOOLS, status = 200 } = {}) {
  await page.route('**/ui/api/status', (r) => r.fulfill({ json: { auth: { enabled: true, signed_in: true, admin: true } } }));
  await page.route('**/ui/api/tools**', (r) => (status === 200
    ? r.fulfill({ json: { tools, total: tools.length } })
    : r.fulfill({ status, json: { error: 'refused' } })));
}

const sorted = [...TOOLS].sort((a, b) => a.name.localeCompare(b.name) || a.server.localeCompare(b.server));
const rows = (page) => page.locator('#content table.t tbody tr.tool');
const search = (page) => page.getByRole('searchbox', { name: 'Search tools' });
const server = (page) => page.getByRole('combobox', { name: 'Server' });

test('T1: /ui/tools lands on Status with no Actions or Settings tab, and counts tools and servers', async ({ page }) => {
  await toolsScreen(page);
  await page.goto('/ui/tools');
  await shellReady(page);
  await expect(page).toHaveURL('/ui/tools/status');
  await expect(page.locator('nav.tabs a')).toHaveText(['Status']);
  await expect(page.locator('.head .sub')).toHaveText('40 tools from 4 servers. Agents find them through search and invoke.');
});

test('T2: every tool is listed A to Z with its server and description', async ({ page }) => {
  await toolsScreen(page);
  await page.goto('/ui/tools/status');
  await expect(rows(page)).toHaveCount(40);
  const names = await rows(page).locator('td:nth-child(1)').allTextContents();
  expect(names.map((n) => n.trim())).toEqual(sorted.map((t) => t.name));
  await expect(rows(page).first().locator('td:nth-child(2)')).toHaveText(sorted[0].server);
  await expect(page.locator('#content')).toContainText('40 tools · A to Z');
});

test('T3: search and the server filter narrow the list, together and apart', async ({ page }) => {
  await toolsScreen(page);
  await page.goto('/ui/tools/status');
  await search(page).fill('thing 3');
  await expect(rows(page)).toHaveCount(4);
  await search(page).fill('j_alpha');
  await expect(rows(page)).toHaveCount(1);
  await search(page).fill('');
  await server(page).selectOption('bravo');
  await expect(rows(page)).toHaveCount(10);
  await search(page).fill('thing 3');
  await expect(rows(page)).toHaveCount(1);
  await expect(page.locator('#content')).toContainText('1 of 40 match');
  await search(page).fill('nothing matches this');
  await expect(page.locator('#content')).toContainText('No tool matches');
  await page.getByRole('button', { name: 'Clear filters' }).click();
  await expect(rows(page)).toHaveCount(40);
  await expect(server(page)).toHaveValue('');
});

test('T4: a tool name opens its detail, and the schema scrolls from the keyboard', async ({ page }) => {
  await toolsScreen(page);
  await page.goto('/ui/tools/status');
  const toggle = page.getByRole('button', { name: sorted[0].name, exact: true });
  await expect(toggle).toHaveAttribute('aria-expanded', 'false');
  await toggle.focus();
  await page.keyboard.press('Enter');
  await expect(toggle).toHaveAttribute('aria-expanded', 'true');
  const schema = page.getByRole('region', { name: `Input schema of ${sorted[0].name}` });
  await expect(schema).toBeVisible();
  await expect(page.locator('#content')).toContainText(sorted[0].class === 'read' ? 'read' : 'write');
  await scrollsFromKeyboard(page, { from: toggle, region: schema, key: 'ArrowDown', axis: 'y' });
  await toggle.click();
  await expect(toggle).toHaveAttribute('aria-expanded', 'false');
  await expect(schema).toBeHidden();
});

test('T5: Open goes to the tool page, and an unknown tool says so', async ({ page }) => {
  await toolsScreen(page);
  await page.goto('/ui/tools/status');
  const t = sorted[3];
  await page.getByRole('button', { name: t.name, exact: true }).click();
  await page.getByRole('link', { name: `Open ${t.name}` }).click();
  await expect(page).toHaveURL(`/ui/tools/${encodeURIComponent(`${t.server}:${t.name}`)}/status`);
  await expect(page.locator('.head .plate')).toHaveText(t.name);
  await expect(page.locator('#content')).toContainText(t.server);
  await expect(page.locator('#content')).toContainText(t.description);
  await expect(page.getByRole('region', { name: `Input schema of ${t.name}` })).toBeVisible();
  await page.getByRole('link', { name: 'Back to all tools' }).click();
  await expect(page).toHaveURL('/ui/tools/status');
  await page.goto(`/ui/tools/${encodeURIComponent('alpha:no_such_tool')}/status`);
  await expect(page.locator('#content')).toContainText('No such tool');
});

test('T6: markup in a tool description renders as text', async ({ page }) => {
  await toolsScreen(page);
  await page.goto('/ui/tools/status');
  await expect(rows(page)).toHaveCount(40);
  await expect(page.locator('#content img')).toHaveCount(0);
  await expect(page.locator('#content')).toContainText(HOSTILE);
  expect(await page.evaluate(() => window.__pwned)).toBeUndefined();
});

test('T8: an empty gateway, and a key without access', async ({ page }) => {
  await toolsScreen(page, { tools: [] });
  await page.goto('/ui/tools/status');
  await expect(page.locator('#content')).toContainText('No tools yet. Add a server and its tools appear here.');
  await page.unrouteAll({ behavior: 'ignoreErrors' });
  await toolsScreen(page, { status: 403 });
  await page.goto('/ui/tools/status');
  await expect(page.locator('#content [data-state="forbidden"]')).toBeVisible();
});

test('T10: the journey from the sidebar to a tool and back', async ({ page }) => {
  await toolsScreen(page);
  await page.goto('/ui/overview');
  await shellReady(page);
  await page.locator('nav.route-nav a[data-page="tools"]').click();
  await expect(page).toHaveURL('/ui/tools/status');
  await search(page).fill('j_charlie');
  await page.getByRole('button', { name: 'j_charlie_tool', exact: true }).click();
  await page.getByRole('link', { name: 'Open j_charlie_tool' }).click();
  await expect(page.locator('.head .plate')).toHaveText('j_charlie_tool');
  await page.goBack();
  await expect(page).toHaveURL('/ui/tools/status');
  await expect(rows(page).first()).toBeVisible();
});

for (const width of WIDTHS) {
  test(`T7: axe finds no blocking violation on the list, an open row and a tool page at ${width} px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await toolsScreen(page);
    await page.goto('/ui/tools/status');
    await expect(rows(page)).toHaveCount(40);
    expect(await blockingViolations(page)).toEqual([]);
    await page.getByRole('button', { name: sorted[0].name, exact: true }).click();
    expect(await blockingViolations(page)).toEqual([]);
    await page.goto(`/ui/tools/${encodeURIComponent(`${sorted[0].server}:${sorted[0].name}`)}/status`);
    await expect(page.locator('.head .plate')).toHaveText(sorted[0].name);
    expect(await blockingViolations(page)).toEqual([]);
  });
}
