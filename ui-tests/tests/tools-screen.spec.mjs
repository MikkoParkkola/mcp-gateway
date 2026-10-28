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
  // Long enough to overflow its pane even on one line.
  schema: { type: 'object', properties: Object.fromEntries(Array.from({ length: 120 }, (_, k) => [`field_${k}`, { type: 'string', description: `Field number ${k}` }])) },
  class: i % 2 ? 'write' : 'read',
  class_source: i % 3 ? 'inferred' : 'declared',
})));
const HOSTILE = '<img src=x onerror="window.__pwned=1">';
TOOLS[0].description = HOSTILE;
TOOLS[1].schema = { type: 'object', description: HOSTILE, properties: { q: { type: 'string', description: HOSTILE } } };
TOOLS[2].description = null;

async function toolsScreen(page, { tools = TOOLS, status = 200, hold } = {}) {
  await page.route('**/ui/api/status', (r) => r.fulfill({ json: { auth: { enabled: true, signed_in: true, admin: true } } }));
  await page.route('**/ui/api/tools**', async (r) => {
    if (hold) await hold;
    return status === 200
      ? r.fulfill({ json: { tools, total: tools.length } })
      : r.fulfill({ status, json: { error: 'refused' } });
  });
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
  // The open marker is a hidden span ahead of the name.
  expect(names.map((n) => n.replace(/^[▸▾]\s*/, '').trim())).toEqual(sorted.map((t) => t.name));
  await expect(rows(page).first().locator('td:nth-child(2)')).toHaveText(sorted[0].server);
  await expect(page.locator('#content')).toContainText('40 · A to Z · name, server, description');
  // The no-match panel is hidden whenever tools match.
  await expect(page.getByText('No tool matches')).toBeHidden();
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
  // The open row names the tool's class and where it came from.
  const want = { read: { declared: 'read (declared)', inferred: 'read (guessed from the name)' },
    write: { declared: 'write (declared)', inferred: 'write (guessed from the name)' } }[sorted[0].class][sorted[0].class_source];
  await expect(page.locator(`#${await toggle.getAttribute('aria-controls')}`)).toContainText(want);
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
  await expect(page).toHaveTitle(`${t.name} · MCP Gateway`);
  await expect(page.getByRole('heading', { level: 2, name: t.name, exact: true })).toBeVisible();
  await expect(page.locator('#content')).toContainText(t.server);
  await expect(page.locator('#content')).toContainText(t.description);
  await expect(page.getByRole('region', { name: `Input schema of ${t.name}` })).toBeVisible();
  const word = `${t.class} (${t.class_source === 'declared' ? 'declared' : 'guessed from the name'})`;
  await expect(page.locator('.tool-facts')).toContainText(word);
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
  // Inside a schema too, and a null description reads as none.
  const withSchema = TOOLS[1];
  await page.getByRole('button', { name: withSchema.name, exact: true }).click();
  // The schema shows as JSON, so the markup's own quotes come out escaped.
  await expect(page.getByRole('region', { name: `Input schema of ${withSchema.name}` })).toContainText('<img src=x onerror=');
  await expect(page.locator('#content img')).toHaveCount(0);
  expect(await page.evaluate(() => window.__pwned)).toBeUndefined();
  // A null description is an empty cell, never the word null.
  const nullRow = rows(page).filter({ has: page.getByRole('button', { name: TOOLS[2].name, exact: true }) });
  await expect(nullRow.locator('td:nth-child(3)')).toHaveText('');
  await expect(page.locator('#content')).not.toContainText('null');
});

test('T6b: markup in a tool name and a server name stays text, in labels and links too', async ({ page }) => {
  const name = 'x"><img src=x onerror="window.__pwned=1">';
  const server = 'srv<img src=x onerror="window.__pwned=2">';
  await toolsScreen(page, { tools: [{ name, server, description: 'Hostile names', schema: {}, class: 'read', class_source: 'declared' }] });
  await page.goto('/ui/tools/status');
  const toggle = page.getByRole('button', { name, exact: true });
  await expect(toggle).toBeVisible();
  await expect(page.locator('#content img')).toHaveCount(0);
  await toggle.click();
  await page.getByRole('link', { name: `Open ${name}` }).click();
  await expect(page).toHaveURL(`/ui/tools/${encodeURIComponent(`${server}:${name}`)}/status`);
  await expect(page.getByRole('heading', { level: 2, name, exact: true })).toBeVisible();
  await expect(page.locator('#content img, .head img')).toHaveCount(0);
  expect(await page.evaluate(() => window.__pwned)).toBeUndefined();
});

test.describe('on a touch screen', () => {
  test.use({ hasTouch: true, isMobile: true, viewport: { width: 390, height: 844 } });
  test('T18: a tool name is a full touch target', async ({ page }) => {
    await toolsScreen(page);
    await page.goto('/ui/tools/status');
    const box = await page.getByRole('button', { name: sorted[0].name, exact: true }).boundingBox();
    expect(box.height).toBeGreaterThanOrEqual(44);
  });
});

test('T11: Enter and Space each toggle a tool once', async ({ page }) => {
  await toolsScreen(page);
  await page.goto('/ui/tools/status');
  const toggle = page.getByRole('button', { name: sorted[0].name, exact: true });
  await toggle.focus();
  for (const [key, open] of [['Enter', true], ['Space', false], ['Space', true], ['Enter', false]]) {
    await page.keyboard.press(key);
    await expect(toggle, key).toHaveAttribute('aria-expanded', String(open));
  }
});

test('T12: the same tool name on two servers opens the right one', async ({ page }) => {
  const twins = [
    { name: 'search', server: 'web', description: 'Search the web', schema: {}, class: 'read', class_source: 'declared' },
    { name: 'search', server: 'docs', description: 'Search the docs', schema: {}, class: 'read', class_source: 'declared' },
  ];
  await toolsScreen(page, { tools: twins });
  await page.goto('/ui/tools/status');
  await expect(rows(page)).toHaveCount(2);
  await expect(rows(page).nth(0).locator('td:nth-child(2)')).toHaveText('docs');
  await page.getByRole('button', { name: 'search', exact: true }).nth(1).click();
  // Only the open row's link is visible.
  await page.getByRole('link', { name: 'Open search' }).click();
  await expect(page).toHaveURL(`/ui/tools/${encodeURIComponent('web:search')}/status`);
  await expect(page.locator('#content')).toContainText('Search the web');
});

test('T13: a tool page loads directly from its address', async ({ page }) => {
  await toolsScreen(page);
  const t = sorted[7];
  await page.goto(`/ui/tools/${encodeURIComponent(`${t.server}:${t.name}`)}/status`);
  await shellReady(page);
  await expect(page.getByRole('heading', { level: 2, name: t.name, exact: true })).toBeVisible();
  await expect(page.locator('#content')).toContainText(t.description);
});

test('T14: a late answer after leaving the page changes nothing', async ({ page }) => {
  let release;
  const hold = new Promise((r) => { release = r; });
  await toolsScreen(page, { hold });
  await page.goto('/ui/tools/status');
  await page.locator('nav.route-nav a[data-page="servers"]').click();
  await expect(page).toHaveURL(/\/ui\/servers/);
  const sub = await page.locator('.head .sub').textContent();
  release();
  await page.waitForTimeout(300);
  await expect(page.locator('.head .plate')).toHaveText('Servers');
  expect(await page.locator('.head .sub').textContent()).toBe(sub);
  await expect(rows(page)).toHaveCount(0);
});

test('T15: about 1,300 tools render and filter within budget', async ({ page }) => {
  const many = Array.from({ length: 1300 }, (_, i) => ({
    name: `tool_${String(i).padStart(4, '0')}`,
    server: `server_${i % 28}`,
    description: `Does thing number ${i} with a description of ordinary length`,
    schema: { type: 'object', properties: Object.fromEntries(Array.from({ length: 6 }, (_, k) => [`p${k}`, { type: 'string', description: `Parameter ${k}` }])) },
    class: i % 2 ? 'write' : 'read',
    class_source: 'inferred',
  }));
  await toolsScreen(page, { tools: many });
  const start = Date.now();
  await page.goto('/ui/tools/status');
  await expect(rows(page)).toHaveCount(1300);
  const rendered = Date.now() - start;
  const t0 = Date.now();
  await search(page).fill('tool_1299');
  await expect(rows(page)).toHaveCount(1);
  const filtered = Date.now() - t0;
  // A broad query, then clearing it: the full list is drawn again.
  const t1 = Date.now();
  await search(page).fill('tool_');
  await expect(rows(page)).toHaveCount(1300);
  await search(page).fill('');
  await expect(rows(page)).toHaveCount(1300);
  const redrawn = Date.now() - t1;
  console.log(`T15: broad query and clear redrawn in ${redrawn} ms`);
  expect(redrawn).toBeLessThan(3000);
  console.log(`T15: 1,300 tools rendered in ${rendered} ms, filtered in ${filtered} ms`);
  // Generous ceilings for a loaded CI runner; the printed numbers go in the PR.
  expect(rendered).toBeLessThan(4000);
  expect(filtered).toBeLessThan(1000);
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
  await expect(page.getByRole('heading', { level: 2, name: 'j_charlie_tool', exact: true })).toBeVisible();
  await page.goBack();
  await expect(page).toHaveURL('/ui/tools/status');
  // The search survives the visit, as it did on the classic tab.
  await expect(search(page)).toHaveValue('j_charlie');
  await expect(rows(page)).toHaveCount(1);
});

test('T16: on a phone the page never scrolls sideways; the table scrolls in its own region', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await toolsScreen(page);
  await page.goto('/ui/tools/status');
  await expect(rows(page)).toHaveCount(40);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
  const region = page.getByRole('region', { name: 'Tool list' });
  await expect(region).toHaveAttribute('tabindex', '0');
});

for (const scheme of ['light', 'dark']) {
  test(`T17: axe finds no blocking violation in the ${scheme} theme`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await toolsScreen(page);
    await page.goto('/ui/tools/status');
    await expect(rows(page)).toHaveCount(40);
    await page.getByRole('button', { name: sorted[0].name, exact: true }).click();
    expect(await blockingViolations(page)).toEqual([]);
  });
}

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
    await expect(page.getByRole('heading', { level: 2, name: sorted[0].name, exact: true })).toBeVisible();
    expect(await blockingViolations(page)).toEqual([]);
  });
}
