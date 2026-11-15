// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Tools › Status, most-called list: with no view, the screen lists
// the tools called in the last hour, ten at most, highest first, and the change
// against the hour before. An empty hour offers the whole catalogue. Search and
// ?view=all open today's A-to-Z list. The shell document is served as the
// gateway serves it; /ui/api answers are mocked for a signed-in admin.
import { test, expect, WIDTHS, blockingViolations } from './base.mjs';

const HOSTILE = '<img src=x onerror="window.__pwned=1">';

async function toolsScreen(page, { tools, status = 200, hold } = {}) {
  await page.route('**/ui/api/status', (r) => r.fulfill({ json: { auth: { enabled: true, signed_in: true, admin: true } } }));
  await page.route('**/ui/api/tools**', async (r) => {
    if (hold) await hold;
    return status === 200
      ? r.fulfill({ json: { tools, total: tools.length } })
      : r.fulfill({ status, json: { error: 'refused' } });
  });
}

function tool(name, server, calls_1h, calls_prev_1h, description = '') {
  return { name, server, description, calls_1h, calls_prev_1h };
}

const mostCalled = (page) => page.getByRole('region', { name: 'Most called, last hour', exact: true });
const panelRow = (page, name) => mostCalled(page).locator('tbody tr').filter({ has: page.getByRole('link', { name, exact: true }) });
const catalogueRows = (page) => page.locator('#content table.t tbody tr.tool');
const search = (page) => page.getByRole('searchbox', { name: 'Search tools' });

// The catalogue draws a hidden marker ahead of the name. The expected names stay literals.
async function catalogueNames(page) {
  const names = await catalogueRows(page).locator('td:nth-child(1)').allTextContents();
  return names.map((n) => n.replace(/^[▸▾]\s*/, '').trim());
}

// 14 tools with distinct calls, listed lowest first, then 3 that were not called.
// Rank is by calls_1h, so the panel order is the reverse of this list's called tools.
const RANKED = [
  tool('quiet_one', 'alpha', 0, 0),
  tool('quiet_two', 'bravo', 0, 0),
  tool('quiet_three', 'charlie', 0, 0),
  tool('fir', 'alpha', 50, 10),
  tool('holly', 'alpha', 60, 10),
  tool('larch', 'alpha', 70, 10),
  tool('ranked_eleventh', 'alpha', 80, 10),
  tool('yarrow', 'alpha', 90, 10),
  tool('aspen', 'alpha', 100, 10),
  tool('birch', 'alpha', 200, 10),
  tool('cedar', 'alpha', 300, 10),
  tool('maple', 'alpha', 400, 10),
  tool('pebble', 'alpha', 500, 10),
  tool('anchor', 'alpha', 600, 10),
  tool('willow', 'alpha', 700, 10),
  tool('ember', 'alpha', 800, 10),
  tool('quartz', 'alpha', 900, 10),
];

test('M1: landing lists the ten most-called tools, highest first', async ({ page }) => {
  await toolsScreen(page, { tools: RANKED });
  await page.goto('/ui/tools/status');
  await expect(mostCalled(page).locator('tbody tr td:nth-child(1)')).toHaveText([
    'quartz',
    'ember',
    'willow',
    'anchor',
    'pebble',
    'maple',
    'cedar',
    'birch',
    'aspen',
    'yarrow',
  ]);
  await expect(mostCalled(page)).not.toContainText('ranked_eleventh');
  await expect(mostCalled(page)).not.toContainText('quiet_one');
  await expect(mostCalled(page)).not.toContainText('quiet_two');
  await expect(mostCalled(page)).not.toContainText('quiet_three');
});

test('M2: equal counts sort by name, then by server', async ({ page }) => {
  // Insertion order is neither name order nor server order.
  await toolsScreen(page, { tools: [
    tool('bravo', 'zulu', 10, 4),
    tool('alpha', 'zulu', 10, 4),
    tool('bravo', 'alpha', 10, 4),
  ] });
  await page.goto('/ui/tools/status');
  await expect(mostCalled(page).locator('tbody tr td:nth-child(1)')).toHaveText(['alpha', 'bravo', 'bravo']);
  await expect(mostCalled(page).locator('tbody tr td:nth-child(2)')).toHaveText(['zulu', 'alpha', 'zulu']);
});

test('M3: the change against the hour before is the exact text', async ({ page }) => {
  await toolsScreen(page, { tools: [
    tool('up_nine', 'alpha', 109, 100),
    tool('down_two', 'alpha', 98, 100),
    tool('flat', 'alpha', 50, 50),
    tool('round_zero', 'alpha', 1003, 1000),
    tool('fresh', 'alpha', 5, 0),
    tool('doubled', 'alpha', 2, 1),
  ] });
  await page.goto('/ui/tools/status');
  await expect(panelRow(page, 'up_nine').getByRole('cell', { name: '↗ 9% vs hour before', exact: true })).toBeVisible();
  await expect(panelRow(page, 'down_two').getByRole('cell', { name: '↘ 2% vs hour before', exact: true })).toBeVisible();
  await expect(panelRow(page, 'flat').getByRole('cell', { name: '→ no change', exact: true })).toBeVisible();
  await expect(panelRow(page, 'round_zero').getByRole('cell', { name: '→ no change', exact: true })).toBeVisible();
  await expect(panelRow(page, 'fresh').getByRole('cell', { name: 'new this hour', exact: true })).toBeVisible();
  await expect(panelRow(page, 'doubled').getByRole('cell', { name: '↗ 100% vs hour before', exact: true })).toBeVisible();
});

test('M4: call counts render with thousands separators', async ({ page }) => {
  await toolsScreen(page, { tools: [
    tool('many_calls', 'alpha', 1234, 100),
    tool('few_calls', 'alpha', 7, 1),
  ] });
  await page.goto('/ui/tools/status');
  await expect(panelRow(page, 'many_calls').getByRole('cell', { name: '1,234', exact: true })).toBeVisible();
  await expect(panelRow(page, 'few_calls').getByRole('cell', { name: '7', exact: true })).toBeVisible();
});

test('M5: an hour with no calls shows the empty line and the catalogue link', async ({ page }) => {
  const forty = Array.from({ length: 40 }, (_, i) => tool(`quiet_${String(i).padStart(2, '0')}`, 'alpha', 0, 0, 'Unused'));
  await toolsScreen(page, { tools: forty });
  await page.goto('/ui/tools/status');
  const panel = mostCalled(page);
  await expect(panel).toContainText('No tool calls in the last hour.');
  await expect(panel.getByRole('link')).toHaveCount(1);
  await expect(panel.getByRole('link', { name: 'See all 40 tools', exact: true })).toHaveAttribute('href', /\?view=all$/);
  await expect(panel.locator('tr')).toHaveCount(0);
});

test('M6: typing on Status opens the A-to-Z list and keeps every key', async ({ page }) => {
  // bravo_lookup matches by name. catalog_fetch matches by description.
  // delta_ping's server is bravo; today's search does not read the server.
  await toolsScreen(page, { tools: [
    tool('echo_time', 'alpha', 6, 1, 'Tells the time'),
    tool('delta_ping', 'bravo', 7, 1, 'Ping a host'),
    tool('catalog_fetch', 'alpha', 8, 1, 'Reads the bravo index'),
    tool('bravo_lookup', 'alpha', 9, 1, 'Looks up records'),
  ] });
  await page.goto('/ui/tools/status');
  await expect(mostCalled(page)).toBeVisible();
  // Key by key: the first key opens the catalogue, and the keys after it must
  // land in the catalogue's own search box.
  await search(page).click();
  await page.keyboard.type('bravo');
  await expect(page).toHaveURL('/ui/tools/status?view=all');
  await expect(search(page)).toHaveValue('bravo');
  await expect(search(page)).toBeFocused();
  await expect.poll(() => catalogueNames(page)).toEqual(['bravo_lookup', 'catalog_fetch']);
  // One history entry: Back returns to the panel in one step.
  await page.goBack();
  await expect(page).toHaveURL('/ui/tools/status');
  await expect(mostCalled(page)).toBeVisible();

  await page.goto('/ui/tools/status');
  await search(page).press('Enter');
  await expect(page).toHaveURL('/ui/tools/status?view=all');
  await expect.poll(() => catalogueNames(page)).toEqual(['bravo_lookup', 'catalog_fetch', 'delta_ping', 'echo_time']);
});

test('M7: view=all opens the A-to-Z list', async ({ page }) => {
  // Call order is zulu_tool, middle_tool, alpha_tool. Name order is the reverse at both ends.
  await toolsScreen(page, { tools: [
    tool('middle_tool', 'alpha', 50, 1, 'Middle'),
    tool('zulu_tool', 'alpha', 90, 1, 'Last by name'),
    tool('alpha_tool', 'alpha', 10, 1, 'First by name'),
  ] });
  await page.goto('/ui/tools/status?view=all');
  await expect(catalogueRows(page)).toHaveCount(3);
  const names = await catalogueNames(page);
  expect(names[0]).toBe('alpha_tool');
  expect(names[2]).toBe('zulu_tool');
});

test('M8: a most-called name links to the tool page', async ({ page }) => {
  await toolsScreen(page, { tools: [
    tool('alpha_link', 'srv_a', 2, 1),
    tool('beta_link', 'srv_b', 9, 1),
  ] });
  await page.goto('/ui/tools/status');
  await expect(mostCalled(page).getByRole('link', { name: 'beta_link', exact: true })).toHaveAttribute('href', '/ui/tools/srv_b%3Abeta_link/status');
  await expect(mostCalled(page).getByRole('link', { name: 'alpha_link', exact: true })).toHaveAttribute('href', '/ui/tools/srv_a%3Aalpha_link/status');
});

test('M9: a hostile tool name is text', async ({ page }) => {
  await toolsScreen(page, { tools: [tool(HOSTILE, 'alpha', 3, 1, 'Plain')] });
  await page.goto('/ui/tools/status');
  const panel = mostCalled(page);
  await expect(panel.getByRole('link', { name: HOSTILE, exact: true })).toBeVisible();
  await expect(panel.locator('img')).toHaveCount(0);
  expect(await page.evaluate(() => window.__pwned)).toBeUndefined();
});

test('M5b: one tool reads "See all 1 tool"', async ({ page }) => {
  await toolsScreen(page, { tools: [tool('lonely', 'alpha', 0, 0)] });
  await page.goto('/ui/tools/status');
  await expect(mostCalled(page).getByRole('link', { name: 'See all 1 tool', exact: true })).toHaveAttribute('href', /\?view=all$/);
});

test('M11: a panel with rows also links to the whole catalogue', async ({ page }) => {
  await toolsScreen(page, { tools: RANKED });
  await page.goto('/ui/tools/status');
  await expect(mostCalled(page).getByRole('link', { name: 'See all 17 tools', exact: true })).toHaveAttribute('href', /\?view=all$/);
});

test('M12: the panel search starts empty after a catalogue search', async ({ page }) => {
  await toolsScreen(page, { tools: RANKED });
  await page.goto('/ui/tools/status?view=all');
  await search(page).fill('birch');
  // In-app navigation keeps the screen's module state, where a stale query would live.
  await page.locator('nav.route-nav a[data-page="tools"]').click();
  await expect(page).toHaveURL('/ui/tools/status');
  await expect(mostCalled(page)).toBeVisible();
  await expect(search(page)).toHaveValue('');
});

for (const width of WIDTHS) {
  test(`M10: the landing panel passes axe and never scrolls sideways at ${width} px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await toolsScreen(page, { tools: RANKED });
    await page.goto('/ui/tools/status');
    await expect(mostCalled(page).locator('tbody tr')).toHaveCount(10);
    expect(await blockingViolations(page)).toEqual([]);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
    // The table scrolls in its own region, reachable from the keyboard.
    await expect(page.getByRole('region', { name: 'Most called tools', exact: true })).toHaveAttribute('tabindex', '0');
  });
}

test('M13: keys typed while the catalogue reads its tools all land', async ({ page }) => {
  let reads = 0;
  let release;
  const gate = new Promise((ok) => { release = ok; });
  await page.route('**/ui/api/status', (r) => r.fulfill({ json: { auth: { enabled: true, signed_in: true, admin: true } } }));
  await page.route('**/ui/api/tools**', async (r) => {
    reads += 1;
    // A second read, if the catalogue makes one, is held while the user keeps typing.
    if (reads === 2) await gate;
    return r.fulfill({ json: { tools: RANKED, total: RANKED.length } });
  });
  await page.goto('/ui/tools/status');
  await expect(mostCalled(page)).toBeVisible();
  await search(page).click();
  await page.keyboard.type('b');
  await expect(page).toHaveURL('/ui/tools/status?view=all');
  await page.keyboard.type('irch');
  release();
  await expect(search(page)).toHaveValue('birch');
});

test('M14: a count the API did not measure is never shown as a number', async ({ page }) => {
  // null is the API's "not measured", never zero.
  await toolsScreen(page, { tools: [
    { name: 'measured_now', server: 'alpha', description: '', calls_1h: 5, calls_prev_1h: null },
    { name: 'unmeasured_now', server: 'alpha', description: '', calls_1h: null, calls_prev_1h: 3 },
  ] });
  await page.goto('/ui/tools/status');
  await expect(panelRow(page, 'measured_now').getByRole('cell', { name: 'no count for the hour before', exact: true })).toBeVisible();
  await expect(mostCalled(page)).not.toContainText('unmeasured_now');
  await expect(mostCalled(page)).not.toContainText('Infinity');
  await expect(mostCalled(page)).not.toContainText('NaN');
});

test('M15: the palette entry All tools opens the catalogue', async ({ page }) => {
  await toolsScreen(page, { tools: RANKED });
  await page.goto('/ui/tools/status');
  await expect(mostCalled(page)).toBeVisible();
  await page.keyboard.press('Control+KeyK');
  await page.locator('dialog.palette [role="option"]', { hasText: 'All tools' }).click();
  await expect(page).toHaveURL('/ui/tools/status?view=all');
});

test('M16: text still being composed (an input method) does not leave the panel', async ({ page }) => {
  await toolsScreen(page, { tools: RANKED });
  await page.goto('/ui/tools/status');
  await expect(mostCalled(page)).toBeVisible();
  const compose = (data, isComposing) => page.locator('#tools-search').evaluate((el, [d, c]) => {
    el.value = d;
    el.dispatchEvent(new InputEvent('input', { data: d, isComposing: c, inputType: c ? 'insertCompositionText' : 'insertText', bubbles: true }));
  }, [data, isComposing]);
  await page.locator('#tools-search').dispatchEvent('compositionstart');
  await compose('ｂ', true);
  // Two timer turns: the jump is queued on one, so after two it would have run.
  await page.evaluate(() => new Promise((r) => setTimeout(() => setTimeout(r, 0), 0)));
  await expect(page).toHaveURL('/ui/tools/status');
  await page.locator('#tools-search').dispatchEvent('compositionend');
  await compose('b', false);
  await expect(page).toHaveURL('/ui/tools/status?view=all');
});
