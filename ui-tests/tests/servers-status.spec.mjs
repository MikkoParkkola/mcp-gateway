// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Pinned behaviour of Servers › Status: which of four
// screens shows, how servers group, what each row says, and how many reads
// a refresh may cost. The gateway is faked per test with page.route; the
// shell's own boot read of /ui/api/status is answered apart and not counted.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { test, expect, blockingViolations, WIDTHS } from './base.mjs';
import { countListeners, shellReady, tooltipCoversNothing } from './shell.mjs';
import { readCopy, readScreens, scanScreens } from './copy-check.mjs';

// ------------------------------------------------------------ fake gateway

const json = (code, body) => ({ code, body });
const DROP = { drop: true };
const srv = (name, state, more = {}) => ({
  name, state, reason: '', next_retry_at: null, tools_cached: 4, calls_24h: 12, latency_p95_ms: 200, ...more,
});
const fullView = (...servers) => json(200, { server_count: servers.length, servers });
// The redacted shape: counts, and no servers member at all.
const countsView = () => json(200, { server_count: 2, healthy_count: 2, degraded_count: 0 });

/**
 * Route the three reads. `status` is a list of answers taken in turn by the
 * screen's reads, the last one repeating; registry and discovery each give one
 * answer every time. An answer may carry `hold`, a promise the reply waits on.
 * Returns live counters of the screen's reads.
 */
async function fakeGateway(page, { status, registry = REGISTRY, discovery = json(200, { servers: [] }) }) {
  const reads = { status: 0, registry: 0, discovery: 0 };
  const queue = [...status];
  let bootDone = false;
  const answer = async (route, a) => {
    if (a.hold) await a.hold;
    if (a.drop) return route.abort('failed');
    return route.fulfill({ status: a.code, contentType: 'application/json', body: JSON.stringify(a.body) });
  };
  await page.route('**/ui/api/status', (route) => {
    if (!bootDone) {
      bootDone = true;
      return route.fulfill({ status: 200, contentType: 'application/json', body: '{}' });
    }
    reads.status += 1;
    return answer(route, queue.length > 1 ? queue.shift() : queue[0]);
  });
  await page.route('**/ui/api/registry', (route) => { reads.registry += 1; return answer(route, registry); });
  await page.route('**/ui/api/discovery', (route) => { reads.discovery += 1; return answer(route, discovery); });
  return reads;
}

/** A promise the test opens by hand, for holding one reply. */
function gate() {
  let open;
  const shut = new Promise((ok) => { open = ok; });
  return { shut, open };
}

/** What the live stream does on a status frame: tell the screens. */
const statusEvent = (page) => page.evaluate(() => window.dispatchEvent(new CustomEvent('gateway-status', { detail: {} })));

async function openScreen(page, query = '') {
  await page.goto(`/ui/servers/status${query}`);
  await shellReady(page);
}

const content = (page) => page.locator('#content');
const block = (page, start) => page.getByRole('region', { name: new RegExp(`^${start} · \\d+`) });
const statusRow = (scope, name) => scope.locator('tr').filter({ has: scope.page().getByRole('rowheader', { name, exact: true }) });
const groupButton = (page, label) => block(page, 'Answering').getByRole('button', { name: label, exact: true });
// Group toggles sit in row headers; the tooltip triggers in column headings are buttons too.
const groupButtons = (page) => block(page, 'Answering').getByRole('rowheader').getByRole('button');
const groupRow = (page, label) => block(page, 'Answering').locator('tr').filter({ has: page.getByRole('button', { name: label, exact: true }) });
const QUIET = 'Could not check this machine for servers outside the gateway.';

// ------------------------------------------------------------ fixtures

const REGISTRY = json(200, {
  entries: [
    { name: 'forge', category: 'dev-tools' },
    { name: 'anvil', category: 'dev-tools' },
    { name: 'kiln', category: 'dev-tools' },
    { name: 'lookout', category: 'search' },
    { name: 'ledger', category: 'database' },
    { name: 'oddity', category: 'astrology' },
  ],
  total: 6,
});

// Reason sentences as server_state.rs writes them, with its numbers filled in.
const WHY_SIGN_IN = 'Waiting for someone to sign in to this server.';
const WHY_FAILING = '3 recent failures; calls still go through.';
const WHY_SLOW = 'Answering, but the p95 of its last 100 answered calls is 1900 ms, over three times its usual 400 ms.';
const WHY_POLICY = 'Refused by the runtime policy: image_not_allowlisted.';
const WHY_HELD = 'Its runtime settings ask for acme.custom_flag; it will not start until those settings change.';
const RETRY_AT = '2026-11-22T14:02:00Z';

const MIXED = fullView(
  srv('forge', 'running', { tools_cached: 7, calls_24h: 40, latency_p95_ms: 310 }),
  srv('anvil', 'slow', { reason: WHY_SLOW, tools_cached: 0, calls_24h: 5, latency_p95_ms: 1900 }),
  srv('kiln', 'dormant', { tools_cached: 2, calls_24h: 0, latency_p95_ms: null }),
  srv('lookout', 'running', { tools_cached: 3, calls_24h: 9, latency_p95_ms: 120 }),
  srv('ledger', 'dormant', { tools_cached: 1, calls_24h: 0, latency_p95_ms: null }),
  srv('mystery', 'running', { tools_cached: 1, calls_24h: 1, latency_p95_ms: 50 }),
  srv('oddity', 'running', { tools_cached: 1, calls_24h: 2, latency_p95_ms: 60 }),
  srv('creaky', 'unhealthy', { reason: WHY_FAILING }),
  srv('vault', 'refused', { reason: WHY_POLICY }),
  srv('gate', 'needs_sign_in', { reason: WHY_SIGN_IN }),
  srv('hold', 'paused', { reason: '5 failures in a row; calls are held back and it retries on its own.', next_retry_at: RETRY_AT }),
);

const finds = (...list) => json(200, { servers: list.map(([name, managed]) => ({ name, source: 'claude_desktop', config_file: '/home/u/cfg.json', managed, adoptable: !managed, refusals: [] })) });

// ------------------------------------------------------------ which screen

test.describe('precedence: one screen per status answer', () => {
  test('a 500 shows the error banner alone and reads nothing else', async ({ page }) => {
    const reads = await fakeGateway(page, { status: [json(500, { error: 'down' })], discovery: finds(['stray', false]) });
    await openScreen(page);
    await expect(content(page).locator('[data-state="error"]')).toBeVisible();
    await expect(content(page).getByRole('button', { name: 'Retry' })).toBeVisible();
    await expect(content(page).getByRole('region')).toHaveCount(0);
    await expect(content(page).getByText(QUIET)).toHaveCount(0);
    expect(reads).toEqual({ status: 1, registry: 0, discovery: 0 });
  });

  test('no answer at all is the same error banner, with no other read', async ({ page }) => {
    const reads = await fakeGateway(page, { status: [DROP] });
    await openScreen(page);
    await expect(content(page).locator('[data-state="error"]')).toBeVisible();
    expect(reads).toEqual({ status: 1, registry: 0, discovery: 0 });
  });

  test('the counts-only shape shows the forbidden state alone, no empty state, no reads', async ({ page }) => {
    const reads = await fakeGateway(page, { status: [countsView()], discovery: finds(['stray', false]) });
    await openScreen(page);
    await expect(content(page).locator('[data-state="forbidden"]')).toBeVisible();
    await expect(content(page).locator('[data-state="empty"]')).toHaveCount(0);
    await expect(content(page).getByRole('region')).toHaveCount(0);
    expect(reads).toEqual({ status: 1, registry: 0, discovery: 0 });
  });

  test('no servers shows the empty state with its one action, and the unmanaged group under it', async ({ page }) => {
    const reads = await fakeGateway(page, { status: [fullView()], discovery: finds(['stray', false]) });
    await openScreen(page);
    const empty = content(page).locator('[data-state="empty"]');
    await expect(empty).toBeVisible();
    await expect(empty.getByRole('link', { name: 'Add a server' })).toHaveAttribute('href', '/ui/classic');
    await expect(statusRow(block(page, 'Not behind the gateway'), 'stray claude_desktop')).toBeVisible();
    expect(reads).toEqual({ status: 1, registry: 1, discovery: 1 });
  });

  test('no servers and a failing discovery shows the empty state and the quiet line', async ({ page }) => {
    await fakeGateway(page, { status: [fullView()], discovery: json(503, { error: 'scan timed out' }) });
    await openScreen(page);
    await expect(content(page).locator('[data-state="empty"]')).toBeVisible();
    await expect(content(page).getByText(QUIET)).toBeVisible();
  });

  test('servers present shows the groups and no page state', async ({ page }) => {
    await fakeGateway(page, { status: [MIXED] });
    await openScreen(page);
    await expect(block(page, 'Needs a look')).toBeVisible();
    await expect(block(page, 'Answering')).toBeVisible();
    await expect(content(page).locator('[data-state]')).toHaveCount(0);
  });
});

// ------------------------------------------------------------ rows

test('needs a look: worst first, then each state says what it should', async ({ page }) => {
  await fakeGateway(page, { status: [MIXED] });
  await openScreen(page);
  const needs = block(page, 'Needs a look');
  await expect(needs.getByRole('heading')).toHaveText('Needs a look · 4');
  await expect(needs.getByRole('rowheader')).toHaveText(['hold', 'gate', 'vault', 'creaky']);
  const at = await page.evaluate((iso) => new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }), RETRY_AT);
  await expect(statusRow(needs, 'hold')).toContainText(`Paused retries ${at}`);
  await expect(statusRow(needs, 'gate')).toContainText(`Needs sign-in ${WHY_SIGN_IN}`);
  await expect(statusRow(needs, 'creaky')).toContainText(`Unhealthy ${WHY_FAILING}`);
  // A Refused reason can carry raw policy codes: the shell's own words show instead.
  const vault = statusRow(needs, 'vault');
  await expect(vault).toContainText('The gateway cannot start vault with its current runtime configuration.');
  await expect(vault).not.toContainText('image_not_allowlisted');
});

test('a refused reason built from confirmation ids never shows either', async ({ page }) => {
  await fakeGateway(page, { status: [fullView(srv('held', 'refused', { reason: WHY_HELD }))] });
  await openScreen(page);
  const row = statusRow(block(page, 'Needs a look'), 'held');
  await expect(row).toContainText('The gateway cannot start held with its current runtime configuration.');
  await expect(row).not.toContainText('acme.custom_flag');
});

test('a state outside the table goes last under needs a look, in the shell badge words', async ({ page }) => {
  await fakeGateway(page, {
    status: [fullView(srv('drifter', 'wandering', { reason: 'raw_code_42' }), srv('loner', 'unmanaged'), srv('creaky', 'unhealthy', { reason: WHY_FAILING }))],
  });
  await openScreen(page);
  const needs = block(page, 'Needs a look');
  await expect(needs.getByRole('rowheader')).toHaveText(['creaky', 'drifter', 'loner']);
  await expect(statusRow(needs, 'drifter')).toContainText('Unknown state');
  await expect(statusRow(needs, 'drifter')).not.toContainText('wandering');
  await expect(statusRow(needs, 'drifter')).not.toContainText('raw_code_42');
  await expect(statusRow(needs, 'loner')).toContainText('Unmanaged');
  await expect(content(page).getByRole('rowheader', { name: 'drifter', exact: true })).toHaveCount(1);
});

/**
 * Named exports of the loaded `servers` and `shell` modules. An import of a URL
 * the page already loaded returns that same module, so nothing runs twice.
 */
async function screenWords(page) {
  return page.evaluate(async () => {
    const loaded = (stem) => performance.getEntriesByType('resource').map((e) => e.name)
      .find((name) => new RegExp(`/ui/assets/${stem}\\.[0-9a-f]{12}\\.js$`).test(name));
    const servers = await import(loaded('servers'));
    const shell = await import(loaded('shell'));
    return { block: servers.OFF_BLOCK_TITLE, word: shell.OFF_WORD };
  });
}

// A server turned off in the config, in the wire shape the gateway sends it.
const PARKED = {
  name: 'parked', state: 'off', running: false, transport: 'http', reason: '', next_retry_at: null,
  tools_cached: 0, calls_24h: 12, calls_prev_24h: 3, latency_p50_ms: null, latency_p95_ms: null, latency_p99_ms: null,
  circuit_state: null, circuit_trips: null, current_failures: null, healthy: null,
  request_count: null, success_count: null, failure_count: null,
  cleartext_credentials_accepted: false, needs_sign_in: false,
};

test('a server turned off in the config has a block of its own, never answering and never a thing to look at', async ({ page }) => {
  await fakeGateway(page, {
    status: [fullView(srv('forge', 'running'), srv('lookout', 'running'), PARKED)],
    // Discovery sees it on this machine too: it is a status row, so not outside the gateway.
    discovery: finds(['parked', false]),
  });
  await openScreen(page);
  const words = await screenWords(page);
  expect(words.block, 'the screen exports its block title').toBeTruthy();
  const off = block(page, words.block);
  await expect(off.getByRole('heading')).toHaveText(`${words.block} · 1`);
  await expect(off.getByRole('columnheader')).toHaveCount(5);
  await expect(statusRow(off, 'parked').getByRole('cell')).toHaveText([new RegExp(`${words.word}$`), '0', '12', '—']);
  await expect(block(page, 'Answering').getByRole('heading')).toHaveText('Answering · 2');
  await expect(block(page, 'Needs a look')).toHaveCount(0);
  await expect(block(page, 'Not behind the gateway')).toHaveCount(0);
});

test('a gateway whose every server is turned off shows the off block, not the empty state', async ({ page }) => {
  await fakeGateway(page, { status: [fullView(PARKED)] });
  await openScreen(page);
  const words = await screenWords(page);
  expect(words.block, 'the screen exports its block title').toBeTruthy();
  await expect(block(page, words.block).getByRole('heading')).toHaveText(`${words.block} · 1`);
  await expect(content(page).locator('[data-state="empty"]')).toHaveCount(0);
});

test('answering: groups by registry category, Other last, sums and the highest p95', async ({ page }) => {
  await fakeGateway(page, { status: [MIXED] });
  await openScreen(page);
  const answering = block(page, 'Answering');
  await expect(answering.getByRole('heading')).toHaveText('Answering · 7');
  await expect(groupButtons(page)).toHaveText(['Databases', 'Developer tools', 'Search and web', 'Other']);
  await expect(groupRow(page, 'Developer tools').getByRole('cell')).toHaveText(['2 answering · 1 slow · 1 idle', '9', '45', '1.9 s']);
  await expect(groupRow(page, 'Developer tools').getByRole('cell', { name: 'Highest p95 among its servers: 1.9 s' })).toHaveCount(1);
  await expect(groupRow(page, 'Search and web').getByRole('cell')).toHaveText(['1 answering', '3', '9', '120 ms']);
  // An all-idle group has no sample: a dash, named as not known, never a zero.
  await expect(groupRow(page, 'Databases').getByRole('cell')).toHaveText(['0 answering · 1 idle', '1', '0', '—']);
  await expect(groupRow(page, 'Databases').getByRole('cell', { name: 'not known' })).toHaveCount(1);
  // mystery is not in the registry; oddity's category has no label.
  await groupButton(page, 'Other').click();
  await expect(answering.getByRole('rowheader', { name: 'mystery', exact: true })).toBeVisible();
  await expect(answering.getByRole('rowheader', { name: 'oddity', exact: true })).toBeVisible();
});

test('a group whose calls are not all known shows its total as not known, never a smaller number', async ({ page }) => {
  const partial = structuredClone(MIXED);
  // One of three members: the other two still report, so only an every-member check gives a dash.
  partial.body.servers.find((s) => s.name === 'forge').calls_24h = null;
  await fakeGateway(page, { status: [partial] });
  await openScreen(page);
  await expect(groupRow(page, 'Developer tools').getByRole('cell')).toHaveText(['2 answering · 1 slow · 1 idle', '9', '—', '1.9 s']);
  await expect(groupRow(page, 'Developer tools').getByRole('cell', { name: 'not known' })).toHaveCount(1);
  // Groups whose members all report still add up.
  await expect(groupRow(page, 'Search and web').getByRole('cell').nth(2)).toHaveText('9');
});

test('a member row: Answering, Slow with its reason, Idle; tools 0 shows 0', async ({ page }) => {
  await fakeGateway(page, { status: [MIXED] });
  await openScreen(page, '?open=developer-tools');
  const answering = block(page, 'Answering');
  await expect(statusRow(answering, 'forge').getByRole('cell')).toHaveText([/Answering$/, '7', '40', '310 ms']);
  await expect(statusRow(answering, 'anvil')).toContainText(`Slow ${WHY_SLOW}`);
  await expect(statusRow(answering, 'anvil').getByRole('cell').nth(1)).toHaveText('0');
  await expect(statusRow(answering, 'kiln').getByRole('cell').first()).toHaveText(/Idle$/);
  await expect(statusRow(answering, 'kiln').getByRole('cell', { name: 'not known' })).toHaveCount(1);
});

test('a group opens from the keyboard, keeps ?open= and survives a reload', async ({ page }) => {
  await fakeGateway(page, { status: [MIXED] });
  await openScreen(page);
  const button = groupButton(page, 'Developer tools');
  await expect(button).toHaveAttribute('aria-expanded', 'false');
  await expect(block(page, 'Answering').getByRole('rowheader', { name: 'forge', exact: true })).toBeHidden();
  await button.focus();
  await page.keyboard.press('Enter');
  await expect(button).toHaveAttribute('aria-expanded', 'true');
  await expect(page).toHaveURL(/[?&]open=developer-tools(&|$)/);
  await page.reload();
  await shellReady(page);
  await expect(groupButton(page, 'Developer tools')).toHaveAttribute('aria-expanded', 'true');
  await expect(block(page, 'Answering').getByRole('rowheader', { name: 'forge', exact: true })).toBeVisible();
  await groupButton(page, 'Developer tools').focus();
  await page.keyboard.press('Space');
  await expect(groupButton(page, 'Developer tools')).toHaveAttribute('aria-expanded', 'false');
  await expect(page).not.toHaveURL(/open=/);
});

test('a click anywhere on a group row opens that group', async ({ page }) => {
  await fakeGateway(page, { status: [MIXED] });
  await openScreen(page);
  await groupRow(page, 'Developer tools').getByRole('cell').first().click();
  await expect(groupButton(page, 'Developer tools')).toHaveAttribute('aria-expanded', 'true');
  await expect(page).toHaveURL(/[?&]open=developer-tools(&|$)/);
});

test('while the first status read is out, the shell shows its loading state', async ({ page }) => {
  const held = gate();
  await fakeGateway(page, { status: [{ ...MIXED, hold: held.shut }] });
  await page.goto('/ui/servers/status');
  await expect(content(page).locator('[data-state="loading"]')).toBeVisible();
  held.open();
  await expect(block(page, 'Answering')).toBeVisible();
  await expect(content(page).locator('[data-state="loading"]')).toHaveCount(0);
});

test('a registry that fails, or never answers, puts every answering server under Other, quietly', async ({ page }) => {
  for (const registry of [json(500, { error: 'no' }), DROP]) {
    await page.unrouteAll({ behavior: 'ignoreErrors' });
    await fakeGateway(page, { status: [MIXED], registry });
    await openScreen(page);
    await expect(groupButtons(page)).toHaveText(['Other']);
    await expect(block(page, 'Needs a look').getByRole('rowheader')).toHaveText(['hold', 'gate', 'vault', 'creaky']);
    await expect(content(page).locator('[data-state]')).toHaveCount(0);
  }
});

test('a registry and a discovery that never reply are given up on, and refreshes still run', async ({ page }) => {
  test.setTimeout(60_000);
  const never = { hold: new Promise(() => {}) };
  const reads = await fakeGateway(page, { status: [MIXED], registry: never, discovery: never });
  await openScreen(page);
  await expect(groupButtons(page)).toHaveText(['Other'], { timeout: 30_000 });
  await expect(content(page).getByText(QUIET)).toHaveCount(1);
  await statusEvent(page);
  await expect.poll(() => reads.status).toBe(2);
  expect(reads).toEqual({ status: 2, registry: 1, discovery: 1 });
});

// ------------------------------------------------------------ not behind the gateway

test.describe('rule D: finds outside the gateway', () => {
  test('only unmanaged finds, dashes named as not known, and no Remove', async ({ page }) => {
    await fakeGateway(page, { status: [MIXED], discovery: finds(['stray', false], ['forge-copy', true]) });
    await openScreen(page);
    const outside = block(page, 'Not behind the gateway');
    await expect(outside.getByRole('heading')).toHaveText('Not behind the gateway · 1');
    const row = statusRow(outside, 'stray claude_desktop');
    await expect(row.getByRole('cell')).toHaveText([/Unmanaged$/, '—', '—', '—']);
    await expect(row.getByRole('cell', { name: 'not known' })).toHaveCount(3);
    await expect(outside.getByText('forge-copy')).toHaveCount(0);
    await expect(content(page).getByRole('button', { name: /remove/i })).toHaveCount(0);
  });

  test('no finds, or only managed ones: no group and no line', async ({ page }) => {
    for (const discovery of [finds(), finds(['forge', true])]) {
      await page.unrouteAll({ behavior: 'ignoreErrors' });
      await fakeGateway(page, { status: [MIXED], discovery });
      await openScreen(page);
      await expect(block(page, 'Answering')).toBeVisible();
      await expect(block(page, 'Not behind the gateway')).toHaveCount(0);
      await expect(content(page).getByText(QUIET)).toHaveCount(0);
    }
  });

  test('a 503, a 500 and no answer each show the one quiet line', async ({ page }) => {
    for (const discovery of [json(503, { error: 'x' }), json(500, { error: 'y' }), DROP]) {
      await page.unrouteAll({ behavior: 'ignoreErrors' });
      await fakeGateway(page, { status: [MIXED], discovery });
      await openScreen(page);
      await expect(block(page, 'Answering')).toBeVisible();
      await expect(content(page).getByText(QUIET)).toHaveCount(1);
      await expect(block(page, 'Not behind the gateway')).toHaveCount(0);
    }
  });

  test('a name that is a status row shows once, as the status row, managed or stale', async ({ page }) => {
    await fakeGateway(page, { status: [MIXED], discovery: finds(['forge', true], ['lookout', false]) });
    await openScreen(page, '?open=developer-tools');
    await expect(content(page).getByRole('rowheader', { name: /^forge\b/ })).toHaveCount(1);
    await expect(content(page).getByRole('rowheader', { name: /^lookout\b/ })).toHaveCount(0); // its group is shut
    await expect(block(page, 'Not behind the gateway')).toHaveCount(0);
  });
});

// ------------------------------------------------------------ refresh

test.describe('refresh on the gateway-status event', () => {
  test('a refresh reads status only; twenty of them make one discovery read', async ({ page }) => {
    const reads = await fakeGateway(page, { status: [MIXED], discovery: finds(['stray', false]) });
    await openScreen(page);
    await expect(block(page, 'Not behind the gateway')).toBeVisible();
    for (let i = 1; i <= 20; i += 1) {
      await statusEvent(page);
      await expect.poll(() => reads.status).toBe(1 + i);
    }
    expect(reads).toEqual({ status: 21, registry: 1, discovery: 1 });
  });

  test('a burst during a held read costs one more read, no more', async ({ page }) => {
    const held = gate();
    const after = fullView(srv('forge', 'paused', { next_retry_at: RETRY_AT }));
    const reads = await fakeGateway(page, { status: [MIXED, { ...MIXED, hold: held.shut }, after] });
    await openScreen(page);
    await statusEvent(page);
    await expect.poll(() => reads.status).toBe(2);
    for (let i = 0; i < 5; i += 1) await statusEvent(page);
    held.open();
    await expect(block(page, 'Needs a look').getByRole('rowheader')).toHaveText(['forge']);
    expect(reads.status).toBe(3);
  });

  test('changed states regroup and re-total, and the open group stays open', async ({ page }) => {
    const moved = structuredClone(MIXED);
    moved.body.servers.find((s) => s.name === 'kiln').state = 'paused';
    moved.body.servers.find((s) => s.name === 'kiln').next_retry_at = RETRY_AT;
    await fakeGateway(page, { status: [MIXED, moved] });
    await openScreen(page, '?open=developer-tools');
    await statusEvent(page);
    await expect(block(page, 'Needs a look').getByRole('heading')).toHaveText('Needs a look · 5');
    // Within one state, by name.
    await expect(block(page, 'Needs a look').getByRole('rowheader')).toHaveText(['hold', 'kiln', 'gate', 'vault', 'creaky']);
    await expect(groupRow(page, 'Developer tools').getByRole('cell').first()).toHaveText('2 answering · 1 slow');
    await expect(groupButton(page, 'Developer tools')).toHaveAttribute('aria-expanded', 'true');
  });

  test('empty, then servers: they land in their groups with no new registry read', async ({ page }) => {
    const reads = await fakeGateway(page, {
      status: [fullView(), fullView(srv('forge', 'running'), srv('lookout', 'running'))],
    });
    await openScreen(page);
    await expect(content(page).locator('[data-state="empty"]')).toBeVisible();
    await statusEvent(page);
    await expect(groupButtons(page)).toHaveText(['Developer tools', 'Search and web']);
    await expect(content(page).locator('[data-state="empty"]')).toHaveCount(0);
    expect(reads.registry).toBe(1);
  });

  test('a server adopted between refreshes leaves the outside group, with no new discovery read', async ({ page }) => {
    const reads = await fakeGateway(page, {
      status: [MIXED, fullView(...MIXED.body.servers, srv('stray', 'running'), srv('other-stray', 'running'))],
      discovery: finds(['stray', false], ['other-stray', false], ['third', false]),
    });
    await openScreen(page);
    await expect(block(page, 'Not behind the gateway').getByRole('heading')).toHaveText('Not behind the gateway · 3');
    await statusEvent(page);
    await expect(block(page, 'Not behind the gateway').getByRole('heading')).toHaveText('Not behind the gateway · 1');
    await expect(block(page, 'Not behind the gateway').getByRole('rowheader')).toHaveText(['third claude_desktop']);
    await groupButton(page, 'Other').click();
    await expect(content(page).getByRole('rowheader', { name: /^stray\b/ })).toHaveCount(1);
    expect(reads.discovery).toBe(1);
  });

  test('when the last outside find is adopted, the group and its line go', async ({ page }) => {
    await fakeGateway(page, {
      status: [MIXED, fullView(...MIXED.body.servers, srv('stray', 'running'))],
      discovery: finds(['stray', false]),
    });
    await openScreen(page);
    await expect(block(page, 'Not behind the gateway')).toBeVisible();
    await statusEvent(page);
    await expect(block(page, 'Not behind the gateway')).toHaveCount(0);
    await expect(content(page).getByText(QUIET)).toHaveCount(0);
  });

  for (const first of [['a 500', json(500, { error: 'down' })], ['counts only', countsView()]]) {
    test(`recovery after ${first[0]}: registry and discovery are read once, then never again`, async ({ page }) => {
      const reads = await fakeGateway(page, { status: [first[1], MIXED], discovery: finds(['stray', false]) });
      await openScreen(page);
      await expect(content(page).locator('[data-state="error"], [data-state="forbidden"]')).toBeVisible();
      await expect(content(page).getByRole('rowheader', { name: /^stray\b/ })).toHaveCount(0);
      await statusEvent(page);
      await expect(block(page, 'Not behind the gateway')).toBeVisible();
      await expect(content(page).locator('[data-state]')).toHaveCount(0);
      expect(reads).toEqual({ status: 2, registry: 1, discovery: 1 });
      await statusEvent(page);
      await expect.poll(() => reads.status).toBe(3);
      expect(reads).toEqual({ status: 3, registry: 1, discovery: 1 });
    });
  }

  for (const next of [['counts only', countsView(), 'forbidden'], ['a failure', json(502, { error: 'gone' }), 'error']]) {
    test(`a full view, then ${next[0]}: the page state alone, nothing left behind`, async ({ page }) => {
      await fakeGateway(page, { status: [MIXED, next[1]], discovery: finds(['stray', false]) });
      await openScreen(page);
      await expect(block(page, 'Not behind the gateway')).toBeVisible();
      await statusEvent(page);
      await expect(content(page).locator(`[data-state="${next[2]}"]`)).toBeVisible();
      await expect(content(page).getByRole('region')).toHaveCount(0);
      await expect(content(page).getByRole('rowheader')).toHaveCount(0);
      await expect(content(page).getByText(QUIET)).toHaveCount(0);
      await expect(content(page).locator('[data-state="empty"]')).toHaveCount(0);
    });
  }

  test('off the screen nothing listens; back on it, one listener', async ({ page }) => {
    await countListeners(page, ['gateway-status']);
    const reads = await fakeGateway(page, { status: [MIXED] });
    await openScreen(page);
    await expect(block(page, 'Answering')).toBeVisible();
    expect(await page.evaluate(() => window.__listeners('gateway-status'))).toBe(1);
    await page.getByRole('navigation').getByRole('link', { name: 'Tools', exact: true }).click();
    await expect(page).toHaveURL(/\/ui\/tools\//);
    await statusEvent(page);
    expect(await page.evaluate(() => window.__listeners('gateway-status'))).toBe(0);
    await page.getByRole('navigation').getByRole('link', { name: 'Servers', exact: true }).click();
    await expect(block(page, 'Answering')).toBeVisible();
    // The away event made no read: the read on return is the second, not the third.
    expect(reads.status).toBe(2);
    expect(await page.evaluate(() => window.__listeners('gateway-status'))).toBe(1);
  });

  test('leaving and coming back twice with no event between leaves one listener', async ({ page }) => {
    await countListeners(page, ['gateway-status']);
    await fakeGateway(page, { status: [MIXED] });
    await openScreen(page);
    await expect(block(page, 'Answering')).toBeVisible();
    for (const link of ['Tools', 'Servers', 'Tools', 'Servers']) {
      await page.getByRole('navigation').getByRole('link', { name: link, exact: true }).click();
      await expect(page).toHaveURL(link === 'Tools' ? /\/ui\/tools\// : /\/ui\/servers\//);
    }
    await expect(block(page, 'Answering')).toBeVisible();
    expect(await page.evaluate(() => window.__listeners('gateway-status'))).toBe(1);
  });

  test('a tooltip module that never loads holds up no refresh, and a group keeps its focus', async ({ page }) => {
    await page.route('**/ui/assets/tooltip.*.js', () => new Promise(() => {}));
    const moved = structuredClone(MIXED);
    moved.body.servers.find((s) => s.name === 'kiln').state = 'paused';
    const reads = await fakeGateway(page, { status: [MIXED, moved, MIXED] });
    await openScreen(page);
    await groupButton(page, 'Other').focus();
    await statusEvent(page);
    await expect(block(page, 'Needs a look').getByRole('heading')).toHaveText('Needs a look · 5');
    await expect(groupButton(page, 'Other')).toBeFocused();
    await statusEvent(page);
    await expect(block(page, 'Needs a look').getByRole('heading')).toHaveText('Needs a look · 4');
    expect(reads.status).toBe(3);
  });

  test('a refresh keeps focus where it was: a tip trigger, a table, a group', async ({ page }) => {
    await fakeGateway(page, { status: [MIXED] });
    await openScreen(page);
    const answering = block(page, 'Answering');
    const targets = [
      answering.getByRole('columnheader', { name: /^Tools/ }).getByRole('button'),
      page.getByRole('region', { name: 'Answering, table', exact: true }),
      groupButton(page, 'Other'),
    ];
    for (const target of targets) {
      await target.focus();
      await expect(target).toBeFocused();
      // Mark the drawn tables, so the wait below ends only once a redraw replaced them.
      await page.evaluate(() => { for (const n of document.querySelectorAll('#content .sv-scroll')) n.dataset.old = '1'; });
      await statusEvent(page);
      await expect(page.locator('#content .sv-scroll[data-old]')).toHaveCount(0);
      await expect(target).toBeFocused();
    }
  });
});

// ------------------------------------------------------------ text, table, access

test('gateway strings go in as text: a name and a reason that look like markup stay words', async ({ page }) => {
  const odd = '<b id="made-by-name">x</b>';
  const oddWhy = 'fine"><i id="made-by-reason">y</i>';
  await fakeGateway(page, {
    status: [fullView(srv(odd, 'needs_sign_in', { reason: oddWhy }))],
    discovery: json(200, { servers: [{ name: '<u id="made-by-find">z</u>', source: '<s id="made-by-source">', managed: false }] }),
  });
  await openScreen(page);
  await expect(statusRow(block(page, 'Needs a look'), odd)).toContainText(oddWhy);
  await expect(block(page, 'Not behind the gateway')).toContainText('<u id="made-by-find">z</u>');
  await expect(page.locator('#made-by-name, #made-by-reason, #made-by-find, #made-by-source')).toHaveCount(0);
});

test('every category in the built-in registry has a label in the screen', async ({ page }) => {
  const source = readFileSync(fileURLToPath(new URL('../../src/registry/server_registry_entries.rs', import.meta.url)), 'utf8');
  const categories = [...new Set([...source.matchAll(/category: "([a-z-]+)"/g)].map((m) => m[1]))];
  expect(categories.length).toBeGreaterThan(10);
  await fakeGateway(page, { status: [MIXED] });
  await openScreen(page);
  const labelled = await page.evaluate(async () => {
    const entry = JSON.parse(document.getElementById('screens').textContent).servers;
    const mod = await import(entry.js);
    return Object.keys(mod.GROUP_LABELS);
  });
  expect(categories.filter((c) => !labelled.includes(c))).toEqual([]);
});

const DRAWN_TIPS = ['servers.status.answering-24-grouped-by-the', 'servers.status.tools', 'servers.status.p95-last-1-000-calls'];

test('the status tab draws its three tips; every servers.settings tip waits as pending-later', () => {
  const scan = scanScreens(readScreens());
  expect(scan.tabs.servers).toEqual({ status: true, actions: true, settings: true });
  for (const id of DRAWN_TIPS) expect(scan.drawn.has(id), id).toBe(true);
  const copy = readCopy();
  expect(copy._pending.servers ?? []).toEqual([]);
  const later = Object.keys(copy).filter((id) => id.startsWith('servers.settings.'));
  expect(later.filter((id) => !Object.hasOwn(copy._pending_later, id))).toEqual([]);
});

test('each tip opens from the keyboard and hides no control', async ({ page }) => {
  await fakeGateway(page, { status: [MIXED], discovery: finds(['stray', false]) });
  await openScreen(page, '?open=developer-tools');
  for (const id of DRAWN_TIPS) {
    await expect(page.locator(`.has-tip[data-tip="${id}"] button`)).toHaveCount(1);
    expect(await tooltipCoversNothing(page, id), id).toEqual([]);
  }
});

for (const width of WIDTHS) {
  for (const scheme of ['light', 'dark']) {
    test(`no blocking axe findings at ${width} px, ${scheme}`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await page.emulateMedia({ colorScheme: scheme });
      await fakeGateway(page, { status: [MIXED], discovery: finds(['stray', false]) });
      await openScreen(page, '?open=developer-tools');
      await expect(block(page, 'Not behind the gateway')).toBeVisible();
      expect(await blockingViolations(page, '#content')).toEqual([]);
    });
  }
}
