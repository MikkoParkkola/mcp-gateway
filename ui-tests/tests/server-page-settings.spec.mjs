// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// A server's Settings tab: Connection, Secrets with Replace, and Who can
// use it (T8, T9, T10, T11 of the frozen test plan, with sidecar 2). The
// secret records come from the fixture the Rust rows of the config read use.
import { test, expect, blockingViolations, WIDTHS } from './base.mjs';
import { shellReady, recordAnnouncements, announced } from './shell.mjs';
import { readCopy, readScreens, scanScreens } from './copy-check.mjs';
import { entry, fullView, fakeServerGateway, key, keysBody, goTo, HARD, HARD_ENC } from './server-page.mjs';

// The flat map carries entries the records do not: none of them may show.
const FLAT = { 'backends.git.env.FLAT_ONLY': 'env:FLAT_SENTINEL', 'backends.svc.env.FLAT_TOO': 'env:FLAT_SENTINEL_2' };
const configBody = (records = [], more = {}) => ({ code: 200, body: { servers: [], secret_references: FLAT, secret_reference_records: records, ...more } });
const lines = (page) => page.locator('ul.sp-secrets > li');
const who = (page) => page.locator('ul.sp-who > li');
// The page's text and every field's value, to prove a typed secret is gone.
const holds = (page, needle) => page.evaluate((n) => document.body.innerText.includes(n)
  || [...document.querySelectorAll('input, textarea')].some((i) => i.value.includes(n)), needle);

/** Open a server's Settings tab; the address must stay on Settings, never fall back to Status. */
async function settings(page, server, opts = {}) {
  const seen = await fakeServerGateway(page, { status: fullView(server, entry('other', 'running')), config: configBody(), ...opts });
  const path = `/ui/servers/${encodeURIComponent(server.name)}/settings`;
  await page.goto(path);
  await shellReady(page);
  expect(new URL(page.url()).pathname).toBe(path);
  await expect(page.getByRole('heading', { level: 2, name: 'Who can use it' })).toBeVisible();
  return seen;
}

test.describe('T1b Settings checks the object before any other read', () => {
  test('T1b settings: a name no server has stays on Settings, shows the empty state, and reads neither config nor keys', async ({ page }) => {
    const seen = await fakeServerGateway(page, { status: fullView(entry('github', 'running')), config: configBody(), keys: keysBody() });
    await page.goto('/ui/servers/ghost/settings');
    await shellReady(page);
    expect(new URL(page.url()).pathname).toBe('/ui/servers/ghost/settings');
    await expect(page.locator('#content [data-state="empty"] h2')).toHaveText('No server named ghost');
    expect({ status: seen.status, config: seen.config, keys: seen.keys }).toEqual({ status: 1, config: 0, keys: 0 });
  });

  test('T1b settings: a counts-only status answer is the forbidden state, with no config or keys read', async ({ page }) => {
    const seen = await fakeServerGateway(page, { status: { server_count: 1, healthy_count: 1, degraded_count: 0 }, config: configBody(), keys: keysBody() });
    await page.goto('/ui/servers/github/settings');
    await shellReady(page);
    expect(new URL(page.url()).pathname).toBe('/ui/servers/github/settings');
    await expect(page.locator('#content [data-state="forbidden"]')).toHaveCount(1);
    expect({ status: seen.status, config: seen.config, keys: seen.keys }).toEqual({ status: 1, config: 0, keys: 0 });
  });
});

test.describe('T9d Connection', () => {
  test('T9d the transport comes from the status entry, never from the config read', async ({ page }) => {
    const config = configBody([], { servers: [{ name: 'git', owner: null, transport: 'tr-sentinel-config', running: true, allowed_tools: null }] });
    await settings(page, entry('git', 'running', { transport: 'stdio' }), { config });
    const facts = page.locator('section.sp-connection dl');
    await expect(facts.locator('dt')).toHaveCount(1);
    await expect(facts.locator('dt')).toContainText('Transport');
    await expect(facts.locator('dd')).toHaveText(['stdio']);
    expect(await holds(page, 'tr-sentinel-config')).toBe(false);
  });
});

const ONLY_REFS = 'Only secrets held as references are listed; a value written into gateway.yaml as text is not.';
const UNREAD = 'The secrets could not be read.';
const fields = (page) => lines(page).locator('.sp-field');

const rec = (field, more = {}) => ({ server: 's', kind: 'env', field, reference: `env:${field}`, ...more });

test.describe('T9b records outside the contract are left out', () => {
  test('T9b a record of another kind, a missing or non-string member, an extra member or null is dropped; the rest stay', async ({ page }) => {
    const { reference: _gone, ...noRef } = rec('NO_REF');
    const records = [rec('KEEP_1'), rec('ODD_KIND', { kind: 'files' }), noRef, rec('NUM_REF', { reference: 7 }),
      rec('EXTRA', { note: 'x' }), null, rec('HDR', { kind: 'headers' }), rec('KEEP_2')];
    await settings(page, entry('s', 'running'), { config: configBody(records) });
    await expect(fields(page)).toHaveText(['KEEP_1', 'HDR', 'KEEP_2']);
    await expect(page.getByText(UNREAD)).toHaveCount(0);
  });

  for (const [label, more] of [
    ['a member that is not a list', { secret_reference_records: { server: 's' } }],
    ['no member at all', { secret_reference_records: undefined }],
  ]) {
    test(`T9b ${label}: no lines and the could-not-read line`, async ({ page }) => {
      const config = configBody([], more);
      if (more.secret_reference_records === undefined) delete config.body.secret_reference_records;
      await settings(page, entry('git', 'running'), { config });
      await expect(lines(page)).toHaveCount(0);
      await expect(page.locator('p.sp-unread')).toHaveText(UNREAD);
    });
  }

  test('T9b an empty list: no lines, the only-references line and no could-not-read line', async ({ page }) => {
    await settings(page, entry('git', 'running'), { config: configBody([]) });
    await expect(lines(page)).toHaveCount(0);
    await expect(page.locator('p.sp-only')).toHaveText(ONLY_REFS);
    await expect(page.getByText(UNREAD)).toHaveCount(0);
  });
});

const SERVER = 'my server/x';
const SERVER_ENC = 'my%20server%2Fx';
const SENT = 'rpl-sentinel-9570-q7';
const DEFENCE = 'The gateway did not confirm that the new value was stored. Check gateway.yaml before trying again.';
const slot = (field = 'API_TOKEN') => configBody([{ server: SERVER, kind: 'env', field, reference: 'env:OLD_API' }]);
const stored = (field) => ({ code: 200, body: { secrets_stored: [{ field, reference: 'keychain:gw.new' }] } });
const patches = (seen) => seen.backend.filter((r) => r.method === 'PATCH');
const saidReplaced = async (page) => /replaced/i.test(await page.locator('#content').innerText());

/** Open Replace on the one slot and type the sentinel. */
async function typeSecret(page, field = 'API_TOKEN') {
  await page.getByRole('button', { name: `Replace ${field}` }).click();
  await page.getByLabel(field, { exact: true }).fill(SENT);
}

test.describe('T8 Replace stores a value or says why not, and keeps no copy', () => {
  test('T8a Save sends one PATCH with the one slot; a stored answer says replaced, announces it and focuses Replace', async ({ page }) => {
    await recordAnnouncements(page);
    const seen = await settings(page, entry(SERVER, 'running'), { config: slot(), backend: () => stored('env.API_TOKEN') });
    await page.getByRole('button', { name: 'Replace API_TOKEN' }).click();
    const field = page.getByLabel('API_TOKEN', { exact: true });
    await expect(field).toHaveAttribute('type', 'password');
    await expect(field).toHaveAttribute('autocomplete', 'new-password');
    await field.fill(SENT);
    await page.getByRole('button', { name: 'Save' }).click();
    await expect(lines(page).locator('.sp-done')).toHaveText('API_TOKEN was replaced.');
    await expect(page.getByRole('button', { name: 'Replace API_TOKEN' })).toBeFocused();
    await expect.poll(() => announced(page)).toContain('API_TOKEN was replaced.');
    expect(patches(seen).map((r) => [r.path, r.body])).toEqual([[`/ui/api/backends/${SERVER_ENC}`, { env: { API_TOKEN: SENT } }]]);
  });

  for (const [code, error] of [[422, 'secret_too_short'], [409, 'now_held'], [404, 'not_found'], [400, 'bad_request']]) {
    test(`T8b a ${code} ${error} shows the gateway's sentence under the field and keeps what was typed`, async ({ page }) => {
      await settings(page, entry(SERVER, 'running'), { config: slot(), backend: () => ({ code, body: { error, message: `sentence ${code}` } }) });
      await typeSecret(page);
      await page.getByRole('button', { name: 'Save' }).click();
      await expect(page.locator('form.sp-replace .sp-error')).toHaveText(`sentence ${code}`);
      await expect(page.getByLabel('API_TOKEN', { exact: true })).toHaveValue(SENT);
      expect(await saidReplaced(page)).toBe(false);
    });
  }

  for (const [label, answer] of [
    ['an empty secrets_stored', { code: 200, body: { secrets_stored: [] } }],
    ["only another slot's entry", stored('env.OTHER_TOKEN')],
  ]) {
    test(`T8c a 200 with ${label} is not called replaced, and the value is gone`, async ({ page }) => {
      await settings(page, entry(SERVER, 'running'), { config: slot(), backend: () => answer });
      await typeSecret(page);
      await page.getByRole('button', { name: 'Save' }).click();
      await expect(page.locator('#content .sp-error')).toHaveText(DEFENCE);
      expect(await saidReplaced(page)).toBe(false);
      expect(await holds(page, SENT)).toBe(false);
    });
  }

  test('T8b a dotted env field is sent as that one key', async ({ page }) => {
    const seen = await settings(page, entry(SERVER, 'running'), { config: slot('a.b.TOKEN'), backend: () => stored('env.a.b.TOKEN') });
    await typeSecret(page, 'a.b.TOKEN');
    await page.getByRole('button', { name: 'Save' }).click();
    await expect(lines(page).locator('.sp-done')).toHaveText('a.b.TOKEN was replaced.');
    expect(patches(seen).map((r) => r.body)).toEqual([{ env: { 'a.b.TOKEN': SENT } }]);
  });

  test('T8d an empty value cannot be saved', async ({ page }) => {
    const seen = await settings(page, entry(SERVER, 'running'), { config: slot() });
    await page.getByRole('button', { name: 'Replace API_TOKEN' }).click();
    await expect(page.getByRole('button', { name: 'Save' })).toBeDisabled();
    expect(patches(seen)).toEqual([]);
  });
});

test.describe('T8d the typed value leaves the page on every way out', () => {
  const gone = async (page) => {
    expect(await holds(page, SENT)).toBe(false);
    await expect(page.locator('input[type="password"]')).toHaveCount(0);
  };

  test('T8d after a stored answer', async ({ page }) => {
    await settings(page, entry(SERVER, 'running'), { config: slot(), backend: () => stored('env.API_TOKEN') });
    await typeSecret(page);
    await page.getByRole('button', { name: 'Save' }).click();
    await expect(lines(page).locator('.sp-done')).toHaveCount(1);
    await gone(page);
  });

  test('T8d after Cancel', async ({ page }) => {
    await settings(page, entry(SERVER, 'running'), { config: slot() });
    await typeSecret(page);
    await page.getByRole('button', { name: 'Cancel' }).click();
    await gone(page);
    await expect(page.getByRole('button', { name: 'Replace API_TOKEN' })).toBeFocused();
  });

  test('T8d after another tab and back', async ({ page }) => {
    await settings(page, entry(SERVER, 'running'), { config: slot() });
    await typeSecret(page);
    await goTo(page, `/ui/servers/${SERVER_ENC}/status`);
    await expect(page.locator('dl.sp-facts')).toHaveCount(1);
    await gone(page);
    await goTo(page, `/ui/servers/${SERVER_ENC}/settings`);
    await expect(fields(page)).toHaveText(['API_TOKEN']);
    await gone(page);
  });

  test('T8d after another page and back', async ({ page }) => {
    await settings(page, entry(SERVER, 'running'), { config: slot() });
    await typeSecret(page);
    await goTo(page, '/ui/overview/status');
    await shellReady(page);
    await gone(page);
    await goTo(page, `/ui/servers/${SERVER_ENC}/settings`);
    await expect(fields(page)).toHaveText(['API_TOKEN']);
    await gone(page);
  });
});

const ALL = 'All of its tools';
const RESTRICT = 'Tool restrictions apply';
const NONE = 'None';
const EMPTY = 'None: its allowlist is empty';
const KEYS_UNREAD = 'The keys could not be read.';

test.describe('T9c-who Who can use it: every key, a link to its page and what it reaches here', () => {
  test('T9c-who eleven keys, in the read order, with the reach rule of sidecar 2', async ({ page }) => {
    const keys = [
      key('k1', ['s']), key('k2', ['*']), key('k3', ['s'], { allowed_tools: ['a'] }), key('k4', ['other']),
      key('k5', ['s'], { live: false }), key('k6', ['s'], { denied_tools: ['b'] }), key('k7', ['*'], { denied_tools: ['b'] }),
      key('k8', ['s'], { allowed_tools: [] }), key('k9', ['*'], { allowed_tools: [] }),
      key('k10', ['s'], { denied_tools: [], allowed_tools: null }), key('k11', ['s'], { allowed_tools: [], denied_tools: ['b'] }),
    ];
    await settings(page, entry('s', 'running'), { keys: keysBody(...keys) });
    const names = keys.map((k) => k.name);
    await expect(who(page).getByRole('link')).toHaveText(names);
    expect(await who(page).getByRole('link').evaluateAll((as) => as.map((a) => a.getAttribute('href'))))
      .toEqual(names.map((n) => `/ui/access/${n}/status`));
    await expect(who(page).locator('.sp-reach')).toHaveText([ALL, ALL, RESTRICT, NONE, ALL, RESTRICT, RESTRICT, EMPTY, EMPTY, ALL, EMPTY]);
    await expect(who(page).nth(4).locator('.sp-live')).toHaveText('Not live');
    await expect(who(page).locator('.sp-live')).toHaveCount(1);
    await expect(page.locator('p.sp-help')).toHaveText("A key's reach is changed on its own page.");
  });

  test('T9c-who a failed keys read: the could-not-read line and no rows', async ({ page }) => {
    await settings(page, entry('s', 'running'), { keys: { code: 500, body: { error: 'x', message: 'y' } } });
    await expect(who(page)).toHaveCount(0);
    await expect(page.locator('p.sp-keys-unread')).toHaveText(KEYS_UNREAD);
  });
});

test.describe('T9c every path that carries a name is encoded (PR B sites)', () => {
  test('T9c the PATCH and the key link', async ({ page }) => {
    const config = configBody([{ server: HARD, kind: 'env', field: 'API_TOKEN', reference: 'env:X' }]);
    const seen = await settings(page, entry(HARD, 'running'), { config, keys: keysBody(key(HARD, [HARD])), backend: () => stored('env.API_TOKEN') });
    await expect(who(page).getByRole('link', { name: HARD, exact: true })).toHaveAttribute('href', `/ui/access/${HARD_ENC}/status`);
    await typeSecret(page);
    await page.getByRole('button', { name: 'Save' }).click();
    await expect.poll(() => patches(seen).length).toBe(1);
    expect(patches(seen)[0].path).toBe(`/ui/api/backends/${HARD_ENC}`);
  });
});

test('T10 at 390 px the open Replace form stays inside the screen, light and dark', async ({ page }) => {
  const server = 'a-rather-long-server-name-for-the-narrow-screen';
  const long = 'A_RATHER_LONG_ENVIRONMENT_VARIABLE_NAME_TOKEN';
  await page.setViewportSize({ width: 390, height: 844 });
  await settings(page, entry(server, 'running'), { config: configBody([{ server, kind: 'env', field: long, reference: 'keychain:gw.a-rather-long-reference' }]) });
  await page.getByRole('button', { name: `Replace ${long}` }).click();
  const form = page.locator('form.sp-replace');
  for (const colorScheme of ['light', 'dark']) {
    await page.emulateMedia({ colorScheme });
    for (const part of [form, form.locator('input'), form.getByRole('button', { name: 'Save' }), form.getByRole('button', { name: 'Cancel' })]) {
      const box = await part.boundingBox();
      expect(box.x, colorScheme).toBeGreaterThanOrEqual(0);
      expect(box.x + box.width, colorScheme).toBeLessThanOrEqual(390);
    }
  }
});

test.describe('T11 the Settings tab and its open Replace form are accessible', () => {
  for (const width of WIDTHS) {
    for (const colorScheme of ['light', 'dark']) {
      test(`T11 settings at ${width} px, ${colorScheme}: no blocking violations, closed and with Replace open`, async ({ page }) => {
        await page.emulateMedia({ colorScheme });
        await page.setViewportSize({ width, height: 900 });
        await settings(page, entry(SERVER, 'running'), { config: slot(), keys: keysBody(key('k1', [SERVER]), key('k2', ['*'], { live: false })) });
        expect(await blockingViolations(page)).toEqual([]);
        await page.getByRole('button', { name: 'Replace API_TOKEN' }).click();
        await expect(page.locator('form.sp-replace')).toBeVisible();
        expect(await blockingViolations(page)).toEqual([]);
      });
    }
  }

  test('T11 the keyboard reaches every Replace and every key link', async ({ page }) => {
    await settings(page, entry(SERVER, 'running'), { config: slot(), keys: keysBody(key('k1', [SERVER]), key('k2', ['other'])) });
    const want = new Set(['Replace API_TOKEN', 'k1', 'k2']);
    const reached = new Set();
    for (let i = 0; i < 80 && reached.size < want.size; i += 1) {
      await page.keyboard.press('Tab');
      const name = await page.evaluate(() => document.activeElement?.getAttribute('aria-label') ?? document.activeElement?.textContent ?? '');
      if (want.has(name)) reached.add(name);
    }
    expect([...reached].sort()).toEqual([...want].sort());
  });

  test('T11 under reduced motion the open Replace form runs no animation', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await settings(page, entry(SERVER, 'running'), { config: slot() });
    await page.getByRole('button', { name: 'Replace API_TOKEN' }).click();
    await expect(page.locator('form.sp-replace')).toBeVisible();
    expect(await page.evaluate(() => document.getAnimations().filter((a) => a.playState === 'running').length)).toBe(0);
  });
});
