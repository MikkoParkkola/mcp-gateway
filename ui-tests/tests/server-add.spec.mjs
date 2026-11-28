// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Servers › Settings at the list level: the "Add a server" card in its
// "Command or URL" mode. Start-once preview (described, running, listed,
// failed), the add, the refusal with its fix and the Override confirm. Rows are
// named after the frozen test plan (V, N, K, E, D, X, U, A); every gateway answer
// is a literal written here, in the shapes preview.rs and add_checks.rs serve.
import { test, expect, blockingViolations, WIDTHS } from './base.mjs';
import { shellReady, recordAnnouncements, announced } from './shell.mjs';
import { entry, fullView, fakeServerGateway, gate } from './server-page.mjs';
import { readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

/** The card module's served path, read from the shell directory (its name carries its hash). */
const ADD_MODULE = (() => {
  const dir = fileURLToPath(new URL('../../src/gateway/ui/shell/', import.meta.url));
  return `/ui/assets/${readdirSync(dir).find((f) => /^server-add\.[0-9a-f]{12}\.js$/.test(f))}`;
})();

/** The card's own sentences, read from its module in the page (lead ruling 2026-11-27: written once, there). */
const addWords = (page, host = '') => page.evaluate(async ([u, h]) => {
  const m = await import(u);
  const { override, overrideProgress, ...words } = m.WORDS;
  return { field: m.FIELD_WORDS, other: m.OTHER_FIELD_WORDS, words, override: override(h), progress: overrideProgress('crm') };
}, [ADD_MODULE, host]);

/** X4: every preview request body any row sends; none may carry the Override's member. */
const PREVIEW_BODIES = [];
test.afterEach(() => {
  const flagged = PREVIEW_BODIES.filter((b) => b && 'allow_cleartext_credentials' in b);
  PREVIEW_BODIES.length = 0;
  expect(flagged, 'X4: the flag never goes to a preview').toEqual([]);
});

const HTTPS = 'https://crm.lan/mcp';
const card = (page) => page.getByRole('region', { name: 'Add a server' });
const field = (page) => card(page).getByRole('textbox', { name: 'Command or URL' });
const previewButton = (page) => card(page).getByRole('button', { name: 'Start once to preview' });
const rows = (page, label) => card(page).getByRole('group', { name: label });

/** The describe answer (no `confirm` sent): nothing has run. `over` replaces members of `preview`. */
const described = (over = {}) => ({
  code: 202,
  body: {
    confirm: 'confirm-1',
    preview: {
      transport: 'http', url: HTTPS,
      withheld: { env: [], headers: [], oauth: false, secrets: 0, identity_propagation: false, account: false },
      publisher: { verified: false, source: null }, package: null, ...over,
    },
  },
});

/**
 * The page at /ui/servers/settings with one existing server, and fakes for the
 * two routes this card calls. `preview(body, n)` and `add(body, n)` answer the
 * n-th request with `{code, body, hold, drop}`; every request body is recorded.
 */
async function addPage(page, { preview = () => ({ code: 404, body: {} }), add = () => ({ code: 404, body: {} }) } = {}) {
  const seen = await fakeServerGateway(page, { status: fullView(entry('existing', 'running')) });
  seen.previews = [];
  seen.adds = [];
  const settle = async (route, a) => {
    if (a.hold) await a.hold;
    if (a.drop) return route.abort('failed');
    return route.fulfill({ status: a.code, contentType: 'application/json', body: JSON.stringify(a.body) });
  };
  await page.route('**/ui/api/previews', (route) => {
    const sent = route.request().postDataJSON();
    seen.previews.push(sent);
    PREVIEW_BODIES.push(sent);
    return settle(route, preview(sent, seen.previews.length));
  });
  await page.route(/\/ui\/api\/backends$/, (route) => {
    if (route.request().method() !== 'POST') return route.fallback();
    const sent = route.request().postDataJSON();
    seen.adds.push(sent);
    return settle(route, add(sent, seen.adds.length));
  });
  await page.goto('/ui/servers/settings');
  await shellReady(page);
  return seen;
}

test.describe('V1 a URL is described before anything runs (UI4.2)', () => {
  test('one describe request, then the nothing-has-run panel; no second request', async ({ page }) => {
    const seen = await addPage(page, {
      preview: () => described({ withheld: { env: [], headers: ['Authorization'], oauth: false, secrets: 0, identity_propagation: false, account: false } }),
    });
    await field(page).fill(HTTPS);
    await previewButton(page).click();
    const panel = card(page).getByRole('region', { name: 'Nothing has run yet' });
    await expect(panel).toBeVisible();
    expect(seen.previews).toEqual([{ name: 'crm', url: HTTPS }]);
    await expect(panel).toContainText('http');
    await expect(panel).toContainText(HTTPS);
    await expect(panel.getByRole('list', { name: 'Held back, not sent' }).getByRole('listitem')).toHaveText(['Authorization']);
    await expect(panel).toContainText('Stops after it lists its tools. No tool is called.');
    await expect(panel.getByRole('button', { name: 'Start once' })).toBeVisible();
    await expect(panel.getByRole('button', { name: 'Cancel' })).toBeVisible();
    await page.waitForTimeout(300);
    expect(seen.previews).toHaveLength(1);
  });
});

test.describe('N1 name and kind are worked out and can be changed', () => {
  const CASES = [
    ['npx -y @modelcontextprotocol/server-github', 'github', 'command'],
    ['uvx mcp-server-fetch', 'fetch', 'command'],
    ['/opt/tools/weather-mcp --port 3000', 'weather', 'command'],
    ['http://intranet.lan:8080/mcp', 'intranet', 'url'],
    [HTTPS, 'crm', 'url'],
    ['wss://stream.acme.lan/ws', 'stream', 'url'],
  ];
  for (const [text, name, kind] of CASES) {
    test(`${text} proposes ${name}, sent as ${kind}`, async ({ page }) => {
      const seen = await addPage(page, { preview: () => ({ code: 422, body: { error: 'Preview refused. You can still add this server.' } }) });
      await field(page).fill(text);
      await expect(card(page).locator('.add-name')).toHaveText(`Name ${name} · Automatic · Change`);
      await previewButton(page).click();
      await expect.poll(() => seen.previews.length).toBe(1);
      expect(seen.previews[0]).toEqual({ name, [kind]: text });
    });
  }

  test('Change sends the typed name', async ({ page }) => {
    const seen = await addPage(page, { preview: () => described() });
    await field(page).fill(HTTPS);
    await card(page).getByRole('button', { name: 'Change' }).click();
    await card(page).getByRole('textbox', { name: 'Name', exact: true }).fill('crm-prod');
    await previewButton(page).click();
    await expect.poll(() => seen.previews.length).toBe(1);
    expect(seen.previews[0].name).toBe('crm-prod');
  });

  test('the server\'s own name replaces the proposal, never a name changed by hand', async ({ page }) => {
    const listed = { code: 200, body: { preview: { ...described().body.preview, stopped: true, truncated: false, elapsed_ms: 900, package: { name: 'crm-suite', version: '2.1.0' }, teardown: { ms: 4 } }, tools: [], withheld_tools: [] } };
    await addPage(page, { preview: (body) => ('confirm' in body ? listed : described()) });
    await field(page).fill(HTTPS);
    await previewButton(page).click();
    await card(page).getByRole('button', { name: 'Start once' }).click();
    await expect(card(page).locator('.add-name')).toHaveText('Name crm-suite · Automatic · Change');
  });

  test('a name changed by hand stays after the preview names the server', async ({ page }) => {
    const listed = { code: 200, body: { preview: { ...described().body.preview, stopped: true, truncated: false, elapsed_ms: 900, package: { name: 'crm-suite', version: '2.1.0' }, teardown: { ms: 4 } }, tools: [], withheld_tools: [] } };
    await addPage(page, { preview: (body) => ('confirm' in body ? listed : described()) });
    await field(page).fill(HTTPS);
    await card(page).getByRole('button', { name: 'Change' }).click();
    await card(page).getByRole('textbox', { name: 'Name', exact: true }).fill('crm-prod');
    await previewButton(page).click();
    await card(page).getByRole('button', { name: 'Start once' }).click();
    await expect(card(page).getByText('Started once: 0 tools took 0.9 s')).toBeVisible();
    await expect(card(page).getByRole('textbox', { name: 'Name', exact: true })).toHaveValue('crm-prod');
  });
});

test.describe('K1 the value rows follow the kind', () => {
  test('a URL sends the row as headers, a command as env; the row survives a change of kind', async ({ page }) => {
    const seen = await addPage(page, { preview: () => ({ code: 422, body: { error: 'Preview refused. You can still add this server.' } }) });
    await field(page).fill(HTTPS);
    await card(page).getByRole('button', { name: 'Add a value' }).click();
    const headers = rows(page, 'Headers');
    await headers.getByRole('textbox', { name: 'Name' }).fill('Authorization');
    await headers.getByLabel('Value').fill('Bearer k-123');
    await previewButton(page).click();
    await expect.poll(() => seen.previews.length).toBe(1);
    expect(seen.previews[0]).toEqual({ name: 'crm', url: HTTPS, headers: { Authorization: 'Bearer k-123' } });

    await field(page).fill('uvx mcp-server-fetch');
    const env = rows(page, 'Environment variables');
    await expect(env.getByRole('textbox', { name: 'Name' })).toHaveValue('Authorization');
    await expect(rows(page, 'Headers')).toHaveCount(0);
    await previewButton(page).click();
    await expect.poll(() => seen.previews.length).toBe(2);
    expect(seen.previews[1]).toEqual({ name: 'fetch', command: 'uvx mcp-server-fetch', env: { Authorization: 'Bearer k-123' } });
  });
});

test.describe('A1 axe in the card\'s states (slice: input and described)', () => {
  for (const width of WIDTHS) {
    for (const colorScheme of ['dark', 'light']) {
      test(`${width} px, ${colorScheme}`, async ({ page }) => {
        await page.setViewportSize({ width, height: 900 });
        await page.emulateMedia({ colorScheme });
        await addPage(page, { preview: () => described({ withheld: { env: [], headers: ['Authorization'], oauth: false, secrets: 0, identity_propagation: false, account: false } }) });
        await field(page).fill(HTTPS);
        await card(page).getByRole('button', { name: 'Add a value' }).click();
        expect(await blockingViolations(page, '.add-server'), 'input state').toEqual([]);
        await previewButton(page).click();
        await expect(card(page).getByRole('region', { name: 'Nothing has run yet' })).toBeVisible();
        expect(await blockingViolations(page, '.add-server'), 'described state').toEqual([]);
      });
    }
  }
});

/** A run's 200: `tools` as served, with the preview members a listed answer carries. */
const listedAnswer = (tools, over = {}) => ({
  code: 200,
  body: {
    preview: { ...described().body.preview, stopped: true, truncated: false, elapsed_ms: 1200, package: null, teardown: { ms: 3 }, ...over },
    tools, withheld_tools: [],
  },
});
const tool = (name, cls, selectable = true) => ({ name, description: `${name} does one thing`, class: cls, class_source: 'declared', destructive: false, selectable });
const THREE = [tool('search', 'read'), tool('odd*', 'read', false), tool('delete_record', 'write')];

/** Fill a URL with one Authorization row and reach the described panel. */
async function toDescribed(page, value = 'Bearer k-123') {
  await field(page).fill(HTTPS);
  await card(page).getByRole('button', { name: 'Add a value' }).click();
  await rows(page, 'Headers').getByRole('textbox', { name: 'Name' }).fill('Authorization');
  await rows(page, 'Headers').getByLabel('Value').fill(value);
  await previewButton(page).click();
  await expect(card(page).getByRole('region', { name: 'Nothing has run yet' })).toBeVisible();
}

test.describe('V2 running, then listed (UI4.10)', () => {
  test('a held run shows its words busy and disabled; released, the tools and their classes', async ({ page }) => {
    const hold = gate();
    await addPage(page, { preview: (b) => ('confirm' in b ? { ...listedAnswer(THREE), hold: hold.shut } : described()) });
    await toDescribed(page);
    const start = card(page).getByRole('button', { name: 'Start once' });
    await start.click();
    const panel = card(page).getByRole('region', { name: 'Nothing has run yet' });
    await expect(panel).toHaveAttribute('aria-busy', 'true');
    await expect(panel).toContainText('Starting crm to preview…');
    await expect(start).toBeDisabled();
    hold.open();
    const listed = card(page).getByRole('region', { name: 'Started once: 3 tools took 1.2 s' });
    await expect(listed).toBeVisible();
    const items = listed.getByRole('listitem');
    await expect(items.nth(0)).toContainText('search');
    await expect(items.nth(0)).toContainText('reads');
    await expect(items.nth(0)).not.toContainText('not included');
    await expect(items.nth(1)).toContainText('not included');
    await expect(items.nth(2)).toContainText('writes');
    await expect(items.nth(2)).toContainText('not included');
    await expect(listed.getByRole('button', { name: 'Add crm with 1 tool' })).toBeVisible();
  });
});

test.describe('V3 a failed run shows its cause and Retry (UI4.10)', () => {
  const CASES = [
    [504, 'the server did not answer within 30 s'],
    [502, 'the server could not be started'],
    [422, 'the gateway does not reach that address'],
    [503, 'no confirmation can be issued now'],
    [409, 'the confirmation is invalid, expired or spent'],
  ];
  for (const [code, words] of CASES) {
    test(`a ${code} from the run`, async ({ page }) => {
      const seen = await addPage(page, { preview: (b) => ('confirm' in b ? { code, body: { error: words } } : described()) });
      await toDescribed(page);
      await card(page).getByRole('button', { name: 'Start once' }).click();
      const failed = card(page).getByRole('region', { name: 'The preview did not finish' });
      await expect(failed).toContainText(words);
      await expect(rows(page, 'Headers').getByLabel('Value')).toHaveValue('Bearer k-123');
      await expect(field(page)).toHaveValue(HTTPS);
      await failed.getByRole('button', { name: 'Retry' }).click();
      await expect.poll(() => seen.previews.length).toBe(3);
      expect(seen.previews[2]).not.toHaveProperty('confirm');
    });
  }

  for (const [label, answer] of [['503', { code: 503, body: { error: 'no confirmation can be issued now' } }], ['a dropped connection', { drop: true }]]) {
    test(`the describe step fails on ${label}`, async ({ page }) => {
      await addPage(page, { preview: () => answer });
      await field(page).fill(HTTPS);
      await previewButton(page).click();
      const failed = card(page).getByRole('region', { name: 'The preview did not finish' });
      await expect(failed.getByRole('button', { name: 'Retry' })).toBeVisible();
      await expect(field(page)).toBeEnabled();
      await expect(field(page)).toHaveValue(HTTPS);
    });
  }
});

test.describe('V3e the answers nobody listed', () => {
  for (const code of [403, 400, 429]) {
    test(`a describe answered ${code}`, async ({ page }) => {
      await addPage(page, { preview: () => ({ code, body: { error: `refused with ${code}` } }) });
      await field(page).fill(HTTPS);
      await previewButton(page).click();
      const failed = card(page).getByRole('region', { name: 'The preview did not finish' });
      await expect(failed).toContainText(`refused with ${code}`);
      await expect(failed.getByRole('button', { name: 'Retry' })).toBeVisible();
      await expect(field(page)).toBeEnabled();
      await expect(field(page)).toHaveValue(HTTPS);
    });
  }

  test('a run answered 403', async ({ page }) => {
    await addPage(page, { preview: (b) => ('confirm' in b ? { code: 403, body: { error: 'this key may not preview' } } : described()) });
    await toDescribed(page);
    await card(page).getByRole('button', { name: 'Start once' }).click();
    const failed = card(page).getByRole('region', { name: 'The preview did not finish' });
    await expect(failed).toContainText('this key may not preview');
    await expect(rows(page, 'Headers').getByLabel('Value')).toBeEnabled();
  });
});

test.describe('V6 a preview already running', () => {
  test('the busy sentence and Retry; the spent token is not sent again', async ({ page }) => {
    let tokens = 0;
    const seen = await addPage(page, {
      preview: (b) => {
        if ('confirm' in b) return b.confirm === 'confirm-1' ? { code: 409, body: { error: 'a preview is already running' } } : listedAnswer(THREE);
        tokens += 1;
        return { code: 202, body: { ...described().body, confirm: `confirm-${tokens}` } };
      },
    });
    await toDescribed(page);
    await card(page).getByRole('button', { name: 'Start once' }).click();
    const failed = card(page).getByRole('region', { name: 'The preview did not finish' });
    await expect(failed).toContainText('a preview is already running');
    await failed.getByRole('button', { name: 'Retry' }).click();
    await card(page).getByRole('button', { name: 'Start once' }).click();
    await expect(card(page).getByRole('region', { name: 'Started once: 3 tools took 1.2 s' })).toBeVisible();
    expect(seen.previews.filter((b) => 'confirm' in b).map((b) => b.confirm)).toEqual(['confirm-1', 'confirm-2']);
  });
});

test.describe('K2 the describe names held-back headers; the value is nowhere but its own input', () => {
  test('the name is listed; the value is in no text and no attribute', async ({ page }) => {
    await addPage(page, { preview: () => described({ withheld: { env: [], headers: ['Authorization'], oauth: false, secrets: 0, identity_propagation: false, account: false } }) });
    await toDescribed(page, 'Bearer s3cr3t-held-value');
    await expect(card(page).getByRole('list', { name: 'Held back, not sent' }).getByRole('listitem')).toHaveText(['Authorization']);
    expect(await page.locator('body').innerText()).not.toContain('s3cr3t-held-value');
    expect(await page.evaluate(() => document.documentElement.outerHTML)).not.toContain('s3cr3t-held-value');
    await expect(rows(page, 'Headers').getByLabel('Value')).toHaveAttribute('type', 'password');
    await expect(rows(page, 'Headers').getByLabel('Value')).toHaveValue('Bearer s3cr3t-held-value');
  });
});

test.describe('K3 names used twice, and a value with no name, are refused before any request', () => {
  const CASES = [
    ['uvx mcp-server-fetch', 'Environment variables', [['TOKEN', 'a'], ['TOKEN', 'b']], 'This name is used twice.'],
    [HTTPS, 'Headers', [['Authorization', 'a'], ['authorization', 'b']], 'This name is used twice.'],
    [HTTPS, 'Headers', [['Authorization', 'a'], ['', 'b']], 'Give this value a name.'],
  ];
  for (const [text, label, pairs, words] of CASES) {
    test(`${label}: ${pairs.map(([n]) => n || '(no name)').join(' + ')}`, async ({ page }) => {
      const seen = await addPage(page, { preview: () => described() });
      await field(page).fill(text);
      for (const [n, v] of pairs) {
        await card(page).getByRole('button', { name: 'Add a value' }).click();
        await rows(page, label).getByRole('textbox', { name: 'Name' }).last().fill(n);
        await rows(page, label).getByLabel('Value').last().fill(v);
      }
      await previewButton(page).click();
      await expect(rows(page, label).locator('.add-row').nth(1)).toContainText(words);
      await page.waitForTimeout(300);
      expect(seen.previews).toHaveLength(0);
    });
  }
});

test.describe('K4 a changed input throws the preview away', () => {
  const ONE = [tool('search', 'read')];

  test('a new field value drops the tools and the panel; the next describe carries no token', async ({ page }) => {
    const seen = await addPage(page, { preview: (b) => ('confirm' in b ? listedAnswer(ONE) : described()) });
    await field(page).fill(HTTPS);
    await previewButton(page).click();
    await card(page).getByRole('button', { name: 'Start once' }).click();
    await expect(card(page).getByRole('button', { name: 'Add crm with 1 tool' })).toBeVisible();
    await field(page).fill('https://billing.lan/mcp');
    await expect(card(page).getByRole('region', { name: /Started once/ })).toHaveCount(0);
    await expect(card(page).getByRole('button', { name: /^Add billing/ })).toHaveCount(0);
    await expect(previewButton(page)).toBeVisible();
    await previewButton(page).click();
    await expect.poll(() => seen.previews.length).toBe(3);
    expect(seen.previews[2]).toEqual({ name: 'billing', url: 'https://billing.lan/mcp' });
  });

  test('an edit of the name by hand, or of a row, returns the card to its input state', async ({ page }) => {
    await addPage(page, { preview: (b) => ('confirm' in b ? listedAnswer(ONE) : described()) });
    await toDescribed(page);
    await rows(page, 'Headers').getByLabel('Value').fill('Bearer other');
    await expect(card(page).getByRole('region', { name: 'Nothing has run yet' })).toHaveCount(0);
    await expect(previewButton(page)).toBeVisible();
    await previewButton(page).click();
    await card(page).getByRole('button', { name: 'Change' }).click();
    await expect(card(page).getByRole('region', { name: 'Nothing has run yet' })).toBeVisible();
    await card(page).getByRole('textbox', { name: 'Name', exact: true }).fill('crm-two');
    await expect(card(page).getByRole('region', { name: 'Nothing has run yet' })).toHaveCount(0);
  });

  test('while a run is held, the field, the name control and the rows are disabled', async ({ page }) => {
    const hold = gate();
    await addPage(page, { preview: (b) => ('confirm' in b ? { ...listedAnswer(ONE), hold: hold.shut } : described()) });
    await toDescribed(page);
    await card(page).getByRole('button', { name: 'Start once' }).click();
    await expect(field(page)).toBeDisabled();
    await expect(card(page).getByRole('button', { name: 'Change' })).toBeDisabled();
    await expect(rows(page, 'Headers').getByRole('textbox', { name: 'Name' })).toBeDisabled();
    await expect(rows(page, 'Headers').getByLabel('Value')).toBeDisabled();
    hold.open();
    await expect(field(page)).toBeEnabled();
  });

  test('the server\'s own name keeps the tool list, and the add button carries the new name', async ({ page }) => {
    await addPage(page, { preview: (b) => ('confirm' in b ? listedAnswer(ONE, { package: { name: 'crm-suite', version: '2.1.0' } }) : described()) });
    await field(page).fill(HTTPS);
    await previewButton(page).click();
    await card(page).getByRole('button', { name: 'Start once' }).click();
    await expect(card(page).getByRole('region', { name: /Started once: 1 tool/ })).toBeVisible();
    await expect(card(page).getByRole('button', { name: 'Add crm-suite with 1 tool' })).toBeVisible();
  });
});

/** The add's 201 as add_backend serves it (BK:265-276), with `over` merged in. */
const created = (name, over = {}) => ({ code: 201, body: { status: 'created', name, reload: { changes: `added backends: [${name}]`, restart_required: false }, notes: [], enabled: true, secrets_stored: [], ...over } });

/** Preview to the tool list with THREE (one selectable reading tool), the add answering `add`. */
async function toListed(page, add, text = HTTPS) {
  const seen = await addPage(page, { preview: (b) => ('confirm' in b ? listedAnswer(THREE) : described()), add });
  await field(page).fill(text);
  await previewButton(page).click();
  await card(page).getByRole('button', { name: 'Start once' }).click();
  await expect(card(page).getByRole('region', { name: /Started once/ })).toBeVisible();
  return seen;
}

test.describe('D1 the add sends the reading tools and lands with the notice (UI4.2)', () => {
  test('allowed_tools is the selectable reading tools; the address encodes the name', async ({ page }) => {
    await recordAnnouncements(page);
    const seen = await toListed(page, (b) => created(b.name));
    await card(page).getByRole('button', { name: 'Change' }).click();
    await card(page).getByRole('textbox', { name: 'Name', exact: true }).fill('crm/a b');
    await previewButton(page).click();
    await card(page).getByRole('button', { name: 'Start once' }).click();
    await card(page).getByRole('button', { name: 'Add crm/a b with 1 tool' }).click();
    await expect(page).toHaveURL('/ui/servers/crm%2Fa%20b/status');
    expect(seen.adds).toEqual([{ name: 'crm/a b', url: HTTPS, allowed_tools: ['search'] }]);
    const notice = page.locator('.done-notice');
    await expect(notice.locator('.done-title')).toHaveText('✓ crm/a b added with 1 tool.');
    await expect(notice.locator('.done-title')).toBeFocused();
    await expect.poll(async () => (await announced(page)).filter((t) => t.includes('added with 1 tool')).length).toBe(1);
  });

  for (const [label, over, words] of [
    ['one stored value', { secrets_stored: ['Authorization'] }, '✓ crm added with 1 tool. 1 value is kept in the secret store.'],
    ['a note holding markup', { notes: ['<b>reload</b> pending'] }, '✓ crm added with 1 tool. <b>reload</b> pending'],
  ]) {
    test(`the notice with ${label}`, async ({ page }) => {
      await toListed(page, (b) => created(b.name, over));
      await card(page).getByRole('button', { name: 'Add crm with 1 tool' }).click();
      await expect(page.locator('.done-notice .done-title')).toHaveText(words);
      await expect(page.locator('.done-notice b')).toHaveCount(0);
    });
  }
});

test.describe('D2 D3 a refused or unconfirmed add', () => {
  test('D2 a duplicate name is told at the Name, which opens for editing', async ({ page }) => {
    await toListed(page, () => ({ code: 409, body: { error: "Backend 'crm' already exists" } }));
    await card(page).getByRole('button', { name: 'Add crm with 1 tool' }).click();
    await expect(card(page)).toContainText("Backend 'crm' already exists");
    await expect(card(page).getByRole('textbox', { name: 'Name', exact: true })).toBeFocused();
  });

  for (const [label, answer] of [['a 500', { code: 500, body: { error: 'write failed' } }], ['a dropped connection', { drop: true }]]) {
    test(`D3 ${label}: not confirmed, with Retry and every value kept`, async ({ page }) => {
      const seen = await toListed(page, () => answer);
      await card(page).getByRole('button', { name: 'Add crm with 1 tool' }).click();
      const panel = card(page).getByRole('region', { name: 'Not confirmed' });
      await expect(panel).toContainText('The gateway did not confirm the add.');
      await expect(field(page)).toHaveValue(HTTPS);
      await panel.getByRole('button', { name: 'Retry' }).click();
      await expect.poll(() => seen.adds.length).toBe(2);
    });
  }
});

test.describe('E1 typed values are sent and never left on the page', () => {
  test('before the add the value input is a password; after the 201 no element holds it', async ({ page }) => {
    await addPage(page, { preview: () => ({ code: 422, body: { error: 'Preview refused. You can still add this server.' } }), add: (b) => created(b.name) });
    await field(page).fill(HTTPS);
    await card(page).getByRole('button', { name: 'Add a value' }).click();
    await rows(page, 'Headers').getByRole('textbox', { name: 'Name' }).fill('Authorization');
    await rows(page, 'Headers').getByLabel('Value').fill('Bearer e1-only-here');
    await expect(rows(page, 'Headers').getByLabel('Value')).toHaveAttribute('type', 'password');
    await previewButton(page).click();
    await card(page).getByRole('button', { name: 'Add without a preview' }).click();
    await expect(page).toHaveURL('/ui/servers/crm/status');
    const held = await page.evaluate(() => [...document.querySelectorAll('input')].some((i) => i.value.includes('e1-only-here'))
      || document.documentElement.outerHTML.includes('e1-only-here'));
    expect(held).toBe(false);
  });
});

test.describe('V4 a refused preview still lets the server be added', () => {
  test('the sentence and "Add without a preview"; the add carries no allowed_tools', async ({ page }) => {
    const words = 'Command servers cannot be previewed yet. You can still add this server.';
    const seen = await addPage(page, { preview: () => ({ code: 422, body: { error: words } }), add: (b) => created(b.name) });
    await field(page).fill('uvx mcp-server-fetch');
    await previewButton(page).click();
    await expect(card(page)).toContainText(words);
    await card(page).getByRole('button', { name: 'Add without a preview' }).click();
    await expect.poll(() => seen.adds.length).toBe(1);
    expect(seen.adds[0]).toEqual({ name: 'fetch', command: 'uvx mcp-server-fetch' });
    await expect(page.locator('.done-notice .done-title')).toHaveText('✓ fetch added.');
  });
});

test.describe('V3b a failed preview of a server with held-back values can still be added', () => {
  const heldBack = () => described({ withheld: { env: [], headers: ['Authorization'], oauth: false, secrets: 0, identity_propagation: false, account: false } });

  test('a 502 after a describe that held a header back: the line, Retry and "Add without a preview"', async ({ page }) => {
    const seen = await addPage(page, { preview: (b) => ('confirm' in b ? { code: 502, body: { error: 'the server refused to start' } } : heldBack()), add: (b) => created(b.name) });
    const { words } = await addWords(page);
    await toDescribed(page);
    await card(page).getByRole('button', { name: 'Start once' }).click();
    const failed = card(page).getByRole('region', { name: 'The preview did not finish' });
    await expect(failed).toContainText('the server refused to start');
    await expect(failed).toContainText(words.ranWithout);
    await expect(failed.getByRole('button', { name: 'Retry' })).toBeVisible();
    await failed.getByRole('button', { name: 'Add without a preview' }).click();
    await expect.poll(() => seen.adds.length).toBe(1);
    expect(seen.adds[0]).toEqual({ name: 'crm', url: HTTPS, headers: { Authorization: 'Bearer k-123' } });
  });

  test('control: the same 502 after a describe that held nothing back offers Retry only', async ({ page }) => {
    await addPage(page, { preview: (b) => ('confirm' in b ? { code: 502, body: { error: 'the server refused to start' } } : described()) });
    await field(page).fill(HTTPS);
    await previewButton(page).click();
    await card(page).getByRole('button', { name: 'Start once' }).click();
    const failed = card(page).getByRole('region', { name: 'The preview did not finish' });
    await expect(failed.getByRole('button', { name: 'Retry' })).toBeVisible();
    await expect(failed.getByRole('button', { name: 'Add without a preview' })).toHaveCount(0);
  });

  test('a later preview of other input reads its own withheld lists, not the earlier one', async ({ page }) => {
    let n = 0;
    await addPage(page, { preview: (b) => { if ('confirm' in b) return { code: 502, body: { error: 'no start' } }; n += 1; return n === 1 ? heldBack() : described(); } });
    await toDescribed(page);
    await rows(page, 'Headers').getByRole('textbox', { name: 'Name' }).fill('');
    await rows(page, 'Headers').getByLabel('Value').fill('');
    await previewButton(page).click();
    await card(page).getByRole('button', { name: 'Start once' }).click();
    const failed = card(page).getByRole('region', { name: 'The preview did not finish' });
    await expect(failed.getByRole('button', { name: 'Retry' })).toBeVisible();
    await expect(failed.getByRole('button', { name: 'Add without a preview' })).toHaveCount(0);
  });

  for (const [code, words] of [[409, 'a preview is already running'], [503, 'no confirmation can be issued now'], [422, 'the gateway does not reach that address']]) {
    test(`V3e a ${code} after a held-back describe shows neither the line nor the button`, async ({ page }) => {
      await addPage(page, { preview: (b) => ('confirm' in b ? { code, body: { error: words } } : heldBack()) });
      const { words: w } = await addWords(page);
      await toDescribed(page);
      await card(page).getByRole('button', { name: 'Start once' }).click();
      const failed = card(page).getByRole('region', { name: 'The preview did not finish' });
      await expect(failed).toContainText(words);
      await expect(failed).not.toContainText(w.ranWithout);
      await expect(failed.getByRole('button', { name: 'Add without a preview' })).toHaveCount(0);
    });
  }
});

const PLAIN = 'http://crm.lan:8080/mcp';
const NO_PREVIEW = { code: 422, body: { error: 'Preview refused. You can still add this server.' } };
const cleartext = (over = {}) => ({ code: 422, body: { error: 'cleartext_credentials', message: '<i>planted</i> cause', fix: '<b>planted</b> fix', ...over } });

/** A plain-http URL with one Authorization row, added without a preview; `add(body, n)` answers each add. */
async function toRefused(page, add, text = PLAIN) {
  let refusalsRead = 0;
  await page.route('**/ui/api/refusals**', (route) => { refusalsRead += 1; return route.fulfill({ status: 200, json: { refusals: [] } }); });
  const seen = await addPage(page, { preview: () => NO_PREVIEW, add });
  await field(page).fill(text);
  await card(page).getByRole('button', { name: 'Add a value' }).click();
  await rows(page, 'Headers').getByRole('textbox', { name: 'Name' }).fill('Authorization');
  await rows(page, 'Headers').getByLabel('Value').fill('Bearer x1');
  await previewButton(page).click();
  await card(page).getByRole('button', { name: 'Add without a preview' }).click();
  seen.refusalsRead = () => refusalsRead;
  return seen;
}
const dialog = (page) => page.locator('dialog.confirm');

test.describe('X1 the plain-http refusal shows the gateway\'s cause and fix (UI4.2)', () => {
  test('cause and fix as text; Try https rewrites the field only; no refusals read', async ({ page }) => {
    const seen = await toRefused(page, () => cleartext());
    const notAdded = card(page).getByRole('region', { name: 'Not added' });
    await expect(notAdded).toContainText('<i>planted</i> cause');
    await expect(notAdded).toContainText('Fix: <b>planted</b> fix');
    await expect(notAdded.locator('i, b')).toHaveCount(0);
    await expect(notAdded.getByRole('button', { name: 'Send unencrypted anyway…' })).toBeVisible();
    expect(seen.adds[0]).not.toHaveProperty('allow_cleartext_credentials');
    await notAdded.getByRole('button', { name: 'Try https://crm.lan:8080' }).click();
    await expect(field(page)).toHaveValue('https://crm.lan:8080/mcp');
    await expect(field(page)).toBeFocused();
    expect(seen.adds).toHaveLength(1);
    expect(seen.refusalsRead()).toBe(0);
  });

  test('without a fix: the cause alone, and both buttons', async ({ page }) => {
    await toRefused(page, () => cleartext({ fix: undefined }));
    const notAdded = card(page).getByRole('region', { name: 'Not added' });
    await expect(notAdded).toContainText('<i>planted</i> cause');
    await expect(notAdded).not.toContainText('Fix:');
    await expect(notAdded.getByRole('button', { name: 'Try https://crm.lan:8080' })).toBeVisible();
    await expect(notAdded.getByRole('button', { name: 'Send unencrypted anyway…' })).toBeVisible();
  });

  test('a ws URL is offered wss', async ({ page }) => {
    await toRefused(page, () => cleartext(), 'ws://stream.lan:9000/ws');
    await expect(card(page).getByRole('button', { name: 'Try wss://stream.lan:9000' })).toBeVisible();
  });
});

test.describe('X2 Override goes through the confirm (UI4.2)', () => {
  test('the five consequences; Cancel sends nothing; confirming sends the flag once, with the same headers', async ({ page }) => {
    const seen = await toRefused(page, (b, n) => (n === 1 ? cleartext() : created(b.name)));
    const w = await addWords(page, 'crm.lan:8080');
    const override = card(page).getByRole('button', { name: 'Send unencrypted anyway…' });
    await override.click();
    await expect(dialog(page).locator('li')).toHaveText(w.override);
    await dialog(page).getByRole('button', { name: 'Cancel crm' }).click();
    await expect(dialog(page)).toHaveCount(0);
    await expect(override).toBeFocused();
    expect(seen.adds).toHaveLength(1);
    await override.click();
    await dialog(page).getByRole('button', { name: `${w.words.overrideVerb} crm` }).click();
    await expect(page).toHaveURL('/ui/servers/crm/status');
    await expect(page.locator('.done-notice .done-title')).toHaveText('✓ crm added.');
    expect(seen.adds).toHaveLength(2);
    expect(seen.adds[1]).toEqual({ name: 'crm', url: PLAIN, headers: { Authorization: 'Bearer x1' }, allow_cleartext_credentials: true });
    expect(seen.adds.filter((b) => 'allow_cleartext_credentials' in b)).toHaveLength(1);
  });

  test('a refusal inside the dialog shows the gateway\'s sentence; in progress first', async ({ page }) => {
    const hold = gate();
    await toRefused(page, (b, n) => (n === 1 ? cleartext() : { code: 422, body: { error: 'that host is not allowed' }, hold: hold.shut }));
    const w = await addWords(page, 'crm.lan:8080');
    await card(page).getByRole('button', { name: 'Send unencrypted anyway…' }).click();
    await dialog(page).getByRole('button', { name: `${w.words.overrideVerb} crm` }).click();
    await expect(dialog(page).locator('.confirm-progress')).toHaveText(w.progress);
    hold.open();
    await expect(dialog(page)).toContainText('that host is not allowed');
  });
});

test.describe('X3 by-field refusals land at their input', () => {
  /** [reason, field, the input the sentence belongs to: field | rows | row, the text typed] */
  const CASES = [
    ['secret_in_url', 'url', 'field', HTTPS],
    ['secret_in_command', 'command', 'field', 'uvx mcp-server-fetch'],
    ['header_name', 'headers', 'rows', HTTPS],
    ['header_value', 'headers.Authorization', 'row', HTTPS],
    ['headers_need_url', 'headers', 'rows', HTTPS],
    ['url_invalid', 'url', 'field', HTTPS],
    ['a_code_nobody_listed', 'url', 'field', HTTPS],
    ['header_value', 'headers.X-Missing', 'rows', HTTPS],
  ];
  for (const [reason, at, where, text] of CASES) {
    test(`${reason} at ${at}`, async ({ page }) => {
      await addPage(page, { preview: () => NO_PREVIEW, add: () => ({ code: 422, body: { error: 'literal_in_value', refusals: [{ reason, field: at }] } }) });
      const w = await addWords(page);
      await field(page).fill(text);
      if (where !== 'field' || text === HTTPS) {
        await card(page).getByRole('button', { name: 'Add a value' }).click();
        const label = kindIsUrl(text) ? 'Headers' : 'Environment variables';
        await rows(page, label).getByRole('textbox', { name: 'Name' }).fill('Authorization');
        await rows(page, label).getByLabel('Value').fill('Bearer x3');
      }
      await previewButton(page).click();
      await card(page).getByRole('button', { name: 'Add without a preview' }).click();
      const words = w.field[reason] ?? w.other;
      const shown = card(page).locator('p.add-err:not([hidden])');
      await expect(shown).toHaveText([words]);
      const id = await shown.getAttribute('id');
      expect(id.endsWith({ field: '-field-err', rows: '-rows-err', row: '-r1-err' }[where]), id).toBe(true);
      expect(await page.locator('body').innerText()).not.toContain('literal_in_value');
      expect(await page.locator('body').innerText()).not.toContain(reason);
    });
  }
});
const kindIsUrl = (text) => /^(https?|wss?):\/\//.test(text);
