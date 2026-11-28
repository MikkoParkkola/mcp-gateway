// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Servers › Settings at the list level: the "Add a server" card in its
// "Command or URL" mode. Start-once preview (described, running, listed,
// failed), the add, the refusal with its fix and the Override confirm. Rows are
// named after the frozen test plan (V, N, K, E, D, X, U, A); every gateway answer
// is a literal written here, in the shapes preview.rs and add_checks.rs serve.
import { test, expect, blockingViolations, WIDTHS } from './base.mjs';
import { shellReady } from './shell.mjs';
import { entry, fullView, fakeServerGateway, gate } from './server-page.mjs';
import { readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

/** The card module's served path, read from the shell directory (its name carries its hash). */
const ADD_MODULE = (() => {
  const dir = fileURLToPath(new URL('../../src/gateway/ui/shell/', import.meta.url));
  return `/ui/assets/${readdirSync(dir).find((f) => /^server-add\.[0-9a-f]{12}\.js$/.test(f))}`;
})();

/** The card's own sentences, read from its module in the page (lead ruling 2026-11-27: written once, there). */
const addWords = (page) => page.evaluate(async (u) => {
  const m = await import(u);
  return { field: m.FIELD_WORDS, other: m.OTHER_FIELD_WORDS, words: m.WORDS };
}, ADD_MODULE);

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
    await card(page).getByRole('textbox', { name: 'Name' }).fill('crm-prod');
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
    await card(page).getByRole('textbox', { name: 'Name' }).fill('crm-prod');
    await previewButton(page).click();
    await card(page).getByRole('button', { name: 'Start once' }).click();
    await expect(card(page).getByText('Started once: 0 tools took 0.9 s')).toBeVisible();
    await expect(card(page).getByRole('textbox', { name: 'Name' })).toHaveValue('crm-prod');
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
