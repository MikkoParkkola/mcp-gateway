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
import { entry, fullView, fakeServerGateway } from './server-page.mjs';

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
