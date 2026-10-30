// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The harness's own checks: the fixture server answers like the gateway, the
// network is closed, and axe runs. Screen behaviour lives in its own specs.
import { test, expect, WIDTHS, blockingViolations } from './base.mjs';
import { fileURLToPath } from 'node:url';

test('the fixture server answering is this worktree\'s own, never another lane\'s left on the port', async ({ request }) => {
  const reply = await request.get('/ui/classic');
  expect(reply.headers()['x-fixture-root']).toBe(fileURLToPath(new URL('..', import.meta.url)).replace(/\/$/, ''));
});

test('a deep link answers the shell document with the gateway CSP', async ({ request }) => {
  const reply = await request.get('/ui/servers/status', { maxRedirects: 0 });
  expect(reply.status()).toBe(200);
  const csp = reply.headers()['content-security-policy'];
  expect(csp).toContain("default-src 'none'");
  expect(csp).toContain("script-src 'self'");
  expect(csp).not.toContain('\\');
  expect(reply.headers()['cache-control']).toContain('no-store');
  expect(reply.headers()['x-content-type-options']).toBe('nosniff');
  expect(reply.headers()['referrer-policy']).toBe('no-referrer');
});

test('a fixture under fixtures/api answers as JSON', async ({ request }) => {
  const reply = await request.get('/ui/api/status');
  expect(reply.status()).toBe(200);
  expect(reply.headers()['content-type']).toBe('application/json');
  expect((await reply.json()).auth).toEqual({ enabled: true, signed_in: true, admin: true });
});

test('another method on the classic routes answers 405, as axum does', async ({ request }) => {
  for (const path of ['/ui', '/ui/classic']) {
    expect((await request.post(path)).status(), path).toBe(405);
  }
});

test('api and asset paths outside the fixtures answer 404, never the shell', async ({ request }) => {
  for (const path of ['/ui/api/nope', '/ui/api', '/ui/assets', '/ui/assets/nope.css', '/ui/assets/a/b', '/ui/']) {
    expect((await request.get(path)).status(), path).toBe(404);
  }
});

test('every asset the shell document names is served, cached immutable', async ({ page, request }) => {
  const doc = await (await request.get('/ui/overview')).text();
  const refs = [...doc.matchAll(/(?:href|src)="(\/ui\/assets\/[^"]+)"/g)].map((m) => m[1]);
  expect(refs.length).toBeGreaterThan(0);
  for (const ref of refs) {
    const reply = await request.get(ref);
    expect(reply.status(), ref).toBe(200);
    expect(reply.headers()['cache-control'], ref).toContain('immutable');
  }
  // In the browser too: no asset request may fail, with or without a response.
  const failed = [];
  const asset = (url) => new URL(url).pathname.startsWith('/ui/assets/');
  page.on('requestfailed', (r) => { if (asset(r.url())) failed.push(`failed ${r.url()}`); });
  page.on('response', (r) => { if (asset(r.url()) && r.status() >= 400) failed.push(`${r.status()} ${r.url()}`); });
  // The fixture stream is held open by default and would keep the network busy;
  // a 404 is retried only at the 30 s ceiling, so the network goes idle.
  await page.route('**/ui/api/stream', (r) => r.fulfill({ status: 404, body: '' }));
  await page.goto('/ui/overview');
  await page.waitForLoadState('networkidle');
  expect(failed).toEqual([]);
});

test('the network guard is on in a test that does not ask for it', async ({ page }) => {
  // The guard's own error, not a DNS failure, which would pass without it.
  const errors = [];
  page.on('requestfailed', (r) => errors.push(r.failure()?.errorText));
  await page.goto('/ui/classic');
  await page.evaluate(() => fetch('https://example.invalid/y').catch(() => null));
  expect(errors).toHaveLength(1);
  expect(errors[0]).toMatch(/^net::ERR_BLOCKED_BY_CLIENT/);
});

test('a request to another host is aborted and recorded', async ({ page, offsite }) => {
  await page.goto('/ui/classic');
  await page.evaluate(() => fetch('https://example.invalid/x').catch(() => null));
  expect(offsite).toEqual(['https://example.invalid/x']);
});

for (const width of WIDTHS) {
  test(`axe finds no blocking violation on the classic stand-in at ${width} px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto('/ui/classic');
    expect(await blockingViolations(page)).toEqual([]);
  });
}

test('the axe gate goes red on a page with a blocking violation', async ({ page }) => {
  await page.goto('/ui/classic');
  await page.setContent('<html><body><button></button><p style="color:#777;background:#888">low contrast</p></body></html>');
  const found = await blockingViolations(page);
  expect(found.some((v) => v.startsWith('button-name'))).toBe(true);
  expect(found.some((v) => v.startsWith('color-contrast'))).toBe(true);
});
