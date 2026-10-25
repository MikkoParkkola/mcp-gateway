// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The harness's own checks: the fixture server answers like the gateway, the
// network is closed, and axe runs. Screen behaviour lives in its own specs.
import { test, expect, WIDTHS, blockingViolations } from './base.mjs';

test('a deep link answers the shell document with the gateway CSP', async ({ request }) => {
  const reply = await request.get('/ui/servers/status', { maxRedirects: 0 });
  expect(reply.status()).toBe(200);
  const csp = reply.headers()['content-security-policy'];
  expect(csp).toContain("default-src 'none'");
  expect(csp).toContain("script-src 'self'");
  expect(csp).not.toContain('\\');
  expect(reply.headers()['cache-control']).toContain('no-store');
});

test('api and asset paths outside the fixtures answer 404, never the shell', async ({ request }) => {
  for (const path of ['/ui/api/nope', '/ui/api', '/ui/assets/nope.css', '/ui/assets/a/b', '/ui/']) {
    expect((await request.get(path)).status(), path).toBe(404);
  }
});

test('every asset the shell document names is served', async ({ page }) => {
  const failed = [];
  page.on('response', (r) => { if (r.status() >= 400) failed.push(`${r.status()} ${r.url()}`); });
  await page.goto('/ui/overview');
  await page.waitForLoadState('networkidle');
  expect(failed).toEqual([]);
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
