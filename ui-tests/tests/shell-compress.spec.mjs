// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// First paint on a slow link: the fixture server compresses by the gateway's
// one rule (src/gateway/ui/compression.json), the document inlines the shell's
// frame CSS under a hashed CSP (src/gateway/ui/csp.golden), the rest of the
// stylesheet changes nothing in the frame, and the shell's boot reads wait for
// the first paint.
import { request as httpRequest } from 'node:http';
import { gunzipSync } from 'node:zlib';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { test, expect } from './base.mjs';
import { PAGES, shellReady } from './shell.mjs';

const PORT = Number(process.env.UI_TESTS_PORT ?? 4173);
const UI = fileURLToPath(new URL('../../src/gateway/ui/', import.meta.url));
const CONTRACT = JSON.parse(readFileSync(`${UI}compression.json`, 'utf8'));
const GOLDEN = readFileSync(`${UI}csp.golden`, 'utf8').trimEnd();

/** Whether the contract compresses a body of this type and length. */
function gzips(type, len) {
  const never = CONTRACT.never_prefixes.some((p) => type.startsWith(p)) && !CONTRACT.except_types.some((e) => type.startsWith(e));
  return len >= CONTRACT.min_bytes && !never;
}

/** One raw GET, bytes as sent: the browser and Playwright's request both decode gzip. */
function raw(path, headers = {}) {
  return new Promise((done, fail) => {
    const req = httpRequest({ host: '127.0.0.1', port: PORT, path, headers }, (res) => {
      const parts = [];
      res.on('data', (c) => parts.push(c));
      res.on('end', () => done({ status: res.statusCode, headers: res.headers, body: Buffer.concat(parts) }));
    });
    req.on('error', fail);
    req.end();
  });
}

const decoded = (r) => (r.headers['content-encoding'] === 'gzip' ? gunzipSync(r.body) : r.body);

/** Every hashed shell asset, by its served path. */
function assetPaths() {
  const out = [];
  for (const dir of ['shell', 'shell/fonts']) {
    for (const f of readdirSync(`${UI}${dir}`)) {
      if (/\.[0-9a-f]{12}\.\w+$/.test(f)) out.push(`/ui/assets/${f}`);
    }
  }
  return out;
}

test.describe('compression', () => {
  test('Z1 the pages and every asset gzip when asked, decode to the plain bytes, and are plain otherwise', async () => {
    const paths = ['/ui', '/ui/classic', '/ui/overview/status', ...assetPaths()];
    expect(paths.some((p) => p.endsWith('.woff2'))).toBe(true);
    for (const path of paths) {
      const plain = await raw(path);
      expect(plain.status, path).toBe(200);
      expect(plain.headers['content-encoding'], `${path} unasked`).toBeUndefined();
      const asked = await raw(path, { 'accept-encoding': 'gzip' });
      const want = gzips(asked.headers['content-type'] ?? '', plain.body.length);
      if (!path.endsWith('.woff2')) expect(want, `${path} is compressible by the contract`).toBe(true);
      expect(asked.headers['content-encoding'], `${path} asked`).toBe(want ? 'gzip' : undefined);
      if (want) expect(asked.headers.vary ?? '', path).toMatch(/accept-encoding/i);
      expect(decoded(asked).equals(plain.body), `${path} decodes to the plain bytes`).toBe(true);
    }
  });

  test('Z2 a /ui/api JSON answer is gzip when asked', async () => {
    const asked = await raw('/ui/api/status', { 'accept-encoding': 'gzip' });
    expect(asked.status).toBe(200);
    expect(asked.headers['content-encoding']).toBe('gzip');
    expect(JSON.parse(decoded(asked).toString('utf8')).auth).toBeTruthy();
  });

  test('Z2 the live stream is never compressed: an event over the threshold arrives as text', async () => {
    const ch = `gz-${Date.now()}`;
    const event = `event: hello\ndata: ${'x'.repeat(CONTRACT.min_bytes * 2)}\n\n`;
    const first = await new Promise((done, fail) => {
      const req = httpRequest({ host: '127.0.0.1', port: PORT, path: '/ui/api/stream', headers: { 'accept-encoding': 'gzip', cookie: `fixture-stream=${ch}` } }, (res) => {
        res.once('data', (chunk) => { done({ status: res.statusCode, headers: res.headers, chunk }); req.destroy(); });
        const send = httpRequest({ host: '127.0.0.1', port: PORT, path: `/__stream/${ch}/send`, method: 'POST' });
        send.on('error', fail);
        send.end(event);
      });
      req.on('error', (e) => (e.code === 'ECONNRESET' ? null : fail(e)));
      req.end();
    });
    expect(first.status).toBe(200);
    expect(first.headers['content-type']).toMatch(/^text\/event-stream/);
    expect(first.headers['content-encoding']).toBeUndefined();
    expect(first.chunk.toString('utf8')).toBe(event);
  });

  test('Z3 the fixture applies the contract on its boundary cases', async () => {
    const cases = [
      ['text/plain', CONTRACT.min_bytes - 1], ['text/plain', CONTRACT.min_bytes], ['text/html; charset=utf-8', 100],
      ['application/json', 100], ['image/png', 100], ['image/svg+xml', 100], ['text/event-stream; charset=utf-8', 100],
      ['application/grpc', 100], ['application/grpc-web', 100], ['font/woff2', 100],
      ...[...CONTRACT.never_prefixes, ...CONTRACT.except_types].map((t) => [`${t}x`, 100]),
    ];
    for (const [type, len] of cases) {
      const r = await raw(`/__compression?type=${encodeURIComponent(type)}&len=${len}`, { 'accept-encoding': 'gzip' });
      expect(r.status, type).toBe(200);
      expect(r.headers['content-encoding'] === 'gzip', `${type}, ${len} bytes`).toBe(gzips(type, len));
      expect(decoded(r).toString(), type).toBe('a'.repeat(len));
    }
  });

  test('Z4 the fixture negotiates Accept-Encoding as the contract rows say, q-values included', async () => {
    expect(CONTRACT.negotiation.length).toBeGreaterThanOrEqual(10);
    for (const { accept_encoding: accept, gzip } of CONTRACT.negotiation) {
      const r = await raw('/ui/overview/status', { 'accept-encoding': accept });
      expect(r.status, accept).toBe(200);
      expect(r.headers['content-encoding'] === 'gzip', `Accept-Encoding: ${accept}`).toBe(gzip);
      expect(decoded(r).toString(), accept).toContain('<style id="frame">');
    }
  });
});

test.describe('inlined frame', () => {
  test('Z5 the fixture sends the gateway policy, exactly as csp.golden holds it', async () => {
    const r = await raw('/ui/overview/status');
    expect(r.headers['content-security-policy']).toBe(GOLDEN);
    expect(GOLDEN).not.toContain('unsafe');
    expect(GOLDEN).toMatch(/style-src 'self' 'sha256-[A-Za-z0-9+/]{43}='/);
  });

  test('Z5 the frame paints under the policy with no violation', async ({ page }) => {
    await page.addInitScript(() => {
      window.__violations = [];
      document.addEventListener('securitypolicyviolation', (e) => window.__violations.push(`${e.violatedDirective} ${e.blockedURI}`));
    });
    await page.goto('/ui/overview/status');
    await shellReady(page);
    expect(await page.evaluate(() => window.__violations)).toEqual([]);
    expect(await page.locator('style#frame').count()).toBe(1);
    // A rule only the frame has: the page grid.
    expect(await page.evaluate(() => getComputedStyle(document.body).display)).toBe('flex');
  });
});

// The frame's elements, compared with and without the rest of the stylesheet.
const FRAME = ['.side', '.brand', 'nav.route-nav', 'nav.route-nav a', '.main', 'header.top', '.top .menu', '.top .mbrand',
  '.top .search', '.top .who', '.top .stream', '.head', '.plate', 'nav.tabs', 'nav.tabs a', 'a.skip', '#content'];

/** Boxes, colours, font families and visibility of the frame, once fonts settle. */
async function frameLook(page, selectors = FRAME) {
  return page.evaluate(async (selectors) => {
    await document.fonts.ready;
    await new Promise((ok) => requestAnimationFrame(() => requestAnimationFrame(ok)));
    const out = {};
    for (const sel of selectors) {
      out[sel] = [...document.querySelectorAll(sel)].map((el) => {
        const r = el.getBoundingClientRect();
        const s = getComputedStyle(el);
        return [r.x, r.y, r.width, r.height].map((n) => Math.round(n * 2) / 2).join(',')
          + ` ${s.color} ${s.backgroundColor} ${s.fontFamily} ${s.fontSize} ${s.visibility} ${s.display}`;
      });
    }
    return out;
  }, selectors);
}

async function splitGuard(page, selectors = FRAME, ready = shellReady) {
  await page.goto('/ui/overview/status');
  await ready(page);
  const rest = page.locator('link[rel="stylesheet"][href^="/ui/assets/shell."]');
  await expect(rest).toHaveCount(1);
  const styled = await frameLook(page, selectors);
  expect(Object.values(styled).flat().length).toBeGreaterThan(10);
  await rest.evaluate((link) => { link.disabled = true; });
  expect(await frameLook(page, selectors), 'the frame looks the same without the rest of the stylesheet').toEqual(styled);
}

/** Signed in as an admin with decisions waiting: the sign-out button and the count badge show. */
async function signedInWithCount(page) {
  await page.route('**/ui/api/status', (r) => r.fulfill({ json: { auth: { enabled: true, signed_in: true, admin: true } } }));
  await page.route('**/ui/api/decisions/count', (r) => r.fulfill({ json: { count: 3 } }));
}

async function signedInReady(page) {
  await shellReady(page);
  await expect(page.locator('.top .signout')).toBeVisible();
  await expect(page.locator(COUNT_BADGE)).toHaveText('3');
}

// The frame's top bar and nav once they hold the signed-in controls: the sign-out button
// (a .btn) and the count badge with its words for screen readers.
const SIGNED_IN = () => [...FRAME, '.top .signout', COUNT_BADGE, `${COUNT_BADGE} + .count-words`];

/** Signed out: the sign-in form is the page. */
async function signedOutReady(page) {
  // Signed out, the page content is hidden: wait for it to exist, not to show.
  await page.waitForSelector('#content [data-rendered]', { state: 'attached' });
  await expect(page.locator('#signin')).toBeVisible();
}
// The chrome the frame hides while signed out; the sign-in's own look waits for the rest.
const SIGNIN = ['.side', '.main', 'a.skip', 'nav.route-nav a', 'header.top'];
const signedOut = (page) => page.route('**/ui/api/status', (r) => r.fulfill({ json: { auth: { enabled: true, signed_in: false, admin: false } } }));

test.describe('split guard', () => {
  test('Z6 at 1440 px, the rest of the stylesheet changes nothing in the frame', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await splitGuard(page);
  });

  test('Z6 at 1440 px signed in with decisions waiting, the rest of the stylesheet changes nothing in the frame', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await signedInWithCount(page);
    await splitGuard(page, SIGNED_IN(), signedInReady);
  });

  test('Z6 at 1440 px signed out, the frame already hides the chrome', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await signedOut(page);
    await splitGuard(page, SIGNIN, signedOutReady);
    // The rest is disabled now: the frame alone hides the chrome.
    for (const sel of ['.side', '.main']) await expect(page.locator(sel), sel).toBeHidden();
  });

  test.describe('phone', () => {
    test.use({ viewport: { width: 390, height: 844 }, hasTouch: true, isMobile: true });
    test('Z6 at 390 px with a coarse pointer signed out, the frame already hides the chrome', async ({ page }) => {
      await signedOut(page);
      await splitGuard(page, SIGNIN, signedOutReady);
      // The rest is disabled now: the frame alone hides the chrome.
      for (const sel of ['.side', '.main']) await expect(page.locator(sel), sel).toBeHidden();
    });
    test('Z6 at 390 px with a coarse pointer, the rest of the stylesheet changes nothing in the frame', async ({ page }) => {
      await page.goto('/ui/classic');
      expect(await page.evaluate(() => matchMedia('(pointer: coarse)').matches)).toBe(true);
      await splitGuard(page);
    });
  });
});

// Records every /ui/api fetch with its start time, in the page's clock.
const RECORD_API = () => {
  window.__api = [];
  const real = window.fetch;
  window.fetch = function (input, init) {
    const path = new URL(typeof input === 'string' ? input : input.url, location.href).pathname;
    if (path.startsWith('/ui/api/')) window.__api.push({ path, at: performance.now() });
    return real.call(this, input, init);
  };
};

// Holds the first paint: paint observers hear nothing until __releasePaint().
const HOLD_PAINT = () => {
  const Real = window.PerformanceObserver;
  const held = [];
  window.PerformanceObserver = class {
    constructor(cb) { this.cb = cb; this.off = false; }
    observe(opts) { if (opts.type === 'paint') held.push(this); else new Real(this.cb).observe(opts); }
    disconnect() { this.off = true; }
  };
  window.PerformanceObserver.supportedEntryTypes = Real.supportedEntryTypes;
  window.__releasePaint = () => {
    const list = { getEntriesByName: (n) => (n === 'first-contentful-paint' ? [{ name: n, startTime: performance.now() }] : []), getEntries: () => [] };
    for (const o of held) if (!o.off) o.cb(list, o);
  };
};

const apiPaths = (page) => page.evaluate(() => window.__api.map((c) => c.path));
const BOOT = ['/ui/api/decisions/count', '/ui/api/status', '/ui/api/stream'];
const COUNT_BADGE = `nav.route-nav a[href="/ui/${PAGES[1][0]}"] .count`;

test.describe('boot reads after first paint', () => {
  test('Z7 with the first paint held, /ui/overview/status starts no /ui/api request; released, the boot reads start', async ({ page }) => {
    await page.addInitScript(RECORD_API);
    await page.addInitScript(HOLD_PAINT);
    await page.goto('/ui/overview/status');
    await shellReady(page);
    await page.evaluate(() => new Promise((ok) => setTimeout(ok, 300)));
    expect(await apiPaths(page)).toEqual([]);
    await page.evaluate(() => window.__releasePaint());
    await expect.poll(() => apiPaths(page)).toEqual(expect.arrayContaining(BOOT));
  });

  test('Z7 with real paint timing, every /ui/api request on /ui/overview/status starts at or after first paint', async ({ page }) => {
    await page.addInitScript(RECORD_API);
    await page.goto('/ui/overview/status');
    await shellReady(page);
    await expect.poll(() => apiPaths(page)).toEqual(expect.arrayContaining(BOOT));
    const { fcp, calls } = await page.evaluate(() => ({ fcp: performance.getEntriesByName('first-contentful-paint')[0]?.startTime, calls: window.__api }));
    expect(fcp).toBeGreaterThan(0);
    for (const c of calls) expect(c.at, `${c.path} started before first paint`).toBeGreaterThanOrEqual(fcp);
  });

  for (const [name, init] of [
    ['without PerformanceObserver', () => { delete window.PerformanceObserver; }],
    ['when observing paint throws', () => { window.PerformanceObserver = class { observe() { throw new TypeError('no paint'); } disconnect() {} }; }],
  ]) {
    test(`Z8 ${name}, the boot reads still start`, async ({ page }) => {
      await page.addInitScript(RECORD_API);
      await page.addInitScript(init);
      await page.goto('/ui/overview/status');
      await shellReady(page);
      await expect.poll(() => apiPaths(page)).toEqual(expect.arrayContaining(BOOT));
    });
  }

  test('Z9 a signed-out key still gets the sign-in prompt, after the paint', async ({ page }) => {
    await page.addInitScript(HOLD_PAINT);
    await page.route('**/ui/api/status', (r) => r.fulfill({ json: { auth: { enabled: true, signed_in: false, admin: false } } }));
    await page.goto('/ui/overview/status');
    // Signed out, the page content is hidden, so wait for it to exist, not to show.
    await page.waitForSelector('#content [data-rendered]', { state: 'attached' });
    await page.evaluate(() => window.__releasePaint());
    await expect(page.locator('#signin')).toBeVisible();
  });

  test('Z9 the count badge still fills, after the paint', async ({ page }) => {
    await page.addInitScript(HOLD_PAINT);
    await page.route('**/ui/api/decisions/count', (r) => r.fulfill({ json: { count: 3 } }));
    await page.goto('/ui/overview/status');
    await shellReady(page);
    await page.evaluate(() => window.__releasePaint());
    await expect(page.locator(COUNT_BADGE)).toHaveText('3');
  });
});

/** A signed-in admin and one tool, so the Tools screen has data. */
async function toolsApi(page) {
  await page.route('**/ui/api/status', (r) => r.fulfill({ json: { auth: { enabled: true, signed_in: true, admin: true } } }));
  await page.route('**/ui/api/tools**', (r) => r.fulfill({ json: { tools: [{ name: 'echo', server: 'alpha', description: 'Echoes', schema: { type: 'object' }, class: 'read', class_source: 'declared' }], total: 1 } }));
}
const toolRows = (page) => page.locator('#content table.t tbody tr.tool');

test.describe('a screen read is not a boot read', () => {
  test('Z10 cold, with the first paint held, /ui/tools/status still reads its tools at render', async ({ page }) => {
    await toolsApi(page);
    await page.addInitScript(RECORD_API);
    await page.addInitScript(HOLD_PAINT);
    await page.goto('/ui/tools/status');
    await expect(toolRows(page)).toHaveCount(1);
    expect((await apiPaths(page)).filter((p) => p.startsWith('/ui/api/tools'))).toHaveLength(1);
  });

  test('Z10 with the Tools screen already preloaded, going there reads its tools', async ({ page }) => {
    await toolsApi(page);
    await page.addInitScript(RECORD_API);
    const preloaded = page.waitForResponse((r) => /\/ui\/assets\/tools\.[0-9a-f]{12}\.js$/.test(r.url()));
    await page.goto('/ui/overview/status');
    await shellReady(page);
    await preloaded;
    // Preloading loads the module only: its data is read when it renders.
    const tools = async () => (await apiPaths(page)).filter((p) => p.startsWith('/ui/api/tools'));
    expect(await tools()).toEqual([]);
    await page.locator('nav.route-nav a[href="/ui/tools"]').click();
    await expect(toolRows(page)).toHaveCount(1);
    expect(await tools()).toHaveLength(1);
  });
});
