// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The live stream (GET /ui/api/stream): the top bar reads Live while it is
// open, a drop shows the stale state with its time and reconnects with the
// last event id, a 503 waits its Retry-After, a key sign-in opens it with a
// bearer, sign-out closes it for good, and status and reload frames reach the
// screens as window events. Rows ST1-ST7. The stream is the fixture server's
// held route (server.mjs), driven per test through /__stream/<channel>/.
import { test, expect } from './base.mjs';
import { withFixturePages, shellReady } from './shell.mjs';

const KEY = 'mcpg_fixture_key_0123456789';
const INDICATOR = '.top .stream';
const STALE = '#content [data-state="stale"]';

/**
 * A held stream for this test. The fixture-stream cookie only names the
 * channel on the fixture server; it is test plumbing, not a session.
 */
async function heldStream(page, request, testInfo, setup = {}) {
  const name = testInfo.testId.replace(/[^\w-]/g, '-');
  await request.post(`/__stream/${name}/setup`, { data: setup });
  const url = `http://127.0.0.1:${process.env.UI_TESTS_PORT ?? 4173}`;
  await page.context().addCookies([{ name: 'fixture-stream', value: name, url }]);
  const log = async () => (await request.get(`/__stream/${name}/log`)).json();
  return {
    log,
    connects: async () => (await log()).length,
    send: (text) => request.post(`/__stream/${name}/send`, { data: text, headers: { 'content-type': 'text/plain' } }),
    end: () => request.post(`/__stream/${name}/end`),
  };
}

/** One SSE frame as the gateway writes it (conn.rs); hello carries a retry hint and no id. */
function frame(event, data, id = null) {
  const head = event === 'hello' ? 'retry: 3000\n' : '';
  return `${head}event: ${event}\n${id ? `id: ${id}\n` : ''}data: ${JSON.stringify(data)}\n\n`;
}
const HELLO = frame('hello', { kinds: ['status', 'reload'], head: 'b1.s1.r1' });

/** Pause the page clock at 14:02 today, local time, before the page loads. */
async function pausedAt1402(page) {
  const at = new Date();
  at.setHours(14, 2, 0, 0);
  await page.clock.install({ time: at.getTime() - 60_000 });
  await page.clock.pauseAt(at.getTime());
}

/** Record every write to the announcer, as shell-live.spec.mjs does. */
async function recordAnnouncements(page) {
  await page.addInitScript(() => {
    window.__writes = [];
    addEventListener('DOMContentLoaded', () => {
      const region = document.getElementById('announcer');
      if (!region) return;
      new MutationObserver((records) => {
        for (const r of records) for (const n of r.addedNodes) window.__writes.push((n.textContent ?? '').trim());
      }).observe(region, { childList: true });
    });
  });
}

/** Record the details of the window events the shell dispatches for stream frames. */
async function recordEvents(page) {
  await page.addInitScript(() => {
    window.__events = { 'gateway-status': [], 'gateway-reload': [] };
    for (const name of Object.keys(window.__events)) addEventListener(name, (ev) => window.__events[name].push(ev.detail));
  });
}
const seen = (page, name) => page.evaluate((n) => window.__events[n], name);

/** Open a fixture page with the stream connected and its hello read. */
async function openLive(page, stream) {
  await withFixturePages(page);
  await page.goto('/ui/servers/status');
  await shellReady(page);
  await expect.poll(stream.connects).toBe(1);
  await stream.send(HELLO);
  await expect(page.locator(INDICATOR)).toHaveText('Live');
}

test('ST1 Live reads live once the stream says hello', async ({ page, request }, testInfo) => {
  const stream = await heldStream(page, request, testInfo);
  await withFixturePages(page);
  await page.goto('/ui/servers/status');
  await shellReady(page);
  await expect.poll(stream.connects).toBe(1);
  // Not before the hello: an open request is not yet a live stream.
  await expect(page.locator(INDICATOR)).not.toHaveText('Live');
  await stream.send(HELLO);
  await expect(page.locator(INDICATOR)).toBeVisible();
  await expect(page.locator(INDICATOR)).toHaveText('Live');
});

test('ST2 a dropped stream shows Updates stopped at its time, and Live reads stopped', async ({ page, request }, testInfo) => {
  await pausedAt1402(page);
  const stream = await heldStream(page, request, testInfo);
  await openLive(page, stream);
  await stream.end();
  const hhmm = await page.evaluate(() => new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
  const title = `Updates stopped at ${hhmm} · reconnecting`;
  await expect(page.locator(`${STALE} h2`)).toHaveText(title);
  await expect(page.locator(INDICATOR)).toHaveText(title);
});

test('ST3 the reconnect sends the last event id, and its hello clears the stale state and says so', async ({ page, request }, testInfo) => {
  await recordAnnouncements(page);
  await recordEvents(page);
  await pausedAt1402(page);
  const stream = await heldStream(page, request, testInfo);
  await openLive(page, stream);
  await stream.send(frame('status', { server_count: 3 }, 'b1.s4.r1'));
  await stream.send(frame('reload', { generation: 2 }, 'b1.s4.r2'));
  await expect.poll(() => seen(page, 'gateway-reload')).toEqual([{ generation: 2 }]); // both frames read
  await stream.end();
  await expect(page.locator(STALE)).toHaveCount(1);
  await page.clock.runFor(3000); // the hello retry hint, above the first backoff
  await expect.poll(stream.connects).toBe(2);
  expect((await stream.log())[1].lastEventId).toBe('b1.s4.r2');
  await stream.send(HELLO);
  await expect(page.locator(STALE)).toHaveCount(0);
  await expect(page.locator(INDICATOR)).toHaveText('Live');
  await page.clock.runFor(5000); // the announcer writes each entry after its dwell
  const said = (await page.evaluate(() => window.__writes)).filter(Boolean).join(' ');
  expect(said.indexOf('Updates resumed.')).toBeGreaterThan(said.indexOf('Updates stopped'));
  expect(said.indexOf('Updates stopped')).toBeGreaterThanOrEqual(0);
});

test('ST4 a 503 with Retry-After waits at least that long before the next attempt', async ({ page, request }, testInfo) => {
  await pausedAt1402(page);
  // Nine seconds: far above the first backoff of one, so a shell that ignored the header fails.
  const stream = await heldStream(page, request, testInfo, { next: [{ status: 503, retryAfter: 9 }] });
  const asked = [];
  page.on('request', (r) => { if (new URL(r.url()).pathname === '/ui/api/stream') asked.push(r.url()); });
  await withFixturePages(page);
  await page.goto('/ui/servers/status');
  await shellReady(page);
  await expect.poll(stream.connects).toBe(1);
  await page.clock.runFor(8999);
  await page.evaluate(() => null); // one round trip, so a request made in that run has been reported
  expect(asked.length).toBe(1);
  expect(await stream.connects()).toBe(1);
  await page.clock.runFor(2);
  await expect.poll(stream.connects).toBe(2);
});

test('ST5 a key-only sign-in opens the stream with the bearer', async ({ page, request }, testInfo) => {
  await page.route('**/ui/api/status', (route) => {
    const signedIn = route.request().headers().authorization === `Bearer ${KEY}`;
    return route.fulfill({ json: { version: '4.0.0', auth: { enabled: true, signed_in: signedIn, admin: signedIn } } });
  });
  const stream = await heldStream(page, request, testInfo, { requireBearer: KEY });
  await page.goto('/ui/overview/status');
  await expect(page.locator('#signin')).toBeVisible();
  await page.locator('#signin-key').fill(KEY);
  await page.keyboard.press('Enter');
  await expect(page.locator('#signin')).toBeHidden();
  // The channel answers 401 to anything but this exact bearer, so a 200 proves it was sent.
  await expect.poll(async () => (await stream.log()).filter((c) => c.authorization && c.status === 200).length).toBe(1);
  // No session cookie: only the bearer could have opened it.
  for (const c of await stream.log()) expect(c.sessionCookie).toBe(false);
  await stream.send(HELLO);
  await expect(page.locator(INDICATOR)).toHaveText('Live');
});

test('ST6 sign-out closes the stream, and nothing reconnects', async ({ page, request }, testInfo) => {
  await pausedAt1402(page);
  const stream = await heldStream(page, request, testInfo);
  await openLive(page, stream);
  await page.locator('.top .signout').click();
  await expect(page.locator('#signin')).toBeVisible();
  await expect.poll(async () => (await stream.log())[0].closed).toBe(true);
  await page.clock.runFor(31_000); // past the longest backoff
  await page.evaluate(() => null);
  expect(await stream.connects()).toBe(1);
  await expect(page.locator(STALE)).toHaveCount(0); // a close on purpose is no drop
});

test('ST7 status and reload frames reach the page as window events', async ({ page, request }, testInfo) => {
  await recordEvents(page);
  const stream = await heldStream(page, request, testInfo);
  await openLive(page, stream);
  const status = { server_count: 3, healthy_count: 2, tool_count: 42 };
  await stream.send(frame('status', status, 'b1.s2.r1'));
  await expect.poll(() => seen(page, 'gateway-status')).toEqual([status]);
  await stream.send(frame('reload', { generation: 5 }, 'b1.s2.r5'));
  await expect.poll(() => seen(page, 'gateway-reload')).toEqual([{ generation: 5 }]);
});

test('ST8 leaving the page closes the stream, a restore reopens it once, and cycles never leave two open', async ({ page, request }, testInfo) => {
  // This setup does not restore from the back/forward cache (the shell document
  // is no-store), so the row dispatches pagehide and pageshow(persisted) itself.
  const stream = await heldStream(page, request, testInfo);
  await openLive(page, stream);
  const leave = () => page.evaluate(() => dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true })));
  const restore = () => page.evaluate(() => dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })));
  const open = async () => (await stream.log()).filter((c) => !c.closed).length;
  await leave();
  await expect.poll(async () => (await stream.log())[0].closed).toBe(true);
  await restore();
  await expect.poll(stream.connects).toBe(2);
  for (let i = 0; i < 3; i += 1) {
    await leave();
    await expect.poll(open).toBe(0);
    await restore();
    await expect.poll(open).toBe(1);
  }
  await restore(); // a second restore with no leave between still holds one
  await expect.poll(stream.connects).toBe(6);
  await expect.poll(open).toBe(1);
});

const UNAVAILABLE = 'Updates unavailable · reconnecting';

test('ST9a a first connect that fails shows Updates unavailable on the page and in the top bar', async ({ page, request }, testInfo) => {
  const stream = await heldStream(page, request, testInfo, { next: [{ status: 500 }] });
  await withFixturePages(page);
  await page.goto('/ui/servers/status');
  await shellReady(page);
  await expect.poll(stream.connects).toBe(1);
  await expect(page.locator(`${STALE} h2`)).toHaveText(UNAVAILABLE);
  await expect(page.locator(INDICATOR)).toBeVisible();
  await expect(page.locator(INDICATOR)).toHaveText(UNAVAILABLE);
});

test('ST9b a later hello clears Updates unavailable and says so', async ({ page, request }, testInfo) => {
  await recordAnnouncements(page);
  await pausedAt1402(page);
  const stream = await heldStream(page, request, testInfo, { next: [{ status: 500 }] });
  await withFixturePages(page);
  await page.goto('/ui/servers/status');
  await shellReady(page);
  await expect(page.locator(`${STALE} h2`)).toHaveText(UNAVAILABLE);
  await page.clock.runFor(1000); // the first backoff
  await expect.poll(stream.connects).toBe(2);
  await stream.send(HELLO);
  await expect(page.locator(STALE)).toHaveCount(0);
  await expect(page.locator(INDICATOR)).toHaveText('Live');
  await page.clock.runFor(5000); // the announcer writes each entry after its dwell
  const said = (await page.evaluate(() => window.__writes)).filter(Boolean).join(' ');
  expect(said.indexOf('Updates unavailable')).toBeGreaterThanOrEqual(0);
  expect(said.indexOf('Updates resumed.')).toBeGreaterThan(said.indexOf('Updates unavailable'));
});

test('ST9c a 404 first connect shows Updates unavailable and retries at the 30 s ceiling', async ({ page, request }, testInfo) => {
  await pausedAt1402(page);
  const stream = await heldStream(page, request, testInfo, { next: [{ status: 404 }, { status: 404 }] });
  const asked = [];
  page.on('request', (r) => { if (new URL(r.url()).pathname === '/ui/api/stream') asked.push(r.url()); });
  await withFixturePages(page);
  await page.goto('/ui/servers/status');
  await shellReady(page);
  await expect.poll(stream.connects).toBe(1);
  await expect(page.locator(`${STALE} h2`)).toHaveText(UNAVAILABLE);
  await expect(page.locator(INDICATOR)).toHaveText(UNAVAILABLE);
  for (const n of [1, 2]) {
    await page.clock.runFor(29_999);
    await page.evaluate(() => null); // one round trip, so a request made in that run has been reported
    expect(asked.length).toBe(n);
    await page.clock.runFor(2);
    await expect.poll(stream.connects).toBe(n + 1);
  }
  await expect(page.locator(INDICATOR)).toHaveText(UNAVAILABLE); // never told it is live
});

/** Drop an open stream and wait for its stale state. */
async function drop(page, stream) {
  await stream.end();
  await expect(page.locator(STALE)).toHaveCount(1);
}

test('ST10 a page opened while the stream is down shows the stale state, and the reconnect clears it', async ({ page, request }, testInfo) => {
  await pausedAt1402(page);
  const stream = await heldStream(page, request, testInfo);
  await openLive(page, stream);
  await drop(page, stream);
  await page.locator('nav.route-nav a[href="/ui/gateway"]').click();
  await expect(page.locator('#content')).toContainText('gateway - status');
  await expect(page.locator(`${STALE} h2`)).toHaveText(/^Updates stopped at .+ · reconnecting$/);
  await page.clock.runFor(3000); // the hello retry hint, above the first backoff
  await expect.poll(stream.connects).toBe(2);
  await stream.send(HELLO);
  await expect(page.locator(STALE)).toHaveCount(0);
});

test('ST11 a restore resumes with the last event id, and its hello clears a stale state from before', async ({ page, request }, testInfo) => {
  await pausedAt1402(page);
  const stream = await heldStream(page, request, testInfo);
  await openLive(page, stream);
  await stream.send(frame('status', { server_count: 3 }, 'b1.s9.r1'));
  await drop(page, stream);
  await page.evaluate(() => dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true })));
  await page.evaluate(() => dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })));
  await expect.poll(stream.connects).toBe(2);
  expect((await stream.log())[1].lastEventId).toBe('b1.s9.r1');
  await expect(page.locator(STALE)).toHaveCount(1); // still down until a hello
  await expect(page.locator(INDICATOR)).not.toHaveText('Live');
  await stream.send(HELLO);
  await expect(page.locator(STALE)).toHaveCount(0);
  await expect(page.locator(INDICATOR)).toHaveText('Live');
});

test('ST12 the reconnect waits for the hello retry hint when it is the largest', async ({ page, request }, testInfo) => {
  await pausedAt1402(page);
  const stream = await heldStream(page, request, testInfo);
  const asked = [];
  page.on('request', (r) => { if (new URL(r.url()).pathname === '/ui/api/stream') asked.push(r.url()); });
  await withFixturePages(page);
  await page.goto('/ui/servers/status');
  await shellReady(page);
  await expect.poll(stream.connects).toBe(1);
  await stream.send(`retry: 7000\nevent: hello\ndata: ${JSON.stringify({ kinds: ['status'] })}\n\n`);
  await expect(page.locator(INDICATOR)).toHaveText('Live');
  await drop(page, stream);
  await page.clock.runFor(6999);
  await page.evaluate(() => null);
  expect(asked.length).toBe(1);
  await page.clock.runFor(2);
  await expect.poll(stream.connects).toBe(2);
});

test('ST13 a reconnect clears only the stale banner the stream set, never one a screen set', async ({ page, request }, testInfo) => {
  await pausedAt1402(page);
  const stream = await heldStream(page, request, testInfo);
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/tools/status'); // this screen marks its own data stale (T6)
  await shellReady(page);
  await expect(page.locator(STALE)).toHaveCount(1);
  await expect.poll(stream.connects).toBe(1);
  await stream.send(HELLO);
  await stream.end();
  await expect(page.locator(INDICATOR)).toHaveText(/^Updates stopped/);
  await page.clock.runFor(3000); // the hello retry hint, above the first backoff
  await expect.poll(stream.connects).toBe(2);
  await stream.send(HELLO);
  await expect(page.locator(INDICATOR)).toHaveText('Live');
  await expect(page.locator(STALE)).toHaveCount(1); // the screen owns it
});

test('ST14 below the phone breakpoint the indicator is hidden visually, not removed', async ({ page, request }, testInfo) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const stream = await heldStream(page, request, testInfo);
  await openLive(page, stream);
  const box = await page.locator(INDICATOR).evaluate((n) => {
    const r = n.getBoundingClientRect();
    return { display: getComputedStyle(n).display, w: r.width, h: r.height };
  });
  expect(box.display).not.toBe('none');
  expect(box.w * box.h).toBeLessThanOrEqual(1);
});

test('ST15 a frame larger than 64 KiB is a drop: stale state, then a reconnect', async ({ page, request }, testInfo) => {
  await pausedAt1402(page);
  const stream = await heldStream(page, request, testInfo);
  await openLive(page, stream);
  await stream.send(`event: status\ndata: "${'x'.repeat(70 * 1024)}`); // never ends
  await expect(page.locator(STALE)).toHaveCount(1);
  await expect.poll(async () => (await stream.log())[0].closed).toBe(true);
  await page.clock.runFor(3000); // the hello retry hint, above the first backoff
  await expect.poll(stream.connects).toBe(2);
});

test('ST16 the parser reads CRLF frames, skips keep-alives, joins data lines and joins a split frame', async ({ page, request }, testInfo) => {
  await recordEvents(page);
  const stream = await heldStream(page, request, testInfo);
  await openLive(page, stream);
  await stream.send('event: status\r\nid: b1.s2.r1\r\ndata: {"crlf":1}\r\n\r\n');
  await stream.send(': keep-alive\n\n');
  await stream.send('event: status\nid: b1.s3.r1\ndata: {"lines":\ndata: 2}\n\n');
  await stream.send('event: status\nid: b1.s4.r1\nda');
  await stream.send('ta: {"split":3}\n\n');
  await expect.poll(() => seen(page, 'gateway-status')).toEqual([{ crlf: 1 }, { lines: 2 }, { split: 3 }]);
});

test('ST17 every hello, first and after a reconnect, is a gateway-hello event', async ({ page, request }, testInfo) => {
  await page.addInitScript(() => {
    window.__hellos = [];
    addEventListener('gateway-hello', (ev) => window.__hellos.push(ev.detail));
  });
  await pausedAt1402(page);
  const stream = await heldStream(page, request, testInfo);
  await openLive(page, stream);
  const hello = { kinds: ['status', 'reload'], head: 'b1.s1.r1' };
  await expect.poll(() => page.evaluate(() => window.__hellos)).toEqual([hello]);
  await drop(page, stream);
  await page.clock.runFor(3000); // the hello retry hint, above the first backoff
  await expect.poll(stream.connects).toBe(2);
  await stream.send(HELLO);
  await expect.poll(() => page.evaluate(() => window.__hellos)).toEqual([hello, hello]);
});

test('ST18 a drop while a screen banner holds the slot leaves it, and the hello clears nothing', async ({ page, request }, testInfo) => {
  await pausedAt1402(page);
  const stream = await heldStream(page, request, testInfo);
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/servers/status'); // this screen shows a server banner (T11)
  await shellReady(page);
  const screenBanner = page.locator('#content [data-state="server"]');
  await expect(screenBanner).toHaveCount(1);
  await expect.poll(stream.connects).toBe(1);
  await stream.send(HELLO);
  await stream.end();
  await expect(page.locator(INDICATOR)).toHaveText(/^Updates stopped/); // the top bar carries the drop
  await expect(screenBanner).toHaveCount(1);
  await expect(page.locator(STALE)).toHaveCount(0);
  await page.clock.runFor(3000);
  await expect.poll(stream.connects).toBe(2);
  await stream.send(HELLO);
  await expect(page.locator(INDICATOR)).toHaveText('Live');
  await expect(screenBanner).toHaveCount(1);
});

test('ST19 a stale banner the screen claims while the stream set it is the screen to clear', async ({ page, request }, testInfo) => {
  await pausedAt1402(page);
  const stream = await heldStream(page, request, testInfo);
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/tools/status'); // this screen marks its own data stale (T6)
  await shellReady(page);
  await page.evaluate(() => window.toolsShow(null)); // the screen clears its own first
  await expect(page.locator(STALE)).toHaveCount(0);
  await expect.poll(stream.connects).toBe(1);
  await stream.send(HELLO);
  await drop(page, stream);
  await page.evaluate(() => window.toolsShow('stale')); // the screen says its data is stale too
  await page.clock.runFor(3000);
  await expect.poll(stream.connects).toBe(2);
  await stream.send(HELLO);
  await expect(page.locator(INDICATOR)).toHaveText('Live');
  await expect(page.locator(STALE)).toHaveCount(1);
});

/** A completed frame over the cap: never dispatched, a drop, then a reconnect. */
async function oversizedFrameIsADrop(page, request, testInfo, payload) {
  await recordEvents(page);
  await pausedAt1402(page);
  const stream = await heldStream(page, request, testInfo);
  await openLive(page, stream);
  await stream.send(`event: status\nid: b1.s8.r1\ndata: ${JSON.stringify({ big: payload })}\n\n`);
  await expect(page.locator(STALE)).toHaveCount(1);
  await expect.poll(async () => (await stream.log())[0].closed).toBe(true);
  expect(await seen(page, 'gateway-status')).toEqual([]);
  await page.clock.runFor(3000);
  await expect.poll(stream.connects).toBe(2);
}

test('ST15b a completed frame over 64 KiB is a drop and is never dispatched', async ({ page, request }, testInfo) => {
  await oversizedFrameIsADrop(page, request, testInfo, 'x'.repeat(70 * 1000));
});

test('ST15c the cap counts UTF-8 bytes: 34,000 two-byte characters are a drop', async ({ page, request }, testInfo) => {
  const payload = 'é'.repeat(34_000); // 34,000 characters, under 64 KiB; 68,000 bytes, over it
  expect(payload.length).toBeLessThan(64 * 1024);
  expect(Buffer.byteLength(payload)).toBeGreaterThan(64 * 1024);
  await oversizedFrameIsADrop(page, request, testInfo, payload);
});

test('ST20 several failed first connects keep the banner, and the waits grow', async ({ page, request }, testInfo) => {
  await pausedAt1402(page);
  const stream = await heldStream(page, request, testInfo, { next: [{ status: 500 }, { status: 500 }, { status: 500 }] });
  const asked = [];
  page.on('request', (r) => { if (new URL(r.url()).pathname === '/ui/api/stream') asked.push(r.url()); });
  await withFixturePages(page);
  await page.goto('/ui/servers/status');
  await shellReady(page);
  await expect.poll(stream.connects).toBe(1);
  for (const [n, wait] of [[1, 1000], [2, 2000], [3, 4000]]) {
    await expect(page.locator(`${STALE} h2`)).toHaveText(UNAVAILABLE);
    await page.clock.runFor(wait - 1);
    await page.evaluate(() => null); // one round trip, so a request made in that run has been reported
    expect(asked.length).toBe(n);
    await page.clock.runFor(2);
    await expect.poll(stream.connects).toBe(n + 1);
  }
  await expect(page.locator(STALE)).toHaveCount(1);
});

test('ST21 signing out while a reconnect waits cancels it', async ({ page, request }, testInfo) => {
  await pausedAt1402(page);
  const stream = await heldStream(page, request, testInfo);
  await openLive(page, stream);
  await drop(page, stream); // a reconnect is now pending
  await page.locator('.top .signout').click();
  await expect(page.locator('#signin')).toBeVisible();
  await page.clock.runFor(31_000);
  await page.evaluate(() => null);
  expect(await stream.connects()).toBe(1);
});

test('ST22 a session cookie alone opens the stream', async ({ page, request }, testInfo) => {
  const url = `http://127.0.0.1:${process.env.UI_TESTS_PORT ?? 4173}`;
  await page.context().addCookies([{ name: 'mcp_gateway_session', value: 'fixture', url }]);
  const stream = await heldStream(page, request, testInfo);
  await openLive(page, stream);
  const [conn] = await stream.log();
  expect(conn.sessionCookie).toBe(true);
  expect(conn.authorization).toBe(false);
});
