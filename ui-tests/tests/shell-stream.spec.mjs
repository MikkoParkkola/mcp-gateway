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
  await page.clock.runFor(1000); // the first backoff
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
  await expect.poll(async () => (await stream.log()).filter((c) => c.authorization === `Bearer ${KEY}`).length).toBe(1);
  // No session cookie: only the bearer could have opened it.
  for (const c of await stream.log()) expect(c.cookie).not.toMatch(/session=/);
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
