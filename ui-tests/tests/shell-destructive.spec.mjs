// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// One destructive-action pattern (UI1.19) and a centred confirmation (UI1.25):
// ctx.confirm's confirm, running, refused, unconfirmed and done states, the
// operation lock, the unconfirmed set, the returned outcome, and placement.
// The fixture's Gateway › Actions row calls ctx.confirm against
// /ui/api/destroy-probe; a test shapes the call through window.__confirm.
import { test, expect, blockingViolations } from './base.mjs';
import { withFixturePages, shellReady } from './shell.mjs';

const PROBE = '**/ui/api/destroy-probe';
const dialog = (page) => page.locator('dialog.confirm');
const action = (page) => dialog(page).getByRole('button', { name: 'Remove probe' });
const keep = (page) => dialog(page).getByRole('button', { name: 'Cancel probe' });
const message = (page) => dialog(page).locator('.confirm-message');

/** Open Gateway › Actions with `extra` merged into the confirm spec (a string of JS, run in the page). */
async function open(page, extra = '{}') {
  await page.addInitScript(`window.__confirm = (opener) => (${extra});`);
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/gateway/actions');
  await shellReady(page);
}

async function recordAnnouncements(page) {
  await page.addInitScript(() => {
    window.__writes = [];
    addEventListener('DOMContentLoaded', () => {
      const region = document.getElementById('announcer');
      new MutationObserver((records) => {
        for (const r of records) for (const n of r.addedNodes) window.__writes.push((n.textContent ?? '').trim());
      }).observe(region, { childList: true });
    });
  });
}

const outcomes = (page) => page.evaluate(() => window.__outcomes);

/** A route answer that waits until `release(status)` is called. */
function held() {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  return {
    release,
    answer: async (r) => {
      const status = await gate;
      return status === 'abort' ? r.abort() : r.fulfill({ status, json: { removed: 'probe', tools: 3 } });
    },
  };
}

const intersects = (a, b) => a.x < b.x + b.width && b.x < a.x + a.width && a.y < b.y + b.height && b.y < a.y + a.height;

test.describe('confirm', () => {
  test('D1 the dialog names the action, lists its consequences, starts on the safe button, and Esc gives focus back', async ({ page }) => {
    await open(page);
    await page.click('#remove-probe');
    await expect(dialog(page)).toBeVisible();
    await expect(dialog(page).getByRole('heading')).toHaveText('Remove probe?');
    await expect(dialog(page).locator('li')).toHaveText(['3 tools disappear for 2 keys.', 'They called them 12 times today.']);
    await expect(keep(page)).toBeFocused();
    await expect(action(page)).toHaveClass(/danger/);
    // The page behind is inert while it is open: its links cannot take focus.
    expect(await page.evaluate(() => { const a = document.querySelector('nav.route-nav a'); a.focus(); return document.activeElement === a; })).toBe(false);
    await page.keyboard.press('Escape');
    await expect(dialog(page)).toHaveCount(0);
    await expect(page.locator('#remove-probe')).toBeFocused();
    await expect.poll(() => outcomes(page)).toEqual([{ outcome: 'kept' }]);
  });

  test('D1b a typed name enables the action only on an exact match', async ({ page }) => {
    await open(page, "{ typeToConfirm: 'probe' }");
    await page.click('#remove-probe');
    const field = dialog(page).getByLabel('Type probe to confirm');
    await expect(action(page)).toBeDisabled();
    await field.fill('Probe');
    await expect(action(page)).toBeDisabled();
    await field.fill('probe ');
    await expect(action(page)).toBeDisabled();
    await field.fill('probe');
    await expect(action(page)).toBeEnabled();
  });

  test('D9 an empty consequence list says so, and a spec without its progress label throws', async ({ page }) => {
    await open(page, '{ consequences: [] }');
    await page.click('#remove-probe');
    await expect(dialog(page)).toContainText('It does not say what it changes.');
    await page.keyboard.press('Escape');
    const thrown = await page.evaluate(() => {
      try { window.gatewayConfirm({ opener: document.body, key: 'k', verb: 'Remove', object: 'x', consequences: [], run: () => null }); return null; } catch (e) { return e.name; }
    });
    expect(thrown).toBe('TypeError');
  });
});

test.describe('running', () => {
  test('D2 a held request shows its progress label, ignores Esc and keep, and is said once after 300 ms', async ({ page }) => {
    await recordAnnouncements(page);
    const h = held();
    await page.route(PROBE, h.answer);
    await open(page);
    await page.click('#remove-probe');
    await action(page).click();
    await expect(dialog(page).getByRole('button', { name: 'Removing probe…' })).toHaveAttribute('aria-busy', 'true');
    await expect(keep(page)).toHaveCount(0);
    await expect(dialog(page).locator('.confirm-progress')).toBeFocused();
    await page.keyboard.press('Escape');
    await expect(dialog(page)).toBeVisible();
    await expect.poll(() => page.evaluate(() => window.__writes.filter((t) => t.includes('Removing probe')).length)).toBe(1);
    h.release(204);
    await expect(dialog(page)).toHaveCount(0);
  });

  test('D2b a double click on the action sends one request', async ({ page }) => {
    let calls = 0;
    await page.route(PROBE, (r) => { calls += 1; return r.fulfill({ status: 204 }); });
    await open(page);
    await page.click('#remove-probe');
    await action(page).dblclick();
    await expect(dialog(page)).toHaveCount(0);
    expect(calls).toBe(1);
  });
});

test.describe('refused', () => {
  test('D3 a 409 says why and offers Reload, never a retry; focus goes to the message; Close resolves failed', async ({ page }) => {
    await page.route(PROBE, (r) => r.fulfill({ status: 409, json: {} }));
    await open(page);
    await page.click('#remove-probe');
    await action(page).click();
    await expect(message(page)).toContainText('probe changed since this page loaded.');
    await expect(message(page)).toBeFocused();
    await expect(dialog(page).getByRole('button', { name: 'Reload page' })).toBeVisible();
    await expect(dialog(page).getByRole('button', { name: 'Try again' })).toHaveCount(0);
    await dialog(page).getByRole('button', { name: 'Close' }).click();
    await expect(page.locator('#remove-probe')).toBeFocused();
    await expect.poll(async () => (await outcomes(page))[0]?.outcome).toBe('failed');
  });

  test('D3b a 403 has its own words, and a screen failed() replaces them', async ({ page }) => {
    await page.route(PROBE, (r) => r.fulfill({ status: 403, json: {} }));
    await open(page);
    await page.click('#remove-probe');
    await action(page).click();
    await expect(message(page)).toContainText('This key may not remove probe.');
    await page.getByRole('button', { name: 'Close' }).click();
    await page.evaluate(() => { window.__confirm = () => ({ failed: () => ({ reason: 'Only an owner may remove it.', next: 'Ask the owner.' }) }); });
    await page.click('#remove-probe');
    await action(page).click();
    await expect(message(page)).toContainText('Only an owner may remove it.');
    await expect(message(page)).toContainText('Ask the owner.');
  });

  test('D3c a replay-safe 503 offers Try again; the typed name must be retyped; then it succeeds', async ({ page }) => {
    let calls = 0;
    await page.route(PROBE, (r) => { calls += 1; return calls === 1 ? r.fulfill({ status: 503, json: {} }) : r.fulfill({ status: 204 }); });
    await open(page, "{ replay: 'safe', typeToConfirm: 'probe' }");
    await page.click('#remove-probe');
    await dialog(page).getByLabel('Type probe to confirm').fill('probe');
    await action(page).click();
    const again = dialog(page).getByRole('button', { name: 'Try again' });
    await expect(again).toBeDisabled();
    await expect(message(page)).toBeFocused();
    await dialog(page).getByLabel('Type probe to confirm').fill('probe');
    await again.click();
    await expect(dialog(page)).toHaveCount(0);
    expect(calls).toBe(2);
    await expect.poll(async () => (await outcomes(page))[0]?.outcome).toBe('done');
  });
});

test.describe('unconfirmed', () => {
  const CASES = [
    ['a lost connection', (r) => r.abort()],
    ['a 500', (r) => r.fulfill({ status: 500, json: {} })],
    ['a 502', (r) => r.fulfill({ status: 502, json: {} })],
    ['a 504', (r) => r.fulfill({ status: 504, json: {} })],
    ['a 408', (r) => r.fulfill({ status: 408, json: {} })],
    ['an unsafe 503', (r) => r.fulfill({ status: 503, json: {} })],
    ['an unreadable success', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{not json' })],
  ];
  for (const [name, answer] of CASES) {
    test(`D3d ${name} is unconfirmed: Reload and Close, no retry, and the same subject is refused until the page renders again`, async ({ page }) => {
      await page.route(PROBE, answer);
      await open(page);
      await page.click('#remove-probe');
      await action(page).click();
      await expect(message(page)).toContainText('The gateway did not confirm the outcome.');
      await expect(message(page)).toContainText('Reload to see whether probe changed.');
      await expect(dialog(page).getByRole('button', { name: 'Reload page' })).toBeVisible();
      await expect(dialog(page).getByRole('button', { name: 'Try again' })).toHaveCount(0);
      await dialog(page).getByRole('button', { name: 'Close' }).click();
      await page.click('#remove-probe');
      await expect(dialog(page)).toHaveCount(0);
      await expect.poll(async () => (await outcomes(page)).map((o) => o.outcome)).toEqual(['unconfirmed', 'declined']);
    });
  }

  test('D3e a throw in the screen own run() is unconfirmed, not a failure', async ({ page }) => {
    await open(page, "{ run: () => { throw new TypeError('screen bug'); } }");
    await page.click('#remove-probe');
    await action(page).click();
    await expect(message(page)).toContainText('The gateway did not confirm the outcome.');
  });

  test('D3f a 401 closes the dialog for sign-in and resolves unconfirmed', async ({ page }) => {
    await page.route(PROBE, (r) => r.fulfill({ status: 401, json: {} }));
    await open(page);
    await page.click('#remove-probe');
    await action(page).click();
    await expect(page.locator('#signin')).toBeVisible();
    await expect(dialog(page)).toHaveCount(0);
    await expect.poll(async () => (await outcomes(page))[0]?.outcome).toBe('unconfirmed');
  });

  test('D3g after 30 s the dialog stops waiting; the lock holds until the late answer, which shows nothing', async ({ page }) => {
    await page.clock.install();
    const h = held();
    await page.route(PROBE, h.answer);
    await open(page);
    await page.click('#remove-probe');
    await action(page).click();
    await page.clock.runFor(10_000);
    await expect(dialog(page)).toContainText('Still waiting for the gateway.');
    await page.clock.runFor(20_000);
    await expect(message(page)).toContainText('The gateway did not confirm the outcome.');
    await dialog(page).getByRole('button', { name: 'Close' }).click();
    // Locked: another confirm is refused while the request is still out.
    const refused = await page.evaluate(() => window.gatewayConfirm({ opener: document.body, key: 'other', verb: 'Remove', object: 'other', progress: 'Removing other…', consequences: [], run: () => null }));
    expect(refused).toEqual({ outcome: 'declined' });
    // A request that never answers cannot hold the lock forever: 120 s after the cutoff it goes.
    await page.clock.runFor(150_000);
    await page.evaluate(() => { window.gatewayConfirm({ opener: document.body, key: 'other', verb: 'Remove', object: 'other', progress: 'Removing other…', consequences: [], run: () => null }); });
    await expect(page.locator('dialog.confirm')).toBeVisible();
    await page.keyboard.press('Escape');
    h.release(204);
    await page.clock.runFor(1_000);
    await expect(page.locator('#content .done-notice')).toHaveCount(0);
    await expect(page).toHaveURL(/\/ui\/gateway\/actions$/);
  });
});

test.describe('done', () => {
  test('D4 done lands on its path with a notice that is said once, has its action and Dismiss, and goes at the next navigation', async ({ page }) => {
    await recordAnnouncements(page);
    await page.route(PROBE, (r) => r.fulfill({ status: 200, json: { tools: 3 } }));
    await open(page, "{ done: (v) => ({ path: '/ui/servers/status', notice: `probe removed · ${v.tools} tools no longer reachable`, action: { label: 'Add probe again', path: '/ui/servers/settings' } }) }");
    await page.click('#remove-probe');
    await action(page).click();
    await expect(page).toHaveURL(/\/ui\/servers\/status$/);
    const notice = page.locator('#content .done-notice');
    await expect(notice).toContainText('probe removed · 3 tools no longer reachable');
    await expect(notice.getByRole('link', { name: 'Add probe again' })).toHaveAttribute('href', '/ui/servers/settings');
    await expect(notice.locator('[tabindex="-1"]').first()).toBeFocused();
    await expect.poll(() => page.evaluate(() => window.__writes.filter((t) => t.includes('probe removed')).length)).toBe(1);
    // It resolves once routing has begun, so the outcome may land just after the new page.
    await expect.poll(async () => (await outcomes(page))[0]).toEqual({ outcome: 'done', value: { tools: 3 } });
    await page.click('nav.route-nav a[data-page="tools"]');
    await expect(page.locator('#content .done-notice')).toHaveCount(0);
  });

  test('D4b Dismiss removes the notice, and a landing page that errors keeps it above its banner', async ({ page }) => {
    await page.route(PROBE, (r) => r.fulfill({ status: 204 }));
    await page.route('**/ui/api/page-probe*', (r) => r.fulfill({ status: 500, json: {} }));
    await open(page, "{ done: { path: '/ui/policies/status', notice: 'probe removed' } }");
    await page.click('#remove-probe');
    await action(page).click();
    await expect(page.locator('#content [data-state="error"]')).toBeVisible();
    const notice = page.locator('#content .done-notice');
    await expect(notice).toContainText('probe removed');
    await notice.getByRole('button', { name: 'Dismiss' }).click();
    await expect(notice).toHaveCount(0);
  });

  test('D8 a decision without done (a write tool) wears no danger fill, stays on the page, and returns the value', async ({ page }) => {
    await page.route(PROBE, (r) => r.fulfill({ status: 200, json: { result: 'ok' } }));
    await open(page, "{ tone: 'decision' }");
    await page.click('#remove-probe');
    await expect(action(page)).not.toHaveClass(/danger/);
    await action(page).click();
    await expect(dialog(page)).toHaveCount(0);
    await expect(page).toHaveURL(/\/ui\/gateway\/actions$/);
    await expect.poll(() => outcomes(page)).toEqual([{ outcome: 'done', value: { result: 'ok' } }]);
  });
});

test.describe('placement', () => {
  const SIZES = [[390, 568], [640, 800], [820, 1180], [1440, 800], [2560, 1440]];
  for (const [width, height] of SIZES) {
    test(`D5 at ${width}×${height} the dialog is centred, its buttons in view, and it never covers its opener`, async ({ page }) => {
      await page.setViewportSize({ width, height });
      await open(page, "{ object: 'probe-with-a-name-of-sixty-characters-for-the-placement-row', consequences: ['One.', 'Two.', 'Three.', 'Four.', 'Five.', 'Six.', 'Seven.', 'Eight.'] }");
      await page.click('#remove-probe');
      const box = await dialog(page).boundingBox();
      const opener = await page.locator('#remove-probe').boundingBox();
      expect(intersects(box, opener), 'the dialog covers its opener').toBe(false);
      expect(Math.abs(box.x + box.width / 2 - width / 2)).toBeLessThanOrEqual(1);
      expect(Math.abs(box.y + box.height / 2 - height / 2)).toBeLessThanOrEqual(1);
      const buttons = await dialog(page).locator('.acts').boundingBox();
      expect(buttons.y >= 0 && buttons.y + buttons.height <= height).toBe(true);
    });
  }

  /** Where the dialog sits: centred in the visible part, or docked 16px from the top edge or below the opener (the one case where centring yields). Vertical only: both modes are centred across, checked apart. */
  const placement = (box, opener, { width, height }) => {
    if (Math.abs(box.y + box.height / 2 - height / 2) <= 1) return 'centred';
    const docked = Math.abs(box.y - 16) <= 1 || Math.abs(box.y - (opener.y + opener.height + 16)) <= 1;
    return docked ? 'docked' : 'neither';
  };

  test('D5b text at 200%, a tall opener, and a resize while open still leave the opener uncovered', async ({ page }) => {
    await page.setViewportSize({ width: 820, height: 600 });
    await page.addInitScript(() => {
      window.__openerStyle = { minHeight: '120px' };
      addEventListener('DOMContentLoaded', () => { document.documentElement.style.fontSize = '200%'; });
    });
    await open(page, "{ typeToConfirm: 'probe' }");
    await page.click('#remove-probe');
    for (const size of [{ width: 820, height: 600 }, { width: 390, height: 568 }]) {
      await page.setViewportSize(size);
      await expect.poll(async () => intersects(await dialog(page).boundingBox(), await page.locator('#remove-probe').boundingBox())).toBe(false);
      const buttons = await dialog(page).locator('.acts').boundingBox();
      expect(buttons.y >= 0 && buttons.y + buttons.height <= size.height, 'the buttons stay in view').toBe(true);
      const box = await dialog(page).boundingBox();
      const opener = await page.locator('#remove-probe').boundingBox();
      expect(Math.abs(box.x + box.width / 2 - size.width / 2), 'centred across in both modes').toBeLessThanOrEqual(1);
      expect(box.x >= 0 && box.x + box.width <= size.width, 'inside the viewport across').toBe(true);
      expect(buttons.x >= 0 && buttons.x + buttons.width <= size.width, 'the button row inside the viewport across').toBe(true);
      expect(['centred', 'docked'], `placed ${JSON.stringify(box)} for the opener ${JSON.stringify(opener)}`).toContain(placement(box, opener, size));
    }
  });

  test('D5c an on-screen keyboard (a shrunk, offset visual viewport) keeps the dialog in the visible part, clear of its opener', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.addInitScript(() => {
      const vv = new EventTarget();
      Object.defineProperties(vv, { height: { get: () => 420 }, width: { get: () => 390 }, offsetTop: { get: () => 120 }, offsetLeft: { get: () => 0 }, scale: { get: () => 1 } });
      Object.defineProperty(window, 'visualViewport', { get: () => vv });
    });
    await open(page);
    await page.click('#remove-probe');
    const box = await dialog(page).boundingBox();
    expect(box.y).toBeGreaterThanOrEqual(120);
    expect(box.y + box.height).toBeLessThanOrEqual(540);
    expect(intersects(box, await page.locator('#remove-probe').boundingBox())).toBe(false);
    const buttons = await dialog(page).locator('.acts').boundingBox();
    expect(buttons.y, 'the buttons start inside the visible part').toBeGreaterThanOrEqual(120);
    expect(buttons.y + buttons.height, 'and end inside it').toBeLessThanOrEqual(540);
    // Centred in the visible part, not the layout viewport.
    expect(Math.abs(box.y + box.height / 2 - (120 + 210))).toBeLessThanOrEqual(1);
  });
});

test.describe('one modal', () => {
  test('D7 while it is open the palette does not open, a second confirm is refused, and there is one live region', async ({ page }) => {
    await open(page);
    await page.click('#remove-probe');
    await page.keyboard.press('Meta+k');
    await page.keyboard.press('Control+k');
    await expect(page.locator('dialog.palette')).toHaveCount(0);
    const second = await page.evaluate(() => window.gatewayConfirm({ opener: document.body, key: 'other', verb: 'Remove', object: 'other', progress: 'Removing other…', consequences: [], run: () => null }));
    expect(second).toEqual({ outcome: 'declined' });
    await expect(page.locator('[aria-live], [role="status"], [role="alert"]')).toHaveCount(1);
  });
});

for (const width of [390, 1440]) {
  test(`D6 axe at ${width} px with the dialog open, refused and unconfirmed`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    let calls = 0;
    await page.route(PROBE, (r) => { calls += 1; return r.fulfill({ status: calls === 1 ? 403 : 500, json: {} }); });
    await open(page);
    await page.click('#remove-probe');
    expect(await blockingViolations(page)).toEqual([]);
    await action(page).click();
    await expect(message(page)).toBeVisible();
    expect(await blockingViolations(page)).toEqual([]);
    await page.getByRole('button', { name: 'Close' }).click();
    await page.click('#remove-probe');
    await action(page).click();
    await expect(message(page)).toContainText('did not confirm');
    expect(await blockingViolations(page)).toEqual([]);
  });
}

test.describe('fold check', () => {
  test('D10 a late first request cannot release a newer lock: a third confirm is still refused', async ({ page }) => {
    await page.clock.install();
    const first = held();
    let calls = 0;
    const second = held();
    await page.route(PROBE, (r) => { calls += 1; return (calls === 1 ? first : second).answer(r); });
    await open(page);
    await page.click('#remove-probe');
    await action(page).click();
    await page.clock.runFor(30_000);
    await dialog(page).getByRole('button', { name: 'Close' }).click();
    await page.clock.runFor(150_000); // the first lock is released by the clock
    // A second operation takes the lock and is still running.
    await page.evaluate(() => { window.gatewayConfirm({ opener: document.getElementById('remove-probe'), key: 'two', verb: 'Remove', object: 'two', progress: 'Removing two…', consequences: [], run: () => fetch('/ui/api/destroy-probe', { method: 'DELETE' }) }); });
    await page.locator('dialog.confirm').getByRole('button', { name: 'Remove two' }).click();
    // It is cut off too and closed, so only its lock (not an open dialog) keeps a third out.
    await page.clock.runFor(30_000);
    await dialog(page).getByRole('button', { name: 'Close' }).click();
    await expect(dialog(page)).toHaveCount(0);
    first.release(204); // the first request settles late, while the second still holds the lock
    await page.clock.runFor(1_000);
    await page.evaluate(() => {
      window.__third = null;
      window.gatewayConfirm({ opener: document.getElementById('remove-probe'), key: 'three', verb: 'Remove', object: 'three', progress: 'Removing three…', consequences: [], run: () => null })
        .then((r) => { window.__third = r; });
    });
    await expect.poll(() => page.evaluate(() => window.__third)).toEqual({ outcome: 'declined' });
    await expect(dialog(page)).toHaveCount(0);
    second.release(204);
  });

  test('D11 the unconfirmed set clears on navigation, never on a Retry of the same page', async ({ page }) => {
    let calls = 0;
    await page.route(PROBE, (r) => { calls += 1; return r.fulfill({ status: 500, json: {} }); });
    await open(page);
    await page.click('#remove-probe');
    await action(page).click();
    await expect(message(page)).toContainText('did not confirm');
    await dialog(page).getByRole('button', { name: 'Close' }).click();
    // A screen refreshing itself in place does not clear it.
    await page.evaluate(() => window.gatewayConfirm({ opener: document.body, key: 'probe:one', verb: 'Remove', object: 'probe', progress: 'Removing probe…', consequences: [], run: () => null }));
    await expect(dialog(page)).toHaveCount(0);
    // Navigating away and back renders the page anew, and the action opens again.
    await page.click('nav.route-nav a[data-page="tools"]');
    await page.click('nav.route-nav a[data-page="gateway"]');
    await page.click('nav.tabs a[href="/ui/gateway/actions"]');
    await page.click('#remove-probe');
    await expect(dialog(page)).toBeVisible();
    expect(calls).toBe(1);
  });

  test('D12 failed() marks a retry only under replay safe, a safe 429 retries, and failed() cannot turn a 500 into a refusal', async ({ page }) => {
    let status = 400;
    await page.route(PROBE, (r) => r.fulfill({ status, json: {} }));
    await open(page, "{ replay: 'safe', failed: (e) => ({ reason: 'Busy.', next: 'Wait a moment.', retry: true }) }");
    await page.click('#remove-probe');
    await action(page).click();
    await expect(dialog(page).getByRole('button', { name: 'Try again' })).toBeVisible();
    await dialog(page).getByRole('button', { name: 'Close' }).click();
    status = 429;
    await page.evaluate(() => { window.__confirm = () => ({ replay: 'safe', key: 'probe:429' }); });
    await page.click('#remove-probe');
    await action(page).click();
    await expect(dialog(page).getByRole('button', { name: 'Try again' })).toBeVisible();
    await dialog(page).getByRole('button', { name: 'Close' }).click();
    status = 500;
    await page.evaluate(() => { window.__confirm = () => ({ replay: 'safe', key: 'probe:500', failed: () => ({ reason: 'Fine.', next: 'Retry.', retry: true }) }); });
    await page.click('#remove-probe');
    await action(page).click();
    await expect(message(page)).toContainText('The gateway did not confirm the outcome.');
    await expect(dialog(page).getByRole('button', { name: 'Try again' })).toHaveCount(0);
    // Without replay safe, failed()'s retry: true is ignored.
    await dialog(page).getByRole('button', { name: 'Close' }).click();
    status = 400;
    await page.evaluate(() => { window.__confirm = () => ({ key: 'probe:400', failed: () => ({ reason: 'Busy.', next: 'Wait.', retry: true }) }); });
    await page.click('#remove-probe');
    await action(page).click();
    await expect(message(page)).toContainText('Busy.');
    await expect(dialog(page).getByRole('button', { name: 'Try again' })).toHaveCount(0);
  });

  test('D13 an opener at the page end on a short page gets temporary room, restored on close with the scroll', async ({ page }) => {
    await page.setViewportSize({ width: 820, height: 500 });
    await open(page);
    const before = await page.evaluate(() => [scrollY, document.getElementById('content').scrollHeight]);
    await page.click('#remove-probe');
    const box = await dialog(page).boundingBox();
    expect(intersects(box, await page.locator('#remove-probe').boundingBox())).toBe(false);
    await page.keyboard.press('Escape');
    // Restored in the dialog's close event, which fires just after Esc.
    await expect.poll(() => page.evaluate(() => [scrollY, document.getElementById('content').scrollHeight])).toEqual(before);
    expect(await page.evaluate(() => document.body.style.minHeight)).toBe('');
  });

  test('D14 a pinch-panned visual viewport centres the dialog in the visible part, sideways too', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.addInitScript(() => {
      const vv = new EventTarget();
      Object.defineProperties(vv, { height: { get: () => 450 }, width: { get: () => 720 }, offsetTop: { get: () => 0 }, offsetLeft: { get: () => 600 }, scale: { get: () => 2 } });
      Object.defineProperty(window, 'visualViewport', { get: () => vv });
    });
    await open(page);
    await page.click('#remove-probe');
    const box = await dialog(page).boundingBox();
    expect(Math.abs(box.x + box.width / 2 - (600 + 360))).toBeLessThanOrEqual(1);
  });

  test('D15 the docking fallback: when no centred box fits, the dialog sits in the band away from the opener, buttons in view', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.addInitScript(() => {
      const vv = new EventTarget();
      Object.defineProperties(vv, { height: { get: () => 420 }, width: { get: () => 390 }, offsetTop: { get: () => 120 }, offsetLeft: { get: () => 0 }, scale: { get: () => 1 } });
      Object.defineProperty(window, 'visualViewport', { get: () => vv });
      window.__openerStyle = { minHeight: '120px' };
    });
    await open(page);
    await page.click('#remove-probe');
    const box = await dialog(page).boundingBox();
    const buttons = await dialog(page).locator('.acts').boundingBox();
    expect(intersects(box, await page.locator('#remove-probe').boundingBox())).toBe(false);
    expect(buttons.y >= 120 && buttons.y + buttons.height <= 540).toBe(true);
  });

  test('D16 a done() that throws after success closes as done with a console error; a removed opener hands focus to the content', async ({ page }) => {
    const errors = [];
    page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
    await page.route(PROBE, (r) => r.fulfill({ status: 204 }));
    await open(page, "{ done: () => { throw new Error('screen done bug'); } }");
    await page.click('#remove-probe');
    await page.evaluate(() => document.getElementById('remove-probe').remove());
    await action(page).click();
    await expect(dialog(page)).toHaveCount(0);
    await expect(page).toHaveURL(/\/ui\/gateway\/actions$/);
    await expect(page.locator('#content')).toBeFocused();
    await expect.poll(async () => (await outcomes(page))[0]?.outcome).toBe('done');
    expect(errors.some((e) => e.includes('screen done bug'))).toBe(true);
  });
});

test.describe('code review round 1', () => {
  test('D17 Esc after a refusal resolves failed, and after an unconfirmed outcome resolves unconfirmed, never kept', async ({ page }) => {
    let status = 409;
    await page.route(PROBE, (r) => r.fulfill({ status, json: {} }));
    await open(page);
    await page.click('#remove-probe');
    await action(page).click();
    await expect(message(page)).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(dialog(page)).toHaveCount(0);
    status = 500;
    await page.evaluate(() => { window.__confirm = () => ({ key: 'probe:two' }); });
    await page.click('#remove-probe');
    await action(page).click();
    await expect(message(page)).toContainText('did not confirm');
    await page.keyboard.press('Escape');
    await expect(dialog(page)).toHaveCount(0);
    await expect.poll(async () => (await outcomes(page)).map((o) => o.outcome)).toEqual(['failed', 'unconfirmed']);
  });

  test('D18 a failed() that throws falls back to the default words and the dialog still settles', async ({ page }) => {
    const errors = [];
    page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
    await page.route(PROBE, (r) => r.fulfill({ status: 403, json: {} }));
    await open(page, "{ failed: () => { throw new Error('screen failed bug'); } }");
    await page.click('#remove-probe');
    await action(page).click();
    await expect(message(page)).toContainText('This key may not remove probe.');
    await dialog(page).getByRole('button', { name: 'Close' }).click();
    await expect.poll(async () => (await outcomes(page))[0]?.outcome).toBe('failed');
    expect(errors.some((e) => e.includes('screen failed bug'))).toBe(true);
  });

  test('D19 sign-in taking over while a request is out stops the dialog clocks: no 10 s or 30 s timer is left pending', async ({ page }) => {
    // A ledger of live timers, by delay: the shell calls the global setTimeout, so it is counted.
    await page.addInitScript(() => {
      const set = window.setTimeout.bind(window);
      const clear = window.clearTimeout.bind(window);
      window.__timers = new Map();
      window.setTimeout = (fn, ms, ...args) => {
        const id = set((...x) => { window.__timers.delete(id); if (typeof fn === 'function') fn(...x); }, ms, ...args);
        window.__timers.set(id, ms);
        return id;
      };
      window.clearTimeout = (id) => { window.__timers.delete(id); clear(id); };
    });
    const h = held();
    await page.route(PROBE, h.answer);
    await page.route('**/ui/api/forbidden-probe', (r) => r.fulfill({ status: 401, json: {} }));
    await open(page);
    await page.click('#remove-probe');
    await action(page).click();
    await expect.poll(() => page.evaluate(() => [...window.__timers.values()].filter((ms) => ms === 30_000).length)).toBe(1);
    // Another request answers 401: sign-in takes over and closes the dialog.
    await page.evaluate(async () => { const m = await import(document.querySelector('script[type="module"][src*="/shell."]').src); try { await m.api('/ui/api/forbidden-probe'); } catch {} });
    await expect(page.locator('#signin')).toBeVisible();
    await expect(dialog(page)).toHaveCount(0);
    expect(await page.evaluate(() => [...window.__timers.values()].filter((ms) => ms === 10_000 || ms === 30_000))).toEqual([]);
    await expect.poll(async () => (await outcomes(page))[0]?.outcome).toBe('unconfirmed');
    h.release(204);
  });

  test('D20 a malformed spec throws before anything opens: run must be a function, consequences a list', async ({ page }) => {
    await open(page);
    const names = await page.evaluate(() => [{ run: 'x', consequences: [] }, { run: () => null, consequences: 'one' }].map((bad) => {
      try { window.gatewayConfirm({ opener: document.body, key: 'k', verb: 'Remove', object: 'x', progress: 'Removing x…', ...bad }); return 'opened'; } catch (e) { return e.name; }
    }));
    expect(names).toEqual(['TypeError', 'TypeError']);
    await expect(dialog(page)).toHaveCount(0);
  });

  test('D21 a visible part shorter than the dialog natural height still holds the whole dialog', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 120 });
    await page.addInitScript(() => { window.__openerStyle = { minHeight: '200px' }; });
    await open(page, "{ typeToConfirm: 'probe', consequences: ['One.', 'Two.', 'Three.', 'Four.', 'Five.', 'Six.', 'Seven.', 'Eight.'] }");
    await page.click('#remove-probe');
    const box = await dialog(page).boundingBox();
    expect(box.y).toBeGreaterThanOrEqual(0);
    expect(box.y + box.height).toBeLessThanOrEqual(120);
    // Not vacuous: the dialog is there, and its buttons can be scrolled to inside it.
    expect(box.height).toBeGreaterThan(40);
    // A user can scroll it: content taller than the dialog is never clipped away.
    expect(await dialog(page).evaluate((d) => d.scrollHeight <= d.clientHeight || ['auto', 'scroll'].includes(getComputedStyle(d).overflowY))).toBe(true);
    await action(page).scrollIntoViewIfNeeded();
    const button = await action(page).boundingBox();
    expect(button.y >= 0 && button.y + button.height <= 120).toBe(true);
    // The typed field and the last consequence can be reached the same way.
    for (const part of [dialog(page).getByLabel('Type probe to confirm'), dialog(page).locator('li').last()]) {
      await part.scrollIntoViewIfNeeded();
      const r = await part.boundingBox();
      expect(r.y >= 0 && r.y + r.height <= 120).toBe(true);
    }
  });
});

test.describe('code review round 1, second seat', () => {
  test('D22 the done notice survives a default-tab redirect and goes on any later navigation, even to the same address', async ({ page }) => {
    await page.route(PROBE, (r) => r.fulfill({ status: 204 }));
    await open(page, "{ done: { path: '/ui/servers', notice: 'probe removed' } }");
    await page.click('#remove-probe');
    await action(page).click();
    await expect(page).toHaveURL(/\/ui\/servers\/status$/);
    await expect(page.locator('#content .done-notice')).toContainText('probe removed');
    await page.evaluate(() => { history.pushState(null, '', '/ui/servers/status'); dispatchEvent(new PopStateEvent('popstate')); });
    await expect(page.locator('#content .done-notice')).toHaveCount(0);
  });

  test('D23 on a page already longer than the screen, an opener at its very end is still moved clear of the dialog', async ({ page }) => {
    await page.setViewportSize({ width: 820, height: 600 });
    await page.addInitScript(() => { window.__openerStyle = { marginTop: '1600px', marginBottom: '400px' }; });
    await open(page, "{ consequences: ['One.', 'Two.', 'Three.', 'Four.', 'Five.', 'Six.', 'Seven.', 'Eight.', 'Nine.', 'Ten.'] }");
    await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
    await page.click('#remove-probe');
    const box = await dialog(page).boundingBox();
    expect(intersects(box, await page.locator('#remove-probe').boundingBox())).toBe(false);
    // Room was added, so it stays centred rather than docking beside the opener.
    expect(Math.abs(box.y + box.height / 2 - 300)).toBeLessThanOrEqual(1);
  });
});

test.describe('code review round 2', () => {
  test('D24 sign-in taking over mid-request frees the lock: nothing opens while signed out, and the next identity can act', async ({ page }) => {
    const h = held();
    await page.route(PROBE, h.answer);
    await page.route('**/ui/api/forbidden-probe', (r) => r.fulfill({ status: 401, json: {} }));
    await open(page);
    await page.click('#remove-probe');
    await action(page).click();
    await page.evaluate(async () => { const m = await import(document.querySelector('script[type="module"][src*="/shell."]').src); try { await m.api('/ui/api/forbidden-probe'); } catch {} });
    await expect(page.locator('#signin')).toBeVisible();
    const confirmOther = () => page.evaluate(() => {
      window.__other = null;
      window.gatewayConfirm({ opener: document.getElementById('remove-probe'), key: 'other', verb: 'Remove', object: 'other', progress: 'Removing other…', consequences: [], run: () => null })
        .then((r) => { window.__other = r; });
    });
    await confirmOther();
    await expect.poll(() => page.evaluate(() => window.__other)).toEqual({ outcome: 'declined' });
    // Signed in again (the request is still out): the lock went with the dialog.
    await page.evaluate(() => { document.body.classList.remove('signed-out'); document.getElementById('signin').hidden = true; });
    await confirmOther();
    await expect(dialog(page)).toBeVisible();
    h.release(204);
  });
});
