// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// A server's Actions tab. Remove and Restart go through the
// shell's one confirm; Sign in again posts to the two sign-in routes (T3-T7 of
// the frozen test plan). Every route answers with a body written here.
import { test, expect, blockingViolations, WIDTHS } from './base.mjs';
import { shellReady, recordAnnouncements, announced } from './shell.mjs';
import { served } from './copy-check.mjs';
import { entry, fullView, fakeServerGateway, gate, shellCall } from './server-page.mjs';

test.use({ timezoneId: 'UTC' });

const NAME = 'my server';
const ENC = 'my%20server';
const dialog = (page) => page.locator('dialog.confirm');
const key = (name, backends, more = {}) => ({ name, backends, allowed_tools: null, denied_tools: null, admin: false, live: true, ...more });
const keysBody = (...keys) => ({ code: 200, body: { keys } });
async function actions(page, server, opts = {}) {
  const seen = await fakeServerGateway(page, { status: fullView(server, entry('other', 'running')), ...opts });
  await page.goto(`/ui/servers/${encodeURIComponent(server.name)}/actions`);
  await shellReady(page);
  return seen;
}
const deletes = (seen) => seen.backend.filter((r) => r.method === 'DELETE');
const posts = (seen, suffix) => seen.backend.filter((r) => r.method === 'POST' && r.path.endsWith(suffix));
// The shell confirm's words per refused DELETE, in order: reason, the gateway's sentence when the shell
// shows it, next step. A 503 is not one of the shell's refusals for a non-retryable action, so it reads
// as not confirmed (pinned as it is today; the wording is filed for v4.0.1).
const REFUSED_WORDS = {
  404: [`⊘ ${NAME} is no longer there.`, 'Reload the page to see what is.'],
  409: [`⊘ ${NAME} changed since this page loaded.`, 'Reload the page and try again.'],
  503: ['⊘ The gateway did not confirm the outcome.', 'sentence 503', `Reload to see whether ${NAME} changed.`],
};

test.describe('T3 Remove states its consequences in numbers', () => {
  test('T3a it names the reaching keys in order, with tools, calls and the after-effects', async ({ page }) => {
    const keys = keysBody(
      key('alpha', [NAME]), key('wild', ['*']), key('later', [NAME], { live: false }),
      key('elsewhere', ['other']), key('nothing', []),
    );
    await actions(page, entry(NAME, 'running', { tools_cached: 7, calls_24h: 31 }), { keys });
    const c = page.locator('#content');
    await expect(c.locator('.sp > .sp-audit')).toHaveText('Actions on this page are recorded in Activity under your name.');
    await expect(c.getByRole('button', { name: 'Keep it paused' })).toHaveCount(0);
    await expect(c.getByRole('button', { name: 'Reconnect' })).toHaveCount(0);
    await c.getByRole('button', { name: `Remove ${NAME}` }).click();
    const items = dialog(page).locator('li');
    await expect(items).toHaveText([
      '7 tools disappear.',
      '3 keys reach it: alpha, wild, later.',
      'It was called 31 times in the last 24 hours.',
      'Those keys get a tool-not-found answer on their next call.',
      'Its entry is deleted from gateway.yaml. It can be restored from the Gateway history, or added again.',
      'The removal is recorded under your name.',
    ]);
  });

  for (const [count, line] of [[3, '3 keys reach it: k1, k2, k3.'], [4, '4 keys reach it: k1, k2, k3 and 1 more.'], [5, '5 keys reach it: k1, k2, k3 and 2 more.']]) {
    test(`T3b ${count} reaching keys: three named and the rest counted`, async ({ page }) => {
      const keys = keysBody(...Array.from({ length: count }, (_, i) => key(`k${i + 1}`, [NAME])));
      await actions(page, entry(NAME, 'running'), { keys });
      await page.getByRole('button', { name: `Remove ${NAME}` }).click();
      await expect(dialog(page).locator('li').nth(1)).toHaveText(line);
    });
  }

  test('T3c a failed keys read says so and Remove still works; no call line when calls are not known', async ({ page }) => {
    const seen = await actions(page, entry(NAME, 'running', { calls_24h: null }), {
      keys: { code: 500, body: {} }, backend: () => ({ code: 204, body: {} }),
    });
    await page.getByRole('button', { name: `Remove ${NAME}` }).click();
    await expect(dialog(page).locator('li')).toContainText(['The keys that reach it could not be counted.']);
    await expect(dialog(page).getByText(/times in the last 24 hours/)).toHaveCount(0);
    await dialog(page).getByRole('button', { name: `Remove ${NAME}` }).click();
    await expect.poll(() => deletes(seen).length).toBe(1);
  });
});

test.describe('T4 Remove: in progress, refused, done', () => {
  test('T4 a held DELETE shows the progress words on a disabled button', async ({ page }) => {
    const hold = gate();
    await actions(page, entry(NAME, 'running'), { backend: () => ({ code: 204, body: {}, hold: hold.shut }) });
    await page.getByRole('button', { name: `Remove ${NAME}` }).click();
    await dialog(page).getByRole('button', { name: `Remove ${NAME}` }).click();
    const busy = dialog(page).locator('button[aria-busy="true"]');
    await expect(busy).toHaveText(`Removing ${NAME}…`);
    await expect(busy).toBeDisabled();
    hold.open();
  });

  for (const [status, words] of Object.entries(REFUSED_WORDS)) {
    const code = Number(status); // object keys are strings; the fake answers with a number
    test(`T4 a ${code} shows its reason and next step, and the dialog stays`, async ({ page }) => {
      await actions(page, entry(NAME, 'running'), { backend: () => ({ code, body: { error: 'x', message: `sentence ${code}` } }) });
      await page.getByRole('button', { name: `Remove ${NAME}` }).click();
      await dialog(page).getByRole('button', { name: `Remove ${NAME}` }).click();
      await expect(dialog(page).locator('.confirm-message p')).toHaveText(words);
      await expect(dialog(page)).toBeVisible();
    });
  }

  test('T4 204 lands on the list with the notice; 200 carries the note', async ({ page }) => {
    let answer = { code: 204, body: {} };
    await actions(page, entry(NAME, 'running'), { backend: () => answer });
    await page.getByRole('button', { name: `Remove ${NAME}` }).click();
    await dialog(page).getByRole('button', { name: `Remove ${NAME}` }).click();
    await expect(page).toHaveURL(/\/ui\/servers\/status$/);
    await expect(page.locator('.done-title')).toContainText(`${NAME} was removed.`);
    answer = { code: 200, body: { note: 'note-sentinel-comments' } };
    await page.goto(`/ui/servers/${ENC}/actions`);
    await shellReady(page);
    await page.getByRole('button', { name: `Remove ${NAME}` }).click();
    await dialog(page).getByRole('button', { name: `Remove ${NAME}` }).click();
    await expect(page.locator('.done-title')).toContainText('note-sentinel-comments');
  });

  test('T4 Cancel sends nothing and gives focus back to Remove', async ({ page }) => {
    const seen = await actions(page, entry(NAME, 'running'));
    const opener = page.locator('#content').getByRole('button', { name: `Remove ${NAME}` });
    await opener.click();
    await dialog(page).getByRole('button', { name: `Cancel ${NAME}` }).click();
    await expect(opener).toBeFocused();
    expect(deletes(seen)).toEqual([]);
  });
});
test.describe('T5 Restart', () => {
  test('T5 the press opens the confirm and sends nothing; Cancel sends nothing', async ({ page }) => {
    const seen = await actions(page, entry(NAME, 'running'));
    const opener = page.locator('#content').getByRole('button', { name: `Restart ${NAME}` });
    await opener.click();
    await expect(dialog(page).locator('li')).toHaveText([
      'Calls in flight are cut.', 'The failure pause is reset.', 'Its tools stay listed.',
    ]);
    expect(posts(seen, '/revive')).toEqual([]);
    await dialog(page).getByRole('button', { name: `Cancel ${NAME}` }).click();
    await expect(opener).toBeFocused();
    expect(posts(seen, '/revive')).toEqual([]);
  });

  test('T5 confirming sends one POST to the encoded revive path; revived lands on Status', async ({ page }) => {
    const seen = await actions(page, entry(NAME, 'running'), {
      backend: () => ({ code: 200, body: { backend: NAME, status: 'revived', breaker_was_open: false, transport_rebuilt: true } }),
    });
    await page.getByRole('button', { name: `Restart ${NAME}` }).click();
    await dialog(page).getByRole('button', { name: `Restart ${NAME}` }).click();
    await expect(page).toHaveURL(new RegExp(`/ui/servers/${ENC}/status$`));
    await expect(page.locator('.done-title')).toContainText(`${NAME} was restarted.`);
    expect(posts(seen, '/revive').map((r) => r.path)).toEqual([`/ui/api/backends/${ENC}/revive`]);
  });

  test('T5 not_revived says it did not restart', async ({ page }) => {
    await actions(page, entry(NAME, 'running'), {
      backend: () => ({ code: 200, body: { backend: NAME, status: 'not_revived', breaker_was_open: false, transport_rebuilt: false } }),
    });
    await page.getByRole('button', { name: `Restart ${NAME}` }).click();
    await dialog(page).getByRole('button', { name: `Restart ${NAME}` }).click();
    await expect(page.locator('.done-title')).toContainText(`${NAME} did not restart: the gateway is shutting down.`);
  });

  test('T5 a held POST is a disabled progress button; a 404 shows its reason and the dialog stays', async ({ page }) => {
    const hold = gate();
    let answer = { code: 200, body: { status: 'revived' }, hold: hold.shut };
    await actions(page, entry(NAME, 'running'), { backend: () => answer });
    await page.getByRole('button', { name: `Restart ${NAME}` }).click();
    await dialog(page).getByRole('button', { name: `Restart ${NAME}` }).click();
    const busy = dialog(page).locator('button[aria-busy="true"]');
    await expect(busy).toHaveText(`Restarting ${NAME}…`);
    await expect(busy).toBeDisabled();
    hold.open();
    answer = { code: 404, body: { error: 'not_found', message: 'gone' } };
    await page.goto(`/ui/servers/${ENC}/actions`);
    await shellReady(page);
    await page.getByRole('button', { name: `Restart ${NAME}` }).click();
    await dialog(page).getByRole('button', { name: `Restart ${NAME}` }).click();
    await expect(dialog(page).locator('.confirm-message p')).toHaveText(REFUSED_WORDS[404]);
    await expect(dialog(page)).toBeVisible();
  });

  test('T5 the button reads Retry now while paused, Restart otherwise', async ({ page }) => {
    await actions(page, entry(NAME, 'paused', { running: false }));
    await expect(page.getByRole('button', { name: `Retry now ${NAME}` })).toHaveCount(1);
    await expect(page.getByRole('button', { name: `Restart ${NAME}` })).toHaveCount(0);
  });
});
const OAUTH = (more = {}) => entry(NAME, 'needs_sign_in', { running: false, needs_sign_in: true, sign_in: { state: 'expired' }, ...more });
const START_OK = { code: 200, body: { authorization_url: 'https://idp.example/authorize?x=1', attempt_id: 'att-1', expires_at: '2026-11-26T10:15:00Z' } };
/** The fake for both sign-in routes: the start answers START_OK, the confirm `confirmAnswer`. */
const signInFake = (confirmAnswer) => (method, path) => (path.endsWith('/signin') ? START_OK : confirmAnswer);
/** Start a sign-in and press Finish: how the sign-in rows begin. */
async function startAndFinish(page) {
  await page.getByRole('button', { name: 'Sign in again' }).click();
  await page.getByRole('button', { name: 'Finish sign-in' }).click();
}

test.describe('T6 Sign in again', () => {
  test('T6 the card shows only for a server with sign_in', async ({ page }) => {
    await actions(page, entry(NAME, 'running'));
    await expect(page.getByRole('button', { name: `Restart ${NAME}` })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Sign in again' })).toHaveCount(0);
  });

  test('T6 start posts JSON, the link opens a new tab, Finish posts the decision, and the status is read again', async ({ page }) => {
    const seen = await actions(page, OAUTH(), {
      backend: signInFake({ code: 200, body: { backend: NAME, outcome: 'confirmed' } }),
    });
    await page.getByRole('button', { name: 'Sign in again' }).click();
    const link = page.getByRole('link', { name: 'Open the sign-in page' });
    await expect(link).toHaveAttribute('href', 'https://idp.example/authorize?x=1');
    await expect(link).toHaveAttribute('target', '_blank');
    await expect(link).toHaveAttribute('rel', /\bnoopener\b/);
    await expect(page.getByText('The sign-in link expires at 2026-11-26 10:15 UTC.')).toBeVisible();
    const reads = seen.status;
    await page.getByRole('button', { name: 'Finish sign-in' }).click();
    await expect.poll(() => seen.status).toBe(reads + 1);
    expect([posts(seen, '/signin').length, posts(seen, '/signin/confirm').length]).toEqual([1, 1]);
    const [start] = posts(seen, '/signin');
    const [finish] = posts(seen, '/signin/confirm');
    expect([start.path, start.body]).toEqual([`/ui/api/backends/${ENC}/signin`, {}]);
    expect([finish.path, finish.body]).toEqual([`/ui/api/backends/${ENC}/signin/confirm`, { decision: 'confirm', attempt_id: 'att-1' }]);
  });

  for (const bad of ['javascript:alert(1)', 'ftp://idp.example/x']) {
    test(`T6 a start answer with ${bad.split(':')[0]}: draws no link`, async ({ page }) => {
      await actions(page, OAUTH(), { backend: () => ({ code: 200, body: { ...START_OK.body, authorization_url: bad } }) });
      await page.getByRole('button', { name: 'Sign in again' }).click();
      await expect(page.getByRole('button', { name: 'Finish sign-in' })).toBeVisible();
      await expect(page.getByRole('link', { name: 'Open the sign-in page' })).toHaveCount(0);
    });
  }
});

const START_REFUSALS = [
  [403, 'dashboard_session_required'], [404, 'not_found'], [409, 'not_oauth'], [409, 'gateway_host_required'],
  [409, 'sign_in_in_progress'], [409, 'sign_in_cancelled'], [502, 'sign_in_unavailable'],
];
const CONFIRM_REFUSALS = [[404, 'no_sign_in'], [409, 'sign_in_not_ready'], [500, 'sign_in_save_failed']];

test.describe('T7 sign-in refusals show the gateway sentence', () => {
  for (const [code, err] of START_REFUSALS) {
    test(`T7 start ${code} ${err}`, async ({ page }) => {
      await actions(page, OAUTH(), { backend: () => ({ code, body: { error: err, message: `msg-${err}` } }) });
      await page.getByRole('button', { name: 'Sign in again' }).click();
      const card = page.locator('.sp-card', { has: page.getByRole('button', { name: 'Sign in again' }) });
      await expect(card.locator('.sp-error')).toHaveText(`msg-${err}`);
    });
  }
  for (const [code, err] of CONFIRM_REFUSALS) {
    test(`T7 confirm ${code} ${err}`, async ({ page }) => {
      const seen = await actions(page, OAUTH(), {
        backend: signInFake({ code, body: { error: err, message: `msg-${err}` } }),
      });
      await startAndFinish(page);
      await expect(page.locator('.sp-error')).toHaveText(`msg-${err}`);
      if (err === 'sign_in_not_ready') {
        await expect(page.getByRole('button', { name: 'Cancel sign-in' })).toBeVisible();
        await page.getByRole('button', { name: 'Finish sign-in' }).click();
        await expect.poll(() => posts(seen, '/signin/confirm').length).toBe(2);
        expect(posts(seen, '/signin/confirm').map((r) => r.body.attempt_id)).toEqual(['att-1', 'att-1']);
        expect(posts(seen, '/signin')).toHaveLength(1);
      } else {
        // A final refusal ends this attempt: its buttons go and the start can be pressed again.
        await expect(page.getByRole('button', { name: 'Finish sign-in' })).toHaveCount(0);
        await expect(page.getByRole('button', { name: 'Sign in again' })).toBeEnabled();
      }
    });
  }
});
test.describe('T10 at 390 px the open Remove dialog does not overflow', () => {
  for (const scheme of ['light', 'dark']) {
    test(`T10 Remove dialog, ${scheme}`, async ({ page }) => {
      await page.emulateMedia({ colorScheme: scheme });
      await page.setViewportSize({ width: 390, height: 844 });
      await actions(page, entry('a-rather-long-server-name-for-the-narrow-screen', 'running'));
      await page.getByRole('button', { name: /^Remove / }).click();
      const box = await dialog(page).boundingBox();
      expect(box.x).toBeGreaterThanOrEqual(0);
      expect(box.x + box.width).toBeLessThanOrEqual(390);
    });
  }
});

const HARD = 'a b/c?d%e#f é';
const HARD_ENC = 'a%20b%2Fc%3Fd%25e%23f%20%C3%A9';

test.describe('T9c every request path that carries the name is encoded (PR A sites)', () => {
  test('T9c the list link and the Activity link', async ({ page }) => {
    await fakeServerGateway(page, { status: fullView(entry(HARD, 'running')) });
    await page.goto('/ui/servers/status?open=other');
    await shellReady(page);
    await expect(page.getByRole('link', { name: HARD, exact: true })).toHaveAttribute('href', `/ui/servers/${HARD_ENC}/status`);
    await page.goto(`/ui/servers/${HARD_ENC}/status`);
    await shellReady(page);
    await expect(page.getByRole('link', { name: 'Its calls in Activity' })).toHaveAttribute('href', `/ui/activity?server=${HARD_ENC}`);
  });

  test('T9c the DELETE and the revive POST', async ({ page }) => {
    const seen = await actions(page, entry(HARD, 'running'), { backend: () => ({ code: 404, body: { error: 'x', message: 'y' } }) });
    await page.getByRole('button', { name: `Remove ${HARD}` }).click();
    await dialog(page).getByRole('button', { name: `Remove ${HARD}` }).click();
    await expect(dialog(page).getByText(/^⊘ /)).toHaveCount(1);
    await dialog(page).getByRole('button', { name: 'Close' }).click();
    await page.getByRole('button', { name: `Restart ${HARD}` }).click();
    await dialog(page).getByRole('button', { name: `Restart ${HARD}` }).click();
    await expect.poll(() => seen.backend.length).toBe(2);
    expect(deletes(seen).map((r) => r.path)).toEqual([`/ui/api/backends/${HARD_ENC}`]);
    expect(posts(seen, '/revive').map((r) => r.path)).toEqual([`/ui/api/backends/${HARD_ENC}/revive`]);
  });

  test('T9c the sign-in start and confirm POSTs', async ({ page }) => {
    const seen = await actions(page, entry(HARD, 'needs_sign_in', { sign_in: { state: 'expired' }, running: false }), {
      backend: signInFake({ code: 200, body: { outcome: 'cancelled' } }),
    });
    await page.getByRole('button', { name: 'Sign in again' }).click();
    await page.getByRole('button', { name: 'Cancel sign-in' }).click();
    await expect.poll(() => posts(seen, '/signin/confirm').length).toBe(1);
    expect(posts(seen, '/signin').map((r) => r.path)).toEqual([`/ui/api/backends/${HARD_ENC}/signin`]);
    expect(posts(seen, '/signin/confirm').map((r) => r.path)).toEqual([`/ui/api/backends/${HARD_ENC}/signin/confirm`]);
    expect(posts(seen, '/signin/confirm')[0].body).toEqual({ decision: 'cancel', attempt_id: 'att-1' });
  });
});

const PAGE_FILE = /^server-page\.[0-9a-f]{12}\.js$/;
const goTo = (page, path) => shellCall(page, (m, p) => m.go(p), path);
// One macrotask after an answer lands, so a late callback has had its turn before a row looks.
const settle = (page) => page.evaluate(() => new Promise((ok) => setTimeout(ok, 50)));

test.describe('review round 1: the replay contract, stale actions, final sign-in refusals', () => {
  test('T5 Restart opens its confirm with replay safe (source)', () => {
    const { name, text } = served(PAGE_FILE);
    expect(text, name).toMatch(/key: `revive:\$\{name\}`[^\n]*replay: 'safe'/);
  });

  test('T7 a confirm that gets no answer keeps the attempt and says the gateway did not answer', async ({ page }) => {
    await actions(page, OAUTH(), { backend: signInFake({ code: 200, drop: true }) });
    await startAndFinish(page);
    await expect(page.locator('.sp-error')).toHaveText('The gateway did not answer. The sign-in may still be open: try again.');
    await expect(page.getByRole('button', { name: 'Finish sign-in' })).toBeEnabled();
  });

  test('T7 one decision at a time: Finish and Cancel wait for the answer', async ({ page }) => {
    const hold = gate();
    await actions(page, OAUTH(), { backend: signInFake({ code: 200, body: { outcome: 'confirmed' }, hold: hold.shut }) });
    await startAndFinish(page);
    await expect(page.getByRole('button', { name: 'Cancel sign-in' })).toBeDisabled();
    await expect(page.getByRole('button', { name: 'Finish sign-in' })).toBeDisabled();
    hold.open();
  });

  test('T3c a keys read that never answers is given up after 15 s, and Remove still opens', async ({ page }) => {
    await page.clock.install();
    const never = gate();
    await actions(page, entry(NAME, 'running'), { keys: { code: 200, body: { keys: [] }, hold: never.shut } });
    await page.locator('#content').getByRole('button', { name: `Remove ${NAME}` }).click();
    await page.clock.fastForward(16_000);
    await expect(dialog(page).locator('li').nth(1)).toHaveText('The keys that reach it could not be counted.');
  });

  test('T6 the sign-in start and a refusal are announced', async ({ page }) => {
    await recordAnnouncements(page);
    await actions(page, OAUTH(), { backend: signInFake({ code: 404, body: { error: 'no_sign_in', message: 'Msg said.' } }) });
    await startAndFinish(page);
    await expect.poll(() => announced(page)).toEqual(expect.arrayContaining(['Sign-in started.', 'Msg said.']));
  });

  test('T4 Remove opens no confirm when the user left while the keys were read', async ({ page }) => {
    const hold = gate();
    await actions(page, entry(NAME, 'running'), { keys: { code: 200, body: { keys: [] }, hold: hold.shut } });
    await page.locator('#content').getByRole('button', { name: `Remove ${NAME}` }).click();
    await goTo(page, `/ui/servers/${ENC}/status`);
    await expect(page.locator('dl.sp-facts')).toHaveCount(1);
    const answered = page.waitForResponse('**/ui/api/keys');
    hold.open();
    await answered;
    await settle(page);
    await expect(dialog(page)).toHaveCount(0);
  });

  test('T6 a decision answered after the user left does not bring the Actions tab back', async ({ page }) => {
    const hold = gate();
    await actions(page, OAUTH(), { backend: signInFake({ code: 200, body: { outcome: 'confirmed' }, hold: hold.shut }) });
    await startAndFinish(page);
    await goTo(page, `/ui/servers/${ENC}/status`);
    await expect(page.locator('dl.sp-facts')).toHaveCount(1);
    const answered = page.waitForResponse('**/signin/confirm');
    hold.open();
    await answered;
    await settle(page);
    await expect(page).toHaveURL(new RegExp(`/ui/servers/${ENC}/status$`));
  });

  test('T7 a Finish answered 200 with a body that does not parse is not called a refusal, and the attempt stays', async ({ page }) => {
    await actions(page, OAUTH(), { backend: signInFake({ code: 200, raw: '{"outcome":"conf' }) });
    await startAndFinish(page);
    await expect(page.locator('.sp-error')).toHaveText("The gateway's answer could not be read. The sign-in may still be open: try again.");
    await expect(page.getByRole('button', { name: 'Finish sign-in' })).toBeEnabled();
  });
});

test.describe('T11 the open confirm, the keyboard and reduced motion', () => {
  for (const scheme of ['light', 'dark']) {
    for (const width of WIDTHS) {
      test(`T11 the open Remove confirm at ${width} px, ${scheme}: no blocking violations`, async ({ page }) => {
        await page.emulateMedia({ colorScheme: scheme });
        await page.setViewportSize({ width, height: 900 });
        await actions(page, entry(NAME, 'running'));
        await page.getByRole('button', { name: `Remove ${NAME}` }).click();
        await expect(dialog(page)).toBeVisible();
        expect(await blockingViolations(page)).toEqual([]);
      });
    }
  }

  test('T11 Tab reaches every action on the tab', async ({ page }) => {
    await actions(page, OAUTH());
    const want = [`Restart ${NAME}`, 'Sign in again', `Remove ${NAME}`];
    const reached = new Set();
    for (let i = 0; i < 60 && reached.size < want.length; i += 1) {
      await page.keyboard.press('Tab');
      const label = await page.evaluate(() => document.activeElement?.textContent ?? '');
      if (want.includes(label)) reached.add(label);
    }
    expect([...reached].sort()).toEqual([...want].sort());
  });

  test('T11 under reduced motion nothing runs an animation, the open confirm included', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await actions(page, entry(NAME, 'running'));
    await page.getByRole('button', { name: `Remove ${NAME}` }).click();
    await expect(dialog(page)).toBeVisible();
    expect(await page.evaluate(() => document.getAnimations().filter((a) => a.playState === 'running').length)).toBe(0);
  });
});
