// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Gateway › Actions, Reload now: the button posts to /ui/api/reload and the
// section reports the result beside the button: no change, the applied summary,
// a pending restart with advice to act on, or the gateway's refusal. Every
// restart block is drawn by restartAdvice(), which the shell exports. Real
// shell assets, mocked /ui/api calls, an admin who is signed in.
import { readFileSync, readdirSync } from 'node:fs';
import { test, expect, WIDTHS, blockingViolations } from './base.mjs';
import { SHELL_DIR } from './copy-check.mjs';
import { shellReady, shellModuleUrl, recordAnnouncements, announced, signedInAdmin } from './shell.mjs';

const RELOAD = '**/ui/api/reload';

// The page's own words.
const INTRO = 'Changes to gateway.yaml are picked up on their own. If an edit has not taken effect, press Reload now: on a network filesystem, or a Docker bind mount from a Mac, the gateway may not see the file change.';
const NOTHING = 'Nothing changed: gateway.yaml matches what the gateway runs.';
const RELOADED = 'Reloaded.';
const NOT_APPLIED = 'These settings are not applied while a restart would not start.';
const REFUSED_409 = 'Not reloaded. The gateway runs as before.';
const REFUSED = 'Not reloaded.';
const UNCONFIRMED = 'Not confirmed: whether the gateway reloaded is not known. Try again.';

// The gateway's words: the mock's own, never the Rust constants.
const RR = 'server_address_changed';
const RS = 'config changed in fields that only a restart applies';
const SUMMARY = 'mock summary: backends changed';
const PENDING = 'mock summary — NOT YET APPLIED, restart required for: auth.enabled';
const ADDR = 'server address changed (restart required)';
const ADVICE = 'Restart the mock gateway now.';
// Two spaces inside a quoted path: the command must render, and so copy, exactly.
const CMD = "'/opt/mock  gw' serve --config '/srv/mock.yaml'";
const REFUSAL = 'A restart would not start: mock reason. Fix the config file first.';
const WARNED = `${PENDING} — WARNING: a restart would not start: mock reason`;
const H = '<img src=x onerror="window.__pwned=1">';

/** A 200 reload answer with `fields` over a no-restart base. */
const ok = (fields) => ({ status: 200, json: { status: 'ok', restart_required: false, restart_reason: null, ...fields } });
const CLASS2 = ok({ changes: SUMMARY });
const ADVICE_ANSWER = ok({ changes: ADDR, restart_required: true, restart_reason: RR, restart_advice: ADVICE, start_command: CMD });
const WIN_ANSWER = ok({ changes: PENDING, restart_required: true, restart_reason: RS, restart_advice: ADVICE });
const REFUSAL_ANSWER = ok({
  changes: WARNED, restart_required: true, restart_reason: RS, start_refusal: REFUSAL, restart_advice: ADVICE, start_command: CMD,
});
const A409 = { status: 409, json: { error: 'mock gate: the network posture refuses this file' } };
const A500 = { status: 500, json: { error: 'mock internal failure' } };

// One `lines()` entry: tag, the data-line (or the block's data-kind), tone, glyph, text.
const P = (line, text, more = {}) => ({ tag: 'p', line, tone: null, glyph: null, text, ...more });
const head = (t) => P('head', t);
const changes = (t) => P('changes', t);
const label = (t) => P('label', t);
const sentence = (t) => P('sentence', t);
const waiting = (t) => P('advice', t, { tone: 'waiting', glyph: '↻' });
const command = (t) => ({ tag: 'code', line: 'advice', tone: null, glyph: null, text: t });
const warning = (t) => P('refusal', t, { tone: 'warning', glyph: '⚠' });

const OK_LINES = [head(RELOADED), changes(SUMMARY)];
const OK_SAID = `${RELOADED} ${SUMMARY}.`;
const ADVICE_LINES = [head(RELOADED), changes(ADDR), waiting(ADVICE), command(CMD)];
const ADVICE_SAID = `${RELOADED} ${ADDR}. ${ADVICE}`;
const WIN_LINES = [head(RELOADED), changes(PENDING), waiting(ADVICE)];
const WIN_SAID = `${RELOADED} ${PENDING}. ${ADVICE}`;
const REFUSAL_LINES = [warning(REFUSAL), label(NOT_APPLIED), changes(WARNED)];
const REFUSAL_SAID = `${REFUSAL} ${NOT_APPLIED} ${WARNED}.`;
const L409 = [head(REFUSED_409), sentence('mock gate: the network posture refuses this file')];
const S409 = `${REFUSED_409} mock gate: the network posture refuses this file.`;
const L500 = [head(UNCONFIRMED), sentence('mock internal failure')];
const S500 = `${UNCONFIRMED} mock internal failure.`;

/** The Gateway module's source (gateway.<hash>.js), or undefined when there is none. */
function gatewaySource() {
  const name = readdirSync(SHELL_DIR).find((f) => /^gateway\.[0-9a-f]{12}\.js$/.test(f));
  return name && readFileSync(SHELL_DIR + name, 'utf8');
}

/**
 * POST /ui/api/reload answers each request with the next of `replies` (the
 * last repeats): {status, json}, {status, body, contentType}, 'abort', or
 * {hold: true}, which waits for release(answer). Each request is kept as
 * {method, postData}.
 */
async function reloadScreen(page, replies) {
  const requests = [];
  const queue = [...replies];
  let held = null;
  await signedInAdmin(page);
  await page.route(RELOAD, async (r) => {
    requests.push({ method: r.request().method(), postData: r.request().postData() });
    const reply = queue.length > 1 ? queue.shift() : queue[0];
    if (reply === 'abort') return r.abort();
    const answer = reply?.hold ? await new Promise((resolve) => { held = resolve; }) : reply;
    if (answer.body !== undefined) {
      return r.fulfill({ status: answer.status, contentType: answer.contentType ?? 'text/plain', body: answer.body });
    }
    return r.fulfill({ status: answer.status, json: answer.json });
  });
  return { requests, release: (answer) => held(answer) };
}

const section = (page) => page.locator('#content #reload');
const button = (page) => section(page).locator('button');
const idle = async (page) => page.evaluate(async (url) => (await import(url)).announcerIdle(), await shellModuleUrl(page));

/** Open Gateway › Actions with the recorder in place; returns how many entries came before any press. */
async function open(page) {
  await recordAnnouncements(page);
  await page.goto('/ui/gateway/actions');
  await shellReady(page);
  await idle(page);
  return (await announced(page)).length;
}

/** The entries written since `from`, once the announcer is idle. */
async function saidSince(page, from) {
  await idle(page);
  return (await announced(page)).slice(from);
}

/** The outcome slot's lines in document order, glyphs left out of the text. */
const lines = (page) => section(page).locator('.reload-outcome').evaluate((slot) => [...slot.querySelectorAll('p, code')].map((n) => {
  const bare = n.cloneNode(true);
  for (const g of bare.querySelectorAll('.glyph')) g.remove();
  return {
    tag: n.tagName.toLowerCase(),
    line: n.dataset.line ?? n.closest('.restart')?.dataset.kind ?? null,
    tone: n.dataset.tone ?? null,
    glyph: n.querySelector('.glyph')?.textContent ?? null,
    text: bare.textContent.trim(),
  };
}));

/** Press Reload now and wait for the answer to be drawn. */
async function press(page) {
  await expect(section(page)).toBeVisible();
  await button(page).click();
  await expect(button(page)).toHaveText('Reload now');
}

/**
 * The standing check after a press: these lines exactly, the button enabled and focused.
 * It ends once the announcer is idle, so the next press's lines are a new entry: the
 * announcer joins whatever is queued at one write, and a quick next press would join them.
 */
async function settled(page, expected) {
  await expect(button(page)).toBeEnabled();
  await expect(button(page)).toHaveText('Reload now');
  expect(await lines(page)).toEqual(expected);
  await expect(button(page)).toBeFocused();
  await idle(page);
}

/** One press with `answer`, its lines and its one entry. */
async function oneOutcome(page, answer, expected, said, absent = []) {
  await reloadScreen(page, [answer]);
  const from = await open(page);
  await press(page);
  await settled(page, expected);
  expect(await saidSince(page, from)).toEqual([said]);
  for (const text of absent) await expect(section(page)).not.toContainText(text);
}

test('R-SECTION: Gateway › Actions draws Reload gateway.yaml with its line and one button, and nothing is asked before a press', async ({ page }) => {
  const { requests } = await reloadScreen(page, [CLASS2]);
  await open(page);
  await expect(section(page)).toBeVisible();
  await expect(section(page).getByRole('heading', { level: 2 })).toHaveText('Reload gateway.yaml');
  await expect(section(page).locator('p').first()).toHaveText(INTRO);
  await expect(section(page).getByRole('button')).toHaveCount(1);
  await expect(section(page).getByRole('button', { name: 'Reload now' })).toBeVisible();
  await expect(section(page).locator('.reload-outcome')).toBeEmpty();
  await expect(section(page).locator('[aria-live], [role="status"], [role="alert"], [role="log"], [role="marquee"], [role="timer"], output')).toHaveCount(0);
  expect(requests).toEqual([]);
});

test('R-ONCE: while a reload is pending the button is busy and the earlier outcome stays; a second press sends nothing', async ({ page }) => {
  const { requests, release } = await reloadScreen(page, [CLASS2, { hold: true }]);
  const from = await open(page);
  await press(page);
  await settled(page, OK_LINES);
  await button(page).click();
  await expect(button(page)).toBeDisabled();
  await expect(button(page)).toHaveText('Reloading…');
  await expect(section(page)).toHaveAttribute('aria-busy', 'true');
  expect(await lines(page)).toEqual(OK_LINES);
  await button(page).click({ force: true });
  await button(page).click({ force: true });
  release(ok({ changes: SUMMARY }));
  await settled(page, OK_LINES);
  expect(requests).toEqual([{ method: 'POST', postData: null }, { method: 'POST', postData: null }]);
  await expect(section(page)).not.toHaveAttribute('aria-busy', /.*/);
  expect(await saidSince(page, from)).toEqual([OK_SAID, OK_SAID]);
});

test('R-OK-NONE: both of the gateway\'s no-change summaries read as nothing changed', async ({ page }) => {
  await reloadScreen(page, [ok({ changes: 'no changes detected' }), ok({ changes: 'no changes' })]);
  const from = await open(page);
  await press(page);
  await settled(page, [head(NOTHING)]);
  expect(await saidSince(page, from)).toEqual([NOTHING]);
  await press(page);
  await settled(page, [head(NOTHING)]);
  expect(await saidSince(page, from)).toEqual([NOTHING, NOTHING]);
});

test('R-SUMMARY-PIN: the page\'s no-change and 503 literals are the gateway\'s own', () => {
  const read = (rel) => readFileSync(new URL(`../../${rel}`, import.meta.url), 'utf8');
  expect(read('src/config_reload/mod.rs')).toContain('const NO_CHANGES_SUMMARY: &str = "no changes detected";');
  expect(read('src/config_reload/diff.rs')).toContain('"no changes".to_string()');
  expect(read('src/gateway/ui/mod.rs')).toContain('"Config reload is not enabled on this gateway"');
  const source = gatewaySource();
  expect(source, 'a gateway.<hash>.js module').toBeTruthy();
  expect(source).toContain("'no changes detected'");
  expect(source).toContain("'no changes'");
});

test('R-OK-CHANGES: an applied reload shows the gateway\'s summary; prose about a restart alone draws no restart block', async ({ page }) => {
  await reloadScreen(page, [CLASS2, ok({ changes: ADDR })]);
  const from = await open(page);
  await press(page);
  await settled(page, OK_LINES);
  await press(page);
  await settled(page, [head(RELOADED), changes(ADDR)]);
  await expect(section(page).locator('.restart')).toHaveCount(0);
  await expect(page.locator('dialog')).toHaveCount(0);
  expect(await saidSince(page, from)).toEqual([OK_SAID, `${RELOADED} ${ADDR}.`]);
});

test('R-RESTART-ADVICE: a pending restart shows the advice and the start command, whole-selectable, never the reason', async ({ page }) => {
  await oneOutcome(page, ADVICE_ANSWER, ADVICE_LINES, ADVICE_SAID, [RR]);
  const code = section(page).locator('code.start-command');
  await expect(code).toHaveCSS('user-select', 'all');
  // innerText is the rendered text, what a selection copies: no space collapsed.
  expect(await code.evaluate((n) => n.innerText)).toBe(CMD);
});

test('R-RESTART-WIN: advice with no start command shows no code line', async ({ page }) => {
  await oneOutcome(page, WIN_ANSWER, WIN_LINES, WIN_SAID, [RS]);
});

test('R-RESTART-NOCMD: Unix advice whose command could not be shown draws no code line', async ({ page }) => {
  await oneOutcome(page, ok({ changes: ADDR, restart_required: true, restart_reason: RR, restart_advice: ADVICE }),
    ADVICE_LINES.slice(0, 3), ADVICE_SAID, [RR]);
});

for (const [name, platform, userAgent] of [
  ['Win32', 'Win32', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'],
  ['Linux', 'Linux x86_64', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'],
]) {
  test.describe(`R-PLATFORM (${name})`, () => {
    test.use({ userAgent });
    test(`R-PLATFORM ${name}: the code line follows the answer's key, never the browser's platform`, async ({ page }) => {
      await page.addInitScript((p) => Object.defineProperty(Navigator.prototype, 'platform', { get: () => p }), platform);
      await reloadScreen(page, [ADVICE_ANSWER]);
      const from = await open(page);
      expect(await page.evaluate(() => navigator.platform)).toBe(platform);
      await press(page);
      await settled(page, ADVICE_LINES);
      expect(await saidSince(page, from)).toEqual([ADVICE_SAID]);
    });
  });
}

test('R-RESTART-REFUSAL-ONLY: the refusal the gateway sends, alone, comes first, above the not-applied label and the summary', async ({ page }) => {
  await oneOutcome(page, ok({ changes: WARNED, restart_required: true, restart_reason: RS, start_refusal: REFUSAL }),
    REFUSAL_LINES, REFUSAL_SAID, [RS, CMD]);
});

test('R-RESTART-REFUSAL: a refusal wins over advice and command, both present', async ({ page }) => {
  await oneOutcome(page, REFUSAL_ANSWER, REFUSAL_LINES, REFUSAL_SAID, [RS, ADVICE, CMD]);
});

test('R-RESTART-NEITHER: a pending restart with no advice key is not confirmed; a lone command is shown nowhere', async ({ page }) => {
  await reloadScreen(page, [
    ok({ changes: PENDING, restart_required: true, restart_reason: RS }),
    ok({ changes: PENDING, restart_required: true, restart_reason: RS, start_command: CMD }),
  ]);
  const from = await open(page);
  for (let i = 0; i < 2; i += 1) {
    await press(page);
    await settled(page, [head(UNCONFIRMED)]);
    await expect(section(page)).not.toContainText(CMD);
    await expect(section(page)).not.toContainText(PENDING);
  }
  expect(await saidSince(page, from)).toEqual([UNCONFIRMED, UNCONFIRMED]);
});

test('R-REPEAT: a second reload with the restart still pending says it again', async ({ page }) => {
  await reloadScreen(page, [WIN_ANSWER]);
  const from = await open(page);
  await press(page);
  await settled(page, WIN_LINES);
  await press(page);
  await settled(page, WIN_LINES);
  expect(await saidSince(page, from)).toEqual([WIN_SAID, WIN_SAID]);
});

for (const [seed, seedLines, seedSaid, next, nextLines, nextSaid] of [
  ['ADVICE', ADVICE_LINES, ADVICE_SAID, CLASS2, OK_LINES, OK_SAID],
  ['REFUSAL', REFUSAL_LINES, REFUSAL_SAID, CLASS2, OK_LINES, OK_SAID],
  ['ADVICE', ADVICE_LINES, ADVICE_SAID, A409, L409, S409],
  ['REFUSAL', REFUSAL_LINES, REFUSAL_SAID, A500, L500, S500],
  ['ADVICE', ADVICE_LINES, ADVICE_SAID, 'abort', [head(UNCONFIRMED)], UNCONFIRMED],
  ['REFUSAL', REFUSAL_LINES, REFUSAL_SAID, { status: 403, json: { error: 'forbidden' } }, [], 'Not available to this key.'],
  ['ADVICE', ADVICE_LINES, ADVICE_SAID, { status: 401, json: {} }, [], null],
]) {
  const nextName = typeof next === 'string' ? next : String(next.status);
  test(`R-REPLACE ${seed} then ${nextName}: a press replaces the earlier outcome`, async ({ page }) => {
    await reloadScreen(page, [seed === 'ADVICE' ? ADVICE_ANSWER : REFUSAL_ANSWER, next]);
    const from = await open(page);
    await press(page);
    await settled(page, seedLines);
    await button(page).click();
    if (nextSaid === null) {
      await expect(page.locator('#signin')).toBeVisible();
      expect(await lines(page)).toEqual(nextLines);
      await expect(page.locator('#signin-key')).toBeFocused();
      expect(await saidSince(page, from)).toEqual([seedSaid]);
    } else {
      await settled(page, nextLines);
      expect(await saidSince(page, from)).toEqual([seedSaid, nextSaid]);
    }
    await expect(section(page).locator('code, [data-kind="refusal"], [data-line="label"]')).toHaveCount(0);
  });
}

test('R-409: a refused reload says the gateway runs as before, with the gateway\'s sentence', async ({ page }) => {
  await oneOutcome(page, A409, L409, S409);
});

test('R-503: a reload the gateway cannot take says so, with its sentence', async ({ page }) => {
  await reloadScreen(page, [
    { status: 503, json: { error: 'Config reload is not enabled on this gateway' } },
    { status: 503, json: { error: 'mock: the gateway is shutting down' } },
  ]);
  const from = await open(page);
  await press(page);
  await settled(page, [head(REFUSED), sentence('Config reload is not enabled on this gateway')]);
  await press(page);
  await settled(page, [head(REFUSED), sentence('mock: the gateway is shutting down')]);
  expect(await saidSince(page, from)).toEqual([
    `${REFUSED} Config reload is not enabled on this gateway.`,
    `${REFUSED} mock: the gateway is shutting down.`,
  ]);
});

test('R-403: a key without the right sees the shell\'s forbidden banner and an empty outcome', async ({ page }) => {
  await reloadScreen(page, [CLASS2, { status: 403, json: { error: 'forbidden' } }]);
  const from = await open(page);
  await press(page);
  await settled(page, OK_LINES);
  await button(page).click();
  await expect(page.locator('#content .state[data-banner][data-state="forbidden"] h2')).toHaveText('Not available to this key');
  await settled(page, []);
  expect(await saidSince(page, from)).toEqual([OK_SAID, 'Not available to this key.']);
});

test('R-401: a signed-out answer shows the sign-in view and no outcome', async ({ page }) => {
  const { requests } = await reloadScreen(page, [{ status: 401, json: {} }]);
  const from = await open(page);
  await expect(section(page)).toBeVisible();
  await button(page).click();
  await expect(page.locator('body')).toHaveClass(/signed-out/);
  await expect(page.locator('#signin')).toBeVisible();
  await expect(page.locator('#signin-key')).toBeFocused();
  expect(await lines(page)).toEqual([]);
  expect(await saidSince(page, from)).toEqual([]);
  expect(requests).toHaveLength(1);
});

test('R-500: a failed reload is not confirmed, with the gateway\'s sentence', async ({ page }) => {
  await oneOutcome(page, A500, L500, S500);
});

test('R-NOANSWER: no answer, or a 200 that is not JSON, is not confirmed', async ({ page }) => {
  await reloadScreen(page, ['abort', { status: 200, contentType: 'application/json', body: '{not json' }]);
  const from = await open(page);
  await press(page);
  await settled(page, [head(UNCONFIRMED)]);
  await press(page);
  await settled(page, [head(UNCONFIRMED)]);
  expect(await saidSince(page, from)).toEqual([UNCONFIRMED, UNCONFIRMED]);
});

test('R-MALFORMED: a 200 that is not a reload answer is not confirmed', async ({ page }) => {
  const bodies = [
    null,
    {},
    { status: 'ok', restart_required: false, restart_reason: null },
    { status: 'ok', changes: SUMMARY, restart_reason: null },
    { status: 'ok', changes: SUMMARY, restart_required: 'false', restart_reason: null },
    { status: 'ok', changes: ['a'], restart_required: false, restart_reason: null },
    { status: 'ok', changes: 7, restart_required: false, restart_reason: null },
  ];
  await reloadScreen(page, bodies.map((json) => ({ status: 200, json })));
  const from = await open(page);
  for (let i = 0; i < bodies.length; i += 1) {
    await press(page);
    await settled(page, [head(UNCONFIRMED)]);
  }
  expect(await saidSince(page, from)).toEqual(bodies.map(() => UNCONFIRMED));
});

test('R-HOSTILE: every gateway string goes in as text', async ({ page }) => {
  const cases = [
    [ok({ changes: H }), [head(RELOADED), changes(H)], `${RELOADED} ${H}.`],
    [ok({ changes: ADDR, restart_required: true, restart_reason: RR, restart_advice: H, start_command: CMD }),
      [head(RELOADED), changes(ADDR), waiting(H), command(CMD)], `${RELOADED} ${ADDR}. ${H}.`],
    [ok({ changes: ADDR, restart_required: true, restart_reason: RR, restart_advice: ADVICE, start_command: H }),
      [head(RELOADED), changes(ADDR), waiting(ADVICE), command(H)], ADVICE_SAID],
    [ok({ changes: PENDING, restart_required: true, restart_reason: RS, start_refusal: H }),
      [warning(H), label(NOT_APPLIED), changes(PENDING)], `${H}. ${NOT_APPLIED} ${PENDING}.`],
    [{ status: 409, json: { error: H } }, [head(REFUSED_409), sentence(H)], `${REFUSED_409} ${H}.`],
  ];
  await reloadScreen(page, cases.map(([answer]) => answer));
  const from = await open(page);
  for (const [, expected] of cases) {
    await press(page);
    await settled(page, expected);
    await expect(section(page).locator('img')).toHaveCount(0);
  }
  expect(await page.evaluate(() => window.__pwned)).toBeUndefined();
  expect(await saidSince(page, from)).toEqual(cases.map(([, , said]) => said));
});

test('R-KEY: Enter and Space on the button each reload once', async ({ page }) => {
  const { requests } = await reloadScreen(page, [CLASS2]);
  const from = await open(page);
  await expect(section(page)).toBeVisible();
  await button(page).focus();
  await page.keyboard.press('Enter');
  await settled(page, OK_LINES);
  expect(requests).toHaveLength(1);
  await page.keyboard.press('Space');
  await expect(async () => expect(requests).toHaveLength(2)).toPass();
  await settled(page, OK_LINES);
  expect(await saidSince(page, from)).toEqual([OK_SAID, OK_SAID]);
});

test('R-ADVICE-FN: the shell exports restartAdvice, the one renderer of the restart keys', async ({ page }) => {
  await reloadScreen(page, [CLASS2]);
  await open(page);
  const got = await page.evaluate(async (url) => {
    const m = await import(url);
    if (typeof m.restartAdvice !== 'function') return { type: typeof m.restartAdvice };
    const describe = (node) => (node === null ? null : {
      kind: node.dataset.kind,
      lines: [...node.querySelectorAll('p, code')].map((n) => {
        const bare = n.cloneNode(true);
        for (const g of bare.querySelectorAll('.glyph')) g.remove();
        return { tag: n.tagName.toLowerCase(), tone: n.dataset.tone ?? null, glyph: n.querySelector('.glyph')?.textContent ?? null, text: bare.textContent.trim() };
      }),
      html: node.querySelectorAll('b, i, u').length,
    });
    return {
      type: 'function',
      cases: [
        { restart_required: true, restart_advice: '<b>a</b>', start_command: '<i>c</i>' },
        { restart_required: true, restart_advice: '<b>a</b>' },
        { restart_required: true, start_refusal: '<u>r</u>', restart_advice: '<b>a</b>', start_command: '<i>c</i>' },
        { restart_required: false },
      ].map((answer) => describe(m.restartAdvice(answer))),
    };
  }, await shellModuleUrl(page));
  expect(got.type).toBe('function');
  const pLine = (tone, glyph, text) => ({ tag: 'p', tone, glyph, text });
  expect(got.cases).toEqual([
    { kind: 'advice', lines: [pLine('waiting', '↻', '<b>a</b>'), { tag: 'code', tone: null, glyph: null, text: '<i>c</i>' }], html: 0 },
    { kind: 'advice', lines: [pLine('waiting', '↻', '<b>a</b>')], html: 0 },
    { kind: 'refusal', lines: [pLine('warning', '⚠', '<u>r</u>')], html: 0 },
    null,
  ]);
});

test('R-ONE-RENDERER: the Gateway module never reads the restart keys itself; it calls restartAdvice', () => {
  const source = gatewaySource();
  expect(source).not.toMatch(/start_refusal|restart_advice|start_command/);
  expect(source).toContain('restartAdvice(');
});

for (const width of WIDTHS) {
  for (const theme of ['dark', 'light']) {
    test(`R-A11Y ${width} ${theme}: the section, its restart and refusal outcomes and the forbidden banner pass axe`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await page.emulateMedia({ colorScheme: theme });
      await reloadScreen(page, [ADVICE_ANSWER, REFUSAL_ANSWER, { status: 403, json: { error: 'forbidden' } }]);
      await open(page);
      await expect(section(page)).toBeVisible();
      expect(await blockingViolations(page, '#reload')).toEqual([]);
      await press(page);
      await settled(page, ADVICE_LINES);
      expect(await blockingViolations(page, '#reload')).toEqual([]);
      await press(page);
      await settled(page, REFUSAL_LINES);
      expect(await blockingViolations(page, '#reload')).toEqual([]);
      await button(page).click();
      await expect(page.locator('#content .state[data-state="forbidden"]')).toBeVisible();
      expect(await blockingViolations(page)).toEqual([]);
    });
  }
}
