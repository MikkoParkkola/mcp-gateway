// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The tooltip component (tooltip.<hash>.js) and its copy loading. Copy is
// served per test through page.route, so each test controls what the module
// loads; triggers come from the module's own tip() on a fixture page.
import { test, expect } from './base.mjs';
import { shellReady, shellModuleUrl, withFixturePages, tooltipCoversNothing, tooltipModuleUrl, tooltipCssUrl } from './shell.mjs';

const COPY = {
  _pending: {},
  'fixture.status.calls': { title: 'Calls today', rows: [['What', 'Tool calls answered or refused.'], ['Window', 'Since 00:00, per call.'], ['Source', "The gateway's call log."]] },
  'fixture.status.paused': { title: 'Paused', text: 'The gateway stopped sending calls to this server.' },
  'fixture.status.markup': { title: '<img src=x onerror="window.pwned=1">', text: '<img src=x onerror="window.pwned=2">' },
  'fixture.status.rowmarkup': { title: 'Rows', rows: [['<img src=x onerror="window.pwned=3">', '<img src=x onerror="window.pwned=4">']] },
};

/** Serve the copy asset; `hold` is a promise the answer waits on; `count` gets each request. */
async function serveCopy(page, { copy = COPY, status = 200, hold, count } = {}) {
  await page.route('**/ui/assets/tips.*.json', async (route) => {
    if (count) count.n += 1;
    if (hold) await hold;
    if (status !== 200) return route.fulfill({ status, body: '' });
    return route.fulfill({ json: copy });
  });
}

/**
 * Draw triggers for `ids` into the content area through the module's tip().
 * With `settle` (the default) it then waits for the copy, so the triggers are finished.
 */
async function mount(page, ids, { layout = 'inline', settle = true } = {}) {
  await page.evaluate(async ({ url, ids, layout, settle }) => {
    const tips = await import(url);
    const box = document.createElement('div');
    box.className = `fixture-tips ${layout}`;
    if (layout !== 'inline') {
      // CSSOM writes are allowed by the CSP; style attributes in markup are not.
      box.style.position = 'fixed';
      const [v, h] = layout.split('-');
      box.style[v] = '4px';
      box.style[h] = '4px';
    }
    for (const id of ids) {
      const row = document.createElement('p');
      row.append(document.createTextNode(`${id} `), tips.tip(id));
      const next = document.createElement('button');
      next.type = 'button';
      next.className = 'next-action';
      next.textContent = 'Next';
      row.append(next);
      box.append(row);
    }
    document.getElementById('content').append(box);
    if (settle) await tips.tipsSettled();
  }, { url: tooltipModuleUrl(), ids, layout, settle });
}

async function settled(page) {
  await page.evaluate(async (url) => (await import(url)).tipsSettled(), tooltipModuleUrl());
}

async function ready(page) {
  await withFixturePages(page);
  await page.goto('/ui/overview/status');
  await shellReady(page);
}

const tipOf = (page, id) => page.locator(`.has-tip[data-tip="${id}"] .tip`);
// clock.install() leaves virtual time running with the wall clock, so a slow
// step between hover() and runFor() can fire a timer early. Pausing makes
// runFor() the only thing that moves time. The pause lands 5 s ahead because
// the clock still runs between reading it and pausing; it is called right
// after mount, before anything arms a timer, so the jump fires nothing.
const pauseClock = async (page) => page.clock.pauseAt(await page.evaluate(() => Date.now() + 5000));

test.describe('component', () => {
  test('T1 a text entry: a button named from the title, described by one tooltip', async ({ page }) => {
    await serveCopy(page);
    await ready(page);
    await mount(page, ['fixture.status.paused']);
    const button = page.getByRole('button', { name: 'About Paused' });
    await expect(button).toBeVisible();
    const id = await button.getAttribute('aria-describedby');
    const tip = page.locator(`[id="${id}"][role="tooltip"]`);
    await expect(tip).toHaveCount(1);
    await expect(tip.locator('.tip-body')).toHaveText('The gateway stopped sending calls to this server.');
    await expect(tip.locator('dl')).toHaveCount(0);
  });

  test('T1b a rows entry: a dl in copy order, absent labels drawn as nothing', async ({ page }) => {
    await serveCopy(page);
    await ready(page);
    await mount(page, ['fixture.status.calls']);
    const button = page.getByRole('button', { name: 'About Calls today' });
    const tip = page.locator(`[id="${await button.getAttribute('aria-describedby')}"][role="tooltip"]`);
    expect(await tip.locator('dt').allTextContents()).toEqual(['What', 'Window', 'Source']);
    expect(await tip.locator('dd').allTextContents()).toEqual(['Tool calls answered or refused.', 'Since 00:00, per call.', "The gateway's call log."]);
    await expect(tip.locator('.tip-body')).toHaveCount(0);
  });

  test('T2 hover waits 300 ms, pointer-out waits 150 ms, and the popup stays open under the pointer', async ({ page }) => {
    await page.clock.install();
    await serveCopy(page);
    await ready(page);
    await mount(page, ['fixture.status.paused']);
    await pauseClock(page);
    const tip = tipOf(page, 'fixture.status.paused');
    await page.getByRole('button', { name: 'About Paused' }).hover();
    await page.clock.runFor(250);
    await expect(tip).not.toHaveClass(/open/);
    await page.clock.runFor(100);
    await expect(tip).toHaveClass(/open/);
    await tip.hover();
    await page.clock.runFor(400);
    await expect(tip).toHaveClass(/open/);
    await page.mouse.move(5, 5);
    await page.clock.runFor(100);
    await expect(tip).toHaveClass(/open/);
    await page.clock.runFor(100);
    await expect(tip).not.toHaveClass(/open/);
  });

  test('T3 focus opens at once, Enter and Space keep it open, Esc closes and keeps focus, Tab away closes', async ({ page }) => {
    await serveCopy(page);
    await ready(page);
    await mount(page, ['fixture.status.paused']);
    const button = page.getByRole('button', { name: 'About Paused' });
    const tip = tipOf(page, 'fixture.status.paused');
    await button.focus();
    await expect(tip).toHaveClass(/open/);
    await page.keyboard.press('Enter');
    await expect(tip).toHaveClass(/open/);
    await page.keyboard.press('Space');
    await expect(tip).toHaveClass(/open/);
    await page.keyboard.press('Escape');
    await expect(tip).not.toHaveClass(/open/);
    await expect(button).toBeFocused();
    await page.keyboard.press('Enter');
    await expect(tip).toHaveClass(/open/);
    await page.keyboard.press('Tab');
    await expect(tip).not.toHaveClass(/open/);
  });

  test.describe('touch', () => {
    test.use({ hasTouch: true, isMobile: true, viewport: { width: 390, height: 844 } });
    test('T4 a tap toggles, and a tap outside closes', async ({ page }) => {
      await serveCopy(page);
      await ready(page);
      await mount(page, ['fixture.status.paused']);
      const tip = tipOf(page, 'fixture.status.paused');
      await page.getByRole('button', { name: 'About Paused' }).tap();
      await expect(tip).toHaveClass(/open/);
      await page.locator('h1').tap();
      await expect(tip).not.toHaveClass(/open/);
    });
  });
});

/** The resting boxes of the open popup, its trigger and the row's next action. */
async function restingBoxes(page) {
  return page.evaluate(async () => {
    await Promise.all(document.getAnimations().map((a) => a.finished));
    const r = (el) => el.getBoundingClientRect().toJSON();
    return { tip: r(document.querySelector('.has-tip .tip.open')), trigger: r(document.querySelector('.has-tip button')), next: r(document.querySelector('.next-action')), w: innerWidth, h: innerHeight };
  });
}

test.describe('placement and motion', () => {
  for (const corner of ['top-left', 'top-right', 'bottom-left', 'bottom-right']) {
    test(`T5 T5b T5c at the ${corner} the popup stays on screen and covers neither its trigger nor the next action`, async ({ page }) => {
      await serveCopy(page);
      await ready(page);
      await mount(page, ['fixture.status.calls'], { layout: corner });
      await page.getByRole('button', { name: 'About Calls today' }).focus();
      const b = await restingBoxes(page);
      const overlap = (x, y) => x.left < y.right && y.left < x.right && x.top < y.bottom && y.top < x.bottom;
      expect(b.tip.left).toBeGreaterThanOrEqual(0);
      expect(b.tip.top).toBeGreaterThanOrEqual(0);
      expect(b.tip.right).toBeLessThanOrEqual(b.w);
      expect(b.tip.bottom).toBeLessThanOrEqual(b.h);
      expect(overlap(b.tip, b.trigger)).toBe(false);
      expect(overlap(b.tip, b.next), JSON.stringify(b)).toBe(false);
    });
  }

  test('T5d at 390 px a trigger mid-screen keeps its popup on screen when neither edge fits', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await serveCopy(page);
    await ready(page);
    await mount(page, ['fixture.status.calls']);
    await page.evaluate(() => { document.querySelector('.fixture-tips p').style.paddingLeft = '150px'; });
    await page.getByRole('button', { name: 'About Calls today' }).focus();
    const b = await restingBoxes(page);
    expect(b.tip.left).toBeGreaterThanOrEqual(0);
    expect(b.tip.right).toBeLessThanOrEqual(390);
  });

  test('T5e in a viewport too short for either side the popup still fits, scrolling inside', async ({ page }) => {
    await page.setViewportSize({ width: 800, height: 160 });
    await serveCopy(page);
    await ready(page);
    await mount(page, ['fixture.status.calls'], { layout: 'top-left' });
    await page.evaluate(() => { document.querySelector('.fixture-tips').style.top = '70px'; });
    await page.getByRole('button', { name: 'About Calls today' }).focus();
    const b = await restingBoxes(page);
    expect(b.tip.top).toBeGreaterThanOrEqual(0);
    expect(b.tip.bottom).toBeLessThanOrEqual(160);
  });

  test("T12 the screens' placement helper passes a clear layout and names a covered control", async ({ page }) => {
    await serveCopy(page);
    await ready(page);
    await mount(page, ['fixture.status.calls']);
    expect(await tooltipCoversNothing(page, 'fixture.status.calls')).toEqual([]);
    await page.evaluate(() => {
      const pop = document.querySelector('.has-tip .tip.open').getBoundingClientRect();
      const b = document.createElement('button');
      b.type = 'button';
      b.textContent = 'Under';
      Object.assign(b.style, { position: 'fixed', left: `${pop.left + 4}px`, top: `${pop.top + 4}px` });
      document.getElementById('content').append(b);
    });
    const covered = await tooltipCoversNothing(page, 'fixture.status.calls');
    expect(covered).toHaveLength(1);
    expect(covered[0]).toContain('Under');
  });

  test('T6 T6b focus moving to the next trigger opens it at once and closes the previous', async ({ page }) => {
    await serveCopy(page);
    await ready(page);
    await mount(page, ['fixture.status.paused', 'fixture.status.calls']);
    await page.getByRole('button', { name: 'About Paused' }).focus();
    await page.getByRole('button', { name: 'About Calls today' }).focus();
    await expect(tipOf(page, 'fixture.status.calls')).toHaveClass(/open/);
    await expect(tipOf(page, 'fixture.status.paused')).not.toHaveClass(/open/);
  });

  test('T7 reduced motion: it fades with no rise (the shell rule: keep cross-fades, remove travel)', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await serveCopy(page);
    await ready(page);
    await mount(page, ['fixture.status.paused']);
    const before = await page.evaluate(() => getComputedStyle(document.querySelector('.has-tip .tip')).transform);
    expect(['none', 'matrix(1, 0, 0, 1, 0, 0)']).toContain(before);
    await page.getByRole('button', { name: 'About Paused' }).focus();
    const props = await page.evaluate(() => document.querySelector('.has-tip .tip').getAnimations().map((a) => a.transitionProperty));
    expect(props.filter((p) => p !== 'opacity')).toEqual([]);
  });

  test('T7b with motion allowed it fades and rises 4 px over --duration-fast', async ({ page }) => {
    await serveCopy(page);
    await ready(page);
    await mount(page, ['fixture.status.paused']);
    const resting = await page.evaluate(() => getComputedStyle(document.querySelector('.has-tip .tip')).transform);
    expect(resting).toBe('matrix(1, 0, 0, 1, 0, 4)');
    await page.getByRole('button', { name: 'About Paused' }).focus();
    const timing = await page.evaluate(() => document.querySelector('.has-tip .tip').getAnimations()
      .map((a) => ({ prop: a.transitionProperty, d: a.effect.getTiming().duration })));
    expect(timing.map((t) => t.prop).sort()).toEqual(['opacity', 'transform']);
    for (const t of timing) expect(t.d).toBe(120);
  });

  test('T8 the text is announced once, as the trigger description', async ({ page }) => {
    await serveCopy(page);
    await ready(page);
    await mount(page, ['fixture.status.paused']);
    const text = 'The gateway stopped sending calls to this server.';
    await expect(page.getByRole('button', { name: 'About Paused' })).toHaveAccessibleDescription(text);
    const counts = await page.evaluate((text) => {
      const described = [...document.querySelectorAll('[aria-describedby]')]
        .filter((e) => e.getAttribute('aria-describedby').split(' ').some((id) => document.getElementById(id)?.textContent.includes(text))).length;
      const tip = document.querySelector('.has-tip .tip');
      return { described, focusable: tip.tabIndex >= 0 || tip.matches('a, button, [tabindex]') };
    }, text);
    expect(counts).toEqual({ described: 1, focusable: false });
  });

  test('T16 opening a tooltip adds nothing to the live region', async ({ page }) => {
    await serveCopy(page);
    await ready(page);
    await mount(page, ['fixture.status.paused']);
    const live = () => page.evaluate(() => [...document.querySelectorAll('[aria-live], [role="status"], [role="alert"]')].map((e) => e.textContent).join('|'));
    const before = await live();
    await page.getByRole('button', { name: 'About Paused' }).focus();
    await expect(tipOf(page, 'fixture.status.paused')).toHaveClass(/open/);
    // The announcer drains its queue before going idle, so a queued message would show by then.
    await page.evaluate(async (url) => (await import(url)).announcerIdle(), await shellModuleUrl(page));
    expect(await live()).toBe(before);
  });

  test('T9 under the controller, hover and focus show nothing until .open is set', async ({ page }) => {
    await page.clock.install();
    await serveCopy(page);
    await ready(page);
    await mount(page, ['fixture.status.paused']);
    await pauseClock(page);
    expect(await page.evaluate(() => document.documentElement.dataset.tips)).toBe('js');
    await page.getByRole('button', { name: 'About Paused' }).hover();
    await page.clock.runFor(50);
    expect(await page.evaluate(() => getComputedStyle(document.querySelector('.has-tip .tip')).opacity)).toBe('0');
  });

  test('T11 copy is text, never markup, in text, title and both row cells', async ({ page }) => {
    await serveCopy(page);
    await ready(page);
    await mount(page, ['fixture.status.markup', 'fixture.status.rowmarkup']);
    await expect(page.locator('.has-tip img')).toHaveCount(0);
    expect(await page.evaluate(() => window.pwned)).toBeUndefined();
  });

  test('T17 leaving the screen with a hover pending, or a tooltip open, leaves nothing open', async ({ page }) => {
    await page.clock.install();
    await serveCopy(page);
    await ready(page);
    const shell = await shellModuleUrl(page);
    await mount(page, ['fixture.status.paused']);
    await pauseClock(page);
    await page.getByRole('button', { name: 'About Paused' }).hover(); // nothing open: the 300 ms timer is armed
    await page.clock.runFor(100);
    await page.evaluate(async (url) => (await import(url)).go('/ui/servers/status'), shell);
    await shellReady(page);
    await page.clock.runFor(400);
    await expect(page.locator('.tip.open')).toHaveCount(0);
    await page.evaluate(async (url) => (await import(url)).go('/ui/overview/status'), shell);
    await shellReady(page);
    await mount(page, ['fixture.status.calls']);
    await page.getByRole('button', { name: 'About Calls today' }).focus();
    await expect(page.locator('.tip.open')).toHaveCount(1);
    await page.evaluate(async (url) => (await import(url)).go('/ui/servers/status'), shell);
    await shellReady(page);
    await expect(page.locator('.tip.open')).toHaveCount(0);
  });
});

/** Collect console warnings for the rest of the test. */
function warnings(page) {
  const seen = [];
  page.on('console', (m) => { if (m.type() === 'warning') seen.push(m.text()); });
  return seen;
}

/** A promise the copy route waits on, and the function that releases it. */
function gate() {
  let release;
  const hold = new Promise((r) => { release = r; });
  return { hold, release };
}

test.describe('copy loading', () => {
  test('C3 a failed copy fetch: the tab is drawn, every placeholder collapses, one warning in total', async ({ page }) => {
    const warned = warnings(page);
    await serveCopy(page, { status: 500 });
    await ready(page);
    await mount(page, ['fixture.status.paused', 'fixture.status.calls']);
    await expect(page.locator('.fixture-tips')).toBeVisible();
    await expect(page.locator('.tip-i')).toHaveCount(0);
    expect(await page.locator('[data-tip]').evaluateAll((els) => els.map((e) => e.hidden))).toEqual([true, true]);
    expect(warned.filter((w) => /tooltip copy/.test(w))).toHaveLength(1);
  });

  test('C3b T19b T19c a missing id warns once per id, and only once', async ({ page }) => {
    const warned = warnings(page);
    await serveCopy(page);
    await ready(page);
    await mount(page, ['missing.status.one', 'missing.status.one', 'missing.status.two', 'fixture.status.paused']);
    await expect(page.getByRole('button', { name: 'About Paused' })).toBeVisible();
    expect(warned.filter((w) => w.includes('missing.status.one'))).toHaveLength(1);
    expect(warned.filter((w) => w.includes('missing.status.two'))).toHaveLength(1);
    expect(await page.locator('[data-tip^="missing."]').evaluateAll((els) => els.every((e) => e.hidden))).toBe(true);
  });

  test('C4 C4b with the copy held the tab paints with empty placeholders, and they fill in place on release', async ({ page }) => {
    const { hold, release } = gate();
    await serveCopy(page, { hold });
    await ready(page);
    await mount(page, ['fixture.status.paused'], { settle: false });
    await expect(page.locator('#content [data-rendered]')).toBeVisible();
    const holder = page.locator('[data-tip="fixture.status.paused"]');
    await expect(holder).toHaveCount(1);
    await expect(holder.locator('button')).toHaveCount(0);
    await page.evaluate(() => { window.__holder = document.querySelector('[data-tip="fixture.status.paused"]'); });
    release();
    await settled(page);
    await expect(page.getByRole('button', { name: 'About Paused' })).toBeVisible();
    expect(await page.evaluate(() => window.__holder === document.querySelector('[data-tip="fixture.status.paused"]') && window.__holder.isConnected)).toBe(true);
  });

  test('C5 C5b the copy is fetched once however many tip() calls run', async ({ page }) => {
    const count = { n: 0 };
    await serveCopy(page, { count });
    await ready(page);
    await mount(page, ['fixture.status.paused', 'fixture.status.calls']);
    await mount(page, ['fixture.status.paused']);
    expect(count.n).toBe(1);
  });

  test('C7 tipsSettled() resolves at once when nothing asked for copy, and nothing is fetched', async ({ page }) => {
    const count = { n: 0 };
    const { hold } = gate();
    await serveCopy(page, { hold, count });
    await ready(page);
    expect(await page.evaluate(async (url) => { await (await import(url)).tipsSettled(); return 'settled'; }, tooltipModuleUrl())).toBe('settled');
    expect(count.n).toBe(0);
  });

  test('T13 a placeholder attached after the copy settles is filled and opens by focus', async ({ page }) => {
    const { hold, release } = gate();
    await serveCopy(page, { hold });
    await ready(page);
    await page.evaluate(async (url) => { window.__late = (await import(url)).tip('fixture.status.paused'); }, tooltipModuleUrl());
    release();
    await settled(page);
    await page.evaluate(() => document.getElementById('content').append(window.__late));
    await page.getByRole('button', { name: 'About Paused' }).focus();
    await expect(tipOf(page, 'fixture.status.paused')).toHaveClass(/open/);
  });

  test('T14 filling a placeholder moves nothing beside it, inline and in a flex row', async ({ page }) => {
    const { hold, release } = gate();
    await serveCopy(page, { hold });
    await ready(page);
    await mount(page, ['fixture.status.paused'], { settle: false });
    await page.evaluate(() => {
      const flex = document.createElement('div');
      flex.style.display = 'flex';
      flex.style.gap = '8px';
      flex.append(document.querySelector('.fixture-tips p').cloneNode(false));
      document.getElementById('content').append(flex);
    });
    await page.evaluate(async (url) => {
      const flex = document.querySelector('#content > div[style*="flex"]');
      const label = document.createElement('span');
      label.textContent = 'label';
      const after = document.createElement('span');
      after.textContent = 'after';
      after.className = 'flex-after';
      flex.append(label, (await import(url)).tip('fixture.status.calls'), after);
    }, tooltipModuleUrl());
    const box = () => page.evaluate(() => [document.querySelector('.next-action'), document.querySelector('.flex-after')].map((e) => e.getBoundingClientRect().toJSON()));
    const before = await box();
    release();
    await settled(page);
    await expect(page.locator('.tip-i')).toHaveCount(2);
    expect(await box()).toEqual(before);
  });

  test('T15 T19a after a failed load the placeholder gives its space back, and later tip() calls fetch nothing more', async ({ page }) => {
    const warned = warnings(page);
    const count = { n: 0 };
    await serveCopy(page, { status: 500, count });
    await ready(page);
    await mount(page, ['fixture.status.paused']);
    // A twin row with the same text and no tooltip: its Next must sit exactly where the failed row's does.
    const lefts = await page.evaluate(() => {
      const row = document.querySelector('.fixture-tips p');
      const twin = document.createElement('p');
      twin.append(document.createTextNode(row.firstChild.textContent));
      const next = document.createElement('button');
      next.type = 'button';
      next.textContent = 'Next';
      twin.append(next);
      row.after(twin);
      return [row.querySelector('.next-action').getBoundingClientRect().left, next.getBoundingClientRect().left];
    });
    expect(lefts[0]).toBe(lefts[1]);
    await mount(page, ['fixture.status.calls']);
    expect(count.n).toBe(1);
    expect(warned.filter((w) => /tooltip copy/.test(w))).toHaveLength(1);
    await expect(page.locator('[data-tip="fixture.status.calls"]')).toHaveJSProperty('hidden', true);
  });

  test('T18 after the copy settles, tip() returns a finished trigger at once', async ({ page }) => {
    await serveCopy(page);
    await ready(page);
    await settled(page);
    await mount(page, ['fixture.status.paused']);
    const sync = await page.evaluate(async (url) => {
      const t = (await import(url)).tip('fixture.status.calls');
      return { hidden: t.hidden, button: !!t.querySelector('button.tip-i') };
    }, tooltipModuleUrl());
    expect(sync).toEqual({ hidden: false, button: true });
  });
});

// The markup tip('fixture.status.paused') builds, written out once. T10 draws it
// with no tooltip module loaded; T10b holds tip() to it, element for element.
const STATIC_PAUSED = '<span class="has-tip" data-tip="fixture.status.paused">'
  + '<button type="button" class="tip-i" aria-label="About Paused" aria-describedby="tip-1">i</button>'
  + '<span class="tip" role="tooltip" id="tip-1"><strong class="tip-title" aria-hidden="true">Paused</strong>'
  + '<span class="tip-body">The gateway stopped sending calls to this server.</span></span></span>';

/** After a failure the controller is off: no marker, nothing open, and CSS shows the text on hover and focus. */
async function expectHandedBack(page, id) {
  expect(await page.evaluate(() => document.documentElement.hasAttribute('data-tips'))).toBe(false);
  await expect(page.locator('.tip.open')).toHaveCount(0);
  const opacity = () => page.evaluate((id) => getComputedStyle(document.querySelector(`.has-tip[data-tip="${id}"] .tip`)).opacity, id);
  await page.locator(`.has-tip[data-tip="${id}"] button`).hover();
  await expect.poll(opacity).toBe('1');
  await page.mouse.move(1, 1);
  await page.locator(`.has-tip[data-tip="${id}"] button`).focus();
  await expect.poll(opacity).toBe('1');
  await expect(page.locator('.tip.open')).toHaveCount(0);
}

test.describe('CSS fallback and the failure latch', () => {
  test('T10 with no controller, the markup shows its text on hover and on keyboard focus', async ({ page }) => {
    await ready(page);
    // The state of a page where the module's stylesheet arrived but its controller never ran.
    await page.evaluate(async ({ html, css }) => {
      const link = Object.assign(document.createElement('link'), { rel: 'stylesheet', href: css });
      const loaded = new Promise((r) => { link.onload = r; });
      document.head.append(link);
      await loaded;
      document.getElementById('content').insertAdjacentHTML('beforeend', `<p>${html}</p>`);
    }, { html: STATIC_PAUSED, css: tooltipCssUrl() });
    const opacity = () => page.evaluate(() => getComputedStyle(document.querySelector('.has-tip .tip')).opacity);
    expect(await opacity()).toBe('0');
    await page.getByRole('button', { name: 'About Paused' }).hover();
    await expect.poll(opacity).toBe('1');
    await page.mouse.move(1, 1);
    await page.getByRole('button', { name: 'About Paused' }).focus();
    await expect.poll(opacity).toBe('1');
  });

  test('T10b tip() builds exactly the static markup, ids normalised', async ({ page }) => {
    await serveCopy(page);
    await ready(page);
    const built = await page.evaluate(async (url) => {
      const tips = await import(url);
      tips.tip('fixture.status.paused'); // the first call starts the copy fetch
      await tips.tipsSettled();
      const t = tips.tip('fixture.status.paused');
      const id = t.querySelector('[role="tooltip"]').id;
      return t.outerHTML.replaceAll(id, 'tip-1');
    }, tooltipModuleUrl());
    expect(built).toBe(STATIC_PAUSED);
  });

  test('T10c a failure inside a handler trips the latch: the open popup closes and CSS takes over', async ({ page }) => {
    const warned = warnings(page);
    await serveCopy(page);
    await ready(page);
    await mount(page, ['fixture.status.paused', 'fixture.status.calls']);
    await page.getByRole('button', { name: 'About Paused' }).focus();
    await expect(tipOf(page, 'fixture.status.paused')).toHaveClass(/open/);
    await page.evaluate(() => {
      window.__rect = Element.prototype.getBoundingClientRect;
      Element.prototype.getBoundingClientRect = () => { throw new Error('planted placement fault'); };
    });
    await page.getByRole('button', { name: 'About Calls today' }).focus(); // opening on focus is synchronous; placement throws
    await page.evaluate(() => { Element.prototype.getBoundingClientRect = window.__rect; });
    expect(warned.filter((w) => /tooltip/.test(w))).toHaveLength(1);
    await expectHandedBack(page, 'fixture.status.paused');
  });

  test('T10g the latch cancels a pending hover timer: that popup never opens', async ({ page }) => {
    await page.clock.install();
    await serveCopy(page);
    await ready(page);
    await mount(page, ['fixture.status.paused']);
    await pauseClock(page);
    await expect(page.locator('.tip.open')).toHaveCount(0);
    await page.getByRole('button', { name: 'About Paused' }).hover(); // nothing open, so the 300 ms timer is armed
    await page.clock.runFor(100);
    // A fault off the show path: filling a new trigger throws once, so only the latch can stop the armed timer.
    await page.evaluate(async (url) => {
      const real = Element.prototype.replaceChildren;
      Element.prototype.replaceChildren = function () {
        Element.prototype.replaceChildren = real;
        throw new Error('planted fill fault');
      };
      document.getElementById('content').append((await import(url)).tip('fixture.status.calls'));
    }, tooltipModuleUrl());
    expect(await page.evaluate(() => document.documentElement.hasAttribute('data-tips'))).toBe(false);
    await page.clock.runFor(400); // the armed timer would have fired by now
    await expect(page.locator('.tip.open')).toHaveCount(0);
  });

  test('T10d a one-shot fault while filling: every placeholder still fills, and CSS takes over', async ({ page }) => {
    const warned = warnings(page);
    const { hold, release } = gate();
    await serveCopy(page, { hold });
    await ready(page);
    await mount(page, ['fixture.status.paused', 'fixture.status.calls', 'fixture.status.markup'], { settle: false });
    await page.evaluate(() => {
      const real = Element.prototype.replaceChildren;
      Element.prototype.replaceChildren = function (...a) {
        Element.prototype.replaceChildren = real;
        throw new Error('planted fill fault');
      };
    });
    release();
    await settled(page);
    await expect(page.locator('.tip-i')).toHaveCount(3);
    await mount(page, ['fixture.status.paused']);
    await expect(page.locator('.tip-i')).toHaveCount(4);
    expect(warned.filter((w) => /tooltip/.test(w))).toHaveLength(1);
    await expectHandedBack(page, 'fixture.status.calls');
  });

  test('T10e a failure in the hover timer callback trips the same latch', async ({ page }) => {
    await page.clock.install();
    await serveCopy(page);
    await ready(page);
    await mount(page, ['fixture.status.paused']);
    await pauseClock(page);
    await page.getByRole('button', { name: 'About Paused' }).hover();
    await page.evaluate(() => {
      window.__rect = Element.prototype.getBoundingClientRect;
      Element.prototype.getBoundingClientRect = () => { throw new Error('planted timer fault'); };
    });
    await page.clock.runFor(350); // the open step runs from the timer and throws
    await page.evaluate(() => { Element.prototype.getBoundingClientRect = window.__rect; });
    await expectHandedBack(page, 'fixture.status.paused');
  });

  test('T10f a failure while the controller starts trips the latch, and triggers still show their text', async ({ page }) => {
    await serveCopy(page);
    await ready(page);
    await page.evaluate(() => {
      const real = document.addEventListener;
      document.addEventListener = function (...a) {
        document.addEventListener = real;
        throw new Error('planted start fault');
      };
    });
    await mount(page, ['fixture.status.paused']);
    await expectHandedBack(page, 'fixture.status.paused');
  });

  test('T20 a bare .has-tip without data-tip is left as the landed CSS draws it', async ({ page }) => {
    await serveCopy(page);
    await ready(page);
    await page.evaluate(() => {
      const s = document.createElement('span');
      s.className = 'has-tip bare';
      s.tabIndex = 0;
      s.innerHTML = 'term<span class="tip" role="tooltip">A plain term.</span>';
      document.getElementById('content').append(s);
    });
    const look = () => page.evaluate(() => {
      const t = document.querySelector('.has-tip.bare .tip');
      return { cls: t.className, attrs: t.getAttributeNames().join(','), opacity: getComputedStyle(t).opacity };
    });
    const before = await look();
    await mount(page, ['fixture.status.paused']);
    await page.locator('.has-tip.bare').hover();
    await page.locator('.has-tip.bare').click();
    await page.locator('.has-tip.bare').focus();
    const after = await look();
    expect(after.cls).toBe(before.cls);
    expect(after.attrs).toBe(before.attrs);
    await expect(page.locator('.has-tip.bare .tip.open')).toHaveCount(0);
  });
});

const TOOLS = [
  { name: 'list_dir', server: 'filesystem', description: 'List a folder inside the allowed paths' },
  { name: 'search', server: 'web', description: 'Search the web' },
];

async function toolsScreen(page) {
  await page.route('**/ui/api/tools**', (r) => r.fulfill({ json: { tools: TOOLS } }));
  await page.goto('/ui/tools/status');
  await shellReady(page);
}

/** Place an element fixed over the open popup: `at` maps the popup's box to {left, top, width, height}. */
async function plantOver(page, html, at) {
  await page.evaluate(({ html, at }) => {
    const pop = document.querySelector('.has-tip .tip.open').getBoundingClientRect();
    const box = new Function('p', `return (${at})(p)`)(pop);
    const holder = document.createElement('div');
    holder.innerHTML = html;
    const el = holder.firstElementChild;
    Object.assign(el.style, { position: 'fixed', left: `${box.left}px`, top: `${box.top}px`, width: `${box.width}px`, height: `${box.height}px` });
    document.getElementById('content').append(el);
  }, { html, at });
}

test.describe('the covers-nothing rule (lead ruling 2026-10-28)', () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await serveCopy(page);
    await ready(page);
    await mount(page, ['fixture.status.calls']);
    await page.getByRole('button', { name: 'About Calls today' }).focus();
  });

  test('T12b a region whose centre the popup hides is covered', async ({ page }) => {
    await plantOver(page, '<div role="region" tabindex="0" aria-label="Middle">m</div>', '(p) => ({ left: p.left + p.width / 4, top: p.top + p.height / 4, width: p.width / 2, height: p.height / 2 })');
    expect(await tooltipCoversNothing(page, 'fixture.status.calls')).toEqual(['div "Middle"']);
  });

  test('T12c a large region with only its corner under the popup is not covered', async ({ page }) => {
    await plantOver(page, '<div role="region" tabindex="0" aria-label="Table"></div>', '(p) => ({ left: p.right - 20, top: p.bottom - 20, width: 900, height: 500 })');
    expect(await tooltipCoversNothing(page, 'fixture.status.calls')).toEqual([]);
  });

  test('T12d a button inside that region, under the popup, is still covered', async ({ page }) => {
    await plantOver(page, '<div role="region" tabindex="0" aria-label="Table"><button type="button" aria-label="Row action"></button></div>',
      '(p) => ({ left: p.right - 20, top: p.bottom - 20, width: 900, height: 500 })');
    // CSSOM, not a style attribute: the CSP refuses inline style in markup. The button sits in the region's covered corner.
    await page.evaluate(() => Object.assign(document.querySelector('[aria-label="Row action"]').style, { position: 'absolute', left: '0px', top: '0px', width: '16px', height: '16px' }));
    expect(await page.evaluate(() => {
      const b = document.querySelector('[aria-label="Row action"]').getBoundingClientRect();
      const p = document.querySelector('.has-tip .tip.open').getBoundingClientRect();
      return b.left < p.right && b.top < p.bottom;
    })).toBe(true);
    expect(await tooltipCoversNothing(page, 'fixture.status.calls')).toEqual(['button "Row action"']);
  });
});

test('T27 a tooltip opened by hover closes on Escape with the pointer still on it, and stays closed', async ({ page }) => {
  await page.clock.install();
  await serveCopy(page);
  await ready(page);
  await mount(page, ['fixture.status.paused']);
  await pauseClock(page);
  const tip = tipOf(page, 'fixture.status.paused');
  await page.getByRole('button', { name: 'About Paused' }).hover();
  await page.clock.runFor(350);
  await expect(tip).toHaveClass(/open/);
  await page.keyboard.press('Escape');
  await expect(tip).not.toHaveClass(/open/);
  await page.clock.runFor(400); // the pointer has not moved: nothing reopens it
  await expect(tip).not.toHaveClass(/open/);
});

test.describe('review round 1', () => {
  for (const width of [390, 1440]) {
    test(`T21 on the real Tools screen at ${width} px the tooltip covers nothing`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await toolsScreen(page);
      await expect(page.locator('.has-tip[data-tip="tools.status.load-11-tools-and-reach"] .tip-i')).toBeVisible();
      expect(await tooltipCoversNothing(page, 'tools.status.load-11-tools-and-reach')).toEqual([]);
    });
  }

  test('T22 Tools draws its catalogue when the tooltip module fails to load, and the sentence stands alone', async ({ page }) => {
    await page.route('**/ui/assets/tooltip.*.js', (r) => r.abort());
    await toolsScreen(page);
    await expect(page.locator('.tool-toggle')).toHaveCount(2);
    await expect(page.locator('.tools-load')).toContainText('Agents load 11 tools');
    await expect(page.locator('.tools-load .tip-i')).toHaveCount(0);
  });

  test('T23 a popup cut short by the viewport scrolls from its focused trigger', async ({ page }) => {
    await page.setViewportSize({ width: 800, height: 160 });
    await serveCopy(page);
    await ready(page);
    await mount(page, ['fixture.status.calls'], { layout: 'top-left' });
    await page.evaluate(() => { document.querySelector('.fixture-tips').style.top = '70px'; });
    const button = page.getByRole('button', { name: 'About Calls today' });
    await button.focus();
    const tip = tipOf(page, 'fixture.status.calls');
    expect(await tip.evaluate((t) => t.scrollHeight > t.clientHeight)).toBe(true);
    await page.keyboard.press('ArrowDown');
    // Its own scroll must not place it again (which would reset the offset): check after a frame, then go further.
    const first = await tip.evaluate((t) => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(() => r(t.scrollTop)))));
    expect(first).toBeGreaterThan(0);
    await page.keyboard.press('ArrowDown');
    expect(await tip.evaluate((t) => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(() => r(t.scrollTop)))))).toBeGreaterThan(first);
    await expect(button).toBeFocused();
  });

  test('T24 an open popup is placed again when the viewport narrows', async ({ page }) => {
    await page.setViewportSize({ width: 1000, height: 800 });
    await serveCopy(page);
    await ready(page);
    await mount(page, ['fixture.status.calls'], { layout: 'top-right' });
    await page.getByRole('button', { name: 'About Calls today' }).focus();
    await page.setViewportSize({ width: 390, height: 800 });
    const b = await restingBoxes(page);
    expect(b.tip.left).toBeGreaterThanOrEqual(0);
    expect(b.tip.right).toBeLessThanOrEqual(390);
  });

  test('T25 T26 a closing popup stays by its trigger while it fades, then drops its placement', async ({ page }) => {
    await page.clock.install();
    await serveCopy(page);
    await ready(page);
    await mount(page, ['fixture.status.calls'], { layout: 'top-right' });
    await pauseClock(page);
    await page.getByRole('button', { name: 'About Calls today' }).focus();
    const tip = tipOf(page, 'fixture.status.calls');
    expect(await tip.evaluate((t) => t.style.left)).not.toBe('');
    await page.keyboard.press('Escape');
    expect(await tip.evaluate((t) => getComputedStyle(t).position)).toBe('absolute');
    await page.clock.runFor(250);
    expect(await tip.evaluate((t) => [getComputedStyle(t).position, t.style.left, t.style.maxHeight])).toEqual(['fixed', '', '']);
  });
});

test.describe('review round 2', () => {
  test('T29 reopened and closed again within one fade, it stays anchored for the whole second fade', async ({ page }) => {
    await page.clock.install();
    await serveCopy(page);
    await ready(page);
    await mount(page, ['fixture.status.calls'], { layout: 'top-right' });
    await pauseClock(page);
    const button = page.getByRole('button', { name: 'About Calls today' });
    const tip = tipOf(page, 'fixture.status.calls');
    await button.focus();
    await page.keyboard.press('Escape');
    await page.clock.runFor(100);
    await page.keyboard.press('Enter'); // reopen inside the first fade
    await expect(tip).toHaveClass(/open/);
    await page.keyboard.press('Escape');
    await page.clock.runFor(100); // the first fade's timer would fire about now
    expect(await tip.evaluate((t) => getComputedStyle(t).position)).toBe('absolute');
    await page.clock.runFor(200);
    expect(await tip.evaluate((t) => getComputedStyle(t).position)).toBe('fixed');
  });

  test('T30 a stylesheet that fails to load: triggers collapse and one warning says so', async ({ page }) => {
    const warned = warnings(page);
    await page.route('**/ui/assets/tooltip.*.css', (r) => r.fulfill({ status: 404, body: '' }));
    await serveCopy(page);
    await ready(page);
    await mount(page, ['fixture.status.paused']);
    await expect(page.locator('.tip-i')).toHaveCount(0);
    await expect(page.locator('[data-tip="fixture.status.paused"]')).toHaveJSProperty('hidden', true);
    expect(warned.filter((w) => /tooltip copy not loaded \(stylesheet not loaded\)/.test(w))).toHaveLength(1);
  });

  test.describe('touch', () => {
    test.use({ hasTouch: true, isMobile: true, viewport: { width: 390, height: 844 } });
    test('T14b with a coarse pointer, filling a placeholder still moves nothing beside it', async ({ page }) => {
      const { hold, release } = gate();
      await serveCopy(page, { hold });
      await ready(page);
      expect(await page.evaluate(() => matchMedia('(pointer: coarse)').matches)).toBe(true);
      await mount(page, ['fixture.status.paused'], { settle: false });
      const box = () => page.evaluate(() => document.querySelector('.next-action').getBoundingClientRect().toJSON());
      const before = await box();
      release();
      await settled(page);
      await expect(page.locator('.tip-i')).toHaveCount(1);
      expect(await box()).toEqual(before);
    });
  });
});
