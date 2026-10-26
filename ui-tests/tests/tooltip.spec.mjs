// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The tooltip component and its copy loading. Rows T1-T11 and C3-C5b of the
// tooltip test plan. Copy is served per test through page.route, so each
// test controls what the shell loads; triggers come from the shell's own
// tip() through a fixture tab built in the page.
import { test, expect } from './base.mjs';
import { shellModuleUrl, shellReady, withFixturePages, tooltipCoversNothing } from './shell.mjs';

const COPY = {
  _pending: {},
  'fixture.status.calls': { title: 'Calls today', rows: [['What', 'Tool calls answered or refused.'], ['Window', 'Since 00:00, per call.'], ['Source', "The gateway's call log."]] },
  'fixture.status.paused': { title: 'Paused', text: 'The gateway stopped sending calls to this server.' },
  'fixture.status.markup': { title: 'Markup', text: '<img src=x onerror="window.pwned=1">' },
};

async function serveCopy(page, copy = COPY, { status = 200, hold } = {}) {
  await page.route('**/ui/assets/tips.*.json', async (route) => {
    if (hold) await hold;
    if (status !== 200) return route.fulfill({ status, body: '' });
    return route.fulfill({ json: copy });
  });
}

/** Render triggers for ids into the content area through the shell's tip(), after its copy wait. */
async function mount(page, ids, { layout = 'inline' } = {}) {
  const url = await shellModuleUrl(page);
  await page.evaluate(async ({ url, ids, layout }) => {
    const shell = await import(url);
    await shell.tipsReady();
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
      row.append(document.createTextNode(`${id} `));
      const t = shell.tip(id);
      if (t) row.append(t);
      const next = document.createElement('button');
      next.type = 'button';
      next.className = 'next-action';
      next.textContent = 'Next';
      row.append(next);
      box.append(row);
    }
    document.getElementById('content').append(box);
  }, { url, ids, layout });
}

async function ready(page) {
  await page.goto('/ui/overview/status');
  await shellReady(page);
}

test.describe('component', () => {
  test('T1 a trigger is a named button described by one tooltip with the rows in order', async ({ page }) => {
    await serveCopy(page);
    await ready(page);
    await mount(page, ['fixture.status.calls']);
    const button = page.getByRole('button', { name: 'About Calls today' });
    await expect(button).toBeVisible();
    const id = await button.getAttribute('aria-describedby');
    const tip = page.locator(`[id="${id}"][role="tooltip"]`);
    await expect(tip).toHaveCount(1);
    expect(await tip.locator('dt').allTextContents()).toEqual(['What', 'Window', 'Source']);
    await expect(tip).toContainText('Tool calls answered or refused.');
  });

  test('T2 hover waits 300 ms, pointer-out waits 150 ms, and the popup stays open under the pointer', async ({ page }) => {
    await page.clock.install();
    await serveCopy(page);
    await ready(page);
    await mount(page, ['fixture.status.paused']);
    const button = page.getByRole('button', { name: 'About Paused' });
    const tip = page.locator('.has-tip .tip');
    await button.hover();
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
    const tip = page.locator('.has-tip .tip');
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
      const button = page.getByRole('button', { name: 'About Paused' });
      const tip = page.locator('.has-tip .tip');
      await button.tap();
      await expect(tip).toHaveClass(/open/);
      await page.locator('h1').tap();
      await expect(tip).not.toHaveClass(/open/);
    });
  });

  for (const corner of ['top-left', 'top-right', 'bottom-left', 'bottom-right']) {
    test(`T5 T5b T5c at the ${corner} the popup stays on screen and covers neither its trigger nor the next action`, async ({ page }) => {
      await serveCopy(page);
      await ready(page);
      await mount(page, ['fixture.status.calls'], { layout: corner });
      await page.getByRole('button', { name: 'About Calls today' }).focus();
      // Measure the resting place, not a frame of the entry slide.
      const boxes = await page.evaluate(async () => {
        await Promise.all(document.getAnimations().map((a) => a.finished));
        const r = (el) => el.getBoundingClientRect().toJSON();
        return { tip: r(document.querySelector('.has-tip .tip')), trigger: r(document.querySelector('.has-tip button')), next: r(document.querySelector('.next-action')), w: innerWidth, h: innerHeight };
      });
      const overlap = (a, b) => a.left < b.right && b.left < a.right && a.top < b.bottom && b.top < a.bottom;
      expect(boxes.tip.left).toBeGreaterThanOrEqual(0);
      expect(boxes.tip.top).toBeGreaterThanOrEqual(0);
      expect(boxes.tip.right).toBeLessThanOrEqual(boxes.w);
      expect(boxes.tip.bottom).toBeLessThanOrEqual(boxes.h);
      expect(overlap(boxes.tip, boxes.trigger)).toBe(false);
      expect(overlap(boxes.tip, boxes.next), JSON.stringify(boxes)).toBe(false);
    });
  }

  test('T5d at 390 px a trigger mid-screen keeps its popup on screen when neither edge fits', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await serveCopy(page);
    await ready(page);
    await mount(page, ['fixture.status.calls']);
    await page.evaluate(() => {
      const row = document.querySelector('.fixture-tips p');
      row.style.paddingLeft = '150px';
    });
    await page.getByRole('button', { name: 'About Calls today' }).focus();
    const box = await page.evaluate(async () => {
      await Promise.all(document.getAnimations().map((a) => a.finished));
      return document.querySelector('.has-tip .tip').getBoundingClientRect().toJSON();
    });
    expect(box.left).toBeGreaterThanOrEqual(0);
    expect(box.right).toBeLessThanOrEqual(390);
  });

  test('T5e in a viewport too short for either side the popup still fits, scrolling inside', async ({ page }) => {
    await page.setViewportSize({ width: 800, height: 160 });
    await serveCopy(page);
    await ready(page);
    await mount(page, ['fixture.status.calls'], { layout: 'top-left' });
    await page.evaluate(() => { document.querySelector('.fixture-tips').style.top = '70px'; });
    await page.getByRole('button', { name: 'About Calls today' }).focus();
    const box = await page.evaluate(async () => {
      await Promise.all(document.getAnimations().map((a) => a.finished));
      return document.querySelector('.has-tip .tip').getBoundingClientRect().toJSON();
    });
    expect(box.top).toBeGreaterThanOrEqual(0);
    expect(box.bottom).toBeLessThanOrEqual(160);
  });

  test('T12 the screens\' placement helper passes a clear layout and names a covered control', async ({ page }) => {
    await serveCopy(page);
    await ready(page);
    await mount(page, ['fixture.status.calls']);
    expect(await tooltipCoversNothing(page, 'fixture.status.calls')).toEqual([]);
    // A control placed under the popup's box is reported.
    await page.evaluate(() => {
      const r = document.querySelector('.has-tip').getBoundingClientRect();
      const b = document.createElement('button');
      b.type = 'button';
      b.textContent = 'Under';
      Object.assign(b.style, { position: 'fixed', left: `${r.left + 20}px`, top: `${r.bottom + 30}px` });
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
    const tips = page.locator('.has-tip .tip');
    await expect(tips.nth(1)).toHaveClass(/open/);
    await expect(tips.nth(0)).not.toHaveClass(/open/);
  });

  test('T7 reduced motion: nothing animates as it opens', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await serveCopy(page);
    await ready(page);
    await mount(page, ['fixture.status.paused']);
    await page.getByRole('button', { name: 'About Paused' }).focus();
    expect(await page.evaluate(() => document.querySelector('.has-tip .tip').getAnimations().length)).toBe(0);
  });

  test('T7b with motion allowed it fades and rises 4 px in 120 ms', async ({ page }) => {
    await serveCopy(page);
    await ready(page);
    await mount(page, ['fixture.status.paused']);
    await page.getByRole('button', { name: 'About Paused' }).focus();
    const timing = await page.evaluate(() => {
      const anims = document.querySelector('.has-tip .tip').getAnimations();
      return anims.map((a) => ({ prop: a.transitionProperty, d: a.effect.getTiming().duration }));
    });
    expect(timing.map((t) => t.prop).sort()).toEqual(['opacity', 'transform']);
    for (const t of timing) expect(t.d).toBe(120);
    const shift = await page.evaluate(() => {
      const tip = document.querySelector('.has-tip .tip');
      tip.classList.remove('open');
      tip.getAnimations().forEach((a) => a.finish());
      return getComputedStyle(tip).transform;
    });
    expect(shift).toContain('4');
  });

  test('T8 the text is announced once, as the trigger description', async ({ page }) => {
    await serveCopy(page);
    await ready(page);
    await mount(page, ['fixture.status.paused']);
    const button = page.getByRole('button', { name: 'About Paused' });
    await expect(button).toHaveAccessibleDescription('The gateway stopped sending calls to this server.');
    const counts = await page.evaluate(() => {
      const text = 'The gateway stopped sending calls to this server.';
      const live = [...document.querySelectorAll('[aria-live], [role="status"], [role="alert"]')].filter((e) => e.textContent.includes(text)).length;
      const described = [...document.querySelectorAll('[aria-describedby]')].filter((e) => e.getAttribute('aria-describedby').split(' ').some((id) => document.getElementById(id)?.textContent.includes(text))).length;
      const tip = document.querySelector('.has-tip .tip');
      return { live, described, focusable: tip.tabIndex >= 0 || tip.matches('a, button, [tabindex]') };
    });
    expect(counts).toEqual({ live: 0, described: 1, focusable: false });
  });

  test('T9 with JS on, hovering shows nothing before the delay', async ({ page }) => {
    await page.clock.install();
    await serveCopy(page);
    await ready(page);
    await mount(page, ['fixture.status.paused']);
    expect(await page.evaluate(() => document.documentElement.hasAttribute('data-js'))).toBe(true);
    await page.getByRole('button', { name: 'About Paused' }).hover();
    await page.clock.runFor(50);
    expect(await page.evaluate(() => getComputedStyle(document.querySelector('.has-tip .tip')).opacity)).toBe('0');
  });

  test('T11 copy is text, never markup', async ({ page }) => {
    await serveCopy(page);
    await ready(page);
    await mount(page, ['fixture.status.markup']);
    await expect(page.locator('.has-tip .tip img')).toHaveCount(0);
    expect(await page.evaluate(() => window.pwned)).toBeUndefined();
  });
});

test.describe('no JavaScript', () => {
  test.use({ javaScriptEnabled: false });
  test('T10 server-rendered tooltip markup shows on hover and focus with no script', async ({ page }) => {
    await page.goto('/ui/classic');
    // The static page carries tipMarkup()'s exact output and the shell stylesheet.
    await page.goto('/ui/assets/fixture-tooltip.html');
    expect(await page.locator('script').count()).toBe(0);
    const tip = page.locator('.has-tip .tip');
    await expect(tip).toHaveCSS('opacity', '0');
    await page.locator('.has-tip button').hover();
    await expect(tip).toHaveCSS('opacity', '1');
    await page.mouse.move(1, 1);
    await page.locator('.has-tip button').focus();
    await expect(tip).toHaveCSS('opacity', '1');
  });

  test('T10c with no script the popup stays open while the pointer moves onto it', async ({ page }) => {
    await page.goto('/ui/assets/fixture-tooltip.html');
    const tip = page.locator('.has-tip .tip');
    await page.locator('.has-tip button').hover();
    await expect(tip).toHaveCSS('opacity', '1');
    const box = await tip.boundingBox();
    const trigger = await page.locator('.has-tip button').boundingBox();
    // Cross the gap between trigger and popup in small steps, as a hand would.
    await page.mouse.move(trigger.x + 4, trigger.y + trigger.height / 2);
    await page.mouse.move(trigger.x + 4, box.y + box.height / 2, { steps: 12 });
    await expect(tip).toHaveCSS('opacity', '1');
  });
});

test('T10d two triggers for one copy id get distinct description targets', async ({ page }) => {
  await serveCopy(page);
  await ready(page);
  const url = await shellModuleUrl(page);
  const ids = await page.evaluate(async (url) => {
    const shell = await import(url);
    await shell.tipsReady();
    const host = document.createElement('div');
    host.innerHTML = shell.tipMarkup('fixture.status.paused') + shell.tipMarkup('fixture.status.paused');
    return [...host.querySelectorAll('button')].map((b) => [b.getAttribute('aria-describedby'), host.querySelectorAll(`[id="${b.getAttribute('aria-describedby')}"]`).length]);
  }, url);
  expect(ids[0][0]).not.toBe(ids[1][0]);
  expect(ids.map(([, n]) => n)).toEqual([1, 1]);
});

test('T10b tipMarkup() output is exactly the static fixture markup', async ({ page, request }) => {
  await serveCopy(page);
  await ready(page);
  const url = await shellModuleUrl(page);
  const markup = await page.evaluate(async (url) => {
    const shell = await import(url);
    await shell.tipsReady();
    return shell.tipMarkup('fixture.status.paused');
  }, url);
  const fixture = await (await request.get('/ui/assets/fixture-tooltip.html')).text();
  expect(fixture).toContain(markup);
});

test.describe('copy loading', () => {
  test('C3 a failed copy fetch still renders the tab: no trigger, one warning', async ({ page }) => {
    const warnings = [];
    page.on('console', (m) => { if (m.type() === 'warning') warnings.push(m.text()); });
    await serveCopy(page, COPY, { status: 500 });
    await ready(page);
    await mount(page, ['fixture.status.paused']);
    await expect(page.locator('#content [data-rendered]')).toBeVisible();
    await expect(page.locator('.has-tip')).toHaveCount(0);
    expect(warnings.filter((w) => w.includes('tooltip copy'))).toHaveLength(1);
  });

  test('C3b an id absent from loaded copy draws no trigger and warns once naming it', async ({ page }) => {
    const warnings = [];
    page.on('console', (m) => { if (m.type() === 'warning') warnings.push(m.text()); });
    await serveCopy(page);
    await ready(page);
    await mount(page, ['missing.status.id', 'fixture.status.paused']);
    await expect(page.locator('.has-tip')).toHaveCount(1);
    expect(warnings.filter((w) => w.includes('missing.status.id'))).toHaveLength(1);
  });

  test('C4 a stalled copy fetch: no render at 1.4 s, a render with no trigger by 1.6 s', async ({ page }) => {
    await page.clock.install();
    await serveCopy(page, COPY, { hold: new Promise(() => {}) });
    await page.goto('/ui/overview/status');
    const url = await shellModuleUrl(page);
    const state = await page.evaluate(async (url) => {
      const shell = await import(url);
      let done = false;
      shell.tipsReady().then(() => { done = true; });
      return { started: true, done };
    }, url);
    expect(state.done).toBe(false);
    await page.clock.runFor(1400);
    expect(await page.evaluate(() => document.querySelector('#content [data-rendered]') !== null)).toBe(false);
    await page.clock.runFor(200);
    await shellReady(page);
    await mount(page, ['fixture.status.paused']);
    await expect(page.locator('.has-tip')).toHaveCount(0);
  });

  test('C4 copy answering at 1.2 s still draws triggers (no early timeout)', async ({ page }) => {
    await page.clock.install();
    let release;
    await serveCopy(page, COPY, { hold: new Promise((ok) => { release = ok; }) });
    await page.goto('/ui/overview/status');
    await page.clock.runFor(1200);
    release();
    await shellReady(page);
    await mount(page, ['fixture.status.paused']);
    await expect(page.locator('.has-tip')).toHaveCount(1);
  });

  test('C4b the tab waits while copy is held, and renders right after release', async ({ page }) => {
    let release;
    await serveCopy(page, COPY, { hold: new Promise((ok) => { release = ok; }) });
    await page.goto('/ui/overview/status');
    await page.waitForTimeout(300);
    expect(await page.locator('#content [data-rendered]').count()).toBe(0);
    release();
    await shellReady(page);
  });

  test('C7 navigating before the copy settles waits for it, and nothing redraws after', async ({ page }) => {
    let release;
    await withFixturePages(page);
    await serveCopy(page, COPY, { hold: new Promise((ok) => { release = ok; }) });
    await page.goto('/ui/overview/status');
    await page.locator('nav.route-nav a', { hasText: 'Servers' }).click();
    await page.waitForTimeout(200);
    expect(await page.locator('#content [data-rendered]').count()).toBe(0);
    release();
    await expect(page.locator('#content [data-rendered]')).toHaveText('servers - status');
    const redraws = await page.evaluate(() => new Promise((ok) => {
      let n = 0;
      new MutationObserver((m) => { n += m.length; }).observe(document.getElementById('content'), { childList: true });
      setTimeout(() => ok(n), 400);
    }));
    expect(redraws).toBe(0);
  });

  test('C8 the content is marked rendered only when its tab has drawn', async ({ page }) => {
    await serveCopy(page);
    await ready(page);
    const url = await shellModuleUrl(page);
    const early = await page.evaluate(async (url) => {
      const shell = await import(url);
      shell.register('servers', { tabs: { status: async (el) => { await new Promise((ok) => setTimeout(ok, 300)); el.textContent = 'late'; } } });
      shell.go('/ui/servers/status');
      await new Promise((ok) => setTimeout(ok, 50));
      return document.querySelector('#content [data-rendered]')?.textContent ?? null;
    }, url);
    expect(early).toBeNull();
    await shellReady(page);
    expect(await page.locator('#content [data-rendered]').textContent()).toBe('late');
  });

  test('C5 C5b copy loads once and triggers render', async ({ page }) => {
    let fetches = 0;
    await page.route('**/ui/assets/tips.*.json', (route) => { fetches++; return route.fulfill({ json: COPY }); });
    await ready(page);
    await mount(page, ['fixture.status.paused', 'fixture.status.calls']);
    await expect(page.locator('.has-tip')).toHaveCount(2);
    expect(fetches).toBe(1);
  });
});
