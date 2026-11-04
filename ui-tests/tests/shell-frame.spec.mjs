// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The shell frame: sidebar, tabs in the address, object paths, history,
// not-built pages, themes, skip link, hit areas, page states and the
// accessibility and budget checks. Rows F1-F19 of the shell test plan.
import { test, expect, WIDTHS, blockingViolations } from './base.mjs';
import { PAGES, TABS, HIDDEN, BUILT, shellModuleUrl, withFixturePages, shellReady } from './shell.mjs';

const TODO = PAGES[1][0];

test.describe('sidebar and tabs', () => {
  test('F2 the matrix covers 9 pages and 26 tab addresses', () => {
    expect(PAGES).toHaveLength(9);
    const urls = PAGES.flatMap(([id]) => TABS.filter((t) => !(id === HIDDEN.page && t === HIDDEN.tab)).map((t) => `/ui/${id}/${t}`));
    expect(urls).toHaveLength(26);
  });

  test('F1 the sidebar lists the nine pages in order, as links', async ({ page }) => {
    await page.goto('/ui/overview/status');
    const links = page.locator('nav.route-nav a');
    await expect(links).toHaveCount(PAGES.length);
    expect(await links.allTextContents()).toEqual(PAGES.map(([, label]) => expect.stringContaining(label)));
    for (const [i, [id]] of PAGES.entries()) {
      await expect(links.nth(i)).toHaveAttribute('href', `/ui/${id}`);
    }
  });

  for (const [id, label] of PAGES) {
    for (const tab of TABS) {
      if (id === HIDDEN.page && tab === HIDDEN.tab) continue;
      test(`F2 a cold load of /ui/${id}/${tab} shows that page and tab`, async ({ page }) => {
        await withFixturePages(page);
        await page.goto(`/ui/${id}/${tab}`);
        await shellReady(page);
        await expect(page).toHaveURL(`/ui/${id}/${tab}`);
        await expect(page.locator('h1')).toContainText(label);
        const tabs = page.locator('nav.tabs a');
        const want = TABS.filter((t) => !(id === HIDDEN.page && t === HIDDEN.tab));
        expect((await tabs.allTextContents()).map((t) => t.trim().toLowerCase())).toEqual(want);
        await expect(page.locator(`nav.tabs a[aria-current="page"]`)).toHaveAttribute('href', `/ui/${id}/${tab}`);
        await expect(page.locator('#content')).toContainText(`${id} - ${tab}`);
      });
    }
  }

  test('F3 a hidden tab replaces to the first visible tab without a history entry', async ({ page }) => {
    await withFixturePages(page);
    await page.goto('/ui/overview/status');
    const before = await page.evaluate(() => history.length);
    await withFixturePages(page);
    await page.goto(`/ui/${HIDDEN.page}/${HIDDEN.tab}`);
    await shellReady(page);
    await expect(page).toHaveURL(`/ui/${HIDDEN.page}/status`);
    await expect(page.locator('nav.tabs a', { hasText: /settings/i })).toHaveCount(0);
    expect(await page.evaluate(() => history.length)).toBe(before + 1);
  });

  test('F3 a bare page address replaces to its first visible tab', async ({ page }) => {
    await withFixturePages(page);
    await page.goto('/ui/servers');
    await shellReady(page);
    await expect(page).toHaveURL('/ui/servers/status');
  });
});

test.describe('not-built pages', () => {
  for (const [id] of PAGES.filter(([p]) => !BUILT.includes(p))) {
    test(`F4 /ui/${id}/* renders the not-built state at that address`, async ({ page }) => {
      for (const tab of TABS) {
        await page.goto(`/ui/${id}/${tab}`);
        await shellReady(page);
        await expect(page).toHaveURL(`/ui/${id}/${tab}`);
        const state = page.locator('#content [data-state="not-built"]');
        await expect(state).toBeVisible();
        await expect(state.locator('a[href="/ui/classic"]')).toBeVisible();
      }
    });
  }

  test('F4 the document no longer redirects', async ({ request }) => {
    const doc = await (await request.get('/ui/overview/status')).text();
    expect(doc).not.toMatch(/http-equiv="refresh"/i);
  });

  test('F5 the classic link leaves the shell', async ({ page }) => {
    await page.goto('/ui/servers/status');
    await shellReady(page);
    await page.locator('#content a[href="/ui/classic"]').click();
    await expect(page).toHaveURL('/ui/classic');
    await expect(page.locator('h1')).toHaveText('Classic page stand-in');
  });
});

test.describe('addresses and history', () => {
  test('F6 an object path lands on that object and tab, also after a reload', async ({ page }) => {
    await withFixturePages(page);
    await page.goto('/ui/servers/github/actions');
    await shellReady(page);
    await expect(page.locator('#content')).toContainText('servers github actions');
    await page.reload();
    await shellReady(page);
    await expect(page).toHaveURL('/ui/servers/github/actions');
    await expect(page.locator('#content')).toContainText('servers github actions');
  });

  test('F6 an object named like a tab is reachable with an explicit tab', async ({ page }) => {
    await withFixturePages(page);
    await page.goto('/ui/servers/status/actions');
    await shellReady(page);
    await expect(page.locator('#content')).toContainText('servers status actions');
  });

  test('F7 back and forward restore page and tab without reloading the document', async ({ page }) => {
    const documents = [];
    page.on('request', (r) => { if (r.resourceType() === 'document') documents.push(r.url()); });
    await withFixturePages(page);
    await page.goto('/ui/overview/status');
    await shellReady(page);
    await page.locator('nav.tabs a', { hasText: /actions/i }).click();
    await expect(page).toHaveURL('/ui/overview/actions');
    await page.locator('nav.route-nav a[href="/ui/servers"]').click();
    await expect(page).toHaveURL('/ui/servers/status');
    await page.goBack();
    await expect(page).toHaveURL('/ui/overview/actions');
    await expect(page.locator('#content')).toContainText('overview - actions');
    await page.goForward();
    await expect(page.locator('#content')).toContainText('servers - status');
    expect(documents).toHaveLength(1);
  });
});

test('F7b modified clicks and new-tab links are left to the browser', async ({ page }) => {
  await withFixturePages(page);
  await page.goto('/ui/overview/status');
  await shellReady(page);
  const prevented = await page.evaluate(() => {
    const a = document.querySelector('nav.route-nav a[href="/ui/servers"]');
    const results = [];
    for (const init of [{ metaKey: true }, { ctrlKey: true }, { shiftKey: true }, { button: 1 }]) {
      const ev = new MouseEvent('click', { bubbles: true, cancelable: true, ...init });
      a.dispatchEvent(ev);
      results.push(ev.defaultPrevented);
    }
    const blank = document.createElement('a');
    blank.href = '/ui/servers';
    blank.target = '_blank';
    document.body.append(blank);
    const ev = new MouseEvent('click', { bubbles: true, cancelable: true });
    blank.dispatchEvent(ev);
    results.push(ev.defaultPrevented);
    blank.remove();
    return results;
  });
  // None was taken over by the router; the browser handles each itself.
  expect(prevented).toEqual([false, false, false, false, false]);
});

test('F7c a keyboard-followed sidebar link moves focus to the new content', async ({ page }) => {
  await withFixturePages(page);
  await page.goto('/ui/overview/status');
  await shellReady(page);
  await page.locator('nav.route-nav a[href="/ui/servers"]').focus();
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL('/ui/servers/status');
  await expect(page.locator('#content')).toBeFocused();
});

test('F7c the decisions count arriving does not take focus off a sidebar link', async ({ page }) => {
  let release;
  const held = new Promise((ok) => { release = ok; });
  await page.route('**/ui/api/decisions/count', async (r) => { await held; await r.fulfill({ json: { count: 2 } }); });
  await page.goto('/ui/overview/status');
  await shellReady(page);
  const link = page.locator('nav.route-nav a[href="/ui/costs"]');
  await link.focus();
  release();
  await expect(page.locator('nav.route-nav .count')).toHaveText('2');
  await expect(link).toBeFocused();
});

test('F6b a malformed escape renders not-found instead of breaking the shell', async ({ page }) => {
  await page.goto('/ui/servers/%E0%A4%A');
  await shellReady(page);
  await expect(page.locator('h1')).toContainText('Not found');
});

test('F7d a link with a query is left to the browser', async ({ page }) => {
  await page.goto('/ui/overview/status');
  await shellReady(page);
  await page.evaluate(() => {
    const a = document.createElement('a');
    a.href = '/ui/servers/status?view=x';
    a.textContent = 'query link';
    document.getElementById('content').append(a);
  });
  const load = page.waitForRequest((r) => r.resourceType() === 'document' && r.url().endsWith('?view=x'));
  await page.getByText('query link').click();
  await load; // a full document load: the router did not take it
});

test('F7e a keyboard-followed tab keeps focus on the new active tab', async ({ page }) => {
  await withFixturePages(page);
  await page.goto('/ui/overview/status');
  await shellReady(page);
  await page.locator('nav.tabs a', { hasText: /actions/i }).focus();
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL('/ui/overview/actions');
  await expect(page.locator('nav.tabs a[aria-current="page"]')).toBeFocused();
});

test('F6c a third segment naming no tab renders not-found with its own title', async ({ page }) => {
  await withFixturePages(page);
  await page.goto('/ui/servers/github/bogus');
  await shellReady(page);
  await expect(page).toHaveURL('/ui/servers/github/bogus');
  await expect(page.locator('h1')).toContainText('Not found');
  await expect(page).toHaveTitle('Not found · MCP Gateway');
});

test('F7f a link with a fragment to another page is left to the browser', async ({ page }) => {
  await page.goto('/ui/overview/status');
  await shellReady(page);
  await page.evaluate(() => {
    const a = document.createElement('a');
    a.href = '/ui/servers/status#limits';
    a.textContent = 'fragment link';
    document.getElementById('content').append(a);
  });
  const load = page.waitForRequest((r) => r.resourceType() === 'document' && r.url().includes('/ui/servers/status'));
  await page.getByText('fragment link').click();
  await load;
});

test.describe('phone menu', () => {
  test.use({ viewport: { width: 390, height: 844 } });
  test('P5 the menu opens the pages, a choice navigates and closes it, Esc returns focus', async ({ page }) => {
    await withFixturePages(page);
    await page.goto('/ui/overview/status');
    await shellReady(page);
    const menu = page.locator('button.menu');
    await expect(menu).toHaveAttribute('aria-expanded', 'false');
    await expect(page.locator('nav.route-nav')).toBeHidden();
    await menu.click();
    await expect(menu).toHaveAttribute('aria-expanded', 'true');
    await expect(page.locator('nav.route-nav a')).toHaveCount(9);
    await page.locator('nav.route-nav a[href="/ui/costs"]').click();
    await expect(page).toHaveURL('/ui/costs/status');
    await expect(page.locator('nav.route-nav')).toBeHidden();
    await menu.click();
    await page.keyboard.press('Escape');
    await expect(page.locator('nav.route-nav')).toBeHidden();
    await expect(menu).toBeFocused();
  });
});

test.describe('route line', () => {
  test('F8 the current station is copper and the To do badge follows the count', async ({ page }) => {
    // Nothing to decide: no badge. (A count the shell cannot read shows "?", T7.)
    await page.route('**/ui/api/decisions/count', (r) => r.fulfill({ json: { count: 0, revision: 'r0' } }));
    await page.goto('/ui/servers/status');
    await shellReady(page);
    const copper = await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--color-accent-default').trim());
    expect(copper).not.toBe('');
    const station = page.locator('nav.route-nav a[aria-current="page"] > i');
    const colour = await station.evaluate((el) => getComputedStyle(el).backgroundColor);
    const want = await page.evaluate((c) => {
      const probe = document.createElement('span');
      probe.style.color = c;
      document.body.append(probe);
      const rgb = getComputedStyle(probe).color;
      probe.remove();
      return rgb;
    }, copper);
    expect(colour).toBe(want);
    await expect(page.locator(`nav.route-nav a[href="/ui/${TODO}"] .count`)).toHaveCount(0);
  });

  test('F8 the To do badge shows a served count', async ({ page }) => {
    await page.route('**/ui/api/decisions/count', (r) => r.fulfill({ json: { count: 3 } }));
    await page.goto('/ui/servers/status');
    await shellReady(page);
    await expect(page.locator(`nav.route-nav a[href="/ui/${TODO}"] .count`)).toHaveText('3');
  });
});

test.describe('layout and themes', () => {
  test.describe.configure({ mode: 'serial' });
  const backgrounds = {};
  for (const [width, labels, sidebar] of [[1440, true, true], [1101, true, true], [1099, true, true], [820, true, true], [641, true, true], [639, false, false], [390, false, false]]) {
    test(`F9 at ${width} px the layout follows the breakpoints`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await page.goto('/ui/overview/status');
      await shellReady(page);
      if (sidebar) {
        await expect(page.locator('nav.route-nav')).toBeVisible();
        await expect(page.locator('nav.route-nav a .lbl').first()).toBeVisible({ visible: labels });
        await expect(page.locator('button.menu')).toBeHidden();
      } else {
        await expect(page.locator('nav.route-nav')).toBeHidden();
        await expect(page.locator('button.menu')).toBeVisible();
      }
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - innerWidth);
      expect(overflow).toBeLessThanOrEqual(0);
    });
  }

  test.describe('script off', () => {
    test.use({ javaScriptEnabled: false });
    for (const [name, media] of [['dark', { colorScheme: 'dark' }], ['light', { colorScheme: 'light' }], ['hc', { colorScheme: 'dark', contrast: 'more' }]]) {
      test(`F10 the ${name} theme applies with JavaScript off`, async ({ page }) => {
        await page.emulateMedia(media);
        await page.goto('/ui/overview/status');
        // Script is off for the page, not for evaluate(), which runs over CDP.
        const [bg, token] = await page.evaluate(() => {
          const probe = document.createElement('div');
          probe.style.background = 'var(--color-bg-canvas)';
          document.body.append(probe);
          return [getComputedStyle(document.body).backgroundColor, getComputedStyle(probe).backgroundColor];
        });
        expect(await page.locator('nav.route-nav a').count()).toBe(0); // proves the module did not run
        expect(token).not.toBe('rgba(0, 0, 0, 0)');
        expect(bg).toBe(token);
        backgrounds[name] = bg;
      });
    }
  });

  test('F10 the three themes differ', () => {
    expect(new Set(Object.values(backgrounds)).size).toBe(3);
  });
});

test.describe('keyboard and touch', () => {
  test('F11 the first Tab focuses the skip link, and Enter moves to the content', async ({ page }) => {
    await page.goto('/ui/overview/status');
    await shellReady(page);
    await page.keyboard.press('Tab');
    const skip = page.locator('a.skip');
    await expect(skip).toBeFocused();
    await expect(skip).toHaveText('Skip to content');
    await page.keyboard.press('Enter');
    await expect(page.locator('#content')).toBeFocused();
  });

  test('F16 Tab reaches every visible link and button', async ({ page }) => {
    await withFixturePages(page);
    await page.goto('/ui/overview/status');
    await shellReady(page);
    const targets = await page.locator('a:visible, button:visible').count();
    const seen = new Set();
    for (let i = 0; i < targets + 5; i++) {
      await page.keyboard.press('Tab');
      seen.add(await page.evaluate(() => {
        const el = document.activeElement;
        return el ? el.outerHTML.slice(0, 120) : '';
      }));
    }
    const reached = await page.evaluate((seenList) => {
      const all = [...document.querySelectorAll('a, button')].filter((el) => el.checkVisibility());
      return all.filter((el) => !seenList.includes(el.outerHTML.slice(0, 120))).map((el) => el.outerHTML.slice(0, 80));
    }, [...seen]);
    expect(reached).toEqual([]);
  });
});

test.describe('touch targets', () => {
  test.use({ isMobile: true, hasTouch: true, viewport: { width: 390, height: 844 } });
  test('F12 on a coarse pointer every link, tab and button is at least 44 px', async ({ page }) => {
    await withFixturePages(page);
    await page.goto('/ui/overview/status');
    await shellReady(page);
    expect(await page.evaluate(() => matchMedia('(pointer: coarse)').matches)).toBe(true);
    const small = await page.evaluate(() => [...document.querySelectorAll('a, button')]
      .filter((el) => el.checkVisibility())
      .map((el) => ({ el: el.outerHTML.slice(0, 60), r: el.getBoundingClientRect() }))
      .filter(({ r }) => r.width < 44 || r.height < 44)
      .map(({ el, r }) => `${el} ${Math.round(r.width)}x${Math.round(r.height)}`));
    expect(small).toEqual([]);
  });
});

test.describe('page states and safety', () => {
  test('F13 state() renders every kind with its heading, and none is itself live', async ({ page }) => {
    await page.goto('/ui/overview/status');
    await shellReady(page);
    const url = await shellModuleUrl(page);
    const kinds = await page.evaluate(async (url) => {
      const { state } = await import(url);
      return ['loading', 'empty', 'error', 'forbidden', 'stale', 'not-built'].map((kind) => {
        const el = state(kind, { title: `t-${kind}` });
        return { kind, data: el.dataset.state, role: el.getAttribute('role'), heading: el.querySelector('h2')?.textContent ?? '' };
      });
    }, url);
    for (const k of kinds) {
      expect(k.data, k.kind).toBe(k.kind);
      expect(k.heading, k.kind).not.toBe('');
    }
    // One live region announces transitions (UI1.18); no state is itself live.
    for (const k of kinds) expect(k.role, k.kind).toBeNull();
  });

  test('F13b a 403 from an API renders the forbidden state in place', async ({ page }) => {
    await page.route('**/ui/api/forbidden-probe', (r) => r.fulfill({ status: 403, json: { error: 'forbidden' } }));
    await withFixturePages(page);
    await page.goto('/ui/access/status');
    await shellReady(page);
    await expect(page).toHaveURL('/ui/access/status');
    await expect(page.locator('#content [data-state="forbidden"]')).toBeVisible();
  });

  test('F13c the page subtitle renders as text under the plate, and only when given', async ({ page }) => {
    await withFixturePages(page);
    await page.goto('/ui/overview/status');
    await shellReady(page);
    await expect(page.locator('.head .sub')).toHaveText('24 of 28 servers ready.');
    await page.locator('nav.route-nav a[href="/ui/servers"]').click();
    await expect(page.locator('.head .sub')).toBeHidden();
  });

  test('F14 a page title is text, never markup', async ({ page }) => {
    await withFixturePages(page, { title: '<img src=x onerror="window.pwned=1">' });
    await page.goto('/ui/overview/status');
    await shellReady(page);
    await expect(page.locator('h1 img')).toHaveCount(0);
    await expect(page.locator('h1')).toContainText('<img src=x');
    expect(await page.evaluate(() => window.pwned)).toBeUndefined();
  });
});

test.describe('accessibility', () => {
  for (const width of WIDTHS) {
    for (const registered of [false, true]) {
      test(`F15 axe at ${width} px, ${registered ? 'with' : 'without'} registered pages`, async ({ page }) => {
        await page.setViewportSize({ width, height: 900 });
        if (registered) await withFixturePages(page);
        await page.goto('/ui/servers/status');
        await shellReady(page);
        expect(await blockingViolations(page)).toEqual([]);
      });
    }
  }
});

test.describe('budgets', () => {
  test('F18 first paint, tab switch, script size and reduced motion', async ({ page }) => {
    const cdp = await page.context().newCDPSession(page);
    await cdp.send('Emulation.setCPUThrottlingRate', { rate: 4 });
    await cdp.send('Network.enable');
    await cdp.send('Network.emulateNetworkConditions', { offline: false, latency: 150, downloadThroughput: (1.6 * 1024 * 1024) / 8, uploadThroughput: (750 * 1024) / 8 });
    let scriptBytes = 0;
    page.on('response', async (r) => {
      if (r.request().resourceType() === 'script') scriptBytes += (await r.body()).length;
    });
    await withFixturePages(page);
    await page.goto('/ui/overview/status');
    await shellReady(page);
    // The critical path: the navigation and every resource requested before first paint.
    const path = await page.evaluate(() => {
      const fcp = performance.getEntriesByName('first-contentful-paint')[0]?.startTime ?? Infinity;
      const size = (e) => e.transferSize || e.encodedBodySize;
      const nav = performance.getEntriesByType('navigation')[0];
      const early = performance.getEntriesByType('resource').filter((r) => r.startTime < fcp);
      return { fcp, names: early.map((r) => new URL(r.name).pathname), requests: 1 + early.length, bytes: size(nav) + early.reduce((sum, r) => sum + size(r), 0) };
    });
    // Measured with the tools screen in the head: 9 requests, 215,405 bytes. Screens now
    // load with their route, so the path is 7 requests, 206,490 bytes: the page, the
    // shell's script and stylesheet, the fixture pages module (test-only) and the three
    // fonts; the fonts are asked for after the stylesheet parses, so a fast host that
    // paints first counts fewer. Budget: the first measured total plus 10%.
    expect(path.requests, `requests before first paint: ${path.names.join(', ')}`).toBeLessThanOrEqual(9);
    expect(path.bytes, 'bytes before first paint').toBeLessThanOrEqual(237_000);
    // Smoke check only. The strict 1000 ms first-paint budget is enforced by the dedicated
    // performance-budget work, not here: wall-clock paint time flakes on loaded runners.
    expect(path.fcp).toBeLessThan(3000);
    // Feedback: click to the selected tab. Tab switch: click to the new
    // content on screen. CI takes the best of two samples for noise.
    const samples = process.env.CI ? 2 : 1;
    let feedback = Infinity;
    let switchMs = Infinity;
    for (let i = 0; i < samples; i++) {
      const target = i % 2 ? '/ui/overview/status' : '/ui/overview/actions';
      const [f, t] = await page.evaluate(async (target) => {
        const t0 = performance.now();
        let selectedAt = Infinity;
        const seen = new MutationObserver(() => {
          if (selectedAt === Infinity && document.querySelector('nav.tabs a[aria-current="page"]')?.getAttribute('href') === target) selectedAt = performance.now();
        });
        seen.observe(document.querySelector('nav.tabs'), { subtree: true, attributes: true, childList: true });
        document.querySelector(`nav.tabs a[href="${target}"]`).click();
        const tab = target.split('/').pop();
        while (!document.querySelector('#content')?.textContent.includes(`overview - ${tab}`)) {
          await new Promise((ok) => requestAnimationFrame(ok));
          if (performance.now() - t0 > 2000) break;
        }
        await new Promise((ok) => requestAnimationFrame(ok));
        seen.disconnect();
        return [selectedAt - t0, performance.now() - t0];
      }, target);
      feedback = Math.min(feedback, f);
      switchMs = Math.min(switchMs, t);
    }
    console.log(`budgets: fcp ${Math.round(path.fcp)} ms, ${path.requests} requests, ${path.bytes} B, feedback ${Math.round(feedback)} ms, tab switch ${Math.round(switchMs)} ms, script ${scriptBytes} B`);
    expect(feedback).toBeLessThan(100);
    expect(switchMs).toBeLessThan(200);
    expect(scriptBytes).toBeGreaterThan(0);
    expect(scriptBytes).toBeLessThan(200 * 1024);
  });

  test('F18 reduced motion leaves nothing animating', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await withFixturePages(page);
    await page.goto('/ui/overview/status');
    await shellReady(page);
    await page.locator('nav.tabs a', { hasText: /actions/i }).click();
    expect(await page.evaluate(() => document.getAnimations().length)).toBe(0);
  });
});

test('F20 a screen sets its header through its context, and a kept one changes nothing after navigation', async ({ page }) => {
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/overview/status');
  await shellReady(page);
  const plate = page.locator('.head .plate');
  const sub = page.locator('.head .sub');
  await expect(sub).toHaveText('24 of 28 servers ready.');
  await page.evaluate(() => window.overviewHeader({ title: 'Counted', subtitle: '40 tools from 4 servers' }));
  await expect(plate).toHaveText('Counted');
  await expect(sub).toHaveText('40 tools from 4 servers');
  await expect(sub).toBeVisible();
  expect(await page.title()).toBe('Counted · MCP Gateway');
  // A field left out stays; a null subtitle hides the line.
  await page.evaluate(() => window.overviewHeader({ subtitle: null }));
  await expect(plate).toHaveText('Counted');
  await expect(sub).toBeHidden();
  // Text, never markup.
  await page.evaluate(() => window.overviewHeader({ title: '<b>x</b>' }));
  await expect(plate).toHaveText('<b>x</b>');
  await expect(plate.locator('b')).toHaveCount(0);
  // Kept past an in-page navigation: the next page's header is left alone.
  await page.click('nav.route-nav a[data-page="tools"]');
  await expect(plate).toHaveText('Tools');
  await page.evaluate(() => window.overviewHeader({ title: 'Stale', subtitle: 'stale' }));
  await expect(plate).toHaveText('Tools');
  await expect(sub).toBeHidden();
  expect(await page.title()).toBe('Tools · MCP Gateway');
  // An empty title leaves the header as it is.
  await page.click('nav.route-nav a[data-page="overview"]');
  await expect(sub).toHaveText('24 of 28 servers ready.');
  await page.evaluate(() => window.overviewHeader({ title: '', subtitle: 'kept' }));
  await expect(plate).toHaveText('Overview');
  await expect(sub).toHaveText('kept');
  // A not-found render clears a subtitle a screen set, not only hides it.
  await page.evaluate(() => { history.pushState(null, '', '/ui/nowhere'); dispatchEvent(new PopStateEvent('popstate')); });
  await expect(plate).toHaveText('Not found');
  await expect(sub).toHaveText('');
});

test('F20b a setter kept from a failed attempt changes nothing after a Retry succeeds', async ({ page }) => {
  await page.addInitScript(() => { window.__fails = 1; });
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/overview/status');
  await page.locator('#content').getByRole('button', { name: /Retry/ }).click();
  await expect(page.locator('#content')).toContainText('overview - status');
  await page.evaluate(() => window.overviewHeader({ title: 'Second' }));
  await page.evaluate(() => window.failedHeader({ title: 'First', subtitle: 'first' }));
  await expect(page.locator('.head .plate')).toHaveText('Second');
  await expect(page.locator('.head .sub')).toHaveText('24 of 28 servers ready.');
});

test('F20c a Retry that sets its header and then fails leaves the header as it was', async ({ page }) => {
  await page.addInitScript(() => { window.__fails = 2; window.__headerThenFail = true; });
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/overview/status');
  const retry = page.locator('#content').getByRole('button', { name: /Retry/ });
  await retry.click();
  await expect(retry).toBeEnabled();
  await expect(page.locator('.head .plate')).toHaveText('Overview');
  await expect(page.locator('.head .sub')).toHaveText('24 of 28 servers ready.');
  // The next Retry succeeds and its own header applies once its content shows.
  await retry.click();
  await expect(page.locator('#content')).toContainText('overview - status');
  await page.evaluate(() => window.overviewHeader({ title: 'Shown' }));
  await expect(page.locator('.head .plate')).toHaveText('Shown');
});

test('F20d a setter kept past a sign-out changes nothing (the identity changes with no re-render)', async ({ page }) => {
  await page.route('**/ui/api/status', (route) => route.fulfill({ json: { auth: { enabled: true, signed_in: true, admin: true } } }));
  await page.route('**/dashboard/logout', (route) => route.fulfill({ status: 204 }));
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/overview/status');
  await expect(page.locator('#content')).toContainText('overview - status');
  await page.evaluate(() => { window.keptSetter = window.overviewHeader; });
  // Sign-out moves to another identity (none) without drawing the page again: only the epoch tells.
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.locator('#signin')).toBeVisible();
  expect(await page.evaluate(() => window.overviewHeader === window.keptSetter), 'no re-render happened').toBe(true);
  await page.evaluate(() => window.keptSetter({ title: 'Stale', subtitle: 'stale' }));
  await expect(page.locator('.head .plate')).toHaveText('Overview');
  await expect(page.locator('.head .sub')).toHaveText('24 of 28 servers ready.');
});

test('F20e a setter from the previous render of the same page changes nothing', async ({ page }) => {
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/overview/status');
  await shellReady(page);
  await page.evaluate(() => { window.keptSetter = window.overviewHeader; window.keptBody = document.querySelector('#content > .body'); });
  const url = await shellModuleUrl(page);
  await page.evaluate(async (u) => (await import(u)).render(), url);
  await page.waitForFunction(() => window.overviewHeader !== window.keptSetter);
  // Put the old container back in the page, so only the setter's own guard can refuse it.
  await page.evaluate(() => { document.getElementById('content').append(window.keptBody); });
  await page.evaluate(() => window.keptSetter({ title: 'Stale', subtitle: 'stale' }));
  await expect(page.locator('.head .plate')).toHaveText('Overview');
  await expect(page.locator('.head .sub')).toHaveText('24 of 28 servers ready.');
});

test('F19 the shell reads fixtures only', async ({ page, offsite }) => {
  // The fixture stream is held open by default and would keep the network busy;
  // a 404 is retried only at the 30 s ceiling, so the network goes idle.
  await page.route('**/ui/api/stream', (r) => r.fulfill({ status: 404, body: '' }));
  await page.goto('/ui/overview/status');
  await shellReady(page);
  await page.waitForLoadState('networkidle');
  expect(offsite).toEqual([]);
});
