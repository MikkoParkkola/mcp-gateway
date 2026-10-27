// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Page errors: the banner names the cause, keeps the last data dimmed under
// it, and offers Retry; a fault in a page's own code never reads as an
// unreachable gateway. Rows E1-E8 and their lettered cases.
import { test, expect, WIDTHS, blockingViolations } from './base.mjs';
import { withFixturePages, shellReady } from './shell.mjs';

const PROBE = '**/ui/api/page-probe*';
const FAULT = '**/ui/api/fault-probe';
const banner = (page) => page.locator('#content [data-state="error"]');
const retry = (page) => banner(page).getByRole('button', { name: /Retry/ });

/** Navigate inside the shell, keeping the document (and what it holds). */
async function inApp(page, path) {
  await page.evaluate((to) => {
    history.pushState(null, '', to);
    dispatchEvent(new PopStateEvent('popstate'));
  }, path);
  await expect(page).toHaveURL(path);
}

/** Open Policies › Status with the probe answering `answer`. */
async function openProbed(page, answer) {
  await page.route(PROBE, answer);
  await withFixturePages(page, { probes: true });
  await page.goto('/ui/policies/status');
  await shellReady(page);
}

test.describe('the cause', () => {
  test('E1 a request that gets no answer says the gateway could not be reached, with Retry', async ({ page }) => {
    await openProbed(page, (r) => r.abort('connectionrefused'));
    await expect(banner(page)).toHaveAttribute('data-cause', 'unreachable');
    await expect(banner(page)).toContainText('Could not reach the gateway');
    await expect(retry(page)).toBeVisible();
  });

  test('E2 a 500 says the gateway answered with an error, and names the code', async ({ page }) => {
    await openProbed(page, (r) => r.fulfill({ status: 500, json: { error: 'boom' } }));
    await expect(banner(page)).toHaveAttribute('data-cause', 'server');
    await expect(banner(page)).toContainText('The gateway answered with an error');
    await expect(banner(page)).toContainText('HTTP 500');
    await expect(banner(page)).not.toContainText('Could not reach');
    await expect(retry(page)).toBeVisible();
  });

  test('E3 a 404 says not found', async ({ page }) => {
    await openProbed(page, (r) => r.fulfill({ status: 404, json: { error: 'missing' } }));
    await expect(banner(page)).toHaveAttribute('data-cause', 'not-found');
    await expect(banner(page)).toContainText('Not found');
    await expect(retry(page)).toBeVisible();
  });

  test('E4 a fault in the page itself says so, never that the gateway could not be reached', async ({ page }) => {
    await page.route(FAULT, (r) => r.fulfill({ json: {} }));
    await withFixturePages(page, { probes: true });
    await page.goto('/ui/costs/status');
    await shellReady(page);
    await expect(banner(page)).toHaveAttribute('data-cause', 'page-fault');
    await expect(banner(page)).toContainText('This page failed');
    await expect(banner(page)).toContainText('TypeError');
    await expect(banner(page)).not.toContainText('Could not reach');
    await expect(retry(page)).toBeVisible();
  });
});

test.describe('retry and last data', () => {
  test('E5 Retry renders the page again once the gateway answers', async ({ page }) => {
    let ok = false;
    await openProbed(page, (r) => (ok ? r.fulfill({ json: { value: 2 } }) : r.fulfill({ status: 503, json: {} })));
    await expect(banner(page)).toBeVisible();
    ok = true;
    await retry(page).click();
    await expect(page.locator('#content')).toContainText('value 2');
    await expect(banner(page)).toHaveCount(0);
    await expect(page.locator('#content [data-dimmed]')).toHaveCount(0);
    expect(await page.evaluate(() => !!document.activeElement?.closest('#content'))).toBe(true);
  });

  test('E6 the last data stays under the banner, dimmed', async ({ page }) => {
    let fail = false;
    await openProbed(page, (r) => (fail ? r.fulfill({ status: 500, json: {} }) : r.fulfill({ json: { value: 1 } })));
    await expect(page.locator('#content')).toContainText('value 1');
    await page.locator('nav.tabs a', { hasText: 'Actions' }).click();
    await expect(page.locator('#content')).toContainText('policies - actions');
    fail = true;
    await page.locator('nav.tabs a', { hasText: 'Status' }).click();
    await expect(banner(page)).toHaveAttribute('data-cause', 'server');
    await expect(banner(page)).toContainText('before the error');
    const dimmed = page.locator('#content [data-dimmed]');
    await expect(dimmed).toContainText('value 1');
    const [colour, muted] = await dimmed.evaluate((el) => {
      const probe = document.createElement('span');
      probe.style.color = 'var(--color-text-secondary)';
      document.body.append(probe);
      const want = getComputedStyle(probe).color;
      probe.remove();
      return [getComputedStyle(el).color, want];
    });
    expect(colour).toBe(muted);
    // Readable by everyone, operable by no one.
    await expect(page.getByRole('region', { name: 'Data from before the error' })).toContainText('value 1');
    await expect(dimmed.locator('a')).toHaveCount(1);
    expect(await dimmed.locator('a').getAttribute('href')).toBeNull();
    await expect(page.locator('#probe-link')).toHaveCount(0); // ids are stripped from the copy
    await retry(page).focus();
    await page.keyboard.press('Tab');
    expect(await page.evaluate(() => !!document.activeElement?.closest('[data-dimmed]'))).toBe(false);
  });

  test('E6b data from another page is never shown under its banner', async ({ page }) => {
    await page.route(PROBE, (r) => r.fulfill({ json: { value: 1 } }));
    await page.route(FAULT, (r) => r.fulfill({ json: {} }));
    await withFixturePages(page, { probes: true });
    await page.goto('/ui/policies/status');
    await shellReady(page);
    await expect(page.locator('#content')).toContainText('value 1');
    await page.locator('nav.route-nav a[href="/ui/costs"]').click();
    await expect(banner(page)).toHaveAttribute('data-cause', 'page-fault');
    await expect(page.locator('#content [data-dimmed]')).toHaveCount(0);
    await expect(page.locator('#content')).not.toContainText('value 1');
  });

  test('E7 Retry says Retrying… and is busy while it runs, and a second click sends nothing', async ({ page }) => {
    let calls = 0;
    let release;
    const held = new Promise((resolve) => { release = resolve; });
    await openProbed(page, async (r) => {
      calls += 1;
      if (calls === 1) return r.fulfill({ status: 500, json: {} });
      await held;
      return r.fulfill({ json: { value: 3 } });
    });
    await expect(banner(page)).toBeVisible();
    await retry(page).click();
    await expect(retry(page)).toHaveText('Retrying…');
    await expect(retry(page)).toHaveAttribute('aria-busy', 'true');
    await retry(page).click({ force: true });
    expect(calls).toBe(2);
    release();
    await expect(page.locator('#content')).toContainText('value 3');
    expect(calls).toBe(2);
  });
});

test.describe('accessibility', () => {
  for (const width of WIDTHS) {
    test(`E8 axe at ${width} px on a banner over dimmed data`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      let fail = false;
      await openProbed(page, (r) => (fail ? r.fulfill({ status: 500, json: {} }) : r.fulfill({ json: { value: 1 } })));
      await page.locator('nav.tabs a', { hasText: 'Actions' }).click();
      fail = true;
      await page.locator('nav.tabs a', { hasText: 'Status' }).click();
      await expect(page.locator('#content [data-dimmed]')).toBeVisible();
      expect(await blockingViolations(page)).toEqual([]);
    });
  }
});

const KEY = 'mcpg_fixture_key_0123456789';

/** Auth on: status answers signed in only for KEY as a bearer. */
async function gate(page) {
  await page.route('**/ui/api/status', (route) => {
    const signedIn = (route.request().headers().authorization ?? '') === `Bearer ${KEY}`;
    return route.fulfill({ json: { version: '4.0.0', auth: { enabled: true, signed_in: signedIn, admin: signedIn } } });
  });
}

async function signIn(page) {
  await page.locator('#signin-key').fill(KEY);
  await page.keyboard.press('Enter');
  await expect(page.locator('#signin')).toBeHidden();
}

test.describe('round 2 cases', () => {
  test('E2b an answer that is not JSON reads as unreadable, not as a page fault', async ({ page }) => {
    await openProbed(page, (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{not json' }));
    await expect(banner(page)).toHaveAttribute('data-cause', 'unreadable');
    await expect(banner(page)).toContainText("The gateway's answer could not be read");
    await expect(banner(page)).not.toContainText('This page failed');
  });

  test('E5b a Retry that fails again shows the new cause and keeps focus on Retry', async ({ page }) => {
    let calls = 0;
    await openProbed(page, (r) => {
      calls += 1;
      return calls === 1 ? r.fulfill({ status: 500, json: {} }) : r.abort('connectionrefused');
    });
    await expect(banner(page)).toHaveAttribute('data-cause', 'server');
    await retry(page).click();
    await expect(banner(page)).toHaveAttribute('data-cause', 'unreachable');
    await expect(retry(page)).toBeFocused();
  });

  test('E6c another object of the same page never lends its data', async ({ page }) => {
    await openProbed(page, (r) => (r.request().url().includes('object=b')
      ? r.fulfill({ status: 500, json: {} })
      : r.fulfill({ json: { value: 'of a' } })));
    await inApp(page, '/ui/policies/a/status');
    await expect(page.locator('#content')).toContainText('value of a');
    await inApp(page, '/ui/policies/b/status');
    await expect(banner(page)).toHaveAttribute('data-cause', 'server');
    await expect(page.locator('#content [data-dimmed]')).toHaveCount(0);
  });

  test('E6d signing in again drops data kept for the session before', async ({ page }) => {
    await gate(page);
    let stage = 0;
    await page.route(PROBE, (r) => {
      if (stage === 0) return r.fulfill({ json: { value: 1 } });
      if (stage === 1) { stage = 2; return r.fulfill({ status: 401, json: {} }); }
      return r.fulfill({ status: 500, json: {} });
    });
    await withFixturePages(page, { probes: true });
    await page.goto('/ui/policies/status');
    await signIn(page);
    await expect(page.locator('#content')).toContainText('value 1');
    await page.locator('nav.tabs a', { hasText: 'Actions' }).click();
    stage = 1;
    await page.locator('nav.tabs a', { hasText: 'Status' }).click();
    await expect(page.locator('#signin')).toBeVisible();
    await signIn(page);
    await expect(banner(page)).toHaveAttribute('data-cause', 'server');
    await expect(page.locator('#content [data-dimmed]')).toHaveCount(0);
  });

  test('E7b a Retry answered after navigating away renders nothing on the new page', async ({ page }) => {
    let calls = 0;
    let release;
    const held = new Promise((resolve) => { release = resolve; });
    await openProbed(page, async (r) => {
      calls += 1;
      if (calls === 1) return r.fulfill({ status: 500, json: {} });
      await held;
      return r.fulfill({ json: { value: 'late' } });
    });
    await retry(page).click();
    await expect(retry(page)).toHaveAttribute('aria-busy', 'true');
    await page.locator('nav.route-nav a[href="/ui/servers"]').click();
    await expect(page.locator('#content')).toContainText('servers - status');
    await expect(page.locator('#content')).not.toHaveAttribute('aria-busy', 'true');
    const answered = page.waitForResponse(PROBE);
    release();
    await answered;
    await page.evaluate(() => new Promise((done) => requestAnimationFrame(() => setTimeout(done, 0))));
    await expect(page.locator('#content')).toContainText('servers - status');
    await expect(page.locator('#content')).not.toContainText('value late');
  });
});

test.describe('round 3 cases', () => {
  test('E6e a render that wrote part of the page and then faulted shows none of it', async ({ page }) => {
    let answer = { value: 1 };
    await openProbed(page, (r) => r.fulfill({ json: answer }));
    await expect(page.locator('#content')).toContainText('value 1');
    await page.locator('nav.tabs a', { hasText: 'Actions' }).click();
    answer = { value: 'partial', fault: true };
    await page.locator('nav.tabs a', { hasText: 'Status' }).click();
    await expect(banner(page)).toHaveAttribute('data-cause', 'page-fault');
    await expect(page.locator('#content')).not.toContainText('value partial');
    await expect(page.locator('#content [data-dimmed]')).toContainText('value 1');
  });

  test('E9 a first render that answers after navigating away changes nothing on the new page', async ({ page }) => {
    let release;
    const held = new Promise((resolve) => { release = resolve; });
    await page.route(PROBE, async (r) => { await held; return r.fulfill({ status: 500, json: {} }); });
    await withFixturePages(page, { probes: true });
    await page.goto('/ui/policies/status');
    await page.locator('nav.route-nav a[href="/ui/servers"]').click();
    await expect(page.locator('#content')).toContainText('servers - status');
    const answered = page.waitForResponse(PROBE);
    release();
    await answered;
    await page.evaluate(() => new Promise((done) => requestAnimationFrame(() => setTimeout(done, 0))));
    await expect(banner(page)).toHaveCount(0);
    await expect(page.locator('#content')).toContainText('servers - status');
  });

  test('E10 a Retry answered 401 shows sign-in', async ({ page }) => {
    await gate(page);
    let retried = false;
    await page.route(PROBE, (r) => r.fulfill({ status: retried ? 401 : 500, json: {} }));
    await withFixturePages(page, { probes: true });
    await page.goto('/ui/policies/status');
    await signIn(page);
    await expect(banner(page)).toHaveAttribute('data-cause', 'server');
    retried = true;
    await retry(page).click();
    await expect(page.locator('#signin')).toBeVisible();
  });

  test('E10b a Retry answered 403 shows forbidden, with no data from before', async ({ page }) => {
    let calls = 0;
    await openProbed(page, (r) => {
      calls += 1;
      if (calls === 1) return r.fulfill({ json: { value: 1 } });
      return calls === 2 ? r.fulfill({ status: 500, json: {} }) : r.fulfill({ status: 403, json: {} });
    });
    await page.locator('nav.tabs a', { hasText: 'Actions' }).click();
    await page.locator('nav.tabs a', { hasText: 'Status' }).click();
    await expect(page.locator('#content [data-dimmed]')).toBeVisible();
    await retry(page).click();
    await expect(page.locator('#content [data-state="forbidden"]')).toBeVisible();
    await expect(page.locator('#content [data-dimmed]')).toHaveCount(0);
    expect(await page.evaluate(() => !!document.activeElement?.closest('#content'))).toBe(true);
  });

  test('E11 a 404 with an empty body reads not found, not unreadable', async ({ page }) => {
    await openProbed(page, (r) => r.fulfill({ status: 404, body: '' }));
    await expect(banner(page)).toHaveAttribute('data-cause', 'not-found');
  });
});

test.describe('code review cases', () => {
  test('E7c moving to a missing page during a Retry leaves nothing busy', async ({ page }) => {
    let calls = 0;
    const held = new Promise(() => {}); // the Retry never answers
    await openProbed(page, async (r) => {
      calls += 1;
      if (calls === 1) return r.fulfill({ status: 500, json: {} });
      await held;
    });
    await retry(page).click();
    await expect(page.locator('#content')).toHaveAttribute('aria-busy', 'true');
    await inApp(page, '/ui/no-such-page');
    await expect(page.locator('.head .plate')).toHaveText('Not found');
    await expect(page.locator('#content')).not.toHaveAttribute('aria-busy', 'true');
  });
});
