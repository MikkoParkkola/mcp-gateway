// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The test base every spec imports. It aborts any request that leaves the
// fixture server, so a test can only ever read fixture JSON, and it records
// the aborted URLs so a spec can assert that none happened.
import { test as base, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

export const test = base.extend({
  // Automatic: every test gets the guard whether or not it names `offsite`.
  offsite: [async ({ context, baseURL }, use) => {
    const origin = new URL(baseURL).origin;
    const blocked = [];
    await context.route('**/*', (route) => {
      const url = route.request().url();
      if (url.startsWith(`${origin}/`) || url.startsWith('data:')) return route.continue();
      blocked.push(url);
      return route.abort('blockedbyclient');
    });
    await use(blocked);
  }, { auto: true }],
});

export { expect };

/**
 * Reach `region` with one Tab from `from`, as a keyboard user does, then
 * press `key` and expect it to scroll along `axis` ('x' or 'y'). The region
 * must overflow first, or the check proves nothing.
 */
export async function scrollsFromKeyboard(page, { from, region, key, axis }) {
  const overflows = (el, a) => (a === 'x' ? el.scrollWidth > el.clientWidth : el.scrollHeight > el.clientHeight);
  expect(await region.evaluate(overflows, axis)).toBe(true);
  await from.focus();
  await page.keyboard.press('Tab');
  await expect(region).toBeFocused();
  await page.keyboard.press(key);
  await expect.poll(() => region.evaluate((el, a) => (a === 'x' ? el.scrollLeft : el.scrollTop), axis)).toBeGreaterThan(0);
}

/** The two widths every screen is checked at (phone and desktop). */
export const WIDTHS = [390, 1440];

/**
 * axe violations that fail a screen: serious or critical impact, plus any
 * colour-contrast, accessible-name or alt-text rule whatever its impact. WCAG 2.2 AA.
 * `include` limits the check to one part of the page (a CSS selector).
 */
export async function blockingViolations(page, include) {
  let builder = new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']);
  if (include) builder = builder.include(include);
  const { violations } = await builder.analyze();
  const nameRules = /contrast|name|label|title|alt/;
  return violations
    .filter((v) => v.impact === 'serious' || v.impact === 'critical' || nameRules.test(v.id))
    .map((v) => `${v.id} (${v.impact}): ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`);
}
