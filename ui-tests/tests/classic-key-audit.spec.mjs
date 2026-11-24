// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Key audit on the shipped classic HTML. An admin types an email and gets back
// the retained issuance of the key that email owns; an email that owns no key
// gets the empty answer. The fixture server only stands in for /ui/classic and
// answers no POST, so this file serves the real page and fakes /ui/api itself,
// the way classic-restart-advice.spec.mjs does. Answers follow the shape the
// server sends (src/gateway/ui/activity/key_lookup.rs): the page throws out any
// other shape and says the lookup failed.
import { readFileSync } from 'node:fs';
import { test, expect } from './base.mjs';

const PAGE_HTML = readFileSync(new URL('../../src/gateway/ui/index.html', import.meta.url), 'utf8');

const HOLDER = 'holder@example.test';
const STRANGER = 'stranger@example.test';
const ISSUANCE = {
  subject: 'svc-reports-2',
  issuer: 'audit-issuer',
  timestamp: '2026-10-03T14:02:11Z',
  backends: ['jira', 'slack'],
  tools: ['tickets.list'],
  token_jti: 'jti-reports-2',
};
// One page of results, nothing held back and nothing unreadable.
const page1 = (rows) => ({ scope: 'retained', rows, unreadable: 0, next_cursor: null, cursor_reset: false, scan_exhausted: false });

/** Key audit as an admin sees it. Every posted lookup is pushed onto `sent`; the email alone picks the reply. */
async function openKeyAudit(page, sent) {
  const replies = new Map([[HOLDER, page1([ISSUANCE])], [STRANGER, page1([])]]);
  const table = {
    'GET /ui/classic': () => ({ html: PAGE_HTML }),
    'GET /ui/api/status': () => ({ json: { auth: { signed_in: true, admin: true, enabled: true } } }),
    'POST /ui/api/key-server/audit/lookup-email': (req) => {
      const posted = JSON.parse(req.postData());
      sent.push(posted);
      return replies.has(posted.email) ? { json: replies.get(posted.email) } : { status: 500, json: {} };
    },
  };
  await page.route(/\/ui\/(classic|api\/)/, (route) => {
    const req = route.request();
    const made = (table[`${req.method()} ${new URL(req.url()).pathname}`] ?? (() => ({ json: {} })))(req);
    return made.html === undefined
      ? route.fulfill({ status: made.status ?? 200, json: made.json })
      : route.fulfill({ contentType: 'text/html', headers: { 'cache-control': 'no-store' }, body: made.html });
  });
  await page.goto('/ui/classic#key-audit');
  // Only an admin gets the page and its nav link, so seeing the link is the premise.
  await expect(page.locator('#nav-key-audit')).toBeVisible();
}

async function search(page, email) {
  await page.locator('#kl-email').fill(email);
  await page.locator('#kl-submit').click();
}

test("KA1 Key audit by email shows the holder's issuance, then the empty answer", async ({ page }) => {
  const sent = [];
  await openKeyAudit(page, sent);
  const results = page.locator('#kl-rows > div');

  await search(page, HOLDER);
  await expect(results).toHaveCount(1);
  // textContent from the DOM keeps the two spaces the page puts between fields.
  expect(await results.first().evaluate((el) => el.textContent))
    .toBe('2026-10-03T14:02:11Z  svc-reports-2  audit-issuer  [jira, slack]');
  await expect(results.first().locator('strong')).toHaveText('svc-reports-2');
  await expect(page.locator('#kl-status')).toHaveText('1 retained issuance(s) on this page.');
  await expect(page.locator('#kl-next')).toBeHidden();
  await expect(page.locator('#kl-email')).toHaveValue('');
  expect(sent).toEqual([{ email: HOLDER }]);

  await search(page, STRANGER);
  await expect(page.locator('#kl-status')).toHaveText('No retained issuance matches.');
  await expect(results).toHaveCount(0);
  expect(sent).toEqual([{ email: HOLDER }, { email: STRANGER }]);
});
