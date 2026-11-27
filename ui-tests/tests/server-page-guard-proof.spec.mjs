// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// PROBE ONLY, never on the PR: shows why every Settings row checks that the
// address stays on Settings. This row skips that check; at red it should PASS
// (the shell sends /settings to Status, which draws the not-found state),
// while the guarded T1b settings row FAILS on the same answer.
import { test, expect } from './base.mjs';
import { shellReady } from './shell.mjs';
import { entry, fullView, fakeServerGateway } from './server-page.mjs';

test('GUARD-PROOF unguarded: an unknown name on /settings shows the empty state', async ({ page }) => {
  await fakeServerGateway(page, { status: fullView(entry('github', 'running')) });
  await page.goto('/ui/servers/ghost/settings');
  await shellReady(page);
  await expect(page.locator('#content [data-state="empty"] h2')).toHaveText('No server named ghost');
});
