// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Part C's harness rows (part C design, "The harness contract"): the additions the journeys use, each proved here
// where no journey row proves it yet. M1 gw.mcp and the key-acceptance read (C-H2).
import { test, expect } from './gateway.mjs';

test.describe('keyed reads', () => {
  test.use({ seed: 'fresh' });

  test('M1 the admin key lists tools on /mcp; GET /ui/api/status takes only an accepted key', async ({ gw }) => {
    const listed = await gw.mcp({ key: gw.adminKey, method: 'tools/list' });
    expect(listed.status, JSON.stringify(listed.body)).toBe(200);
    expect(listed.body?.error, 'tools/list answered with a protocol error').toBeUndefined();
    expect(Array.isArray(listed.body?.result?.tools), JSON.stringify(listed.body)).toBe(true);
    // Accepted is exactly 200; 401 is the refusal; any other status fails the read (design C-H2).
    expect((await gw.api('/ui/api/status')).status).toBe(200);
    expect((await gw.api('/ui/api/status', { key: 'jh-not-a-key' })).status).toBe(401);
    expect((await gw.api('/ui/api/status', { key: null })).status).toBe(401);
    // Nothing here about a wrong key on /mcp: that behaviour is under triage and no row may pin it yet.
  });
});
