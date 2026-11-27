// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The Overview's flow map: callers, the gateway and servers drawn from the one
// overview read, folded to a fixed number of rows, kept by key across updates.
import { test, expect } from './base.mjs';
import { serve, open } from './overview.mjs';
import { SMALL, big, flowBody, edge, srv, callers, servers } from './flowmap.mjs';

const map = (page) => page.locator('#content [data-panel="flow-map"]');
const agentRows = (page) => map(page).locator('ol.ov-agents > li');
const serverRows = (page) => map(page).locator('ol.ov-servers > li');
const names = (rows) => rows.locator('.ov-row-name');
const callsOf = (rows) => rows.locator('.ov-row-calls');
/** Open the Overview on `body` and wait for the map. */
async function showMap(page, body, width) {
  await serve(page, { body });
  await open(page, width);
  await expect(map(page).locator('.ov-map')).toHaveCount(1);
}

test.use({ timezoneId: 'UTC', locale: 'en-GB' });

test('M1 the map draws callers, the gateway and servers from the overview read', async ({ page }) => {
  const reads = [];
  page.on('request', (r) => { if (new URL(r.url()).pathname === '/ui/api/overview') reads.push(r.url()); });
  await showMap(page, SMALL);
  await expect(names(agentRows(page))).toHaveText(['alice', 'bob', 's1']);
  await expect(callsOf(agentRows(page))).toHaveText(['120', '80', '40']);
  // A server that is not running comes first, with its state in words.
  await expect(names(serverRows(page))).toHaveText(['jira', 'github', 'stripe', 'linear']);
  await expect(serverRows(page).first()).toContainText('Paused');
  await expect(map(page).locator('svg.ov-lines path')).toHaveCount(7);
  await expect(map(page).locator('svg.ov-lines path.ov-dashed')).toHaveCount(1);
  await expect(map(page).locator('.ov-hub')).toHaveText('4 servers, 12 tools');
  expect(reads).toHaveLength(1);
});

test('M2 140 servers fold to "+N more", and the flows not drawn are said', async ({ page }) => {
  await showMap(page, big());
  await expect(serverRows(page)).toHaveCount(11);
  const fold = serverRows(page).last();
  await expect(fold.locator('.ov-row-name')).toHaveText('+130 more');
  await expect(fold.locator('.ov-row-sub')).toHaveText('124 answering, 6 not answering');
  await expect(fold.locator('a')).toHaveAttribute('href', '/ui/servers/status');
  await expect(agentRows(page)).toHaveCount(6);
  await expect(names(agentRows(page)).last()).toHaveText('+4 more agents');
  await expect(map(page).locator('.ov-map-note')).toHaveText('12 smaller flows with 345 calls are not drawn.');
  // Calls no flow kept are a clause of their own, never added into the flows' calls.
  for (const [overflow, words] of [[7, '12 smaller flows with 345 calls are not drawn, and 7 more calls were not attributed to a flow.'],
    [0, '12 smaller flows with 345 calls are not drawn.']]) {
    const body = big();
    body.edges.more.overflow_calls = overflow;
    await page.unrouteAll({ behavior: 'ignoreErrors' });
    await showMap(page, body);
    await expect(map(page).locator('.ov-map-note'), `${overflow}`).toHaveText(words);
  }
});

test('M3 exactly 11 servers and exactly 6 callers fold nothing', async ({ page }) => {
  await showMap(page, flowBody({ edges: callers(6), servers: servers(11) }));
  await expect(serverRows(page)).toHaveCount(11);
  await expect(agentRows(page)).toHaveCount(6);
  await expect(map(page).locator('.ov-fold')).toHaveCount(0);
});

test('M3b one over: 7 callers and 12 servers fold the rest, and nothing is counted twice or lost', async ({ page }) => {
  const edges = callers(7, (i) => i);
  const rows = [...servers(11), srv('s12', { state: 'paused', calls: 0 })];
  await showMap(page, flowBody({ edges, servers: rows }));
  await expect(agentRows(page)).toHaveCount(6);
  // The fold holds the two smallest callers: 20 + 10 calls, 5 + 6 blocked.
  const agentFold = agentRows(page).last();
  await expect(agentFold.locator('.ov-row-name')).toHaveText('+2 more agents');
  await expect(agentFold.locator('.ov-row-calls')).toHaveText('30');
  await expect(agentFold).toContainText('11 blocked');
  const drawnCalls = (await callsOf(agentRows(page)).allTextContents()).reduce((a, s) => a + Number(s.replace(/,/g, '')), 0);
  expect(drawnCalls).toBe(edges.reduce((a, e) => a + e.calls, 0));
  // The paused server comes first; ten rows, then "+2 more" with their answering counts.
  await expect(serverRows(page)).toHaveCount(11);
  await expect(names(serverRows(page)).first()).toHaveText('s12');
  await expect(names(serverRows(page)).last()).toHaveText('+2 more');
  await expect(serverRows(page).last().locator('.ov-row-sub')).toHaveText('2 answering, 0 not answering');
  const answering = await serverRows(page).evaluateAll((ls) => ls.filter((l) => l.dataset.up === 'true').length);
  expect(answering + 2).toBe(rows.filter((r) => r.up).length);
});

test('M3c a server with no calls number shows none, at the neutral width', async ({ page }) => {
  const rows = [srv('a', { calls: 90 }), srv('b'), srv('c', { calls: null }), srv('d', { calls: 30 })];
  await showMap(page, flowBody({ edges: [edge('key:k', 'a', 5)], servers: rows }));
  await expect(callsOf(serverRows(page))).toHaveText(['90', '', '', '30']);
  const widths = await map(page).locator('svg.ov-lines path[data-side="servers"]').evaluateAll((ps) => ps.map((p) => p.getAttribute('stroke-width')));
  expect(widths[1]).toBe('1');
  expect(widths[2]).toBe('1');
  expect(Number(widths[0])).toBeGreaterThan(Number(widths[3]));
  await expect(map(page)).not.toContainText('undefined');
  await expect(map(page)).not.toContainText('NaN');
  // The fold row of a fleet past 11 has no calls number and the neutral width too.
  await page.unrouteAll({ behavior: 'ignoreErrors' });
  await showMap(page, big());
  await expect(serverRows(page).last().locator('.ov-row-calls')).toHaveText('');
  expect(await map(page).locator('svg.ov-lines path[data-side="servers"]').last().getAttribute('stroke-width')).toBe('1');
});

test('O1 the map takes its place in the one panel order', async ({ page }) => {
  await showMap(page, SMALL);
  const order = await page.locator('#content .ov > [data-panel]').evaluateAll((ss) => ss.map((s) => s.dataset.panel));
  expect(order.filter((p) => ['kpis', 'flow-map', 'needs-you', 'calls-chart'].includes(p))).toEqual(['kpis', 'flow-map', 'needs-you', 'calls-chart']);
});
