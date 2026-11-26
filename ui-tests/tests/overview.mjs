// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The Overview's test fixtures, shared by its specs: the overview body, the
// series reads, serve() and open().
import { expect } from './base.mjs';

export const H = (hh, mm = 0) => Date.UTC(2026, 10, 19, hh, mm) / 1000;

/** The overview body: every field the tiles read, with a slowest server named. */
export function overview(over = {}) {
  return {
    kpi: {
      servers_total: 28, servers_up: 24, tools_total: 1284, uptime_secs: 3600, version: '4.0.0',
      calls_24h: 4812, calls_prev_24h: 4415, blocks_24h: 3, blocks_prev_24h: 1, errors_24h: 0, errors_prev_24h: 0,
      counting_since: H(9, 15),
      ...over.kpi,
    },
    latency: 'latency' in over ? over.latency : {
      from: H(14), to: H(15),
      servers: [{ name: 'kubernetes', p95_ms: 2100, calls: 12 }, { name: 'github', p95_ms: 1900, calls: 300 }],
      more: { count: 0 },
      slowest: { name: 'github', p95_ms: 1900, calls: 300 },
    },
    ...('degraded' in over ? { degraded: over.degraded } : {}),
  };
}

// Four half-hour buckets; the last is in progress and left out of the cache sums.
export const T = [H(13), H(13, 30), H(14), H(14, 30)];
export const points = (vs) => vs.map((v, i) => ({ t: T[i], v }));
/** A series body as GET /ui/api/metrics/series answers it. */
export const series = (metric, vs) => ({
  metric, window: '24h', bucket_secs: 1800, day_basis: null, zone: 'UTC', since: T[0], folded: false,
  points: points(vs), previous: points(vs.map(() => 0)), previous_complete: true,
});
export const SERIES = {
  calls: series('calls', [100, 200, 0, 50]),
  blocks: series('blocks', [1, 0, 2, 0]),
  cache_hits: series('cache_hits', [10, 50, 0, 40]),
};

/**
 * Answer the overview and the three series reads. `reads` maps a metric to a body, a status
 * number, 'abort' (a network failure) or a promise that settles with one of those (a held read).
 */
export async function serve(page, { body = overview(), reads = {} } = {}) {
  await page.route('**/ui/api/status', (r) => r.fulfill({ json: { auth: { enabled: true, signed_in: true, admin: true } } }));
  await page.route('**/ui/api/overview', (r) => r.fulfill({ json: body }));
  await page.route('**/ui/api/metrics/series**', async (r) => {
    const metric = new URL(r.request().url()).searchParams.get('metric');
    const given = await (reads[metric] ?? SERIES[metric]);
    if (given === 'abort') return r.abort('failed');
    if (typeof given === 'number') return r.fulfill({ status: given, json: { error: 'no' } });
    return r.fulfill({ json: given });
  });
}

/** Open the Overview at `width` and wait for the tiles' first paint. */
export async function open(page, width = 1440) {
  await page.setViewportSize({ width, height: width < 640 ? 844 : 1100 });
  await page.goto('/ui/overview/status');
  await expect(page.locator('#content [data-overview-painted]')).toHaveCount(1);
}
