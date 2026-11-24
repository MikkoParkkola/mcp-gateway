// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The Overview screen, its KPI tiles: Calls, Firewall, From cache, Slowest 5%,
// Tools and Spend. Four reads start together: GET /ui/api/overview and one
// /ui/api/metrics/series read per metric (calls, blocks, cache_hits; 24 h with
// the 24 h before). The numbers paint from the overview read alone; each
// sparkline and the cache ratio fill in as their series return. Costs are never
// read. A field the API leaves out reads "Not available yet", never a zero.
// Every value goes in with textContent. The other Overview panels (Needs you,
// the flow map, the chart) are their own slices.
import { register, go, el as h } from '/ui/assets/shell.60857ec1239d.js';

// The SVG namespace, read off an element the HTML parser makes, so no asset carries a URL.
const SVG = document.createRange().createContextualFragment('<svg></svg>').firstChild.namespaceURI;
const NOT_YET = 'Not available yet';
const CLOCK = "Not available right now: the counter clock can't be read";
const UNCOUNTED = 'Not counted on this gateway';
const FAILED = 'Not available right now: a read failed';
const DISAGREE = 'Not available right now: the reads disagree';
const TREND_OFF = 'Trend unavailable right now';
/** The API cuts a name at 256 bytes on a character boundary, so a cut name is 253 to 256 bytes. */
const MAYBE_CUT_BYTES = 253;
/** Phones get the three-tile strip and More numbers below this width. */
const PHONE = '(max-width: 639px)';
/** The overview's counter fields (overview.rs COUNTER_FIELDS); none present and none degraded means no store. */
const COUNTER_FIELDS = ['kpi.calls_24h', 'kpi.blocks_24h', 'kpi.errors_24h', 'servers.calls_24h', 'edges', 'markers', 'checklist.tool_tried', 'latency'];

const n = (v) => v.toLocaleString('en');
const isCount = (v) => Number.isInteger(v) && v >= 0;
const degraded = (data, field) => Array.isArray(data.degraded) && data.degraded.includes(field);
/** Whether the overview carries the counter field `f` (one of COUNTER_FIELDS). */
function carries(data, f) {
  if (f.startsWith('kpi.')) return isCount(data.kpi?.[f.slice(4)]);
  if (f === 'servers.calls_24h') return Array.isArray(data.servers?.rows) && data.servers.rows.some((r) => r && 'calls_24h' in r);
  if (f === 'checklist.tool_tried') return Boolean(data.checklist) && 'tool_tried' in data.checklist;
  return f in data;
}
/** No counter store: every counter field is absent and none is named in `degraded`. */
const uncounted = (data) => !COUNTER_FIELDS.some((f) => carries(data, f) || degraded(data, f));
/** A counter field's words when it is absent. */
const absent = (data, field) => (uncounted(data) ? UNCOUNTED : degraded(data, field) ? CLOCK : NOT_YET);

/** "19 Nov, 09:15" in the browser's zone. */
const when = (secs) => new Date(secs * 1000).toLocaleString('en-GB', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
/** "14:00" in the browser's zone. */
const clock = (secs) => new Date(secs * 1000).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });

/** The context line of a counted tile: the comparison, else when counting began, else nothing. */
function compared(kpi, name) {
  const now = kpi[`${name}_24h`];
  const prev = kpi[`${name}_prev_24h`];
  if (!isCount(prev)) return isCount(kpi.counting_since) ? `counting since ${when(kpi.counting_since)}` : '';
  if (name === 'calls') {
    if (prev === 0) return now === 0 ? 'same as the 24 h before' : 'none the 24 h before';
    const pct = Math.round(((now - prev) / prev) * 100);
    return pct === 0 ? 'same as the 24 h before' : `${pct > 0 ? '↗' : '↘'} ${Math.abs(pct)}% vs the 24 h before`;
  }
  const d = now - prev;
  if (d === 0) return 'same as the 24 h before';
  return `${d > 0 ? '↗' : '↘'} ${n(Math.abs(d))} ${d > 0 ? 'more' : 'fewer'} than the 24 h before`;
}

/** A decorative sparkline; null values are gaps, so each run of numbers is its own line. */
function spark(values) {
  const nums = values.filter((v) => v !== null);
  const max = Math.max(...nums, 0);
  const step = values.length > 1 ? 72 / (values.length - 1) : 0;
  const svg = document.createElementNS(SVG, 'svg');
  svg.setAttribute('class', 'ov-spark');
  svg.setAttribute('viewBox', '0 0 72 18');
  svg.setAttribute('preserveAspectRatio', 'none');
  svg.setAttribute('aria-hidden', 'true');
  let run = [];
  const flush = () => {
    if (run.length) {
      const line = document.createElementNS(SVG, 'polyline');
      line.setAttribute('points', run.join(' '));
      svg.append(line);
    }
    run = [];
  };
  values.forEach((v, i) => {
    if (v === null) return flush();
    run.push(`${(i * step).toFixed(1)},${(17 - (max ? (v / max) * 16 : 0)).toFixed(1)}`);
  });
  flush();
  return svg;
}

/** A tile: its label and number (a link when it has a destination), then its trend and context line. */
function tileNode(id, label, value, context, href) {
  const head = [h('span', { class: 'ov-label' }, label), h('span', { class: 'ov-num num' })];
  const top = href ? h('a', { class: 'ov-go', href }, ...head) : h('div', { class: 'ov-go' }, ...head);
  // The shell routes plain paths itself; a link with a query (the Firewall tile's filter) would
  // otherwise reload the page and lose a key held only in memory, so it goes through go().
  if (href?.includes('?')) {
    top.addEventListener('click', (ev) => {
      if (ev.defaultPrevented || ev.button !== 0 || ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey) return;
      ev.preventDefault();
      go(href);
      document.getElementById('content').focus({ preventScroll: true });
    });
  }
  const tile = h('div', { class: 'ov-tile', 'data-tile': id }, top, h('div', { class: 'ov-trend' }, h('span', { class: 'ov-ctx' })));
  setNum(tile, value);
  setCtx(tile, context);
  return tile;
}
/** A sentence, not a value with a unit ("340 ms", "1.9 s"). */
const WORDS = /[A-Za-z]{3,}/;
/** A number reads in the large figure; a sentence in its place reads at text size. */
function setNum(tile, text) {
  const num = tile.querySelector('.ov-num');
  num.textContent = text;
  num.classList.toggle('ov-words', WORDS.test(text));
}
const setCtx = (tile, text) => { tile.querySelector('.ov-ctx').textContent = text; };
const addSpark = (tile, values) => tile.querySelector('.ov-trend').prepend(spark(values));
const trendOff = (tile) => tile.querySelector('.ov-trend').prepend(h('span', { class: 'ov-trend-off' }, TREND_OFF));

const ms = (v) => (v >= 1000 ? `${(v / 1000).toFixed(1)} s` : `${Math.round(v)} ms`);

/** A server's page, or the Servers list when its name may be cut, or is "." or ".." (a browser folds those). */
function serverPath(name) {
  if (name === '.' || name === '..' || new TextEncoder().encode(name).length >= MAYBE_CUT_BYTES) return '/ui/servers/status';
  return `/ui/servers/${encodeURIComponent(name)}/status`;
}

/** Slowest 5%: the slowest named server of the last hour, from the overview's `latency`. */
function slowestTile(data) {
  const label = 'Slowest 5%, last hour';
  const lat = data.latency;
  if (!lat || typeof lat !== 'object') return tileNode('p95', label, absent(data, 'latency'), '', null);
  const s = lat.slowest;
  if (s && typeof s.name === 'string' && Number.isFinite(s.p95_ms) && isCount(s.calls)) {
    const hour = isCount(lat.from) && isCount(lat.to) ? ` ${clock(lat.from)}–${clock(lat.to)}` : '';
    return tileNode('p95', label, ms(s.p95_ms), `${s.name}, slowest${hour} (${n(s.calls)} calls)`, serverPath(s.name));
  }
  if (Array.isArray(lat.servers) && lat.servers.length) {
    return tileNode('p95', label, 'Not enough calls yet', 'a server needs 21 timed calls in an hour to be named', null);
  }
  return tileNode('p95', label, 'No timed calls in the last hour', '', null);
}

/** The six tiles from the overview read; the series fill some in later. */
function tiles(data) {
  const kpi = data.kpi ?? {};
  const counted = (id, name, label, href) => (isCount(kpi[`${name}_24h`])
    ? tileNode(id, label, n(kpi[`${name}_24h`]), compared(kpi, name), href)
    : tileNode(id, label, absent(data, `kpi.${name}_24h`), '', href));
  const servers = isCount(kpi.servers_total) ? `across ${n(kpi.servers_total)} ${kpi.servers_total === 1 ? 'server' : 'servers'}` : '';
  return {
    calls: counted('calls', 'calls', 'Calls, last 24 h', '/ui/activity/status'),
    blocks: counted('blocks', 'blocks', 'Firewall, last 24 h', '/ui/activity/status?outcome=blocked'),
    // No cache destination exists (a later API adds one), so the tile is plain text.
    cache: tileNode('cache', 'From cache, last 24 h', uncounted(data) ? UNCOUNTED : '…', '', null),
    p95: slowestTile(data),
    tools: isCount(kpi.tools_total)
      ? tileNode('tools', 'Tools available', n(kpi.tools_total), servers, '/ui/tools/status')
      : tileNode('tools', 'Tools available', NOT_YET, '', '/ui/tools/status'),
    // The Overview never reads costs (an unbounded body); a later API adds a bounded spend summary.
    spend: tileNode('spend', 'Spend', NOT_YET, '', null),
  };
}

const FAIL = Symbol('failed read');
/** A series' points sorted by time when every one is a {t, v} count, else null (read as failed). */
function pointsOf(s) {
  if (!s || !Array.isArray(s.points)) return null;
  return s.points.every((p) => isCount(p?.t) && isCount(p?.v)) ? [...s.points].sort((a, b) => a.t - b.t) : null;
}

/**
 * The cache tile from both series, by its state table (the first applying row wins): no store, a
 * degraded counter field, a failed read, reads that disagree, no completed buckets, no calls, else the
 * ratio. The newest bucket (the half hour in progress) is left out of every sum.
 */
function fillCache(tile, data, callsRead, hitsRead) {
  if (uncounted(data)) return setNum(tile, UNCOUNTED);
  if (COUNTER_FIELDS.some((f) => degraded(data, f))) return setNum(tile, CLOCK);
  const calls = callsRead === FAIL ? null : pointsOf(callsRead);
  const hits = hitsRead === FAIL ? null : pointsOf(hitsRead);
  if (!calls || !hits) return setNum(tile, FAILED);
  if (calls.length !== hits.length || calls.some((p, i) => p.t !== hits[i].t)) return setNum(tile, DISAGREE);
  const done = calls.length - 1;
  if (done < 1) return setNum(tile, NOT_YET);
  const total = (list) => list.slice(0, done).reduce((a, p) => a + p.v, 0);
  const [c, k] = [total(calls), total(hits)];
  if (k > c) return setNum(tile, DISAGREE);
  if (c === 0) return setNum(tile, 'No calls in the last 24 h');
  setNum(tile, `${Math.round((k / c) * 100)}%`);
  setCtx(tile, `${n(k)} of ${n(c)} calls`);
  return addSpark(tile, calls.slice(0, done).map((p, i) => (p.v > 0 ? hits[i].v / p.v : null)));
}

/** Calls or Firewall: a sparkline from its series, or the trend words when the read failed. */
function fillTrend(tile, kpi, name, read) {
  if (!isCount(kpi[`${name}_24h`])) return;
  const pts = read === FAIL ? null : pointsOf(read);
  if (pts) addSpark(tile, pts.map((p) => p.v));
  else trendOff(tile);
}

const METRICS = ['calls', 'blocks', 'cache_hits'];
/** The breakpoint listener of the Overview drawn last. */
let watching = null;
const seriesPath = (m) => `/ui/api/metrics/series?metric=${m}&window=24h&compare=prev`;

/** Phones: the first three tiles, then More numbers holding the rest; wider: all six in one strip. */
function arrange(strip, more, t, phone) {
  const first = [t.calls, t.blocks, t.cache];
  const rest = [t.p95, t.tools, t.spend];
  if (phone) {
    strip.replaceChildren(...first);
    more.replaceChildren(h('summary', { class: 'ov-more-sum' }, `More numbers (${rest.length})`), ...rest);
    if (!more.isConnected) strip.after(more);
  } else {
    strip.replaceChildren(...first, ...rest);
    more.remove();
  }
}

async function statusTab(body, ctx) {
  // The four reads start together; a failed series is its tile's own state, never the page's. The shell
  // runs a tab only after the first paint, so none of them starts before it.
  const overview = ctx.api('/ui/api/overview');
  const reads = METRICS.map((m) => ctx.api(seriesPath(m)).catch(() => FAIL));
  const data = (await overview) ?? {};
  const kpi = data.kpi ?? {};
  const t = tiles(data);
  const strip = h('div', { class: 'ov-strip' });
  const more = h('details', { class: 'ov-more' });
  const phone = window.matchMedia(PHONE);
  const section = h('section', { class: 'tk ov-kpis', 'aria-label': 'Key numbers' }, strip,
    h('i', { class: 'c1', 'aria-hidden': 'true' }), h('i', { class: 'c2', 'aria-hidden': 'true' }));
  body.append(h('div', { class: 'ov', 'data-overview-painted': '' }, section));
  arrange(strip, more, t, phone.matches);
  // One breakpoint listener at a time: a new render takes the last one's place.
  watching?.mql.removeEventListener('change', watching.fn);
  const fn = (e) => {
    // A page that has moved on lets go of its tiles at the next breakpoint change.
    if (!section.isConnected) {
      phone.removeEventListener('change', fn);
      if (watching?.fn === fn) watching = null;
      return;
    }
    arrange(strip, more, t, e.matches);
  };
  watching = { mql: phone, fn };
  phone.addEventListener('change', watching.fn);

  const [calls, blocks, hits] = reads;
  await Promise.all([
    calls.then((s) => fillTrend(t.calls, kpi, 'calls', s)),
    blocks.then((s) => fillTrend(t.blocks, kpi, 'blocks', s)),
    Promise.all([calls, hits]).then(([c, k]) => fillCache(t.cache, data, c, k)),
  ]);
}

register('overview', {
  title: 'Overview',
  tabs: {
    status: statusTab,
    // The Overview is a status page: its actions live on the pages it links to.
    actions: null,
    settings: null,
  },
});
