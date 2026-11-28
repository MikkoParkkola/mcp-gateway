// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The Overview screen, its KPI tiles: Calls, Firewall, From cache, Slowest 5%,
// Tools and Spend. Four reads start together: GET /ui/api/overview and one
// /ui/api/metrics/series read per metric (calls, blocks, cache_hits; 24 h with
// the 24 h before). The numbers paint from the overview read alone; each
// sparkline and the cache ratio fill in as their series return. Costs are never
// read. A field the API leaves out reads "Not available yet", never a zero.
// Every value goes in with textContent. Below the tiles, from the same overview
// read: the first-run checklist, Needs you and Last actions. The 24 h calls chart
// draws from the calls series and the markers with the shared chart module. The
// flow map is its own slice; every panel takes its place through place().
import { register, go, el as h, serverBadge } from '/ui/assets/shell.23eb92bf6df3.js';
import { chart, spark } from '/ui/assets/chart.8cb6bfe27b11.js';

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

// One formatter and one encoder for the page: building them per call cost the flow map's update budget.
const NUMBER = new Intl.NumberFormat('en');
const n = (v) => NUMBER.format(v);
const UTF8 = new TextEncoder();
const bytes = (s) => UTF8.encode(s).length;
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

/**
 * Route link `a` through go(): the shell routes plain paths itself, but a link with a query (a
 * filter) would reload the page and lose a key held only in memory. Returns `a`.
 */
function viaGo(a) {
  a.addEventListener('click', (ev) => {
    if (ev.defaultPrevented || ev.button !== 0 || ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey) return;
    ev.preventDefault();
    go(a.getAttribute('href'));
    document.getElementById('content').focus({ preventScroll: true });
  });
  return a;
}
/** A tile: its label and number (a link when it has a destination), then its trend and context line. */
function tileNode(id, label, value, context, href) {
  const head = [h('span', { class: 'ov-label' }, label), h('span', { class: 'ov-num num' })];
  const top = href ? h('a', { class: 'ov-go', href }, ...head) : h('div', { class: 'ov-go' }, ...head);
  if (href?.includes('?')) viaGo(top);
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
/** A tile's sparkline, named by the tile's label and the unit of what it draws. */
const addSpark = (tile, values, unit) => tile.querySelector('.ov-trend')
  .prepend(spark(values, { unit, label: tile.querySelector('.ov-label').textContent }));
const CALLS_UNIT = { words: 'calls per 30 min' };
const SHARE_UNIT = { words: 'share of calls per 30 min' };
const trendOff = (tile) => tile.querySelector('.ov-trend').prepend(h('span', { class: 'ov-trend-off' }, TREND_OFF));

const ms = (v) => (v >= 1000 ? `${(v / 1000).toFixed(1)} s` : `${Math.round(v)} ms`);

/** The Overview's panels in page order; each section names itself with data-panel. */
const PANEL_ORDER = ['kpis', 'checklist', 'flow-map', 'needs-you', 'calls-chart', 'last-actions'];
/** Put `section` before the first panel under `root` that comes later in PANEL_ORDER, else at the end. */
export function place(root, section) {
  const rank = PANEL_ORDER.indexOf(section.dataset.panel);
  const later = [...root.children].find((s) => PANEL_ORDER.indexOf(s.dataset.panel) > rank);
  root.insertBefore(section, later ?? null);
}
/** A panel card with its heading; `extra` sits beside the heading text. */
function card(id, title, ...extra) {
  return h('section', { class: 'tk ov-panel', 'data-panel': id }, h('h2', { class: 'ov-panel-h' }, title, ...extra));
}

/** A server's page, or the Servers list when its name may be cut, or is "." or ".." (a browser folds those). */
function serverPath(name) {
  if (name === '.' || name === '..' || bytes(name) >= MAYBE_CUT_BYTES) return '/ui/servers/status';
  return `/ui/servers/${encodeURIComponent(name)}/status`;
}

/** "14:33" for today, else "19 Nov, 14:33"; '' for text that is not a time. */
function stamp(text) {
  const t = Date.parse(typeof text === 'string' ? text : '');
  if (Number.isNaN(t)) return '';
  return new Date(t).toDateString() === new Date().toDateString() ? clock(t / 1000) : when(t / 1000);
}
const str = (v) => (typeof v === 'string' ? v : '');
const TO_DO = `/ui/${'to'}${'do'}/status`;
const NOTHING_NEEDED = 'Nothing needs you right now';
const UNKNOWN_ITEM = 'This page does not recognise this item yet';
const CONFIG_NOT_APPLIED = 'The configuration file was not applied';
const ALERT_TITLE = {
  not_running: 'Alerts may not go out: the alert channel is not fully running',
  suspended: 'No alerts are going out: the channel was suspended after repeated failures',
  failing: 'The latest alerts could not be delivered',
};
const ALERT_TITLE_UNKNOWN = 'The alert channel has a problem';
const ALERT_LAST_DELIVERY = (at) => (stamp(at) ? `Last alert delivered ${stamp(at)}` : 'No alert has been delivered yet');
/** A server's Actions tab, or the Servers list when its name was clipped or cannot address one page. */
function signInPath(name, clipped) {
  const page = serverPath(name);
  return clipped || page === '/ui/servers/status' ? '/ui/servers/status' : page.replace(/\/status$/, '/actions');
}
/** A key's page, or the Access list when its name may be cut or is "." or "..", as serverPath() does. */
function keyPath(name) {
  if (name === '.' || name === '..' || bytes(name) >= MAYBE_CUT_BYTES) return '/ui/access/status';
  return `/ui/access/${encodeURIComponent(name)}/status`;
}
/** `table[key]` only when the table itself holds it, so a value such as "constructor" reads as unknown. */
const own = (table, key) => (typeof key === 'string' && Object.hasOwn(table, key) ? table[key] : undefined);

/** Each needs-you kind's row: glyph, title, detail lines, link and link words. */
const NEEDS = {
  invalid_config: ({ detail: d = {} }) => ({
    glyph: '⊘', title: CONFIG_NOT_APPLIED, href: '/ui/gateway/status', go: 'Gateway status ›',
    lines: [str(d.cause), str(d.fix), d.repeats > 1 ? `Refused ${d.repeats} times` : ''],
  }),
  refused: ({ subject, detail: d = {} }) => (subject === 'config'
    ? { glyph: '⊘', title: CONFIG_NOT_APPLIED, href: '/ui/gateway/status', go: 'Gateway status ›', lines: [str(d.cause), str(d.fix)] }
    : { glyph: '⊘', title: `${str(subject)} was not started`, href: serverPath(str(subject)), go: 'Open the server ›', lines: [str(d.cause), str(d.fix)] }),
  limit_80: ({ detail: d = {} }) => {
    const key = d.scope === 'key';
    const who = d.scope === 'global' ? 'The gateway' : str(d.name);
    const limit = Number.isFinite(d.limit_usd) ? d.limit_usd.toFixed(2) : '?';
    return {
      glyph: '⚠', title: `${who} is at ${Math.floor(d.percent)}% of its $${limit} limit`, lines: [],
      href: key ? keyPath(str(d.name)) : '/ui/costs/status',
      go: key ? `See ${str(d.name)} ›` : 'See costs ›',
    };
  },
  alert_failed: ({ detail: d = {} }) => ({
    glyph: '⚠', title: own(ALERT_TITLE, d.state) ?? ALERT_TITLE_UNKNOWN, href: '/ui/gateway/status', go: 'Gateway status ›',
    lines: [str(d.fix), ALERT_LAST_DELIVERY(d.last_delivery_at)],
  }),
  sign_in: ({ subject, detail: d = {} }) => ({
    glyph: '⚠', title: `${str(subject)} needs sign-in`, lines: [], href: signInPath(str(subject), d.clipped === true), go: 'Sign in ›',
  }),
  decisions: ({ detail: d = {} }) => ({
    glyph: '☐', title: `${d.count} ${d.count === 1 ? 'decision' : 'decisions'} in To do`, lines: [], href: TO_DO, go: 'Open To do ›',
  }),
};

/** One needs-you row: a link when it has a destination, so a keyboard stops once per row. */
function needRow(kind, { glyph, title, lines, href, go }) {
  const parts = [h('span', { class: 'ny-glyph', 'aria-hidden': 'true' }, glyph),
    h('span', { class: 'ny-body' }, h('span', { class: 'ny-title' }, title),
      ...lines.filter(Boolean).map((l) => h('span', { class: 'ny-line' }, l)),
      ...(href ? [h('span', { class: 'ny-go' }, go)] : []))];
  return href ? h('a', { class: 'ny-row', 'data-kind': kind, href }, ...parts) : h('div', { class: 'ny-row', 'data-kind': kind }, ...parts);
}

/** Needs you: the served rows in the served order, then what folded. */
function needsYouPanel(data) {
  const ny = data.needs_you ?? {};
  const served = Array.isArray(ny.rows) ? ny.rows : [];
  const more = isCount(ny.more?.count) ? ny.more.count : 0;
  const rows = served.map((r) => {
    const draw = own(NEEDS, r?.kind);
    if (draw) return needRow(r.kind, draw(r));
    console.warn('overview: a needs-you row of a kind this page does not draw');
    return needRow('unknown', { glyph: '⚠', title: UNKNOWN_ITEM, lines: [str(r?.subject)] });
  });
  if (degraded(data, 'needs_you.decisions')) {
    const after = rows.findIndex((r) => r.dataset.kind !== 'invalid_config');
    rows.splice(after < 0 ? rows.length : after, 0, needRow('decisions', { glyph: '☐', title: FAILED, lines: [] }));
  }
  const section = card('needs-you', 'Needs you ', h('span', { class: 'ny-count num' }, n(rows.length + more)));
  if (!rows.length && !more) section.append(h('p', { class: 'ny-empty' }, NOTHING_NEEDED));
  section.append(...rows);
  const signIns = ny.more?.by_kind?.sign_in;
  if (isCount(signIns) && signIns > 0) {
    section.append(h('a', { class: 'ny-signins', href: '/ui/servers/status' }, `and ${n(signIns)} more servers wait for a sign-in`));
  }
  if (more) section.append(h('p', { class: 'ny-more' }, `and ${n(more)} more`));
  return section;
}

/** What an admin write did, keyed "<METHOD> <route template>": every non-GET row of the UI access table. */
const ROUTE_WORDS = new Map([
  ['POST /ui/api/tools/call', 'Tool tried'],
  ['POST /ui/api/decisions/{id}/resolve', 'Decision answered'],
  ['POST /ui/api/keys', 'Key made'],
  ['POST /ui/api/key-server/audit/lookup-email', 'Key server audit searched'],
  ['DELETE /ui/api/keys/{name}', 'Key revoked'],
  ['POST /ui/api/events/dead-letters/replay', 'Failed events sent again'],
  ['POST /ui/api/events/dead-letters/{id}/replay', 'Failed event sent again'],
  ['POST /ui/api/capabilities', 'Capability created'],
  ['PUT /ui/api/capabilities/{name}', 'Capability saved'],
  ['DELETE /ui/api/capabilities/{name}', 'Capability deleted'],
  ['POST /ui/api/capabilities/{name}/validate', 'Capability checked'],
  ['POST /ui/api/backends', 'Server added'],
  ['DELETE /ui/api/backends/{name}', 'Server removed'],
  ['PATCH /ui/api/backends/{name}', 'Server changed'],
  ['POST /ui/api/backends/{name}/revive', 'Server restarted'],
  ['POST /ui/api/backends/{name}/signin', 'Server sign-in started'],
  ['POST /ui/api/backends/{name}/signin/confirm', 'Server signed in'],
  ['POST /ui/api/settings/diff', 'Settings compared'],
  ['POST /ui/api/settings', 'Settings saved'],
  ['DELETE /ui/api/settings/secrets/unused/{name}', 'Unused secret removed'],
  ['POST /ui/api/config/restore', 'Configuration restored'],
  ['POST /ui/api/discovery/adopt', 'Found server brought in'],
  ['POST /ui/api/import/openapi/preview', 'OpenAPI import previewed'],
  ['POST /ui/api/import/openapi', 'OpenAPI tools imported'],
  ['POST /ui/api/previews', 'Server previewed'],
  ['POST /ui/api/control-plane/grants', 'Grant changed'],
  ['POST /ui/api/control-plane/policies', 'Policy changed'],
  ['POST /ui/api/control-plane/decisions', 'Decision recorded'],
  ['POST /ui/api/reload', 'Configuration reloaded'],
  ['POST /ui/api/gateway/restart', 'Gateway restarted'],
  ['POST /ui/api/dashboard-link', 'Dashboard link made'],
]);
const SOME_ACTION = 'Admin action';
const UNNAMED = 'an unnamed caller';
/** The sentence's ending by the audit's outcome word, first match: ok adds nothing. */
const ENDINGS = [['ok', ''], ['denied', ', refused'], ['invalid', ', not accepted']];
const ending = (outcome) => (ENDINGS.find(([w]) => w === outcome) ?? [null, ', failed'])[1];

/** Last actions: the newest admin actions, or the read-failed words; null when the gateway keeps no log. */
function lastActionsPanel(data) {
  const all = h('a', { class: 'la-all', href: '/ui/activity/status' }, 'All in Activity ›');
  const la = data.last_actions;
  if (!la || typeof la !== 'object') {
    if (!degraded(data, 'last_actions')) return null;
    const failed = card('last-actions', 'Last actions');
    failed.append(all, h('p', { class: 'la-empty' }, FAILED));
    return failed;
  }
  const section = card('last-actions', 'Last actions');
  section.append(all);
  const rows = Array.isArray(la.rows) ? la.rows : [];
  if (!rows.length) section.append(h('p', { class: 'la-empty' }, 'No admin actions yet'));
  for (const r of rows) {
    const what = ROUTE_WORDS.get(`${str(r?.method)} ${str(r?.route)}`) ?? SOME_ACTION;
    const who = str(r?.who?.account) || str(r?.who?.subject) || UNNAMED;
    section.append(h('div', { class: 'la-row' }, h('span', { class: 'la-time num' }, stamp(r?.at)),
      h('span', { class: 'la-what' }, `${what} by ${who}${ending(r?.outcome)}`)));
  }
  if (la.complete === false) {
    section.append(h('p', { class: 'la-older' }, 'Older actions may exist. ', h('a', { href: '/ui/activity/status' }, 'See Activity ›')));
  }
  return section;
}

/** The first-run steps: title open, title done, the open line, link and its words. */
const STEPS = [
  { open: 'Bring in your servers', done: 'Servers brought in', line: 'Or add a server by hand under', href: '/ui/servers/settings', go: 'Servers › Settings' },
  { open: 'Try a tool', done: 'Tool tried', line: 'Call one tool through the gateway to see it answer.', href: '/ui/tools/actions', go: 'Try a tool' },
  { open: 'Connect a client', done: 'Client connected', line: 'Point Claude, Cursor or VS Code at the gateway.', href: '/ui/gateway/settings', go: 'Connect a client' },
];
const WAIT_FOR_ONE = 'Opens after step 1.';

/** The first-run checklist; null once all three steps are done, so it retires itself. */
function checklistPanel(data) {
  const ck = data.checklist ?? {};
  const done = [isCount(data.kpi?.servers_total) && data.kpi.servers_total > 0, ck.tool_tried === true,
    ck.has_key === true || ck.client_seen === true];
  if (done.every(Boolean)) return null;
  const section = card('checklist', 'Get started ', h('span', { class: 'ck-count' }, `${done.filter(Boolean).length} of 3`));
  const list = h('ol', { class: 'ck-steps', role: 'list' });
  STEPS.forEach((s, i) => {
    const step = h('li', { class: 'ck-step', 'data-step': String(i + 1) },
      h('span', { class: 'ck-mark num', 'aria-hidden': 'true' }, done[i] ? '✓' : String(i + 1)));
    const body = h('span', { class: 'ck-body' }, h('span', { class: 'ck-title' }, done[i] ? s.done : s.open));
    if (!done[i]) {
      const waits = i > 0 && !done[0];
      body.append(h('span', { class: 'ck-line' }, waits ? `${s.line} ${WAIT_FOR_ONE}` : s.line));
      if (i === 1 && !('tool_tried' in ck)) body.append(h('span', { class: 'ck-line' }, absent(data, 'checklist.tool_tried')));
      if (!waits) body.append(h('a', { class: 'ck-go', href: s.href }, s.go));
    }
    step.append(body);
    list.append(step);
  });
  section.append(list);
  return section;
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
  return addSpark(tile, calls.slice(0, done).map((p, i) => (p.v > 0 ? hits[i].v / p.v : null)), SHARE_UNIT);
}

/** Calls or Firewall: a sparkline from its series, or the trend words when the read failed. */
function fillTrend(tile, kpi, name, read) {
  if (!isCount(kpi[`${name}_24h`])) return;
  const pts = read === FAIL ? null : pointsOf(read);
  if (pts) addSpark(tile, pts.map((p) => p.v), CALLS_UNIT);
  else trendOff(tile);
}

/** Each marker kind's glyph and words in the frame's form, from its subject (a server name or a version). */
const MARKER_WORDS = {
  restart: () => ['↻', 'gateway restarted'],
  upgrade: (s) => ['↻', `upgraded to ${s}`],
  config_reload: () => ['↻', 'configuration reloaded'],
  pause: (s) => ['⏸', `${s} paused`],
  switch_off: (s) => ['⚠', `${s} off`],
  switch_on: (s) => ['▶', `${s} on`],
};
/** A kind this page does not know reads in fixed words, never as its code. */
const SOME_EVENT = () => ['•', 'a gateway event'];
/** The API stamps the previous day's points a day earlier; the chart draws them over this day's. */
const DAY = 86_400;

/**
 * The calls chart from the calls read (its body, or FAIL) and the overview's markers. Words about the
 * panel rather than the plot (since when counting runs, the markers' state, how many are older) are
 * lines after the figure.
 */
function fillChart(section, data, read) {
  const say = (cls, words) => section.replaceChildren(h('p', { class: cls }, words));
  if (uncounted(data)) return say('chart-uncounted', UNCOUNTED);
  const points = read === FAIL ? null : pointsOf(read);
  if (!points) return say('chart-failed', FAILED);
  const before = read.previous_complete === true ? pointsOf({ points: read.previous }) : null;
  const series = [{ name: 'Last 24 h', role: 'main', points }];
  if (before) series.push({ name: '24 h before', role: 'previous', points: before.map((p) => ({ t: p.t + DAY, v: p.v })) });
  const sum = (list) => n(list.reduce((a, p) => a + p.v, 0));
  const summary = before ? `${sum(points)} calls in the last 24 h, ${sum(before)} in the 24 h before.` : `${sum(points)} calls in the last 24 h.`;
  const rows = Array.isArray(data.markers?.rows) ? data.markers.rows : [];
  const markers = rows.filter((m) => isCount(m?.t)).map((m) => {
    const [glyph, words] = (own(MARKER_WORDS, m.kind) ?? SOME_EVENT)(str(m.subject));
    return { t: m.t, glyph, words };
  });
  section.replaceChildren(chart({ caption: 'Calls per 30 min', unit: CALLS_UNIT, series, markers, x: clock, y: n, summary }));
  if (!before && isCount(read.since)) section.append(h('p', { class: 'chart-note chart-since' }, `counting since ${when(read.since)}`));
  if (degraded(data, 'markers')) section.append(h('p', { class: 'chart-note' }, CLOCK));
  const earlier = data.markers?.more?.count;
  if (isCount(earlier) && earlier > 0) section.append(h('p', { class: 'chart-note chart-more' }, `and ${n(earlier)} earlier`));
}

// ---------------------------------------------------------------- flow map

/** Rows drawn per column: the motion budget's fixed count, so an update's cost never grows with the fleet. */
const AGENT_ROWS = 6;
const SERVER_ROWS = 11;
/** The second line of a caller by the kind before its colon; a kind not listed shows none. */
const CALLER_KIND = { key: 'API key', oidc: 'OIDC sign-in', session: 'MCP session', token: 'Token' };
/** Callers with no colon in their label: their name in words. */
const CALLER_WORDS = { bearer: 'Static bearer token', local: 'Local process', anonymous: 'Anonymous caller' };
const FIRST_RUN = 'The live map appears here after the first call.';

/**
 * The account a caller label names, as the audit record holds it, or null: `key:`, `oidc:`, `session:`
 * or `token:` and a non-empty text. A label the counters cut (125 to 128 bytes ending in `~` and eight
 * hex digits, counters/mod.rs normalize) no longer holds the account, so it names none.
 */
export function accountOf(label) {
  const m = /^(?:key|oidc|session|token):(.+)$/s.exec(typeof label === 'string' ? label : '');
  if (!m) return null;
  // A label under 42 characters is under 125 bytes (three bytes a character at most), so only a
  // longer one is encoded to look for the cut.
  const size = label.length < 42 ? 0 : bytes(label);
  if (size >= 125 && size <= 128 && /~[0-9a-f]{8}$/.test(label)) return null;
  return m[1];
}

/** A caller row's name and second line from its label. */
function callerWords(label) {
  const words = own(CALLER_WORDS, label);
  if (words) return { name: words, sub: '' };
  const at = label.indexOf(':');
  return at < 0 ? { name: label, sub: '' } : { name: label.slice(at + 1), sub: own(CALLER_KIND, label.slice(0, at)) ?? '' };
}

/**
 * The map's rows from the overview read, pure: at most 6 caller rows and 11 server rows, the hub's two
 * totals, the note on flows not drawn, and `empty`, the words that stand in for the map (or null).
 */
export function flowModel(data) {
  const hub = { servers: isCount(data?.kpi?.servers_total) ? data.kpi.servers_total : null, tools: isCount(data?.kpi?.tools_total) ? data.kpi.tools_total : null };
  const edges = data?.edges;
  if (!edges || typeof edges !== 'object') return { agents: [], servers: [], hub, note: '', empty: absent(data ?? {}, 'edges') };
  const rows = Array.isArray(edges.rows) ? edges.rows.filter((r) => r && typeof r.caller === 'string' && isCount(r.calls)) : [];
  const more = edges.more ?? {};
  const overflow = isCount(more.overflow_calls) ? more.overflow_calls : 0;
  if (!rows.length) {
    return { agents: [], servers: [], hub, note: '', empty: overflow ? `${n(overflow)} calls were not attributed to a flow.` : FIRST_RUN };
  }

  // Callers: their flows summed, busiest first, then by name; past six, five and one fold row.
  const sums = new Map();
  for (const r of rows) {
    const s = sums.get(r.caller) ?? { calls: 0, blocks: 0 };
    s.calls += r.calls;
    s.blocks += isCount(r.blocks) ? r.blocks : 0;
    sums.set(r.caller, s);
  }
  const ranked = [...sums].map(([label, s]) => ({ key: `c:${label}`, label, ...callerWords(label), ...s, account: accountOf(label) }))
    .sort((a, b) => b.calls - a.calls || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  let agents = ranked;
  if (ranked.length > AGENT_ROWS) {
    const rest = ranked.slice(AGENT_ROWS - 1);
    agents = [...ranked.slice(0, AGENT_ROWS - 1), { key: 'fold:agents', fold: true, name: `+${n(rest.length)} more agents`, sub: '', account: null,
      calls: rest.reduce((a, r) => a + r.calls, 0), blocks: rest.reduce((a, r) => a + r.blocks, 0) }];
  }

  // Servers: not running first, each group in the order served; past eleven, ten and one fold row.
  const served = Array.isArray(data.servers?.rows) ? data.servers.rows.filter((r) => r && typeof r.name === 'string') : [];
  const smore = data.servers?.more ?? {};
  const folded = isCount(smore.count) ? smore.count : 0;
  const ordered = [...served.filter((r) => r.state !== 'running'), ...served.filter((r) => r.state === 'running')];
  const seen = new Map();
  const asRow = (r) => {
    // A name the API clipped can be served twice; its ordinal keeps the two rows apart.
    const nth = seen.get(r.name) ?? 0;
    seen.set(r.name, nth + 1);
    return { key: `s:${nth}:${r.name}`, name: r.name, state: r.state, up: r.up === true, calls: isCount(r.calls_24h) ? r.calls_24h : null, dashed: r.state !== 'running' };
  };
  let serverRows = ordered.map(asRow);
  if (served.length + folded > SERVER_ROWS) {
    const rest = serverRows.slice(SERVER_ROWS - 1);
    const up = rest.filter((r) => r.up).length + (isCount(smore.up) ? smore.up : 0);
    const down = rest.length - rest.filter((r) => r.up).length + (isCount(smore.down) ? smore.down : 0);
    serverRows = [...serverRows.slice(0, SERVER_ROWS - 1), { key: 'fold:servers', fold: true, name: `+${n(rest.length + folded)} more`,
      sub: `${n(up)} answering, ${n(down)} not answering`, calls: null, up: false, dashed: false }];
  }

  const count = isCount(more.count) ? more.count : 0;
  let note = '';
  if (count > 0) {
    note = `${n(count)} smaller flows with ${n(isCount(more.calls) ? more.calls : 0)} calls are not drawn`;
    note += overflow ? `, and ${n(overflow)} more calls were not attributed to a flow.` : '.';
  } else if (overflow) note = `${n(overflow)} more calls were not attributed to a flow.`;
  return { agents, servers: serverRows, hub, note, empty: null };
}

/** The rows drawn in each map, by key; kept per card, so an update reuses its nodes. */
const drawn = new WeakMap();
const SVG_NS = document.createRange().createContextualFragment('<svg/>').firstChild.namespaceURI;
/** One line of the map, for a row on `side`. */
function svgPath(side) {
  const p = document.createElementNS(SVG_NS, 'path');
  p.dataset.side = side;
  return p;
}

/**
 * A caller's gold dot: a link to its calls when it has an account, text when not. Each caller row keeps
 * one dot for its whole life and shows it only while the caller has blocked calls, so a dot that comes
 * or goes changes a class, not the row's layout. A dot that comes pulses once while fewer than three do.
 * Wide, it sits on its line where the line leaves the callers' column, at the row's height: clear of
 * the row's words (the list's right padding) and of the hub.
 */
function fillDot(nodes, row, y, drawLines) {
  const on = row.blocks > 0;
  if (!nodes.dot) {
    const linked = row.account && !row.fold;
    nodes.dot = linked ? viaGo(h('a', { class: 'ov-dot ov-dot-off', href: callsOfCaller(row.account) })) : h('span', { class: 'ov-dot ov-dot-off' });
    nodes.li.append(nodes.dot);
  }
  if (nodes.dotOn !== on) {
    nodes.dotOn = on;
    nodes.dot.classList.toggle('ov-dot-off', !on);
    const map = on ? nodes.box : null;
    if (map && map.querySelectorAll('.ov-pulse').length < 3) {
      nodes.dot.classList.add('ov-pulse');
      nodes.dot.addEventListener('animationend', () => nodes.dot?.classList.remove('ov-pulse'), { once: true });
    }
  }
  if (!on) return;
  const want = nodes.dot.localName;
  const dw = nodes.dw ?? (nodes.dw = {});
  const put = (name, v, write) => { if (dw[name] !== v) { write(v); dw[name] = v; } };
  if (want === 'a') put('href', callsOfCaller(row.account), (v) => nodes.dot.setAttribute('href', v));
  put('words', `${n(row.blocks)} blocked`, (v) => { nodes.dot.textContent = v; });
  if (drawLines) put('at', `${y}%`, () => {
    nodes.dot.style.setProperty('--at-x', `${(EDGE.agents / CALLER_COLUMN) * 100}%`);
    nodes.dot.style.setProperty('--at-y', `${y}%`);
  });
}
/** A line's width: 1 to 8 px by its calls against the column's busiest; no number gives the neutral 1. */
const width = (calls, max) => (calls === null || !max ? 1 : Math.round((1 + (7 * calls) / max) * 100) / 100);
/** The x where each column's lines meet the hub, in the 0-100 box the svg spans. */
const EDGE = { agents: 37.5, servers: 62.5 };
/**
 * The callers' list is the grid's first column, 37.5% of the map (overview.css). Wide, it contains its
 * layout, which makes it the box a dot is placed in, so a dot's x in the map is turned into the list's.
 */
const CALLER_COLUMN = 37.5;

/** A caller's link to its calls in Activity, by account, built so any character stays one value. */
const callsOfCaller = (account) => `/ui/activity/status?${new URLSearchParams({ key: account })}`;

/** One row's nodes: the item, its link or box, name, second line and calls. */
function rowNodes(side) {
  const name = h('span', { class: 'ov-row-name' });
  const sub = h('span', { class: 'ov-row-sub' });
  const calls = h('span', { class: 'ov-row-calls num' });
  const li = h('li', { class: 'ov-row' });
  return { li, name, sub, calls, go: null, dot: null, path: svgPath(side) };
}

/** Fill one row's nodes from its model row; the link is made again only when its target changes. */
function fillRow(nodes, row, side, i, count, max, drawLines) {
  // The link follows from the name (or account) alone, so it is worked out again only when that changes.
  const target = `${row.fold ? 'fold' : ''}|${side === 'servers' ? row.name : row.account ?? ''}`;
  if (nodes.target !== target) {
    nodes.target = target;
    nodes.href = side === 'servers' ? (row.fold ? '/ui/servers/status' : serverPath(row.name)) : (row.account ? callsOfCaller(row.account) : null);
  }
  const { href } = nodes;
  if (!nodes.go || nodes.go.getAttribute('href') !== href) {
    const go = href ? h('a', { class: 'ov-row-go', href }) : h('div', { class: 'ov-row-go' });
    if (href?.includes('?')) viaGo(go);
    go.append(nodes.name, nodes.sub, nodes.calls);
    nodes.go?.remove();
    nodes.li.prepend(go);
    nodes.go = go;
  }
  nodes.li.classList.toggle('ov-fold', Boolean(row.fold));
  // Only what changed is written: an unchanged text or attribute set again still costs style work.
  const was = nodes.was ?? {};
  const set = (k, v, write) => { if (was[k] !== v) { write(v); was[k] = v; } };
  set('up', String(Boolean(row.up)), (v) => { nodes.li.dataset.up = v; });
  set('name', row.name, (v) => { nodes.name.textContent = v; nodes.name.title = v; });
  if (side === 'servers' && !row.fold) set('state', row.state, (v) => nodes.sub.replaceChildren(serverBadge(v, { plain: true })));
  else set('sub', row.sub, (v) => { was.state = undefined; nodes.sub.textContent = v; });
  set('calls', row.calls === null ? '' : n(row.calls), (v) => { nodes.calls.textContent = v; });
  const y = ((i + 0.5) / count) * 100;
  const x0 = side === 'agents' ? 0 : 100;
  const mid = (EDGE[side] + 50) / 2;
  if (drawLines) set('d', `M ${x0} ${y} L ${EDGE[side]} ${y} C ${mid} ${y}, ${mid} 50, 50 50`, (v) => nodes.path.setAttribute('d', v));
  if (drawLines) set('w', String(width(row.calls, max)), (v) => nodes.path.setAttribute('stroke-width', v));
  if (drawLines) set('dashed', Boolean(row.dashed), (v) => nodes.path.classList.toggle('ov-dashed', v));
  nodes.was = was;
  if (side === 'agents') fillDot(nodes, row, y, drawLines);
}

/**
 * Draw `model` into the flow-map card `root`: the first call builds, later calls keep every row whose
 * key is still there (its item, link, line and dot), add the rows that came and remove the ones that
 * went. At most 17 rows exist, so an update touches a bounded number of nodes. No layout is read.
 */
export function updateMap(root, model) {
  let state = drawn.get(root);
  if (!state) {
    const agents = h('ol', { class: 'ov-agents', role: 'list', 'aria-label': 'Callers, busiest first' });
    const servers = h('ol', { class: 'ov-servers', role: 'list', 'aria-label': 'Servers, those that need a look first' });
    const hub = h('div', { class: 'ov-hub' });
    const lines = document.createElementNS(SVG_NS, 'svg');
    for (const [k, v] of Object.entries({ class: 'ov-lines', viewBox: '0 0 100 100', preserveAspectRatio: 'none', 'aria-hidden': 'true' })) lines.setAttribute(k, v);
    const box = h('div', { class: 'ov-map' }, lines, agents, hub, servers);
    const note = h('p', { class: 'ov-map-note' });
    const empty = h('p', { class: 'ov-map-empty' });
    const stale = h('p', { class: 'ov-map-stale', hidden: true });
    root.append(box, note, stale, empty);
    state = { box, lines, hub, note, stale, empty, lists: { agents, servers }, rows: { agents: new Map(), servers: new Map() } };
    drawn.set(root, state);
  }
  // Kept so a phone that widens draws the lines it skipped from the last model.
  state.model = model;
  // Each element is written only when its own value changed: a same-value write still costs a relayout.
  const text = (el, v) => { if (el.textContent !== v) el.textContent = v; };
  const hide = (el, v) => { if (el.hidden !== v) el.hidden = v; };
  text(state.empty, model.empty ?? '');
  hide(state.empty, !model.empty);
  hide(state.box, Boolean(model.empty));
  text(state.note, model.note);
  hide(state.note, !model.note);
  const words = [model.hub.servers === null ? '' : `${n(model.hub.servers)} servers`, model.hub.tools === null ? '' : `${n(model.hub.tools)} tools`];
  text(state.hub, words.filter(Boolean).join(', '));
  for (const side of ['agents', 'servers']) {
    const rows = model[side];
    const held = state.rows[side];
    const keep = new Set(rows.map((r) => r.key));
    for (const [key, nodes] of held) {
      if (keep.has(key)) continue;
      nodes.li.remove();
      nodes.path.remove();
      held.delete(key);
    }
    // Every row with a number counts, the callers' fold row too, so no line is wider than 8 px.
    const max = Math.max(0, ...rows.filter((r) => !r.fold && r.calls !== null).map((r) => r.calls));
    rows.forEach((row, i) => {
      let nodes = held.get(row.key);
      if (!nodes) {
        nodes = rowNodes(side);
        // A new row is not in the page while it is filled, so its dot is told where the map is.
        nodes.box = state.box;
        held.set(row.key, nodes);
      }
      fillRow(nodes, row, side, i, rows.length, max, !state.phone);
      // A kept node moves to its new place in the ranking; one already in place is left alone.
      if (state.lists[side].children[i] !== nodes.li) moveTo(state.lists[side], nodes.li, state.lists[side].children[i] ?? null);
      if (!nodes.path.isConnected) state.lines.append(nodes.path);
    });
  }
}

/** Put `node` before `before`; a move drops focus inside the node, so focus is given back without scrolling. */
function moveTo(parent, node, before) {
  const had = node.contains(document.activeElement) ? document.activeElement : null;
  parent.insertBefore(node, before);
  if (had && document.activeElement !== had) had.focus({ preventScroll: true });
}

/** On a phone the servers' list comes first in the page, so what is seen is what is read and tabbed. */
function orderLists(root, phone) {
  const state = drawn.get(root);
  if (!state) return;
  // On a phone the lines and the hub are hidden, so updates skip writing them; widening draws them again.
  const wasPhone = state.phone;
  state.phone = phone;
  if (wasPhone && !phone && state.model) updateMap(root, state.model);
  const { agents, servers } = state.lists;
  const [first, second] = phone ? [servers, agents] : [agents, servers];
  // Moved only when out of order: a node already in place is never touched (its focus and probes stay).
  if (second.compareDocumentPosition(first) & Node.DOCUMENT_POSITION_FOLLOWING) moveTo(state.box, first, second);
  // Wide, the hub stands between the two lists; on a phone it is hidden, so its place does not matter.
  if (!phone && agents.nextElementSibling !== state.hub) agents.after(state.hub);
}

/** How long after a stream event the map reads again: a fixed deadline that later events never push back. */
const REREAD_MS = 1000;

/**
 * Keep the map live: the stream's status and reload events read the overview again after REREAD_MS,
 * one read at a time; an event during a read asks for one more after it. Every step first checks that
 * the card is still on the page, and lets go of everything when it is not. A failed read leaves the
 * map as it was and says since when it has not changed.
 */
function keepLive(root, ctx) {
  let timer = null;
  let reading = false;
  let again = false;
  let lastGood = Date.now() / 1000;
  const gone = () => {
    if (root.isConnected) return false;
    removeEventListener('gateway-status', onEvent);
    removeEventListener('gateway-reload', onEvent);
    clearTimeout(timer);
    return true;
  };
  async function reread() {
    timer = null;
    if (gone()) return;
    reading = true;
    let fresh = null;
    try {
      fresh = (await ctx.api('/ui/api/overview')) ?? {};
    } catch {
      fresh = null;
    }
    reading = false;
    if (gone()) return;
    const line = drawn.get(root)?.stale;
    if (fresh) {
      updateMap(root, flowModel(fresh));
      lastGood = Date.now() / 1000;
      if (line) line.hidden = true;
    } else if (line) {
      line.textContent = `Not updated since ${clock(lastGood)}`;
      line.hidden = false;
    }
    if (again) {
      again = false;
      onEvent();
    }
  }
  function onEvent() {
    if (gone()) return;
    if (reading) again = true;
    else if (!timer) timer = setTimeout(reread, REREAD_MS);
  }
  addEventListener('gateway-status', onEvent);
  addEventListener('gateway-reload', onEvent);
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
  const section = h('section', { class: 'tk ov-kpis', 'aria-label': 'Key numbers', 'data-panel': 'kpis' }, strip,
    h('i', { class: 'c1', 'aria-hidden': 'true' }), h('i', { class: 'c2', 'aria-hidden': 'true' }));
  // Every panel is in place before the page counts as painted.
  const root = h('div', { class: 'ov' }, section);
  // The chart's panel holds its place until the calls read settles.
  const callsChart = h('section', { class: 'tk ov-panel', 'data-panel': 'calls-chart' }, h('p', { class: 'chart-note chart-wait' }, '…'));
  // The flow map draws from the same read, so it is complete before the page counts as painted.
  const flowMap = card('flow-map', 'Live traffic ', h('span', { class: 'ov-panel-when' }, 'last 24 h'));
  flowMap.classList.add('ov-flow');
  updateMap(flowMap, flowModel(data));
  orderLists(flowMap, phone.matches);
  keepLive(flowMap, ctx);
  for (const p of [checklistPanel(data), flowMap, needsYouPanel(data), callsChart, lastActionsPanel(data)]) if (p) place(root, p);
  root.setAttribute('data-overview-painted', '');
  body.append(root);
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
    orderLists(flowMap, e.matches);
  };
  watching = { mql: phone, fn };
  phone.addEventListener('change', watching.fn);

  const [calls, blocks, hits] = reads;
  await Promise.all([
    calls.then((s) => fillTrend(t.calls, kpi, 'calls', s)),
    calls.then((s) => fillChart(callsChart, data, s)),
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
