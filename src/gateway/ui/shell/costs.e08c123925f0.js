// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Costs › Status: each API key's spend today against its own daily limit,
// its 7-day and 30-day spend, what happens at the limit, and whether its
// priced calls are refused now, from one read of GET /ui/api/costs. A
// figure the gateway does not know reads as words, never $0.00, and the page
// never invents a limit or a warning percent. Key names go in as text.
import { register, el as h } from '/ui/assets/shell.23eb92bf6df3.js';

const NA = 'not available';
const money = new Intl.NumberFormat('en', { minimumFractionDigits: 2, maximumFractionDigits: 2 });

/** Dollars with two decimals and `en` grouping: "$1,234.50". */
export const usd = (n) => `$${money.format(n)}`;

const num = (v) => typeof v === 'number' && Number.isFinite(v);
const cost = (win) => (win && num(win.cost_usd) ? win.cost_usd : null);

/** "X h Y min" from whole minutes, rounded up; "X h" or "Y min" when the other part is 0. */
function untilWords(secs) {
  const mins = Math.ceil(secs / 60);
  const hours = Math.floor(mins / 60);
  const rest = mins % 60;
  if (hours === 0) return `${rest} min`;
  return rest === 0 ? `${hours} h` : `${hours} h ${rest} min`;
}

/** The reset subtitle, or null when the gateway gave no future reset or no zone. */
function resetLine(body, nowSecs) {
  const at = body?.resets_at;
  const zone = body?.day_zone;
  if (!num(at) || at <= nowSecs || typeof zone !== 'string' || zone === '') return null;
  return `Limits reset at midnight, ${zone} time, in ${untilWords(at - nowSecs)}`;
}

/** Whether the enforcer answered for this row: `blocking` is never null when it did. */
const answered = (row) => typeof row.blocking === 'boolean';

/** Today's spend, only when the enforcer answered and the gateway can date today. */
const todayOf = (row, dated) => (answered(row) && dated && num(row.today_usd) ? row.today_usd : null);

/** The percent shown beside a warning: whole, and never 100 or more below the limit. */
function percentWords(today, limit) {
  let p = Math.round((today / limit) * 100);
  if (p >= 100 && today < limit) p = 99;
  return `${p}%`;
}

function todayCell(row, dated, warnAt) {
  const today = todayOf(row, dated);
  if (today === null) {
    const day = cost(row.window_24h);
    return day === null ? [NA] : [`${usd(day)} last 24 h`];
  }
  const limit = row.daily_limit_usd;
  const parts = [usd(today)];
  if (num(limit)) parts.push(` of ${usd(limit)}`);
  if (num(limit) && limit > 0 && num(warnAt) && (today / limit) * 100 >= warnAt) {
    parts.push(h('span', { class: 'cost-warn' }, ` ⚠ ${percentWords(today, limit)}`));
  }
  return parts;
}

const AT_LIMIT = { block: 'Blocks priced calls', notify: 'Notifies you' };

function atLimitWords(row) {
  if (!answered(row)) return NA;
  if (!num(row.daily_limit_usd)) return 'No limit';
  return AT_LIMIT[row.at_limit] ?? 'No action at the limit';
}

/** "Blocking", then " since HH:MM", then ", resets in <N>", each when known; null when not blocking. */
function blockedLine(row, body, nowSecs) {
  if (row.blocking !== true) return null;
  let line = 'Blocking';
  if (num(row.blocked_since)) {
    const t = new Date(row.blocked_since * 1000);
    line += ` since ${String(t.getHours()).padStart(2, '0')}:${String(t.getMinutes()).padStart(2, '0')}`;
  }
  const at = body.resets_at;
  if (num(at) && at > nowSecs) {
    const left = at - nowSecs;
    line += left < 3600 ? ', resets in under an hour' : `, resets in ${Math.ceil(left / 3600)}h`;
  }
  return h('p', { class: 'cost-blocked' }, line);
}

const byName = (a, b) => String(a.api_key_name).localeCompare(String(b.api_key_name));

/** Highest spend today first; rows without today's spend by their 24 h figure, nulls last; then the name. */
function ordered(rows, dated) {
  const key = (row) => {
    const today = todayOf(row, dated);
    return today !== null ? [0, today] : [1, cost(row.window_24h)];
  };
  return [...rows].sort((a, b) => {
    const [ga, va] = key(a);
    const [gb, vb] = key(b);
    if (ga !== gb) return ga - gb;
    if (va !== vb) {
      if (va === null) return 1;
      if (vb === null) return -1;
      return vb - va;
    }
    return byName(a, b);
  });
}

/** Said above the table when the gateway's alert rules are not in severity order (wording confirmed by review). */
const UNORDERED = 'Your alert rules are out of severity order, so a key shown as blocking can still have some calls let through. Give the higher percent the stricter action.';
const COLUMNS = ['Key', 'Today', '7 days', '30 days', 'At the limit'];

const cell = (label, ...content) => h('td', { 'data-label': label }, ...content);

function keyRow(row, body, nowSecs, dated) {
  const name = String(row.api_key_name);
  const link = h('a', { class: 'lnk', href: `/ui/access/${encodeURIComponent(name)}/status` }, name);
  const blocked = blockedLine(row, body, nowSecs);
  const spend = (w) => { const c = cost(w); return c === null ? NA : usd(c); };
  return h('tr', { class: 'cost-key' },
    cell(COLUMNS[0], link),
    cell(COLUMNS[1], ...todayCell(row, dated, body.warn_at_percent)),
    cell(COLUMNS[2], spend(row.window_7d)),
    cell(COLUMNS[3], spend(row.window_30d)),
    cell(COLUMNS[4], atLimitWords(row), ...(blocked ? [blocked] : [])));
}

async function statusTab(body, ctx) {
  let answer;
  try {
    answer = await ctx.api('/ui/api/costs');
  } catch (err) {
    if (err?.status !== 404) throw err;
    body.append(ctx.state('empty', { title: 'Spend is not tracked on this gateway', body: 'This gateway is built without cost governance.' }));
    return;
  }
  const rows = (Array.isArray(answer?.by_key) ? answer.by_key : []).filter((r) => r && r.api_key_name != null);
  if (rows.length === 0) {
    const action = h('p', {}, h('a', { class: 'lnk', href: '/ui/tools/actions' }, 'Try a tool'));
    body.append(ctx.state('empty', { title: 'No spend recorded yet', action }));
    return;
  }
  const nowSecs = Date.now() / 1000;
  ctx.header({ subtitle: resetLine(answer, nowSecs) });
  const dated = num(answer.resets_at);
  const table = h('table', { class: 't cost-table' },
    h('caption', { class: 'sr-only' }, 'Spend by key against its daily limit'),
    h('thead', {}, h('tr', {}, ...COLUMNS.map((c) => h('th', { scope: 'col' }, c)))),
    h('tbody', {}, ...ordered(rows, dated).map((row) => keyRow(row, answer, nowSecs, dated))));
  if (answer.alert_rules === 'unordered') body.append(h('p', { class: 'cost-unordered' }, UNORDERED));
  body.append(h('section', { class: 'tk cost-card' }, table));
}

register('costs', {
  title: 'Costs',
  // Settings is another ticket's; Actions has nothing to do yet. Null keeps both off the tab bar.
  tabs: { status: statusTab, actions: null, settings: null },
  entries: [],
});
