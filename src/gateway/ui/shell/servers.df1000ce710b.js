// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Servers › Status. Reads /ui/api/status and, once it has servers to show (or
// an empty list), the registry and discovery once per render. Precedence on
// the status answer: a failed read shows the error banner, the counts-only
// shape the forbidden state, an empty list the empty state, and servers the
// groups. A gateway-status event re-reads status alone, never two at a time:
// events that arrive during a read ask for one more read after it. The
// listener goes away at the first event after the screen has left the page
// (the shell gives a screen no leave hook). Gateway strings go in as text.
import { register, el, serverBadge, SERVER_STATES, GLOSSARY } from '/ui/assets/shell.08fc113e48aa.js';

/** Registry category to group label; a server with no labelled category goes under Other. */
export const GROUP_LABELS = {
  cloud: 'Cloud',
  code: 'Code',
  communication: 'Communication',
  crm: 'CRM',
  database: 'Databases',
  'dev-tools': 'Developer tools',
  filesystem: 'Files',
  finance: 'Finance',
  knowledge: 'Knowledge',
  memory: 'Memory',
  monitoring: 'Monitoring',
  productivity: 'Productivity',
  search: 'Search and web',
  utility: 'Utilities',
  'vector-db': 'Vector databases',
};
const OTHER = 'Other';

/** Needs a look, worst first. Any state that is neither here nor answering sorts after these. */
const WORST_FIRST = ['paused', 'needs_sign_in', 'refused', 'unhealthy'];
/** The states grouped under Answering, and the word each member row shows. */
const MEMBER_WORD = { running: 'Answering', slow: 'Slow', dormant: 'Idle' };
const answers = (s) => Object.hasOwn(MEMBER_WORD, s.state);

/** States whose `reason` is always one of the gateway's own sentences (server_state.rs). */
const SAYS_REASON = new Set(['needs_sign_in', 'unhealthy', 'slow']);

const QUIET_LINE = 'Could not check this machine for servers outside the gateway.';

/** The heading over the servers whose config entry turns them off: the state's one word, from the glossary (UI1.24). */
export const OFF_BLOCK_TITLE = GLOSSARY.server.off;

/**
 * How long the registry and discovery reads may take before the page draws without
 * them. Past the gateway's own 10 s scan bound (SCAN_TIMEOUT in discovery/listing.rs),
 * so its 503 normally answers first; this only covers a reply that never comes.
 */
const EXTRA_MS = 15_000;

/** The live screen's listener, dropped when the screen opens again, so a quiet session keeps no old screen. */
let dropListener = null;

const slug = (label) => label.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
const known = (n) => typeof n === 'number' && Number.isFinite(n);
const ms = (n) => (n < 1000 ? `${Math.round(n)} ms` : `${(n / 1000).toFixed(1)} s`);
const notKnown = () => el('td', { class: 'n', 'aria-label': 'not known' }, '—');
const numberCell = (n) => (known(n) ? el('td', { class: 'n' }, String(n)) : notKnown());
const p95Cell = (n) => (known(n) ? el('td', { class: 'n' }, ms(n)) : notKnown());

/** The words after a needs-a-look badge: a retry time, the gateway's sentence, or the shell's. */
function detail(s) {
  if (s.state === 'paused') {
    const at = typeof s.next_retry_at === 'string' ? new Date(s.next_retry_at) : null;
    return at && !Number.isNaN(at.getTime()) ? `retries ${at.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}` : '';
  }
  if (SAYS_REASON.has(s.state)) return typeof s.reason === 'string' ? s.reason : '';
  // A Refused reason can name raw policy codes or setting ids: the shell's words instead.
  if (s.state === 'refused') return SERVER_STATES.refused.banner(s);
  return ''; // a state this page does not know: its badge says so
}

function stateCell(badge, words) {
  const cell = el('td', {}, badge);
  if (words) cell.append(' ', el('span', { class: 'sv-why' }, words));
  return cell;
}

/** A member row's badge: the state's glyph and tone, with the screen's own word. */
function memberBadge(state) {
  const row = SERVER_STATES[state];
  return el('span', { class: `lb ${row.tone} plain` }, el('span', { class: 'glyph', 'aria-hidden': 'true' }, row.glyph), ' ', MEMBER_WORD[state]);
}

// The tooltip module loads after the screen has drawn and never holds it up; if it
// fails, the headings stand without their (i). Each caller names its id literally.
let tipModule = null;
function withTip(node, make) {
  (tipModule ??= import('/ui/assets/tooltip.cd1750e8bd65.js'))
    .then((mod) => node.append(' ', make(mod.tip)), () => {});
  return node;
}

/** The column headings; `tips` adds the Tools explanation (the Answering table only, so one per page). */
const head = (tips) => el('thead', {}, el('tr', {},
  el('th', { scope: 'col' }, 'Server'), el('th', { scope: 'col' }, 'State'),
  tips ? withTip(el('th', { scope: 'col', class: 'n' }, 'Tools'), (tip) => tip('servers.status.tools')) : el('th', { scope: 'col', class: 'n' }, 'Tools'),
  el('th', { scope: 'col', class: 'n' }, 'Calls, last 24 h'), el('th', { scope: 'col', class: 'n' }, 'p95')));

/** One titled block: its heading names the region, and the table scrolls on its own when narrow. */
function block(title, count, tbody, { tips = false, after = [] } = {}) {
  const id = `sv-${slug(title)}`;
  return el('section', { class: 'sv-block', 'aria-labelledby': id },
    el('div', { class: 'sv-head' }, el('h2', { id }, `${title} · ${count}`)),
    el('div', { class: 'sv-scroll', tabindex: 0, role: 'region', 'aria-label': `${title}, table` },
      el('table', { class: 't sv-table' }, head(tips), tbody)),
    ...after);
}

function needsBlock(list) {
  const rank = (s) => (WORST_FIRST.includes(s.state) ? WORST_FIRST.indexOf(s.state) : WORST_FIRST.length);
  const sorted = [...list].sort((a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name));
  return block('Needs a look', sorted.length, el('tbody', {}, ...sorted.map((s) => el('tr', {},
    el('th', { scope: 'row' }, s.name), stateCell(serverBadge(s.state, { plain: true }), detail(s)),
    numberCell(s.tools_cached), numberCell(s.calls_24h), p95Cell(s.latency_p95_ms)))));
}

function groupsOf(list, categories) {
  const byLabel = new Map();
  for (const s of list) {
    const cat = categories?.get(s.name);
    const label = typeof cat === 'string' && Object.hasOwn(GROUP_LABELS, cat) ? GROUP_LABELS[cat] : OTHER;
    if (!byLabel.has(label)) byLabel.set(label, []);
    byLabel.get(label).push(s);
  }
  return [...byLabel].sort(([a], [b]) => (a === OTHER) - (b === OTHER) || a.localeCompare(b))
    .map(([label, members]) => ({ label, members: members.sort((a, b) => a.name.localeCompare(b.name)) }));
}

function groupSummary(members) {
  const count = (state) => members.filter((s) => s.state === state).length;
  const slow = count('slow');
  const idle = count('dormant');
  let words = `${count('running') + slow} answering`;
  if (slow) words += ` · ${slow} slow`;
  if (idle) words += ` · ${idle} idle`;
  // A total with an unknown part is not known: a smaller number would read as exact.
  const sum = (key) => (members.every((s) => known(s[key])) ? members.reduce((n, s) => n + s[key], 0) : null);
  const p95s = members.map((s) => s.latency_p95_ms).filter(known);
  const top = p95s.length ? Math.max(...p95s) : null;
  return [
    el('td', {}, words),
    numberCell(sum('tools_cached')),
    numberCell(sum('calls_24h')),
    top === null ? notKnown() : el('td', { class: 'n', 'aria-label': `Highest p95 among its servers: ${ms(top)}` }, ms(top)),
  ];
}

function answeringBlock(list, categories, view) {
  const tbody = el('tbody', {});
  for (const { label, members } of groupsOf(list, categories)) {
    const key = slug(label);
    const button = el('button', { type: 'button', class: 'sv-group', 'aria-expanded': 'false', 'data-group': key }, label);
    button.addEventListener('click', () => {
      view.open = view.open === key ? null : key;
      const url = new URL(location.href);
      if (view.open) url.searchParams.set('open', view.open);
      else url.searchParams.delete('open');
      history.replaceState(history.state, '', url);
      showOpen(tbody, view.open);
    });
    const row = el('tr', { class: 'sv-group-row' }, el('th', { scope: 'row' }, button), ...groupSummary(members));
    // The whole row toggles; the button stays its one keyboard stop.
    row.addEventListener('click', (event) => { if (!button.contains(event.target)) button.click(); });
    tbody.append(row);
    for (const s of members) {
      const words = s.state === 'slow' && typeof s.reason === 'string' ? s.reason : '';
      tbody.append(el('tr', { class: 'sv-member', 'data-member-of': key },
        el('th', { scope: 'row' }, s.name), stateCell(memberBadge(s.state), words),
        numberCell(s.tools_cached), numberCell(s.calls_24h), p95Cell(s.latency_p95_ms)));
    }
  }
  showOpen(tbody, view.open);
  // The p95 explanation sits on the column note: in the header row its popup would cover the Tools (i).
  const note = withTip(el('p', { class: 't3 sv-note' }, "A group's p95 is the highest of its servers' p95s, not one pooled across them."),
    (tip) => tip('servers.status.p95-last-1-000-calls'));
  const section = block('Answering', list.length, tbody, { tips: true, after: [note] });
  // The frame's heading reads "Answering · N, grouped by the gateway"; its (i) follows the phrase.
  const phrase = el('span', { class: 't3' }, 'grouped by the gateway');
  section.querySelector('.sv-head').append(phrase);
  withTip(phrase, (tip) => tip('servers.status.answering-24-grouped-by-the'));
  return section;
}

/** Open the group `key` (or none) and shut every other one, in place. */
function showOpen(tbody, key) {
  for (const b of tbody.querySelectorAll('button[data-group]')) b.setAttribute('aria-expanded', String(b.dataset.group === key));
  for (const r of tbody.querySelectorAll('tr[data-member-of]')) r.hidden = r.dataset.memberOf !== key;
}

/** Servers turned off in the config: the same five columns, by name; none of them answers or needs a look. */
function offBlock(list) {
  const sorted = [...list].sort((a, b) => a.name.localeCompare(b.name));
  return block(OFF_BLOCK_TITLE, sorted.length, el('tbody', {}, ...sorted.map((s) => el('tr', {},
    el('th', { scope: 'row' }, s.name), el('td', {}, serverBadge('off', { plain: true })),
    numberCell(s.tools_cached), numberCell(s.calls_24h), p95Cell(s.latency_p95_ms)))));
}

/** Rule D: unmanaged finds no status row names, or the quiet line when discovery failed. */
function outsideBlock(discovery, statusNames) {
  if (!discovery.ok) return el('p', { class: 't3 sv-quiet' }, QUIET_LINE);
  const finds = discovery.servers.filter((f) => f && f.managed === false && typeof f.name === 'string' && !statusNames.has(f.name));
  if (!finds.length) return null;
  return block('Not behind the gateway', finds.length, el('tbody', {}, ...finds.map((f) => {
    const who = el('th', { scope: 'row' }, f.name);
    if (typeof f.source === 'string' && f.source) who.append(' ', el('span', { class: 't3' }, f.source));
    return el('tr', {}, who, el('td', {}, serverBadge('unmanaged', { plain: true })), notKnown(), notKnown(), notKnown());
  })));
}

/** A selector for the screen's focused control that still finds it after a redraw, or null. */
function focusKey(root) {
  const at = document.activeElement;
  if (!at || !root.contains(at)) return null;
  if (at.dataset.group) return `button[data-group="${CSS.escape(at.dataset.group)}"]`;
  const holder = at.closest('.has-tip[data-tip]');
  if (holder) return `.has-tip[data-tip="${CSS.escape(holder.dataset.tip)}"] button`;
  if (at.matches('.sv-scroll')) return `.sv-scroll[aria-label="${CSS.escape(at.getAttribute('aria-label'))}"]`;
  return null;
}

async function readOr(ctx, path) {
  try {
    return { ok: true, body: await ctx.api(path, { signal: AbortSignal.timeout(EXTRA_MS) }) };
  } catch {
    return { ok: false, body: null };
  }
}

function statusTab(body, ctx) {
  // The root joins the body at the first draw: an empty body lets the shell show its
  // loading state meanwhile. Whether the screen is still up is the body's to say.
  const root = el('div', { class: 'sv' });
  const up = () => body.isConnected;
  // Per render: the registry's categories and the discovery answer, each read once.
  const view = { open: new URL(location.href).searchParams.get('open'), extras: null };
  let reading = false;
  let again = false;

  const retry = () => {
    const button = el('button', { type: 'button', class: 'btn' }, 'Retry');
    button.addEventListener('click', () => { refresh().catch(() => {}); });
    return button;
  };
  const alone = (kind) => {
    root.replaceChildren();
    ctx.show(kind, kind === 'error' ? { body: 'The gateway did not answer with its servers.', action: retry() } : {});
  };

  async function paint() {
    let answer;
    try {
      answer = await ctx.api('/ui/api/status');
    } catch (err) {
      if (err?.status === 401) throw err; // the shell is showing sign-in
      return alone('error');
    }
    if (!up()) return;
    if (!Array.isArray(answer?.servers)) return alone('forbidden');
    if (!view.extras) {
      view.extras = Promise.all([readOr(ctx, '/ui/api/registry'), readOr(ctx, '/ui/api/discovery')]).then(([registry, found]) => ({
        categories: registry.ok && Array.isArray(registry.body?.entries)
          ? new Map(registry.body.entries.filter((e) => e && typeof e.name === 'string').map((e) => [e.name, e.category]))
          : null,
        discovery: found.ok && Array.isArray(found.body?.servers) ? { ok: true, servers: found.body.servers } : { ok: false },
      }));
    }
    const { categories, discovery } = await view.extras;
    if (!up()) return;
    const servers = answer.servers.filter((s) => s && typeof s.name === 'string');
    const focused = focusKey(root);
    ctx.show(null);
    const parts = [];
    if (!servers.length) {
      const add = el('a', { class: 'btn', href: '/ui/classic' }, 'Add a server');
      parts.push(ctx.state('empty', { title: 'No servers behind the gateway yet', body: 'Add one and it shows here with its state.', action: add }));
    }
    // Turned-off servers sit apart: never counted as answering, never a thing to look at.
    const off = servers.filter((s) => s.state === 'off');
    const live = servers.filter((s) => s.state !== 'off');
    const needs = live.filter((s) => !answers(s));
    if (needs.length) parts.push(needsBlock(needs));
    const fine = live.filter(answers);
    if (fine.length) parts.push(answeringBlock(fine, categories, view));
    if (off.length) parts.push(offBlock(off));
    const outside = outsideBlock(discovery, new Set(servers.map((s) => s.name)));
    if (outside) parts.push(outside);
    if (root.parentNode !== body) body.append(root);
    root.replaceChildren(...parts);
    if (focused) {
      // Focus lost with the old nodes comes back; a focus the user has since moved stays.
      const restore = () => {
        const at = document.activeElement;
        if (up() && (!at || at === document.body)) root.querySelector(focused)?.focus();
      };
      restore();
      // Tip triggers join their headings once the tooltip module answers. That is not waited
      // on here, so a module that never loads holds up no refresh.
      // Only a trigger not drawn yet waits; a group or table took its focus above.
      if (!root.querySelector(focused)) tipModule?.then(restore, () => {});
    }
  }

  async function refresh() {
    if (reading) {
      again = true;
      return;
    }
    reading = true;
    try {
      do {
        again = false;
        await paint();
      } while (again && up());
    } finally {
      reading = false;
    }
  }

  const onStatus = () => {
    if (!up()) {
      removeEventListener('gateway-status', onStatus);
      return;
    }
    refresh().catch(() => {});
  };
  dropListener?.();
  addEventListener('gateway-status', onStatus);
  dropListener = () => removeEventListener('gateway-status', onStatus);
  return refresh();
}

register('servers', {
  title: 'Servers',
  tabs: { status: statusTab, actions: null, settings: null },
  entries: [],
});
