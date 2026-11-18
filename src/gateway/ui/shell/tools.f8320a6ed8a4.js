// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The Tools screen: Tools › Status opens on the tools called in the last
// hour, and ?view=all lists every tool A to Z, filters it by text and
// server, opens a row to its input schema, and links each tool to its own
// page. It reads GET /ui/api/tools once per render. Every server-supplied
// string goes in with textContent. The shell is imported by its exact hashed
// name, so this page registers in the same module instance the document loaded.
import { go, register } from '/ui/assets/shell.2f0fa8846ded.js';

/** One element: attributes set through setAttribute, children appended as nodes or text. */
function h(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v !== null && v !== undefined && v !== false) node.setAttribute(k, v === true ? '' : String(v));
  }
  node.append(...children);
  return node;
}

const BYNAME = (a, b) => a.name.localeCompare(b.name) || a.server.localeCompare(b.server);

/** The object segment of a tool's own page: its server and name. */
const objectOf = (t) => `${t.server}:${t.name}`;
const toolPath = (t) => `/ui/tools/${encodeURIComponent(objectOf(t))}/status`;

/** The catalogue. The most-called panel is this route with no view. */
const CATALOGUE_PATH = '/ui/tools/status?view=all';
const showingAll = () => new URLSearchParams(location.search).get('view') === 'all';

/**
 * A link to the catalogue that the router follows in place. The shell leaves a link
 * with a query to the browser, and a full reload would lose a key held only in
 * memory; a modified click (new tab or window) keeps the browser's own behaviour.
 * `narrowing` is 'keep' (return to the catalogue as it was left) or 'clear' (a link
 * that promises every tool must not open a subset).
 */
function catalogueLink(text, narrowing) {
  const a = h('a', { class: 'lnk', href: CATALOGUE_PATH }, text);
  a.addEventListener('click', (ev) => {
    if (ev.defaultPrevented || ev.button !== 0 || ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey) return;
    ev.preventDefault();
    if (narrowing === 'clear') {
      filters.query = '';
      filters.server = '';
    }
    go(CATALOGUE_PATH);
    // The shell's own link handler skips a cancelled click, so hand focus to the
    // new content here, as it does for every other in-app link.
    document.getElementById('content').focus({ preventScroll: true });
  });
  return a;
}

/** Read every tool, sorted A to Z, with the server list beside it. */
async function readTools(api) {
  const { tools } = await api('/ui/api/tools');
  const list = (Array.isArray(tools) ? tools : [])
    .filter((t) => t && typeof t.name === 'string' && typeof t.server === 'string')
    .sort(BYNAME);
  const servers = [...new Set(list.map((t) => t.server))].sort((a, b) => a.localeCompare(b));
  return { list, servers };
}

const plural = (n, one, many) => `${n.toLocaleString('en')} ${n === 1 ? one : many}`;

/** The class and where it came from: "read (declared)", "write (guessed from the name)", … */
function classWord(t) {
  const cls = t.class === 'read' ? 'read' : 'write';
  return `${cls} (${t.class_source === 'declared' ? 'declared' : 'guessed from the name'})`;
}

/**
 * JSON on one line with a space after each `:` and `,`, as frame 48q draws a
 * schema. Formatting newlines are the only raw newlines JSON writes (a string
 * escapes its own), so collapsing them never touches a value.
 */
function oneLine(value) {
  return JSON.stringify(value, null, 1)
    .replace(/([[{])\n\s*/g, '$1').replace(/\n\s*([\]}])/g, '$1').replace(/\n\s*/g, ' ');
}

/** The schema in a focusable named region a keyboard can scroll: one line in the list, indented on the tool's page. */
function schemaBlock(t, { compact = false } = {}) {
  const text = t.schema === undefined || t.schema === null ? 'No input schema.'
    : compact ? oneLine(t.schema) : JSON.stringify(t.schema, null, 2);
  return h('pre', { class: 'mono tool-schema', tabindex: 0, role: 'region', 'aria-label': `Input schema of ${t.name}` }, text);
}

/** The rows a search and a server choice leave. */
function matching(list, query, server) {
  const q = query.trim().toLowerCase();
  return list.filter((t) => (!server || t.server === server)
    && (!q || t.name.toLowerCase().includes(q) || (t.description ?? '').toLowerCase().includes(q)));
}

// The search and the server choice survive a visit to a tool's page and
// back, as the classic tab's did (it never unmounted).
const filters = { query: '', server: '' };

/**
 * The first keystroke on Status opens the catalogue and pushes one history
 * entry, so Back from a tool page returns to the search and Back again to
 * Status. go() is that push (shell.js go). Later keystrokes happen on the
 * catalogue, which does not push. Deferred so the keystroke finishes on the
 * input it started on; one queue, so a second event in the same turn adds none.
 */
let catalogueQueued = false;
// Set when the catalogue is opened from the Status search: the catalogue then
// takes the focus, so the keys typed after the first land in its search box.
let focusCatalogueSearch = false;
// The tools the panel just read, handed to the catalogue it opens: drawn at once, with
// no second read for typed keys to fall into.
let carried = null;
function queueCatalogue(from, read) {
  if (catalogueQueued || showingAll()) return;
  catalogueQueued = true;
  setTimeout(() => {
    catalogueQueued = false;
    // Only while the user is still on this panel: a navigation that won the
    // race must not be overridden by a jump to the catalogue.
    if (showingAll() || !from.isConnected || location.pathname !== '/ui/tools/status') return;
    focusCatalogueSearch = true;
    carried = read;
    go(CATALOGUE_PATH);
  }, 0);
}

/** Frame 48s: how agents reach this catalogue, beside the search (copy D11). */
function loadNote() {
  const load = h('p', { class: 't3 tools-load' }, 'Agents load 11 tools and reach the rest through search and invoke ');
  // The tooltip module loads after the catalogue is drawn and never holds it up: a static
  // import would put its bytes before every page's first paint, and if it fails to load
  // the sentence simply stands without its (i).
  import('/ui/assets/tooltip.c4528509befc.js').then(({ tip }) => load.append(tip('tools.status.load-11-tools-and-reach')), () => {});
  return load;
}

function searchBox(list) {
  return h('input', {
    class: 'input', type: 'search', id: 'tools-search', 'aria-label': 'Search tools', autocomplete: 'off', spellcheck: 'false',
    placeholder: `Search ${plural(list.length, 'tool', 'tools')} by name or what they do`,
  });
}

/** Called in the last hour, highest first, ties by name then server, ten at most. */
function topCalled(list) {
  return list.filter((t) => t.calls_1h > 0).sort((a, b) => b.calls_1h - a.calls_1h || BYNAME(a, b)).slice(0, 10);
}

/** p == 0 is "new", before the ratio; a ratio that rounds to 0 is no change. */
function changeWord(hour, prev) {
  // null is the API's "not measured": no comparison, and never a number.
  if (typeof prev !== 'number') return 'no count for the hour before';
  if (prev === 0) return 'new this hour';
  const d = Math.round(Math.abs(hour - prev) / prev * 100);
  if (d === 0) return '→ no change';
  return `${hour > prev ? '↗' : '↘'} ${d}% vs hour before`;
}

function mostCalled(body, read) {
  const { list } = read;
  // Starts empty: a query left from an earlier catalogue visit would claim a
  // filter this panel does not apply.
  const search = searchBox(list);
  // Typing, or Enter in an empty box, leaves this panel for the catalogue.
  search.addEventListener('input', (ev) => {
    // An input method's text is not typed until it is committed: neither the
    // query nor the jump sees it before then.
    if (ev.isComposing) return;
    filters.query = search.value;
    queueCatalogue(search, read);
  });
  search.addEventListener('keydown', (ev) => {
    if (ev.isComposing || ev.key !== 'Enter' || search.value !== '') return;
    ev.preventDefault();
    // Enter in an empty box promises every tool: no narrowing from an earlier
    // catalogue visit survives, as the See all link's 'clear' does.
    filters.query = '';
    filters.server = '';
    queueCatalogue(search, read);
  });
  const rows = topCalled(list);
  const titleId = 'tools-called-title';
  const section = h('section', { class: 'tk tools-card', 'aria-labelledby': titleId },
    h('div', { class: 'tools-card-head' }, h('h2', { class: 'kicker', id: titleId }, 'Most called, last hour'),
      // The whole catalogue is one click away, with or without calls this hour.
      catalogueLink(`See all ${plural(list.length, 'tool', 'tools')}`, 'clear')));
  if (rows.length === 0) {
    // null is the API's "not measured": with no measured call this hour and a
    // count missing, "no calls" would be a claim the gateway cannot make.
    const unmeasured = list.some((t) => typeof t.calls_1h !== 'number');
    section.append(h('div', { class: 'tools-called-empty' },
      h('p', { class: 'muted' }, unmeasured ? 'No count for the last hour yet.' : 'No tool calls in the last hour.')));
  } else {
    // Scrolls in its own region on a narrow screen, reachable from the keyboard.
    section.append(h('div', { class: 'tools-scroll', tabindex: 0, role: 'region', 'aria-label': 'Most called tools' }, h('table', { class: 't tools-called' },
      h('thead', {}, h('tr', {},
        h('th', { scope: 'col' }, 'Tool'), h('th', { scope: 'col' }, 'Server'),
        h('th', { scope: 'col' }, 'Calls, last hour'), h('th', { scope: 'col' }, 'Change'))),
      h('tbody', {}, ...rows.map((t) => h('tr', {},
        h('td', {}, h('a', { href: toolPath(t) }, t.name)),
        h('td', { class: 't2' }, t.server),
        h('td', {}, t.calls_1h.toLocaleString('en')),
        h('td', {}, changeWord(t.calls_1h, t.calls_prev_1h))))))));
  }
  section.append(h('i', { class: 'c1', 'aria-hidden': 'true' }), h('i', { class: 'c2', 'aria-hidden': 'true' }));
  body.append(h('div', { class: 'tools-bar' }, search, loadNote()), section);
}

function catalogue(body, list, servers) {
  const search = searchBox(list);
  const pick = h('select', { class: 'input', id: 'tools-server', 'aria-label': 'Server' }, h('option', { value: '' }, 'All servers'), ...servers.map((s) => h('option', { value: s }, s)));
  const meta = h('span', { class: 't3 tools-meta' });
  const tbody = h('tbody');
  const table = h('table', { class: 't tools-table' },
    h('thead', {}, h('tr', {}, h('th', { scope: 'col' }, 'Tool'), h('th', { scope: 'col' }, 'Server'), h('th', { scope: 'col' }, 'Description'))),
    tbody);
  const none = h('div', { class: 'tools-none', hidden: true }, h('p', { class: 'muted' }, 'No tool matches'),
    h('button', { class: 'btn', type: 'button' }, 'Clear filters'));
  const card = h('section', { class: 'tk tools-card', 'aria-labelledby': 'tools-card-title' },
    h('div', { class: 'tools-card-head' }, h('h2', { class: 'kicker', id: 'tools-card-title' }, 'All tools'), meta),
    h('div', { class: 'tools-scroll', tabindex: 0, role: 'region', 'aria-label': 'Tool list' }, table),
    none, h('i', { class: 'c1', 'aria-hidden': 'true' }), h('i', { class: 'c2', 'aria-hidden': 'true' }));
  body.append(h('div', { class: 'tools-bar' }, search, pick, loadNote()), card);
  search.value = filters.query;
  if (focusCatalogueSearch) {
    focusCatalogueSearch = false;
    search.focus();
    search.setSelectionRange(search.value.length, search.value.length);
  }
  pick.value = servers.includes(filters.server) ? filters.server : '';

  const draw = () => {
    filters.query = search.value;
    filters.server = pick.value;
    const shown = matching(list, search.value, pick.value);
    meta.textContent = shown.length === list.length
      ? `${list.length.toLocaleString('en')} · A to Z · name, server, description`
      : `${shown.length.toLocaleString('en')} of ${list.length.toLocaleString('en')} match`;
    table.hidden = shown.length === 0;
    none.hidden = shown.length !== 0;
    tbody.replaceChildren(...shown.flatMap((t, i) => {
      const id = `tool-detail-${i}`;
      const mark = h('span', { class: 'mark', 'aria-hidden': 'true' }, '▸ ');
      const toggle = h('button', { class: 'tool-toggle mono', type: 'button', 'aria-expanded': 'false', 'aria-controls': id }, mark, t.name);
      const row = h('tr', { class: 'tool' }, h('td', {}, toggle), h('td', { class: 't2' }, t.server), h('td', { class: 'muted' }, t.description ?? ''));
      // As frame 48q: the open row is the schema, with the tool's class; the row
      // above already shows the description. Built on first open, so a filter
      // never serialises schemas nobody looks at.
      const cell = h('td', { colspan: 3 });
      const detail = h('tr', { class: 'tool-detail', id, hidden: true }, cell);
      toggle.addEventListener('click', () => {
        if (!cell.childElementCount) {
          cell.append(
            h('p', { class: 'mono tool-schema-label' }, `Input schema · ${classWord(t)}`),
            schemaBlock(t, { compact: true }),
            h('p', {}, h('a', { class: 'lnk', href: toolPath(t), 'aria-label': `Open ${t.name}` }, 'Open')));
        }
        const open = toggle.getAttribute('aria-expanded') !== 'true';
        toggle.setAttribute('aria-expanded', String(open));
        mark.textContent = open ? '▾ ' : '▸ ';
        detail.hidden = !open;
      });
      return [row, detail];
    }));
  };
  search.addEventListener('input', draw);
  pick.addEventListener('change', draw);
  none.querySelector('button').addEventListener('click', () => {
    search.value = '';
    pick.value = '';
    draw();
    search.focus();
  });
  draw();
}

async function statusTab(body, ctx) {
  const read = showingAll() && carried ? carried : await readTools(ctx.api);
  carried = null;
  const { list, servers } = read;
  ctx.header({ subtitle: `${plural(list.length, 'tool', 'tools')} from ${plural(servers.length, 'server', 'servers')}. Agents find them through search and invoke.` });
  if (list.length === 0) {
    body.append(ctx.state('empty', { title: 'No tools yet', body: 'No tools yet. Add a server and its tools appear here.' }));
    return;
  }
  if (showingAll()) catalogue(body, list, servers);
  else mostCalled(body, read);
}

async function toolPage(body, ctx) {
  const { list } = await readTools(ctx.api);
  const t = list.find((x) => objectOf(x) === ctx.object);
  if (!t) {
    ctx.header({ title: 'No such tool', subtitle: null });
    body.append(ctx.state('empty', { title: 'No such tool', body: 'The gateway offers no tool by that name.' }),
      h('p', {}, catalogueLink('Back to all tools', 'keep')));
    return;
  }
  // The plate names the tool; it draws in capitals, and a tool's name is
  // case-sensitive, so the page's own heading shows the name as written.
  ctx.header({ title: t.name, subtitle: null });
  body.append(h('section', { class: 'tk tool-page', 'aria-labelledby': 'tool-page-title' },
    h('h2', { class: 'mono tool-page-name', id: 'tool-page-title' }, t.name),
    h('dl', { class: 'tool-facts' },
      h('dt', { class: 'kicker' }, 'Server'), h('dd', {}, t.server),
      h('dt', { class: 'kicker' }, 'Class'), h('dd', {}, classWord(t)),
      h('dt', { class: 'kicker' }, 'Description'), h('dd', {}, t.description ?? 'No description.')),
    h('p', { class: 'kicker' }, 'Input schema'),
    schemaBlock(t),
    h('i', { class: 'c1', 'aria-hidden': 'true' }), h('i', { class: 'c2', 'aria-hidden': 'true' })),
  h('p', {}, catalogueLink('Back to all tools', 'keep')));
}

register('tools', {
  title: 'Tools',
  tabs: {
    // One renderer, two routes: no object is the list, an object is a tool.
    status: (body, ctx) => (ctx.object ? toolPage(body, ctx) : statusTab(body, ctx)),
    // Try a tool comes with its API; scopes live in Access, so no Settings.
    actions: null,
    settings: null,
  },
  entries: [{ label: 'All tools', path: CATALOGUE_PATH, kind: 'go' }],
});
