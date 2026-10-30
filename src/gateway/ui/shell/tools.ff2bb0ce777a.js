// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The Tools screen, first slice: Tools › Status lists every tool the gateway
// offers, A to Z, filters it by text and server, opens a row to its input
// schema, and links each tool to its own page. It reads GET /ui/api/tools
// once per render. Every server-supplied string goes in with textContent.
// The shell is imported by its exact hashed name, so this page registers in
// the same module instance the document loaded.
import { register } from '/ui/assets/shell.ae2d6f9af7ac.js';

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

async function statusTab(body, ctx) {
  const { list, servers } = await readTools(ctx.api);
  ctx.header({ subtitle: `${plural(list.length, 'tool', 'tools')} from ${plural(servers.length, 'server', 'servers')}. Agents find them through search and invoke.` });
  if (list.length === 0) {
    body.append(ctx.state('empty', { title: 'No tools yet', body: 'No tools yet. Add a server and its tools appear here.' }));
    return;
  }

  const search = h('input', { class: 'input', type: 'search', id: 'tools-search', 'aria-label': 'Search tools', autocomplete: 'off', spellcheck: 'false', placeholder: `Search ${plural(list.length, 'tool', 'tools')} by name or what they do` });
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
  // Frame 48s: how agents reach this catalogue, beside the search (copy D11).
  const load = h('p', { class: 't3 tools-load' }, 'Agents load 11 tools and reach the rest through search and invoke ');
  // The tooltip module loads after the catalogue is drawn and never holds it up: a static
  // import would put its bytes before every page's first paint, and if it fails to load
  // the sentence simply stands without its (i).
  import('/ui/assets/tooltip.deb27f374db3.js').then(({ tip }) => load.append(tip('tools.status.load-11-tools-and-reach')), () => {});
  body.append(h('div', { class: 'tools-bar' }, search, pick, load), card);
  search.value = filters.query;
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

async function toolPage(body, ctx) {
  const { list } = await readTools(ctx.api);
  const t = list.find((x) => objectOf(x) === ctx.object);
  if (!t) {
    ctx.header({ title: 'No such tool', subtitle: null });
    body.append(ctx.state('empty', { title: 'No such tool', body: 'The gateway offers no tool by that name.' }),
      h('p', {}, h('a', { class: 'lnk', href: '/ui/tools/status' }, 'Back to all tools')));
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
  h('p', {}, h('a', { class: 'lnk', href: '/ui/tools/status' }, 'Back to all tools')));
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
  entries: [{ label: 'All tools', path: '/ui/tools/status', kind: 'go' }],
});
