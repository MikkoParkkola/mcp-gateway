// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The Tools screen: Tools › Status opens on the tools called in the last
// hour, and ?view=all lists every tool A to Z, filters it by text and
// server, opens a row to its input schema, and links each tool to its own
// page. It reads GET /ui/api/tools once per render. Every server-supplied
// string goes in with textContent. The shell is imported by its exact hashed
// name, so this page registers in the same module instance the document loaded.
import { go, register, ApiError } from '/ui/assets/shell.b052b8d989a6.js';

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
    && (!q || t.name.toLowerCase().includes(q) || t.server.toLowerCase().includes(q)
      || (t.description ?? '').toLowerCase().includes(q)));
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
  import('/ui/assets/tooltip.74a1006768d8.js').then(({ tip }) => load.append(tip('tools.status.load-11-tools-and-reach')), () => {});
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

/** The catalogue sorts A to Z; Try a tool keeps the API's own order. */
async function readToolsListed(api) {
  const { tools } = await api('/ui/api/tools');
  return (Array.isArray(tools) ? tools : [])
    .filter((t) => t && typeof t.name === 'string' && typeof t.server === 'string');
}

const wait = (ms) => new Promise((ok) => setTimeout(ok, ms));

function asText(v) {
  return v == null ? '' : String(v);
}

function jsonText(v) {
  try { return JSON.stringify(v); } catch { return asText(v); }
}

function toolOptionLabel(t) {
  return `${t.name} ${t.server} · ${t.class === 'read' ? 'reads only' : 'writes'}`;
}

function rootMode(schema) {
  if (schema == null) return 'none';
  if (typeof schema !== 'object' || Array.isArray(schema)) return 'json';
  if (Object.keys(schema).length === 0) return 'none';
  if (schema.type === 'object' && schema.properties && typeof schema.properties === 'object'
      && !Array.isArray(schema.properties) && !schema.$ref && !schema.oneOf && !schema.anyOf
      && !schema.allOf) {
    return 'fields';
  }
  return 'json';
}

function fieldKind(prop, required) {
  if (!prop || typeof prop !== 'object') return 'json';
  if (prop.$ref || prop.oneOf || prop.anyOf || prop.allOf) return 'json';
  const t = prop.type;
  if (t === 'object' || t === 'array' || Array.isArray(t)) return 'json';
  if (Array.isArray(prop.enum)) return 'enum';
  if (t === 'string') return 'string';
  if (t === 'integer' || t === 'number') return 'number';
  if (t === 'boolean') return required ? 'checkbox' : 'bool-select';
  return 'json';
}

function defaultBits(prop) {
  if (!prop || !Object.prototype.hasOwnProperty.call(prop, 'default')) return { extra: [] };
  const d = prop.default;
  const placeholder = typeof d === 'string' || typeof d === 'number' || typeof d === 'boolean'
    ? String(d) : jsonText(d);
  return { extra: [h('span', { class: 'muted' }, 'default')], placeholder };
}

/** A boolean or enum default is text beside the control; a select has no placeholder. */
function defaultShown(prop) {
  if (!prop || !Object.prototype.hasOwnProperty.call(prop, 'default')) return [];
  const d = prop.default;
  const shown = typeof d === 'string' || typeof d === 'number' || typeof d === 'boolean'
    ? String(d) : jsonText(d);
  return [h('span', { class: 'muted' }, shown)];
}

function wrapField(id, name, control, extra = []) {
  return h('div', { class: 'field' }, h('label', { for: id }, name), control, ...extra);
}

function markField(field, invalid) {
  field.el.removeAttribute('aria-invalid');
  field.wrap.classList.remove('err');
  field.wrap.querySelector('.msg')?.remove();
  if (!invalid) return;
  field.el.setAttribute('aria-invalid', 'true');
  field.wrap.classList.add('err');
  field.wrap.append(h('span', { class: 'msg' }, `${field.name} needs a value`));
}

function jsonControl(name, required, { root = false, i, prop } = {}) {
  const id = `try-f-${i ?? 'args'}`;
  const { extra, placeholder } = defaultBits(prop ?? {});
  const el = h('textarea', {
    class: 'input', id, rows: 3, spellcheck: 'false', autocomplete: 'off',
    ...(placeholder ? { placeholder } : {}),
    ...(required && !root ? { required: true, 'aria-required': 'true' } : {}),
  });
  return {
    wrap: wrapField(id, name, el, extra), el, name, root,
    read() {
      if (el.value.trim() === '') {
        if (root) return { present: true, value: {} };
        if (required) return { invalid: true };
        return { present: false };
      }
      let value;
      try { value = JSON.parse(el.value); } catch { return { invalid: true }; }
      // The whole arguments value has to be one JSON object. An array, a string or a number is not.
      if (root && (value === null || typeof value !== 'object' || Array.isArray(value))) return { invalid: true };
      return { present: true, value };
    },
  };
}

function enumOptions(prop, optional) {
  const opts = optional ? [h('option', { value: '' }, 'default')] : [];
  for (const v of prop.enum) opts.push(h('option', { value: JSON.stringify(v) }, String(v)));
  return opts;
}

function makeField(name, prop, required, i) {
  const kind = fieldKind(prop, required);
  if (kind === 'json') return jsonControl(name, required, { i, prop });
  const id = `try-f-${i}`;
  const { extra, placeholder } = defaultBits(prop);
  if (kind === 'string') {
    const el = h('input', {
      class: 'input', type: 'text', id, autocomplete: 'off', spellcheck: 'false',
      ...(placeholder ? { placeholder } : {}),
      ...(required ? { required: true, 'aria-required': 'true' } : {}),
    });
    return {
      wrap: wrapField(id, name, el, extra), el, name,
      read() {
        if (el.value === '') return required ? { present: true, value: '' } : { present: false };
        return { present: true, value: el.value };
      },
    };
  }
  if (kind === 'number') {
    const el = h('input', {
      class: 'input', type: 'number', id, autocomplete: 'off',
      step: prop.type === 'integer' ? '1' : 'any',
      ...(placeholder ? { placeholder } : {}),
      ...(required ? { required: true, 'aria-required': 'true' } : {}),
    });
    return {
      wrap: wrapField(id, name, el, extra), el, name,
      read() {
        if (el.value === '') return required ? { invalid: true } : { present: false };
        const n = Number(el.value);
        return Number.isNaN(n) ? { invalid: true } : { present: true, value: n };
      },
    };
  }
  if (kind === 'checkbox') {
    const el = h('input', { type: 'checkbox', id, 'aria-required': 'true' });
    // A required boolean starts at its default, shown beside it like the others.
    if (prop && prop.default === true) el.checked = true;
    return {
      wrap: wrapField(id, name, el, defaultShown(prop)), el, name,
      read() { return { present: true, value: el.checked }; },
    };
  }
  if (kind === 'bool-select') {
    const el = h('select', { class: 'input', id },
      h('option', { value: '' }, 'default'),
      h('option', { value: 'true' }, 'true'),
      h('option', { value: 'false' }, 'false'));
    return {
      wrap: wrapField(id, name, el, defaultShown(prop)), el, name,
      read() {
        if (el.value === '') return { present: false };
        return { present: true, value: el.value === 'true' };
      },
    };
  }
  const optional = !required;
  const el = h('select', {
    class: 'input', id,
    ...(required ? { required: true, 'aria-required': 'true' } : {}),
  }, ...enumOptions(prop, optional));
  return {
    wrap: wrapField(id, name, el, defaultShown(prop)), el, name,
    read() {
      if (optional && el.value === '') return { present: false };
      try { return { present: true, value: JSON.parse(el.value) }; } catch { return { invalid: true }; }
    },
  };
}

function fieldsFor(schema) {
  const mode = rootMode(schema);
  if (mode === 'none') return [];
  if (mode === 'json') return [jsonControl('arguments', false, { root: true })];
  const req = new Set(Array.isArray(schema.required) ? schema.required : []);
  return Object.entries(schema.properties).map(([name, prop], i) =>
    makeField(name, prop && typeof prop === 'object' && !Array.isArray(prop) ? prop : {}, req.has(name), i));
}

function collectArgs(fields) {
  if (fields.length === 1 && fields[0].root) {
    const r = fields[0].read();
    markField(fields[0], r.invalid);
    if (r.invalid) return null;
    return r.value;
  }
  // A normal object drops a key named __proto__. The arguments map has to keep it.
  const args = Object.create(null);
  let ok = true;
  for (const f of fields) {
    const r = f.read();
    markField(f, r.invalid);
    if (r.invalid) ok = false;
    else if (r.present) args[f.name] = r.value;
  }
  return ok ? args : null;
}

function contentOf(body) {
  const c = body?.result?.content;
  return Array.isArray(c) ? c : null;
}

function resultText(result) {
  const content = result?.content;
  if (!Array.isArray(content)) return result == null ? '' : jsonText(result);
  const parts = [];
  for (const item of content) {
    if (item && item.type === 'text' && item.text != null) parts.push(String(item.text));
    else if (item != null) parts.push(jsonText(item));
  }
  const text = parts.join('\n');
  if (text) return text;
  if (result.structuredContent != null) return oneLine(result.structuredContent);
  return '';
}

function countsText(content, answer) {
  const n = Array.isArray(content) ? content.length : null;
  const line = typeof answer?.line === 'string' ? answer.line : '';
  const listed = answer?.records?.[0]?.findings_listed;
  let right = null;
  if (/not scanned|not recorded/i.test(line)) {
    const m = line.match(/the answer was not (?:scanned|recorded)/i);
    right = m ? m[0] : line;
  } else if (typeof listed === 'number') {
    right = `${listed} caught`;
  }
  if (n == null) return right;
  if (!right) return `${n} results`;
  return `${n} results · ${right}`;
}

function outcomeNodes({ status, unreadable, body, message }) {
  const nodes = [];
  const disp = body && typeof body.disposition === 'string' ? body.disposition : null;
  if (unreadable || status === 0) {
    nodes.push(h('p', {}, 'No answer from the gateway; the tool may have run'));
    return nodes;
  }
  if (disp === 'ran' || (status >= 200 && status < 300 && body?.result)) {
    const latency = body?.latency_ms;
    if (body?.is_error) {
      nodes.push(h('p', {}, 'The tool answered with an error'));
      if (latency != null) nodes.push(h('p', {}, `${latency} ms`));
    } else {
      nodes.push(h('p', {}, `Answered in ${latency} ms`));
    }
    const text = resultText(body?.result);
    if (text) nodes.push(h('pre', { class: 'mono' }, text));
    return nodes;
  }
  if (status === 504 && disp === 'may_have_run') {
    nodes.push(h('p', {}, 'Timed out; the tool may still be running'));
    if (message) nodes.push(h('p', {}, message));
    return nodes;
  }
  // A 5xx with no disposition (the admin layer's own refusal) may have run. An explicit not_run did not.
  if (disp === 'may_have_run' || (disp == null && status >= 500)) {
    nodes.push(h('p', {}, 'The tool may have run'));
    if (message) nodes.push(h('p', {}, message));
    return nodes;
  }
  if (status === 403 && disp === 'not_run') {
    nodes.push(h('p', {}, 'Blocked'));
    if (message) nodes.push(h('p', {}, message));
    return nodes;
  }
  nodes.push(h('p', {}, 'Not run'));
  if (message) nodes.push(h('p', {}, message));
  return nodes;
}

/**
 * Tools whose last confirmed run the gateway never confirmed. The shell refuses their confirm until the page
 * reloads, so this lives as long as the page does, not as long as one visit to the tab.
 */
const unconfirmed = new Set();
const keyOf = (tool) => `tools-try:${tool.server}/${tool.name}`;

function mountTryForm(slot, answer, tools, ctx) {
  const section = answer.closest('section');
  let seq = 0;
  // The lock follows the outstanding call, not the picked tool or the run number.
  let inFlight = false;
  let fields = [];
  let runBtn = null;
  let mainNodes = [];
  let stepNodes = [];
  // Set while the shell confirm is or was open for this Run: its close sends focus to a still-disabled Run.
  let asked = false;

  const picker = h('select', { class: 'input', id: 'try-tool' },
    ...tools.map((t, i) => h('option', { value: String(i) }, toolOptionLabel(t))));
  const pickerField = h('div', { class: 'field' }, h('label', { for: 'try-tool' }, 'Tool'), picker);
  const fieldsBox = h('div', { class: 'tools-try-fields' });
  const form = h('div', { class: 'tools-try-form' });
  slot.replaceChildren(form);

  const chosen = () => tools[Number(picker.value)] ?? tools[0];

  const paint = (runId) => {
    if (runId !== seq || !answer.isConnected) return;
    const nodes = [...mainNodes, ...stepNodes];
    if (nodes.length) {
      nodes.push(h('p', {}, h('a', { class: 'lnk', href: '/ui/gateway/settings' }, 'Connect a client')));
    }
    answer.replaceChildren(...nodes);
  };

  const clearAnswer = () => {
    mainNodes = [];
    stepNodes = [];
    answer.replaceChildren();
  };

  const paintSteps = (runId, row, rec, content) => {
    if (runId !== seq) return;
    const nodes = [];
    const account = asText(row.who?.account);
    const href = `/ui/activity/${encodeURIComponent(row.id)}/status`;
    nodes.push(h('p', {}, `Recorded in Activity as a call by ${account} `,
      h('a', { class: 'lnk', href }, 'Open')));
    const d = rec?.decision;
    if (d && typeof d === 'object') {
      if (d.rule != null) nodes.push(h('p', {}, asText(d.rule)));
      if (d.decided != null) nodes.push(h('p', {}, asText(d.decided)));
      if (d.effect != null) nodes.push(h('p', {}, asText(d.effect)));
      const findings = d.findings;
      if (Array.isArray(findings)) {
        for (const f of findings) nodes.push(h('p', {}, asText(f)));
      } else if (findings != null && findings !== '') {
        nodes.push(h('p', {}, asText(findings)));
      }
    }
    const counts = countsText(content, rec?.answer);
    if (counts) nodes.push(h('p', {}, counts));
    stepNodes = nodes;
    paint(runId);
    ctx.announce(`Recorded in Activity as a call by ${account}`);
  };

  const paintMiss = (runId, sawError, receipt) => {
    if (runId !== seq) return;
    const line = sawError ? 'Firewall steps could not be read' : 'Firewall steps not recorded yet';
    stepNodes = [h('p', {}, line), h('p', {}, receipt)];
    paint(runId);
    ctx.announce(line);
  };

  const lookupReceipt = async (runId, receipt, content) => {
    let sawError = false;
    for (let i = 0; i < 4; i++) {
      if (i > 0) {
        await wait(500);
        if (runId !== seq) return;
      }
      try {
        const data = await ctx.api(`/ui/api/activity?q=${encodeURIComponent(receipt)}`);
        if (runId !== seq) return;
        const row = (Array.isArray(data?.rows) ? data.rows : [])
          .find((r) => r && r.trace_id === receipt && typeof r.id === 'string');
        if (row) {
          try {
            const rec = await ctx.api(`/ui/api/activity/${encodeURIComponent(row.id)}`);
            if (runId !== seq) return;
            paintSteps(runId, row, rec, content);
            return;
          } catch (err) {
            if (err?.name === 'AbortError') return;
            sawError = true;
          }
        }
      } catch (err) {
        if (err?.name === 'AbortError') return;
        sawError = true;
      }
    }
    if (runId !== seq) return;
    paintMiss(runId, sawError, receipt);
  };

  const showOutcome = (runId, info) => {
    if (runId !== seq) return;
    mainNodes = outcomeNodes(info);
    stepNodes = [];
    paint(runId);
    ctx.announce(mainNodes[0].textContent);
    const receipt = info.body && typeof info.body.receipt === 'string' ? info.body.receipt : '';
    if (receipt) lookupReceipt(runId, receipt, contentOf(info.body));
  };

  /**
   * One call. Every answer the gateway gives comes back as what the panel draws; a 401
   * (sign-in takes over) and no readable answer throw, so inside the confirm they are
   * the shell's own states.
   */
  const send = async (tool, args, confirmWrite) => {
    try {
      const body = await ctx.api('/ui/api/tools/call', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          server: tool.server,
          tool: tool.name,
          arguments: args,
          confirm_write: confirmWrite,
        }),
      });
      return { status: 200, body };
    } catch (err) {
      if (!(err instanceof ApiError) || err.unreadable || err.status === 0 || err.status === 401) throw err;
      return { status: err.status, body: err.body, message: err.serverMessage, code: err.code };
    }
  };

  /** The shell's one deciding-action dialog (UI1.19) runs the confirmed call. */
  const confirmRun = async (tool, args) => {
    asked = true;
    const res = await ctx.confirm({
      opener: runBtn,
      key: keyOf(tool),
      verb: 'Run',
      object: tool.name,
      progress: `Running ${tool.name}…`,
      consequences: [`${tool.name} can change things.`],
      run: () => send(tool, args, true),
    });
    if (res.outcome === 'unconfirmed') unconfirmed.add(keyOf(tool));
    if (res.outcome === 'unconfirmed' && section.isConnected) {
      const runId = ++seq;
      mainNodes = [h('p', {}, `${tool.name} may have run; the gateway did not confirm it`),
        h('p', {}, 'Reload the page before running it again.')];
      stepNodes = [];
      paint(runId);
      ctx.announce(mainNodes[0].textContent);
    }
    return res;
  };

  const callTool = async (runId, tool, args) => {
    let info;
    try {
      info = await send(tool, args, false);
    } catch (err) {
      if (err?.name === 'AbortError') return;
      info = err instanceof ApiError
        ? { status: err.status, unreadable: err.unreadable, body: err.body, message: err.serverMessage }
        : { status: 0 };
    }
    if (runId !== seq) return;
    if (info.status === 409 && (info.code === 'confirm_write_required' || info.body?.error === 'confirm_write_required')) {
      // A confirm for a run the user has left, or for an older run, never opens and never resends.
      if (!section.isConnected) return;
      const res = await confirmRun(tool, args);
      if (res.outcome !== 'done' || runId !== seq || !section.isConnected) return;
      info = res.value;
    }
    showOutcome(runId, info);
  };

  const syncRun = () => {
    if (runBtn && runBtn.isConnected) runBtn.disabled = inFlight || unconfirmed.has(keyOf(chosen()));
  };

  const onRun = async () => {
    if (!runBtn || runBtn.disabled || inFlight || unconfirmed.has(keyOf(chosen()))) return;
    const args = collectArgs(fields);
    if (!args) return;
    const tool = chosen();
    inFlight = true;
    syncRun();
    try {
      if (tool.class !== 'read') {
        const res = await confirmRun(tool, args);
        if (res.outcome !== 'done' || !section.isConnected) return;
        showOutcome(++seq, res.value);
        return;
      }
      await callTool(++seq, tool, args);
    } finally {
      inFlight = false;
      syncRun();
      // The shell's close could not focus Run while it was disabled; focus it now it is enabled.
      if (asked && runBtn?.isConnected && !runBtn.disabled
          && (document.activeElement === document.body || document.activeElement === null)) runBtn.focus();
      asked = false;
    }
  };

  const rebuild = () => {
    const t = chosen();
    fields = fieldsFor(t.schema);
    fieldsBox.replaceChildren(...fields.map((f) => f.wrap));
    runBtn = h('button', { class: 'btn', type: 'button' }, `Run ${t.name}`);
    runBtn.addEventListener('click', onRun);
    form.replaceChildren(pickerField, fieldsBox, runBtn);
    syncRun();
  };

  picker.addEventListener('change', () => {
    seq += 1;
    clearAnswer();
    rebuild();
  });
  rebuild();
}

/** Try a tool. The marker stays: the rows find this panel by it. */
async function actionsTab(body, ctx) {
  const titleId = 'tools-try-title';
  const section = h('section', {
    class: 'tk tools-try',
    'data-try-stub': true,
    'aria-labelledby': titleId,
  }, h('h2', { class: 'kicker', id: titleId }, 'Try a tool'));
  const slot = h('div', { class: 'tools-try-slot' });
  const answer = h('div', { class: 'tools-try-answer' });
  section.append(slot, answer,
    h('i', { class: 'c1', 'aria-hidden': 'true' }),
    h('i', { class: 'c2', 'aria-hidden': 'true' }));
  body.append(section);
  slot.append(h('p', {}, 'Reading tools…'));

  let tools;
  try {
    tools = await readToolsListed(ctx.api);
  } catch {
    if (!section.isConnected) return;
    slot.replaceChildren(h('p', {}, 'Tools could not be read'));
    return;
  }
  if (!section.isConnected) return;
  if (tools.length === 0) {
    slot.replaceChildren(
      h('p', {}, 'No tools yet'),
      h('p', {}, h('a', { class: 'lnk', href: '/ui/servers/status' }, 'Servers')));
    return;
  }
  mountTryForm(slot, answer, tools, ctx);
}

register('tools', {
  title: 'Tools',
  tabs: {
    // One renderer, two routes: no object is the list, an object is a tool.
    status: (body, ctx) => (ctx.object ? toolPage(body, ctx) : statusTab(body, ctx)),
    // Try a tool comes with its API; scopes live in Access, so no Settings.
    actions: actionsTab,
    settings: null,
  },
  entries: [{ label: 'All tools', path: CATALOGUE_PATH, kind: 'go' }],
});
