// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The tooltip copy checks, as pure functions over the copy asset and the
// shell's screen modules, so tips.spec.mjs can run them on the real files and
// on planted faults alike.
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const SHELL_DIR = fileURLToPath(new URL('../../src/gateway/ui/shell/', import.meta.url));
const TABS = ['status', 'actions', 'settings'];
const ID = /^[a-z0-9-]+\.(status|actions|settings)\.[a-z0-9-]+$/;
// The copy asset's bookkeeping keys, never copy entries. `_pending` lists ids by
// page while the page or tab is unbuilt; `_pending_later` maps an id under a
// built tab to the part of the page that will draw it, so a page can land part
// by part. Before cutover both must be empty (the pending list's own check).
// `_pending_rows` lists ids still in free text, to be rewritten into frame-36 rows;
// before cutover it must be empty like the others.
const META = new Set(['_pending', '_pending_later', '_pending_rows']);
// A part is named in plain words; the length cap keeps it a name, not a note.
const PART_MAX = 60;

/** The text inside `tabs: { … }` of the register() call at `from`, braces balanced; null when absent. */
function tabsBlock(src, from) {
  const at = src.slice(from).search(/\btabs\s*:\s*\{/);
  if (at < 0) return null;
  let i = src.indexOf('{', from + at);
  const start = i + 1;
  for (let depth = 0; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}' && --depth === 0) return src.slice(start, i);
  }
  return null;
}

/** `key: value` pairs at the top level of an object literal's body, values trimmed. */
function topLevelEntries(body) {
  const out = new Map();
  let depth = 0;
  let part = '';
  const flush = () => {
    const m = /^\s*([a-z]+)\s*:\s*([\s\S]*?)\s*$/.exec(part);
    if (m) out.set(m[1], m[2]);
    part = '';
  };
  for (const ch of body) {
    if ('({['.includes(ch)) depth++;
    else if (')}]'.includes(ch)) depth--;
    if (ch === ',' && depth === 0) flush();
    else part += ch;
  }
  flush();
  return out;
}

/** The copy asset, parsed. */
export function readCopy(dir = SHELL_DIR) {
  const name = readdirSync(dir).find((f) => /^tips\.[0-9a-f]{12}\.json$/.test(f));
  if (!name) throw new Error('no copy asset (tips.<hash>.json) in src/gateway/ui/shell');
  return JSON.parse(readFileSync(dir + name, 'utf8'));
}

/** The screen modules' source: every hashed .js except the shell and the tooltip module. */
export function readScreens(dir = SHELL_DIR) {
  return readdirSync(dir)
    .filter((f) => /\.[0-9a-f]{12}\.js$/.test(f) && !/^(shell|tooltip)\./.test(f))
    .map((f) => readFileSync(dir + f, 'utf8'));
}

/**
 * The shell module's source. The shell draws tooltips of its own (the top bar's
 * environment chip) but registers no screen, so its ids count as drawn and never
 * as a built tab: a11y.spec.mjs keeps reading the screens alone.
 */
export function readShell(dir = SHELL_DIR) {
  const name = readdirSync(dir).find((f) => /^shell\.[0-9a-f]{12}\.js$/.test(f));
  if (!name) throw new Error('no shell module (shell.<hash>.js) in src/gateway/ui/shell');
  return readFileSync(dir + name, 'utf8');
}

/**
 * What the screens draw and build: `drawn` is every literal tip('<id>') argument,
 * `nonLiteral` counts tip( calls whose argument is not a string literal, and
 * `tabs` maps each registered page to its tabs, a tab being built unless its spec is null.
 */
export function scanScreens(sources) {
  const drawn = new Set();
  let nonLiteral = 0;
  const tabs = {};
  for (const src of sources) {
    for (const m of src.matchAll(/\btip\(\s*([^)]*?)\s*\)/g)) {
      const lit = /^'([^']*)'$|^"([^"]*)"$/.exec(m[1]);
      if (lit) drawn.add(lit[1] ?? lit[2]);
      else nonLiteral += 1;
    }
    // Brackets, commas and colons inside strings are text, not structure: blank them (same length) first.
    const code = src.replace(/'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"|`(?:\\.|[^`\\])*`/g, (lit) => lit.replace(/[{}()[\],:]/g, ' '));
    for (const m of code.matchAll(/register\(\s*'([a-z0-9-]+)'/g)) {
      const block = tabsBlock(code, m.index);
      if (block === null) continue;
      // Comments go first: their commas and colons are not entries. A // inside a string needs no space before it.
      const specs = topLevelEntries(block.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|\s)\/\/[^\n]*/g, '$1'));
      tabs[m[1]] = Object.fromEntries(TABS.map((t) => [t, specs.has(t) && specs.get(t) !== 'null']));
    }
  }
  return { drawn, nonLiteral, tabs };
}

/** C8: every entry is {title, text} or {title, rows}, never both, with non-empty strings throughout. */
export function shapeProblems(copy) {
  const out = [];
  const str = (v) => typeof v === 'string' && v.trim() !== '';
  const later = copy._pending_later;
  if (later !== undefined && (!later || typeof later !== 'object' || Array.isArray(later))) {
    out.push('_pending_later: not an object');
  }
  const pendingRows = copy._pending_rows;
  const rowIds = Array.isArray(pendingRows) && pendingRows.every((id) => typeof id === 'string' && id !== '');
  if (pendingRows !== undefined && !rowIds) out.push('_pending_rows: not an array of ids');
  for (const [id, e] of Object.entries(copy)) {
    if (META.has(id)) continue;
    if (!e || typeof e !== 'object' || Array.isArray(e)) { out.push(`${id}: not an object`); continue; }
    const extra = Object.keys(e).filter((k) => !['title', 'text', 'rows'].includes(k));
    if (extra.length) out.push(`${id}: unexpected key ${extra.join(', ')}`);
    if (!str(e.title)) out.push(`${id}: missing or empty title`);
    if ('text' in e && 'rows' in e) out.push(`${id}: both text and rows`);
    else if ('text' in e) { if (!str(e.text)) out.push(`${id}: empty text`); }
    else if ('rows' in e) {
      const ok = Array.isArray(e.rows) && e.rows.length > 0
        && e.rows.every((r) => Array.isArray(r) && r.length === 2 && r.every(str));
      if (!ok) out.push(`${id}: rows must be [label, value] pairs of non-empty strings`);
    } else out.push(`${id}: neither text nor rows`);
  }
  return out;
}

/**
 * C1 and C2, by page and tab: an id drawn by a screen must have copy; a copy id
 * must be drawn, or pending because its page is unregistered or its tab is null,
 * or pending-later under a built tab, naming the part of the page that draws it.
 */
export function pairingProblems(copy, { drawn, nonLiteral, tabs }) {
  const out = [];
  if (nonLiteral) out.push(`${nonLiteral} tip() call(s) with a non-literal id`);
  const pending = new Set(Object.values(copy._pending ?? {}).flat());
  const later = copy._pending_later ?? {};
  const ids = Object.keys(copy).filter((k) => !META.has(k));
  for (const id of [...drawn, ...ids, ...pending, ...Object.keys(later)]) {
    if (!ID.test(id)) out.push(`${id}: not <page>.<tab>.<subject>`);
  }
  for (const id of drawn) if (!(id in copy)) out.push(`${id}: drawn with no copy`);
  for (const id of ids) {
    const [page, tab] = id.split('.');
    const built = tabs[page]?.[tab] === true;
    if (drawn.has(id)) {
      if (pending.has(id)) out.push(`${id}: drawn but still listed as pending`);
      continue;
    }
    if (Object.hasOwn(later, id)) continue; // judged with the pending-later map below
    if (!pending.has(id)) out.push(`${id}: neither drawn nor pending`);
    else if (built) out.push(`${id}: pending under built ${page}.${tab}`);
  }
  for (const [id, part] of Object.entries(later)) {
    const [page, tab] = id.split('.');
    if (pending.has(id)) out.push(`${id}: pending twice`);
    else if (!(id in copy)) out.push(`${id}: pending-later with no copy`);
    else if (drawn.has(id)) out.push(`${id}: pending-later but drawn`);
    else if (tabs[page]?.[tab] !== true) out.push(`${id}: pending-later under unbuilt ${page}.${tab}, list it in _pending`);
    else if (typeof part !== 'string' || part.trim() === '' || part.length > PART_MAX) {
      out.push(`${id}: pending-later names no part`);
    }
  }
  for (const id of pending) if (!(id in copy)) out.push(`${id}: pending with no copy`);
  return out;
}

/**
 * C10: every entry is in frame-36 row form unless `_pending_rows` lists it as still free text.
 */
export function rowFormProblems(copy) {
  const out = [];
  const listed = Array.isArray(copy._pending_rows) ? copy._pending_rows : [];
  const pending = new Set(listed);
  for (const [id, entry] of Object.entries(copy)) {
    if (!META.has(id) && entry && typeof entry === 'object' && 'text' in entry && !pending.has(id)) {
      out.push(`${id}: free text; rewrite it into rows or list it in _pending_rows`);
    }
  }
  // Own keys only: a listed `__proto__` or `constructor` names no copy.
  const own = (id) => (Object.hasOwn(copy, id) ? copy[id] : undefined);
  for (const id of listed) {
    const entry = own(id);
    if (entry && typeof entry === 'object' && !Array.isArray(entry) && !META.has(id) && 'rows' in entry) {
      out.push(`${id}: listed in _pending_rows but already in rows`);
    }
  }
  for (const id of listed) {
    const entry = own(id);
    if (META.has(id) || !entry || typeof entry !== 'object' || Array.isArray(entry)) {
      out.push(`${id}: listed in _pending_rows with no copy`);
    }
  }
  return out;
}

// Frame 36's contract order; the unit goes in Window's text and "Automatic" is
// the Default row's value; rows that don't apply are left out.
const ROW_LABELS = ['What', 'Window', 'Source', 'Default', 'Why'];

/**
 * C11: each row tip's labels are the frame-36 five, in contract order.
 */
export function orderProblems(copy) {
  const out = [];
  const filled = (v) => typeof v === 'string' && v.trim() !== '';
  for (const [id, entry] of Object.entries(copy)) {
    if (META.has(id) || !entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
    // Free text is not this check, and a malformed rows value belongs to shapeProblems.
    if ('text' in entry || !Array.isArray(entry.rows)) continue;
    const rows = entry.rows;
    if (rows.length === 0 || !rows.every((r) => Array.isArray(r) && r.length === 2 && r.every(filled))) continue;
    const seen = new Set();
    let furthest = -1;
    for (const [label] of rows) {
      const at = ROW_LABELS.indexOf(label);
      if (at < 0) {
        out.push(`${id}: label ${label} is not one of ${ROW_LABELS.join(', ')}`);
        continue;
      }
      if (seen.has(label)) {
        out.push(`${id}: label ${label} appears twice`);
        continue;
      }
      seen.add(label);
      if (at < furthest) out.push(`${id}: rows out of order: ${ROW_LABELS[furthest]} before ${label}`);
      else furthest = at;
    }
  }
  return out;
}

/** The single served file whose name fits `pattern`: its name and text. */
export function served(pattern) {
  const hits = readdirSync(SHELL_DIR).filter((f) => pattern.test(f));
  if (hits.length !== 1) throw new Error(`want exactly one ${pattern} in src/gateway/ui/shell, have ${hits.length}`);
  return { name: hits[0], text: readFileSync(SHELL_DIR + hits[0], 'utf8') };
}
