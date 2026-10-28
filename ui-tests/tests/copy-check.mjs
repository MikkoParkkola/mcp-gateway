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
  for (const [id, e] of Object.entries(copy)) {
    if (id === '_pending') continue;
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
 * must be drawn, or pending because its page is unregistered or its tab is null.
 */
export function pairingProblems(copy, { drawn, nonLiteral, tabs }) {
  const out = [];
  if (nonLiteral) out.push(`${nonLiteral} tip() call(s) with a non-literal id`);
  const pending = new Set(Object.values(copy._pending ?? {}).flat());
  const ids = Object.keys(copy).filter((k) => k !== '_pending');
  for (const id of [...drawn, ...ids, ...pending]) if (!ID.test(id)) out.push(`${id}: not <page>.<tab>.<subject>`);
  for (const id of drawn) if (!(id in copy)) out.push(`${id}: drawn with no copy`);
  for (const id of ids) {
    const [page, tab] = id.split('.');
    const built = tabs[page]?.[tab] === true;
    if (drawn.has(id)) {
      if (pending.has(id)) out.push(`${id}: drawn but still listed as pending`);
      continue;
    }
    if (!pending.has(id)) out.push(`${id}: neither drawn nor pending`);
    else if (built) out.push(`${id}: pending under built ${page}.${tab}`);
  }
  for (const id of pending) if (!(id in copy)) out.push(`${id}: pending with no copy`);
  return out;
}
