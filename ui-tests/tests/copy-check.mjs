// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The two-way tooltip copy check. Used ids are the literal arguments of
// tip("…") and tipMarkup("…") in the shipped scripts; built pages are the
// pages the shipped scripts register. Every used id must have copy, and every
// copy id must be used or pending under a page that is not built yet.

const PAGES = ['overview', 'to' + 'do', 'servers', 'tools', 'activity', 'costs', 'access', 'policies', 'gateway'];
const TABS = ['status', 'actions', 'settings'];
const ID = /^([a-z0-9-]+)\.([a-z]+)\.[a-z0-9]+(?:-[a-z0-9]+)*$/;

/**
 * @param {Record<string, unknown>} copy the parsed copy asset
 * @param {string[]} scripts the shipped scripts' sources
 * @returns {string[]} problems; empty when the copy and the screens agree
 */
export function checkCopy(copy, scripts) {
  const problems = [];
  const used = new Set();
  const built = new Set();
  for (const src of scripts) {
    // Calls only: a definition (`function tip(id)`) is not a use.
    for (const m of src.matchAll(/(?<!function\s+)\btip(?:Markup)?\s*\(\s*([^)]*)\)/g)) {
      const arg = m[1].trim();
      // The whole argument must be one string literal: `"a" + b` is not.
      const lit = arg.match(/^(['"])([^'"]+)\1$/);
      if (!lit) problems.push(`non-literal tooltip id: tip(${arg})`);
      else used.add(lit[2]);
    }
    for (const m of src.matchAll(/\bregister\(\s*(['"])([^'"]+)\1/g)) built.add(m[2]);
  }
  const pending = copy._pending ?? {};
  const pendingIds = new Map();
  for (const [page, ids] of Object.entries(pending)) for (const id of ids) pendingIds.set(id, page);
  const ids = Object.keys(copy).filter((k) => k !== '_pending');
  for (const id of [...ids, ...used]) {
    const m = id.match(ID);
    if (!m || !PAGES.includes(m[1]) || !TABS.includes(m[2])) problems.push(`malformed id: ${id}`);
  }
  for (const id of ids) {
    const e = copy[id];
    const body = (typeof e?.text === 'string') + Array.isArray(e?.rows);
    if (typeof e?.title !== 'string' || body !== 1) problems.push(`malformed entry (a title and exactly one of text or rows): ${id}`);
  }
  for (const id of used) if (!ids.includes(id)) problems.push(`used without copy: ${id}`);
  for (const [id, page] of pendingIds) {
    if (id.split('.')[0] !== page) problems.push(`pending under another page (${page}): ${id}`);
    if (built.has(page)) problems.push(`pending under a built page (${page}): ${id}`);
  }
  for (const id of ids) if (!used.has(id) && !pendingIds.has(id)) problems.push(`orphan copy (neither used nor pending): ${id}`);
  for (const id of pendingIds.keys()) if (!ids.includes(id)) problems.push(`pending without copy: ${id}`);
  return problems;
}
