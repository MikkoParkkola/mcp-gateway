// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The Gateway screen, first slice: Gateway › Settings lists the unused secret
// entries (entries a failed or rolled-back save left in a secret store, named
// by nothing) from GET /ui/api/settings/secrets/unused, and deletes one at a
// time after the shell's confirm. A refusal shows the gateway's own sentence
// and the list is read again, so a kept entry stays listed. Status and Actions
// come with the rest of this page; until then they are not drawn. Every
// server-supplied string goes in with textContent.
import { register, render } from '/ui/assets/shell.48e18d9899c2.js';

/** One element: attributes set through setAttribute, children appended as nodes or text. */
function h(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v !== null && v !== undefined && v !== false) node.setAttribute(k, v === true ? '' : String(v));
  }
  node.append(...children);
  return node;
}

const STORES = { files: 'Files', keychain: 'Keychain' };
const storeWord = (s) => STORES[s] ?? String(s);

/** "2026-11-10 08:00 UTC", or "Not recorded" when the store kept no time. */
function writtenWord(at) {
  const when = typeof at === 'string' ? new Date(at) : null;
  if (!when || Number.isNaN(when.getTime())) return 'Not recorded';
  return `${when.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
}

const entryPath = (e) => `/ui/api/settings/secrets/unused/${encodeURIComponent(e.name)}?store=${encodeURIComponent(e.store)}`;

/** Delete one entry through the shell's confirm; whatever the outcome, the list is read again. */
async function remove(e, opener, ctx) {
  const result = await ctx.confirm({
    opener,
    key: `unused:${e.store}:${e.name}`,
    verb: 'Delete',
    object: `entry ${e.name}`,
    progress: `Deleting ${e.name}…`,
    consequences: [`The ${storeWord(e.store).toLowerCase()} entry is removed.`, 'No setting names it, so nothing else changes.'],
    run: () => ctx.api(entryPath(e), { method: 'DELETE' }),
    // The gateway's own sentence when it gave one; the shell's words otherwise.
    failed: (err) => (err.serverMessage ? { reason: err.serverMessage, next: 'The entry stays listed.' } : null),
    done: (value) => ({
      path: '/ui/gateway/settings',
      notice: value?.already_gone ? `${e.name} was already gone.` : `Deleted ${e.name}.`,
    }),
  });
  // A done outcome already routed and re-read the list; any other one reads it now.
  if (result.outcome !== 'done') render();
}

async function settingsTab(body, ctx) {
  const listed = await ctx.api('/ui/api/settings/secrets/unused');
  const entries = (Array.isArray(listed?.entries) ? listed.entries : [])
    .filter((e) => e && typeof e.name === 'string' && typeof e.store === 'string');
  const errors = (Array.isArray(listed?.errors) ? listed.errors : []).filter((x) => x && typeof x.store === 'string');

  const card = h('section', { class: 'tk unused-card', id: 'unused-secrets', 'aria-labelledby': 'unused-title' },
    h('h2', { class: 'unused-title', id: 'unused-title' }, 'Unused secret entries'),
    h('p', { class: 't3' }, 'Entries a failed or rolled-back save left in a secret store. Nothing names them; delete them one at a time.'));
  if (errors.length) {
    card.append(h('ul', { class: 'unused-errors' },
      ...errors.map((x) => h('li', {}, `${storeWord(x.store)} could not be read: ${String(x.why ?? '')}`))));
  }
  if (entries.length === 0) {
    if (!errors.length) card.append(ctx.state('empty', { title: 'No unused entries', body: 'No secret store holds an entry that nothing names.' }));
  } else {
    const tbody = h('tbody', {}, ...entries.map((e) => {
      const del = h('button', { class: 'btn danger', type: 'button', 'aria-label': `Delete ${e.name}` }, 'Delete');
      del.addEventListener('click', () => remove(e, del, ctx));
      return h('tr', { class: 'unused-entry' },
        h('td', { class: 'mono' }, e.name), h('td', {}, storeWord(e.store)), h('td', { class: 't2' }, writtenWord(e.written_at)), h('td', {}, del));
    }));
    card.append(h('div', { class: 'unused-scroll', tabindex: 0, role: 'region', 'aria-label': 'Unused entries' },
      h('table', { class: 't unused-table' },
        h('thead', {}, h('tr', {}, h('th', { scope: 'col' }, 'Name'), h('th', { scope: 'col' }, 'Store'),
          h('th', { scope: 'col' }, 'Written'), h('th', { scope: 'col' }, h('span', { class: 'sr-only' }, 'Action')))),
        tbody)));
  }
  card.append(h('i', { class: 'c1', 'aria-hidden': 'true' }), h('i', { class: 'c2', 'aria-hidden': 'true' }));
  body.append(card);
}

register('gateway', {
  title: 'Gateway',
  tabs: {
    // Status and Actions are the rest of this page's work; null keeps them off the tab bar.
    status: null,
    actions: null,
    settings: settingsTab,
  },
  entries: [],
});
