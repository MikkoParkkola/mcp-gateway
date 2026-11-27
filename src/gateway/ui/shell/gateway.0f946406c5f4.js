// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The Gateway screen, first slice: Gateway › Settings lists the unused secret
// entries (entries a failed or rolled-back save left in a secret store, named
// by nothing) from GET /ui/api/settings/secrets/unused, and deletes one at a
// time after the shell's confirm. A refusal shows the gateway's own sentence
// and the list is read again, so a kept entry stays listed.
// Gateway › Actions draws Reload now: one press posts /ui/api/reload and the answer shows
// under the button, its restart block from the shell's restartAdvice(). Status
// is the rest of this page and stays undrawn until it is built. Every
// server-supplied string goes in with textContent.
import { register, render, restartAdvice, el as h } from '/ui/assets/shell.509e3442f83e.js';

const STORES = { files: 'Files', keychain: 'Keychain' };
const storeWord = (s) => STORES[s] ?? String(s);

/** "2026-11-10 08:00 UTC", or "Not recorded" when the store kept no time. */
function writtenWord(at) {
  const when = typeof at === 'string' ? new Date(at) : null;
  if (!when || Number.isNaN(when.getTime())) return 'Not recorded';
  return `${when.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
}

/** The entry whose Delete gets focus back once the list is read again; null when none. */
let refocus = null;

const keyOf = (e) => `unused:${e.store}:${e.name}`;

const entryPath = (e) => `/ui/api/settings/secrets/unused/${encodeURIComponent(e.name)}?store=${encodeURIComponent(e.store)}`;

/** Delete one entry through the shell's confirm; whatever the outcome, the list is read again. */
async function remove(e, opener, ctx) {
  const result = await ctx.confirm({
    opener,
    key: keyOf(e),
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
  // A done outcome already routed and re-read the list. A refusal or an outcome the
  // gateway did not confirm reads it again, and focus goes back to this entry's
  // Delete. Cancel changed nothing: the dialog already returned focus to its opener.
  if (result.outcome === 'failed' || result.outcome === 'unconfirmed') {
    refocus = keyOf(e);
    render();
  }
}

async function settingsTab(body, ctx) {
  const listed = await ctx.api('/ui/api/settings/secrets/unused');
  const entries = (Array.isArray(listed?.entries) ? listed.entries : [])
    .filter((e) => e && typeof e.name === 'string' && typeof e.store === 'string');
  const errors = (Array.isArray(listed?.errors) ? listed.errors : []).filter((x) => x && typeof x.store === 'string');

  const card = h('section', { class: 'tk unused-card', id: 'unused-secrets', 'aria-labelledby': 'unused-title' },
    h('h2', { class: 'unused-title', id: 'unused-title', tabindex: -1 }, 'Unused secret entries'),
    h('p', { class: 't3' }, 'Entries a failed or rolled-back save left in a secret store. Nothing names them; delete them one at a time.'));
  if (errors.length) {
    card.append(h('ul', { class: 'unused-errors' },
      ...errors.map((x) => h('li', {}, `${storeWord(x.store)} could not be read: ${String(x.why ?? '')}`))));
  }
  if (entries.length === 0) {
    if (!errors.length) card.append(ctx.state('empty', { title: 'No unused entries', body: 'No secret store holds an entry that nothing names.' }));
  } else {
    const tbody = h('tbody', {}, ...entries.map((e) => {
      const del = h('button', { class: 'btn danger', type: 'button', 'aria-label': `Delete ${e.name}`, 'data-key': keyOf(e) }, 'Delete');
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
  if (refocus) {
    const back = [...card.querySelectorAll('button[data-key]')].find((b) => b.dataset.key === refocus);
    refocus = null;
    (back ?? card.querySelector('#unused-title')).focus();
  }
}

const INTRO = 'Changes to gateway.yaml are picked up on their own. If an edit has not taken effect, press Reload now: on a network filesystem, or a Docker bind mount from a Mac, the gateway may not see the file change.';
const UNCONFIRMED = 'Not confirmed: whether the gateway reloaded is not known. Try again.';
const RELOADED = 'Reloaded.';
/** The gateway's two summaries of a reload that found nothing to apply. */
const NO_CHANGES = new Set(['no changes detected', 'no changes']);

const outLine = (kind, text) => h('p', { 'data-line': kind }, text);

/**
 * The lines a 200 reload answer draws, or null when it is not one the page
 * understands: `changes` must be text and `restart_required` a boolean, and a
 * pending restart must come with a refusal or advice (restartAdvice draws it).
 */
function answeredLines(a) {
  if (!a || typeof a.changes !== 'string' || typeof a.restart_required !== 'boolean') return null;
  if (!a.restart_required) {
    return NO_CHANGES.has(a.changes)
      ? [outLine('head', 'Nothing changed: gateway.yaml matches what the gateway runs.')]
      : [outLine('head', RELOADED), outLine('changes', a.changes)];
  }
  const block = restartAdvice(a);
  if (!block) return null;
  // A refusal leads, and the summary sits under the page's own label; advice follows the summary.
  return block.dataset.kind === 'refusal'
    ? [block, outLine('label', 'These settings are not applied while a restart would not start.'), outLine('changes', a.changes)]
    : [outLine('head', RELOADED), outLine('changes', a.changes), block];
}

/** The lines for a reload the gateway refused or did not confirm, with its own sentence when it gave one. */
function refusedLines(err) {
  const head = err?.status === 409 ? 'Not reloaded. The gateway runs as before.'
    : err?.status === 503 ? 'Not reloaded.' : UNCONFIRMED;
  return err?.serverMessage ? [outLine('head', head), outLine('sentence', err.serverMessage)] : [outLine('head', head)];
}

/** What is said for drawn lines: each line's text, never the start command. */
const spoken = (lines) => lines.flatMap((n) => (n.classList.contains('restart-advice')
  ? [...n.querySelectorAll('p > span:not(.glyph)')] : [n])).map((n) => n.textContent);

async function reloadTab(body, ctx) {
  const outcome = h('div', { class: 'reload-outcome' });
  const button = h('button', { class: 'btn', type: 'button' }, 'Reload now');
  const card = h('section', { class: 'tk reload-card', id: 'reload', 'aria-labelledby': 'reload-title' },
    h('h2', { class: 'reload-title', id: 'reload-title' }, 'Reload gateway.yaml'),
    h('div', { class: 'reload-row' }, h('p', { class: 't3' }, INTRO), button),
    outcome,
    h('i', { class: 'c1', 'aria-hidden': 'true' }), h('i', { class: 'c2', 'aria-hidden': 'true' }));
  button.addEventListener('click', async () => {
    if (button.disabled) return;
    // One reload at a time; the earlier outcome stays until this one's answer replaces it.
    button.disabled = true;
    button.textContent = 'Reloading…';
    card.setAttribute('aria-busy', 'true');
    let lines;
    let signedOut = false;
    try {
      lines = answeredLines(await ctx.api('/ui/api/reload', { method: 'POST' })) ?? [outLine('head', UNCONFIRMED)];
    } catch (err) {
      // 401: the shell's sign-in view takes over (and the focus). 403: the shell's forbidden banner says it.
      signedOut = err?.status === 401;
      if (err?.status === 403) ctx.show('forbidden');
      lines = signedOut || err?.status === 403 ? [] : refusedLines(err);
    }
    outcome.replaceChildren(...lines);
    button.disabled = false;
    button.textContent = 'Reload now';
    card.removeAttribute('aria-busy');
    for (const text of spoken(lines)) ctx.announce(text);
    if (!signedOut) button.focus();
  });
  body.append(card);
}

register('gateway', {
  title: 'Gateway',
  // Settings is built in parts: this one draws the unused secret entries. The later parts'
  // tooltips wait in the copy's _pending_later, each naming the part that will draw it.
  tabs: {
    // Status is the rest of this page's work; null keeps it off the tab bar.
    status: null,
    actions: reloadTab,
    settings: settingsTab,
  },
  entries: [],
});
