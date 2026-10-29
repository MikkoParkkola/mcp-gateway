// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The web UI shell: sidebar, page title, tabs in the address, page states
// and the authenticated API client. Screens register a page; the shell owns
// the URL. The document lists the screens in a manifest; the shell loads the
// screen of the current route before rendering it and the rest after the first
// paint. A screen calls register() whenever it runs, before boot or after.
// All text goes in with textContent.

/** The sidebar, in order. The To do page id is composed so it reads as a name. */
export const NAV = [
  ['overview', 'Overview'],
  ['to' + 'do', 'To do'],
  ['servers', 'Servers'],
  ['tools', 'Tools'],
  ['activity', 'Activity'],
  ['costs', 'Costs'],
  ['access', 'Access'],
  ['policies', 'Policies'],
  ['gateway', 'Gateway'],
];

const TABS = [['status', 'Status'], ['actions', 'Actions'], ['settings', 'Settings']];
const PAGE_IDS = new Set(NAV.map(([id]) => id));
const pages = new Map();

/**
 * Register a page: `{title, subtitle, tabs: {status, actions, settings}, entries}`.
 * A null tab is hidden. The subtitle is the one line under the plate.
 * A tab can set either later, as text, through `header({title, subtitle})` in its context.
 */
export function register(id, spec) {
  if (!PAGE_IDS.has(id)) throw new Error(`register: no sidebar page ${id}`);
  pages.set(id, spec);
}

/** The screen manifest of the document: page id → {js, css}. The shell never names a screen file itself. */
function screens() {
  try {
    return JSON.parse(document.getElementById('screens')?.textContent || '{}');
  } catch {
    return {};
  }
}

/** One load per screen; a failed one is forgotten so Retry tries again. */
const loads = new Map();

/** One load per stylesheet; the next attempt of its screen reuses a loaded one. */
const sheets = new Map();

/** Add a stylesheet and settle when it has loaded; a failed one is taken out again. */
function sheet(href) {
  if (!sheets.has(href)) {
    const load = new Promise((ok, fail) => {
      const link = el('link', { rel: 'stylesheet', href });
      link.addEventListener('load', ok);
      link.addEventListener('error', () => {
        link.remove();
        fail(new Error(`stylesheet ${href} did not load`));
      });
      document.head.append(link);
    });
    load.catch(() => sheets.delete(href));
    sheets.set(href, load);
  }
  return sheets.get(href);
}

/** A manifest path the shell will fetch: one file name under /ui/assets/, nothing else. */
const ASSET_PATH = /^\/ui\/assets\/[A-Za-z0-9._-]+$/;

/** Pages whose stylesheet and module have both loaded. */
const ready = new Set();
/** Pages the shell has itself tried to load. */
const tried = new Set();

/**
 * Whether page id must load its screen before it is drawn: it has a
 * manifest entry and is not ready. A page registered without the shell
 * ever loading it, such as a test fixture page, is drawn as it is.
 */
function needsLoad(id) {
  if (!screens()[id] || ready.has(id)) return false;
  return tried.has(id) || !pages.has(id);
}

/**
 * Load the screen of page id, its stylesheet and module; the module registers
 * itself. The page is ready once both have loaded. A failed load is
 * forgotten, so the next attempt fetches again only the part that failed:
 * a loaded stylesheet and an evaluated module are kept.
 */
function loadScreen(id) {
  if (!needsLoad(id)) return Promise.resolve();
  if (!loads.has(id)) {
    tried.add(id);
    const entry = screens()[id];
    const load = ASSET_PATH.test(entry?.js) && ASSET_PATH.test(entry?.css)
      ? Promise.all([sheet(entry.css), import(entry.js)]).then(() => { ready.add(id); })
      : Promise.reject(new Error(`screen ${id}: the manifest entry is not an asset path`));
    load.catch(() => loads.delete(id));
    loads.set(id, load);
  }
  return loads.get(id);
}

/** Every screen in the manifest; failures stay with their own route. */
const loadAllScreens = () => Promise.allSettled(Object.keys(screens()).map(loadScreen));

/**
 * The palette's entries, navigation only: every sidebar page, each visible
 * tab, and each page's declared entries (named actions and settings, each a
 * route to its tab). An entry is plain data, `{label, path, kind}`, with no
 * callback, so choosing one can only change the address.
 */
export function entries() {
  const out = [];
  for (const [id, label] of NAV) {
    out.push({ label, path: `/ui/${id}`, kind: 'go' });
    for (const [tab, tabLabel] of visibleTabs(id)) out.push({ label: `${label} › ${tabLabel}`, path: `/ui/${id}/${tab}`, kind: 'go' });
    for (const e of pages.get(id)?.entries ?? []) {
      const kind = e.kind === 'action' || e.kind === 'setting' ? e.kind : 'go';
      out.push({ label: String(e.label), path: String(e.path), kind });
    }
  }
  return out;
}

function visibleTabs(id) {
  const tabs = pages.get(id)?.tabs;
  return tabs ? TABS.filter(([t]) => typeof tabs[t] === 'function') : [];
}

// ---------------------------------------------------------------- elements

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v !== null && v !== undefined && v !== false) node.setAttribute(k, v === true ? '' : String(v));
  }
  node.append(...children);
  return node;
}

/**
 * The one word for each state, used across every screen (UI1.24). Server
 * states are keyed by the gateway's ServerState wire values. A dropped live
 * stream has its own words below, never the paused server state's.
 */
export const GLOSSARY = {
  server: {
    running: 'Running',
    slow: 'Slow',
    paused: 'Paused',
    dormant: 'Dormant',
    unhealthy: 'Unhealthy',
    refused: 'Refused',
    needs_sign_in: 'Needs sign-in',
    unmanaged: 'Unmanaged',
  },
  stream: { stopped: 'Updates stopped', resumed: 'Updates resumed' },
};

const unlistedStates = new Set();

/** A server state's word; one the glossary lacks reads "Unknown state", never its code. */
export function stateWord(value) {
  if (typeof value === 'string' && Object.hasOwn(GLOSSARY.server, value)) return GLOSSARY.server[value];
  if (!unlistedStates.has(value)) {
    unlistedStates.add(value);
    console.warn('A server state this page does not recognise'); // never the raw value
  }
  return 'Unknown state';
}

/**
 * One table for every server state the gateway reports (UI1.22): the badge's
 * glyph and tone, and the banner and next step, which may read the row's own
 * fields (`circuit_state`, `running`, `next_retry_at`). The gateway's `reason`
 * is never shown: a Refused reason carries raw policy codes.
 */
export const SERVER_STATES = {
  running: { glyph: '✓', tone: 'success', banner: () => null, next: () => null },
  // Calls still work, but its recent ones are far slower than its own usual.
  slow: {
    glyph: '⚠',
    tone: 'warning',
    banner: (s) => `${s.name} still works, but far slower than its usual.`,
    next: () => 'Open Activity and filter by this server.',
  },
  paused: {
    glyph: '⏸',
    tone: 'neutral',
    // Only what the fields establish: when calls may try again, not that a retry is under way.
    banner: (s) => (s.circuit_state === 'half_open'
      ? `The gateway is letting calls through to ${s.name} to see if it has recovered.`
      : `Calls to ${s.name} are held back after failures. ${validDate(s.next_retry_at)
        ? `The gateway lets calls try it again from ${stamp(new Date(s.next_retry_at))}.`
        : 'The gateway lets calls try it again after a short wait.'}`),
    next: (s) => (s.circuit_state === 'half_open' ? null : 'To retry now, use the Actions tab.'),
  },
  dormant: { glyph: 'ⓘ', tone: 'neutral', banner: () => null, next: () => null },
  unhealthy: {
    glyph: '⚠',
    tone: 'warning',
    banner: (s) => (s.running ? `${s.name} is failing; calls still go through.` : `${s.name} is failing; the next call tries to start it again.`),
    next: () => 'Open Activity and filter by this server.',
  },
  refused: {
    glyph: '⊘',
    tone: 'danger',
    // The policy, an unavailable runtime or a missing image: the field does not say which.
    banner: (s) => `The gateway cannot start ${s.name} with its current runtime configuration.`,
    next: () => "Check this server's runtime profile and the runtime policy.",
  },
  needs_sign_in: {
    glyph: '⚠',
    tone: 'warning',
    banner: (s) => `${s.name} is waiting for someone to sign in.`,
    next: () => 'Sign in from its Actions tab.',
  },
  unmanaged: {
    glyph: 'ⓘ',
    tone: 'neutral',
    banner: (s) => `${s.name} is on this machine but not behind the gateway.`,
    next: () => 'Add it from the Servers Actions tab.',
  },
};

/** A state the table lacks is not shown as harmless. */
const UNLISTED_STATE = {
  glyph: '⚠',
  tone: 'warning',
  banner: (s) => `${s.name} is in a state this page does not recognise.`,
  next: () => 'Open Activity and filter by this server.',
};

/** A time the API sent that reads as a real date. */
const validDate = (value) => typeof value === 'string' && !Number.isNaN(new Date(value).getTime());

const stateRow = (state) => (typeof state === 'string' && Object.hasOwn(SERVER_STATES, state) ? SERVER_STATES[state] : UNLISTED_STATE);

/** A server's line badge: glyph, word, tone; `plain` drops the frame for lists. */
export function serverBadge(state, { plain = false } = {}) {
  const row = stateRow(state);
  return el('span', { class: `lb ${row.tone}${plain ? ' plain' : ''}` },
    el('span', { class: 'glyph', 'aria-hidden': 'true' }, row.glyph), ' ', stateWord(state));
}

/** A server's banner and next step, or null when there is nothing to know. */
export function serverBanner(server) {
  const row = stateRow(server.state);
  const text = row.banner(server);
  if (!text) return null;
  const next = row.next(server);
  const node = el('section', { class: `state banner ${row.tone}`, 'data-state': 'server' }, el('h2', {}, text));
  if (next) node.append(el('p', {}, next));
  return node;
}

/** The stale banner's title: when updates stopped, and that it reconnects. */
export function staleTitle(since) {
  return since instanceof Date && !Number.isNaN(since.getTime())
    ? `${GLOSSARY.stream.stopped} at ${stamp(since)} · reconnecting`
    : `${GLOSSARY.stream.stopped} · reconnecting`;
}

const STATE_COPY = {
  loading: ['Loading', 'Reading the gateway.'],
  empty: ['Nothing here yet', ''],
  error: ['Something went wrong', 'Try again.'],
  forbidden: ['Not available to this key', 'Ask an admin for access.'],
  stale: [GLOSSARY.stream.stopped, 'Reconnecting.'],
  'not-built': ['Not built yet', 'This page is not in the new UI yet.'],
};

/** A page state (loading, empty, error, forbidden, stale, not-built). */
export function state(kind, { title, body, action } = {}) {
  const [defTitle, defBody] = STATE_COPY[kind] ?? STATE_COPY.error;
  // No role: the one live region says transitions (UI1.18); a state is plain content.
  const node = el('section', { class: 'state', 'data-state': kind }, el('h2', {}, title ?? defTitle));
  const text = body ?? defBody;
  if (text) node.append(el('p', { class: 'muted' }, text));
  if (kind === 'not-built') node.append(el('p', {}, el('a', { class: 'lnk', href: '/ui/classic' }, 'Open the classic page')));
  if (action) node.append(action);
  return node;
}

// ---------------------------------------------------------------- api

let bearer = null;
/** Counts sign-ins; an answer to a request started before the latest one is stale. */
let authEpoch = 0;

/**
 * An error from /ui/api: its HTTP status (0 when no answer came at all), and
 * whether an ok answer's body could not be read.
 */
export class ApiError extends Error {
  constructor(status, path, { unreadable = false } = {}) {
    super(`${path} answered ${status}`);
    this.status = status;
    this.unreadable = unreadable;
  }
}

/** GET (or another method) on /ui/api with the session cookie, or the key held in memory. */
export async function api(path, init = {}) {
  if (typeof path !== 'string' || !path.startsWith('/ui/api/')) throw new TypeError(`api: not a /ui/api/ path: ${path}`);
  const headers = new Headers(init.headers);
  if (bearer) headers.set('Authorization', `Bearer ${bearer}`);
  // Built before the call, so a request the page cannot build stays the page's own fault.
  const request = new Request(path, { credentials: 'same-origin', ...init, headers });
  const epoch = authEpoch;
  let reply;
  try {
    reply = await fetch(request);
  } catch (err) {
    if (err?.name === 'AbortError') throw err; // the caller's own abort, not the gateway
    throw new ApiError(0, path);
  }
  // A 401 to a request sent before the latest sign-in says nothing about now.
  if (reply.status === 401 && epoch === authEpoch) showSignIn();
  // A refusal is judged by its status alone; its body is never read.
  if (!reply.ok) throw new ApiError(reply.status, path);
  if (reply.status === 204) return null;
  try {
    return await reply.json();
  } catch (err) {
    if (err?.name === 'AbortError') throw err; // the caller cancelled the read
    throw new ApiError(reply.status, path, { unreadable: true });
  }
}

// ---------------------------------------------------------------- announcer

/**
 * dwellMs: the pause between writes, so a screen reader takes each entry on its
 * own. Exported so a test can lengthen it and pin a race regardless of the
 * host's load.
 */
export const announcerTiming = { dwellMs: 500 };
/** How long an entry stays in the region; removing it is not announced. */
const ENTRY_MS = 10_000;
/** Messages waiting for the next write, in arrival order. */
const pending = [];
let pumpTimer = null;
let lastWrite = 0;
const idleWaiters = [];

/**
 * Say `text` through the one live region (UI1.18). For state transitions only,
 * never a counter or a chart. A `count` message keeps only its latest value;
 * every other message is said, in order. A message about a page (`page`, or a
 * screen's own) is dropped once the user moves to another page, and every
 * message once the signed-in identity changes.
 */
export function announce(text, { subject = 'page', guard: given = null } = {}) {
  const pageBound = subject === 'page' || subject.startsWith('screen:');
  const guard = given ?? { epoch: authEpoch, seq: pageBound ? renderSeq : null };
  if (!guardHolds(guard)) return; // asked for by a page or identity already gone
  if (subject === 'count') {
    const i = pending.findIndex((m) => m.subject === 'count');
    if (i >= 0) pending.splice(i, 1);
  }
  const item = { text, subject, guard };
  pending.push(item);
  if (!pumpTimer) pumpTimer = setTimeout(pump, Math.max(0, lastWrite + announcerTiming.dwellMs - Date.now()));
  // Withdraw it, if it has not been written yet.
  return () => {
    const i = pending.indexOf(item);
    if (i >= 0) pending.splice(i, 1);
  };
}

/** Append everything still current as one entry; queue the rest for the next dwell. */
function pump() {
  pumpTimer = null;
  const signedOut = document.body.classList.contains('signed-out');
  // While sign-in shows, only its own messages still describe what the user sees.
  const current = pending.splice(0).filter(({ subject, guard }) =>
    guardHolds(guard) && (!signedOut || subject.startsWith('signin')));
  if (current.length) {
    const entry = el('p', {}, current.map((m) => sentence(m.text)).join(' '));
    document.getElementById('announcer').append(entry);
    setTimeout(() => entry.remove(), ENTRY_MS);
    lastWrite = Date.now();
  }
  if (pending.length) pumpTimer = setTimeout(pump, announcerTiming.dwellMs);
  else for (const done of idleWaiters.splice(0)) done();
}

/** Whether the page and identity a message was asked for are still the ones shown. */
const guardHolds = (guard) => guard.epoch === authEpoch && (guard.seq === null || guard.seq === renderSeq);

/** `text` ending as a sentence, so a batch reads as separate sentences. */
const sentence = (text) => (/[.!?…]$/.test(text.trim()) ? text.trim() : `${text.trim()}.`);

/**
 * Move the live region to `parent` empty: a region re-parented with an entry
 * in it may be read again.
 */
function moveAnnouncer(parent) {
  const region = document.getElementById('announcer');
  region.replaceChildren();
  parent.append(region);
}

/** Resolves once everything queued has been written. */
export function announcerIdle() {
  return new Promise((done) => {
    if (!pending.length && !pumpTimer) done();
    else idleWaiters.push(done);
  });
}

/** What a page error says it was: the cause, its banner copy, and for a server answer its code. */
export function causeOf(err) {
  if (!(err instanceof ApiError)) {
    const name = typeof err?.name === 'string' && err.name ? err.name : 'error';
    return { cause: 'page-fault', title: 'This page failed', body: `A fault in the page itself (${name}), not in the gateway. Try again or reload; if it repeats, report it.` };
  }
  if (err.status === 0) return { cause: 'unreachable', title: 'Could not reach the gateway', body: 'Check that it is running and that this browser can reach it.' };
  if (err.unreadable) return { cause: 'unreadable', title: "The gateway's answer could not be read", body: `It answered HTTP ${err.status} with something this page could not read. Try again; if it repeats, check the gateway's log.` };
  if (err.status === 404) return { cause: 'not-found', title: 'Not found', body: 'The gateway has no such page or item.' };
  return { cause: 'server', title: 'The gateway answered with an error', body: `It answered HTTP ${err.status}. Try again; if it repeats, check the gateway's log.` };
}

// ---------------------------------------------------------------- palette

const GROUPS = [['go', 'Go to'], ['action', 'Actions, opens the Actions tab'], ['setting', 'Settings']];

/** Where an entry leads, in words: "Servers › github › Actions". */
function crumb(path) {
  const parts = path.split('#')[0].replace(/^\/ui\/?/, '').split('/').filter(Boolean);
  return parts.map((p, i) => {
    if (i === 0) return NAV.find(([id]) => id === p)?.[1] ?? p;
    return TABS.find(([t]) => t === p)?.[1] ?? safeDecode(p);
  }).join(' › ');
}

function safeDecode(p) {
  try { return decodeURIComponent(p); } catch { return p; }
}

let paletteEl = null;

/** Open the palette. It finds pages, actions and settings and opens them on their tab; nothing runs from it. */
export function openPalette() {
  if (paletteEl) return; // also while a closing palette's cleanup is pending
  if (confirmEl) return; // one modal at a time
  if (document.body.classList.contains('signed-out')) return;
  const opener = document.activeElement;
  const input = el('input', { type: 'text', role: 'combobox', 'aria-expanded': 'true', 'aria-controls': 'palette-list', 'aria-autocomplete': 'list', 'aria-label': 'Go to anything', placeholder: 'Go to anything', autocomplete: 'off', spellcheck: 'false' });
  const list = el('div', { id: 'palette-list', role: 'listbox', 'aria-label': 'Results' });
  const foot = el('div', { class: 'palette-foot muted' },
    el('span', {}, '↵ open · ↑↓ move · esc close'), el('span', {}, 'Actions open on their tab. Nothing runs from here.'));
  paletteEl = el('dialog', { class: 'palette', 'aria-label': 'Go to anything' }, input, list, foot);
  document.body.append(paletteEl);
  let options = [];
  let active = 0;
  let chosen = false;
  const draw = (keep = false) => {
    const was = keep ? options[active]?.dataset.path : null;
    const q = input.value.trim().toLowerCase();
    const found = entries().filter((e) => !q || e.label.toLowerCase().includes(q) || crumb(e.path).toLowerCase().includes(q));
    list.replaceChildren();
    options = [];
    for (const [kind, heading] of GROUPS) {
      const group = found.filter((e) => e.kind === kind);
      if (!group.length) continue;
      const hid = `palette-g-${kind}`;
      const box = el('div', { role: 'group', 'aria-labelledby': hid }, el('div', { class: 'palette-group', id: hid }, heading));
      for (const e of group) {
        const option = el('div', { role: 'option', id: `palette-o-${options.length}`, class: 'palette-option', 'data-path': e.path },
          el('span', {}, e.label), el('span', { class: 'muted' }, crumb(e.path)));
        option.addEventListener('click', () => choose(e.path));
        box.append(option);
        options.push(option);
      }
      list.append(box);
    }
    if (!options.length) list.append(el('p', { class: 'muted palette-empty' }, 'No page, action or setting matches.'));
    // A redraw keeps the place of the user on the entry, not on its position.
    const kept = was ? options.findIndex((o) => o.dataset.path === was) : -1;
    active = kept >= 0 ? kept : Math.min(active, Math.max(options.length - 1, 0));
    mark();
  };
  const mark = () => {
    options.forEach((o, i) => o.setAttribute('aria-selected', i === active ? 'true' : 'false'));
    if (options[active]) {
      input.setAttribute('aria-activedescendant', options[active].id);
      options[active].scrollIntoView({ block: 'nearest' });
    } else {
      input.removeAttribute('aria-activedescendant');
    }
  };
  const search = document.querySelector('button.search');
  const close = () => {
    paletteEl.close();
  };
  const choose = (path) => {
    chosen = true;
    close();
    closeMenu();
    go(path);
    document.getElementById('content').focus({ preventScroll: true });
  };
  input.addEventListener('input', () => { active = 0; draw(); });
  input.addEventListener('keydown', (ev) => {
    if (ev.isComposing) return; // an IME is still committing text
    if (ev.key === 'ArrowDown' || ev.key === 'ArrowUp') {
      ev.preventDefault();
      if (!options.length) return;
      active = (active + (ev.key === 'ArrowDown' ? 1 : options.length - 1)) % options.length;
      mark();
    } else if (ev.key === 'Enter' && options[active]) {
      ev.preventDefault();
      choose(options[active].dataset.path);
    }
  });
  paletteEl.addEventListener('close', () => {
    moveAnnouncer(document.body); // before the dialog goes
    paletteEl.remove();
    paletteEl = null;
    search?.setAttribute('aria-expanded', 'false');
    // A choice hands focus to the content (choose() moves it after this);
    // Esc or a click outside gives it back to the opener.
    if (!chosen && opener && document.contains(opener)) opener.focus();
  });
  paletteEl.addEventListener('click', (ev) => { if (ev.target === paletteEl) close(); });
  draw();
  // Screens not loaded yet declare their entries when they register: list them as they arrive.
  const dialog = paletteEl;
  for (const id of Object.keys(screens()).filter(needsLoad)) {
    loadScreen(id).then(() => { if (paletteEl === dialog) draw(true); }, () => {});
  }
  search?.setAttribute('aria-expanded', 'true');
  paletteEl.showModal();
  // A modal makes the rest of the page inert, the live region with it: it rides along.
  moveAnnouncer(paletteEl);
  input.focus();
}

// ---------------------------------------------------------------- confirm

/** In-progress said after this long; "still waiting" after the next; the dialog stops waiting after the last. */
const CONFIRM_SAY_MS = 300;
const CONFIRM_WAIT_MS = 10_000;
const CONFIRM_CUTOFF_MS = 30_000;
/** A request that never settles gives the lock up this long after the cutoff. */
const LOCK_GRACE_MS = 120_000;
/** Statuses that mean the gateway refused before acting; anything else may have acted. */
const REFUSALS = new Set([400, 403, 404, 409, 422]);

let confirmEl = null;
/** The one operation in flight. Released only by its own token, so a late request cannot free a newer one's. */
let lock = null;
/** Subjects whose last outcome was not confirmed, for one render: a new render (a navigation or reload) shows their real state. */
let unconfirmed = { seq: -1, keys: new Set() };
/** The done notice, bound to the page it landed on and the identity that acted. */
let doneNotice = null;

const unconfirmedKeys = () => {
  if (unconfirmed.seq !== renderSeq) unconfirmed = { seq: renderSeq, keys: new Set() };
  return unconfirmed.keys;
};

const releaseLock = (token) => { if (lock?.token === token) lock = null; };

/** What a failed run() means: a refusal the gateway made before acting, or an outcome nobody can confirm. */
function classify(err, spec) {
  const safe = spec.replay === 'safe';
  if (!(err instanceof ApiError) || err.unreadable || err.status === 0) return { kind: 'unconfirmed' };
  const s = err.status;
  const object = spec.object;
  if ((s === 429 || s === 503) && safe) {
    return { kind: 'refusal', retry: true, reason: `The gateway is busy (HTTP ${s}).`, next: 'Try again in a moment.' };
  }
  if (!REFUSALS.has(s)) return { kind: 'unconfirmed' };
  let own = null;
  try {
    own = spec.failed?.(err) ?? null;
  } catch (fault) {
    console.error(fault); // the screen's own words failed; the default words still say what happened
  }
  const words = own ?? {
    403: { reason: `This key may not ${spec.verb.toLowerCase()} ${object}.`, next: 'Ask an admin, or sign in with a key that may.' },
    404: { reason: `${object} is no longer there.`, next: 'Reload the page to see what is.' },
    409: { reason: `${object} changed since this page loaded.`, next: 'Reload the page and try again.' },
  }[s] ?? { reason: `The gateway refused the request (HTTP ${s}).`, next: 'Check the details, then reload the page.' };
  return { kind: 'refusal', retry: safe && own?.retry === true, reload: s === 409, reason: words.reason, next: words.next };
}

/** The page content, keeping the done notice at its top while it belongs to this page. */
function setContent(container, ...nodes) {
  if (doneNotice && (doneNotice.seq !== renderSeq || doneNotice.epoch !== authEpoch)) doneNotice = null;
  const keep = doneNotice && container.id === 'content' ? [doneNotice.node] : [];
  container.replaceChildren(...keep, ...nodes);
}

/** The part of the page the user can see: the visual viewport, so an on-screen keyboard or pinch zoom counts. */
const visible = () => {
  const vv = window.visualViewport;
  return vv ? { top: vv.offsetTop, left: vv.offsetLeft, height: vv.height, width: vv.width }
    : { top: 0, left: 0, height: innerHeight, width: innerWidth };
};

const overlaps = (a, b) => a.left < b.right && b.left < a.right && a.top < b.bottom && b.top < a.bottom;

/**
 * Centre the dialog in the visible part, never over its opener (UI1.25).
 * Its height is capped so the bands above and below it each fit the opener;
 * the opener is scrolled into the nearer band, with the page made taller when
 * it cannot scroll that far. When even the smallest
 * dialog (title and buttons) does not fit between two such bands, it docks in
 * the band away from the opener: the one case where centring yields.
 */
function placeConfirm(dialogEl, opener, room) {
  const v = visible();
  const margin = 16;
  const width = Math.min(480, v.width - 2 * margin);
  Object.assign(dialogEl.style, { width: `${width}px`, left: `${v.left + (v.width - width) / 2}px`, maxHeight: 'none' });
  const box = (top, height) => ({ top, bottom: top + height, left: v.left + (v.width - width) / 2, right: v.left + (v.width + width) / 2 });
  const body = dialogEl.querySelector('.confirm-body');
  const smallest = dialogEl.offsetHeight - body.clientHeight + 48;
  // An opener taller than half the visible part cannot be kept clear of anything: centre as if it were gone.
  const at = () => {
    const r = opener?.isConnected ? opener.getBoundingClientRect() : null;
    return r && r.height + 2 * margin < v.height / 2 ? r : null;
  };
  let o = at();
  const band = o ? o.height + 2 * margin : 0;
  const cap = Math.max(v.height - 2 * band, 0);
  if (cap >= smallest || !o) {
    dialogEl.style.maxHeight = `${Math.min(Math.max(cap, smallest), v.height - 2 * margin)}px`;
    const h = dialogEl.offsetHeight;
    const top = v.top + (v.height - h) / 2;
    if (o && overlaps(box(top, h), o)) {
      // Into the nearer band: top or bottom of the visible part.
      const upper = o.top + o.height / 2 < v.top + v.height / 2;
      const want = upper ? v.top + margin : v.top + v.height - margin - o.height;
      scrollPage(room, o.top - want);
      o = at();
    }
    // Checked again after the scroll: an opener that could not move docks the dialog instead.
    if (!o || !overlaps(box(top, h), o)) {
      dialogEl.style.top = `${top}px`;
      return;
    }
  }
  // Docked: the opener goes to the top band if the page can scroll it there, and the
  // dialog takes the larger free part beside it, measured after the scroll.
  scrollPage(room, o.top - (v.top + margin));
  o = at() ?? o;
  const above = o.top - margin - v.top;
  const below = v.top + v.height - (o.bottom + margin);
  const space = Math.max(above, below) - margin;
  // Never below the smallest usable dialog; when even that does not fit, the dialog scrolls.
  dialogEl.style.maxHeight = `${Math.max(space, Math.min(smallest, v.height - 2 * margin))}px`;
  dialogEl.style.top = `${above >= below ? v.top + margin : o.bottom + margin}px`;
}

/**
 * Scroll the page by `dy`. When it cannot scroll that far, the page is made
 * taller first: the content fills the screen as a flex child, so only a taller
 * body adds room. The body's min-height is reset when the dialog closes.
 */
function scrollPage(room, dy) {
  const max = document.documentElement.scrollHeight - innerHeight;
  const need = scrollY + dy - max;
  if (need > 0) {
    // From the page's own height: a page already taller than the screen gains nothing from 100vh.
    room.base ??= document.documentElement.scrollHeight;
    room.extra += need;
    document.body.style.minHeight = `${room.base + room.extra}px`;
  }
  window.scrollTo({ top: Math.max(0, scrollY + dy), behavior: 'instant' });
}

/**
 * One pattern for every destructive or deciding action (UI1.19). The screen
 * gives the words and the request; the shell owns the dialog and every state
 * after it, and resolves once, when the dialog closes, with
 * `{ outcome: 'done', value } | 'kept' | 'failed' | 'unconfirmed' | 'declined'`.
 */
export function confirmAction(spec) {
  for (const field of ['opener', 'key', 'verb', 'object', 'progress', 'consequences', 'run']) {
    if (spec?.[field] === undefined || spec[field] === null) throw new TypeError(`confirm: ${field} is required`);
  }
  if (typeof spec.run !== 'function') throw new TypeError('confirm: run must be a function');
  if (!Array.isArray(spec.consequences)) throw new TypeError('confirm: consequences must be a list');
  const signedOut = document.body.classList.contains('signed-out');
  if (signedOut || confirmEl || lock || unconfirmedKeys().has(spec.key) || paletteEl) {
    console.warn(signedOut ? 'confirm: nobody is signed in'
      : confirmEl || lock ? 'confirm: another action is still open or running'
      : paletteEl ? 'confirm: the palette is open' : 'confirm: the last outcome for this subject is not confirmed; reload first');
    return Promise.resolve({ outcome: 'declined' });
  }
  const { opener, key, verb, object, progress } = spec;
  const keepWord = spec.keep ?? 'Cancel';
  const tone = spec.tone === 'decision' ? 'primary' : 'danger';
  const titleId = 'confirm-title';
  const listId = 'confirm-list';
  const consequences = spec.consequences.length
    ? el('ul', { id: listId }, ...spec.consequences.map((c) => el('li', {}, String(c))))
    : el('ul', { id: listId }, el('li', {}, 'It does not say what it changes.'));
  const typed = spec.typeToConfirm === undefined ? null
    : el('input', { type: 'text', id: 'confirm-typed', autocomplete: 'off', spellcheck: 'false' });
  const typedRow = typed && el('p', { class: 'confirm-typed' }, el('label', { for: 'confirm-typed' }, `Type ${spec.typeToConfirm} to confirm`), typed);
  const line = el('p', { class: 'confirm-progress', tabindex: '-1' });
  const note = el('div', { class: 'confirm-message', tabindex: '-1' });
  const body = el('div', { class: 'confirm-body' }, consequences, ...(typedRow ? [typedRow] : []), line, note);
  line.hidden = true;
  note.hidden = true;
  const keep = el('button', { type: 'button', class: 'btn' }, `${keepWord} ${object}`);
  const act = el('button', { type: 'button', class: `btn ${tone}` }, `${verb} ${object}`);
  const acts = el('div', { class: 'acts' }, keep, act);
  const room = { base: null, extra: 0 };
  confirmEl = el('dialog', { class: 'confirm', 'aria-labelledby': titleId, 'aria-describedby': listId },
    el('h2', { id: titleId }, `${verb} ${object}?`), body, acts);
  const dialogEl = confirmEl;
  const before = scrollY;
  document.body.append(dialogEl);

  let phase = 'confirm';
  let routed = false;
  let stopClocks = () => {};
  let heldToken = null;
  let saidAfterClose = '';
  let settle;
  const result = new Promise((resolve) => { settle = resolve; });
  let outcome = { outcome: 'kept' };
  const matches = () => !typed || typed.value === spec.typeToConfirm;
  const arm = () => { act.disabled = !matches(); retry.disabled = !matches(); };
  const retry = el('button', { type: 'button', class: `btn ${tone}` }, 'Try again');
  const close = el('button', { type: 'button', class: 'btn' }, 'Close');
  const reload = el('button', { type: 'button', class: 'btn' }, 'Reload page');
  reload.addEventListener('click', () => location.reload());
  typed?.addEventListener('input', arm);
  arm();

  const place = () => placeConfirm(dialogEl, opener, room);
  const vv = window.visualViewport;
  addEventListener('resize', place);
  vv?.addEventListener('resize', place);
  vv?.addEventListener('scroll', place);

  const finish = (result) => {
    outcome = result;
    if (dialogEl.open) dialogEl.close();
  };
  dialogEl.addEventListener('cancel', (ev) => {
    ev.preventDefault();
    if (phase === 'sending') return;
    // Esc is Close: after a sent request it reports what happened to it.
    if (phase === 'refusal') finish({ outcome: 'failed', error: lastError });
    else if (phase === 'unconfirmed') finish({ outcome: 'unconfirmed', ...(lastError ? { error: lastError } : {}) });
    else finish({ outcome: 'kept' });
  });
  dialogEl.addEventListener('close', () => {
    stopClocks();
    // Closed mid-request (sign-in took over): the lock goes with the dialog. Nothing new
    // starts while signed out, and the subject stays refused until the page renders again.
    if (phase === 'sending') releaseLock(heldToken);
    removeEventListener('resize', place);
    vv?.removeEventListener('resize', place);
    vv?.removeEventListener('scroll', place);
    moveAnnouncer(document.body); // before the dialog goes
    dialogEl.remove();
    document.body.style.minHeight = '';
    if (confirmEl === dialogEl) { confirmEl = null; onSignIn = null; }
    // Said once the announcer is back in the page, so the entry is not emptied with the move.
    if (saidAfterClose) announce(saidAfterClose, { subject: 'page' });
    if (!routed) {
      window.scrollTo({ top: before, behavior: 'instant' });
      const back = opener?.isConnected ? opener : document.getElementById('content');
      back.focus({ preventScroll: true });
    }
    settle(outcome);
  });
  // Sign-in takes over before a 401 reaches run()'s handler: a sent request's outcome is not known.
  onSignIn = () => {
    if (phase === 'sending') { unconfirmedKeys().add(key); finish({ outcome: 'unconfirmed' }); } else finish({ outcome: 'kept' });
  };
  keep.addEventListener('click', () => finish({ outcome: 'kept' }));
  close.addEventListener('click', () => finish(phase === 'refusal' ? { outcome: 'failed', error: lastError } : { outcome: 'unconfirmed', ...(lastError ? { error: lastError } : {}) }));

  let lastError = null;
  const show = (kind, words) => {
    phase = kind;
    line.hidden = true;
    note.hidden = false;
    note.replaceChildren(el('p', {}, `⊘ ${words.reason}`), el('p', {}, words.next));
    if (typed) typed.value = '';
    arm();
    const buttons = [close];
    if (words.reload) buttons.push(reload);
    if (words.retry) buttons.push(retry);
    acts.replaceChildren(...buttons);
    place();
    note.focus();
    announce(`${words.reason} ${words.next}`, { subject: 'confirm', guard: { epoch: authEpoch, seq: null } });
  };

  const start = () => {
    if (phase === 'sending' || !matches()) return;
    phase = 'sending';
    const token = {};
    heldToken = token;
    lock = { token };
    const epoch = authEpoch;
    note.hidden = true;
    line.hidden = false;
    line.textContent = progress;
    act.textContent = progress;
    act.disabled = true;
    act.setAttribute('aria-busy', 'true');
    acts.replaceChildren(act);
    place();
    line.focus();
    let open = true;
    const say = setTimeout(() => announce(progress, { subject: 'confirm', guard: { epoch, seq: null } }), CONFIRM_SAY_MS);
    const wait = setTimeout(() => { line.textContent = `${progress} Still waiting for the gateway.`; }, CONFIRM_WAIT_MS);
    const cutoff = setTimeout(() => {
      if (!dialogEl.open) return;
      open = false;
      clearTimeout(say);
      unconfirmedKeys().add(key);
      setTimeout(() => releaseLock(token), LOCK_GRACE_MS);
      showUnconfirmed();
    }, CONFIRM_CUTOFF_MS);
    stopClocks = () => { clearTimeout(say); clearTimeout(wait); clearTimeout(cutoff); };
    const ended = () => { stopClocks(); releaseLock(token); };
    Promise.resolve().then(() => spec.run()).then((value) => {
      ended();
      if (!open || epoch !== authEpoch || !dialogEl.open) return; // stopped waiting, or someone else signed in
      landDone(value);
    }, (err) => {
      ended();
      if (!open || !dialogEl.open) return;
      lastError = err;
      if (err instanceof ApiError && err.status === 401) {
        // Sign-in takes over; the request was sent, so its outcome is not known.
        unconfirmedKeys().add(key);
        finish({ outcome: 'unconfirmed', error: err });
        return;
      }
      const c = classify(err, spec);
      if (c.kind === 'refusal') show('refusal', c);
      else { unconfirmedKeys().add(key); showUnconfirmed(); }
    });
  };
  const showUnconfirmed = () => show('unconfirmed', {
    reason: 'The gateway did not confirm the outcome.', next: `Reload to see whether ${object} changed.`, reload: true,
  });

  const landDone = (value) => {
    let target = null;
    try {
      target = typeof spec.done === 'function' ? spec.done(value) : (spec.done ?? null);
    } catch (err) {
      console.error(err); // the gateway succeeded; only the screen's own words failed
    }
    outcome = { outcome: 'done', value };
    if (!target?.path) {
      finish(outcome);
      return;
    }
    const heading = el('p', { class: 'done-title', tabindex: '-1' }, `✓ ${target.notice ?? ''}`);
    const dismiss = el('button', { type: 'button', class: 'btn quiet' }, 'Dismiss');
    const node = el('section', { class: 'done-notice', 'aria-label': 'Done' }, heading,
      ...(target.action ? [el('a', { href: target.action.path }, target.action.label)] : []), dismiss);
    dismiss.addEventListener('click', () => { node.remove(); doneNotice = null; });
    routed = true;
    finish(outcome);
    go(target.path);
    // Bound to the render go() ended on, after any default-tab redirect: any later
    // navigation, even to the same address, is a new render and drops it.
    doneNotice = { node, seq: renderSeq, epoch: authEpoch };
    document.getElementById('content').prepend(node);
    heading.focus({ preventScroll: true });
    saidAfterClose = target.notice ?? '';
  };

  act.addEventListener('click', start);
  retry.addEventListener('click', start);
  dialogEl.showModal();
  // A modal makes the rest of the page inert, the live region with it: it rides along.
  moveAnnouncer(dialogEl);
  place();
  keep.focus();
  return result;
}

/** Set while a confirmation is open: closes it when sign-in takes over. */
let onSignIn = null;

// ---------------------------------------------------------------- segmented

/**
 * A segmented control: one pressed button among a few (range pickers, view
 * switches). `onChange(value)` runs on a choice; it is the screen's code.
 */
export function segmented({ label, options, value, onChange }) {
  const group = el('div', { class: 'segmented', role: 'group', 'aria-label': label });
  const buttons = options.map(([v, text]) => {
    const b = el('button', { type: 'button', 'aria-pressed': v === value ? 'true' : 'false', 'data-value': v }, text);
    b.addEventListener('click', () => {
      if (b.getAttribute('aria-pressed') === 'true') return;
      for (const other of buttons) other.setAttribute('aria-pressed', other === b ? 'true' : 'false');
      onChange?.(v);
    });
    return b;
  });
  group.append(...buttons);
  return group;
}

// ---------------------------------------------------------------- router

/**
 * Parse /ui/<page>[/<object>][/<tab>]. A lone second segment that names a
 * tab is the tab; an object called like a tab needs its tab spelled out
 * (/ui/servers/status/actions). A hidden tab then falls back to the first.
 */
function parse(pathname) {
  let parts;
  try {
    parts = pathname.replace(/^\/ui\/?/, '').split('/').filter(Boolean).map(decodeURIComponent);
  } catch {
    return { page: null, object: null, tab: null }; // a malformed escape: not-found
  }
  const [page, second, third] = parts;
  if (second !== undefined && third === undefined && TABS.some(([t]) => t === second)) {
    return { page, object: null, tab: second };
  }
  return { page, object: second ?? null, tab: third ?? null };
}

function pathFor({ page, object, tab }) {
  return `/ui/${page}${object ? `/${encodeURIComponent(object)}` : ''}/${tab}`;
}

/** Links the router owns: same origin, a registered sidebar page as the first segment. */
function owned(a) {
  if (!a || a.target || a.hasAttribute('download') || a.origin !== location.origin) return false;
  // A query or a fragment keeps the browser's own behaviour (and its scroll).
  if (a.search || a.hash) return false;
  const first = a.pathname.split('/')[2];
  return a.pathname.startsWith('/ui/') && PAGE_IDS.has(first);
}

export function go(path, { replace = false } = {}) {
  history[replace ? 'replaceState' : 'pushState'](null, '', path);
  render();
}

// ---------------------------------------------------------------- render

let renderSeq = 0;

/** How many routes keep their last good render for a page error to show. */
const SNAPSHOT_LIMIT = 9;
/** The last good render of each recent route, for one signed-in identity only. */
const snapshots = { epoch: -1, byRoute: new Map() };

/** The snapshots of the identity signed in now; a sign-in change empties them. */
function snapshotsNow() {
  if (snapshots.epoch !== authEpoch) {
    snapshots.epoch = authEpoch;
    snapshots.byRoute.clear();
  }
  return snapshots.byRoute;
}

const routeKey = (route) => `${route.page}/${route.object ?? ''}/${route.tab}`;

function saveSnapshot(key, body) {
  const map = snapshotsNow();
  map.delete(key);
  map.set(key, { node: body.cloneNode(true), at: new Date() });
  if (map.size > SNAPSHOT_LIMIT) map.delete(map.keys().next().value);
}

/** A copy of `node` that reads the same but that no one can operate. */
function neutralised(node) {
  const copy = node.cloneNode(true);
  for (const e of [copy, ...copy.querySelectorAll('*')]) {
    e.removeAttribute('id');
    e.removeAttribute('contenteditable');
    for (const { name } of [...e.attributes]) if (name.startsWith('on')) e.removeAttribute(name);
    if (e.matches('a[href]')) e.removeAttribute('href');
    if (e.matches('iframe, object, embed')) {
      for (const attr of ['src', 'srcdoc', 'data']) e.removeAttribute(attr);
      e.setAttribute('tabindex', '-1');
    }
    if (e.matches('button, input, select, textarea')) e.disabled = true;
    if (e.hasAttribute('tabindex') || e.matches('summary')) e.setAttribute('tabindex', '-1');
  }
  return copy;
}

/** HH:MM, and the date too when it is not today. */
function stamp(at) {
  const time = at.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  return at.toDateString() === new Date().toDateString() ? time : `${at.toLocaleDateString()} ${time}`;
}

/** The banner for `err`, over the route's last good data if any, with Retry. */
function failure(err, key, onRetry) {
  const { cause, title, body } = causeOf(err);
  if (cause === 'page-fault') console.error(err);
  const last = snapshotsNow().get(key);
  const retry = el('button', { type: 'button', class: 'btn' }, 'Retry');
  retry.addEventListener('click', () => onRetry(retry));
  const text = last ? `${body} The data below is from ${stamp(last.at)}, before the error.` : body;
  const banner = bannerState('error', { title, body: text, action: retry });
  banner.dataset.cause = cause;
  const node = el('div', { class: 'failure' }, banner);
  if (last) {
    node.append(el('section', { role: 'region', 'aria-label': 'Data from before the error', 'data-dimmed': true }, neutralised(last.node)));
  }
  return node;
}

/** Run a page's tab into `into`; a fault thrown synchronously becomes a rejection. */
const runTab = (spec, route, into) => {
  // Taken when the context is made: a screen holding on to it after the user moved
  // on, or after another identity signed in, announces nothing.
  const guard = { epoch: authEpoch, seq: renderSeq };
  return Promise.resolve().then(() => spec.tabs[route.tab](into, {
    object: route.object, tab: route.tab, api, state,
    show: screenBanner(into, route.page, guard),
    // The title or subtitle a screen sets itself, e.g. a count. A kept one changes nothing
    // later: Retry reuses the render, so a failed attempt is told apart by its container.
    header: (fields) => { if (guardHolds(guard) && into.isConnected) setHeader(fields); },
    refreshCounts,
    announce: (text) => announce(text, { subject: `screen:${route.page}`, guard }),
    confirm: confirmAction,
  }));
};

/**
 * A banner state (error, forbidden, stale) for showBanner() or failure() only:
 * every banner is inserted through showBanner(), which says it.
 */
function bannerState(kind, opts) {
  return state(kind, opts);
}

/** Put a banner node in `container`, and say its heading for the page shown now. */
function showBanner(container, node) {
  setContent(container, mark(node));
  announce(node.querySelector('.state h2, h2').textContent, { subject: 'page' });
}

/**
 * A screen's banner: show(kind, opts) puts one at the top of its content and
 * says its title; show(null) takes it away, saying "Updates resumed." when it
 * was stale.
 */
function screenBanner(into, page, guard) {
  // show(kind, opts) for a page state, show(node) for a built banner such as
  // serverBanner()'s, show(null) to take it away. Either way the shell owns its
  // insertion, its announcement and its removal.
  return (kind, opts = {}) => {
    if (!guardHolds(guard)) return; // a screen the user has left
    const old = into.querySelector(':scope > .state[data-banner]');
    if (kind instanceof Node) {
      kind.dataset.banner = '';
      if (old?.isEqualNode(kind)) return; // the same banner again is no transition
      old?.remove();
      into.removeAttribute('data-stale');
      into.prepend(kind);
      announce(kind.querySelector('h2').textContent, { subject: `screen:${page}`, guard });
      return;
    }
    // The same banner again is no transition: leave it, say nothing.
    if (kind && old?.dataset.state === kind && !opts.title) return;
    old?.remove();
    // While stale, the tab's numbers are dimmed (CSS, [data-stale]).
    into.toggleAttribute('data-stale', kind === 'stale');
    const subject = `screen:${page}`;
    if (!kind) {
      if (old?.dataset.state === 'stale') announce(GLOSSARY.stream.resumed, { subject, guard });
      return;
    }
    const built = kind === 'stale' ? { ...opts, title: staleTitle(opts.since) } : opts;
    const node = bannerState(kind, built);
    node.dataset.banner = '';
    into.prepend(node);
    announce(node.querySelector('h2').textContent, { subject, guard });
  };
}

/**
 * Set the header title and subtitle as text. A title left out or empty stays; a
 * subtitle left out stays, and a null or empty one hides the line. Nothing is
 * announced, so it suits a count read on load, not a value that keeps changing.
 */
function setHeader({ title, subtitle } = {}) {
  if (title) {
    document.querySelector('.head .plate').textContent = title;
    document.title = `${title} · MCP Gateway`;
  }
  if (subtitle !== undefined) {
    const sub = document.querySelector('.head .sub');
    sub.textContent = subtitle ?? '';
    sub.hidden = !subtitle;
  }
}

/** Render the current address. */
export function render() {
  draw(++renderSeq);
}

/**
 * Draw render `seq`. A page whose screen is not loaded yet loads it first,
 * under the loading state, then draws again into the same body with the same
 * loading state (`held`), so a slow load and slow data say "Loading" once.
 */
function draw(seq, held = null) {
  // A Retry left running by the last page has nothing to show here.
  if (!held) document.getElementById('content').removeAttribute('aria-busy');
  const route = parse(location.pathname);
  const label = NAV.find(([id]) => id === route.page)?.[1];
  drawNav(route.page);
  const content = document.getElementById('content');
  const tabsNav = document.querySelector('nav.tabs');
  tabsNav.replaceChildren();

  const tabNamed = route.tab === null || TABS.some(([t]) => t === route.tab);
  if (!label || !tabNamed) {
    setHeader({ title: 'Not found', subtitle: null });
    setContent(content, mark(state('empty', { title: 'No such page', body: 'Pick a page from the list.' })));
    return;
  }
  if (!held && needsLoad(route.page)) {
    setHeader({ title: label, subtitle: null });
    // Not marked: shellReady and the screens wait for the render of the screen itself.
    const body = el('div', { class: 'body' });
    setContent(content, body);
    content.setAttribute('aria-busy', 'true');
    const epoch = authEpoch;
    const current = () => seq === renderSeq && epoch === authEpoch;
    const loading = watchLoading(content, body, label, current);
    loadScreen(route.page).then(
      () => { if (current()) draw(seq, { body, loading }); else loading.release(); },
      (err) => loading.after(() => {
        if (!current()) return;
        showBanner(content, failure(err, routeKey(route), () => render()));
        content.removeAttribute('aria-busy');
      }),
    );
    return;
  }
  const spec = pages.get(route.page);
  const ownHeader = { title: spec?.title ?? label, subtitle: spec?.subtitle ?? null };
  setHeader(ownHeader);
  const tabs = visibleTabs(route.page);
  if (tabs.length === 0) {
    if (held) {
      held.loading.release();
      content.removeAttribute('aria-busy');
    }
    setContent(content, mark(state('not-built')));
    return;
  }
  if (!tabs.some(([t]) => t === route.tab)) {
    if (held) {
      held.loading.release();
      content.removeAttribute('aria-busy');
    }
    go(pathFor({ ...route, tab: tabs[0][0] }), { replace: true });
    return;
  }
  for (const [t, tabLabel] of tabs) {
    const href = pathFor({ ...route, tab: t });
    tabsNav.append(el('a', { href, 'aria-current': t === route.tab ? 'page' : null }, tabLabel));
  }
  const body = held?.body ?? el('div', { class: 'body' });
  // A held body is in place already, under its loading state.
  if (held) mark(body);
  else setContent(content, mark(body));
  // Every effect of this render is dropped once the user navigates or signs in as someone else.
  const epoch = authEpoch;
  const current = () => seq === renderSeq && epoch === authEpoch;
  const key = routeKey(route);

  const settle = (err) => {
    const status = err instanceof ApiError ? err.status : null;
    if (status === 401) return; // the sign-in view is showing; it re-renders after sign-in
    setHeader(ownHeader); // a failed attempt's own header goes with its content
    if (status === 403) {
      snapshotsNow().delete(key); // this identity may no longer see it
      showBanner(content, bannerState('forbidden'));
    } else showBanner(content, failure(err, key, retry));
  };

  // Retry runs the tab again into a staging container laid out under the banner, so the
  // banner and the last data stay until it succeeds.
  const retry = (button) => {
    if (button.disabled) return;
    button.disabled = true;
    button.textContent = 'Retrying…';
    button.setAttribute('aria-busy', 'true');
    content.setAttribute('aria-busy', 'true');
    const stage = el('div', { class: 'body staging' });
    content.append(stage);
    const loading = watchLoading(content, stage, label, current);
    const teardown = () => {
      if (stage.classList.contains('staging')) stage.remove();
      if (current()) content.removeAttribute('aria-busy');
    };
    runTab(spec, route, stage)
      .then(() => loading.after(() => {
        if (current()) {
          stage.classList.remove('staging');
          setContent(content, mark(stage));
          saveSnapshot(key, stage);
          content.focus({ preventScroll: true });
        }
        teardown();
      }))
      .catch((err) => loading.after(() => {
        if (current()) {
          settle(err);
          const again = content.querySelector('[data-state="error"] button');
          if (again) again.focus();
          else content.focus({ preventScroll: true });
        }
        teardown();
      }));
  };

  const loading = held?.loading ?? watchLoading(content, body, label, current);
  // Busy from the first render's start until it settles (data, error or empty), as a Retry is.
  content.setAttribute('aria-busy', 'true');
  runTab(spec, route, body)
    .then(() => {
      // The data is already in the body, under the loading state: let it go after its minimum.
      // Busy ends when the loading state does, never while it still covers the arrived content.
      loading.release(() => { if (current()) content.removeAttribute('aria-busy'); });
      if (current()) saveSnapshot(key, body);
    })
    .catch((err) => loading.after(() => {
      if (!current()) return;
      settle(err);
      content.removeAttribute('aria-busy');
    }));
}

/** How long a page may wait for its data before the shell says it is loading (UI1.17). */
const LOADING_MS = 300;
/** Once shown, the loading state stays this long, so it never flickers. */
const LOADING_MIN_MS = 400;

/**
 * Show the loading state above `body`, and say it once, if this attempt has
 * nothing to show after LOADING_MS. When the attempt settles:
 * - after(swap) waits out the rest of LOADING_MIN_MS if the state is up, takes
 *   it away, then runs `swap` (an error, a 403, a Retry's result), so a state
 *   shown at 300 ms is never replaced 10 ms later;
 * - release(done) is for data already drawn under it: it goes after its minimum, then `done` runs.
 * Either withdraws a loading message not yet said.
 */
function watchLoading(content, body, label, current) {
  let node = null;
  let shownAt = 0;
  let withdraw = null;
  const guard = { epoch: authEpoch, seq: renderSeq };
  const timer = setTimeout(() => {
    // A screen that drew anything, even its own loading state, has said enough.
    if (!current() || body.hasChildNodes() || !body.isConnected) return;
    node = state('loading');
    content.insertBefore(node, body);
    shownAt = Date.now();
    withdraw = announce(`Loading ${label}`, { subject: 'page', guard });
  }, LOADING_MS);
  const stop = () => {
    clearTimeout(timer);
    withdraw?.();
  };
  const left = () => (node ? Math.max(0, LOADING_MIN_MS - (Date.now() - shownAt)) : 0);
  return {
    after(swap) {
      stop();
      const finish = () => {
        node?.remove();
        swap();
      };
      const wait = left();
      if (wait > 0) setTimeout(finish, wait);
      else finish();
    },
    release(done) {
      stop();
      const wait = left();
      const finish = () => {
        node?.remove();
        done?.();
      };
      if (wait > 0) setTimeout(finish, wait);
      else finish();
    },
  };
}

/** Mark a node as the rendered content (tests and screens wait on it). */
function mark(node) {
  node.setAttribute('data-rendered', '');
  return node;
}

/** The decisions count for the sidebar badge; null hides it. */
const DECISIONS = { count: null };

/** Build the sidebar once, then update it in place, so a focused link is never replaced. */
function drawNav(current) {
  const nav = document.querySelector('nav.route-nav');
  if (!nav.childElementCount) {
    nav.append(...NAV.map(([id, label]) => el('a', { class: 'stn', href: `/ui/${id}`, 'data-page': id },
      el('i', { 'aria-hidden': 'true' }), el('span', { class: 'lbl' }, label))));
  }
  for (const a of nav.children) {
    if (a.dataset.page === current) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  }
  const decide = nav.querySelector(`[data-page="${NAV[1][0]}"]`);
  let badge = decide.querySelector('.count');
  const n = DECISIONS.count;
  // A count that failed reads "?", never a missing badge that looks like zero (UI1.22).
  const unavailable = n === 'unavailable';
  if (unavailable || (Number.isInteger(n) && n > 0)) {
    if (!badge) decide.append(badge = el('span', { class: 'count' }), el('span', { class: 'sr-only count-words' }));
    badge.textContent = unavailable ? '?' : String(n);
    // The link's name comes from its text: the words sit beside the number, unseen.
    decide.querySelector('.count-words').textContent = unavailable ? ' count unavailable' : ' to decide';
  } else {
    badge?.remove();
    decide.querySelector('.count-words')?.remove();
  }
}

/** The last count this identity saw, kept through stretches where none is known. */
const COUNT_SEEN = { epoch: -1, value: null };
/** Orders count requests: an answer to an older one is dropped. */
let countSeq = 0;

/**
 * Read the To do count and draw it; say it when a value this identity already
 * knew changes (UI1.18). Its callers: start-up, sign-in, and, through the
 * render context, the screens and the live stream that change it.
 */
export async function refreshCounts() {
  const epoch = authEpoch;
  const seq = ++countSeq;
  let next = null;
  try {
    const reply = await api('/ui/api/decisions/count');
    next = Number.isInteger(reply?.count) && reply.count >= 0 ? reply.count : 'unavailable';
  } catch (err) {
    // A 404: the route ships with the To do queue, so until then no badge.
    // Anything else failed and reads "?".
    next = err instanceof ApiError && err.status === 404 ? null : 'unavailable';
  }
  if (epoch !== authEpoch || seq !== countSeq) return; // a newer read, or another identity, owns the badge now
  DECISIONS.count = next;
  drawNav(parse(location.pathname).page);
  if (COUNT_SEEN.epoch !== epoch) {
    COUNT_SEEN.epoch = epoch; // a new identity's first count is not news
    COUNT_SEEN.value = Number.isInteger(next) ? next : null;
    return;
  }
  if (!Number.isInteger(next)) return; // not a value: nothing to say, and the last one is kept
  if (Number.isInteger(COUNT_SEEN.value) && COUNT_SEEN.value !== next) {
    announce(next === 0 ? 'Nothing to decide.' : `${next} to decide.`, { subject: 'count' });
  }
  COUNT_SEEN.value = next;
}

/** Read who is signed in; when auth is on and nobody is, ask for sign-in. */
async function loadWho() {
  const epoch = authEpoch;
  try {
    const { auth } = await api('/ui/api/status');
    if (epoch !== authEpoch) return true; // answered for a session that has since signed in
    if (auth?.enabled && !auth.signed_in) {
      showSignIn();
      return false;
    }
    showWho(auth);
    return true;
  } catch {
    return false; // a 401 already shows sign-in; other failures show in the page states
  }
}

// ---------------------------------------------------------------- sign-in

/**
 * The top bar's sign-in line, and sign-out offered only to a signed-in
 * session: in the top bar from 641 px up, as the phone menu's last row below.
 */
function showWho(auth) {
  const signedIn = Boolean(auth?.signed_in);
  document.querySelector('.top .who').textContent = signedIn ? (auth.admin ? 'Signed in · admin' : 'Signed in') : '';
  for (const b of document.querySelectorAll('.signout')) b.hidden = !signedIn;
  showEnvironment(auth);
}

/** The sign-in whose environment chip is drawn or on its way; null while there is none. */
let envEpoch = null;

/**
 * The environment chip: the gateway environment name, in the top bar of every
 * page, for an admin key only. Read once per sign-in. Any refusal or failure
 * (a 403 for another key, a 404 from a gateway without the route) leaves it
 * out, silently: the chip is a hint, never an error. A name the gateway fell
 * back to (the hostname, or its default) says so in a tooltip.
 */
async function showEnvironment(auth) {
  const epoch = authEpoch;
  if (envEpoch === epoch && auth?.admin === true) return;
  document.querySelector('.top .envchip')?.remove();
  envEpoch = null;
  if (!auth?.signed_in || auth.admin !== true) return;
  envEpoch = epoch;
  let environment;
  try {
    ({ environment } = await api('/ui/api/gateway'));
  } catch {
    return;
  }
  const name = environment?.name;
  if (epoch !== authEpoch || envEpoch !== epoch || typeof name !== 'string' || name === '') return;
  const chip = document.createElement('span');
  chip.className = 'env';
  chip.setAttribute('role', 'img');
  chip.setAttribute('aria-label', `Environment: ${name}`);
  chip.textContent = name;
  const wrap = document.createElement('span');
  wrap.className = 'envchip';
  wrap.append(chip);
  document.querySelector('.top .mbrand').after(wrap);
  const source = environment.source;
  if (source !== 'hostname' && source !== 'default') return;
  // The tooltip module and its stylesheet load only when a fallback name needs them.
  let m;
  try {
    m = await import('/ui/assets/tooltip.32447d51da98.js');
  } catch {
    return;
  }
  if (!wrap.isConnected) return;
  wrap.append(source === 'hostname' ? m.tip('gateway.status.environment-from-hostname') : m.tip('gateway.status.environment-not-set'));
}

/**
 * Sign out: forget the typed key, end the cookie session on the server
 * (POST /dashboard/logout revokes it there, not only in this browser), and
 * show sign-in at the same address. The key goes first, so a slow or failed
 * logout never leaves it usable. The session cookie outlives the browser
 * (it has a Max-Age), so until the gateway confirms the logout the sign-in
 * view says the session is still being ended; a logout that fails, or does
 * not answer within the key check's deadline, says this browser may still be
 * signed in. An answer arriving after a newer sign-in changes nothing.
 */
/**
 * Show a sign-in message and say it through the one live region. Only a key
 * the gateway refused marks the key field invalid; any other outcome clears it.
 */
function signinMessage(node, text, { subject, refusedKey = false }) {
  node.textContent = text;
  node.hidden = false;
  announce(text, { subject });
  if (node.classList.contains('signin-error')) markKey(refusedKey);
}

/** Tie the key field to the error line while a refused key shows, and only then. */
function markKey(refused) {
  const input = document.getElementById('signin-key');
  if (refused) {
    input.setAttribute('aria-invalid', 'true');
    input.setAttribute('aria-describedby', 'signin-error');
  } else {
    input.removeAttribute('aria-invalid');
    input.removeAttribute('aria-describedby');
  }
}

async function signOut() {
  bearer = null;
  const epoch = ++authEpoch;
  // The identity changed with no re-render: a load still running can no longer clear this itself.
  document.getElementById('content').removeAttribute('aria-busy');
  showWho(null);
  // Its own status line, apart from the key check's error: a key typed while
  // the logout is pending must not hide this, nor this overwrite its answer.
  const notice = document.querySelector('.signin-notice');
  showSignIn();
  signinMessage(notice, 'Ending the session on the gateway…', { subject: 'signin-session' });
  let ended = false;
  try {
    const reply = await fetch('/dashboard/logout', {
      method: 'POST',
      credentials: 'same-origin',
      redirect: 'manual',
      keepalive: true,
      signal: AbortSignal.timeout(KEY_CHECK_MS),
    });
    ended = reply.ok || reply.type === 'opaqueredirect';
  } catch {
    ended = false;
  }
  if (epoch !== authEpoch) return;
  if (ended) {
    notice.hidden = true;
    notice.textContent = '';
    announce('Signed out.', { subject: 'signin-session' });
  } else {
    signinMessage(notice, "Signed out here, but the gateway did not confirm the session ended, so this browser may still be signed in. Reload and sign out again, or clear this site's cookies.", { subject: 'signin-session' });
  }
}

/**
 * Show the sign-in view at the current address, so the same page and tab
 * render after sign-in. A cookie session comes from the one-time link or
 * the handoff code; a key typed here is held in this module only (never in
 * storage, a cookie or the URL), so a reload asks for it again.
 */
function showSignIn() {
  if (document.body.classList.contains('signed-out')) return;
  closeMenu();
  paletteEl?.close(); // a modal palette would keep the key field inert
  onSignIn?.(); // and so would an open confirmation
  document.body.classList.add('signed-out');
  document.getElementById('signin').hidden = false;
  document.querySelector('.signin-host').textContent = location.host;
  document.getElementById('signin-key').focus();
}

/**
 * The rate-limited key check's message. `Retry-After` is read as whole
 * seconds; any other form (an HTTP date, a typo) falls back to a minute,
 * the gateway's own default wait.
 */
function rateLimited(retryAfter) {
  const seconds = /^\d+$/.test(retryAfter ?? '') ? Number(retryAfter) : 0;
  const wait = seconds === 1 ? '1 second' : seconds > 0 ? `${seconds} seconds` : 'a minute';
  return `The gateway is limiting sign-in attempts. Wait ${wait}, then try again.`;
}

let signingIn = false;
/** Set once the user submits a key: from then on its answer owns the error line. */
let keyCheckStarted = false;
/** How long a key check may take before it counts as unreachable. */
const KEY_CHECK_MS = 10_000;

/**
 * Check a typed key on its own and keep it only if it signs in. The check
 * leaves cookies off the request (credentials: 'omit'), so an existing
 * session cookie can never make a wrong key look accepted.
 */
async function signIn(ev) {
  ev.preventDefault();
  keyCheckStarted = true;
  if (signingIn) return;
  const input = document.getElementById('signin-key');
  const error = document.querySelector('.signin-error');
  const button = document.querySelector('#signin button[type="submit"]');
  const key = input.value.trim();
  error.hidden = true;
  markKey(false);
  if (!key) {
    signinMessage(error, 'Paste an API key, or use the sign-in link.', { subject: 'signin-key', refusedKey: true });
    return;
  }
  const form = document.getElementById('signin-form');
  signingIn = true;
  button.disabled = true;
  button.textContent = 'Checking…';
  form.setAttribute('aria-busy', 'true');
  let auth = null;
  let message = '';
  let refused = false;
  try {
    // A gateway that takes the connection but never answers must not leave
    // the button disabled: give up after the check's own deadline.
    const reply = await fetch('/ui/api/status', {
      credentials: 'omit',
      headers: { Authorization: `Bearer ${key}` },
      signal: AbortSignal.timeout(KEY_CHECK_MS),
    });
    if (reply.ok) auth = (await reply.json())?.auth ?? null;
    else if (reply.status === 403) message = 'That key is valid, but it is not allowed into the web UI. Ask an admin for access.';
    else if (reply.status === 429) message = rateLimited(reply.headers.get('retry-after'));
    else if (reply.status !== 401) message = 'Could not reach the gateway. Try again.';
    // The gateway judged the key itself (a network failure or a rate limit did not).
    refused = reply.ok || reply.status === 401 || reply.status === 403;
  } catch {
    message = 'Could not reach the gateway. Try again.';
  } finally {
    signingIn = false;
    button.disabled = false;
    button.textContent = 'Sign in';
    form.removeAttribute('aria-busy');
  }
  if (!auth?.signed_in) {
    signinMessage(error, message || 'That key was not accepted.', { subject: 'signin-key', refusedKey: refused });
    input.select();
    return;
  }
  markKey(false);
  bearer = key;
  // A newer sign-in supersedes a pending or unconfirmed sign-out's notice.
  const notice = document.querySelector('.signin-notice');
  notice.hidden = true;
  notice.textContent = '';
  authEpoch++;
  input.value = '';
  document.getElementById('signin').hidden = true;
  document.body.classList.remove('signed-out');
  showWho(auth);
  render();
  refreshCounts();
  document.getElementById('content').focus({ preventScroll: true });
}

/** The phone menu: the sidebar shown as a sheet under the top bar. */
function openMenu() {
  document.body.classList.add('menu-open');
  document.querySelector('button.menu').setAttribute('aria-expanded', 'true');
  document.querySelector('nav.route-nav a')?.focus();
}

function closeMenu() {
  document.body.classList.remove('menu-open');
  document.querySelector('button.menu').setAttribute('aria-expanded', 'false');
}

/**
 * The gateway sends a browser whose sign-in link or code was refused here
 * with `?signin=link-refused`, one fixed word for every cause. Take it off the
 * address so a reload or a shared link does not repeat it, and say whether it
 * was there. Any other value is left alone and means nothing.
 */
function takeLinkRefused() {
  const url = new URL(location.href);
  if (url.searchParams.get('signin') !== 'link-refused') return false;
  url.searchParams.delete('signin');
  history.replaceState(history.state, '', url.pathname + url.search + url.hash);
  return true;
}

function boot() {
  const linkRefused = takeLinkRefused();
  document.addEventListener('click', (ev) => {
    if (ev.defaultPrevented || ev.button !== 0 || ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey) return;
    const a = ev.target.closest?.('a');
    if (!owned(a)) return;
    ev.preventDefault();
    // Read where the link sits before rendering replaces it.
    const fromTabs = Boolean(a.closest('nav.tabs'));
    closeMenu();
    if (a.pathname !== location.pathname) go(a.pathname);
    // A tab keeps focus (on its replacement) so the next tab is one key
    // away; any other link hands focus to the new content, as a load would.
    if (fromTabs) document.querySelector('nav.tabs a[aria-current="page"]')?.focus();
    else document.getElementById('content').focus({ preventScroll: true });
  });
  const search = document.querySelector('button.search');
  search.addEventListener('click', openPalette);
  // The hint names the key this platform uses; both work everywhere.
  if (!/Mac|iPhone|iPad/.test(navigator.platform)) search.querySelector('kbd').textContent = 'Ctrl K';
  document.addEventListener('keydown', (ev) => {
    if ((ev.metaKey || ev.ctrlKey) && !ev.shiftKey && !ev.altKey && ev.key.toLowerCase() === 'k') {
      ev.preventDefault();
      openPalette();
    }
  });
  const menu = document.querySelector('button.menu');
  menu.addEventListener('click', () => (document.body.classList.contains('menu-open') ? closeMenu() : openMenu()));
  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape' && document.body.classList.contains('menu-open')) {
      closeMenu();
      menu.focus();
    }
  });
  addEventListener('popstate', render);
  document.getElementById('signin-form').addEventListener('submit', signIn);
  for (const b of document.querySelectorAll('.signout')) b.addEventListener('click', signOut);
  document.querySelector('a.skip').addEventListener('click', (ev) => {
    ev.preventDefault();
    document.getElementById('content').focus();
  });
  render();
  // The other screens load once the first paint is out, when the browser is idle,
  // so the palette lists their actions and settings and a later visit is instant.
  // Without paint timing they load after this first render instead; either way
  // the rest of boot runs.
  const preload = () => (window.requestIdleCallback ?? ((fn) => setTimeout(fn, 50)))(loadAllScreens);
  try {
    if (!PerformanceObserver.supportedEntryTypes?.includes('paint')) throw new Error('no paint timing');
    new PerformanceObserver((list, observer) => {
      if (!list.getEntriesByName('first-contentful-paint').length) return;
      observer.disconnect();
      preload();
    }).observe({ type: 'paint', buffered: true });
  } catch {
    preload();
  }
  refreshCounts();
  loadWho().then(() => {
    // Only a browser still signed out is told; one with a session has nothing to fix.
    // A key check the user has started owns the error line; a late startup
    // answer must not write over it.
    if (!linkRefused || keyCheckStarted || !document.body.classList.contains('signed-out')) return;
    const error = document.querySelector('.signin-error');
    signinMessage(error, 'That sign-in link or code did not work. It may be wrong, already used or expired. Run `mcp-gateway dashboard-link` on the gateway’s machine for a new one.', { subject: 'signin-link' });
  });
}

document.addEventListener('DOMContentLoaded', boot);
