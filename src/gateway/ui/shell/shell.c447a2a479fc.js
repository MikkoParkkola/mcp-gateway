// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The web UI shell: sidebar, page title, tabs in the address, page states
// and the authenticated API client. Screens register a page; the shell owns
// the URL. Page modules run before DOMContentLoaded and call register(), so
// the first render already knows them. All text goes in with textContent.

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
  const draw = () => {
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
    active = Math.min(active, Math.max(options.length - 1, 0));
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
  search?.setAttribute('aria-expanded', 'true');
  paletteEl.showModal();
  // A modal makes the rest of the page inert, the live region with it: it rides along.
  moveAnnouncer(paletteEl);
  input.focus();
}

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
  container.replaceChildren(mark(node));
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
  const seq = ++renderSeq;
  // A Retry left running by the last page has nothing to show here.
  document.getElementById('content').removeAttribute('aria-busy');
  const route = parse(location.pathname);
  const label = NAV.find(([id]) => id === route.page)?.[1];
  drawNav(route.page);
  const content = document.getElementById('content');
  const tabsNav = document.querySelector('nav.tabs');
  tabsNav.replaceChildren();

  const tabNamed = route.tab === null || TABS.some(([t]) => t === route.tab);
  if (!label || !tabNamed) {
    setHeader({ title: 'Not found', subtitle: null });
    content.replaceChildren(mark(state('empty', { title: 'No such page', body: 'Pick a page from the list.' })));
    return;
  }
  const spec = pages.get(route.page);
  const ownHeader = { title: spec?.title ?? label, subtitle: spec?.subtitle ?? null };
  setHeader(ownHeader);
  const tabs = visibleTabs(route.page);
  if (tabs.length === 0) {
    content.replaceChildren(mark(state('not-built')));
    return;
  }
  if (!tabs.some(([t]) => t === route.tab)) {
    go(pathFor({ ...route, tab: tabs[0][0] }), { replace: true });
    return;
  }
  for (const [t, tabLabel] of tabs) {
    const href = pathFor({ ...route, tab: t });
    tabsNav.append(el('a', { href, 'aria-current': t === route.tab ? 'page' : null }, tabLabel));
  }
  const body = el('div', { class: 'body' });
  content.replaceChildren(mark(body));
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
          content.replaceChildren(mark(stage));
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

  const loading = watchLoading(content, body, label, current);
  runTab(spec, route, body)
    .then(() => {
      // The data is already in the body, under the loading state: let it go after its minimum.
      loading.release();
      if (current()) saveSnapshot(key, body);
    })
    .catch((err) => loading.after(() => { if (current()) settle(err); }));
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
 * - release() is for data already drawn under it: it goes after its minimum.
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
    release() {
      stop();
      const wait = left();
      if (!node) return;
      if (wait > 0) setTimeout(() => node.remove(), wait);
      else node.remove();
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
