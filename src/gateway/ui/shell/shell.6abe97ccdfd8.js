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

const STATE_COPY = {
  loading: ['Loading', 'Reading the gateway.'],
  empty: ['Nothing here yet', ''],
  error: ['Could not reach the gateway', 'The numbers below may be out of date.'],
  forbidden: ['Not available to this key', 'Ask an admin for access.'],
  stale: ['Updates stopped', 'Reconnecting.'],
  'not-built': ['Not built yet', 'This page is not in the new UI yet.'],
};

/** A page state (loading, empty, error, forbidden, stale, not-built). */
export function state(kind, { title, body, action } = {}) {
  const [defTitle, defBody] = STATE_COPY[kind] ?? STATE_COPY.error;
  const role = kind === 'loading' || kind === 'stale' ? 'status' : kind === 'error' || kind === 'forbidden' ? 'alert' : null;
  const node = el('section', { class: 'state', 'data-state': kind, role }, el('h2', {}, title ?? defTitle));
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

/** An error from /ui/api with its HTTP status. */
export class ApiError extends Error {
  constructor(status, path) {
    super(`${path} answered ${status}`);
    this.status = status;
  }
}

/** GET (or another method) on /ui/api with the session cookie, or the key held in memory. */
export async function api(path, init = {}) {
  const headers = new Headers(init.headers);
  if (bearer) headers.set('Authorization', `Bearer ${bearer}`);
  const epoch = authEpoch;
  const reply = await fetch(path, { credentials: 'same-origin', ...init, headers });
  // A 401 to a request sent before the latest sign-in says nothing about now.
  if (reply.status === 401 && epoch === authEpoch) showSignIn();
  if (!reply.ok) throw new ApiError(reply.status, path);
  return reply.status === 204 ? null : reply.json();
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

/** Render the current address. */
export function render() {
  const seq = ++renderSeq;
  const route = parse(location.pathname);
  const label = NAV.find(([id]) => id === route.page)?.[1];
  drawNav(route.page);
  const content = document.getElementById('content');
  const plate = document.querySelector('.head .plate');
  const tabsNav = document.querySelector('nav.tabs');
  tabsNav.replaceChildren();

  const tabNamed = route.tab === null || TABS.some(([t]) => t === route.tab);
  if (!label || !tabNamed) {
    plate.textContent = 'Not found';
    document.title = 'Not found · MCP Gateway';
    document.querySelector('.head .sub').hidden = true;
    content.replaceChildren(mark(state('empty', { title: 'No such page', body: 'Pick a page from the list.' })));
    return;
  }
  const spec = pages.get(route.page);
  plate.textContent = spec?.title ?? label;
  const sub = document.querySelector('.head .sub');
  sub.textContent = spec?.subtitle ?? '';
  sub.hidden = !spec?.subtitle;
  document.title = `${spec?.title ?? label} · MCP Gateway`;
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
  Promise.resolve()
    .then(() => spec.tabs[route.tab](body, { object: route.object, tab: route.tab, api, state }))
    .catch((err) => {
      if (seq !== renderSeq) return;
      const status = err instanceof ApiError ? err.status : 0;
      if (status === 401) return; // the sign-in view is showing; it re-renders after sign-in
      content.replaceChildren(mark(state(status === 403 ? 'forbidden' : 'error')));
    });
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
  if (Number.isInteger(n) && n > 0) {
    if (!badge) decide.append(badge = el('span', { class: 'count' }));
    badge.textContent = String(n);
    badge.setAttribute('aria-label', `${n} to decide`);
  } else {
    badge?.remove();
  }
}

async function loadCounts() {
  try {
    const { count } = await api('/ui/api/decisions/count');
    DECISIONS.count = Number.isInteger(count) ? count : null;
  } catch {
    DECISIONS.count = null; // the count route ships with the To do queue; until then no badge
  }
  drawNav(parse(location.pathname).page);
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
 * logout never leaves it usable. Logout answers with a redirect; any other
 * answer, or none, means the cookie session may still be open, and the
 * sign-in view says so rather than look like a clean sign-out.
 */
async function signOut() {
  bearer = null;
  authEpoch++;
  showWho(null);
  const error = document.querySelector('.signin-error');
  error.hidden = true;
  showSignIn();
  let ended = false;
  try {
    const reply = await fetch('/dashboard/logout', { method: 'POST', credentials: 'same-origin', redirect: 'manual' });
    ended = reply.ok || reply.type === 'opaqueredirect';
  } catch {
    ended = false;
  }
  if (!ended) {
    error.textContent = 'Signed out here, but the gateway did not confirm the browser session ended. Close the browser to end it.';
    error.hidden = false;
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

let signingIn = false;
/** How long a key check may take before it counts as unreachable. */
const KEY_CHECK_MS = 10_000;

/**
 * Check a typed key on its own and keep it only if it signs in. The check
 * leaves cookies off the request (credentials: 'omit'), so an existing
 * session cookie can never make a wrong key look accepted.
 */
async function signIn(ev) {
  ev.preventDefault();
  if (signingIn) return;
  const input = document.getElementById('signin-key');
  const error = document.querySelector('.signin-error');
  const button = document.querySelector('#signin button[type="submit"]');
  const key = input.value.trim();
  error.hidden = true;
  if (!key) {
    error.textContent = 'Paste an API key, or use the sign-in link.';
    error.hidden = false;
    return;
  }
  const form = document.getElementById('signin-form');
  signingIn = true;
  button.disabled = true;
  button.textContent = 'Checking…';
  form.setAttribute('aria-busy', 'true');
  let auth = null;
  let message = '';
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
    else if (reply.status !== 401) message = 'Could not reach the gateway. Try again.';
  } catch {
    message = 'Could not reach the gateway. Try again.';
  } finally {
    signingIn = false;
    button.disabled = false;
    button.textContent = 'Sign in';
    form.removeAttribute('aria-busy');
  }
  if (!auth?.signed_in) {
    error.textContent = message || 'That key was not accepted.';
    error.hidden = false;
    input.select();
    return;
  }
  bearer = key;
  authEpoch++;
  input.value = '';
  document.getElementById('signin').hidden = true;
  document.body.classList.remove('signed-out');
  showWho(auth);
  render();
  loadCounts();
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

function boot() {
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
  loadCounts();
  loadWho();
}

document.addEventListener('DOMContentLoaded', boot);
