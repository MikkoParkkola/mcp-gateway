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

/** Register a page: `{title, tabs: {status, actions, settings}, entries}`. A null tab is hidden. */
export function register(id, spec) {
  if (!PAGE_IDS.has(id)) throw new Error(`register: no sidebar page ${id}`);
  pages.set(id, spec);
}

/** The palette's entries: every page and visible tab, plus each page's declared entries. Navigation only. */
export function entries() {
  const out = [];
  for (const [id, label] of NAV) {
    for (const [tab, tabLabel] of visibleTabs(id)) out.push({ label: `${label} › ${tabLabel}`, path: `/ui/${id}/${tab}` });
    for (const e of pages.get(id)?.entries ?? []) out.push({ label: String(e.label), path: String(e.path) });
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
  const role = kind === 'loading' || kind === 'stale' ? 'status' : kind === 'error' ? 'alert' : null;
  const node = el('section', { class: 'state', 'data-state': kind, role }, el('h2', {}, title ?? defTitle));
  const text = body ?? defBody;
  if (text) node.append(el('p', { class: 'muted' }, text));
  if (kind === 'not-built') node.append(el('p', {}, el('a', { class: 'lnk', href: '/ui/classic' }, 'Open the classic page')));
  if (action) node.append(action);
  return node;
}

// ---------------------------------------------------------------- api

let bearer = null;

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
  const reply = await fetch(path, { credentials: 'same-origin', ...init, headers });
  if (!reply.ok) throw new ApiError(reply.status, path);
  return reply.status === 204 ? null : reply.json();
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
  // A query, or a fragment on this same page, keeps the browser's own behaviour.
  if (a.search || (a.hash && a.pathname === location.pathname)) return false;
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

  if (!label) {
    plate.textContent = 'Not found';
    content.replaceChildren(mark(state('empty', { title: 'No such page', body: 'Pick a page from the list.' })));
    return;
  }
  const spec = pages.get(route.page);
  plate.textContent = spec?.title ?? label;
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

async function loadWho() {
  try {
    const { auth } = await api('/ui/api/status');
    document.querySelector('.top .who').textContent = auth?.signed_in ? (auth.admin ? 'Signed in · admin' : 'Signed in') : '';
  } catch {
    // the page states report reachability; the label just stays empty
  }
}

function boot() {
  document.addEventListener('click', (ev) => {
    if (ev.defaultPrevented || ev.button !== 0 || ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey) return;
    const a = ev.target.closest?.('a');
    if (!owned(a)) return;
    ev.preventDefault();
    if (a.pathname !== location.pathname) go(a.pathname + a.hash);
    // A tab keeps focus so the next tab is one key away; any other link
    // hands focus to the new content, as a page load would.
    if (!a.closest('nav.tabs')) document.getElementById('content').focus({ preventScroll: true });
  });
  addEventListener('popstate', render);
  document.querySelector('a.skip').addEventListener('click', (ev) => {
    ev.preventDefault();
    document.getElementById('content').focus();
  });
  render();
  loadCounts();
  loadWho();
}

document.addEventListener('DOMContentLoaded', boot);
