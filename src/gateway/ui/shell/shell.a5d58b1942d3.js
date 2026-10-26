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

// ---------------------------------------------------------------- tooltips

/** How long the first render waits for the tooltip copy before going on without it. */
const TIPS_WAIT_MS = 1_500;
let tipsCopy = null; // id -> entry, once loaded; stays null if loading failed or was late
let tipsDone = null;
let tipSeq = 0;

/**
 * Start loading the copy once and resolve when it has loaded, failed, or
 * taken longer than TIPS_WAIT_MS, whichever comes first. A failure or a
 * late answer leaves no copy, so every tip call draws nothing, and the page
 * renders regardless.
 */
export function tipsReady() {
  if (tipsDone) return tipsDone;
  let settled = false;
  tipsDone = new Promise((resolve) => {
    const finish = (copy, why) => {
      if (settled) return;
      settled = true;
      tipsCopy = copy;
      if (why) console.warn(`tooltip copy not loaded (${why}); tooltips are left out`);
      resolve();
    };
    setTimeout(() => finish(null, `no answer in ${TIPS_WAIT_MS} ms`), TIPS_WAIT_MS);
    fetch('/ui/assets/tips.eed0441539d0.json', { credentials: 'same-origin' })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then((copy) => finish(copy, null), (err) => finish(null, err.message));
  });
  return tipsDone;
}

const warnedIds = new Set();

function tipEntry(id) {
  const entry = tipsCopy?.[id];
  if (!entry && tipsCopy && !warnedIds.has(id)) {
    warnedIds.add(id);
    console.warn(`tooltip copy has no entry ${id}; its trigger is left out`);
  }
  return entry && typeof entry.title === 'string' ? entry : null;
}

function tipBody(entry) {
  if (Array.isArray(entry.rows)) {
    const dl = el('dl', { class: 'tip-rows' });
    for (const [label, value] of entry.rows) dl.append(el('div', {}, el('dt', {}, String(label)), el('dd', {}, String(value))));
    return dl;
  }
  return el('span', { class: 'tip-body' }, String(entry.text ?? ''));
}

/**
 * The (i) trigger for a copy id: a button named "About {title}", described by
 * one role="tooltip" element holding the copy, inside a .has-tip wrapper. The
 * title is hidden from the description because the name already says it. It
 * returns null when there is no copy for the id, so no empty description is
 * ever announced. Call with a literal id; the copy check reads them.
 */
export function tip(id) {
  const entry = tipEntry(id);
  if (!entry) return null;
  const tid = `tip-${++tipSeq}`;
  return el('span', { class: 'has-tip' },
    el('button', { type: 'button', class: 'tip-i', 'aria-label': `About ${entry.title}`, 'aria-describedby': tid }, 'i'),
    el('span', { class: 'tip', role: 'tooltip', id: tid }, el('strong', { class: 'tip-title', 'aria-hidden': 'true' }, entry.title), tipBody(entry)));
}

/**
 * The same trigger as HTML text, for pages rendered without JavaScript:
 * the stylesheet shows it on hover and focus there. Every value is escaped.
 */
const markupSeq = new Map();

export function tipMarkup(id) {
  const entry = tipEntry(id);
  if (!entry) return '';
  const esc = (v) => String(v).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
  // Ids stay stable for the first trigger of an id, and distinct after it.
  const slug = `tip-${id.replace(/[^a-z0-9-]/g, '-')}`;
  const n = (markupSeq.get(slug) ?? 0) + 1;
  markupSeq.set(slug, n);
  const tid = n === 1 ? slug : `${slug}-${n}`;
  const body = Array.isArray(entry.rows)
    ? `<dl class="tip-rows">${entry.rows.map(([l, v]) => `<div><dt>${esc(l)}</dt><dd>${esc(v)}</dd></div>`).join('')}</dl>`
    : `<span class="tip-body">${esc(entry.text ?? '')}</span>`;
  return `<span class="has-tip"><button type="button" class="tip-i" aria-label="About ${esc(entry.title)}" aria-describedby="${tid}">i</button>`
    + `<span class="tip" role="tooltip" id="${tid}"><strong class="tip-title" aria-hidden="true">${esc(entry.title)}</strong>${body}</span></span>`;
}

/** Hover opens after 300 ms; leaving closes after 150 ms; focus, Enter, Space and tap open at once; Esc closes. */
const TIP_OPEN_MS = 300;
const TIP_CLOSE_MS = 150;
/** The popup keeps this far from the viewport's sides (its width leaves 2 x 8 px). */
const TIP_MARGIN = 8;
/** The gap between trigger and popup, as in the stylesheet. */
const TIP_GAP = 6;
let openTip = null;
let tipTimer = 0;

function showTip(wrap) {
  clearTimeout(tipTimer);
  if (openTip && openTip !== wrap) hideTip(openTip);
  openTip = wrap;
  const pop = wrap.querySelector('.tip');
  pop.classList.add('open');
  placeTip(wrap, pop);
}

function hideTip(wrap) {
  wrap.querySelector('.tip')?.classList.remove('open', 'flip-y');
  if (openTip === wrap) openTip = null;
}

/** Below the trigger, left edges aligned; slide left and flip up to stay inside the viewport, never over the trigger. */
function placeTip(wrap, pop) {
  pop.classList.remove('flip-y');
  pop.style.left = '';
  pop.style.maxHeight = '';
  const r = pop.getBoundingClientRect();
  // Slide left by what overflows the right edge, never past the left margin:
  // on a narrow screen a mid-line trigger fits neither edge-aligned placement.
  const shift = Math.max(0, Math.min(r.right - (innerWidth - TIP_MARGIN), r.left - TIP_MARGIN));
  if (shift) pop.style.left = `${-shift}px`;
  // Below unless it does not fit there and above has more room; when neither
  // side fits, the popup takes the roomier side and scrolls inside.
  const w = wrap.getBoundingClientRect();
  const below = innerHeight - w.bottom - TIP_GAP - TIP_MARGIN;
  const above = w.top - TIP_GAP - TIP_MARGIN;
  const up = r.height > below && above > below;
  if (up) pop.classList.add('flip-y');
  const room = up ? above : below;
  if (r.height > room) pop.style.maxHeight = `${Math.max(room, 0)}px`;
}

function wireTips() {
  const wrapOf = (t) => t.closest?.('.has-tip');
  document.addEventListener('pointerover', (ev) => {
    const wrap = wrapOf(ev.target);
    if (!wrap || ev.pointerType === 'touch') return;
    clearTimeout(tipTimer);
    if (openTip === wrap) return;
    // Moving straight from one open tooltip to the next skips the delay.
    if (openTip) showTip(wrap);
    else tipTimer = setTimeout(() => showTip(wrap), TIP_OPEN_MS);
  });
  document.addEventListener('pointerout', (ev) => {
    const wrap = wrapOf(ev.target);
    if (!wrap || wrap.contains(ev.relatedTarget) || ev.pointerType === 'touch') return;
    clearTimeout(tipTimer);
    if (openTip === wrap && !wrap.contains(document.activeElement)) tipTimer = setTimeout(() => hideTip(wrap), TIP_CLOSE_MS);
  });
  document.addEventListener('focusin', (ev) => {
    const wrap = wrapOf(ev.target);
    if (wrap) showTip(wrap);
    else if (openTip) hideTip(openTip);
  });
  document.addEventListener('focusout', (ev) => {
    const wrap = wrapOf(ev.target);
    if (wrap && !wrap.contains(ev.relatedTarget)) hideTip(wrap);
  });
  document.addEventListener('keydown', (ev) => {
    if (!openTip) return;
    if (ev.key === 'Escape') {
      hideTip(openTip);
      ev.stopPropagation();
    } else if ((ev.key === 'Enter' || ev.key === ' ') && wrapOf(ev.target)) {
      ev.preventDefault();
      showTip(wrapOf(ev.target));
    }
  }, true);
  // A tap focuses (which opens) before it clicks, so the toggle reads the
  // state from before the tap.
  let tapWasOpen = false;
  document.addEventListener('pointerdown', (ev) => {
    if (ev.pointerType === 'touch') tapWasOpen = Boolean(openTip && openTip === wrapOf(ev.target));
  }, true);
  document.addEventListener('click', (ev) => {
    const wrap = wrapOf(ev.target);
    if (wrap && ev.target.closest('.tip-i')) {
      if (ev.pointerType === 'touch' && tapWasOpen) hideTip(wrap);
      else showTip(wrap);
    } else if (openTip && !wrap) {
      hideTip(openTip);
    }
  });
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
    settle(content, state('empty', { title: 'No such page', body: 'Pick a page from the list.' }), seq);
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
    settle(content, state('not-built'), seq);
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
  content.replaceChildren(body);
  // Every render waits for the tooltip copy (loaded, failed or late), so a
  // tab draws once, with its triggers; it is marked rendered only once drawn.
  tipsReady()
    .then(() => (seq === renderSeq ? spec.tabs[route.tab](body, { object: route.object, tab: route.tab, api, state }) : null))
    .then(() => {
      if (seq === renderSeq) mark(body);
    })
    .catch((err) => {
      if (seq !== renderSeq) return;
      const status = err instanceof ApiError ? err.status : 0;
      if (status === 401) return; // the sign-in view is showing; it re-renders after sign-in
      content.replaceChildren(mark(state(status === 403 ? 'forbidden' : 'error')));
    });
}

/** Show a fixed state, marked rendered once the copy settles, as a tab would be. */
function settle(content, node, seq) {
  content.replaceChildren(node);
  tipsReady().then(() => {
    if (seq === renderSeq) mark(node);
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
    document.querySelector('.top .who').textContent = auth?.signed_in ? (auth.admin ? 'Signed in · admin' : 'Signed in') : '';
    return true;
  } catch {
    return false; // a 401 already shows sign-in; other failures show in the page states
  }
}

// ---------------------------------------------------------------- sign-in

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
  signingIn = true;
  button.disabled = true;
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
    else if (reply.status !== 401 && reply.status !== 403) message = 'Could not reach the gateway. Try again.';
  } catch {
    message = 'Could not reach the gateway. Try again.';
  } finally {
    signingIn = false;
    button.disabled = false;
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
  document.querySelector('.top .who').textContent = auth.admin ? 'Signed in · admin' : 'Signed in';
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
  // Scripted page: the stylesheet's hover/focus fallback stands down so the
  // controller's delays apply.
  document.documentElement.setAttribute('data-js', '');
  wireTips();
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
  document.querySelector('a.skip').addEventListener('click', (ev) => {
    ev.preventDefault();
    document.getElementById('content').focus();
  });
  drawNav(parse(location.pathname).page);
  render();
  loadCounts();
  loadWho();
}

document.addEventListener('DOMContentLoaded', boot);
