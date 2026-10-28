// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Tooltips (frame 36). tip(id) returns a trigger at once: an (i) button named
// "About {title}", described by one role="tooltip" popup holding the copy.
// The copy is fetched once, on the first tip() call, and never awaited by a
// render: until it answers, tip() returns an empty placeholder that fills in
// place. A leaf module: it imports nothing, so no screen's import pulls in a cycle.
//
// One guard runs every entry point (start, fill, handlers, timers). On the
// first exception the controller stops for good: timers cancelled, popups
// closed, html[data-tips] removed, so tooltip.css's CSS fallback shows the text
// on hover and focus again. Building and filling markup is not controller work
// and goes on after that.

const COPY_URL = '/ui/assets/tips.7c43dc6560cf.json';
const OPEN_MS = 300;
const CLOSE_MS = 150;
/** The popup keeps this far from the viewport's sides. */
const MARGIN = 8;
/** The gap between trigger and popup, as in the stylesheet (--space-1-5). */
const GAP = 6;

let copy = null; // id -> entry once loaded
let settled = null; // the fill pass's promise, once a fetch has started
let done = false; // the copy has answered or failed and the fill pass has run
let pending = []; // placeholders waiting for the copy
const warned = new Set();
let failed = false;
let started = false;
let openWrap = null;
const timers = new Set();
let seq = 0;

function warnOnce(key, message) {
  if (warned.has(key)) return;
  warned.add(key);
  console.warn(message);
}

/** The latch: stop the controller and hand the popups back to CSS. */
function trip(err) {
  if (failed) return;
  failed = true;
  for (const t of timers) clearTimeout(t);
  timers.clear();
  for (const pop of document.querySelectorAll('.has-tip[data-tip] .tip.open')) pop.classList.remove('open', 'flip-y');
  openWrap = null;
  document.documentElement.removeAttribute('data-tips');
  console.warn(`tooltip controller stopped (${err?.message ?? err}); tooltips fall back to hover and focus`);
}

function guard(fn) {
  return (...args) => {
    if (failed) return undefined;
    try {
      return fn(...args);
    } catch (err) {
      trip(err);
      return undefined;
    }
  };
}

function later(fn, ms) {
  const t = setTimeout(guard(() => {
    timers.delete(t);
    fn();
  }), ms);
  timers.add(t);
  return t;
}

function cancel(t) {
  clearTimeout(t);
  timers.delete(t);
}

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  for (const c of children) node.append(c);
  return node;
}

function body(entry) {
  if (Array.isArray(entry.rows)) {
    return el('dl', { class: 'tip-rows' }, ...entry.rows.map(([label, value]) => el('div', {}, el('dt', {}, String(label)), el('dd', {}, String(value)))));
  }
  return el('span', { class: 'tip-body' }, String(entry.text ?? ''));
}

/** Put the trigger into a placeholder, or collapse it when there is no copy for it. */
function fill(holder) {
  const id = holder.dataset.tip;
  const entry = copy?.[id];
  if (!entry || id === '_pending') {
    if (copy) warnOnce(`id:${id}`, `tooltip copy has no entry ${id}; its trigger is left out`);
    holder.classList.remove('tip-pending');
    holder.hidden = true;
    return;
  }
  const tid = `tip-${++seq}`;
  const button = el('button', { type: 'button', class: 'tip-i', 'aria-label': `About ${entry.title}`, 'aria-describedby': tid }, 'i');
  const pop = el('span', { class: 'tip', role: 'tooltip', id: tid },
    el('strong', { class: 'tip-title', 'aria-hidden': 'true' }, String(entry.title)), body(entry));
  holder.replaceChildren(button, pop);
  holder.classList.remove('tip-pending');
}

/** fill() under its own guard: a failure trips the latch, the placeholder gets one retry, then collapses. */
function fillOnce(holder) {
  try {
    fill(holder);
  } catch (err) {
    trip(err);
    try {
      fill(holder);
    } catch {
      holder.classList.remove('tip-pending');
      holder.hidden = true;
    }
  }
}

function load() {
  if (settled) return settled;
  settled = fetch(COPY_URL, { credentials: 'same-origin' })
    .then((r) => {
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return r.json();
    })
    .then((c) => { copy = c; }, (err) => {
      warnOnce('copy', `tooltip copy not loaded (${err.message}); tooltips are left out`);
    })
    .then(() => {
      const list = pending;
      pending = [];
      for (const holder of list) fillOnce(holder);
      done = true;
    });
  return settled;
}

/** Resolves once the copy fetch has answered or failed and every placeholder is filled; at once if no tip() asked for copy. */
export function tipsSettled() {
  return settled ?? Promise.resolve();
}

/** A trigger for copy id `id`, returned at once. */
export function tip(id) {
  start();
  const holder = document.createElement('span');
  holder.className = 'has-tip';
  holder.dataset.tip = id;
  if (done) {
    fillOnce(holder);
  } else {
    holder.classList.add('tip-pending');
    pending.push(holder);
    load();
  }
  return holder;
}

// ---------------------------------------------------------------- controller

function show(wrap) {
  cancel(hoverTimer);
  // A screen the shell has since replaced keeps no open popup, nor does a hover timer that fires after it.
  if (!wrap.isConnected) return;
  if (openWrap && openWrap !== wrap) hide(openWrap);
  openWrap = wrap;
  const pop = wrap.querySelector('.tip');
  pop.classList.add('open');
  place(wrap, pop);
}

function hide(wrap) {
  wrap.querySelector('.tip')?.classList.remove('open', 'flip-y');
  if (openWrap === wrap) openWrap = null;
}

/** Below the trigger, left edges aligned; slide left and flip up to stay inside the viewport, never over the trigger. */
function place(wrap, pop) {
  pop.classList.remove('flip-y');
  pop.style.left = '';
  pop.style.maxHeight = '';
  const r = pop.getBoundingClientRect();
  // Slide left by what overflows the right edge, never past the left margin.
  const shift = Math.max(0, Math.min(r.right - (innerWidth - MARGIN), r.left - MARGIN));
  if (shift) pop.style.left = `${-shift}px`;
  // Below unless it does not fit there and above has more room; when neither
  // side fits, it takes the roomier side and scrolls inside.
  const w = wrap.getBoundingClientRect();
  const below = innerHeight - w.bottom - GAP - MARGIN;
  const above = w.top - GAP - MARGIN;
  const up = r.height > below && above > below;
  if (up) pop.classList.add('flip-y');
  const room = up ? above : below;
  if (r.height > room) pop.style.maxHeight = `${Math.max(room, 0)}px`;
}

let hoverTimer = 0;
let tapWasOpen = false;
const wrapOf = (t) => t?.closest?.('.has-tip[data-tip]') ?? null;

const HANDLERS = [
  ['pointerover', (ev) => {
    const wrap = wrapOf(ev.target);
    if (!wrap || ev.pointerType === 'touch' || !wrap.querySelector('.tip')) return;
    cancel(hoverTimer);
    if (openWrap === wrap) return;
    // Moving straight from one open tooltip to the next skips the delay.
    if (openWrap) show(wrap);
    else hoverTimer = later(() => show(wrap), OPEN_MS);
  }],
  ['pointerout', (ev) => {
    const wrap = wrapOf(ev.target);
    if (!wrap || wrap.contains(ev.relatedTarget) || ev.pointerType === 'touch') return;
    cancel(hoverTimer);
    if (openWrap === wrap && !wrap.contains(document.activeElement)) hoverTimer = later(() => hide(wrap), CLOSE_MS);
  }],
  ['focusin', (ev) => {
    const wrap = wrapOf(ev.target);
    if (wrap && wrap.querySelector('.tip')) show(wrap);
    else if (openWrap) hide(openWrap);
  }],
  ['focusout', (ev) => {
    const wrap = wrapOf(ev.target);
    if (wrap && !wrap.contains(ev.relatedTarget)) hide(wrap);
  }],
  ['keydown', (ev) => {
    if (!openWrap) return;
    if (ev.key === 'Escape') {
      hide(openWrap);
      ev.stopPropagation();
    } else if ((ev.key === 'Enter' || ev.key === ' ') && wrapOf(ev.target)) {
      ev.preventDefault();
      show(wrapOf(ev.target));
    }
  }],
  // A tap focuses (which opens) before it clicks, so the toggle reads the state from before the tap.
  ['pointerdown', (ev) => {
    if (ev.pointerType === 'touch') tapWasOpen = Boolean(openWrap && openWrap === wrapOf(ev.target));
  }],
  ['click', (ev) => {
    const wrap = wrapOf(ev.target);
    if (wrap && ev.target.closest('.tip-i')) {
      if (ev.pointerType === 'touch' && tapWasOpen) hide(wrap);
      else show(wrap);
    } else if (openWrap && !wrap) {
      hide(openWrap);
    }
  }],
];

function start() {
  if (started) return;
  started = true;
  guard(() => {
    document.documentElement.dataset.tips = 'js';
    for (const [type, fn] of HANDLERS) document.addEventListener(type, guard(fn), true);
  })();
}
