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

const COPY_URL = '/ui/assets/tips.2b1d0c91519f.json';

// The stylesheet comes with the module, not with the document: only pages that draw a
// tooltip need it, and a render-blocking link would hold up every page's first paint.
// Triggers are filled only once it has loaded, so the controller never runs on unstyled popups.
const cssReady = new Promise((resolve, reject) => {
  const css = document.createElement('link');
  css.rel = 'stylesheet';
  css.href = '/ui/assets/tooltip.5251c22696fd.css';
  css.dataset.tooltipCss = '';
  css.onload = () => resolve();
  css.onerror = () => reject(new Error('stylesheet not loaded'));
  // After the shell's own stylesheet (linked at the end of the body), so its rules win ties.
  document.body.append(css);
});
// Handled here; load() reports a failure when a tooltip asks for it.
cssReady.catch(() => {});
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
  for (const pop of document.querySelectorAll('.has-tip[data-tip] .tip')) clearPlacement(pop);
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

const RESERVED = ['display', 'inline-size', 'block-size', 'vertical-align'];

/** Drop the box a placeholder reserved, and only that: a screen may style the element too. */
function unreserve(holder) {
  for (const prop of RESERVED) holder.style.removeProperty(prop);
  if (!holder.getAttribute('style')) holder.removeAttribute('style');
}

/** Put the trigger into a placeholder, or collapse it when there is no copy for it. */
function fill(holder) {
  const id = holder.dataset.tip;
  const entry = copy?.[id];
  if (!entry || id === '_pending') {
    if (copy) warnOnce(`id:${id}`, `tooltip copy has no entry ${id}; its trigger is left out`);
    holder.classList.remove('tip-pending');
    unreserve(holder);
    holder.hidden = true;
    return;
  }
  const tid = `tip-${++seq}`;
  const button = el('button', { type: 'button', class: 'tip-i', 'aria-label': `About ${entry.title}`, 'aria-describedby': tid }, 'i');
  const pop = el('span', { class: 'tip', role: 'tooltip', id: tid },
    el('strong', { class: 'tip-title', 'aria-hidden': 'true' }, String(entry.title)), body(entry));
  holder.replaceChildren(button, pop);
  holder.classList.remove('tip-pending');
  unreserve(holder);
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
      unreserve(holder); // an inline display would beat [hidden]
      holder.hidden = true;
    }
  }
}

function load() {
  if (settled) return settled;
  const copyFetch = fetch(COPY_URL, { credentials: 'same-origin' }).then((r) => {
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  });
  // The copy and the stylesheet both, or neither: an unstyled popup would show where it should hide.
  settled = Promise.all([copyFetch, cssReady])
    .then(([c]) => c)
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
    // Reserve the finished trigger's box now, from the shell's tokens (loaded with the page): the
    // module's stylesheet may still be on its way, and filling must move nothing beside it.
    const size = matchMedia('(pointer: coarse)').matches ? 'var(--size-touch)' : 'var(--size-icon-sm)';
    Object.assign(holder.style, { display: 'inline-block', inlineSize: size, blockSize: size, verticalAlign: 'middle' });
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
  cancel(pop.fadeTimer);
  pop.classList.remove('closing');
  pop.classList.add('open');
  place(wrap, pop);
}

/** How long the exit fade runs: the popup's own transition, plus a frame. */
const fadeMs = (pop) => Math.max(0, ...getComputedStyle(pop).transitionDuration.split(',').map((d) => parseFloat(d) * (d.trim().endsWith('ms') ? 1 : 1000))) + 20;

function clearPlacement(pop) {
  pop.classList.remove('open', 'closing', 'flip-y');
  pop.style.left = '';
  pop.style.maxHeight = '';
}

function hide(wrap) {
  const pop = wrap.querySelector('.tip');
  if (openWrap === wrap) openWrap = null;
  if (!pop?.classList.contains('open')) return;
  pop.classList.replace('open', 'closing');
  // Anchored by its trigger until the fade ends, then back to its closed place.
  pop.fadeTimer = later(() => clearPlacement(pop), fadeMs(pop));
}

/** Below the trigger, left edges aligned; slide left and flip up to stay inside the viewport, never over the trigger. */
function place(wrap, pop) {
  const scrolled = pop.scrollTop;
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
  pop.scrollTop = scrolled;
}

let hoverTimer = 0;
const SCROLL_KEYS = {
  ArrowDown: () => 40,
  ArrowUp: () => -40,
  PageDown: (p) => p.clientHeight,
  PageUp: (p) => -p.clientHeight,
  Home: (p) => -p.scrollHeight,
  End: (p) => p.scrollHeight,
};
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
    const pop = openWrap.querySelector('.tip.open');
    if (ev.key === 'Escape') {
      hide(openWrap);
      ev.stopPropagation();
    } else if (SCROLL_KEYS[ev.key] && pop && wrapOf(ev.target) === openWrap && pop.scrollHeight > pop.clientHeight) {
      // A popup cut short by the viewport scrolls from its trigger, which keeps focus.
      ev.preventDefault();
      pop.scrollBy({ top: SCROLL_KEYS[ev.key](pop) });
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
    // The page moved under an open popup: place it again by its trigger.
    // Its own scrolling is not the page moving; and one placement per frame is enough.
    let frame = 0;
    const replace = guard((ev) => {
      if (ev?.target instanceof Element && ev.target.closest('.has-tip[data-tip] .tip')) return;
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(guard(() => { if (openWrap?.isConnected) place(openWrap, openWrap.querySelector('.tip')); }));
    });
    addEventListener('resize', replace);
    document.addEventListener('scroll', replace, true);
  })();
}
