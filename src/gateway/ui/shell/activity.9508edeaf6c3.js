// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Activity › Status: the gateway's rows, newest as the answer lists them.
// Filters live in the page URL. Every server-supplied string goes in with
// textContent. The shell is imported by its exact hashed name, so this page
// registers in the same module instance the document loaded.
import { register, segmented } from '/ui/assets/shell.260480aea22f.js';

/** One element: attributes set through setAttribute, children appended as nodes or text. */
function h(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v !== null && v !== undefined && v !== false) node.setAttribute(k, v === true ? '' : String(v));
  }
  node.append(...children);
  return node;
}

const RANGES = { '1h': 60 * 60 * 1000, '24h': 24 * 60 * 60 * 1000, '7d': 7 * 24 * 60 * 60 * 1000 };
const RANGE_WORD = { '1h': '1 h', '24h': '24 h', '7d': '7 days' };
const EMPTY_LINE = 'Calls, caught calls, decisions and changes appear here as they happen. Widen the range, or connect a client.';

/** UTC to the second, the shape ListQuery compares (`YYYY-MM-DDTHH:MM:SSZ`). */
const utcSeconds = (d) => d.toISOString().replace(/\.\d{3}Z$/, 'Z');

/** The browser's local clock, 24 h, so a row reads the same in any locale. */
function clock(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const p = (n) => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

const text = (v) => (typeof v === 'string' ? v : '');

/** outcome, server, key, q and range, as the page URL holds them. `key` is the URL's name for `caller`. */
function readFilters() {
  const q = new URLSearchParams(location.search);
  const outcome = q.get('outcome');
  const range = q.get('range');
  return {
    outcome: outcome === 'ok' || outcome === 'failed' || outcome === 'blocked' ? outcome : null,
    server: q.get('server') || null,
    key: q.get('key') || null,
    q: q.get('q') || null,
    range: Object.hasOwn(RANGES, range) ? range : '24h',
  };
}

/**
 * One row, one link, nothing inside it a keyboard can reach. The key is who.account.
 * One cell per column, so the list's grid lines the rows up; the spaces between the
 * cells keep the link's name one readable line.
 */
function rowLink(row) {
  const outcome = text(row.outcome);
  return h('a', { class: 'activity-row', href: `/ui/activity/${encodeURIComponent(row.id)}/status` },
    h('span', { class: 'activity-time' }, clock(row.timestamp)), ' ',
    h('span', {}, text(row.who?.account)), ' ',
    h('span', {}, text(row.tool)), ' ',
    h('span', { class: 'activity-outcome', 'data-outcome': outcome }, outcome));
}

async function statusTab(body, ctx) {
  // A row's address is this same tab with an object. Rendering the list again
  // would replace that address with the list's query, so a call stands on its own.
  if (ctx.object) {
    const line = h('p', { class: 'activity-call' });
    line.textContent = ctx.object;
    body.append(line);
    return;
  }

  const filters = readFilters();
  // The session's role, read from the route the shell reads it from, never from the
  // shell's header text. Only an explicit member sees the own-key line; a failed read shows nothing.
  const status = await ctx.api('/ui/api/status').catch(() => null);
  const member = status?.auth?.admin === false;

  const outcomeTip = h('span', { class: 'activity-tip' });
  const blockedTip = h('span', { class: 'activity-tip' });
  // The blocked trigger sits beside the option, outside the group: the group's
  // buttons are only All, ok, failed and blocked.
  const outcomeGroup = segmented({
    label: 'Outcome',
    options: [['all', 'All'], ['ok', 'ok'], ['failed', 'failed'], ['blocked', 'blocked']],
    value: filters.outcome ?? 'all',
    onChange: (value) => {
      filters.outcome = value === 'all' ? null : value;
      commit();
    },
  });
  const outcomeRow = h('div', { class: 'activity-line' },
    h('span', { class: 'activity-label' }, 'Outcome'), outcomeTip, outcomeGroup, blockedTip);

  const rangeGroup = segmented({
    label: 'Range',
    options: [['1h', 'Last 1 h'], ['24h', 'Last 24 h'], ['7d', 'Last 7 days']],
    value: filters.range,
    onChange: (value) => chooseRange(value),
  });

  const search = h('input', {
    class: 'input activity-search',
    type: 'search',
    'aria-label': 'Call id, tool, key or rule',
    placeholder: 'Call id, tool, key or rule',
    autocomplete: 'off',
    spellcheck: 'false',
  });
  search.value = filters.q ?? '';

  const active = h('p', { class: 'activity-active' });
  // Each value is its own text node, so the word on screen is exactly the filter.
  if (filters.server) active.append(h('span', { class: 'activity-label' }, 'Server'), h('span', { class: 'activity-value' }, filters.server));
  if (filters.key) active.append(h('span', { class: 'activity-label' }, 'Key'), h('span', { class: 'activity-value' }, filters.key));

  const empty = h('div', { class: 'activity-empty' });
  const rowsEl = h('div', { class: 'activity-rows' });
  // The observer's target, after the last row. Not focusable: Tab from the
  // search lands on the first row.
  const sentinel = h('div', { class: 'activity-more', 'aria-hidden': 'true' });
  // Where a next page that could not be read says so, after the rows it would have followed.
  const moreLine = h('p', { class: 'activity-more-error', hidden: true });

  const root = h('div', { class: 'activity' });
  // A member's line is above the list. Its trigger is a button, so it stays
  // before the search: nothing focusable may sit between the search and a row.
  let memberTip = null;
  if (member) {
    memberTip = h('span', { class: 'activity-tip' });
    root.append(h('p', { class: 'activity-member' }, 'Calls made with your key', memberTip));
  }
  root.append(outcomeRow, rangeGroup, search);
  if (filters.server || filters.key) root.append(active);
  root.append(empty, rowsEl, moreLine, sentinel);
  body.append(root);

  // After the controls are drawn. A static import would put the module before
  // every page's first paint; a failure leaves the labels standing without (i).
  try {
    const { tip } = await import('/ui/assets/tooltip.fc459693146e.js');
    outcomeTip.append(tip('activity.status.outcome'));
    blockedTip.append(tip('activity.status.blocked'));
    if (memberTip) memberTip.append(tip('activity.status.calls-made-with-your-key'));
  } catch {
    // The line stands without its (i).
  }

  let epoch = 0;
  let tail = Promise.resolve();
  let pageCursor = null;
  let onScreen = false;
  let debounce = 0;
  // One window per filter set: every page of it asks for the same from and to, so a
  // cursor never continues a window that has slid on since the first page.
  let windowFrom = '';
  let windowTo = '';

  function freezeWindow() {
    const to = new Date();
    windowTo = utcSeconds(to);
    windowFrom = utcSeconds(new Date(to.getTime() - RANGES[filters.range]));
  }

  const queryOf = (cursor) => {
    const params = new URLSearchParams();
    if (filters.outcome) params.set('outcome', filters.outcome);
    if (filters.server) params.set('server', filters.server);
    if (filters.key) params.set('caller', filters.key);
    if (filters.q) params.set('q', filters.q);
    params.set('from', windowFrom);
    params.set('to', windowTo);
    if (cursor) params.set('cursor', cursor);
    return params.toString();
  };

  // Replace, so a filter change is not a new history entry. The list refetches
  // from the first page (no cursor) once the address matches the filters.
  function writeUrl() {
    const url = new URL(location.href);
    const set = (name, value) => (value ? url.searchParams.set(name, value) : url.searchParams.delete(name));
    set('outcome', filters.outcome);
    set('server', filters.server);
    set('key', filters.key);
    set('q', filters.q);
    set('range', filters.range);
    const next = `${url.pathname}${url.search}${url.hash}`;
    if (next !== `${location.pathname}${location.search}${location.hash}`) history.replaceState(history.state, '', next);
  }

  function emptyNode() {
    let action;
    if (filters.range !== '7d') {
      action = h('button', { class: 'btn', type: 'button' }, 'Last 7 days');
      action.addEventListener('click', () => chooseRange('7d'));
    }
    return ctx.state('empty', {
      title: `No calls in the last ${RANGE_WORD[filters.range]}`,
      body: EMPTY_LINE,
      action,
    });
  }

  function paint(data, append) {
    const rows = Array.isArray(data?.rows) ? data.rows : [];
    const next = data?.next_cursor;
    pageCursor = typeof next === 'string' && next ? next : null;
    // A reset cursor starts again from the newest row: what is on screen would show twice.
    if (!append || data?.cursor_reset === true) rowsEl.replaceChildren();
    for (const row of rows) {
      if (row && typeof row.id === 'string') rowsEl.append(rowLink(row));
    }
    // Empty only once the list has run out: a page with no rows but a cursor is a scan
    // that stopped short on a sparse filter, and pump() reads on at once.
    empty.replaceChildren();
    if (rowsEl.childElementCount === 0 && !pageCursor) empty.append(emptyNode());
    ctx.show(null);
  }

  // A next page that could not be read: the rows stay, the list says it stopped short,
  // and Retry asks for the same cursor.
  function failMore(cursor) {
    const retry = h('button', { class: 'btn', type: 'button' }, 'Retry');
    retry.addEventListener('click', () => {
      // The button goes; focus stays in the list, on the row the next page follows.
      rowsEl.lastElementChild?.focus();
      clearMore();
      schedule(cursor);
    });
    moreLine.replaceChildren('More calls could not be read. ', retry);
    moreLine.hidden = false;
  }

  function clearMore() {
    moreLine.hidden = true;
    moreLine.replaceChildren();
  }

  function failList() {
    clearMore();
    pageCursor = null;
    rowsEl.replaceChildren();
    empty.replaceChildren();
    ctx.show('error', { title: 'Activity is unavailable', body: 'The list could not be read.' });
  }

  // One fetch at a time: a later filter waits until the request already out
  // comes back, and its answer is dropped when the filters have moved on.
  function schedule(cursor) {
    const token = epoch;
    const append = cursor != null;
    const job = tail.then(async () => {
      if (token !== epoch) return;
      try {
        const data = await ctx.api(`/ui/api/activity?${queryOf(cursor)}`);
        if (token !== epoch) return;
        paint(data, append);
      } catch {
        if (token !== epoch) return;
        if (append) failMore(cursor);
        else failList();
        return;
      }
      pump();
    });
    tail = job.catch(() => {});
    return job;
  }

  function pump() {
    // A list with rows reads on when its end is in view; an empty one at once.
    if (!pageCursor || (!onScreen && rowsEl.childElementCount > 0)) return;
    const cursor = pageCursor;
    pageCursor = null;
    schedule(cursor);
  }

  function commit() {
    // A search wait can end after the user has left: the address is then another
    // page's, and this list is no longer on screen.
    if (!root.isConnected) return;
    epoch += 1;
    pageCursor = null;
    clearMore();
    freezeWindow();
    writeUrl();
    schedule(null);
  }

  function chooseRange(value) {
    filters.range = value;
    for (const button of rangeGroup.querySelectorAll('button')) {
      button.setAttribute('aria-pressed', button.getAttribute('data-value') === value ? 'true' : 'false');
    }
    commit();
  }

  // One request, 300 ms after typing stops: each key restarts the wait.
  search.addEventListener('input', () => {
    clearTimeout(debounce);
    debounce = setTimeout(() => {
      filters.q = search.value === '' ? null : search.value;
      commit();
    }, 300);
  });

  const io = new IntersectionObserver((entries) => {
    // The page was left: stop watching rather than keep a dead list's observer.
    if (!sentinel.isConnected) { io.disconnect(); return; }
    onScreen = entries.some((e) => e.isIntersecting);
    if (onScreen) pump();
  });
  io.observe(sentinel);

  freezeWindow();
  await schedule(null);
}

register('activity', {
  title: 'Activity',
  tabs: {
    status: statusTab,
    actions: null,
    settings: null,
  },
});
