// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Activity › Status: the gateway's rows, newest as the answer lists them.
// Filters live in the page URL. Every server-supplied string goes in with
// textContent. The shell is imported by its exact hashed name, so this page
// registers in the same module instance the document loaded.
import { register, segmented } from '/ui/assets/shell.e97c8490b811.js';
import * as listCore from '/ui/assets/activity-list.3e4eec96100d.js';

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
    // A receipt's rule link lands here; the list asks for exactly that rule.
    rule: q.get('rule') || null,
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
    // The effect shares the outcome's cell: the grid has one column per cell and one for the chevron.
    h('span', { class: 'activity-outcome', 'data-outcome': outcome }, outcome, ...effectOf(row)));
}

/** A call's delivery effect, when the row has one. no_record is never final: the record lands after the call. */
function effectOf(row) {
  if (typeof row.effect !== 'string' || !row.effect) return [];
  const words = row.effect === 'no_record' ? 'delivery not yet recorded' : row.effect;
  return [' ', h('span', { class: 'activity-effect', 'data-effect': row.effect }, words)];
}

async function statusTab(body, ctx) {
  // A row's address is this same tab with an object. Rendering the list again
  // would replace that address with the list's query, so a call stands on its own.
  if (ctx.object) return receiptTab(body, ctx);

  const filters = readFilters();

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
    // What q matches today (a tool name, or a call's exact trace id), not the frame's
    // "Call id, tool, key or rule": a key or a rule typed here would find nothing.
    'aria-label': 'Tool or trace id',
    placeholder: 'Tool or trace id',
    autocomplete: 'off',
    spellcheck: 'false',
  });
  search.value = filters.q ?? '';

  const active = h('p', { class: 'activity-active' });
  // Each value is its own text node, so the word on screen is exactly the filter.
  if (filters.server) active.append(h('span', { class: 'activity-label' }, 'Server'), h('span', { class: 'activity-value' }, filters.server));
  if (filters.key) active.append(h('span', { class: 'activity-label' }, 'Key'), h('span', { class: 'activity-value' }, filters.key));

  const empty = h('div', { class: 'activity-empty' });
  // Focusable by script only (outside the Tab order): it holds focus when the end of the
  // list has nothing left that could, until the next draw offers a real target.
  const rowsEl = h('div', { class: 'activity-rows', tabindex: '-1' });
  // The observer's target, after the last row. Not focusable: Tab from the
  // search lands on the first row.
  const sentinel = h('div', { class: 'activity-more', 'aria-hidden': 'true' });
  // The one line after the rows that says how to get more: Load more, "Reading more…", the
  // next-page retry, or Keep looking. It can hold focus itself while a press with no rows reads.
  const moreLine = h('p', { class: 'activity-more-error', hidden: true, tabindex: '-1' });

  const root = h('div', { class: 'activity' });
  // The member line says why the rest is hidden. It shows above the list, only when the
  // list answer says it holds only the caller's own calls (access "own"). Status's admin
  // flag cannot say that: an auditor and a backend-scoped admin read false there and are
  // served others' calls. No key name: the shell holds none for the signed-in key.
  // Its trigger is a button, so the line stays before the search: nothing focusable may
  // sit between the search and a row. Hidden, it is out of the Tab order.
  const memberTip = h('span', { class: 'activity-tip' });
  const memberLine = h('p', { class: 'activity-member', hidden: true }, 'Showing only calls made with your key. Members see their own calls.', memberTip);
  root.append(memberLine);
  root.append(outcomeRow, rangeGroup, search);
  if (filters.rule) {
    const label = h('span', { class: 'activity-label' }, 'Rule');
    const value = h('span', { class: 'activity-value' }, filters.rule);
    const clear = h('button', { class: 'btn', type: 'button', 'aria-label': 'Clear the rule filter' }, 'Clear');
    clear.addEventListener('click', () => {
      filters.rule = null;
      label.remove();
      value.remove();
      clear.remove();
      commit();
    });
    active.append(label, value, clear);
  }
  if (filters.server || filters.key || filters.rule) root.append(active);
  root.append(empty, rowsEl, moreLine, sentinel);
  body.append(root);

  // After the controls are drawn. A static import would put the module before
  // every page's first paint. Not awaited: the controls are live from here, and a
  // slow or failing module must neither hold the list back nor open a window in
  // which a click reaches state not yet set up; it only leaves the labels without (i).
  import('/ui/assets/tooltip.cd1750e8bd65.js').then(({ tip }) => {
    outcomeTip.append(tip('activity.status.outcome'));
    blockedTip.append(tip('activity.status.blocked'));
    memberTip.append(tip('activity.status.calls-made-with-your-key'));
  }).catch(() => {
    // The line stands without its (i).
  });

  let debounce = 0;
  // The list's state lives in the core (activity-list.js); this screen only performs
  // what it returns and draws the state. A handle owns the abort of its one request.
  const query = () => ({ ...filters, spanMs: RANGES[filters.range] });
  const handle = () => ({ abort: new AbortController() });
  let list = listCore.initial(query());
  let left = false;
  let shownRows = [];
  let controlOn = false;
  // The slot's face: null, 'reading', 'retry', 'look' (Keep looking) or 'more' (Load more).
  let face = null;
  // A Keep looking press whose request is out: its handle, and where it left focus.
  let looking = null;
  // Set while a Keep looking ending settles: that ending places focus, not the face rule.
  let placing = false;
  let failedShown = false;
  let opened;
  const firstDone = new Promise((done) => { opened = done; });

  /** The wire parameters of one request: the query it was made for, its window, its cursor. */
  function paramsOf(q, ask) {
    const params = new URLSearchParams();
    if (q.outcome) params.set('outcome', q.outcome);
    if (q.server) params.set('server', q.server);
    if (q.key) params.set('caller', q.key);
    if (q.q) params.set('q', q.q);
    if (q.rule) params.set('rule', q.rule);
    params.set('from', utcSeconds(new Date(ask.window.from)));
    params.set('to', utcSeconds(new Date(ask.window.to)));
    if (ask.cursor) params.set('cursor', ask.cursor);
    return params.toString();
  }

  // Replace, so a filter change is not a new history entry. The list refetches
  // from the first page (no cursor) once the address matches the filters.
  function writeUrl() {
    const url = new URL(location.href);
    const set = (name, value) => (value ? url.searchParams.set(name, value) : url.searchParams.delete(name));
    set('outcome', filters.outcome);
    set('server', filters.server);
    set('key', filters.key);
    set('rule', filters.rule);
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
    const node = ctx.state('empty', {
      title: `No calls in the last ${RANGE_WORD[filters.range]}`,
      body: EMPTY_LINE,
      action,
    });
    // A Keep looking press that reaches the end of the log moves focus here.
    node.querySelector('h2')?.setAttribute('tabindex', '-1');
    return node;
  }

  // Shown while the operator reads older pages and news is waiting; pressing it
  // goes back to the newest page 1. It stays at the top of the list's view.
  const newerControl = h('button', { class: 'btn activity-newer', type: 'button' }, 'Newer activity · show');
  newerControl.style.position = 'sticky';
  newerControl.style.top = '0';
  newerControl.style.zIndex = '1';
  newerControl.addEventListener('click', () => step('replace', { query: query() }));
  const staleLine = h('p', { class: 'activity-stale', hidden: true }, 'The newest calls could not be read.');
  // The control is in the page only while it shows: .btn sets display, which beats `hidden`.
  rowsEl.before(staleLine);

  /** Valid rows and the cursor of one answer, in the shape the core reads. */
  const answerOf = (data) => ({
    rows: (Array.isArray(data?.rows) ? data.rows : []).filter((row) => row && typeof row.id === 'string'),
    next_cursor: typeof data?.next_cursor === 'string' ? data.next_cursor : null,
    cursor_reset: data?.cursor_reset === true,
    scan_exhausted: data?.scan_exhausted === true,
  });

  /** Carry out what the core returned: abort, then the new state, then any request, then draw. */
  function perform(out) {
    out.abort?.abort.abort();
    list = out.state;
    if (out.issue) startRequest(out.issue);
    draw();
  }

  /** One core transition with a fresh handle and the clock read now. */
  function step(name, input = {}) {
    if (left) return;
    perform(listCore[name](list, { ...input, fresh: handle(), now: Date.now() }));
  }

  /** The one issuer: every list request this screen makes starts here. */
  function startRequest(ask) {
    ctx.api(`/ui/api/activity?${paramsOf(list.query, ask)}`, { signal: ask.handle.abort.signal }).then(
      (data) => settle(ask, { answer: answerOf(data), data }),
      (err) => { if (err?.name !== 'AbortError') settle(ask, { failed: true }); },
    );
  }

  function settle(ask, { answer, data, failed }) {
    if (left) return;
    const mine = list.flight?.handle === ask.handle;
    const before = list.rows.length;
    // A Keep looking press ends here when its own answer applies; a failure or a reset
    // falls to the face rule in draw(). Read before the step: a hidden slot drops focus.
    const ending = mine && answer && !answer.cursor_reset && looking?.handle === ask.handle ? looking : null;
    const stayed = ending !== null && document.activeElement === ending.from;
    if (looking?.handle === ask.handle) looking = null;
    // A first page says whose calls the list holds.
    if (mine && answer && ask.kind !== 'append') memberLine.hidden = data?.access !== 'own';
    placing = ending !== null;
    step('settle', failed ? { handle: ask.handle, failed: true } : { handle: ask.handle, answer });
    placing = false;
    // Rows added below the reader are said: a screen reader would otherwise find them only by walking the links.
    const added = list.rows.length - before;
    if (mine && answer && ask.kind === 'append' && !answer.cursor_reset && added > 0) {
      ctx.announce(`${added} more call${added === 1 ? '' : 's'}.`);
    }
    if (ending) endLooking(ending.from, stayed, added);
    opened();
  }

  /** Where a Keep looking press ends. Focus moves only if it is still where the press left it. */
  function endLooking(from, stayed, added) {
    const rows = rowsEl.children;
    let target = null;
    let say = null;
    if (added > 0) {
      // The new rows were said above; a press with no rows hands focus to the first of them.
      if (from === moreLine) target = rows[rows.length - added];
    } else if (list.cursor && list.stalled) {
      target = keepLooking;
      say = rows.length ? 'No more matching calls yet. You can keep looking.' : 'Nothing found yet. You can keep looking.';
    } else if (!list.cursor) {
      // With rows, focus stays on the last one, where the press put it.
      if (!rows.length) target = empty.querySelector('h2');
      say = rows.length ? 'No more matching calls.' : 'No calls found.';
    } else if (from === moreLine) {
      // A page that read to its end with a cursor and nothing in it: the face rule's target.
      target = faceTarget();
    }
    if (stayed) target?.focus({ preventScroll: true });
    if (say) ctx.announce(say);
  }

  /** Where focus goes when the face it sat in changes: its button, else the last row, else the empty state. */
  const faceTarget = () => moreLine.querySelector('button') ?? rowsEl.lastElementChild ?? empty.querySelector('h2')
    // Then the slot itself (a Retry pressed with no rows reads there), else the rows container.
    ?? (moreLine.hidden ? rowsEl : moreLine);

  /** A paging press: focus waits on the row the next page follows, or on the slot with no rows. */
  function pressFrom() {
    const from = rowsEl.lastElementChild ?? moreLine;
    // No scroll: only the press asks, never the list end coming into view because of it.
    from.focus({ preventScroll: true });
    return from;
  }

  const loadMore = h('button', { class: 'btn', type: 'button' }, 'Load more');
  loadMore.addEventListener('click', () => {
    pressFrom();
    step('next');
  });
  const keepLooking = h('button', { class: 'btn', type: 'button' }, 'Keep looking');
  const lookSays = document.createTextNode('');
  keepLooking.addEventListener('click', () => {
    const from = pressFrom();
    step('next');
    looking = list.flight?.kind === 'append' ? { handle: list.flight.handle, from } : null;
  });
  const retry = h('button', { class: 'btn', type: 'button' }, 'Retry');
  retry.addEventListener('click', () => {
    // Focus stays in the list, on the row the next page follows.
    rowsEl.lastElementChild?.focus();
    step('next');
  });

  /** Rebuild the slot for a new face. Keep looking's sentence is kept current by draw(). */
  function showFace(next) {
    moreLine.hidden = next === null;
    if (next === 'reading') moreLine.replaceChildren('Reading more…');
    else if (next === 'more') moreLine.replaceChildren(loadMore);
    else if (next === 'look') moreLine.replaceChildren(lookSays, keepLooking);
    else if (next === 'retry') {
      moreLine.replaceChildren('More calls could not be read. ', retry);
      // Said as well as shown: the rows above stay, so nothing else says paging stopped.
      ctx.announce('More calls could not be read.');
    } else moreLine.replaceChildren();
  }

  function draw() {
    const rows = list.rows;
    if (rows !== shownRows) {
      // An append of no rows keeps every row element, so a focused row is never rebuilt away.
      const grew = rows.length >= shownRows.length && shownRows.every((row, i) => rows[i] === row);
      if (grew) rowsEl.append(...rows.slice(shownRows.length).map(rowLink));
      else rowsEl.replaceChildren(...rows.map(rowLink));
      shownRows = rows;
      // Back from a receipt: focus returns to the row it was opened from, once.
      if (returnTo && rows.length) {
        [...rowsEl.children].find((link) => link.getAttribute('href') === returnTo)?.focus();
        returnTo = null;
      }
    }
    const has = (notice) => list.notices.includes(notice);
    if (has('page1-retry') !== failedShown) {
      failedShown = has('page1-retry');
      if (failedShown) {
        const again = h('button', { class: 'btn', type: 'button' }, 'Try again');
        again.addEventListener('click', () => step('replace', { query: query() }));
        ctx.show('error', { title: 'Activity is unavailable', body: 'The list could not be read.', action: again });
      } else {
        ctx.show(null);
      }
    }
    staleLine.hidden = !has('stale');
    const want = list.flight?.kind === 'append' ? 'reading'
      : has('next-retry') ? 'retry'
        : !list.cursor ? null
          : list.stalled ? 'look' : 'more';
    // Read before the rebuild: a removed button takes focus with it.
    // The end area: the slot, the empty state, or the rows container holding focus for them.
    const at = document.activeElement;
    const inEnd = !placing && (moreLine.contains(at) || empty.contains(at) || at === rowsEl);
    const faceMoved = want !== face;
    if (want !== face) {
      face = want;
      showFace(want);
    }
    // Changed in place, so a focused Keep looking stays the same element.
    if (face === 'look') {
      lookSays.data = rows.length ? 'The search stopped before the end of the log. ' : 'No matching call in the part of the log searched so far. ';
    }
    const waiting = list.held && list.newer;
    if (waiting !== controlOn) {
      controlOn = waiting;
      if (waiting) staleLine.before(newerControl);
      else newerControl.remove();
      if (waiting) ctx.announce('Newer activity is waiting above the list.');
    }
    // Empty only once nothing is out and the list has run out of pages.
    empty.replaceChildren();
    if (!list.flight && rows.length === 0 && !list.cursor && !failedShown) empty.append(emptyNode());
    // The face focus sat in changed: focus stays in the list, after the empty state is drawn.
    // Focus there moves on when the face changed, when its element went or hid, or when the
    // rows container held it and a real target may exist now.
    const gone = !at?.isConnected || at.closest('[hidden]') !== null;
    if (inEnd && (faceMoved || gone || at === rowsEl)) faceTarget()?.focus({ preventScroll: true });
    readOn();
  }

  // The automatic next page, asked when the list end is in view (measured after each draw);
  // a failed next page waits for its Retry instead. A reading that finds a live refresh out
  // waits for that one refresh, so its rows land first. The reading after it goes ahead even
  // when a newer refresh has started meanwhile, so a busy gateway cannot starve paging.
  // The operator scrolling the end into view reads on at once. The observer also fires when
  // a draw moves the end into view; that is no scroll, so a wait already set stands.
  let waitedOn = null;
  function readOn(scrolled = false) {
    const prior = waitedOn;
    waitedOn = null;
    // A scan that stopped short waits for Keep looking: each read can cost the gateway 8 MB.
    if (left || !list.cursor || list.stalled) return;
    const out = list.flight;
    if (out?.kind === 'append' || list.notices.includes('next-retry')) return;
    const box = sentinel.getBoundingClientRect();
    if (box.bottom < 0 || box.top > innerHeight) return;
    const live = out?.kind === 'live' ? out.handle : null;
    if (live && (prior ? prior === live : !scrolled)) {
      waitedOn = live;
      return;
    }
    step('next');
  }

  function commit() {
    // A search wait can end after the user has left: this list is then no longer on screen.
    if (!root.isConnected) return;
    writeUrl();
    step('replace', { query: query() });
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

  // Scrolling the list end into view reads on.
  const endSeen = new IntersectionObserver((changes) => {
    if (changes.some((c) => c.isIntersecting)) readOn(true);
  });
  endSeen.observe(sentinel);
  // An activity frame says the log moved; the core decides whether to ask again.
  const onFrame = () => step('frame');
  addEventListener('gateway-activity', onFrame);
  // A reset of the activity log means the same: what the list showed may be gone.
  // A reset of another log (config) leaves this list as it is.
  const onReset = (e) => { if (e.detail?.kind === 'activity') { step('frame'); step('frame'); } };
  addEventListener('gateway-reset', onReset);
  // Leaving: the shell swaps the content out, so this list's root leaves the document.
  // The request in flight is aborted and nothing more is asked or drawn.
  const gone = new MutationObserver(() => {
    if (left || root.isConnected) return;
    left = true;
    listCore.leave(list).abort?.abort.abort();
    removeEventListener('gateway-activity', onFrame);
    removeEventListener('gateway-reset', onReset);
    endSeen.disconnect();
    gone.disconnect();
    opened();
  });
  gone.observe(document.body, { childList: true, subtree: true });

  step('replace', { query: query() });
  await firstDone;
}

// ---------------------------------------------------------------- receipt

/** The list row a receipt was opened from; the list gives it focus again on the way back. */
let returnTo = null;

/** What the gateway records when a check kept no rule id (src/security/decision_record_read.rs). */
const RULE_NOT_RECORDED = 'rule not recorded for this check';

// The keys a receipt shows, per wire kind (a refusal's kind is "call"). true is a plain
// value; STR and WHOLE take only a string or only a whole number; an object maps its own
// keys; LIST is a list of items of that shape; TEXTS a list of strings; EITHER takes a
// string or that shape. Nothing else is shown or
// copied: an unlisted key, or a listed key holding another shape, is dropped.
const LIST = (item) => ({ list: item });
const STR = (v) => typeof v === 'string';
const WHOLE = (v) => Number.isInteger(v);
const TEXTS = { texts: true };
const EITHER = (shape) => ({ either: shape });
const FINDINGS = LIST({ scan_type: true, severity: true, location: true });
const BASE = {
  id: true, kind: true, counter: true, timestamp: true, signature: true, integrity: true, unanchored: true,
  signing_anchor: true,
  chain: { counter: true, prev_entry_hash: true, entry_hash: true, link: true, window: true, window_scope: true },
};
const SHOWN = {
  call: {
    ...BASE,
    server: true, tool: true, route: true, trace_id: true, outcome: true, error_code: true,
    who: { credential_kind: true, account: true, authority: true, subject: true },
    request_hash: true, response_hash: true, effect: true,
    answer_findings: EITHER(FINDINGS), answer_findings_total: true, answer_integrity: true, answer_integrity_scope: true,
    findings: EITHER(FINDINGS), findings_truncated: true,
    answer: {
      effect: true, line: true, records: LIST({ counter: true, effect: true, findings_listed: WHOLE }), more: true,
      search: { bytes: true, lines: true, stopped: true },
    },
    decision: EITHER({
      kind: true, rule: true, grant: STR, flags: STR, effect: true, decided: true,
      config_revision: true, running_revision: true, config_revision_capabilities: true,
      reason: true, scope: true, capability: true, grant_id: true,
    }),
    reach: EITHER({ jti: true, backends: TEXTS, tools: TEXTS, expires_by: true }),
  },
  config: {
    ...BASE,
    action: true, actor_id: true, target_id: true, outcome: true,
    reason: { recorded: true, length: true }, rollback_summary: { recorded: true, length: true },
  },
  admin_action: { ...BASE, surface: true, route: true, method: true, http_status: true, tool: true, outcome: true },
};

const plain = (v) => typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean';
const isMap = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

/** The one projection: what the receipt shows, what Copy as JSON copies, and what its fallback shows. */
function project(value, shape) {
  if (shape === true) return plain(value) ? value : undefined;
  if (typeof shape === 'function') return shape(value) ? value : undefined;
  if (shape.either) return typeof value === 'string' ? value : project(value, shape.either);
  if (shape.texts) return Array.isArray(value) ? value.filter((v) => typeof v === 'string') : undefined;
  if (shape.list) {
    if (!Array.isArray(value)) return undefined;
    return value.filter(isMap).map((entry) => project(entry, shape.list));
  }
  if (!isMap(value)) return undefined;
  const out = {};
  for (const [key, sub] of Object.entries(shape)) {
    const v = project(value[key], sub);
    if (v !== undefined) out[key] = v;
  }
  return out;
}

const labelOf = (path) => path.replace(/\[\]/g, '').split('.').map((k) => k.replace(/_/g, ' ')).join(' · ');

/** A value as words. no_record is never final: the delivery record lands after the call. */
function wordsOf(path, v) {
  if (v === true) return 'yes';
  if (v === false) return 'no';
  if ((path === 'effect' || path === 'answer.effect') && v === 'no_record') return 'delivery not yet recorded';
  if (path === 'reach.expires_by') return `expires by ${v}`;
  return String(v);
}

/** Each shown value as a dt naming it and a dd carrying its key path in data-field. */
function factsOf(projected, shape, path, into) {
  for (const [key, sub] of Object.entries(shape)) {
    const v = projected[key];
    if (v === undefined) continue;
    const at = path ? `${path}.${key}` : key;
    const form = sub.either && !plain(v) ? sub.either : sub;
    if (isMap(form) && !form.list && !form.texts && !form.either && !plain(v)) {
      factsOf(v, form, at, into);
      continue;
    }
    const value = h('dd', {});
    value.style.overflowWrap = 'anywhere';
    value.style.minWidth = '0';
    if (form.list) {
      const items = h('ol', { class: 'activity-items' });
      for (const entry of v) {
        const li = h('li', {});
        for (const k of Object.keys(form.list)) {
          if (entry[k] === undefined) continue;
          li.append(h('span', { 'data-field': `${at}[].${k}` }, `${k.replace(/_/g, ' ')}: ${wordsOf(`${at}.${k}`, entry[k])}`), ' ');
        }
        items.append(li);
      }
      value.append(items);
    } else {
      value.setAttribute('data-field', at);
      if (form.texts) value.textContent = v.join(', ');
      else if (at === 'decision.rule' && typeof v === 'string' && v !== RULE_NOT_RECORDED) {
        // The rule link is the list filtered by that rule.
        value.append(h('a', { class: 'lnk', href: `/ui/activity?rule=${encodeURIComponent(v)}` }, v));
      } else value.textContent = wordsOf(at, v);
    }
    into.append(h('dt', {}, labelOf(at)), value);
  }
}

/** Copy the projection's JSON; where the clipboard cannot take it, show it read-only and selected. */
async function copyJson(text, out) {
  try {
    if (!navigator.clipboard?.writeText) throw new Error('no clipboard');
    await navigator.clipboard.writeText(text);
    out.replaceChildren(h('p', { class: 'muted' }, 'Copied.'));
  } catch {
    const area = h('textarea', { class: 'input activity-json', readonly: true, rows: 12, 'aria-label': 'This entry as JSON' });
    area.value = text;
    area.style.width = '100%';
    out.replaceChildren(area);
    area.focus();
    area.select();
  }
}

/** One entry on its own page: one request at a time, aborted on a new one or on leaving. */
async function receiptTab(body, ctx) {
  const id = ctx.object;
  returnTo = `/ui/activity/${encodeURIComponent(id)}/status`;
  const root = h('div', { class: 'activity-receipt' });
  root.style.minWidth = '0';
  const view = h('div', {});
  const note = h('p', { class: 'muted', hidden: true });
  root.append(h('p', {}, h('a', { class: 'lnk', href: '/ui/activity/status' }, 'Back to Activity')), view);
  body.append(root);
  let flight = null;
  let left = false;
  let recordedShown = false;
  let settled;
  const firstDone = new Promise((done) => { settled = done; });

  function draw(p, kind) {
    const facts = h('dl', { class: 'activity-facts' });
    facts.style.minWidth = '0';
    factsOf(p, SHOWN[kind] ?? BASE, '', facts);
    const copyOut = h('div', {});
    const copy = h('button', { class: 'btn', type: 'button' }, 'Copy as JSON');
    copy.addEventListener('click', () => copyJson(JSON.stringify(p, null, 2), copyOut));
    const parts = [facts, h('p', {}, copy), copyOut];
    if (p.effect === 'no_record') {
      const again = h('button', { class: 'btn', type: 'button' }, 'Check again');
      again.addEventListener('click', () => load(true));
      parts.push(h('p', {}, again));
    }
    note.hidden = true;
    unbanner();
    view.replaceChildren(...parts, note);
  }

  // The error and forbidden states are the shell's banner, so it owns their insertion
  // and announcement; a later answer takes the banner away again.
  let bannered = false;
  function unbanner() {
    if (bannered) ctx.show(null);
    bannered = false;
  }

  function failed(err) {
    const status = err?.status;
    // A banner replaces the one shown; the same banner again stays, with the focus in it.
    if (status === 404 || status === 401) unbanner();
    if (status === 404) {
      view.replaceChildren(ctx.state('not-found', {
        title: 'Not in the kept log',
        body: 'No such entry is in the kept log: it may have rotated out, or this key may not read it.',
      }));
    } else if (status === 401) {
      // The shell's own sign-in has taken the page; the receipt draws again after it.
    } else if (status === 403) {
      view.replaceChildren();
      bannered = true;
      ctx.show('forbidden');
    } else {
      const retry = h('button', { class: 'btn', type: 'button' }, 'Retry');
      retry.addEventListener('click', () => load(false));
      view.replaceChildren();
      bannered = true;
      ctx.show('error', { title: 'This entry could not be read', action: retry });
    }
  }

  function load(again) {
    flight?.abort();
    const mine = new AbortController();
    flight = mine;
    ctx.api(`/ui/api/activity/${encodeURIComponent(id)}`, { signal: mine.signal }).then((data) => {
      if (left || flight !== mine) return;
      flight = null;
      const kind = isMap(data) && typeof data.kind === 'string' ? data.kind : null;
      const p = project(data, SHOWN[kind] ?? BASE) ?? {};
      const recorded = typeof p.effect === 'string' && p.effect !== 'no_record';
      // A no_record answer never undoes a recorded effect already shown for this entry.
      if (recorded || !recordedShown) {
        draw(p, kind);
        recordedShown = recorded;
      }
      settled();
    }, (err) => {
      if (err?.name === 'AbortError' || left || flight !== mine) return;
      flight = null;
      // A refusal or a missing entry is an answer, not a failed check: it gets its own state.
      if (again && ![401, 403, 404].includes(err?.status)) {
        note.textContent = 'Could not check again. The entry above is as last read.';
        note.hidden = false;
      } else {
        failed(err);
      }
      settled();
    });
  }

  // Leaving or opening another entry swaps the content out: abort, ask nothing more.
  const gone = new MutationObserver(() => {
    if (left || root.isConnected) return;
    left = true;
    flight?.abort();
    gone.disconnect();
    settled();
  });
  gone.observe(document.body, { childList: true, subtree: true });

  load(false);
  await firstDone;
}

register('activity', {
  title: 'Activity',
  tabs: {
    status: statusTab,
    actions: null,
    settings: null,
  },
});
