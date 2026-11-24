// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The Activity list's state, with no page, network or clock of its own: each
// transition takes the state and its input and returns the next state, the
// request to abort and the request to start. activity.js owns the requests.
//
// One request at most is in flight. A settle acts only for the handle in
// flight, compared by identity. The shown chain (rows, cursor, window) changes
// only when an operator replace drops it or an answer applies to it.

/** The list for a query before any answer: nothing shown, nothing in flight. */
export function initial(query) {
  return {
    query,
    rows: [],
    cursor: null,
    window: null,
    dirty: false,
    held: false,
    newer: false,
    notices: [],
    flight: null,
    // The last applied answer's scan stopped before the end of the log; its cursor goes on.
    stalled: false,
  };
}

const unchanged = (state) => ({ state, abort: null, issue: null });
const spanAt = (query, now) => ({ from: now - query.spanMs, to: now });
const cursorOf = (answer) => (typeof answer.next_cursor === 'string' && answer.next_cursor ? answer.next_cursor : null);
const plus = (notices, name) => (notices.includes(name) ? notices : [...notices, name]);
const minus = (notices, ...names) => notices.filter((n) => !names.includes(n));
/** A live refresh of page 1 over the window that ends now. */
const liveAsk = (s, fresh, now) => ({ handle: fresh, kind: 'live', window: spanAt(s.query, now) });

/** The operator asks for page 1 of a query (open, filter, reset, release, page-1 retry). */
export function replace(state, { query, fresh, now }) {
  const ask = { handle: fresh, kind: 'page1', window: spanAt(query, now) };
  // Nothing of the old state carries over; the flight is the only addition.
  return { state: { ...initial(query), flight: ask }, abort: state.flight?.handle ?? null, issue: ask };
}

/** A live activity frame arrived on the stream. */
export function frame(state, { fresh, now }) {
  // While the operator reads older pages, news is only marked, never asked for.
  if (state.held) return { state: { ...state, newer: true }, abort: null, issue: null };
  // A page 1 or live refresh is out: one more refresh follows when it settles.
  if (state.flight) return { state: { ...state, dirty: true }, abort: null, issue: null };
  const ask = liveAsk(state, fresh, now);
  return { state: { ...state, flight: ask }, abort: null, issue: ask };
}

/** The operator asks for the next page (the list end in view, or the next-page retry). */
export function next(state, { fresh }) {
  if (!state.cursor || state.flight?.kind === 'append') return unchanged(state);
  const ask = { handle: fresh, kind: 'append', cursor: state.cursor, window: state.window };
  // A live refresh aborted here held news of its own: it is kept as `newer`.
  const newer = state.newer || state.flight?.kind === 'live';
  return { state: { ...state, held: true, dirty: false, newer, flight: ask }, abort: state.flight?.handle ?? null, issue: ask };
}

/** A request ended: an answer or a failure, for the handle it names. */
export function settle(state, { handle, answer, failed, fresh, now }) {
  const req = state.flight;
  // A late settle of an aborted request changes nothing at all.
  if (!req || handle !== req.handle) return unchanged(state);
  let s = { ...state, flight: null };
  if (failed) {
    const notice = { append: 'next-retry', page1: 'page1-retry', live: 'stale' }[req.kind];
    s.notices = plus(s.notices, notice);
  } else if (req.kind === 'append' && answer.cursor_reset === true) {
    // The cursor no longer exists: the chain starts again from this page, and
    // news held while paging becomes the one refresh that follows.
    s = { ...initial(state.query), rows: answer.rows, cursor: cursorOf(answer), window: req.window, dirty: state.newer };
  } else if (req.kind === 'append') {
    s = { ...s, rows: [...state.rows, ...answer.rows], cursor: cursorOf(answer), notices: minus(s.notices, 'next-retry') };
  } else {
    s = { ...s, rows: answer.rows, cursor: cursorOf(answer), window: req.window, notices: minus(s.notices, 'page1-retry', 'stale') };
  }
  // Every applied answer decides it afresh; a failure leaves it as it was.
  if (!failed) s.stalled = answer.scan_exhausted === true;
  if (!s.dirty) return { state: s, abort: null, issue: null };
  const ask = liveAsk(s, fresh, now);
  return { state: { ...s, dirty: false, flight: ask }, abort: null, issue: ask };
}

/** The operator left the screen: the request in flight is aborted, nothing starts. */
export function leave(state) {
  return { state, abort: state.flight?.handle ?? null, issue: null };
}
