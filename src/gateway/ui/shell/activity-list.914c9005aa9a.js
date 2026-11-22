// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The Activity list's state, with no page, network or clock of its own: each
// transition takes the state and its input and returns the next state, the
// request to abort and the request to start. activity.js owns the requests.
//
// RED STUB, wrong on purpose: it follows the design except for one planted
// fault per core row (each marked "planted"), so every row gets through its
// setup and fails at the assertion it exists for. The real core replaces it.

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
  };
}

const unchanged = (state) => ({ state, abort: null, issue: null });
const spanAt = (query, now) => ({ from: now - query.spanMs, to: now });
const cursorOf = (answer) => (typeof answer.next_cursor === 'string' && answer.next_cursor ? answer.next_cursor : null);
const plus = (notices, name) => (notices.includes(name) ? notices : [...notices, name]);
const minus = (notices, ...names) => notices.filter((n) => !names.includes(n));
// Planted (ignored completion): handles compared by their contents, not identity.
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

/** The operator asks for page 1 of a query (open, filter, reset, release, page-1 retry). */
export function replace(state, { query, fresh, now }) {
  const ask = { handle: fresh, kind: 'page1', window: spanAt(query, now) };
  // Planted (fresh state): notices, held, newer and dirty survive the replace.
  const kept = { notices: state.notices, held: state.held, newer: state.newer, dirty: state.dirty };
  return { state: { ...initial(query), ...kept, flight: ask }, abort: state.flight?.handle ?? null, issue: ask };
}

/** A live activity frame arrived on the stream. */
export function frame(state, { fresh, now }) {
  if (state.held) {
    if (state.flight?.kind === 'append') {
      // Planted (frame while held): the page being read is dropped for a refresh.
      const ask = { handle: fresh, kind: 'live', window: spanAt(state.query, now) };
      return { state: { ...state, newer: true, flight: ask }, abort: state.flight.handle, issue: ask };
    }
    return { state: { ...state, newer: true }, abort: null, issue: null };
  }
  if (state.flight) return { state: { ...state, dirty: true }, abort: null, issue: null };
  // Planted (window): the refresh asks for the shown chain's window, not a new one.
  const ask = { handle: fresh, kind: 'live', window: state.window };
  return { state: { ...state, flight: ask }, abort: null, issue: ask };
}

/** The operator asks for the next page (the list end in view, or the next-page retry). */
export function next(state, { fresh }) {
  if (!state.cursor || state.flight?.kind === 'append') return unchanged(state);
  const ask = { handle: fresh, kind: 'append', cursor: state.cursor, window: state.window };
  // Planted (next page): an aborted refresh's news is dropped, `newer` stays as it was.
  return { state: { ...state, held: true, dirty: false, flight: ask }, abort: state.flight?.handle ?? null, issue: ask };
}

/** A request ended: an answer or a failure, for the handle it names. */
export function settle(state, { handle, answer, failed, fresh, now }) {
  const req = state.flight;
  if (!req || !same(handle, req.handle)) return unchanged(state);
  let s = { ...state, flight: null };
  if (failed) {
    if (req.kind === 'append') s.notices = plus(s.notices, 'next-retry');
    // Planted (kinds): a failed trailing refresh is taken for a failed page 1.
    else if (req.kind === 'page1' || req.trailing) s.notices = plus(s.notices, 'page1-retry');
    // Planted (failures): the stale notice replaces the others instead of joining them.
    else s.notices = ['stale'];
  } else if (req.kind === 'append' && answer.cursor_reset === true) {
    // Planted (cursor reset): the old notices come along into the new chain.
    s = { ...initial(state.query), rows: answer.rows, cursor: cursorOf(answer), window: req.window, notices: state.notices };
    if (!state.newer) return { state: s, abort: null, issue: null };
    const ask = { handle: fresh, kind: 'live', window: spanAt(state.query, now) };
    return { state: { ...s, flight: ask }, abort: null, issue: ask };
  } else if (req.kind === 'append') {
    s = { ...s, rows: [...state.rows, ...answer.rows], cursor: cursorOf(answer), notices: minus(s.notices, 'next-retry') };
  } else {
    s = { ...s, rows: answer.rows, cursor: cursorOf(answer), window: req.window, notices: minus(s.notices, 'page1-retry', 'stale') };
  }
  if (!s.dirty) return { state: s, abort: null, issue: null };
  // Planted (live counting): `dirty` is never cleared, so the refreshes never stop.
  const ask = { handle: fresh, kind: 'live', window: spanAt(state.query, now) };
  return { state: { ...s, flight: { ...ask, trailing: true } }, abort: null, issue: ask };
}

/** The operator left the screen. */
export function leave(state) {
  // Planted (leaving): the request in flight is left running.
  return { state, abort: null, issue: null };
}
