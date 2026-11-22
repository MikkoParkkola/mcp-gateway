// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The Activity list's state, with no page, network or clock of its own: each
// transition takes the state and its input and returns the next state, the
// request to abort and the request to start. activity.js owns the requests.
//
// RED STUB: every transition leaves the state as it is and starts nothing, so
// each list row fails at its own assertion until the real core replaces this.

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

/** The operator asks for page 1 of a query (open, filter, reset, release, page-1 retry). */
export function replace(state, _input) {
  return unchanged(state);
}

/** A live activity frame arrived on the stream. */
export function frame(state, _input) {
  return unchanged(state);
}

/** The operator asks for the next page (the list end in view, or the next-page retry). */
export function next(state, _input) {
  return unchanged(state);
}

/** A request ended: an answer or a failure, for the handle it names. */
export function settle(state, _input) {
  return unchanged(state);
}

/** The operator left the screen. */
export function leave(state) {
  return unchanged(state);
}
