// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Rows for how Activity › Status fetches its list: one request in flight at a
// time, a state built anew on every operator replace, and live news held back
// while the operator reads older pages. Two levels:
//   LC  the list core (activity-list.<hash>.js), a pure module, loaded here in
//       Node from the very bytes the gateway serves;
//   LE  the real shell and screen in Chromium, list answers held in routes and
//       activity frames sent on the fixture server's held stream.
import { isDeepStrictEqual } from 'node:util';
import { test, expect, blockingViolations, WIDTHS } from './base.mjs';
import { shellReady, heldStream, frame, countListeners } from './shell.mjs';
import { served } from './copy-check.mjs';

test.use({ timezoneId: 'UTC' });

let corePromise = null;
/**
 * The core module. Imported from a data: URL of its bytes, so Node reads it as
 * an ES module with no package.json deciding, and the bytes are the served ones.
 */
function loadCore() {
  corePromise ??= import(`data:text/javascript;base64,${Buffer.from(served(/^activity-list\.[0-9a-f]{12}\.js$/).text).toString('base64')}`);
  return corePromise;
}

// ---------------------------------------------------------------- LC: core

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const T1 = Date.parse('2026-11-15T12:00:00Z');
const T2 = T1 + 90_000;
const T3 = T1 + 180_000;
const Q0 = { name: 'q0', spanMs: DAY };
const QA = { name: 'qa', spanMs: DAY };
const Q2 = { name: 'q2', spanMs: HOUR };
/** The window a page 1 asked at `t` proposes for query `q`. */
const span = (q, t) => ({ from: t - q.spanMs, to: t });
/** What initial(q) must hold, written out here rather than read from the core. */
const FRESH = (q) => ({ query: q, rows: [], cursor: null, window: null, dirty: false, held: false, newer: false, notices: [], flight: null, stalled: false });
/** An answer whose scan stopped before the end of the log: the cursor keeps looking. */
const stalledAnswer = (q, page, next) => ({ ...answer(q, page, next), scan_exhausted: true });
/** Fields that may survive an operator replace. None. */
const CARRY_OVER = [];
/** Rows of this test's own making, each naming its query, its page and its place. */
const tags = (q, page, n = 2) => Array.from({ length: n }, (_, i) => ({ id: `${q.name}.p${page}.${i}` }));
/** A list answer for page `page` of `q`, pointing on to `next`. */
const answer = (q, page, next) => ({ rows: tags(q, page), next_cursor: next });
const noticeSet = (s) => [...(s.notices ?? [])].sort();

/** Freeze a state all the way down, so a core that edits its input throws instead of passing. */
function frozen(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const v of Object.values(value)) frozen(v);
  }
  return value;
}

/**
 * What a step broke, or null. `open` is the test's own ledger (handle to the
 * request it was issued as): requests issued, minus those aborted, minus those
 * settled. It is built from the returned effects, never from state.flight.
 */
function broken({ name, input, before, out, openBefore, open }) {
  const s = out.state;
  if (open.size > 1) return `I1: ${open.size} requests in flight`;
  const stillOut = [...openBefore.keys()].filter((h) => !(name === 'settle' && h === input.handle));
  if (out.issue && stillOut.length > 0 && out.abort !== stillOut[0]) return `I2: ${name} started a request without aborting the one in flight`;
  if (s.dirty && s.held) return 'I3: dirty while held';
  if (s.dirty) {
    const [req] = open.values();
    if (!req || req.kind === 'append') return 'I4: dirty with no page 1 or live request in flight';
  }
  const chain = (x) => ({ rows: x.rows, cursor: x.cursor, window: x.window });
  let want = chain(before);
  if (name === 'replace') want = { rows: [], cursor: null, window: null };
  else if (name === 'settle' && input.answer && openBefore.has(input.handle)) {
    const req = openBefore.get(input.handle);
    const a = input.answer;
    const cursor = typeof a.next_cursor === 'string' && a.next_cursor ? a.next_cursor : null;
    want = req.kind === 'append' && a.cursor_reset !== true
      ? { rows: [...before.rows, ...a.rows], cursor, window: before.window }
      : { rows: a.rows, cursor, window: req.window };
  }
  if (!isDeepStrictEqual(chain(s), want)) return `I5: after ${name} the shown chain is ${JSON.stringify(chain(s))}, want ${JSON.stringify(want)}`;
  return null;
}

/** One list driven step by step, every step checked against the invariants. */
class Run {
  constructor(core, query, label) {
    this.core = core;
    this.label = label;
    this.state = frozen(core.initial(query));
    this.open = new Map();
    this.issues = [];
  }

  step(name, input = {}) {
    const before = this.state;
    const openBefore = new Map(this.open);
    const out = name === 'leave' ? this.core.leave(before) : this.core[name](before, input);
    expect(out !== null && typeof out === 'object' && 'state' in out, `${this.label}: ${name} returns { state, abort, issue }`).toBe(true);
    if (name === 'settle') this.open.delete(input.handle);
    if (out.abort) this.open.delete(out.abort);
    if (out.issue) {
      this.issues.push(out.issue);
      this.open.set(out.issue.handle, out.issue);
    }
    if (name !== 'leave') {
      expect(broken({ name, input, before, out, openBefore, open: this.open }), `${this.label}: invariants after ${name}`).toBeNull();
      this.state = frozen(out.state);
    }
    return out;
  }

  replace(query, now = T1, fresh = {}) { return this.step('replace', { query, fresh, now }); }
  frame(now = T2) { return this.step('frame', { fresh: {}, now }); }
  next(now = T2) { return this.step('next', { fresh: {}, now }); }
  ok(handle, body, now = T2) { return this.step('settle', { handle, answer: body, fresh: {}, now }); }
  fail(handle, now = T2) { return this.step('settle', { handle, failed: true, fresh: {}, now }); }
  leave() { return this.step('leave'); }
}

/** The request a step started; the row stops here, by name, when it started none or another kind. */
function started(out, kind, what) {
  expect(out.issue, `${what}: starts a ${kind} request`).not.toBeNull();
  expect(out.issue.kind, `${what}: the request's kind`).toBe(kind);
  return out.issue;
}

/** Page 1 of `q` asked at T1 and answered, pointing on to c2. Returns the run. */
function shown(core, q, label) {
  const r = new Run(core, q, label);
  const p1 = started(r.replace(q, T1), 'page1', `${label}: open`);
  r.ok(p1.handle, answer(q, 1, 'c2'));
  return r;
}

test.describe('LC list core', () => {
  // Three reachable states, each far from initial in its own way. Each drive
  // returns the request it leaves in flight (or null) and the fields it moved.
  const LC1_DRIVES = {
      'failed page 1': (r) => {
        const p1 = started(r.replace(Q0, T1), 'page1', 'failed page 1: open');
        r.fail(p1.handle);
        return { inFlight: null, moved: ['notices'] };
      },
      'held chain': (r) => {
        const p1 = started(r.replace(Q0, T1), 'page1', 'held chain: open');
        r.ok(p1.handle, answer(Q0, 1, 'c2'));
        r.fail(started(r.frame(T2), 'live', 'held chain: frame').handle);
        r.fail(started(r.next(T2), 'append', 'held chain: next page').handle);
        r.frame(T3);
        const more = started(r.next(T3), 'append', 'held chain: next page again');
        return { inFlight: more.handle, moved: ['rows', 'cursor', 'window', 'held', 'newer', 'notices'] };
      },
      'dirty live refresh': (r) => {
        const p1 = started(r.replace(Q0, T1), 'page1', 'dirty: open');
        r.ok(p1.handle, answer(Q0, 1, 'c2'));
        const live = started(r.frame(T2), 'live', 'dirty: frame');
        r.frame(T2);
        return { inFlight: live.handle, moved: ['rows', 'cursor', 'window', 'dirty'] };
      },
      'stopped scan': (r) => {
        const p1 = started(r.replace(Q0, T1), 'page1', 'stopped scan: open');
        r.ok(p1.handle, stalledAnswer(Q0, 1, 'c2'));
        return { inFlight: null, moved: ['rows', 'cursor', 'window', 'stalled'] };
      },
  };

  test('LC1 initial() holds exactly the fresh fields, and some drive moves each one', async () => {
    const core = await loadCore();
    expect(core.initial(Q2), 'LC1 initial()').toEqual(FRESH(Q2));
    const everMoved = new Set();
    for (const [label, drive] of Object.entries(LC1_DRIVES)) {
      const r = new Run(core, Q0, `LC1 ${label}`);
      drive(r);
      for (const key of Object.keys(FRESH(Q0))) if (!isDeepStrictEqual(r.state[key], FRESH(Q0)[key])) everMoved.add(key);
    }
    // A field added to the state later fails here until some drive moves it.
    for (const key of Object.keys(FRESH(Q0)).filter((k) => k !== 'query' && k !== 'flight')) {
      expect(everMoved.has(key), `LC1: some drive moves ${key}`).toBe(true);
    }
  });

  for (const [label, drive] of Object.entries(LC1_DRIVES)) {
    test(`LC1 an operator replace after a ${label} keeps nothing of it`, async () => {
      const core = await loadCore();
      const r = new Run(core, Q0, `LC1 ${label}`);
      const { inFlight, moved } = drive(r);
      for (const key of moved) {
        expect(r.state[key], `LC1 ${label}: premise, ${key} is not initial's`).not.toEqual(FRESH(Q0)[key]);
      }
      const H = {};
      const out = r.replace(Q2, T2, H);
      const { flight, ...rest } = out.state;
      const { flight: _none, ...freshRest } = FRESH(Q2);
      expect(Object.keys(out.state).sort(), `LC1 ${label}: key set`).toEqual([...Object.keys(FRESH(Q2)), ...CARRY_OVER].sort());
      expect(rest, `LC1 ${label}: every field but flight is initial's`).toEqual(freshRest);
      expect(flight?.handle, `LC1 ${label}: the flight is the new handle`).toBe(H);
      expect(flight.kind, `LC1 ${label}: flight kind`).toBe('page1');
      expect(flight.window, `LC1 ${label}: flight window`).toEqual({ from: T2 - HOUR, to: T2 });
      expect(out.abort, `LC1 ${label}: aborts what was in flight`).toBe(inFlight);
    });
  }

  // Each setup leaves A aborted and B, made the same way, in flight.
  const LC2_SETUPS = {
      page1: (r) => {
        const a = started(r.replace(Q0, T1), 'page1', 'LC2 page1: A');
        const b = r.replace(Q0, T1);
        return { a, b: started(b, 'page1', 'LC2 page1: B'), aborted: b.abort };
      },
      live: (r) => {
        const p1 = started(r.replace(Q0, T1), 'page1', 'LC2 live: open');
        r.ok(p1.handle, answer(Q0, 1, 'c2'));
        const a = started(r.frame(T2), 'live', 'LC2 live: A');
        const again = r.replace(Q0, T1);
        r.ok(started(again, 'page1', 'LC2 live: reopen').handle, answer(Q0, 1, 'c2'));
        return { a, b: started(r.frame(T2), 'live', 'LC2 live: B'), aborted: again.abort };
      },
      append: (r) => {
        const p1 = started(r.replace(Q0, T1), 'page1', 'LC2 append: open');
        r.ok(p1.handle, answer(Q0, 1, 'c2'));
        const a = started(r.next(T2), 'append', 'LC2 append: A');
        const again = r.replace(Q0, T1);
        r.ok(started(again, 'page1', 'LC2 append: reopen').handle, answer(Q0, 1, 'c2'));
        return { a, b: started(r.next(T2), 'append', 'LC2 append: B'), aborted: again.abort };
      },
  };

  for (const [kind, setup] of Object.entries(LC2_SETUPS)) {
    for (const how of ['answer', 'failure']) {
      test(`LC2 a late ${how} for an aborted ${kind} request changes nothing`, async () => {
        const core = await loadCore();
        const label = `LC2 ${kind} ${how}`;
        const r = new Run(core, Q0, label);
        const { a, b, aborted } = setup(r);
        expect(aborted, `${label}: premise, A was aborted`).toBe(a.handle);
        const { handle: _a, ...aRest } = a;
        const { handle: _b, ...bRest } = b;
        expect(bRest, `${label}: premise, B is built like A`).toEqual(aRest);
        // Called on the core itself: this row's own checks are the point, not the step invariants.
        const snapshot = r.state;
        const late = core.settle(snapshot, how === 'answer'
          ? { handle: a.handle, answer: answer(Q0, 7, 'c8'), fresh: {}, now: T3 }
          : { handle: a.handle, failed: true, fresh: {}, now: T3 });
        expect(late.state, `${label}: state unchanged`).toEqual(snapshot);
        expect(late.abort, `${label}: aborts nothing`).toBeNull();
        expect(late.issue, `${label}: starts nothing`).toBeNull();
        expect(late.state.flight?.handle, `${label}: B is still the flight, by identity`).toBe(b.handle);
      });
    }
  }

  test('LC2 a late page 1 does not read the dirty flag set on its successor', async () => {
    const core = await loadCore();
    const r = new Run(core, Q0, 'LC2 dirty');
    const a = started(r.replace(Q0, T1), 'page1', 'LC2 dirty: A');
    started(r.replace(Q0, T1), 'page1', 'LC2 dirty: B');
    r.frame(T2);
    expect(r.state.dirty, 'LC2 dirty: premise, the frame set dirty').toBe(true);
    const late = core.settle(r.state, { handle: a.handle, answer: answer(Q0, 1, 'c2'), fresh: {}, now: T3 });
    expect(late.state.dirty, 'LC2 dirty: still dirty').toBe(true);
    expect(late.issue, 'LC2 dirty: starts nothing').toBeNull();
  });

  test('LC3 every sequence of six inputs keeps the invariants', async () => {
    test.setTimeout(120_000);
    const core = await loadCore();
    // Settles target the request in flight; late ones the last aborted request.
    // With nothing to target, a settle names a handle never issued.
    const INPUTS = ['replace', 'frame', 'next', 'settle-ok', 'settle-fail', 'late-ok', 'late-fail', 'leave'];
    const DEPTH = 6;
    const stats = { sequences: 0, issued: 0, applied: 0 };
    let bad = null;
    const pageOf = (req) => (req.kind === 'append' ? Number(String(req.cursor).slice(1)) : 1);
    const ghost = (q) => ({ handle: {}, kind: 'page1', window: span(q, T1), query: q });
    // P1: the rows are pages 1..k of the shown query, in order, none twice, no gap.
    const chainOk = (s) => s.rows.length % 2 === 0
      && isDeepStrictEqual(s.rows, Array.from({ length: s.rows.length / 2 }, (_, i) => tags(s.query, i + 1)).flat());

    function walk(state, open, lastAborted, path) {
      if (bad) return;
      if (path.length === DEPTH) { stats.sequences += 1; return; }
      for (const name of INPUTS) {
        if (bad) return;
        const now = T1 + (path.length + 1) * 1000;
        const seq = [...path, name].join(' ');
        const current = [...open.values()][0] ?? null;
        let fn = name;
        let input;
        let target = null;
        if (name === 'replace') input = { query: state.query === Q0 ? QA : Q0, fresh: {}, now };
        else if (name === 'frame' || name === 'next') input = { fresh: {}, now };
        else if (name !== 'leave') {
          fn = 'settle';
          target = name.startsWith('late') ? (lastAborted ?? ghost(state.query)) : (current ?? ghost(state.query));
          input = name.endsWith('ok')
            // Every other depth answers with a stopped scan, so both values reach every input.
            ? { handle: target.handle, answer: { ...answer(target.query, pageOf(target), `c${pageOf(target) + 1}`), scan_exhausted: path.length % 2 === 1 }, fresh: {}, now }
            : { handle: target.handle, failed: true, fresh: {}, now };
        }
        let out;
        try {
          out = fn === 'leave' ? core.leave(state) : core[fn](state, input);
        } catch (e) {
          bad = `${seq}: threw ${e.message}`;
          return;
        }
        if (fn === 'leave') {
          // P8: leaving aborts what is in flight and starts nothing; a later visit opens afresh.
          if (out.abort !== (current?.handle ?? null) || out.issue) { bad = `${seq}: leave aborted the wrong request or started one`; return; }
          walk(frozen(core.initial(state.query)), new Map(), current ?? lastAborted, [...path, name]);
          continue;
        }
        const after = new Map(open);
        let aborted = lastAborted;
        if (target) after.delete(target.handle);
        if (out.abort) {
          aborted = after.get(out.abort) ?? aborted;
          after.delete(out.abort);
        }
        if (out.issue) {
          stats.issued += 1;
          after.set(out.issue.handle, { ...out.issue, query: name === 'replace' ? input.query : state.query });
        }
        if (target && input.answer && open.has(target.handle)) stats.applied += 1;
        const why = broken({ name: fn, input, before: state, out, openBefore: open, open: after });
        if (why) { bad = `${seq}: ${why}`; return; }
        // I6: stopped only when the last applied answer said so; a replace starts unstopped.
        const applied = fn === 'settle' && input.answer && open.has(target.handle);
        const wantStalled = name === 'replace' ? false : applied ? input.answer.scan_exhausted === true : state.stalled;
        if (out.state.stalled !== wantStalled) { bad = `${seq}: I6 stalled is ${out.state.stalled}, want ${wantStalled}`; return; }
        if (!chainOk(out.state)) { bad = `${seq}: P1 rows are not pages 1..k of ${out.state.query?.name}: ${JSON.stringify(out.state.rows)}`; return; }
        if (state.held && (name === 'frame' || name.startsWith('late')) && !isDeepStrictEqual(out.state.rows, state.rows)) {
          bad = `${seq}: P4 rows moved while held`;
          return;
        }
        walk(frozen(out.state), after, aborted, [...path, name]);
      }
    }

    walk(frozen(core.initial(Q0)), new Map(), null, []);
    expect(stats.issued, 'LC3 premise: the walk starts requests').toBeGreaterThan(0);
    expect(stats.applied, 'LC3 premise: some answers apply').toBeGreaterThan(0);
    expect(bad, 'LC3 first counterexample').toBeNull();
    expect(stats.sequences, 'LC3 sequences walked (8^6)').toBe(262_144);
  });

  test('LC12 a stopped scan marks the list stalled until the next answer', async () => {
    const core = await loadCore();
    const r = new Run(core, Q0, 'LC12');
    r.ok(started(r.replace(Q0, T1), 'page1', 'LC12: open').handle, stalledAnswer(Q0, 1, 'c2'));
    expect(r.state.stalled, 'LC12 page 1 stopped short').toBe(true);
    r.fail(started(r.next(T2), 'append', 'LC12: next').handle);
    expect(r.state.stalled, 'LC12 a failed next page leaves it').toBe(true);
    r.ok(started(r.next(T2), 'append', 'LC12: retry').handle, answer(Q0, 2, 'c3'));
    expect(r.state.stalled, 'LC12 an answer that read to its end clears it').toBe(false);
    r.ok(started(r.next(T3), 'append', 'LC12: next again').handle, stalledAnswer(Q0, 3, 'c4'));
    expect(r.state.stalled, 'LC12 a next page that stopped short sets it').toBe(true);
    const again = started(r.replace(Q0, T3), 'page1', 'LC12: reopen');
    expect(r.state.stalled, 'LC12 a replace clears it').toBe(false);
    r.ok(again.handle, answer(Q0, 1, 'c2'));
    const reset = started(r.next(T3), 'append', 'LC12: next before a reset');
    r.ok(reset.handle, { ...stalledAnswer(Q0, 1, 'c2'), cursor_reset: true });
    expect(r.state.stalled, 'LC12 a cursor reset takes it from its own answer').toBe(true);
    // A live refresh applies its answer as page 1 does.
    const live = shown(core, Q0, 'LC12 live');
    live.ok(started(live.frame(T2), 'live', 'LC12 live: frame').handle, stalledAnswer(Q0, 1, 'c2'));
    expect(live.state.stalled, 'LC12 a live refresh that stopped short sets it').toBe(true);
  });

  test('LC4 on an idle page 1, no frame asks nothing and one frame asks one refresh', async () => {
    const core = await loadCore();
    {
      const r = shown(core, Q0, 'LC4 idle');
      expect(r.issues.length, 'LC4 idle: 0 frames start 0 requests').toBe(1);
      const live = started(r.frame(T2), 'live', 'LC4 idle: 1 frame');
      expect(r.issues.length, 'LC4 idle: exactly 1 refresh').toBe(2);
      const end = r.ok(live.handle, answer(Q0, 1, 'c2'));
      expect(end.issue, 'LC4 idle: no frame during it, so the chain stops').toBeNull();
    }
  });

  for (const frames of [1, 5]) {
    for (const how of ['ok', 'fail']) {
      test(`LC4 ${frames} frame(s) during a refresh that ends ${how} give exactly one more`, async () => {
        const core = await loadCore();
        const label = `LC4 ${frames} frame(s), refresh ${how}`;
        const r = shown(core, Q0, label);
        const live = started(r.frame(T2), 'live', `${label}: first frame`);
        for (let i = 0; i < frames; i += 1) expect(r.frame(T2).issue, `${label}: a frame during the refresh starts nothing`).toBeNull();
        const count = r.issues.length;
        const end = how === 'ok' ? r.ok(live.handle, answer(Q0, 1, 'c2'), T3) : r.fail(live.handle, T3);
        const trailing = started(end, 'live', `${label}: settle`);
        expect(r.issues.length - count, `${label}: exactly one trailing refresh`).toBe(1);
        expect(trailing.window, `${label}: the trailing refresh asks a window from its own clock`).toEqual(span(Q0, T3));
        expect(r.frame(T3).issue, `${label}: a frame during the trailing one starts nothing yet`).toBeNull();
        const more = started(r.ok(trailing.handle, answer(Q0, 1, 'c2'), T3), 'live', `${label}: one more`);
        expect(r.ok(more.handle, answer(Q0, 1, 'c2'), T3).issue, `${label}: then the chain stops`).toBeNull();
      });
    }
  }

  test('LC5 a next page holds the list and aborts a live refresh', async () => {
    const core = await loadCore();
    const r = shown(core, Q0, 'LC5');
    const live = started(r.frame(T2), 'live', 'LC5: frame');
    r.frame(T2);
    expect(r.state.dirty, 'LC5: premise, dirty before the next page').toBe(true);
    const out = r.next(T2);
    const append = started(out, 'append', 'LC5: next page');
    expect(append.cursor, 'LC5: asks after the shown cursor').toBe('c2');
    expect(out.abort, 'LC5: aborts the live refresh, by identity').toBe(live.handle);
    expect([out.state.held, out.state.newer, out.state.dirty], 'LC5: held, newer, not dirty').toEqual([true, true, false]);
    const busy = r.next(T3);
    expect([busy.state, busy.abort, busy.issue], 'LC5: refused while an append is in flight').toEqual([out.state, null, null]);
  });

  test('LC5 a next page is refused before any page 1 answer gives a cursor', async () => {
    const core = await loadCore();
    const f = new Run(core, Q0, 'LC5 fresh');
    started(f.replace(Q0, T1), 'page1', 'LC5 fresh: open');
    const before = f.state;
    const early = f.next(T2);
    expect([early.state, early.abort, early.issue], 'LC5 fresh: refused with no cursor').toEqual([before, null, null]);
  });

  test('LC6 a frame while held only marks newer', async () => {
    const core = await loadCore();
    const r = shown(core, Q0, 'LC6');
    started(r.next(T2), 'append', 'LC6: next page');
    expect(r.state.held, 'LC6: premise, held').toBe(true);
    const { rows, cursor } = r.state;
    const out = r.frame(T3);
    expect(out.issue, 'LC6: starts nothing').toBeNull();
    expect(out.state.newer, 'LC6: newer').toBe(true);
    expect([out.state.rows, out.state.cursor], 'LC6: rows and cursor kept').toEqual([rows, cursor]);
  });

  test('LC7 a failed page 1 then a failed refresh keep both notices; a page 1 answer clears them', async () => {
    const core = await loadCore();
    {
      const r = new Run(core, Q0, 'LC7 page 1');
      r.fail(started(r.replace(Q0, T1), 'page1', 'LC7 page 1: open').handle);
      expect([noticeSet(r.state), r.state.rows, r.state.held], 'LC7 page 1 failed').toEqual([['page1-retry'], [], false]);
      const live = started(r.frame(T2), 'live', 'LC7 page 1: frame');
      r.fail(live.handle);
      expect(noticeSet(r.state), 'LC7 page 1 then live failed: both notices').toEqual(['page1-retry', 'stale']);
      const again = started(r.frame(T3), 'live', 'LC7 page 1: frame again');
      r.ok(again.handle, answer(Q0, 1, 'c2'), T3);
      expect(noticeSet(r.state), 'LC7 page 1: a page 1 answer clears both').toEqual([]);
    }
  });

  test('LC7 a failed live refresh keeps the rows and shows stale; its answer clears it', async () => {
    const core = await loadCore();
    {
      const r = shown(core, Q0, 'LC7 live');
      r.fail(started(r.frame(T2), 'live', 'LC7 live: frame').handle);
      expect([r.state.rows, noticeSet(r.state)], 'LC7 live failed: rows kept, stale shown').toEqual([tags(Q0, 1), ['stale']]);
      r.ok(started(r.frame(T3), 'live', 'LC7 live: frame again').handle, answer(Q0, 1, 'c2'), T3);
      expect(noticeSet(r.state), 'LC7 live: the refresh answer clears stale').toEqual([]);
    }
  });

  test('LC7 a failed next page keeps the chain and the hold; its retry appends', async () => {
    const core = await loadCore();
    {
      const r = shown(core, Q0, 'LC7 append');
      r.fail(started(r.next(T2), 'append', 'LC7 append: next').handle);
      expect([r.state.rows, r.state.cursor, noticeSet(r.state), r.state.held], 'LC7 append failed').toEqual([tags(Q0, 1), 'c2', ['next-retry'], true]);
      const retry = started(r.next(T3), 'append', 'LC7 append: retry');
      r.ok(retry.handle, answer(Q0, 2, 'c3'), T3);
      expect([r.state.rows, noticeSet(r.state)], 'LC7 append: its answer appends and clears the retry').toEqual([[...tags(Q0, 1), ...tags(Q0, 2)], []]);
    }
  });

  for (const kind of ['live', 'append']) {
    test(`LC8 leaving with a ${kind} request out aborts it and starts nothing`, async () => {
      const core = await loadCore();
      const r = shown(core, Q0, `LC8 ${kind}`);
      const req = started(kind === 'live' ? r.frame(T2) : r.next(T2), kind, `LC8 ${kind}: in flight`);
      const out = r.leave();
      expect(out.abort, `LC8 ${kind}: aborts it, by identity`).toBe(req.handle);
      expect(out.issue, `LC8 ${kind}: starts nothing`).toBeNull();
    });
  }

  test('LC8 a later open starts from initial', async () => {
    const core = await loadCore();
    const back = new Run(core, Q0, 'LC8 back').replace(Q0, T3);
    const { flight: _f, ...rest } = back.state;
    const { flight: _g, ...fresh } = FRESH(Q0);
    expect(rest, 'LC8: a later open is initial').toEqual(fresh);
  });

  test('LC9 a next page asks its chain\'s window, not the clock\'s', async () => {
    const core = await loadCore();
    {
      const r = shown(core, Q0, 'LC9 append');
      const append = started(r.next(T2), 'append', 'LC9 append: next');
      expect(append.window, 'LC9 append: the chain window').toEqual(span(Q0, T1));
      expect(append.window, 'LC9 append: not a clock window').not.toEqual(span(Q0, T2));
    }
  });

  /** A shown page 1 (asked at T1) and a frame's live refresh asked at T3. */
  const liveAt3 = (core, label) => {
      const r = shown(core, Q0, label);
      const live = started(r.frame(T3), 'live', `${label}: frame`);
      expect(live.window, `${label}: a window at the frame's clock`).toEqual(span(Q0, T3));
      expect(live.window, `${label}: not the chain's`).not.toEqual(span(Q0, T1));
      return { r, live };
  };

  test('LC9 a live refresh asks a new window, and its answer moves the chain to it', async () => {
    const core = await loadCore();
    {
      const { r, live } = liveAt3(core, 'LC9 live');
      r.ok(live.handle, answer(Q0, 1, 'c2'), T3);
      expect(started(r.next(T3), 'append', 'LC9 live: next').window, 'LC9 live: the applied window').toEqual(span(Q0, T3));
    }
  });

  test('LC9 an aborted live refresh leaves the chain\'s window', async () => {
    const core = await loadCore();
    {
      const { r } = liveAt3(core, 'LC9 aborted');
      expect(started(r.next(T3), 'append', 'LC9 aborted: next').window, 'LC9 aborted: the chain window').toEqual(span(Q0, T1));
    }
  });

  test('LC9 a failed live refresh leaves the chain\'s window', async () => {
    const core = await loadCore();
    {
      const { r, live } = liveAt3(core, 'LC9 failed');
      r.fail(live.handle, T3);
      expect(started(r.next(T3), 'append', 'LC9 failed: next').window, 'LC9 failed: the chain window').toEqual(span(Q0, T1));
    }
  });

  test('LC10 each request names its kind, and fails by it', async () => {
    const core = await loadCore();
    const r = new Run(core, Q0, 'LC10');
    const p1 = started(r.replace(Q0, T1), 'page1', 'LC10: replace');
    r.ok(p1.handle, answer(Q0, 1, 'c2'));
    const live = started(r.frame(T2), 'live', 'LC10: frame on an idle page 1');
    r.frame(T2);
    const trailing = started(r.ok(live.handle, answer(Q0, 1, 'c2')), 'live', 'LC10: trailing refresh');
    r.fail(trailing.handle);
    expect(r.state.rows, 'LC10: a failed live refresh keeps the rows').toEqual(tags(Q0, 1));
    expect(noticeSet(r.state), 'LC10: and fails as a live refresh, not as a page 1').toEqual(['stale']);
    started(r.next(T3), 'append', 'LC10: next page');
  });

  const R = [{ id: 'q0.reset.0' }, { id: 'q0.reset.1' }];
  /** A held chain of pages 1-2 with the stale notice and page 3 in flight; `newer` as asked. */
  const held = (core, label, withNewer) => {
      const r = shown(core, Q0, label);
      r.fail(started(r.frame(T2), 'live', `${label}: frame`).handle);
      r.ok(started(r.next(T2), 'append', `${label}: page 2`).handle, answer(Q0, 2, 'c3'));
      if (withNewer) r.frame(T2);
      const append = started(r.next(T2), 'append', `${label}: page 3`);
      expect([r.state.rows, r.state.held, r.state.newer, noticeSet(r.state)], `${label}: premise`)
        .toEqual([[...tags(Q0, 1), ...tags(Q0, 2)], true, withNewer, ['stale']]);
      return { r, append };
  };

  test('LC11 a cursor reset starts the chain again and refreshes for the news held', async () => {
    const core = await loadCore();
    const { flight: _f, ...fresh } = FRESH(Q0);
    {
      const { r, append } = held(core, 'LC11 newer', true);
      const out = r.ok(append.handle, { rows: R, next_cursor: 'c9', cursor_reset: true }, T3);
      const { flight, ...rest } = out.state;
      expect(rest, 'LC11 newer: initial with the answer applied').toEqual({ ...fresh, rows: R, cursor: 'c9', window: span(Q0, T1) });
      const live = started(out, 'live', 'LC11 newer: the reset settle');
      expect(live.window, 'LC11 newer: on a new window').toEqual(span(Q0, T3));
      expect(flight?.handle, 'LC11 newer: that request is the flight').toBe(live.handle);
    }
  });

  test('LC11 a cursor reset with no news held asks nothing, and ends the hold', async () => {
    const core = await loadCore();
    {
      const { r, append } = held(core, 'LC11 quiet', false);
      const out = r.ok(append.handle, { rows: R, next_cursor: 'c9', cursor_reset: true }, T3);
      expect([out.issue, out.state.flight], 'LC11 quiet: starts nothing').toEqual([null, null]);
      expect(out.state.held, 'LC11 quiet: the hold ended').toBe(false);
      started(r.frame(T3), 'live', 'LC11 quiet: a frame now refreshes');
    }
  });

  test('LC11 the same answer without a reset appends and stays held', async () => {
    const core = await loadCore();
    {
      const { r, append } = held(core, 'LC11 no reset', true);
      const out = r.ok(append.handle, { rows: R, next_cursor: 'c9' }, T3);
      expect([out.state.rows, out.state.held], 'LC11 no reset: appends and stays held').toEqual([[...tags(Q0, 1), ...tags(Q0, 2), ...R], true]);
    }
  });
});

// ---------------------------------------------------------------- LE: browser

const AT = Date.parse('2026-11-15T12:00:00Z');
/** Epoch ms as the list query writes it: UTC to the second. */
const utc = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
const HELLO = frame('hello', { kinds: ['status', 'reload', 'activity', 'config'], head: 'b1.s1.r1' });
const STALE_TEXT = 'The newest calls could not be read.';
const CONTROL = 'Newer activity · show';
const NEWER_SAID = 'Newer activity is waiting above the list.';
const MORE_FAILED = 'More calls could not be read.';
const UNAVAILABLE = 'Activity is unavailable';
const NOT_FINAL = 'delivery not yet recorded';
// The slot's faces and what it says (the frozen spec's words).
const LOAD_MORE = 'Load more';
const KEEP_LOOKING = 'Keep looking';
const READING = 'Reading more…';
const NONE_YET = 'No matching call in the part of the log searched so far.';
const STOPPED = 'The search stopped before the end of the log.';
const SAY_NONE_YET = 'Nothing found yet. You can keep looking.';
const SAY_NO_MORE_YET = 'No more matching calls yet. You can keep looking.';
const SAY_NONE = 'No calls found.';
const SAY_NO_MORE = 'No more matching calls.';
/** A list answer that stopped short of the end of the log, with a cursor to keep looking. */
const stopped = (rows, next = 'c2') => ({ rows, next_cursor: next, scan_exhausted: true });

/** A call row as the list answers it. Every row of a page has its own tool, so its text is its own. */
function callRow(tool, extra = {}) {
  return {
    id: `id-${tool}`,
    kind: 'call',
    timestamp: '2026-11-15T08:00:00Z',
    outcome: 'ok',
    who: { credential_kind: 'api_key', account: 'ops' },
    server: 'docs',
    tool,
    ...extra,
  };
}
/** `n` rows for page `p` of a query tagged `q`. */
const rowsOf = (q, p, n = 2) => Array.from({ length: n }, (_, i) => callRow(`${q}.p${p}.r${i}`));
/** The text a row link shows for a row (the page runs in UTC). */
const textOf = (row) => `08:00:00 ops ${row.tool} ok`;
let frameId = 1;
const activityFrame = (row) => frame('activity', row, `b1.s1.r${(frameId += 1)}`);
/** A live-stream reset frame; its data names the log that was reset, or nothing. */
const resetFrame = (kind) => frame('reset', kind === undefined ? {} : { kind }, `b1.s1.r${(frameId += 1)}`);

/**
 * Count the stream events the shell hands the page, by kind, so a row knows a
 * frame arrived before it judges what the screen did with it. Add before open.
 */
const countDelivered = (page) => page.addInitScript(() => {
  window.__seen = { activity: 0, reset: 0 };
  addEventListener('gateway-activity', () => { window.__seen.activity += 1; });
  addEventListener('gateway-reset', () => { window.__seen.reset += 1; });
});
/** Filters an Activity address can carry; the list query names the caller where the address says `key`. */
const FILTERS = { outcome: 'failed', server: 'mail', caller: 'build-bot', q: 'invoice' };
/** The Activity address that opens with `filters` set. */
const filteredPath = ({ caller, ...rest }) => `/ui/activity/status?${new URLSearchParams({ ...rest, key: caller })}`;
/** Wait until the page has received exactly `n` events of `kind`. */
const seen = (page, kind, n, what) => expect.poll(() => page.evaluate((k) => window.__seen[k], kind), {
  message: `${what}: ${kind} events received`,
  timeout: 5_000,
}).toBe(n);

/**
 * The Activity screen with every list request held until the row answers it.
 * `sent` lists the requests in order; `failed` maps a request URL to the error
 * Chromium raised when the page aborted it.
 */
class Screen {
  constructor(page) {
    this.page = page;
    this.sent = [];
    this.failed = new Map();
  }

  async install() {
    const { page } = this;
    await page.clock.install({ time: AT - 60_000 });
    await page.clock.pauseAt(AT);
    await page.route('**/ui/api/status', (route) => route.fulfill({ json: { auth: { enabled: true, signed_in: true, admin: true } } }));
    await page.route((url) => url.pathname === '/ui/api/activity', (route) => new Promise((done) => {
      const href = route.request().url();
      const settleWith = async (reply) => {
        // A request the page aborted takes no answer; that is what the rows check.
        await route.fulfill(reply).catch(() => {});
        done();
      };
      this.sent.push({
        href,
        params: Object.fromEntries(new URL(href).searchParams),
        answer: (body) => settleWith({ json: body }),
        fail: (status = 500) => settleWith({ status, json: {} }),
      });
    }));
    page.on('requestfailed', (req) => {
      if (new URL(req.url()).pathname === '/ui/api/activity') this.failed.set(req.url(), req.failure()?.errorText ?? null);
    });
    // Every node written into the announcer, in order.
    await page.addInitScript(() => {
      window.__said = [];
      addEventListener('DOMContentLoaded', () => {
        const live = document.getElementById('announcer');
        if (live) new MutationObserver((changes) => {
          for (const c of changes) for (const n of c.addedNodes) window.__said.push((n.textContent ?? '').trim());
        }).observe(live, { childList: true, subtree: true, characterData: true });
      });
    });
  }

  /** Open the screen, then connect the held stream and say hello. */
  async open(stream, path = '/ui/activity/status') {
    await this.page.goto(path);
    await shellReady(this.page);
    await expect.poll(stream.connects, { message: 'the stream connects once' }).toBe(1);
    await stream.send(HELLO);
  }

  /** The `i`-th list request (from 0), once it has been sent. */
  async request(i, what) {
    await expect.poll(() => this.sent.length, { message: `${what}: list request #${i + 1} goes out`, timeout: 5_000 }).toBeGreaterThan(i);
    return this.sent[i];
  }

  /** The first list request that fits `pred`, once one has been sent. */
  async requestWhere(pred, what) {
    await expect.poll(() => this.sent.some(pred), { message: `${what}: goes out`, timeout: 5_000 }).toBe(true);
    return this.sent.find(pred);
  }

  /** No list request beyond the first `n` in a 500 ms wait. */
  async quiet(n, what) {
    await this.page.waitForTimeout(500);
    expect(this.sent.length, `${what}: list requests sent`).toBe(n);
  }

  /** The request ended aborted on the wire. */
  async aborted(req, what) {
    await expect.poll(() => this.failed.get(req.href) ?? 'not failed', { message: `${what}: aborted on the wire`, timeout: 5_000 }).toBe('net::ERR_ABORTED');
  }

  rows() { return this.page.locator('#content .activity-rows a'); }

  async texts() {
    return (await this.rows().allTextContents()).map((t) => t.replace(/\s+/g, ' ').trim());
  }

  /** Bring the end of the list into view, as reading down to it does. */
  async toEnd() {
    await this.rows().last().scrollIntoViewIfNeeded();
  }

  control() { return this.page.getByRole('button', { name: CONTROL, exact: true }); }

  said() { return this.page.evaluate(() => window.__said.length); }

  /** A button of the screen by its exact name. */
  button(name) { return this.page.locator('#content').getByRole('button', { name, exact: true }); }

  /** The one line after the rows that says how to get more. */
  slot() { return this.page.locator('#content .activity-more-error'); }

  emptyState() { return this.page.locator('#content [data-state="empty"]'); }

  /** What the focused element says, spaces folded as texts() folds a row. */
  focusedText() { return this.page.evaluate(() => (document.activeElement?.textContent ?? '').replace(/\s+/g, ' ').trim()); }

  /** Whether focus sits on the slot element itself. */
  focusOnSlot() { return this.page.evaluate(() => document.activeElement?.classList.contains('activity-more-error') ?? false); }

  /** Whether the observer's target after the rows is inside the viewport. */
  endInView() {
    return this.page.evaluate(() => {
      const box = document.querySelector('#content .activity-more').getBoundingClientRect();
      return box.bottom >= 0 && box.top <= innerHeight;
    });
  }

  /** How many times `text` was said: one announcer entry can join several messages. */
  heard(text) { return this.page.evaluate((t) => window.__said.join(' ').split(t).length - 1, text); }
}

/** A Screen and a held stream for this test, installed before the page loads. */
async function screenFor(page, request, testInfo) {
  const stream = await heldStream(page, request, testInfo);
  const screen = new Screen(page);
  await screen.install();
  return { screen, stream };
}

/** A filter change: an outcome button, which commits at once (the search waits 300 ms). */
const pickOutcome = (page, name) => page.locator('#content').getByRole('button', { name, exact: true }).click();

test.describe('LE list screen', () => {
  test('LE1 pages chain on one window, and a frame while paging asks for nothing', async ({ page, request }, testInfo) => {
    const { screen, stream } = await screenFor(page, request, testInfo);
    const [one, two, three] = [rowsOf('a', 1), rowsOf('a', 2), rowsOf('a', 3)];
    await screen.open(stream);
    const p1 = await screen.request(0, 'LE1 page 1');
    await p1.answer({ rows: one, next_cursor: 'c2' });
    const p2 = await screen.request(1, 'LE1 page 2');
    expect([p2.params.cursor, p2.params.from, p2.params.to], 'LE1 page 2 on page 1\'s window').toEqual(['c2', p1.params.from, p1.params.to]);
    await p2.answer({ rows: two, next_cursor: 'c3' });
    const p3 = await screen.request(2, 'LE1 page 3');
    expect([p3.params.cursor, p3.params.from, p3.params.to], 'LE1 page 3 on page 1\'s window').toEqual(['c3', p1.params.from, p1.params.to]);
    await p3.answer({ rows: three, next_cursor: null });
    const all = [...one, ...two, ...three].map(textOf);
    await expect.poll(() => screen.texts(), { message: 'LE1 the chain in order' }).toEqual(all);
    await stream.send(activityFrame(callRow('a.live')));
    await screen.quiet(3, 'LE1 after a frame while paging');
    expect(await screen.texts(), 'LE1 texts unchanged').toEqual(all);
  });

  test('LE2 back-to-back filters abort the requests they leave', async ({ page, request }, testInfo) => {
    const { screen, stream } = await screenFor(page, request, testInfo);
    await screen.open(stream);
    const q0 = await screen.request(0, 'LE2 page 1 of the first query');
    await pickOutcome(page, 'failed');
    const a = await screen.request(1, 'LE2 page 1 of filter A, sent while the first is out');
    await pickOutcome(page, 'blocked');
    const b = await screen.request(2, 'LE2 page 1 of filter B');
    await screen.aborted(q0, 'LE2 first query');
    await screen.aborted(a, 'LE2 filter A');
    const bRows = rowsOf('b', 1);
    await b.answer({ rows: bRows, next_cursor: null });
    await q0.answer({ rows: rowsOf('q0', 1), next_cursor: null });
    await a.answer({ rows: rowsOf('fa', 1), next_cursor: null });
    await page.waitForTimeout(500);
    expect(await screen.texts(), 'LE2 only B\'s rows').toEqual(bRows.map(textOf));
  });

  test('LE3 a frame refreshes page 1 on a new window, one more per burst', async ({ page, request }, testInfo) => {
    const { screen, stream } = await screenFor(page, request, testInfo);
    await screen.open(stream);
    const p1 = await screen.request(0, 'LE3 page 1');
    await p1.answer({ rows: rowsOf('a', 1), next_cursor: null });
    await screen.quiet(1, 'LE3 no frame');
    await page.clock.runFor(60_000);
    await stream.send(activityFrame(callRow('a.live')));
    const live = await screen.request(1, 'LE3 one frame');
    expect([live.params.cursor ?? null, live.params.from, live.params.to], 'LE3 the refresh asks up to now')
      .toEqual([null, utc(AT + 60_000 - DAY), utc(AT + 60_000)]);
    expect(live.params.to, 'LE3 not page 1\'s window').not.toBe(p1.params.to);
    for (let i = 0; i < 5; i += 1) await stream.send(activityFrame(callRow(`a.burst${i}`)));
    await screen.quiet(2, 'LE3 five frames while the refresh is out');
    await live.answer({ rows: rowsOf('a', 1), next_cursor: null });
    await screen.request(2, 'LE3 one trailing refresh');
    await screen.quiet(3, 'LE3 and only one');
  });

  test('LE4 paging holds live news behind one control the keyboard reaches', async ({ page, request }, testInfo) => {
    const { screen, stream } = await screenFor(page, request, testInfo);
    await screen.open(stream);
    await (await screen.request(0, 'LE4 page 1')).answer({ rows: rowsOf('a', 1, 60), next_cursor: 'c2' });
    await screen.toEnd();
    await screen.requestWhere((r) => r.params.cursor === 'c2', 'LE4 page 2, the hold starts');
    const before = await screen.said();
    for (let i = 0; i < 3; i += 1) await stream.send(activityFrame(callRow(`a.news${i}`)));
    await screen.quiet(2, 'LE4 three frames while held');
    await expect(screen.control(), 'LE4 the control shows').toBeVisible();
    expect(await screen.control().evaluate((el) => el.tagName), 'LE4 the control is a button').toBe('BUTTON');
    // The announcer writes after its dwell, and the clock is paused.
    await page.clock.runFor(2000);
    expect(await screen.said() - before, 'LE4 announced once for three frames').toBe(1);
    expect(await screen.heard('Newer activity is waiting'), 'LE4 the news is said once, not once per frame').toBe(1);
    const box = await screen.control().boundingBox();
    const { height } = page.viewportSize();
    expect(box.y >= 0 && box.y + box.height <= height, `LE4 the control stays in view at the list end (${JSON.stringify(box)})`).toBe(true);
    await page.evaluate(() => document.activeElement?.blur());
    let reached = false;
    for (let i = 0; i < 120 && !reached; i += 1) {
      await page.keyboard.press('Tab');
      reached = await screen.control().evaluate((el) => el === document.activeElement);
    }
    expect(reached, 'LE4 Tab reaches the control').toBe(true);
    await page.keyboard.press('Enter');
    const p1 = await screen.request(2, 'LE4 Enter asks page 1');
    expect(p1.params.cursor ?? null, 'LE4 page 1 has no cursor').toBeNull();
  });

  test('LE5 a next page aborts a live refresh, whose late answer shows nothing', async ({ page, request }, testInfo) => {
    const { screen, stream } = await screenFor(page, request, testInfo);
    const one = rowsOf('a', 1, 60);
    const two = rowsOf('a', 2);
    await screen.open(stream);
    const p1 = await screen.request(0, 'LE5 page 1');
    await p1.answer({ rows: one, next_cursor: 'c2' });
    await stream.send(activityFrame(callRow('a.live')));
    const live = await screen.requestWhere((r) => r !== p1 && !r.params.cursor, 'LE5 live refresh');
    // Page 2 is asked when the operator reaches the list end, not as soon as a tall page 1 arrives.
    expect(screen.sent.filter((r) => r.params.cursor).length, 'LE5 premise: no next page before the list end is in view').toBe(0);
    await screen.toEnd();
    const p2 = await screen.requestWhere((r) => r.params.cursor === 'c2', 'LE5 page 2');
    await screen.aborted(live, 'LE5 live refresh');
    await p2.answer({ rows: two, next_cursor: null });
    const want = [...one, ...two].map(textOf);
    await expect.poll(() => screen.texts(), { message: 'LE5 page 2 appends' }).toEqual(want);
    await live.answer({ rows: rowsOf('late', 1), next_cursor: null });
    await screen.quiet(3, 'LE5 after the late answer');
    expect(await screen.texts(), 'LE5 nothing of the late answer').toEqual(want);
  });

  test('LE5 a short page 1 whose end is in view reads on to page 2 after it is drawn', async ({ page, request }, testInfo) => {
    const { screen, stream } = await screenFor(page, request, testInfo);
    await screen.open(stream);
    await (await screen.request(0, 'LE5 short page')).answer({ rows: rowsOf('a', 1), next_cursor: 'c2' });
    await screen.requestWhere((r) => r.params.cursor === 'c2', 'LE5 short page: page 2 without a scroll');
  });

  test('LE5 a short page 1 lets its trailing live refresh land before it reads on', async ({ page, request }, testInfo) => {
    const { screen, stream } = await screenFor(page, request, testInfo);
    await screen.open(stream);
    const p1 = await screen.request(0, 'LE5 trailing: page 1');
    // A frame while page 1 is out: one live refresh follows its answer.
    await stream.send(activityFrame(callRow('a.live')));
    await p1.answer({ rows: rowsOf('a', 1), next_cursor: 'c2' });
    const live = await screen.request(1, 'LE5 trailing: the live refresh');
    expect(live.params.cursor ?? null, 'LE5 trailing: premise, a page 1 refresh').toBeNull();
    await screen.quiet(2, 'LE5 trailing: no next page while it is out');
    expect(screen.failed.has(live.href), 'LE5 trailing: the refresh is not aborted').toBe(false);
    const fresh = rowsOf('b', 1);
    await live.answer({ rows: fresh, next_cursor: 'c2' });
    await expect.poll(() => screen.texts(), { message: 'LE5 trailing: the refresh\'s rows' }).toEqual(fresh.map(textOf));
    await screen.requestWhere((r) => r.params.cursor === 'c2', 'LE5 trailing: then page 2');
  });

  test('LE5 on a busy gateway a short page 1 reads on after one live refresh', async ({ page, request }, testInfo) => {
    const { screen, stream } = await screenFor(page, request, testInfo);
    await screen.open(stream);
    const p1 = await screen.request(0, 'LE5 busy: page 1');
    await stream.send(activityFrame(callRow('a.live1')));
    await p1.answer({ rows: rowsOf('a', 1), next_cursor: 'c2' });
    const first = await screen.request(1, 'LE5 busy: the first live refresh');
    // One more frame while it is out, so another refresh starts the moment it lands.
    await stream.send(activityFrame(callRow('a.live2')));
    await screen.quiet(2, 'LE5 busy: waiting on the first refresh');
    const fresh = rowsOf('b', 1);
    await first.answer({ rows: fresh, next_cursor: 'c2' });
    await expect.poll(() => screen.texts(), { message: 'LE5 busy: the first refresh lands' }).toEqual(fresh.map(textOf));
    // The second refresh stays unanswered: page 2 must not wait for it.
    await screen.requestWhere((r) => r.params.cursor === 'c2', 'LE5 busy: page 2 without a second wait');
  });

  test('LE5 a refresh that shortens the list lets its trailing refresh land', async ({ page, request }, testInfo) => {
    const { screen, stream } = await screenFor(page, request, testInfo);
    await screen.open(stream);
    await (await screen.request(0, 'LE5 shorten: page 1')).answer({ rows: rowsOf('a', 1, 60), next_cursor: 'c2' });
    await stream.send(activityFrame(callRow('a.live1')));
    const first = await screen.request(1, 'LE5 shorten: the first live refresh');
    await stream.send(activityFrame(callRow('a.live2')));
    // A one-page answer: the list end comes into view by layout alone, nobody scrolls.
    await first.answer({ rows: rowsOf('b', 1), next_cursor: 'c2' });
    const second = await screen.request(2, 'LE5 shorten: the trailing refresh');
    await screen.quiet(3, 'LE5 shorten: no next page while it is out');
    expect(screen.failed.has(second.href), 'LE5 shorten: the trailing refresh is not aborted').toBe(false);
    const fresh = rowsOf('c', 1);
    await second.answer({ rows: fresh, next_cursor: 'c2' });
    await expect.poll(() => screen.texts(), { message: 'LE5 shorten: the trailing refresh lands' }).toEqual(fresh.map(textOf));
    await screen.requestWhere((r) => r.params.cursor === 'c2', 'LE5 shorten: then page 2');
  });

  // Accepted behaviour: a taller window that shows the list end reads on like a scroll does,
  // and the refresh it overtakes waits behind the control, one press away.
  test('LE5 a window made tall enough to show the end reads on and holds', async ({ page, request }, testInfo) => {
    const { screen, stream } = await screenFor(page, request, testInfo);
    await screen.open(stream);
    await (await screen.request(0, 'LE5 resize: page 1')).answer({ rows: rowsOf('a', 1, 60), next_cursor: 'c2' });
    await stream.send(activityFrame(callRow('a.live')));
    const live = await screen.request(1, 'LE5 resize: the live refresh');
    await screen.quiet(2, 'LE5 resize: premise, the end is out of view');
    const { width } = page.viewportSize();
    await page.setViewportSize({ width, height: 8000 });
    await screen.requestWhere((r) => r.params.cursor === 'c2', 'LE5 resize: page 2');
    await screen.aborted(live, 'LE5 resize: the live refresh');
    await expect(screen.control(), 'LE5 resize: its rows wait behind the control').toBeVisible();
  });

  test('LE5 the next-page retry asks again with the list end out of view', async ({ page, request }, testInfo) => {
    const { screen, stream } = await screenFor(page, request, testInfo);
    await screen.open(stream);
    await (await screen.request(0, 'LE5 retry: page 1')).answer({ rows: rowsOf('a', 1, 60), next_cursor: 'c2' });
    await screen.toEnd();
    await (await screen.requestWhere((r) => r.params.cursor === 'c2', 'LE5 retry: page 2')).fail();
    const retry = page.locator('#content').getByRole('button', { name: 'Retry', exact: true });
    await expect(retry, 'LE5 retry: premise, the retry shows').toBeVisible();
    await screen.rows().first().scrollIntoViewIfNeeded();
    // A click event, not a pointer click: a pointer click would scroll the end back into view first.
    await retry.dispatchEvent('click');
    await expect.poll(() => screen.sent.filter((r) => r.params.cursor === 'c2').length, { message: 'LE5 retry: page 2 asked again' }).toBe(2);
  });

  // A held page 2, voided three ways: its late answer must show nothing.
  for (const how of ['filter', 'control', 'leave']) {
    test(`LE5 a held next page is voided by ${how}`, async ({ page, request }, testInfo) => {
      const { screen, stream } = await screenFor(page, request, testInfo);
      await screen.open(stream);
      await (await screen.request(0, `LE5 ${how}: page 1`)).answer({ rows: rowsOf('a', 1), next_cursor: 'c2' });
      const p2 = await screen.request(1, `LE5 ${how}: page 2`);
      if (how === 'filter') await pickOutcome(page, 'failed');
      if (how === 'control') {
        await stream.send(activityFrame(callRow('a.news')));
        await expect(screen.control(), 'LE5 control: premise, the control shows').toBeVisible();
        await screen.control().click();
      }
      if (how === 'leave') await page.getByRole('link', { name: 'Tools', exact: true }).first().click();
      await screen.aborted(p2, `LE5 ${how}: page 2`);
      const fresh = rowsOf('n', 1);
      if (how !== 'leave') await (await screen.request(2, `LE5 ${how}: page 1 again`)).answer({ rows: fresh, next_cursor: null });
      await p2.answer({ rows: rowsOf('late', 2), next_cursor: null });
      await page.waitForTimeout(500);
      if (how === 'leave') expect(await page.locator('#content').innerText(), 'LE5 leave: nothing late on Tools').not.toContain('late.p2');
      else expect(await screen.texts(), `LE5 ${how}: only the new page 1`).toEqual(fresh.map(textOf));
    });
  }

  test('LE6 the control releases the hold to a new page 1', async ({ page, request }, testInfo) => {
    const { screen, stream } = await screenFor(page, request, testInfo);
    await screen.open(stream);
    const p1 = await screen.request(0, 'LE6 page 1');
    await p1.answer({ rows: rowsOf('a', 1), next_cursor: 'c2' });
    await screen.request(1, 'LE6 page 2 held');
    await stream.send(activityFrame(callRow('a.news')));
    await page.clock.runFor(60_000);
    await expect(screen.control(), 'LE6 premise, the control shows').toBeVisible();
    await screen.control().focus();
    await page.keyboard.press('Enter');
    const fresh = await screen.request(2, 'LE6 release');
    expect([fresh.params.cursor ?? null, fresh.params.to], 'LE6 page 1 on a new window').toEqual([null, utc(AT + 60_000)]);
    const newest = rowsOf('n', 1);
    await fresh.answer({ rows: newest, next_cursor: null });
    await expect.poll(() => screen.texts(), { message: 'LE6 the newest page 1' }).toEqual(newest.map(textOf));
    await expect(screen.control(), 'LE6 the control is gone').toHaveCount(0);
    await screen.quiet(3, 'LE6 settled');
    await stream.send(activityFrame(callRow('n.live')));
    await screen.request(3, 'LE6 a frame refreshes again');
    await screen.quiet(4, 'LE6 exactly one');
  });

  test('LE6 a filter change also releases the hold', async ({ page, request }, testInfo) => {
    const { screen, stream } = await screenFor(page, request, testInfo);
    await screen.open(stream);
    await (await screen.request(0, 'LE6 filter: page 1')).answer({ rows: rowsOf('a', 1), next_cursor: 'c2' });
    await screen.request(1, 'LE6 filter: page 2 held');
    await stream.send(activityFrame(callRow('a.news')));
    await expect(screen.control(), 'LE6 filter: premise, the control shows').toBeVisible();
    await pickOutcome(page, 'ok');
    const fresh = await screen.request(2, 'LE6 filter: page 1 of the filter');
    await fresh.answer({ rows: rowsOf('f', 1), next_cursor: null });
    await expect(screen.control(), 'LE6 filter: the control is gone').toHaveCount(0);
    await screen.quiet(3, 'LE6 filter: settled');
    await stream.send(activityFrame(callRow('f.live')));
    await screen.request(3, 'LE6 filter: a frame refreshes again');
    await screen.quiet(4, 'LE6 filter: exactly one');
  });

  test('LE7a a failed page 1 after a filter change shows no earlier rows', async ({ page, request }, testInfo) => {
    const { screen, stream } = await screenFor(page, request, testInfo);
    await screen.open(stream);
    await (await screen.request(0, 'LE7a page 1')).answer({ rows: rowsOf('a', 1), next_cursor: null });
    await pickOutcome(page, 'failed');
    await (await screen.request(1, 'LE7a filtered page 1')).fail();
    await expect(page.getByText(UNAVAILABLE), 'LE7a the unavailable state').toBeVisible();
    expect(await screen.rows().count(), 'LE7a no rows').toBe(0);
  });

  test('LE7b a failed live refresh keeps the rows and says the news is stale', async ({ page, request }, testInfo) => {
    const { screen, stream } = await screenFor(page, request, testInfo);
    const one = rowsOf('a', 1);
    await screen.open(stream);
    await (await screen.request(0, 'LE7b page 1')).answer({ rows: one, next_cursor: null });
    await stream.send(activityFrame(callRow('a.live')));
    await (await screen.request(1, 'LE7b live refresh')).fail();
    await expect(page.getByText(STALE_TEXT, { exact: true }), 'LE7b the stale notice').toBeVisible();
    expect(await screen.texts(), 'LE7b rows kept').toEqual(one.map(textOf));
  });

  test('LE7c a failed next page offers a retry that appends', async ({ page, request }, testInfo) => {
    const { screen, stream } = await screenFor(page, request, testInfo);
    const [one, two] = [rowsOf('a', 1), rowsOf('a', 2)];
    await screen.open(stream);
    await (await screen.request(0, 'LE7c page 1')).answer({ rows: one, next_cursor: 'c2' });
    await (await screen.request(1, 'LE7c page 2')).fail();
    await expect(page.getByText(MORE_FAILED), 'LE7c the next-page notice').toBeVisible();
    await page.locator('#content').getByRole('button', { name: 'Retry', exact: true }).click();
    const again = await screen.request(2, 'LE7c retry');
    expect(again.params.cursor, 'LE7c the same cursor').toBe('c2');
    await again.answer({ rows: two, next_cursor: null });
    await expect.poll(() => screen.texts(), { message: 'LE7c appended' }).toEqual([...one, ...two].map(textOf));
  });

  test('LE7d a filter change voids a failed next page and its retry', async ({ page, request }, testInfo) => {
    const { screen, stream } = await screenFor(page, request, testInfo);
    await screen.open(stream);
    await (await screen.request(0, 'LE7d page 1')).answer({ rows: rowsOf('a', 1), next_cursor: 'c2' });
    await (await screen.request(1, 'LE7d page 2')).fail();
    await expect(page.getByText(MORE_FAILED), 'LE7d premise, the retry shows').toBeVisible();
    await pickOutcome(page, 'failed');
    const textB = rowsOf('b', 1);
    await (await screen.request(2, 'LE7d filtered page 1')).answer({ rows: textB, next_cursor: null });
    await screen.quiet(3, 'LE7d settled');
    expect(await screen.texts(), 'LE7d exactly the filter\'s rows').toEqual(textB.map(textOf));
    await expect(page.getByText(MORE_FAILED), 'LE7d no next-page notice').toHaveCount(0);
    await expect(page.locator('#content').getByRole('button', { name: 'Retry', exact: true }), 'LE7d no retry').toHaveCount(0);
    expect(screen.sent.filter((r) => r.params.cursor === 'c2').length, 'LE7d page 2 asked once in the run').toBe(1);
  });

  test('LE7e a failed page 1 then a failed refresh shows both notices', async ({ page, request }, testInfo) => {
    const { screen, stream } = await screenFor(page, request, testInfo);
    await screen.open(stream);
    await (await screen.request(0, 'LE7e page 1')).fail();
    await expect(page.getByText(UNAVAILABLE), 'LE7e premise, the unavailable state').toBeVisible();
    await stream.send(activityFrame(callRow('a.live')));
    await (await screen.request(1, 'LE7e live refresh')).fail();
    await expect(page.getByText(UNAVAILABLE), 'LE7e still the page-1 state').toBeVisible();
    await expect(page.getByText(STALE_TEXT, { exact: true }), 'LE7e and the stale notice').toBeVisible();
  });

  for (const held of ['live', 'append']) {
    for (const late of ['answer', 'failure']) {
      test(`LE8 leaving with a ${held} request out aborts it; its late ${late} shows nothing`, async ({ page, request }, testInfo) => {
        const label = `LE8 ${held} ${late}`;
        const { screen, stream } = await screenFor(page, request, testInfo);
        await screen.open(stream);
        await (await screen.request(0, `${label}: page 1`)).answer({ rows: rowsOf('a', 1), next_cursor: held === 'append' ? 'c2' : null });
        if (held === 'live') await stream.send(activityFrame(callRow('a.live')));
        const out = await screen.request(1, `${label}: the held request`);
        await page.getByRole('link', { name: 'Tools', exact: true }).first().click();
        await expect(page, `${label}: on Tools`).toHaveURL(/\/ui\/tools\/status$/);
        await screen.aborted(out, label);
        if (late === 'answer') await out.answer({ rows: rowsOf('late', 1), next_cursor: 'c9' });
        else await out.fail();
        await screen.quiet(2, `${label}: after the late ${late}`);
        expect(await page.locator('#content').innerText(), `${label}: nothing of it on Tools`).not.toContain('late.p1');
      });
    }
  }

  for (const newer of [true, false]) {
    test(`LE8b a cursor reset shows page 1 again${newer ? ' and refreshes for the news held' : ''}`, async ({ page, request }, testInfo) => {
      const label = `LE8b ${newer ? 'newer' : 'quiet'}`;
      const { screen, stream } = await screenFor(page, request, testInfo);
      await screen.open(stream);
      await (await screen.request(0, `${label}: page 1`)).answer({ rows: rowsOf('a', 1), next_cursor: 'c2' });
      const p2 = await screen.request(1, `${label}: page 2`);
      if (newer) {
        await stream.send(activityFrame(callRow('a.news')));
        await expect(screen.control(), `${label}: premise, the control shows`).toBeVisible();
      }
      await p2.answer({ rows: rowsOf('a', 2), next_cursor: 'c3' });
      const p3 = await screen.request(2, `${label}: page 3`);
      await page.clock.runFor(60_000);
      const reset = rowsOf('reset', 1);
      await p3.answer({ rows: reset, next_cursor: null, cursor_reset: true });
      await expect.poll(() => screen.texts(), { message: `${label}: exactly the reset rows` }).toEqual(reset.map(textOf));
      await expect(screen.control(), `${label}: no control`).toHaveCount(0);
      if (newer) {
        const live = await screen.request(3, `${label}: a refresh with no further frame`);
        expect([live.params.cursor ?? null, live.params.to], `${label}: page 1 up to now`).toEqual([null, utc(AT + 60_000)]);
        await screen.quiet(4, `${label}: one refresh`);
      } else {
        await screen.quiet(3, `${label}: nothing asked after the reset`);
        await stream.send(activityFrame(callRow('reset.live')));
        await screen.request(3, `${label}: a frame refreshes`);
        await screen.quiet(4, `${label}: one refresh`);
      }
    });
  }

  /** [start, end) of `function name(...) { ... }` in `text`, or null. */
  function functionSpan(text, name) {
    const start = text.indexOf(`function ${name}(`);
    if (start < 0) return null;
    let depth = 0;
    for (let i = text.indexOf('{', start); i < text.length; i += 1) {
      if (text[i] === '{') depth += 1;
      if (text[i] === '}' && (depth -= 1) === 0) return [start, i + 1];
    }
    return null;
  }

  test('LE9 the list request is written once, inside the one issuer', () => {
    const LITERAL = '/ui/api/activity?';
    const files = [served(/^activity\.[0-9a-f]{12}\.js$/), served(/^activity-list\.[0-9a-f]{12}\.js$/)];
    const hits = files.flatMap((f) => [...f.text.matchAll(/\/ui\/api\/activity\?/g)].map((m) => ({ file: f, at: m.index })));
    expect(hits.length, `LE9 ${LITERAL} occurs once across the screen and the core`).toBe(1);
    const where = functionSpan(hits[0].file.text, 'startRequest');
    expect(where, `LE9 ${hits[0].file.name} has a function startRequest`).not.toBeNull();
    expect(hits[0].at >= where[0] && hits[0].at < where[1], 'LE9 the literal sits inside startRequest').toBe(true);
  });

  test('LE9b the core touches no page, network, timer or clock', () => {
    const TOKENS = ['document', 'window.', 'fetch', 'ctx.', 'setTimeout', 'setInterval', 'AbortController', 'Date.now', 'new Date', '/ui/api/'];
    const { text } = served(/^activity-list\.[0-9a-f]{12}\.js$/);
    expect(TOKENS.filter((t) => text.includes(t)), 'LE9b tokens found in the core').toEqual([]);
  });

  test('V5 the list cell and the receipt heading both word an admin row through one changeText', () => {
    // Comments go first: a doc comment that quotes a sentence must not fail correct code.
    const text = served(/^activity\.[0-9a-f]{12}\.js$/).text.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, '');
    expect(text.split('function changeText(').length - 1, 'V5 changeText is written once').toBe(1);
    const body = (name) => {
      const span = functionSpan(text, name);
      expect(span, `V5 the screen has a function ${name}`).not.toBeNull();
      return text.slice(...span);
    };
    expect(body('rowLink'), 'V5 the list cell asks changeText').toContain('changeText(');
    expect(body('receiptTab'), 'V5 the receipt heading asks changeText').toContain('changeText(');
    // The sentences the behavioural rows pin; none may be written out anywhere else.
    const [start, end] = functionSpan(text, 'changeText');
    const elsewhere = text.slice(0, start) + text.slice(end);
    const PINNED = [
      'Capability file changed',
      'Saved capability billing · re-pinned', 'Created capability billing · pinned', 'Deleted capability billing',
      'Saved capability billing', 'Saved capability billing · pinned',
    ];
    expect(PINNED.filter((s) => elsewhere.includes(s)), 'V5 pinned sentences outside changeText').toEqual([]);
  });

  test('LE10 a frame draws nothing of its own; rows come from the list answer', async ({ page, request }, testInfo) => {
    const { screen, stream } = await screenFor(page, request, testInfo);
    const SECRETS = ['SECRET-TOP-7f3', 'SECRET-WHO-7f3'];
    await screen.open(stream);
    await (await screen.request(0, 'LE10 page 1')).answer({ rows: rowsOf('a', 1), next_cursor: null });
    const base = callRow('a.live');
    await stream.send(activityFrame({ ...base, request_body: SECRETS[0], who: { ...base.who, request_body: SECRETS[1] } }));
    const shownNow = async () => page.locator('body').innerText();
    for (const s of SECRETS) expect(await shownNow(), `LE10 before the refresh: no ${s}`).not.toContain(s);
    const live = await screen.request(1, 'LE10 the frame asks for a refresh');
    const fromList = [callRow('a.listed'), ...rowsOf('a', 1)];
    await live.answer({ rows: fromList, next_cursor: null });
    await expect.poll(() => screen.texts(), { message: 'LE10 the list answer\'s rows' }).toEqual(fromList.map(textOf));
    for (const s of SECRETS) expect(await shownNow(), `LE10 after the refresh: no ${s}`).not.toContain(s);
  });

  test('LE11 a not-recorded row never reads final, and its refresh shows the record', async ({ page, request }, testInfo) => {
    const { screen, stream } = await screenFor(page, request, testInfo);
    const FINAL = /\b(delivered|annotated|rewritten|refused)\b/i;
    await screen.open(stream);
    await (await screen.request(0, 'LE11 page 1')).answer({ rows: [callRow('a.x', { effect: 'no_record' })], next_cursor: null });
    const row = screen.rows().first();
    await expect(row, 'LE11 the not-final words').toContainText(NOT_FINAL);
    expect(await row.innerText(), 'LE11 no final word').not.toMatch(FINAL);
    await stream.send(activityFrame(callRow('a.x', { effect: 'no_record' })));
    await (await screen.request(1, 'LE11 refresh')).answer({ rows: [callRow('a.x', { effect: 'delivered' })], next_cursor: null });
    await expect(row, 'LE11 the recorded word').toContainText(/delivered/i);
    expect(await row.innerText(), 'LE11 the not-final words are gone').not.toContain(NOT_FINAL);
  });

  for (const width of WIDTHS) {
    test(`LE12 the control passes axe at ${width} and its news is said politely`, async ({ page, request }, testInfo) => {
      await page.setViewportSize({ width, height: 900 });
      const { screen, stream } = await screenFor(page, request, testInfo);
      await screen.open(stream);
      await (await screen.request(0, `LE12 ${width}: page 1`)).answer({ rows: rowsOf('a', 1), next_cursor: 'c2' });
      await screen.request(1, `LE12 ${width}: page 2 held`);
      await stream.send(activityFrame(callRow('a.news')));
      await expect(screen.control(), `LE12 ${width}: the control shows`).toBeVisible();
      // axe waits on timers of its own; under the paused clock they never fire.
      await page.clock.resume();
      expect(await blockingViolations(page), `LE12 ${width}: axe`).toEqual([]);
      // role=status is polite by definition; the shell's one live region carries no aria-live of its own.
      expect(await page.locator('#announcer').getAttribute('role'), `LE12 ${width}: polite`).toBe('status');
    });
  }

  // ---- The slot after the rows: Load more, Keep looking, Reading more…

  /** Focus an element without scrolling, so the list end stays where it was. */
  const focusInPlace = (locator) => locator.evaluate((el) => el.focus({ preventScroll: true }));
  /** Let the announcer's dwell pass: the clock is paused. */
  const letSay = (page) => page.clock.runFor(2000);
  const searchField = (page) => page.locator('#content .activity-search');
  const asked = (screen, cursor) => screen.sent.filter((r) => r.params.cursor === cursor).length;

  test('LE5 Load more asks one next page while the end is hidden', async ({ page, request }, testInfo) => {
    const { screen, stream } = await screenFor(page, request, testInfo);
    const one = rowsOf('a', 1, 60);
    const two = rowsOf('a', 2);
    await screen.open(stream);
    await (await screen.request(0, 'LE5 load more: page 1')).answer({ rows: one, next_cursor: 'c2' });
    await expect(screen.button(LOAD_MORE), 'LE5 load more: the button shows').toBeVisible();
    expect(await screen.endInView(), 'LE5 load more: premise, the end is out of view').toBe(false);
    await screen.quiet(1, 'LE5 load more: premise, nothing asked yet');
    // A click event: a pointer click would first scroll the end into view.
    await screen.button(LOAD_MORE).dispatchEvent('click');
    const p2 = await screen.requestWhere((r) => r.params.cursor === 'c2', 'LE5 load more: the press asks page 2');
    expect(await screen.endInView(), 'LE5 load more: the end is still out of view').toBe(false);
    await screen.quiet(2, 'LE5 load more: one press, one request');
    await expect.poll(() => screen.focusedText(), { message: 'LE5 load more: focus on page 1\'s last row' }).toBe(textOf(one.at(-1)));
    await p2.answer({ rows: two, next_cursor: null });
    await expect.poll(() => screen.texts(), { message: 'LE5 load more: page 2 follows page 1' }).toEqual([...one, ...two].map(textOf));
    await letSay(page);
    expect(await screen.heard('2 more calls.'), 'LE5 load more: the new rows are said').toBe(1);
  });

  test('LE13 Tab reaches Load more; it reads, then goes at the end', async ({ page, request }, testInfo) => {
    const { screen, stream } = await screenFor(page, request, testInfo);
    await screen.open(stream);
    await (await screen.request(0, 'LE13 page 1')).answer({ rows: rowsOf('a', 1, 60), next_cursor: 'c2' });
    const more = screen.button(LOAD_MORE);
    await expect(more, 'LE13 Load more shows after the rows').toBeVisible();
    // Chromium centres a focused element that is out of view. With the slot's bottom on the
    // window's, the button is in view and the end below it is not, so focus scrolls nothing.
    await screen.slot().evaluate((el) => el.scrollIntoView({ block: 'end' }));
    expect(await screen.endInView(), 'LE13 premise: the end is out of view').toBe(false);
    await focusInPlace(screen.rows().last());
    await page.keyboard.press('Tab');
    await expect(more, 'LE13 Tab from the last row reaches Load more').toBeFocused();
    await screen.quiet(1, 'LE13 premise: reaching it asked nothing');
    await page.keyboard.press('Enter');
    const p2 = await screen.requestWhere((r) => r.params.cursor === 'c2', 'LE13 Enter asks page 2');
    await expect(screen.slot(), 'LE13 the slot says it is reading').toHaveText(READING);
    await expect(more, 'LE13 no Load more while a page is out').toHaveCount(0);
    await p2.answer({ rows: rowsOf('a', 2), next_cursor: null });
    await expect.poll(() => screen.rows().count(), { message: 'LE13 page 2 lands' }).toBe(62);
    await expect(screen.slot(), 'LE13 the slot hides at the list end').toBeHidden();
    await expect(more, 'LE13 no Load more at the end').toHaveCount(0);
  });

  for (const end of ['rows', 'stopped', 'end', 'moved']) {
    test(`LE14 an empty stopped scan offers Keep looking; ending: ${end}`, async ({ page, request }, testInfo) => {
      const label = `LE14 ${end}`;
      const { screen, stream } = await screenFor(page, request, testInfo);
      await screen.open(stream);
      await (await screen.request(0, `${label}: page 1`)).answer(stopped([]));
      const look = screen.button(KEEP_LOOKING);
      await expect(look, `${label}: Keep looking shows`).toBeVisible();
      await expect(screen.slot(), `${label}: the no-match sentence`).toContainText(NONE_YET);
      await expect(screen.emptyState(), `${label}: no empty state`).toHaveCount(0);
      await screen.quiet(1, `${label}: nothing asked by itself`);
      await look.click();
      const p2 = await screen.requestWhere((r) => r.params.cursor === 'c2', `${label}: the press asks c2`);
      await expect(screen.slot(), `${label}: the slot says it is reading`).toHaveText(READING);
      await expect.poll(() => screen.focusOnSlot(), { message: `${label}: focus waits on the slot` }).toBe(true);
      if (end === 'rows') {
        const found = rowsOf('b', 2);
        await p2.answer({ rows: found, next_cursor: null });
        await expect.poll(() => screen.texts(), { message: `${label}: the found rows show` }).toEqual(found.map(textOf));
        await expect.poll(() => screen.focusedText(), { message: `${label}: focus on the first new row` }).toBe(textOf(found[0]));
        await letSay(page);
        expect(await screen.heard('2 more calls.'), `${label}: the rows are said`).toBe(1);
        return;
      }
      if (end === 'end') {
        await p2.answer({ rows: [], next_cursor: null });
        await expect(screen.emptyState(), `${label}: the empty state shows`).toBeVisible();
        await expect(screen.emptyState().locator('h2'), `${label}: its heading has focus`).toBeFocused();
        await letSay(page);
        expect(await screen.heard(SAY_NONE), `${label}: said once`).toBe(1);
        return;
      }
      if (end === 'moved') await searchField(page).focus();
      await p2.answer(stopped([], 'c3'));
      await expect(look, `${label}: Keep looking is back`).toBeVisible();
      await expect(screen.emptyState(), `${label}: still no empty state`).toHaveCount(0);
      if (end === 'moved') {
        await expect(searchField(page), `${label}: focus stays on the search`).toBeFocused();
      } else {
        await expect(look, `${label}: focus back on the button`).toBeFocused();
        await letSay(page);
        expect(await screen.heard(SAY_NONE_YET), `${label}: said once`).toBe(1);
      }
      await screen.quiet(2, `${label}: c3 waits for a press`);
    });
  }

  test('LE15 a stopped scan with rows offers Keep looking, not Load more', async ({ page, request }, testInfo) => {
    const { screen, stream } = await screenFor(page, request, testInfo);
    const one = rowsOf('a', 1, 3);
    await screen.open(stream);
    await (await screen.request(0, 'LE15 page 1')).answer(stopped(one));
    await expect(screen.button(KEEP_LOOKING), 'LE15 Keep looking shows').toBeVisible();
    await expect(screen.slot(), 'LE15 the stopped sentence').toContainText(STOPPED);
    await expect(screen.slot(), 'LE15 not the no-match one').not.toContainText(NONE_YET);
    await expect(screen.button(LOAD_MORE), 'LE15 no Load more').toHaveCount(0);
    await screen.quiet(1, 'LE15 nothing asked by itself');
    expect(await screen.texts(), 'LE15 the rows stay').toEqual(one.map(textOf));
  });

  for (const face of [LOAD_MORE, KEEP_LOOKING]) {
    test(`LE16 one ${face} press sends one request, even scrolled to the end`, async ({ page, request }, testInfo) => {
      const label = `LE16 ${face}`;
      const { screen, stream } = await screenFor(page, request, testInfo);
      const one = rowsOf('a', 1, 60);
      await screen.open(stream);
      await (await screen.request(0, `${label}: page 1`)).answer(face === LOAD_MORE ? { rows: one, next_cursor: 'c2' } : stopped(one));
      await expect(screen.button(face), `${label}: the button shows`).toBeVisible();
      await screen.button(face).dispatchEvent('click');
      await screen.requestWhere((r) => r.params.cursor === 'c2', `${label}: the press asks c2`);
      await screen.toEnd();
      await screen.quiet(2, `${label}: still one next page`);
    });
  }

  test('LE17 a failed page after Load more shows Retry in its place', async ({ page, request }, testInfo) => {
    const { screen, stream } = await screenFor(page, request, testInfo);
    await screen.open(stream);
    await (await screen.request(0, 'LE17 page 1')).answer({ rows: rowsOf('a', 1, 60), next_cursor: 'c2' });
    await expect(screen.button(LOAD_MORE), 'LE17 Load more shows').toBeVisible();
    await screen.button(LOAD_MORE).dispatchEvent('click');
    await (await screen.requestWhere((r) => r.params.cursor === 'c2', 'LE17 the press asks c2')).fail();
    await expect(screen.slot(), 'LE17 the slot says the page failed').toContainText(MORE_FAILED);
    const retry = screen.button('Retry');
    await expect(retry, 'LE17 Retry shows').toBeVisible();
    await expect(screen.button(LOAD_MORE), 'LE17 no Load more beside it').toHaveCount(0);
    await retry.dispatchEvent('click');
    await expect.poll(() => asked(screen, 'c2'), { message: 'LE17 Retry asks c2 again' }).toBe(2);
  });

  test('LE18 Keep looking with rows never shows the empty state', async ({ page, request }, testInfo) => {
    const { screen, stream } = await screenFor(page, request, testInfo);
    const one = rowsOf('a', 1, 3);
    const lastRow = textOf(one.at(-1));
    await screen.open(stream);
    await (await screen.request(0, 'LE18 page 1')).answer(stopped(one));
    const look = screen.button(KEEP_LOOKING);
    await expect(look, 'LE18 Keep looking shows').toBeVisible();
    await look.click();
    const p2 = await screen.requestWhere((r) => r.params.cursor === 'c2', 'LE18 the first press asks c2');
    await expect.poll(() => screen.focusedText(), { message: 'LE18 the press puts focus on the last row' }).toBe(lastRow);
    await p2.answer(stopped([], 'c3'));
    await expect(look, 'LE18 still stopped: Keep looking is back').toBeVisible();
    await expect(look, 'LE18 still stopped: and has focus').toBeFocused();
    expect(await screen.texts(), 'LE18 still stopped: the rows stay').toEqual(one.map(textOf));
    await letSay(page);
    expect(await screen.heard(SAY_NO_MORE_YET), 'LE18 still stopped: said once').toBe(1);
    expect(await screen.heard(SAY_NONE_YET), 'LE18 still stopped: not the no-rows words').toBe(0);
    await look.click();
    const p3 = await screen.requestWhere((r) => r.params.cursor === 'c3', 'LE18 the second press asks c3');
    await p3.answer({ rows: [], next_cursor: null });
    await expect(screen.slot(), 'LE18 at the end the slot hides').toBeHidden();
    await expect(screen.emptyState(), 'LE18 at the end no empty state').toHaveCount(0);
    expect(await screen.texts(), 'LE18 at the end the rows stay').toEqual(one.map(textOf));
    await expect.poll(() => screen.focusedText(), { message: 'LE18 at the end focus stays on the last row' }).toBe(lastRow);
    await letSay(page);
    expect(await screen.heard(SAY_NO_MORE), 'LE18 at the end said once').toBe(1);
    expect(await screen.heard(SAY_NONE), 'LE18 at the end not the no-rows words').toBe(0);
  });

  test('LE19 live rows on an empty stopped list keep the focused button', async ({ page, request }, testInfo) => {
    const { screen, stream } = await screenFor(page, request, testInfo);
    await screen.open(stream);
    await (await screen.request(0, 'LE19 page 1')).answer(stopped([]));
    const look = screen.button(KEEP_LOOKING);
    await expect(look, 'LE19 Keep looking shows').toBeVisible();
    await look.focus();
    // The node itself: a locator finds a rebuilt button too.
    const before = await look.elementHandle();
    await stream.send(activityFrame(callRow('a.live')));
    const live = await screen.request(1, 'LE19 the frame asks a refresh');
    expect(live.params.cursor ?? null, 'LE19 premise: a page 1 refresh').toBeNull();
    const fresh = rowsOf('b', 1);
    await live.answer(stopped(fresh));
    await expect.poll(() => screen.texts(), { message: 'LE19 the live rows show' }).toEqual(fresh.map(textOf));
    await expect(screen.slot(), 'LE19 the stopped sentence').toContainText(STOPPED);
    await expect(screen.slot(), 'LE19 the no-match sentence is gone').not.toContainText(NONE_YET);
    await expect(look, 'LE19 one Keep looking').toHaveCount(1);
    expect(await before.evaluate((el) => el.isConnected && el === document.activeElement), 'LE19 the same button, still focused').toBe(true);
  });

  for (const to of [LOAD_MORE, 'the end']) {
    test(`LE20 a live refresh turning Keep looking into ${to} keeps focus`, async ({ page, request }, testInfo) => {
      const label = `LE20 ${to}`;
      const { screen, stream } = await screenFor(page, request, testInfo);
      await screen.open(stream);
      await (await screen.request(0, `${label}: page 1`)).answer(stopped(rowsOf('a', 1, 60)));
      const look = screen.button(KEEP_LOOKING);
      await expect(look, `${label}: Keep looking shows`).toBeVisible();
      expect(await screen.endInView(), `${label}: premise, the end is out of view`).toBe(false);
      await focusInPlace(look);
      await expect(look, `${label}: premise, Keep looking has focus`).toBeFocused();
      await stream.send(activityFrame(callRow('a.live')));
      const live = await screen.request(1, `${label}: the frame asks a refresh`);
      const fresh = rowsOf('b', 1, 60);
      if (to === LOAD_MORE) {
        await live.answer({ rows: fresh, next_cursor: 'c2' });
        await expect(screen.button(LOAD_MORE), `${label}: focus moves to Load more`).toBeFocused();
        await screen.quiet(2, `${label}: nothing asked`);
      } else {
        await live.answer({ rows: fresh, next_cursor: null });
        await expect(screen.slot(), `${label}: the slot hides`).toBeHidden();
        await expect.poll(() => screen.focusedText(), { message: `${label}: focus moves to the last row` }).toBe(textOf(fresh.at(-1)));
      }
    });
  }

  // How each face is reached for the axe rows.
  const FACES = {
    [LOAD_MORE]: async (screen, label) => {
      await (await screen.request(0, `${label}: page 1`)).answer({ rows: rowsOf('a', 1, 60), next_cursor: 'c2' });
      await expect(screen.button(LOAD_MORE), `${label}: Load more shows`).toBeVisible();
    },
    [KEEP_LOOKING]: async (screen, label) => {
      await (await screen.request(0, `${label}: page 1`)).answer(stopped([]));
      await expect(screen.button(KEEP_LOOKING), `${label}: Keep looking shows`).toBeVisible();
    },
    [READING]: async (screen, label) => {
      await FACES[LOAD_MORE](screen, label);
      await screen.button(LOAD_MORE).dispatchEvent('click');
      await screen.requestWhere((r) => r.params.cursor === 'c2', `${label}: page 2 is out`);
      await expect(screen.slot(), `${label}: the slot says it is reading`).toHaveText(READING);
    },
  };
  for (const [face, reach] of Object.entries(FACES)) {
    for (const width of WIDTHS) {
      for (const scheme of ['light', 'dark']) {
        test(`LE21 the ${face} face passes axe at ${width} in ${scheme}`, async ({ page, request }, testInfo) => {
          const label = `LE21 ${face} ${width} ${scheme}`;
          await page.setViewportSize({ width, height: 900 });
          await page.emulateMedia({ colorScheme: scheme });
          const { screen, stream } = await screenFor(page, request, testInfo);
          await screen.open(stream);
          await reach(screen, label);
          // axe waits on timers of its own; under the paused clock they never fire.
          await page.clock.resume();
          expect(await blockingViolations(page), `${label}: axe`).toEqual([]);
        });
      }
    }
  }

  test('LE22 Tab from the search walks the rows to Keep looking', async ({ page, request }, testInfo) => {
    const { screen, stream } = await screenFor(page, request, testInfo);
    const one = rowsOf('a', 1, 3);
    await screen.open(stream);
    await (await screen.request(0, 'LE22 page 1')).answer(stopped(one));
    await expect(screen.button(KEEP_LOOKING), 'LE22 Keep looking shows').toBeVisible();
    await searchField(page).focus();
    const walked = [];
    for (let i = 0; i < one.length; i += 1) {
      await page.keyboard.press('Tab');
      walked.push(await screen.focusedText());
    }
    expect(walked, 'LE22 Tab walks the rows in order, nothing between').toEqual(one.map(textOf));
    await page.keyboard.press('Tab');
    await expect(screen.button(KEEP_LOOKING), 'LE22 the next Tab reaches Keep looking').toBeFocused();
  });

  test('LE23 Retry on an empty stopped list keeps focus on the slot', async ({ page, request }, testInfo) => {
    const { screen, stream } = await screenFor(page, request, testInfo);
    await screen.open(stream);
    await (await screen.request(0, 'LE23 page 1')).answer(stopped([]));
    await screen.button(KEEP_LOOKING).click();
    await (await screen.requestWhere((r) => r.params.cursor === 'c2', 'LE23 the press asks c2')).fail();
    const retry = screen.button('Retry');
    await expect(retry, 'LE23 Retry replaces Keep looking').toBeVisible();
    await focusInPlace(retry);
    await page.keyboard.press('Enter');
    await expect.poll(() => asked(screen, 'c2'), { message: 'LE23 Retry asks c2 again' }).toBe(2);
    await expect(screen.slot(), 'LE23 the slot says it is reading').toHaveText(READING);
    // No button, no row and no empty state remain, so the slot itself holds focus.
    await expect.poll(() => screen.focusOnSlot(), { message: 'LE23 focus waits on the slot' }).toBe(true);
  });

  /** Whether focus sits on the rows container itself. */
  const focusOnRows = (page) => page.evaluate(() => document.activeElement?.classList.contains('activity-rows') ?? false);

  for (const drive of ['redraw', 'refresh', 'reset']) {
    test(`LE24 an empty list end keeps focus in the list through a ${drive}`, async ({ page, request }, testInfo) => {
      const label = `LE24 ${drive}`;
      const { screen, stream } = await screenFor(page, request, testInfo);
      await screen.open(stream);
      const heading = screen.emptyState().locator('h2');
      if (drive === 'refresh') {
        // Nothing held on a plain empty list: a frame asks a refresh, which hides the empty state.
        await (await screen.request(0, `${label}: page 1`)).answer({ rows: [], next_cursor: null });
        await focusInPlace(heading);
        await expect(heading, `${label}: premise, the heading has focus`).toBeFocused();
        await stream.send(activityFrame(callRow('a.live')));
      } else {
        await (await screen.request(0, `${label}: page 1`)).answer(stopped([]));
        await screen.button(KEEP_LOOKING).click();
        const p2 = await screen.requestWhere((r) => r.params.cursor === 'c2', `${label}: the press asks c2`);
        if (drive === 'redraw') {
          await p2.answer({ rows: [], next_cursor: null });
          await expect(heading, `${label}: premise, the heading has focus`).toBeFocused();
          // Still held from paging: the frame only marks news, and that draw rebuilds the empty state.
          await stream.send(activityFrame(callRow('a.live')));
          await expect(page.locator('#content').getByRole('button', { name: CONTROL }), `${label}: the news is marked`).toBeVisible();
          await expect(heading, `${label}: focus moves to the rebuilt heading`).toBeFocused();
          return;
        }
        // News held while the press reads; the reset turns it into one refresh.
        await stream.send(activityFrame(callRow('a.live')));
        await p2.answer({ rows: [], next_cursor: null, cursor_reset: true });
      }
      const live = await screen.request(drive === 'refresh' ? 1 : 2, `${label}: a refresh is out`);
      await expect(screen.emptyState(), `${label}: no empty state while it reads`).toHaveCount(0);
      await expect.poll(() => focusOnRows(page), { message: `${label}: the list holds focus` }).toBe(true);
      await live.answer({ rows: [], next_cursor: null });
      await expect(heading, `${label}: the heading has focus again`).toBeFocused();
    });
  }

  // A reset frame for the activity log asks the list again, the way an activity frame does.

  test('LE-R1 an activity reset refreshes page 1', async ({ page, request }, testInfo) => {
    const { screen, stream } = await screenFor(page, request, testInfo);
    await screen.open(stream, filteredPath(FILTERS));
    await (await screen.request(0, 'LE-R1 page 1')).answer({ rows: rowsOf('a', 1), next_cursor: null });
    await screen.quiet(1, 'LE-R1 before the reset');
    await page.clock.runFor(60_000);
    const now = AT + 60_000;
    await stream.send(resetFrame('activity'));
    const live = await screen.request(1, 'LE-R1 the reset');
    expect(live.params, 'LE-R1 page 1 again: same filters, window up to now, no cursor')
      .toEqual({ ...FILTERS, from: utc(now - DAY), to: utc(now) });
    const fresh = rowsOf('r', 1);
    await live.answer({ rows: fresh, next_cursor: null });
    await expect.poll(() => screen.texts(), { message: 'LE-R1 the rows are the answer\'s' }).toEqual(fresh.map(textOf));
    await screen.quiet(2, 'LE-R1 one request, not two');
  });

  test('LE-R2 paged down, an activity reset shows the control and keeps the rows', async ({ page, request }, testInfo) => {
    const { screen, stream } = await screenFor(page, request, testInfo);
    const [one, two] = [rowsOf('a', 1), rowsOf('a', 2)];
    await screen.open(stream);
    await (await screen.request(0, 'LE-R2 page 1')).answer({ rows: one, next_cursor: 'c2' });
    const p2 = await screen.request(1, 'LE-R2 page 2');
    expect(p2.params.cursor, 'LE-R2 page 2 reads on from page 1').toBe('c2');
    await p2.answer({ rows: two, next_cursor: null });
    const both = [...one, ...two].map(textOf);
    await expect.poll(() => screen.texts(), { message: 'LE-R2 both pages' }).toEqual(both);
    // Page 2's answer is announced after the dwell; let it pass before counting.
    await page.clock.runFor(2000);
    const before = await screen.said();
    await stream.send(resetFrame('activity'));
    await screen.quiet(2, 'LE-R2 a held list asks nothing');
    expect(await screen.texts(), 'LE-R2 the rows are unchanged').toEqual(both);
    await expect(screen.control(), 'LE-R2 the control shows').toBeVisible();
    await page.clock.runFor(2000);
    expect(await screen.said() - before, 'LE-R2 announced once').toBe(1);
    expect(await screen.heard(NEWER_SAID), 'LE-R2 the news is said once').toBe(1);
    await screen.control().click();
    const p1 = await screen.request(2, 'LE-R2 the control asks page 1');
    expect(p1.params.cursor ?? null, 'LE-R2 page 1 has no cursor').toBeNull();
    const fresh = rowsOf('n', 1);
    await p1.answer({ rows: fresh, next_cursor: null });
    await expect.poll(() => screen.texts(), { message: 'LE-R2 the new page 1' }).toEqual(fresh.map(textOf));
    await expect(screen.control(), 'LE-R2 the control is gone').toHaveCount(0);
  });

  test('LE-R3 config, unknown and kindless resets are ignored', async ({ page, request }, testInfo) => {
    const { screen, stream } = await screenFor(page, request, testInfo);
    await countDelivered(page);
    await screen.open(stream);
    await (await screen.request(0, 'LE-R3 page 1')).answer({ rows: rowsOf('a', 1), next_cursor: null });
    await screen.quiet(1, 'LE-R3 settled');
    for (const kind of ['config', 'audit', undefined]) {
      await stream.send(resetFrame(kind));
      await screen.quiet(1, `LE-R3 a ${kind ?? 'kindless'} reset asks nothing`);
    }
    // The stream still delivers: an activity reset on the same screen asks.
    await stream.send(resetFrame('activity'));
    const live = await screen.request(1, 'LE-R3 an activity reset asks');
    await screen.quiet(2, 'LE-R3 once');
    await live.answer({ rows: rowsOf('b', 1), next_cursor: 'c2' });
    // The next page holds the list in the step that sends it.
    const p2 = await screen.request(2, 'LE-R3 the next page, which holds the list');
    expect(p2.params.cursor, 'LE-R3 the next page reads on').toBe('c2');
    const delivered = await page.evaluate(() => window.__seen.reset);
    await stream.send(resetFrame('config'));
    await seen(page, 'reset', delivered + 1, 'LE-R3 the held config reset arrived');
    await page.clock.runFor(2000);
    await expect(screen.control(), 'LE-R3 no control for a config reset').toHaveCount(0);
    expect(await screen.heard(NEWER_SAID), 'LE-R3 no news said for a config reset').toBe(0);
    await screen.quiet(3, 'LE-R3 a held list asks nothing for config');
    await stream.send(resetFrame('activity'));
    await expect(screen.control(), 'LE-R3 an activity reset on a held list shows the control').toBeVisible();
    await screen.quiet(3, 'LE-R3 and asks nothing');
  });

  test('LE-R4 leaving drops the reset listener', async ({ page, request }, testInfo) => {
    await countListeners(page, ['gateway-reset', 'gateway-activity']);
    const { screen, stream } = await screenFor(page, request, testInfo);
    const listeners = () => page.evaluate(() => ({
      reset: window.__listeners('gateway-reset'),
      activity: window.__listeners('gateway-activity'),
    }));
    const nav = (name) => page.getByRole('navigation').getByRole('link', { name, exact: true }).first();
    await screen.open(stream);
    await (await screen.request(0, 'LE-R4 page 1')).answer({ rows: rowsOf('a', 1), next_cursor: null });
    expect(await listeners(), 'LE-R4 on the screen: one listener of each').toEqual({ reset: 1, activity: 1 });
    await nav('Tools').click();
    await expect(page).toHaveURL(/\/ui\/tools\//);
    await stream.send(resetFrame('activity'));
    await screen.quiet(1, 'LE-R4 a reset after leaving asks nothing');
    expect(await listeners(), 'LE-R4 off the screen: none').toEqual({ reset: 0, activity: 0 });
    await nav('Activity').click();
    const back = await screen.request(1, 'LE-R4 page 1 on return');
    expect(back.params.cursor ?? null, 'LE-R4 page 1 on return has no cursor').toBeNull();
    await back.answer({ rows: rowsOf('b', 1), next_cursor: null });
    expect(await listeners(), 'LE-R4 back on the screen: one of each').toEqual({ reset: 1, activity: 1 });
    await stream.send(resetFrame('activity'));
    await screen.request(2, 'LE-R4 a reset on return asks');
    await screen.quiet(3, 'LE-R4 once');
  });

  test('LE-R5 resets during a request coalesce to one refresh', async ({ page, request }, testInfo) => {
    const { screen, stream } = await screenFor(page, request, testInfo);
    await countDelivered(page);
    await screen.open(stream);
    // Activity frames first: the landed path, which LE3 also pins.
    const p1 = await screen.request(0, 'LE-R5 page 1');
    for (let i = 0; i < 5; i += 1) await stream.send(activityFrame(callRow(`a.burst${i}`)));
    await seen(page, 'activity', 5, 'LE-R5 five activity frames');
    await screen.quiet(1, 'LE-R5 nothing more while page 1 is out');
    await p1.answer({ rows: rowsOf('a', 1), next_cursor: null });
    const live = await screen.request(1, 'LE-R5 one trailing refresh for the activity frames');
    await screen.quiet(2, 'LE-R5 and only one');
    // The same burst of resets while that refresh is out.
    for (let i = 0; i < 5; i += 1) await stream.send(resetFrame('activity'));
    await seen(page, 'reset', 5, 'LE-R5 five resets');
    await screen.quiet(2, 'LE-R5 nothing more while the refresh is out');
    await live.answer({ rows: rowsOf('b', 1), next_cursor: null });
    const trailing = await screen.request(2, 'LE-R5 one trailing refresh for the resets');
    expect(trailing.params.cursor ?? null, 'LE-R5 the trailing refresh is page 1').toBeNull();
    await screen.quiet(3, 'LE-R5 and only one');
    await trailing.answer({ rows: rowsOf('c', 1), next_cursor: null });
    await screen.quiet(3, 'LE-R5 settled');
    // Leaving: a refresh out and resets behind it ask nothing once the screen is gone.
    await stream.send(resetFrame('activity'));
    await seen(page, 'reset', 6, 'LE-R5 one more reset');
    const out = await screen.request(3, 'LE-R5 a reset asks');
    for (let i = 0; i < 5; i += 1) await stream.send(resetFrame('activity'));
    await seen(page, 'reset', 11, 'LE-R5 five more while it is out');
    await screen.quiet(4, 'LE-R5 nothing more while it is out');
    await page.getByRole('link', { name: 'Tools', exact: true }).first().click();
    await screen.aborted(out, 'LE-R5 leaving aborts the refresh');
    await out.answer({ rows: rowsOf('late', 1), next_cursor: null });
    await screen.quiet(4, 'LE-R5 nothing asked after the leave');
  });
});
