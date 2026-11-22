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
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { test, expect, blockingViolations, WIDTHS } from './base.mjs';
import { shellReady, heldStream, frame } from './shell.mjs';

test.use({ timezoneId: 'UTC' });

const SHELL_DIR = fileURLToPath(new URL('../../src/gateway/ui/shell/', import.meta.url));

/** The single served file whose name fits `pattern`: its name and text. */
function served(pattern) {
  const hits = readdirSync(SHELL_DIR).filter((f) => pattern.test(f));
  if (hits.length !== 1) throw new Error(`want exactly one ${pattern} in src/gateway/ui/shell, have ${hits.length}`);
  return { name: hits[0], text: readFileSync(SHELL_DIR + hits[0], 'utf8') };
}

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
const FRESH = (q) => ({ query: q, rows: [], cursor: null, window: null, dirty: false, held: false, newer: false, notices: [], flight: null });
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
            ? { handle: target.handle, answer: answer(target.query, pageOf(target), `c${pageOf(target) + 1}`), fresh: {}, now }
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
const MORE_FAILED = 'More calls could not be read.';
const UNAVAILABLE = 'Activity is unavailable';
const NOT_FINAL = 'delivery not yet recorded';

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
    expect(await screen.said() - before, 'LE4 announced once for three frames').toBe(1);
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
      expect(await blockingViolations(page), `LE12 ${width}: axe`).toEqual([]);
      expect(await page.locator('#announcer').getAttribute('aria-live'), `LE12 ${width}: polite`).toBe('polite');
    });
  }
});
