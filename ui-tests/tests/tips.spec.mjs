// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The tooltip copy checks (C1, C2, C8, C9, S1): the real copy asset and screen
// modules pass, and each planted fault fails. No browser needed.
import { readFileSync, readdirSync } from 'node:fs';
import { test, expect } from './base.mjs';
import { SHELL_DIR, readCopy, readScreens, readShell, scanScreens, shapeProblems, pairingProblems, rowFormProblems, orderProblems } from './copy-check.mjs';

test('C8 the real copy has the agreed shape', () => {
  expect(shapeProblems(readCopy())).toEqual([]);
});

test('C1 C2 the real screens and copy pair up by page and tab', () => {
  const scan = scanScreens(readScreens());
  expect(Object.keys(scan.tabs).length, 'the scan found no registered screen').toBeGreaterThan(0);
  // The shell's own tooltips (the environment chip) are drawn too, though no screen draws them.
  const shell = scanScreens([readShell()]);
  expect(shell.tabs, 'the shell registers no screen').toEqual({});
  expect([...shell.drawn].sort()).toEqual(['gateway.status.environment-from-hostname', 'gateway.status.environment-not-set']);
  for (const id of shell.drawn) scan.drawn.add(id);
  scan.nonLiteral += shell.nonLiteral;
  expect(pairingProblems(readCopy(), scan)).toEqual([]);
});

test('C9 Tools draws its Status note, and Run as is no longer pending (it moved to v4.0.1)', () => {
  const scan = scanScreens(readScreens());
  expect(scan.tabs.tools).toEqual({ status: true, actions: true, settings: false });
  expect(scan.drawn.has('tools.status.load-11-tools-and-reach')).toBe(true);
  const copy = readCopy();
  expect(copy._pending.tools).toBeUndefined();
  expect(copy._pending_later['tools.actions.run-as']).toBeUndefined();
});

test('S1 the tooltip module imports nothing from the shell', () => {
  const name = readdirSync(SHELL_DIR).find((f) => /^tooltip\.[0-9a-f]{12}\.js$/.test(f));
  expect(name, 'no tooltip module').toBeTruthy();
  const src = readFileSync(SHELL_DIR + name, 'utf8');
  expect(src).not.toMatch(/\bimport\b[^;]*['"]\/ui\/assets\/shell/);
});

const SCREEN = (body) => `register('servers', { title: 'Servers', tabs: { status: (b) => b, actions: null, settings: null } });\n${body}`;
const OK = {
  _pending: { servers: ['servers.actions.add'] },
  'servers.status.paused': { title: 'Paused', text: 'Stopped.' },
  'servers.actions.add': { title: 'Add', text: 'Adds one.' },
};
const pair = (copy, body) => pairingProblems(copy, scanScreens([SCREEN(body)]));

test.describe('C2 planted faults', () => {
  test('a clean pairing passes, including an id pending under a null tab', () => {
    expect(pair(OK, "tip('servers.status.paused');")).toEqual([]);
  });
  test('a drawn id with no copy fails', () => {
    expect(pair(OK, "tip('servers.status.paused'); tip('servers.status.gone');")).toEqual(['servers.status.gone: drawn with no copy']);
  });
  test('an extra copy id, neither drawn nor pending, fails', () => {
    const copy = { ...OK, 'servers.status.extra': { title: 'Extra', text: 'x' } };
    expect(pair(copy, "tip('servers.status.paused');")).toEqual(['servers.status.extra: neither drawn nor pending']);
  });
  test('an id pending under a built tab fails', () => {
    const copy = { ...OK, _pending: { servers: ['servers.actions.add', 'servers.status.paused'] } };
    expect(pair(copy, '')).toEqual(['servers.status.paused: pending under built servers.status']);
  });
  test('an unknown tab segment fails', () => {
    const copy = { ...OK, 'servers.extras.x': { title: 'X', text: 'x' }, _pending: { servers: ['servers.actions.add', 'servers.extras.x'] } };
    expect(pair(copy, "tip('servers.status.paused');")).toContain('servers.extras.x: not <page>.<tab>.<subject>');
  });
  test('comments with commas and colons inside tabs do not hide a tab', () => {
    const src = "register('servers', { tabs: {\n // One renderer, two routes: a note\n status: (b) => b,\n /* later: a, b */ actions: null,\n settings: null } });";
    expect(scanScreens([src]).tabs.servers).toEqual({ status: true, actions: false, settings: false });
  });
  test('a closing brace inside a string does not end the tabs early', () => {
    const src = "register('servers', { tabs: { status: (b) => { b.textContent = '} oops: ,'; }, actions: (b) => b, settings: null } });";
    expect(scanScreens([src]).tabs.servers).toEqual({ status: true, actions: true, settings: false });
  });
  test('a tab function with braces in it is still read as built', () => {
    const src = "register('servers', { title: 'S', tabs: { status: (b) => { if (b) { b.x = 1; } }, actions: null, settings: null } });\ntip('servers.status.paused');";
    expect(pairingProblems(OK, scanScreens([src]))).toEqual([]);
    expect(scanScreens([src]).tabs.servers).toEqual({ status: true, actions: false, settings: false });
  });
  test('a non-literal id fails', () => {
    expect(pair(OK, "tip('servers.status.paused'); tip(someId);")).toContain('1 tip() call(s) with a non-literal id');
  });
});

// A page lands child by child: its first child builds the Status tab, and an id
// a later part of the page draws there stays pending, naming that part.
test.describe('C2 pending later', () => {
  const LOAD = { title: 'Load', text: 'Calls per hour.' };
  // Clean: the built Status tab keeps servers.status.load for the chart, drawn later.
  const LATER = { ...OK, 'servers.status.load': LOAD, _pending_later: { 'servers.status.load': 'the 24 h chart' } };
  const later = (part) => ({ ...LATER, _pending_later: { 'servers.status.load': part } });
  test('an id a later part draws may stay pending under a built tab', () => {
    expect(pair(LATER, "tip('servers.status.paused');")).toEqual([]);
  });
  test('a pending-later id that is drawn fails', () => {
    expect(pair(LATER, "tip('servers.status.paused'); tip('servers.status.load');"))
      .toEqual(['servers.status.load: pending-later but drawn']);
  });
  test('the part may be 60 characters, not 61, and not empty', () => {
    expect(pair(later('x'.repeat(60)), "tip('servers.status.paused');")).toEqual([]);
    expect(pair(later('x'.repeat(61)), "tip('servers.status.paused');")).toEqual(['servers.status.load: pending-later names no part']);
    expect(pair(later('  '), "tip('servers.status.paused');")).toEqual(['servers.status.load: pending-later names no part']);
    expect(pair(later(7), "tip('servers.status.paused');")).toEqual(['servers.status.load: pending-later names no part']);
  });
  test('a pending-later id under a null tab fails: it belongs in _pending', () => {
    const copy = { ...OK, _pending: {}, _pending_later: { 'servers.actions.add': 'the add flow' } };
    expect(pair(copy, "tip('servers.status.paused');"))
      .toEqual(['servers.actions.add: pending-later under unbuilt servers.actions, list it in _pending']);
  });
  test('a pending-later id with no copy fails', () => {
    const copy = { ...OK, _pending_later: { 'servers.status.ghost': 'the 24 h chart' } };
    expect(pair(copy, "tip('servers.status.paused');")).toEqual(['servers.status.ghost: pending-later with no copy']);
  });
  test('an id both pending and pending-later fails', () => {
    const copy = { ...LATER, _pending: { servers: ['servers.actions.add', 'servers.status.load'] } };
    expect(pair(copy, "tip('servers.status.paused');")).toEqual(['servers.status.load: pending twice']);
  });
  test('the pending-later map is not read as a copy entry', () => {
    expect(shapeProblems(LATER)).toEqual([]);
  });
  test('a pending-later map that is not a plain object fails its shape', () => {
    expect(shapeProblems({ ...LATER, _pending_later: ['servers.status.load'] })).toEqual(['_pending_later: not an object']);
    expect(shapeProblems({ ...LATER, _pending_later: 'the 24 h chart' })).toEqual(['_pending_later: not an object']);
  });
  test('a pending-later id on a page no screen registers fails: it belongs in _pending', () => {
    const copy = { ...OK, 'billing.status.due': LOAD, _pending_later: { 'billing.status.due': 'the invoice list' } };
    expect(pair(copy, "tip('servers.status.paused');"))
      .toEqual(['billing.status.due: pending-later under unbuilt billing.status, list it in _pending']);
  });
  test('a screen cannot draw the bookkeeping key itself', () => {
    expect(pair(LATER, "tip('servers.status.paused'); tip('_pending_later');"))
      .toContain('_pending_later: not <page>.<tab>.<subject>');
  });
});

test.describe('C8 planted faults', () => {
  const one = (e) => shapeProblems({ _pending: {}, 'a.status.b': e });
  for (const [label, entry, problem] of [
    ['a missing title', { text: 't' }, 'a.status.b: missing or empty title'],
    ['an empty title', { title: ' ', text: 't' }, 'a.status.b: missing or empty title'],
    ['both text and rows', { title: 'T', text: 't', rows: [['a', 'b']] }, 'a.status.b: both text and rows'],
    ['neither text nor rows', { title: 'T' }, 'a.status.b: neither text nor rows'],
    ['an empty text', { title: 'T', text: '' }, 'a.status.b: empty text'],
    ['a malformed row', { title: 'T', rows: [['only one']] }, 'a.status.b: rows must be [label, value] pairs of non-empty strings'],
    ['an extra key', { title: 'T', text: 't', note: 'x' }, 'a.status.b: unexpected key note'],
  ]) {
    test(`${label} fails`, () => { expect(one(entry)).toContain(problem); });
  }
  test('a rows entry passes', () => { expect(one({ title: 'T', rows: [['What', 'x'], ['Window', 'y']] })).toEqual([]); });
});

test.describe('C10 every tip in row form, or listed as still free text', () => {
  test('C10 the real copy: every tip in rows or listed, and the list is exactly the free-text tips', () => {
    const copy = readCopy();
    expect(rowFormProblems(copy)).toEqual([]);
    const free = Object.entries(copy).filter(([id, e]) => !id.startsWith('_') && 'text' in e).map(([id]) => id).sort();
    expect([...(copy._pending_rows ?? [])].sort()).toEqual(free);
  });

  const ROWS = { title: 'Calls today', rows: [['What', 'Tool calls.'], ['Why', 'Shows the load.']] };
  const FREE = { title: 'Paused', text: 'Stopped.' };
  const base = () => ({ _pending_rows: ['a.status.free'], 'a.status.rows': ROWS, 'a.status.free': FREE });

  test('C10 a row tip and a listed free-text tip pass', () => {
    expect(rowFormProblems(base())).toEqual([]);
  });
  test('C10a a free-text tip not on the list fails', () => {
    expect(rowFormProblems({ ...base(), 'a.status.new': FREE }))
      .toEqual(['a.status.new: free text; rewrite it into rows or list it in _pending_rows']);
  });
  test('C10b a listed tip already in rows fails', () => {
    expect(rowFormProblems({ ...base(), _pending_rows: ['a.status.free', 'a.status.rows'] }))
      .toEqual(['a.status.rows: listed in _pending_rows but already in rows']);
  });
  test('C10c a listed id with no copy fails', () => {
    expect(rowFormProblems({ ...base(), _pending_rows: ['a.status.free', 'a.status.gone'] }))
      .toEqual(['a.status.gone: listed in _pending_rows with no copy']);
  });
  test('C10d the list is bookkeeping: shape and pairing do not read it as a copy entry, and a screen drawing it fails', () => {
    const copy = { _pending: { a: ['a.status.rows', 'a.status.free'] }, ...base() };
    expect(shapeProblems(copy)).toEqual([]);
    expect(pairingProblems(copy, { drawn: new Set(), nonLiteral: 0, tabs: {} })).toEqual([]);
    expect(pairingProblems(copy, { drawn: new Set(['_pending_rows']), nonLiteral: 0, tabs: {} }))
      .toEqual(['_pending_rows: not <page>.<tab>.<subject>']);
  });
  test('C10e a list that is not an array of ids fails its shape', () => {
    expect(shapeProblems({ ...base(), _pending_rows: { 'a.status.free': true } }))
      .toContain('_pending_rows: not an array of ids');
    expect(shapeProblems({ ...base(), _pending_rows: ['a.status.free', 3] }))
      .toContain('_pending_rows: not an array of ids');
  });
});

test.describe('C11 rows in the frame-36 order, five labels only', () => {
  test('C11 the real copy: every row tip uses the five labels in order', () => {
    expect(orderProblems(readCopy())).toEqual([]);
  });

  const one = (rows) => orderProblems({ _pending_rows: [], 'a.status.b': { title: 'T', rows } });
  const row = (label) => [label, `${label} text.`];

  test('C11 all five labels in order pass', () => {
    expect(one(['What', 'Window', 'Source', 'Default', 'Why'].map(row))).toEqual([]);
  });
  test('C11a rows that do not apply are left out: What then Why passes', () => {
    expect(one(['What', 'Why'].map(row))).toEqual([]);
  });
  test('C11b Why before What fails', () => {
    expect(one(['Why', 'What'].map(row))).toEqual(['a.status.b: rows out of order: Why before What']);
  });
  test('C11b Default before Source fails', () => {
    expect(one(['What', 'Default', 'Source'].map(row))).toEqual(['a.status.b: rows out of order: Default before Source']);
  });
  test('C11c a label used twice fails', () => {
    expect(one(['What', 'What'].map(row))).toEqual(['a.status.b: label What appears twice']);
  });
  test('C11d a label outside the five fails', () => {
    expect(one(['What', 'Next'].map(row)))
      .toEqual(['a.status.b: label Next is not one of What, Window, Source, Default, Why']);
  });
  test('C11d labels are exact: lower-case what is not What', () => {
    expect(one(['what'].map(row))).toEqual(['a.status.b: label what is not one of What, Window, Source, Default, Why']);
  });
  test('C11e a free-text tip is not judged here', () => {
    expect(orderProblems({ _pending_rows: ['a.status.b'], 'a.status.b': { title: 'T', text: 'Why first.' } })).toEqual([]);
  });
});
