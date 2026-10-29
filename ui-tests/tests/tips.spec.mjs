// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The tooltip copy checks (C1, C2, C8, C9, S1): the real copy asset and screen
// modules pass, and each planted fault fails. No browser needed.
import { readFileSync, readdirSync } from 'node:fs';
import { test, expect } from './base.mjs';
import { SHELL_DIR, readCopy, readScreens, scanScreens, shapeProblems, pairingProblems } from './copy-check.mjs';

test('C8 the real copy has the agreed shape', () => {
  expect(shapeProblems(readCopy())).toEqual([]);
});

test('C1 C2 the real screens and copy pair up by page and tab', () => {
  const scan = scanScreens(readScreens());
  expect(Object.keys(scan.tabs).length, 'the scan found no registered screen').toBeGreaterThan(0);
  expect(pairingProblems(readCopy(), scan)).toEqual([]);
});

test('C9 Tools draws its Status note and keeps Try a tool pending under the null Actions tab', () => {
  const scan = scanScreens(readScreens());
  expect(scan.tabs.tools).toEqual({ status: true, actions: false, settings: false });
  expect(scan.drawn.has('tools.status.load-11-tools-and-reach')).toBe(true);
  const copy = readCopy();
  expect(copy._pending.tools).toEqual(['tools.actions.run-as']);
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
