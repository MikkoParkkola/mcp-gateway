// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Every address and request path that carries a name comes from ONE
// side-effect-free module, server-paths, which also owns the shell's pathFor.
// Unit rows import it from a data: URL of its served bytes; source rows read
// the modules that must not build such a path themselves.
import { test, expect } from './base.mjs';
import { served } from './copy-check.mjs';

const PATHS = /^server-paths\.[0-9a-f]{12}\.js$/;
const PAGE = /^server-page\.[0-9a-f]{12}\.js$/;
const SERVERS = /^servers\.[0-9a-f]{12}\.js$/;
const SHELL = /^shell\.[0-9a-f]{12}\.js$/;

let pathsPromise = null;
const loadPaths = () => (pathsPromise ??= import(`data:text/javascript;base64,${Buffer.from(served(PATHS).text).toString('base64')}`));

const HARD = 'a b/c?d%e#f é';
const HARD_ENC = 'a%20b%2Fc%3Fd%25e%23f%20%C3%A9';

test.describe('S3 pathFor lives in server-paths', () => {
  test('S3 pathFor gives the shell its addresses, with and without an object', async () => {
    const { pathFor } = await loadPaths();
    expect(pathFor({ page: 'servers', object: HARD, tab: 'status' })).toBe(`/ui/servers/${HARD_ENC}/status`);
    expect(pathFor({ page: 'servers', object: 'a b', tab: 'actions' })).toBe('/ui/servers/a%20b/actions');
    expect(pathFor({ page: 'servers', object: null, tab: 'status' })).toBe('/ui/servers/status');
  });

  test('S3 the shell no longer defines pathFor and imports it from server-paths', () => {
    const shell = served(SHELL).text;
    const file = served(PATHS).name.replace(/\./g, '\\.');
    expect(shell).not.toMatch(/function\s+pathFor\s*\(/);
    expect(shell).toMatch(new RegExp(`import\\s*\\{[^}]*\\bpathFor\\b[^}]*\\}\\s*from\\s*'/ui/assets/${file}'`));
  });
});

test.describe('server-paths builds every name-bearing path', () => {
  test('serverPath, keyPath, backendApi and activityHref encode the name as one segment or one query value', async () => {
    const { serverPath, keyPath, backendApi, activityHref } = await loadPaths();
    expect(serverPath('my server', 'status')).toBe('/ui/servers/my%20server/status');
    expect(serverPath(HARD, 'actions')).toBe(`/ui/servers/${HARD_ENC}/actions`);
    expect(keyPath('ops team')).toBe('/ui/access/ops%20team/status');
    expect(keyPath(HARD)).toBe(`/ui/access/${HARD_ENC}/status`);
    expect(backendApi(HARD)).toBe(`/ui/api/backends/${HARD_ENC}`);
    for (const suffix of ['revive', 'signin', 'signin/confirm']) {
      expect(backendApi(HARD, suffix)).toBe(`/ui/api/backends/${HARD_ENC}/${suffix}`);
    }
    expect(activityHref('my server')).toBe('/ui/activity?server=my%20server');
    expect(activityHref(HARD)).toBe(`/ui/activity?server=${HARD_ENC}`);
  });

  test('addressable refuses the two names no address can carry', async () => {
    const { addressable } = await loadPaths();
    expect([addressable('.'), addressable('..'), addressable('github'), addressable('a.b')]).toEqual([false, false, true, true]);
  });
});

test.describe('source rows', () => {
  test('S1 names enter paths only through server-paths', () => {
    for (const pattern of [PAGE, SERVERS]) {
      const { name, text } = served(pattern);
      // Only server-paths encodes a name; no other module builds a /ui/ path from parts.
      expect(text, name).not.toMatch(/encodeURIComponent|encodeURI\(/);
      expect(text, name).not.toMatch(/`[^`]*\/ui\/[^`]*\$\{/);
      expect(text, name).not.toMatch(/['"`]\/ui\/[^'"`]*['"`]\s*\+/);
      expect(text, name).not.toMatch(/\+\s*['"`]\/ui\//);
      expect(text, name).not.toMatch(/\.concat\([^)]*\/ui\/|\/ui\/[^\n]*\.join\(|\.replace\([^)]*\/ui\//);
    }
  });

  test('S2 the server page, the paths module and the Servers module insert no markup', () => {
    for (const pattern of [PAGE, PATHS, SERVERS]) {
      const { name, text } = served(pattern);
      expect(text, name).not.toMatch(/innerHTML|outerHTML|insertAdjacentHTML|document\.write/);
    }
  });

  test('server-paths imports nothing and touches no page state', () => {
    const { name, text } = served(PATHS);
    expect(text, name).not.toMatch(/^\s*import\s/m);
    expect(text, name).not.toMatch(/\bregister\(|addEventListener\(|document\./);
  });
});
