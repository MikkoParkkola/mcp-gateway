// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Fixture server for the browser tests. It answers /ui the way the gateway
// does (src/gateway/ui/mod.rs and shell.rs), so the shell runs unchanged:
//
//   /ui, /ui/classic       a stand-in for the classic page (fixtures/classic.html)
//   /ui/assets/{file}      an asset from shell.rs's ASSETS table, by exact name
//   /ui/api/{path}         fixtures/api/{path}.json for GET, else 404
//   /ui/{*path}            the shell document, with the CSP read from shell.rs
//
// The asset table and the CSP are parsed from shell.rs rather than copied, so
// the tests cannot drift from what the gateway serves. Node stdlib only.

import { createServer } from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const SHELL_DIR = join(HERE, '..', 'src', 'gateway', 'ui', 'shell');
const SHELL_RS = readFileSync(join(HERE, '..', 'src', 'gateway', 'ui', 'shell.rs'), 'utf8');
const FIXTURES = join(HERE, 'fixtures');

/** The CSP constant, with Rust's `\` line continuations folded. */
function parseCsp(src) {
  const m = src.match(/const CSP: &str = "((?:[^"\\]|\\.)*)"/s);
  if (!m) throw new Error('shell.rs: CSP constant not found');
  return m[1].replace(/\\\n\s*/g, '');
}

/** Asset name to file, from the ASSETS table. */
function parseAssets(src) {
  const table = new Map();
  for (const m of src.matchAll(/"([\w.-]+)",\s*include_bytes!\("shell\/([^"]+)"\)/g)) {
    table.set(m[1], join(SHELL_DIR, m[2]));
  }
  if (table.size === 0) throw new Error('shell.rs: ASSETS table not found');
  return table;
}

const CSP = parseCsp(SHELL_RS);
const ASSETS = parseAssets(SHELL_RS);
const TYPES = { css: 'text/css; charset=utf-8', js: 'text/javascript; charset=utf-8', woff2: 'font/woff2', svg: 'image/svg+xml', png: 'image/png' };

/** The shell document, plus the fixture pages when the test asked for them. */
function shellDocument(req) {
  const doc = readFileSync(join(SHELL_DIR, 'index.html'), 'utf8');
  if (!/(?:^|;\s*)fixture-pages=1(?:;|$)/.test(req.headers.cookie ?? '')) return doc;
  return doc.replace('</head>', '<script type="module" src="/ui/assets/fixture-pages.mjs"></script>\n</head>');
}

function send(res, status, headers, body) {
  // Names the worktree this server reads, so a run can prove it reached its own.
  res.writeHead(status, { ...headers, 'x-fixture-root': HERE });
  res.end(body);
}

function handle(req, res) {
  const path = new URL(req.url, 'http://fixture').pathname;
  const get = req.method === 'GET' || req.method === 'HEAD';
  if (path === '/ui' || path === '/ui/classic') {
    // axum's get() route: another method answers 405.
    if (!get) return send(res, 405, { allow: 'GET,HEAD' }, '');
    return send(res, 200, { 'content-type': 'text/html; charset=utf-8' }, readFileSync(join(FIXTURES, 'classic.html')));
  }
  // Test-only page registrations (fixtures/fixture-pages.mjs), never in ASSETS.
  if (path === '/ui/assets/fixture-pages.mjs' && get) {
    const shell = [...ASSETS.keys()].find((n) => /^shell\.[0-9a-f]{12}\.js$/.test(n));
    if (!shell) return send(res, 404, {}, '');
    const src = readFileSync(join(FIXTURES, 'fixture-pages.mjs'), 'utf8').replaceAll('__SHELL__', `/ui/assets/${shell}`);
    return send(res, 200, { 'content-type': TYPES.js }, src);
  }
  if (path.startsWith('/ui/assets/')) {
    const file = ASSETS.get(path.slice('/ui/assets/'.length));
    if (!get || !file) return send(res, 404, {}, '');
    const ext = file.split('.').pop();
    return send(res, 200, {
      'content-type': TYPES[ext] ?? 'application/octet-stream',
      'cache-control': 'public, max-age=31536000, immutable',
      'x-content-type-options': 'nosniff',
    }, readFileSync(file));
  }
  if (path === '/ui/api' || path.startsWith('/ui/api/')) {
    const rel = path.slice('/ui/api/'.length);
    const file = join(FIXTURES, 'api', `${rel}.json`);
    if (!get || !/^[\w-]+(\/[\w-]+)*$/.test(rel) || !existsSync(file)) return send(res, 404, {}, '');
    return send(res, 200, { 'content-type': 'application/json' }, readFileSync(file));
  }
  // As shell.rs: a first segment of `api` or `assets` never gets the shell.
  const first = path.slice('/ui/'.length).split('/')[0];
  if (first === 'api' || first === 'assets') return send(res, 404, {}, '');
  if (path.startsWith('/ui/') && path !== '/ui/' && get) {
    return send(res, 200, {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-cache, no-store, must-revalidate',
      'content-security-policy': CSP,
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
    }, shellDocument(req));
  }
  return send(res, 404, {}, '');
}

const port = Number(process.env.PORT ?? 4173);
createServer(handle).listen(port, '127.0.0.1', () => {
  console.log(`fixture server on http://127.0.0.1:${port}`);
});
