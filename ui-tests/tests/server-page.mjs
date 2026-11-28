// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Test plumbing for the Server page rows: one fake gateway that
// answers the status, config and keys reads and records every backend request,
// so a row can count reads and read back exactly what the page sent.
import { shellModuleUrl } from './shell.mjs';

/** One status entry with the members status.rs serves, overridable. */
export const entry = (name, state, more = {}) => ({
  name, state, reason: '', next_retry_at: null, running: state === 'running', transport: 'stdio',
  tools_cached: 7, calls_24h: 31, circuit_state: 'closed', cleartext_credentials_accepted: false,
  needs_sign_in: false, ...more,
});

/** The full status view an unscoped admin gets. */
export const fullView = (...servers) => ({ server_count: servers.length, servers });

/** A keys-read entry and its answer, as keys.rs serves them. */
export const key = (name, backends, more = {}) => ({ name, backends, allowed_tools: null, denied_tools: null, admin: false, live: true, ...more });
export const keysBody = (...keys) => ({ code: 200, body: { keys } });

/** A name with every character a path must encode: space, slash, ?, %, # and a non-ASCII letter. */
export const HARD = 'a b/c?d%e#f é';
export const HARD_ENC = 'a%20b%2Fc%3Fd%25e%23f%20%C3%A9';

/** A promise opened by hand, to hold one reply. */
export function gate() {
  let open;
  const shut = new Promise((ok) => { open = ok; });
  return { shut, open };
}

/**
 * Fake the gateway for one page. `status` answers every status read after the
 * shell's own first one (a body, or `{code, body}`); `keys` and `config` answer
 * their reads; `backend(method, path, body)` answers a request under
 * /ui/api/backends/, returning `{code, body, hold?}`. Returns live counters and
 * the list of backend requests as sent (raw path, method, parsed body).
 */
export async function fakeServerGateway(page, { status, keys = { code: 200, body: { keys: [] } }, config = { code: 200, body: {} }, backend = () => ({ code: 404, body: {} }) }) {
  const seen = { status: 0, config: 0, keys: 0, backend: [] };
  let boot = true;
  const reply = async (route, a) => {
    const { code = 200, body = a, hold = null, drop = false, raw = null } = a && 'code' in a ? a : { body: a };
    if (hold) await hold;
    if (drop) return route.abort('failed');
    return route.fulfill({ status: code, contentType: 'application/json', body: raw ?? JSON.stringify(body) });
  };
  await page.route('**/ui/api/status', (route) => {
    if (boot) { boot = false; return route.fulfill({ status: 200, contentType: 'application/json', body: '{}' }); }
    seen.status += 1;
    return reply(route, typeof status === 'function' ? status(seen.status) : status);
  });
  await page.route('**/ui/api/config', (route) => { seen.config += 1; return reply(route, config); });
  await page.route('**/ui/api/keys', (route) => { seen.keys += 1; return reply(route, keys); });
  await page.route('**/ui/api/backends/**', (route) => {
    const req = route.request();
    const raw = new URL(req.url()).pathname;
    let body = null;
    try { body = req.postDataJSON(); } catch { body = req.postData(); }
    seen.backend.push({ method: req.method(), path: raw, body });
    return reply(route, backend(req.method(), raw, body));
  });
  return seen;
}

/** What the live stream does on a status frame: hand the screens the status body. */
export const statusEvent = (page, body) => page.evaluate((detail) => dispatchEvent(new CustomEvent('gateway-status', { detail })), body);

/**
 * Run `fn(shellModule, arg)` in the page and return its plain result. The module
 * comes back as a handle and `fn` runs on it through Playwright, never as page
 * code built from a string: the shell's policy has no 'unsafe-eval'.
 */
export async function shellCall(page, fn, arg) {
  const url = await shellModuleUrl(page);
  const shell = await page.evaluateHandle((u) => import(u), url);
  try {
    return await shell.evaluate(fn, arg);
  } finally {
    await shell.dispose();
  }
}

/** Move the page to `path` the way the app does, through the shell's go(). */
export const goTo = (page, path) => shellCall(page, (m, p) => m.go(p), path);
