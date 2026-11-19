// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The first-paint gate's planted slowdown (UI12.10), used only by server.mjs
// when the gate starts it with --perf-gate. The plant is an inline script at
// the very start of the head that spins on the wall clock, so the CPU
// throttling multiplier does not scale it. The page's first paint needs no
// subresource (inline frame CSS, a deferred module, shell.css at the end of
// the body), so the spin holds the parser while nothing first paint waits on
// is in flight. The CSP allows inline code only by hash, so the spin's hash
// is added to script-src, and that is the only other change.

import { createHash } from 'node:crypto';

const FLAG = '--plant-first-paint-delay-ms=';

/** The planted delay in ms from server.mjs's arguments, or null. Refused without --perf-gate. */
export function plantFromArgs(args) {
  const given = args.filter((a) => a.startsWith(FLAG));
  if (given.length === 0) return null;
  if (!args.includes('--perf-gate')) throw new Error('--plant-first-paint-delay-ms is refused without --perf-gate');
  const raw = given[given.length - 1].slice(FLAG.length);
  const ms = Number(raw);
  if (!/^\d+$/.test(raw) || ms <= 0) throw new Error(`--plant-first-paint-delay-ms needs a positive whole number, got "${raw}"`);
  return ms;
}

const spin = (ms) => `{const t=performance.now()+${ms};while(performance.now()<t);}`;

/** The document with the spin as the head's first element. */
export function plantDoc(doc, ms) {
  if (!doc.includes('<head>\n')) throw new Error('index.html: no "<head>" line to plant after');
  return doc.replace('<head>\n', `<head>\n<script>${spin(ms)}</script>\n`);
}

/** The policy with the spin's hash added to script-src, nothing else. */
export function plantCsp(csp, ms) {
  if (!csp.includes("script-src 'self';")) throw new Error(`CSP has no "script-src 'self';" to extend: ${csp}`);
  const hash = createHash('sha256').update(spin(ms), 'utf8').digest('base64');
  return csp.replace("script-src 'self';", `script-src 'self' 'sha256-${hash}';`);
}
