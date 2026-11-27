// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Fixtures for the Overview's flow map, shared by its spec and its perf rows:
// overview bodies carrying `edges` and `servers` the way GET /ui/api/overview
// sends them (src/gateway/ui/overview.rs), from three callers up to 140 servers.
import { overview } from './overview.mjs';

/** A server row as the overview read sends it; `calls` undefined leaves calls_24h out. */
export function srv(name, { state = 'running', up = state === 'running', calls } = {}) {
  return { name, up, tools: 3, state, reason: null, ...(calls === undefined ? {} : { calls_24h: calls }) };
}
/** One caller x server flow. */
export const edge = (caller, server, calls, blocks = 0) => ({ caller, server, calls, blocks });

/** The overview body with `edges` and `servers`; kpi totals follow the servers unless given. */
export function flowBody({ edges = [], edgesMore = { count: 0, calls: 0, overflow_calls: 0 }, servers = [], serversMore = { count: 0, up: 0, down: 0 }, kpi = {} } = {}) {
  const base = overview();
  return {
    ...base,
    kpi: { ...base.kpi, servers_total: servers.length + serversMore.count, tools_total: 12, ...kpi },
    edges: { rows: edges, more: edgesMore },
    servers: { rows: servers, more: serversMore },
  };
}

/** Three callers, four servers (one paused): the small map. */
export const SMALL = flowBody({
  edges: [edge('key:alice', 'github', 70), edge('key:alice', 'stripe', 50), edge('oidc:bob', 'github', 80), edge('session:s1', 'linear', 40)],
  servers: [srv('github', { calls: 150 }), srv('stripe', { calls: 50 }), srv('linear', { calls: 40 }), srv('jira', { state: 'paused', calls: 0 })],
});

/** `count` callers named c1..cN with descending calls (N * 10 ... 10), one flow each to `github`. */
export const callers = (count, blocks = () => 0) => Array.from({ length: count }, (_, i) => edge(`key:c${i + 1}`, 'github', (count - i) * 10, blocks(i)));
/** `count` running servers s1..sN with descending calls. */
export const servers = (count) => Array.from({ length: count }, (_, i) => srv(`s${i + 1}`, { calls: (count - i) * 5 }));

/**
 * 140 servers: 24 served rows (one stopped, one paused, 22 running) and 116 folded (110 answering,
 * 6 not), with 48 flows over 9 callers and 12 smaller flows not drawn. `variant` 1 changes every
 * number, swaps one caller for another and gives one more caller blocked calls (the F1 alternation).
 */
export function big(variant = 0) {
  const rows = [srv('down-1', { state: 'unhealthy', calls: 3 }), srv('paused-1', { state: 'paused', calls: 0 }),
    ...Array.from({ length: 22 }, (_, i) => srv(`srv-${i + 1}`, { calls: 900 - i * 30 + variant * 7 }))];
  const who = Array.from({ length: 9 }, (_, i) => (variant && i === 0 ? 'oidc:late' : `key:agent-${i + 1}`));
  const edges = Array.from({ length: 48 }, (_, i) => edge(who[i % 9], rows[i % 24].name, 400 - i * 7 + variant * 3, (i % 9 === 1 || (variant && i % 9 === 2)) ? 2 : 0));
  return flowBody({ edges, edgesMore: { count: 12, calls: 345, overflow_calls: 0 }, servers: rows, serversMore: { count: 116, up: 110, down: 6 } });
}
