// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The 4.0.0 breaking-change notice items, printed by `migrate_4_0_0_release_notice`.
//!
//! Its own file so a new item does not grow `upgrade.rs`, which is held at its line baseline.

// ── 4.0.0 migration: breaking-change notice ───────────────────────────────────
// v4.0.0 carries the changes listed below: each can surprise an operator, and
// no config edit can pre-empt any of them. The list is the count.
// A 3.x `gateway.yaml` loads unchanged, so this migration never edits the file — it reports, once, on the first 4.0.0 start.

/// The twenty-four 4.0.0 changes, in the order they are printed.
///
/// Pinned as a slice so a test can assert the notice still carries every item:
/// a release note that quietly loses one is worse than none, because the operator has read it.
pub(super) const NOTICE_4_0_0_ITEMS: &[&str] = &[
    "OAuth credentials are now stored per issuer, so 3.x tokens are no longer \
read where they sit. By default each OAuth backend re-authenticates once, on \
its next use: expect one authorization prompt per backend, and no config \
change is needed. To keep a credential instead, run `mcp-gateway accounts \
migrate-credentials --descriptor-id ID --legacy-issuer URL` per backend, which \
is offline and refuses rather than guessing. Either way your 3.x token files \
are left untouched in `~/.mcp-gateway/oauth/` at mode 0600. Delete them once \
every backend has re-authorized or migrated AND been used successfully: a \
migrated credential is still the same grant, so the first refresh against a \
provider that rotates refresh tokens retires the copy in the old file.",
    "A malformed line in an `env_files` file now FAILS STARTUP instead of being \
skipped silently. A typo that used to cost one missing variable now costs a \
refused start, and says which line.",
    "Protocol version 2024-10-07 is no longer advertised. Clients that only \
speak it must upgrade; 2025-03-26 and later are unaffected.",
    "Rate-limited backend responses (HTTP 429 and equivalents) no longer count \
against the error budgets or the circuit breaker (GH #475). A throttled backend \
is no longer auto-killed for being busy.",
    "A response is cached only under a protocol revision the gateway can \
identify. A stateless POST that sends no `MCP-Protocol-Version` header and \
never completes `initialize` is no longer served from cache, so that traffic \
reaches your backends and the gateway's own rate limits now apply to calls that \
previously never got that far. Nothing errors: the symptom is throughput and \
backend load. Send the header on stateless requests, or complete `initialize` \
and reuse the session.",
    super::webhook_notice::ITEM,
    "`logging/setLevel` over HTTP now needs an admin key, because it sets the \
log level of every shared backend for every user. Other callers are refused \
with HTTP 403, and with auth off nobody is admin, so it is refused for everyone. \
Stdio is unchanged. To receive fewer log messages, declare a level in each \
request's `_meta` instead.",
    "On an authenticated gateway, `notifications/tools/list_changed` from an \
admin backend edit now reaches only sessions whose key may access that backend; \
a session that presented no credential is not told. With auth off, every \
session is told, as before.",
    "Grant, policy and decision writes to the admin panel's control-plane API \
now return HTTP 409, because nothing enforced that store. Change grants with \
`mcp-gateway identity grants` and policies with `security.sanitize_input` / \
`security.ssrf_protection`. Keep the old store files: 4.1 re-imports them as drafts.",
    "On an authenticated gateway, `subscriptions/listen` without a credential \
that authenticates is refused with HTTP 401, including on a public `/mcp`. A \
listener is told about `tools/list_changed` only for backends its key may \
access, and its stream closes once its credential is revoked or expires; \
re-subscribe with a fresh one. With auth off, nothing changes.",
    "An identity-grants row bound to `exact: <id>` is refused at load, and the \
error lists every such row. Rewrite each as `!exact {source: mtls, id: ...}` or \
`!exact {source: jwt, id: ...}`; the gateway will not pick the source. Until \
then personal capabilities fail closed. `identity grants grant --agent` takes \
`mtls:<id>` or `jwt:<id>`.",
    "Attestation is now off unless `GATEWAY_ATTESTATION_MODE` is set (set `observe` to keep the \
audit lines). `enforce` now refuses unattested calls, playbooks and code mode, and needs a \
signing key; enforce with no key, or any unrecognised value, now FAILS STARTUP.",
    "A tool call carrying an argument key its schema does not declare, at any depth, is \
refused with `isError: true`; relax it with `input_schema_enforcement: standard` or `off`.",
    super::backend_grant_notice::ITEM,
    "`/metrics` now requires `server.metrics_token` (HTTP 401 until set; the admin bearer is \
refused). A missing `env:` variable does not stop startup. Scrape with a dedicated job or the \
chart's ServiceMonitor, never a generic annotation-driven one.",
    "The inbound WebSocket listener, which only echoed frames, is removed: `server.ws_port` now \
FAILS the config load. Clients connect via stdio or HTTP (`POST /mcp`).",
    "More than one replica is refused while state lives in one process: `server.replicas` \
(default 1) above 1 FAILS STARTUP with the modern protocol on, or with the key server or accounts \
enabled. The Helm chart now defaults `replicaCount` to 1 and fails the render on the same rules. \
Without the chart, set `server.replicas` to the processes you run: 1 is a declaration, not a detection.",
    "`server.request_timeout`, never enforced, is removed and now FAILS the config load; bound \
calls with per-backend `timeout`. `server.max_body_size` is enforced on every route: an oversize \
body on `/mcp` gets HTTP 413, JSON-RPC -32600 (was 400, -32700), and webhooks now accept up to it.",
    "With auth on, `security.transparency_log.enabled: true` is REQUIRED (the load FAILS without \
it), and a failed append refuses calls with 503 and unreadies `/readyz` until it recovers. Records \
carry `schema_version: 2`, `who` and `outcome`, including refused and failed calls. On Kubernetes \
the chart's audit volume is an emptyDir: set `audit.existingClaim` to keep the log.",
    "A backend that fails to START now counts toward its circuit breaker on every transport \
(a stdio command that cannot spawn, an HTTP or WebSocket backend that cannot connect). Once it \
opens, callers get `Circuit breaker open ...; last failure: <the start error>` instead of the \
start error itself. Code matching `Error::CircuitOpen(name)` must now match \
`CircuitOpen { backend, last_failure }`.",
    "WebSocket is a backend transport again: `ws_url: wss://...` selects it. Every caller shares \
one socket and the one static credential in `headers`, sent on the upgrade only. `ws://` with \
credentials to another host needs `allow_cleartext_credentials`; `oauth`, identity propagation and \
header or query `secrets` are refused on `ws_url`.",
    "`/health` now answers 503 `degraded` while any backend's circuit breaker is open; before, \
only a failing health tracker did. Monitors on `/health` will see it. `/livez` and `/readyz` stay \
backend-blind, so Kubernetes probes are unaffected.",
    "The audit log now ROTATES at 64 MiB and keeps 12 sealed segments, deleting older ones with \
a signed `audit_segment_expired` record for each; on a full disk it deletes the oldest sealed \
segment (`rotation.on_disk_full: refuse` keeps every record and goes unready instead). \
`audit verify` reads every segment. Do not rotate the log externally: logrotate breaks the chain.",
    "Legacy HTTP session ids are now always minted by the gateway: a client-chosen \
`Mcp-Session-Id` that names no live session is replaced (the new id is in the response header), \
an empty one counts as absent, and logs carry an 8-hex fingerprint instead of the id. With auth \
off, holding a session id is what makes a session yours.",
    "A tool call to a tool the gateway has not yet listed for that caller now lists the backend \
first, as the caller, instead of being forwarded unchecked. Under `closed`, a list the backend \
answers but the gateway cannot read refuses the call (an unreachable backend fails as a call to it \
would), and so does a tool the backend's complete list lacks; set \
`input_schema_enforcement: standard` to forward. A cold call spends a rate-limit token on the list.",
];
