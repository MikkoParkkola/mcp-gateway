<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# 4.0.0 release: acceptance criteria verified against source, four groups

Four criterion groups are recorded here — MRTR, cache and header, control on the stateless path,
and identity. The other groups in the requirements document have not been swept, so the blocking
count below is a floor. Each group's disagreements with earlier documents are logged under
`audit-notes/`.

Method: every criterion below carries a stable ID (`MIK-NNNN.COMPONENT.N`) pulled from
`docs/requirements/RELEASE-4.0.0-requirements.md`. Status was determined by reading `src/` and
`tests/` directly — never inferred from a requirements/test-plan/gap-plan document's own claim.
Status vocabulary:

- **MET** — production code implements it AND a test exercises it through a production path (file:line for both).
- **UNWIRED** — code exists but has zero non-test callers (symbol + "zero production call sites").
- **UNTESTED** — production code exists and is reachable, but no test covers it (file:line).
- **ABSENT** — nothing implements it.
- **N/A** — with reason.

A criterion is BLOCKING unless it is MET or N/A.

Sections below are appended incrementally as each requirement group is verified.

## MIK-7213 (CACHE) + MIK-7214 (HEADER)

| criterion ID | requirement (short) | status | evidence (file:line) | blocking |
|---|---|---|---|---|
| MIK-7213.CACHE.1 | ttlMs+cacheScope on 5 list methods | MET | `handlers.rs:1293-1299,1306-1341`; test `tests/mik_7213_acs.rs:252-295` | no |
| MIK-7213.CACHE.2 | caller-dependent list results ⇒ private scope | MET | `cacheable.rs:44-66`; test `tests/mik_7213_acs.rs:96-102,253-260` | no |
| MIK-7213.CACHE.3 | public scope only with proof + decision table | ABSENT | enforcement itself is MET/tested, but the decision table it depends on does not exist anywhere — `cacheable.rs:60-62`'s own comment admits it | yes |
| MIK-7213.CACHE.4 | shared cache keyed on all 8 response-varying inputs + policy epoch | ABSENT | key covers only 2 of 8 dimensions, both conditional (`invoke.rs:639-640,780`); zero tests; test-plan itself marks its own case "I" (inferred) not "T" (tested) | yes |
| MIK-7214.HEADER.1 | protocol-version header must equal body | MET | `headers.rs:148-162`, wired `handlers.rs:657-685`, unit+http tests | no |
| MIK-7214.HEADER.2 | method header always present, name header for exactly 3 methods | MET | `headers.rs:43-65`, wired `handlers.rs:627-676`, unit+http tests | no |
| MIK-7214.HEADER.3 | mismatch → HTTP 400 + JSON-RPC -32020 | MET | `era.rs:37`, `handlers.rs:677-685`, tested | no |
| MIK-7214.HEADER.4 | non-ASCII name via sentinel | MET | `headers.rs:79-98`, 5 unit tests — caveat: decode-only, no encode/emit path found anywhere in src/ | no |
| MIK-7214.HEADER.5 | x-mcp-header forwarding (SEP-2243) | ABSENT | zero hits anywhere in src/, zero tests | yes |
| MIK-7214.HEADER.6 | header validation happens before authorize/execute | MET | `handlers.rs:619-716` straight-line order; e2e test `tests/mik_7214_acs.rs:609-636` | no |

Note: `tests/mik_7272_conformance.rs:194-201` bundles HEADER.1-.6 under one row claiming "support x-mcp-header" — its own cited evidence only covers HEADER.1-.4-style tests. That conformance table claims coverage for HEADER.5, which has zero implementing code and zero tests. Do not trust that table's self-report.

Note: gap-plan's separate claim that `EraCache::resolve_with`/`classify` (`src/protocol/era.rs`) are implemented+tested but have zero callers in `src/backend`/`src/transport` is confirmed true — but that is the *outbound* era-negotiation feature, structurally distinct from CACHE.1-4/HEADER.1-6; not conflated here.

## MIK-7212 (MRTR)

| criterion ID | requirement (short) | status | evidence (file:line) | blocking |
|---|---|---|---|---|
| MIK-7212.MRTR.1 | carry `inputResponses`/`requestState` on a `tools/call` retry | UNWIRED | Impl extracts both fields (`src/protocol/mrtr.rs:57-91`, called `handlers.rs:860`), but every well-formed retry is refused unconditionally at `handlers.rs:873-889` (-32602) before the fields reach a backend — zero production call sites carry them onward | yes |
| MIK-7212.MRTR.2 | mint gateway's own sealed envelope, never forward backend's `requestState` verbatim | UNWIRED | `Keyring::mint`/`open` (`continuation.rs:206-414`, AEAD-sealed, unit-tested) have zero production call sites; `AppState.continuation` field (`src/gateway/router/mod.rs:93`) is constructed (`server/mod.rs:1171`) but never read anywhere in `src/` outside tests | yes |
| MIK-7212.MRTR.3 | client-presented `requestState` treated as attacker-controlled, verified, rejected on failure | UNWIRED | `Keyring::open` fails closed on tamper (`continuation.rs:366-405`, tested), but has no production caller — `handlers.rs:873-889` rejects every retry before verification is attempted | yes |
| MIK-7212.MRTR.4 | continuation bound to principal + original request; not usable elsewhere | UNWIRED | `Payload::redeemable_by` (`continuation.rs:122-144`, constant-time) has real falsifiable tests (`tests/mik_7212_acs.rs:117-153`), but zero production call sites — `rg -n "redeemable_by" src` returns only its definition and the test module | yes |
| MIK-7212.MRTR.5 | single-use + expiry, atomic, holds across every replica | UNWIRED | `ConsumedLedger::consume` (`continuation.rs:440-518`) has a non-test constructor via `ContinuationState::new()` (`server/mod.rs:1171`) and `AppState` does carry the field — but nothing in `src/` outside tests calls `.consume(`/`.ledger()`, so enforcement never runs on a real request | yes |
| MIK-7212.MRTR.6 | retry MUST reach the replica holding the exchange, or fail explicitly — never silently start a second exchange | UNWIRED | `InFlight::hold`/`route`/`complete` (`continuation.rs:551-638`, unit-tested `tests/mik_7212_acs.rs:400-486`) reachable only via `ContinuationState.in_flight()`, never called outside tests | yes |
| MIK-7212.MRTR.7 | modern-backend `InputRequiredResult` bridged to a legacy client via server-initiated request, then retried with collected answers | UNWIRED | `Bridge::to_legacy_client`/`retry_params`, `InputRequired::from_result` (`src/protocol/mrtr.rs:128-223`) — zero production call sites (`rg -n "to_legacy_client\|retry_params\|InputRequired::from_result" src tests` shows only test callers); test-plan itself marks this row `**NOT YET**` (`RELEASE-4.0.0-test-plan.md:311`) | yes |
| MIK-7212.MRTR.8 | in-flight state bounded in count/lifetime, reclaimed on client abandonment | UNWIRED | `InFlight::reap`, capacity refusal (`continuation.rs:571-627`), `ConsumedLedger` capacity refusal (`continuation.rs:483-495`) — unit-tested, but nothing in production calls `hold`/`reap`/`complete`, so no real exchange is ever bounded or reclaimed | yes |
| MIK-7212.MRTR.9 | never send an `inputRequest` of a type the client hasn't declared support for | ABSENT | no implementation anywhere — `rg -n "declared.support\|declaredInputRequestTypes\|input_request_types" src tests` returns nothing; no `ac_mrtr_9_*` test exists; test-plan admits it (`RELEASE-4.0.0-test-plan.md:312`) | yes |
| MIK-7212.MRTR.10 | idempotency key MUST include `inputResponses`/`requestState`; an `InputRequired` result MUST NOT be cached as completed | ABSENT | `idempotency::derive_key` (`src/idempotency.rs:296-299`) hashes only `tool_name`+`arguments`; sole caller `resolve_idempotency_key` (`meta_mcp/support.rs:31-46`) never passes continuation fields (different call path from `tools/call`). `cacheable::result_type_of` (`protocol/cacheable.rs:78`) is unit-tested but has zero production callers. `IdempotencyCache::mark_completed` (`idempotency.rs:198-203`) unconditionally caches, called at `meta_mcp/invoke.rs:852,1277` with no `resultType` gate | yes |

Note: this group's own subagent corrected two of the prior gap-plan's specific claims without changing its functional conclusion — see `audit-notes/criteria-mrtr.md` for the full disagreement log (MRTR.4/.5/.6 constructor/field claims were wrong in gap-plan; the unwired verdict itself still holds for a different reason in each case).

## MIK-6704 (IDENT) + MIK-6865 (SCHEMA) + MIK-7084 (SURFACE) + MIK-7116 (TENANT) + MIK-7252 (IDENT)

| criterion ID | requirement (short) | status | evidence (file:line) | blocking |
|---|---|---|---|---|
| MIK-6704.IDENT.1 | authorization MUST derive from authenticated credential; `clientInfo` MUST NOT influence any authorization decision | MET | `src/protocol/meta.rs:117,271`; test `tests/mik_6704_acs.rs:138` | no |
| MIK-6704.IDENT.2 | `clientInfo`/`clientCapabilities` carried as diagnostic/negotiation context, labelled untrusted | MET | `src/protocol/meta.rs:271` `declares_capability`; tests `tests/mik_6704_acs.rs:63,89,107` | no |
| MIK-6704.IDENT.3 | end-user identity MUST be propagatable to a backend via token exchange (RFC 8693) | MET | `src/identity_propagation/token_exchange.rs`, wired `src/gateway/server/mod.rs:1053-1061`; tests `token_exchange.rs:547,565,604,648` | no |
| MIK-6704.IDENT.5 | where identity cannot be established, gateway MUST refuse rather than fall back to shared credential | MET | `src/identity_propagation/mod.rs:123-137` (`enum PropagationError`, no downgrade variant); tests `tests/mik_6704_acs.rs:194,207` | no |
| MIK-6865.SCHEMA.1 | tool schemas MUST avoid nested-object-in-array shapes; MUST remain valid under JSON Schema 2020-12 | MET* | `tests/mik_7272_exploit_acs.rs:323,343,365` via real `MetaMcp::handle_tools_list`. Caveat: only nested-object-in-array is tested; no 2020-12 dialect/`$ref`/composition validator found anywhere | no (flagged) |
| MIK-7084.SURFACE.1 | `gateway_search` MUST support tiered disclosure; MUST NOT emit ranking telemetry the caller cannot act on | MET* | `src/gateway/meta_mcp/support.rs:161-167,177`, wired via `search.rs:417`, dispatched `mod.rs:1272`; tests `tests/mik_7272_exploit_acs.rs:229,254,272`. Caveat: tests call `prune_constant_signals` directly, not a full dispatch round-trip with an active ranker | no (flagged) |
| MIK-7116.TENANT.1 | cross-tenant data-minimisation guard MUST key on authenticated principal, not session | ABSENT | `rg` for data-minimisation/cross-tenant/sensitive-data-access guard returns only unrelated credential-slot isolation (`src/backend/pool.rs`, `src/identity_propagation/mod.rs`) and network-layer DLP (`src/commands/doctor/shadow.rs`). Matches prior audit: `RELEASE-4.0.0-audit-partial.md:16` | yes |
| MIK-7252.IDENT.4 | playbook steps MUST execute under caller's identity, subject to same per-client backend scoping as a direct call | MET | `src/gateway/meta_mcp/support.rs:190-212` `MetaMcpInvoker` carries `caller` whole into `invoke_tool`; wired `src/gateway/meta_mcp/invoke.rs:2287` inside prod `run_playbook`; tests `src/gateway/meta_mcp/authz_tests.rs:230,248,279` via real `MetaMcp::run_playbook` | no |

Note: `MIK-6704.IDENT.4` is not a gap — that ID slot is filed under ticket `MIK-7252` (a later ticket reused the IDENT component code); see `MIK-7252.IDENT.4` above, the actual criterion at that slot per `audit-notes/criteria-ident.md`.

## MIK-7215 (CONTROL) + MIK-7215 (STATELESS)

| criterion ID | requirement (short) | status | evidence (file:line) | blocking |
|---|---|---|---|---|
| MIK-7215.CONTROL.1 | anomaly detection MUST treat an unobservable identity as blocking, never a silent pass | MET | `src/security/firewall/anomaly.rs` `Observation::{Scored,Unobservable}`; wired `src/security/firewall/mod.rs` `check_request()` (~L280-455), `anomaly_blind` forces `Block`; prod callers `src/gateway/router/backend_handlers.rs:102`, `handlers.rs:952`; tests `tests/mik_7215_controls_acs.rs` `ac_control_1_*` (4) + in-module `mod.rs` (~L944-1020) | no |
| MIK-7215.CONTROL.2 | principal-keyed budget replacing session-keyed budget | ABSENT | cited source lines are CONTROL.1's anomaly code, not budget logic (requirement's own citation is stale). `rg -ni budget src/security/firewall/mod.rs` = 0. `FirewallAction` has no budget variant. Only budget code in repo is backend-keyed (`src/kill_switch/budget.rs`) or spend-tracking (`src/cost_accounting/*`) — neither is this control. Zero `control_2` tests. RFC-0061:284 confirms planned, not built | yes |
| MIK-7215.CONTROL.3 | transparency-log correlation key MUST be the OTel trace id, not session id | ABSENT | `src/protocol/trace.rs` `TraceContext::from_meta` exists+tested, but the one prod call site `src/gateway/meta_mcp/invoke.rs:1303` uses `let sid = session_id.unwrap_or("unknown")` — a `trace_id` var is in scope in the same fn (used at L1280,L1310 debug/warn) and is not substituted here. Every stateless call logs `"unknown"` as its correlation key. `src/security/transparency_log.rs` has zero trace_id/traceparent/correlation occurrences | yes |
| MIK-7215.CONTROL.4 | session-lifecycle TTL-reaping owns cleanup previously done by disconnect | UNWIRED | `src/gateway/session_lifecycle.rs` `SessionLifecycle::{register,track,reap}` — solid impl, tests pass against the real type (`tests/mik_7215_controls_acs.rs` `mod lifecycle`, 3 tests) — but `rg -n SessionLifecycle` shows zero references outside its own module: no `AppState` field, no startup construction, no prod caller of `.track(`/`.reap(`. Two other modules' comments say "register via SessionLifecycle::register" — aspirational, never called | yes |
| MIK-7215.CONTROL.5 | no session-keyed mechanism removed before its replacement is named in the governance inventory | MET (I) | `docs/design/RFC-0061-protocol-2026-07-28-release-scope.md` §"U7 RESOLVED" (~L271-293), 12-row table, every row's Replacement column non-empty. Gate as literally stated is satisfied structurally — caveat: several named replacements (firewall budgets, trace-id correlation) are not yet built, per CONTROL.2/.3 above | no |
| MIK-7215.STATELESS.1 | a request carrying its own protocol version is classified modern independent of connection state | MET | `src/protocol/meta.rs` `classify_request()`/`RequestShape::Modern`; tests `tests/mik_7215_acs.rs` (two same-connection requests, different versions, classified independently) | no |
| MIK-7215.STATELESS.2 | modern result identifies the server via `_meta` | MET | wired `src/gateway/router/handlers.rs`; tests `tests/mik_7215_acs.rs` `mod http` (modern asserts `_meta`, legacy regression asserts none) | no |
| MIK-7215.STATELESS.3 | modern response carries no session header | MET | tests assert `Mcp-Session-Id` absent modern / present legacy, via real router | no |
| MIK-7215.STATELESS.4 | unsupported/disabled version refused with its own error + supportedVersions | MET | `handlers.rs` (~L598-617) → `-32022`, HTTP 400; test asserts code + non-empty array | no |
| MIK-7215.STATELESS.5 | unknown method is 404 with a JSON-RPC body | MET | test asserts HTTP 404 + `-32601` + `jsonrpc:"2.0"` | no |
| MIK-7215.STATELESS.6 | removed-in-2026-07-28 methods refused only on modern path | MET | `src/protocol/meta.rs::REMOVED_IN_2026_07_28`, consulted `handlers.rs:707` inside `Modern` branch only. Tests cover only `ping`; `logging/setLevel`/`notifications/roots/list_changed` share the code path but have no direct test — flagged soft spot | no |
| MIK-7215.STATELESS.7 | log notification never delivered to a subscriber that didn't ask for it | MET | test calls real `subscription_registry::delivers()`, asserts `!delivers(...)` | no |
| MIK-7215.STATELESS.8 | one endpoint serves both eras, gated by `modern_protocol` flag | MET | 3 tests against real router: same-URL dual-era, flag-off refusal, legacy-unaffected | no |
| MIK-7215.STATELESS.9 | malformed modern request (missing version/capabilities) refused, distinct from legacy | MET | `classify_request()` → `Malformed{missing}`; 5 unit tests + 1 integration test (HTTP 400, `-32602`, names missing field) via real router | no |
| MIK-7215.STATELESS.10 | undeclared capability named in the refusal | MET | wired `handlers.rs:689-703` → `-32021` + `requiredCapabilities`; test via real router (`sampling/createMessage` case) | no |

Note: CONTROL/STATELESS group source is `audit-notes/criteria-control-stateless.md`; its own summary tally (MET 12, UNWIRED 1, ABSENT 2) matches the rows above.

