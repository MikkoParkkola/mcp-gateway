<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# 4.0.0 release: every blocking acceptance criterion, verified status

Coverage: four criterion groups are recorded here — MRTR, cache and header, control on the
stateless path, and identity. Other groups in the requirements document have not been swept yet,
so the title describes the method rather than the extent. Treat the blocking count as a floor.
Each group's disagreements with earlier documents are logged under `audit-notes/`.

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

