<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# 4.0.0 release: which In Progress/Blocked tickets are actually close to done

Read-only triage. Every verdict below is from reading source at the cited file:line, not from
ticket comments. Ticket comments claiming "implemented, suite green" were treated as claims to
verify, not facts — several did not survive contact with the source (see MIK-7212, MIK-7213,
MIK-7217, MIK-7116).

State check against Linear: all 12 tickets are **In Progress** except **MIK-7265, which is
Blocked** — the team-lead's framing assumed all 12 were In Progress/In Review; that's wrong for
one of them.

## Summary — closest to done first

| ticket | ACs met/total | what remains (one line) | size |
|---|---|---|---|
| MIK-7320 | 3/3 (1 wording nit) | Evidence comment + merge PR #464; code is green | XS |
| MIK-7272 | 4/4 | Nothing but merging the branch | XS |
| MIK-7256 | 0 FAIL / 9 PASS / 6 PARTIAL / 11 NO TEST of 26 | Mechanism fully built; 17 ACs lack a verifying test — operator must decide write-tests vs accept-residual | M |
| MIK-7265 | Blocked correctly | Drift-check script (its own deliverable) unbuilt; guard code it depends on predates the ticket | S |
| MIK-7246 | 2/4 | Delete hardcoded tool-name match arm, wire the annotations-based gate that already exists but has zero callers, add an e2e test | S |
| MIK-7214 | 3/6 | No outbound 2026 headers, no header-based routing, no x-mcp-header decision | M |
| MIK-7215 | ~2.5/7 | Firewall budgets don't exist in code; SessionLifecycle module unwired; 2 of 6 named features and all 5 reviewer categories missing from the inventory | L |
| MIK-7213 | 2/8 | Decision table doesn't exist; cache key has 2 of 8 required dimensions; tools/list ordering fn has zero callers; no hit-rate measurement | L |
| MIK-7217 | 1/8 | The probe repair — the entire point of the ticket — is unbuilt; health check still pings unconditionally | L |
| MIK-7212 | ~0-1/9 | Mint/verify mechanism built and unit-tested but zero production callers; RFC contract literally says "not written yet"; destructive-confirmation path untouched | L |
| MIK-7116 | 0/6 | Nothing exists — no tenant attribution, no summarizing wrapper, no question-validation model | L (unstarted) |
| MIK-6865 | 0/4 | Deliberately deferred past this release per `RELEASE-4.0.0-backlog-triage.md:102` | N/A (parked) |

## Per-ticket detail

### MIK-7320 — golden fixture, `cargo test --all-features` — 3/3, XS remainder

- FIXTURE.1 MET — `cargo test --all-features --test mik_7217_acs` run live: 22 passed, 0 failed.
- FIXTURE.2 PARTIAL — fixtures captured (`tests/fixtures/mik_7217/initialize_3_5_0_{2025_06_18,2025_11_25}_spec_preview.json`, commit `e6e2ddd9`); rationale for why the tree qualifies is recorded but lives in `docs/requirements/RELEASE-4.0.0-dod-check.md:62-74`, not the commit body the AC's literal wording asks for — wording nit, not a substance gap.
- FIXTURE.3 MET — full `cargo test --all-features --no-fail-fast` run live: 0 failed across 4619+ tests plus doctests.
- Branch is 311 commits ahead of main; PR #464 open, covers the whole 4.0.0 protocol revision. A stale 2026-08-30 Linear comment claiming "no branch, no PR, no commit exists" is now false.
- Remainder: evidence comment on the ticket + merging the PR. Nothing left at code level.

### MIK-7272 — spec-decision documentation — 4/4, XS remainder

- SPEC.1 MET — `src/config/mod.rs:1113-1127` doc comment records the decision (`modern_protocol` off by default, one switch to flip).
- SPEC.2 MET — `server/discover` handler `src/gateway/router/handlers.rs:822-828`, dispatch `src/gateway/server/mod.rs:1683`, test `ac_discover_1_stdio_dispatch_answers_server_discover` (`server/mod.rs:2358-2371`).
- SPEC.3 MET — `handlers.rs:1289-1292`: modern path drops `Mcp-Session-Id`, legacy path keeps it, justified in comment.
- SPEC.4 MET — `docs/design/RFC-0061-protocol-2026-07-28-release-scope.md:49,58,344` records the design review and fix (shared list cache keyed on projection input) for the `src/projection/role.rs` divergence.
- Remainder: none at code level. Only gap is the branch being unmerged.

### MIK-7256 — env-files must not leak into process env on a failed reload — 0 FAIL, test-coverage gap, M

Two conflicting Linear comments exist (an early "closed as documented residual" and a later
"redesign in flight"). Source shows the redesign **landed**: `rg -n "from_path_override" src/`
and `rg -n "set_var" src/` both return **zero matches** — the crate denies `unsafe`
(`src/lib.rs:25`), so a live reload literally cannot mutate the process environment anymore.
Replacement mechanism: `EnvOverlay` (`src/config/env_overlay.rs`), consumed by
`Config::load_with_overlay` and `load_config_patch` (`src/config_reload/mod.rs:1252-1272`).

The ticket's own scored verdict table (`docs/design/mik-7256-ac-verdicts.md`, commit `30b462a8`)
is the most honest artifact in this whole sweep — it states plainly: **"this change does not pass
DoD §1. Of 26 acceptance criteria, 9 are verified by a test, 6 are partly verified, and 11 have no
verifying test. None is unimplemented."** 0 FAIL means the mechanism is real everywhere; the gap
is proving it, not building it.
- Remainder: 11 ACs with no test, 6 partial — operator decides write-tests vs accept-residual (the doc frames this explicitly as a scope decision, not an engineering one).

### MIK-7265 — DNS-rebinding guard drift check — Blocked status is correct, S remainder

- Origin guard code (`src/gateway/router/origin_guard.rs`, wired at `router/mod.rs:209,306`) already exists and predates this ticket — not this ticket's code to write.
- GW.1/GW.2 (reinstall + re-probe) are deployment actions, not repo work.
- DRIFT.1/DRIFT.2 (merged-vs-installed drift-check script + wiring): zero hits anywhere in the tree for any such script (`fd`/`rg` for drift/is_ancestor/installed-commit patterns all empty).
- Remainder: the drift-check script itself (~2-4h per the ticket's own estimate) plus an ops/deploy action no source file can settle. Blocked label is accurate, not stale.

### MIK-7246 — destructive-op confirmation, header-scoped — 2/4, S remainder

- CONF.1 MET — `src/gateway/destructive_confirmation.rs:5-18` doc comment: explicit "courtesy, not a security control" decision, with rationale (avoids an over-trust framing under OWASP's agentic-AI top 10 — the security checklist this repo tracks).
- CONF.2 MET — `ConfirmationPolicy` (`destructive_confirmation.rs:73-108`, `for_modern()`=REFUSE, `for_legacy()`=PROCEED_WITH_WARNING) is consulted and enforced at `handlers.rs:1050-1071` — real `-32001` refusal on the modern path, unchanged pass-through on legacy.
- CONF.3 NOT MET — `destructive_tools_from_annotations` (`destructive_confirmation.rs:117-138`) has **zero production callers** (only its own definition and a doc-comment mention). The live gate at `handlers.rs:1024` still uses the hardcoded match arm `matches!(tool_name, "gateway_kill_server")` (`destructive_confirmation.rs:148-150`) — exactly the thing this AC exists to eliminate.
- CONF.4 NOT MET — no test exercises the `handlers.rs` refusal path end-to-end; the module's own tests (`:245-349`) only unit-test helpers in isolation.
- Remainder: delete the hardcoded match arm, wire `destructive_tools_from_annotations` into the live gate, add one e2e test.

### MIK-7214 — 2026 protocol header contract — 3/6, M remainder

- HDR.1 MET — `src/protocol/headers.rs:102-205` (`HeaderCheck`), wired at `handlers.rs:683` (returns error code -32020 on mismatch), gated to `RequestShape::Modern` (`handlers.rs:601`).
- HDR.2 NOT MET — zero hits for `Mcp-Method`/`Mcp-Name` in `src/backend/` or `src/transport/`. No outbound header emission to 2026-era backends.
- HDR.3 NOT MET — dispatch still keys off the JSON-RPC body's `method` field; the header is only compared for mismatch, never used to route. No documented list of body-dependent routes.
- HDR.4 NOT MET — zero hits for `x-mcp-header` anywhere. No support built, no recorded decision to decline it.
- HDR.5 MET — `RFC-0061-protocol-2026-07-28-release-scope.md:99,113,116,362` records this concern (labelled U5) closed "for routing, not for authorization."
- HDR.6 MET (inferred, not directly tested) — the header-validate block only fires inside `RequestShape::Modern`, so the legacy path is structurally untouched; full suite green corroborates but no test targets this specifically.
- Remainder: outbound header emission, header-based routing, and an explicit x-mcp-header decision — three separate small builds, not one.

### MIK-7215 — session-keyed inventory + stateless controls — ~2.5/7, L remainder

Cross-cutting problem first: none of this ticket's literal AC IDs match what's actually written
into the codebase's own audit docs (`docs/requirements/audit-notes/criteria-*.md` invented a
parallel `CONTROL.*`/`STATELESS.*` numbering that doesn't line up 1:1 with the ticket's real
criterion text). Verdicts below are against the ticket's own literal AC wording, not that doc.

- SESSION.1 MET — a 12-row inventory table exists, `docs/design/RFC-0061-protocol-2026-07-28-release-scope.md:280-293`, sourced from a real `session_id` grep sweep, every row's replacement populated.
- SESSION.2 PARTIAL FAIL — of six *named* gateway features the AC lists, only 4 appear as rows. **"session sandbox" and "last-event-id resume" have zero mentions anywhere in the inventory** (`rg -n "sandbox|last.event.id"` = 0 hits), and `src/session_sandbox.rs` — the file the ticket names by filename — is never referenced in it at all.
- SESSION.3 FAIL, wholesale — zero matches for any of the five reviewer categories the AC names (auth/token binding, subscriptions, progress, cancellation, backend affinity) anywhere in the inventory section.
- SESSION.4 MET for the 12 rows that exist, moot for the 7 missing rows from .2/.3.
- SESSION.5 FAIL — no test exists, and can't meaningfully exist yet: firewall budgets are **absent from the code** (`rg -ni budget src/security/firewall/mod.rs` = 0 hits; the only `budget.rs` hit is unrelated, keyed on backend not principal), and `SessionLifecycle` (`src/gateway/session_lifecycle.rs`) is a real, unit-tested type with **zero production callers** — only aspirational comments point at it ("Register this via `SessionLifecycle::register`").
- SESSION.6 MET — `tests/mik_7215_acs.rs` `ac_stateless_3_a_modern_response_carries_no_session_header`, run against the real router.
- SESSION.7 FAIL as literally worded — the table lives in RFC-0061, not RFC-0060 as the AC names.
- Remainder: build firewall budgets, wire `SessionLifecycle`, and extend the inventory to cover its own 2 missing named items plus all 5 reviewer categories.

### MIK-7213 — cacheScope decision table + cache-key hardening — 2/8, L remainder

- CACHE.1 FAIL — the decision table (naming which endpoints may be cached publicly) doesn't exist; `src/protocol/cacheable.rs:60-62`'s own doc comment admits it.
- CACHE.2 MET — `handlers.rs:1300-1306` `CACHEABLE_METHODS` = exactly the 5 named endpoints, fields inserted at `:1334-1344`, gated behind `is_modern`.
- CACHE.3 FAIL — the cache key (`src/cache.rs:205-213`, `server:tool:args_hash` plus two *optional* suffixes) has 2 of the 8 required dimensions; no `policy_epoch`/`routing_profile`/`protocolVersion` anywhere near it.
- CACHE.4 FAIL — `CacheScope` (`cacheable.rs:22-28`) is a bare enum with no type/lint linkage stopping misattachment to a scoped assembly.
- CACHE.5 FAIL as wired — `stable_tool_order()` exists (`src/gateway/meta_mcp/prompt_cache.rs:162`) with **zero production callers** (only its own unit tests); `handle_tools_list*` never calls it.
- CACHE.6 FAIL — no hit-rate measurement anywhere.
- CACHE.7 FAIL for this change specifically — only generic pre-existing tests, none tied to this AC.
- CACHE.8 MET structurally — `build_modern_response` (which adds the cache fields) is only reached when `is_modern`; legacy path is untouched, corroborated by `tests/mik_7213_acs.rs:238-250`.
- Remainder: the decision table, 6 missing cache-key dimensions, wiring `stable_tool_order()` in, and a hit-rate measurement — the hard requirements are essentially all undone; only the field-plumbing (2/8) landed.

### MIK-7217 — outbound era-negotiation probe repair — 1/8, L remainder

Don't trust the "in progress" momentum on this one — the probe repair, which is the entire point
of the ticket, is unbuilt.

- DISCOVER.1 MET — same evidence as MIK-7272's SPEC.2 (`server/discover` handler).
- DISCOVER.2 NOT MET / out of this repo's scope — points at hebb/nab/metacognition/throttla, separate repos untouched here.
- DISCOVER.3 NOT MET — both `server/discover` tests assert only "supportedVersions is present," neither asserts the exact version list the AC requires.
- DISCOVER.4 NOT MET — `src/backend/lifecycle.rs:997-1034` `health_probe` still calls `transport.request("ping", ...)` unconditionally; no `server/discover`-based probe, no era branch, no fallback exists.
- DISCOVER.5 NOT MET — same evidence: `ping` is sent unconditionally on every connection, 2026-era backend or not.
- DISCOVER.6 NOT MET — no test links a 2026 backend, tool-search visibility, and circuit-breaker state.
- DISCOVER.7 UNCLEAR — no regression evidence either way, moot while the probe repair doesn't exist.
- DISCOVER.8 NOT MET — `benchmarks/public_claims.json` still declares `gateway_tools: 16` with no CI check tying it to this ticket's change.
- Remainder: the actual probe repair (era-aware handshake replacing the unconditional ping) plus version-list assertions and a CI tie-in — this is a build, not a wiring fix.

### MIK-7212 — MRTR (modern retry) proxy contract — ~0-1/9, L remainder

The "implemented, suite green" comment on this ticket is false at source.

- MRTR.1 (probe run+posted) FAIL — no probe result exists anywhere in the tree.
- MRTR.2/3 (written proxy contract) FAIL — `RFC-0060-dual-generation-mcp.md:155` says outright, in its own words, "No contract is written yet."
- MRTR.4 (stop discarding unknown params) FAIL — `src/gateway/router/helpers.rs:185` `extract_tools_call_params` still returns only `(name, arguments)`, unchanged.
- MRTR.5 (destructive confirmation rewritten for the new response shape) FAIL — `src/gateway/destructive_confirmation.rs:160-171` still takes the old `session_id: &str` and calls the old forwarding path, untouched.
- MRTR.6 (end-to-end test, both directions) FAIL — no such test exists.
- MRTR.7/8 (`requestState` sealed/verified, tamper test) mechanism **exists and is unit-tested** (`src/protocol/continuation.rs` mint/open, consume-once ledger) but has **zero production call sites** — the state object it lives on is built at `src/gateway/server/mod.rs:1171` but never read outside tests. Unwired, not done.
- MRTR.9 FAIL — not written into the RFC.
- Real forward progress, credited: `handlers.rs:867-896` now returns an honest -32602 error ("retry forwarding is not available on this build") instead of silently corrupting a call — a correctness fix, not a closed AC.
- Remainder: essentially the whole ticket — write the proxy contract, wire the mint/verify mechanism into the live retry path, fix the four dead-code call sites above.

### MIK-7116 — tenant-mixing / question-validation guard — 0/6, unstarted

Nothing has landed since the ticket's own 2026-08-30 "not closeable" comment.
`rg -i 'tenant_attribution|TenantAttribution|cross_tenant_guard|summariz.*wrapper|question.validation'`
across `src/` returns **zero hits** outside an unrelated connection-pool file. No summarizing
wrapper, no question-validation model, no observe-only measurement gate exists anywhere.
- Remainder: everything — this is a from-scratch build, not a wiring fix. Size L, possibly bigger once scoped.

### MIK-6865 — schema hardening probe — 0/4, deliberately deferred

Zero hits repo-wide for `probe/`, `nested-schema-rate.json`, `schema-shape-audit.json`,
`test_repair.py`, or any `MCPGW.SCHEMA` string. `docs/requirements/RELEASE-4.0.0-backlog-triage.md:102`
explicitly lists this ticket under "tool surface" as **deferred backlog for this release**. This
isn't in-flight on this branch — it's parked by the release's own triage doc, not stalled work.

