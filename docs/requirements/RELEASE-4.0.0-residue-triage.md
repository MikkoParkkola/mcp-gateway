<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# The residue, triaged

The blocking rows that no named cluster accounts for, derived from the ledger rather
than transcribed from the rollup, and sorted by what each one is waiting on.

## How the population was derived

`python3 scripts/release/count-release-criteria.py --check`, verbatim:

```
Coverage: 146 criteria, 146 rows, 102 met or non-blocking, 44 blocking.
```

Every row in `docs/requirements/RELEASE-4.0.0-criteria-status.md` whose blocking cell
reads `yes` was enumerated, then the seven clusters named in
`docs/requirements/RELEASE-4.0.0-blocking-rollup.md` were subtracted by membership. That
rollup's cluster table is the checked copy: `rollup_membership`
(`scripts/release/count-release-criteria.py:234-244`) derives each cluster's rows from the
ledger and fails the run when a declared count, a listed name, or an unlisted blocking row
disagrees. It is not restated here. The script does not read this file, so a second table
of the same counts would be a copy nothing maintains — the mechanism `24f8b91e` and
`2bf64e6f` removed from the plan and the status document for drifting three times.

What is left after the subtraction is the ten below. The rollup's prose list under *The
residue, one line each* names nine, because `MIK-7214.HEADER.9` was split into `9a` and
`9b` in the ledger and the prose was not resplit with it. The ten below are the ledger's.

## The ten

| criterion | what it requires | current state, with file:line | what is actually missing | class |
|---|---|---|---|---|
| `MIK-7214.HEADER.9a` | outbound modern `_meta` and standard headers emitted only where the peer negotiated a modern era | `build_mcp_headers` (`src/transport/http/mod.rs:534-627`) is the single outbound header builder by its own doc comment and inserts `MCP-Protocol-Version` (`:560`) and `MCP-Session-Id` (`:595`, `:598`) on every outbound request, with no branch on the peer's era | a decision on where a per-backend negotiated era is read at header-build time, and what an outbound `_meta` envelope carries. `docs/design/2026-08-31-discover-outbound-era-probe.md:16-23` places this explicitly OUT of the era-probe increment and names HEADER.9 as its owner | DESIGN |
| `MIK-7214.HEADER.9b` | outbound header values derived from the negotiated envelope, not the legacy handshake version | same builder, same lines; the value written is the handshake constant, and `PROTOCOL_VERSION` / `SUPPORTED_VERSIONS` in `src/protocol/mod.rs` carry no 2026 revision, so no negotiated value exists to derive from | the same decision as `9a` — one mechanism, one design | DESIGN |
| `MIK-6704.IDENT.1a` | authorization MUST derive from the authenticated credential | implemented and consumed: `principal_of` (`src/gateway/auth.rs:38-43`) digests the validated secret, set from the bearer token at `:209`, the API key at `:224`, and the OIDC client identity at `src/key_server/mod.rs:154` | an assertion. `tests/auth_tests.rs` uses `principal` only as `String::new()` (`:166`, `:241`, `:255`, `:268`); the three IDENT.1 tests in `tests/mik_6704_acs.rs` (`:30`, `:46`, `:138`) all prove the negative clause, now scored as `1b` | TEST |
| `MIK-6865.SCHEMA.1c` | tool schemas MUST stay within the revision's `$ref` and composition bounds | the only `$ref` handling in the tree is OpenAPI import (`src/capability/openapi/refs.rs:75`), which resolves references inward; `tests/schema_2020_12_validity.rs` contains no `$ref`, `allOf`, `anyOf` or `oneOf` | an assertion over the emitted surface. Inbound resolution is a plausible reason no `$ref` survives outbound, and a plausible reason is not a verdict | TEST |
| `MIK-7215.CONTROL.3a` | transparency log MUST retain a correlation key across the removal of sessions | `src/gateway/meta_mcp/invoke.rs:1812-1816` reads the `_meta` W3C trace id, falls back to `session_id`, then to a literal placeholder. After this release there is no session, so a caller sending no `_meta` trace id is logged under that placeholder | a decision on what supplies the key when the caller sends none. A per-invocation id is already minted at `src/gateway/meta_mcp/invoke.rs:767` (`trace::generate()`) and that chain does not consult it | DESIGN |
| `MIK-7215.CONTROL.4` | session-lifecycle TTL-reaping owns cleanup previously done by disconnect | `SessionLifecycle::{register,track,reap}` (`src/gateway/session_lifecycle.rs:48`, `:107`, `:124`) is implemented and unit-tested (`tests/mik_7215_controls_acs.rs`, `mod lifecycle`); `rg SessionLifecycle` outside the module returns only doc comments in `src/security/firewall/**`. Nothing constructs, holds or drives it | what calls `reap` and on what clock, and what the TTL is. `docs/design/2026-09-01-residue-four-rows.md:73-121` establishes that ownership is not the blocker and names both questions without answering either | DESIGN |
| `MIK-7246.CONFIRM.2` | gate MUST be reachable through the MRTR path, so a modern client can confirm | the confirmation path is `elicitation/create` over an SSE session (`src/gateway/proxy.rs:213-243`); `src/gateway/destructive_confirmation.rs:83-84` states that this revision deletes sessions, so a modern call has none to elicit over | code, not a ruling. `docs/design/2026-09-01-residue-four-rows.md:127-146` treats "does an equivalent mechanism satisfy this?" as open, but the criterion names the MRTR path in its own text, so the requirement already answered it. Both readings — MRTR carrying `elicitation/create`, or a confirmation shaped for MRTR — are work, and both wait on cluster A. Raised by GPT-5.5 on 2026-09-03 and confirmed against the criterion at `docs/requirements/RELEASE-4.0.0-criteria-status.md:229` | CODE |
| `NFR.SEC.1` | no 3.5.0 control becomes inoperative for a modern caller; each has a refusal test | 15 controls in `docs/requirements/nfr-sec1-control-inventory.md` — 14 enumerated plus a firewall gate the inventory records at `:99-101` as owned by another session and untested; thirteen carry a refusal test. `cargo test --test nfr_sec1_controls` = 10 passed, 0 failed (2026-09-03), covering controls 2, 3, 4, 6, 7, 8, 9, 11 and 13 — row 2 was closed since that inventory was written, by two tests reaching both refusal arms with an empty registry (`tests/nfr_sec1_controls.rs:434`, `:457`) | a test for the firewall gate, which waits on another session's files, and a ruling on row 5. The client circuit breaker refuses on a trip count and has no absent input to remove (`nfr-sec1-control-inventory.md:108`); that reads as N/A under the derivation rule, but reclassifying a row is the operator's call | TEST |
| `NFR.SEC.6` | MIK-7249, MIK-7256, MIK-7262 and MIK-7222 closed in this release | 7222 has `tests/mik_7222_acs.rs`; 7256 is referenced across `src/config/env_overlay.rs` and `src/config_reload/mod.rs`; 7249 is fixed and asserted (`src/config_reload/mod.rs:279`, `:285`, test at `:346`). 7262 is **not** closed: the declaration check at `src/capability/definition/mod.rs:1150` returns the declared value, but two earlier short-circuits return `false` before it is reached — `if !mutating` (`:1129`) and the missing-`properties` `else` arm (`:1132-1139`) | a code fix, not a test. A capability declaring `registers_external_callback: true` that is GET-only, or whose input schema has no `properties` object, is still overruled by inference — which is the defect MIK-7262 names. Raised by GPT-5.5 on 2026-09-03 and confirmed at source | CODE |
| `NFR.PERF.4` | Meta-MCP surface remains 14-16 tools; `server/discover` does not count against it | `benchmarks/public_claims.json:3-6` records `minimum: 14`, `readme_benchmark: 16`, `with_webhook_status: 17`. The 17th is `gateway_webhook_status`, pushed at `src/gateway/meta_mcp_tool_defs.rs:564-566` behind `webhooks_enabled`. Nothing clamps the count | how the 17th stops counting. The operator ruled on 2026-09-02 that the ceiling stands and the requirement is not widened; the mechanism holding it is unchosen | DESIGN |

## Bottom line

| class | rows |
|---|---|
| DESIGN | 5 — `HEADER.9a`, `HEADER.9b`, `CONTROL.3a`, `CONTROL.4`, `NFR.PERF.4` |
| TEST | 3 — `IDENT.1a`, `SCHEMA.1c`, `NFR.SEC.1` |
| CODE | 2 — `NFR.SEC.6`, `CONFIRM.2` |
| DECISION | 0 |
| MEASUREMENT | 0 |
| COVERED | 0 |
| UNKNOWN | 0 |

`CODE` was not in the class set this triage started with, and `NFR.SEC.6` is why it
exists. That row read as a missing test until GPT-5.5 asked whether the fix it cites is
reachable. It is not, on two paths, and a class set with no room for "the fix is
incomplete" would have pushed that answer into `TEST` — wrong in the direction that
closes rows. Adding the class was cheaper than mislabelling the row.

`DECISION` is now empty, and that is the same review's other correction. `CONFIRM.2` was
held open as a question about whether an equivalent mechanism counts; the criterion names
the MRTR path in its own text, so the requirement had already answered it and the row was
never waiting on an operator.

Three rows moved after this table was first written: `NFR.SEC.1`, because its last test
landed mid-triage and `docs/requirements/nfr-sec1-control-inventory.md:107` has not
caught up (that inventory belongs to another increment and is reported, not edited
here); `NFR.SEC.6` and `CONFIRM.2`, because a reviewer's questions survived verification
at source. All three moves are recorded rather than silently restated — a triage whose
rows move without a trace is a snapshot pretending to be a ledger.

No row is `MEASUREMENT`. The only measurement the residue touches is `NFR.PERF.4`'s tool
count, and that number exists — `benchmarks/public_claims.json:3-6` records it. What is
missing there is the mechanism that holds it, not the count.

No row is `COVERED`. `docs/design/2026-09-01-residue-four-rows.md` covers four of these
rows analytically and is cited above for each, but it makes no decision for `CONTROL.4`:
it establishes that the decision has no owner and stops, which is why that row is
`DESIGN` and not `COVERED`. Its own scope line says it addresses four of a five-row
residue; the residue is ten, and the six rows it does not reach are listed above.

The three designs this triage calls for are `HEADER.9a`+`9b` (one mechanism, one design),
`CONTROL.3a`+`CONTROL.4` (both blocked on what identifies a caller once sessions are
gone), and `NFR.PERF.4` (unrelated to either). Of the three, two are now written:
`docs/design/2026-09-03-post-session-caller-identity.md` and
`docs/design/2026-09-02-perf4-meta-tool-ceiling.md`. `HEADER.9a`+`9b` has none.

Pairing `CONTROL.3a` with `CONTROL.4` drew a review objection worth recording: 3a has a
per-invocation id already in the tree, so the two rows are not one problem. The design
agrees and answers them with **different** keys — per-invocation for the log, per-principal
for the reaper. They travel together because they were blocked on the same unmade choice,
not because they share an answer, and the design that separates them is the artifact that
proves the pairing was worth making once.

## What the `HEADER.9a`/`9b` design will need

Pinned at source on 2026-09-03 so the next increment starts from facts rather than
re-deriving them. Not a design — a design makes a decision, and none is made here.

| fact | where |
|---|---|
| one outbound header builder, by its own doc comment | `build_mcp_headers`, `src/transport/http/mod.rs:534`; version inserted at `:560`, `MCP-Session-Id` at `:595` and `:598`, all unconditional (re-verified at source 2026-09-03, and the row at `:41` corrected to match: the anchors this file and the probe design carried, `:570`/`:605`, had drifted by ten lines — read the symbol, not the line) |
| the value it writes comes from the legacy handshake | `protocol_version: RwLock<Option<String>>` at `:200`, written at `:469` from `negotiate_protocol_version` (`:644`), read at `:539-543` defaulting to `PROTOCOL_VERSION` |
| its only external callers are tests | `src/transport/http/tests.rs:382, 423, 456, 487, 512, 529, 621, 635, 646` |
| era classification has landed and is per-backend | `Era::{Modern, Legacy}` at `src/protocol/era.rs:22-26`, `classify` at `:61` ("Modern requires positive evidence", `:57`), `EraCache` at `:115` with `cached()` at `:130` returning `Option<Era>`; `Backend::cached_era` at `src/backend/era.rs:61`, resolved on the start path at `src/backend/lifecycle.rs:232`, field at `src/backend/mod.rs:58` |
| a modern revision constant exists in production, not only in tests | `MODERN_VERSIONS = ["2026-07-28"]` at `src/protocol/meta.rs:216`, with `declares_modern_era` at `:206` deliberately broader (any `2026-` prefix, `:202-207`) |
| the inbound path already negotiates against it | `src/gateway/router/handlers.rs:175`, `:219`, `:572`, `:702` — so a negotiated modern value exists; the outbound builder simply cannot see it |
| 2026-07-28 is deliberately absent from the handshake list | `SUPPORTED_VERSIONS` at `src/protocol/mod.rs:48` excludes it, pinned by the test at `:80`; `docs/design/2026-08-31-discover-outbound-era-probe.md` (rev 6) states it never joins that list and puts `HEADER.9` explicitly OUT |

Leading option, unreviewed: share the same `Arc<EraCache>` down into `HttpTransport` so
`build_mcp_headers` can read `cached()` and shape the request, with `None` meaning legacy
— which matches `classify`'s positive-evidence rule rather than fighting it. Alternatives
are threading an era argument through every call site, or moving header construction up
to `Backend`.

One sub-question is open and is spec-checkable, not askable: for a Modern peer, is
`MCP-Protocol-Version: 2026-07-28` emitted or is the header omitted? `MCP-Session-Id`
must not be sent to a Modern peer either way. **Deferred, not assumed** — the probe design was read for it and does not settle it: it fixes only that the legacy handshake runs regardless and permanently, because `SUPPORTED_VERSIONS` will never carry a 2026 revision (`docs/design/2026-08-31-discover-outbound-era-probe.md:145-147`), which constrains the handshake channel and says nothing about what a modern-shaped request emits.


| deferred field | value |
|---|---|
| owner | the `HEADER.9a`/`9b` design increment — this is the decision that design exists to make, not a blocker on starting it |
| what would resolve it | read the 2026-07-28 revision text on whether a modern request carries `MCP-Protocol-Version`; it is not in this tree, so the check is a fetch, not a `rg` |
| when | at design time, before any header-shaping code is written |
| what if it resolves badly | revision unobtainable → emit `2026-07-28` (the truthful value for a request the gateway shaped as modern), record it as an assumption, and pin it with a test so a later reading of the spec fails loudly instead of silently disagreeing |
