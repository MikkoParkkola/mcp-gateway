<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# The residue, triaged

The blocking rows that no named cluster accounts for, derived from the ledger rather
than transcribed from the rollup, and sorted by what each one is waiting on.

## How the population was derived

`python3 scripts/release/count-release-criteria.py --check`, verbatim (re-run 2026-09-06,
after `GH475.OBS.1` landed the same day):

```
Coverage: 146 criteria, 182 rows, 154 met or non-blocking, 28 blocking.
```

The line this document carried earlier the same day — `146 criteria, 182 rows, 147 met or
non-blocking, 35 blocking` — was already stale when it was pasted: `GH475.OBS.2` and
`GH475.MIG.3` had landed as MET rows in `RELEASE-4.0.0-criteria-status.md` (commits `a8b1158f`
03:24:22 and `82d8490b` 03:12:56, both 2026-09-06) and the doc-sync commit `78bd401a` (05:11:55
the same day) flipped their `criteria-status.md` rows without recomputing this document's own
headline or `RELEASE-4.0.0-blocking-rollup.md` row H, which still declared cluster H at `5` rows
against an actual `3` (`RL.9`, `RL.10`, `OBS.1`) at that point — itself a transient count, since
this same pass also lands `GH475.RL.9` (see below), which dropped row H to `2`
(`RL.10`, `OBS.1`) at that point; the `3` describes the moment right after `78bd401a`, not the
state this pass leaves behind. `GH475.MIG.2` is NOT
part of this drift and never was: it was already MET (`version-coupled`), blocking `no`, before
`78bd401a` — confirmed at `78bd401a^` and five commits further back — and was never a member of
cluster H (`git show HEAD:RELEASE-4.0.0-blocking-rollup.md` names no `MIG.2`); `98bef5d1` the
same day only tightened its test assertion to the literal `4.0.0` and did not touch its blocking
status. An earlier draft of this paragraph named `GH475.MIG.2` as a third flip; it was not one —
only two rows changed status that day (`OBS.2`, `MIG.3`), `147 + 2 = 149`, which is the count
`--check` reports against a clean `HEAD` taken with this session's own edits set aside (verified
by temporary `git stash`, restored after). `GH475.RL.9` landing the same day
(`tests/gh475_rl9_429_only_neither_opens_circuit_nor_exhausts_budget.rs`, GH #481) closed a third
row, bringing the headline to `150`/`32`. The line before that — `146 criteria, 146 rows, 102 met
or non-blocking, 44 blocking` — was a transcript of the run made when the document was written,
not a broken gate: the check passes today, and the ledger has grown sub-rows and closed criteria
since. A pasted count is a measurement with a date on it, so this one now carries its date.
`GH475.OBS.1` closed a fourth row the same day (`5e0a8da2`, the trio scoped by the `0961b990`
ruling), which is what moves the headline from `150`/`32` to `151`/`31` above — cluster H's own
`rows` cell drops from `2` to `1` (`RL.10` alone), not the residue count below, since `OBS.1` was
never one of the ten residue rows this section triages.

Every row in `docs/requirements/RELEASE-4.0.0-criteria-status.md` whose blocking cell
reads `yes` was enumerated, then the seven clusters named in
`docs/requirements/RELEASE-4.0.0-blocking-rollup.md` were subtracted by membership. That
rollup's cluster table is the checked copy: `rollup_membership`
(`scripts/release/count-release-criteria.py:234-244`) derives each cluster's rows from the
ledger and fails the run when a declared count, a listed name, or an unlisted blocking row
disagrees. It is not restated here. The script does not read this file, so a second table
of the same counts would be a copy nothing maintains — the mechanism `24f8b91e` and
`2bf64e6f` removed from the plan and the status document for drifting three times.

What is left after the subtraction was the ten below until 2026-09-06, when two rows
flipped to non-blocking in the ledger the same day, for unrelated reasons, and dropped
the count to eight: `MIK-6704.IDENT.1a` (its own three tests now prove the assertion
directly, see `RELEASE-4.0.0-criteria-status.md:152`) and `NFR.SEC.6` (see the bottom
line, below). The rollup's prose list under *The residue, one line each* named nine
until 2026-09-06, because `MIK-7214.HEADER.9` was split into `9a` and `9b` in the ledger
and neither the cluster row nor the prose was resplit with it — that split moved this
document's own count from nine to ten, only for the same day's two closures to move it
to eight. Both now carry the ledger's eight names. The eight below are the ledger's.

## The eight

| criterion | what it requires | current state, with file:line | what is actually missing | class |
|---|---|---|---|---|
| `MIK-7214.HEADER.9a` | outbound modern `_meta` and standard headers emitted only where the peer negotiated a modern era | `build_mcp_headers` (`src/transport/http/mod.rs:534-627`) is the single outbound header builder by its own doc comment and inserts `MCP-Protocol-Version` (`:560`) and `MCP-Session-Id` (`:595`, `:598`) on every outbound request, with no branch on the peer's era | a decision on where a per-backend negotiated era is read at header-build time, and what an outbound `_meta` envelope carries. `docs/design/2026-08-31-discover-outbound-era-probe.md:16-23` places this explicitly OUT of the era-probe increment and names HEADER.9 as its owner | DESIGN |
| `MIK-7214.HEADER.9b` | outbound header values derived from the negotiated envelope, not the legacy handshake version | same builder, same lines; the value written is the handshake constant, and `PROTOCOL_VERSION` / `SUPPORTED_VERSIONS` in `src/protocol/mod.rs` carry no 2026 revision, so no negotiated value exists to derive from | the same decision as `9a` — one mechanism, one design | DESIGN |
| `MIK-6865.SCHEMA.1c` | tool schemas MUST stay within the revision's `$ref` and composition bounds | the only `$ref` handling in the tree is OpenAPI import (`src/capability/openapi/refs.rs:75`), which resolves references inward; `tests/schema_2020_12_validity.rs` now walks every published `$ref` — both schema fields of all 19 Meta-MCP tool definitions, asserted by set equality rather than a floor, and every capability in the PUBLIC catalogue (`capabilities/`; private ones live in `mcp-gateway-private` and are out of this tree's reach) — and finds none, which is a measured fact rather than the plausible reason recorded here (commit `ec9c0d9a`, plan row P12a). Composition is now walked too, over the same two populations, and finds none; each row was probed on its own population — a hand-edited `allOf` in a Meta-MCP definition and one in a capability YAML each fail their own assertion, and meta-validation stays green under both. What the walks cannot reach is a schema the gateway did not write: `Backend::get_cached_tool` (`src/gateway/meta_mcp/surfaced.rs`) hands a connected server's `Tool` to the same projection, which serializes it verbatim | **the first-party half**: resolution and composition are both observed on the schemas this tree writes. Two things remain, and neither is a check: U9 (plan row P12b) — what the revision's bounds actually are — and whether they bind schemas the gateway only forwards | TEST |
| `MIK-7215.CONTROL.3a` | transparency log MUST retain a correlation key across the removal of sessions | `src/gateway/meta_mcp/invoke.rs:1812-1816` reads the `_meta` W3C trace id, falls back to `session_id`, then to a literal placeholder. After this release there is no session, so a caller sending no `_meta` trace id is logged under that placeholder | a decision on what supplies the key when the caller sends none. A per-invocation id is already minted at `src/gateway/meta_mcp/invoke.rs:767` (`trace::generate()`) and that chain does not consult it | DESIGN |
| `MIK-7215.CONTROL.4` | session-lifecycle TTL-reaping owns cleanup previously done by disconnect | `SessionLifecycle::{register,track,reap}` (`src/gateway/session_lifecycle.rs:48`, `:107`, `:124`) is implemented and unit-tested (`tests/mik_7215_controls_acs.rs`, `mod lifecycle`); `rg SessionLifecycle` outside the module returns only doc comments in `src/security/firewall/**`. Nothing constructs, holds or drives it | what calls `reap` and on what clock, and what the TTL is. `docs/design/2026-09-01-residue-four-rows.md:73-121` establishes that ownership is not the blocker and names both questions without answering either | DESIGN |
| `MIK-7246.CONFIRM.2` | gate MUST be reachable through the MRTR path, so a modern client can confirm | the confirmation path is `elicitation/create` over an SSE session (`src/gateway/proxy.rs:213-243`); `src/gateway/destructive_confirmation.rs:83-84` states that this revision deletes sessions, so a modern call has none to elicit over | code, not a ruling. `docs/design/2026-09-01-residue-four-rows.md:127-146` treats "does an equivalent mechanism satisfy this?" as open, but the criterion names the MRTR path in its own text, so the requirement already answered it. Both readings — MRTR carrying `elicitation/create`, or a confirmation shaped for MRTR — are work, and both wait on cluster A. Raised by GPT-5.5 on 2026-09-03 and confirmed against the criterion at `docs/requirements/RELEASE-4.0.0-criteria-status.md:229` | CODE |
| `NFR.SEC.1` | no 3.5.0 control becomes inoperative for a modern caller; each has a refusal test | 15 controls in `docs/requirements/nfr-sec1-control-inventory.md` — 14 enumerated plus a firewall gate the inventory records at `:99-101` as owned by another session and untested; thirteen carry a refusal test. `cargo test --test nfr_sec1_controls` = 10 passed, 0 failed (2026-09-03), covering controls 2, 3, 4, 6, 7, 8, 9, 11 and 13 — row 2 was closed since that inventory was written, by two tests reaching both refusal arms with an empty registry (`tests/nfr_sec1_controls.rs:434`, `:457`) | a test for the firewall gate, which waits on another session's files, and a ruling on row 5. The client circuit breaker refuses on a trip count and has no absent input to remove (`nfr-sec1-control-inventory.md:108`); that reads as N/A under the derivation rule, but reclassifying a row is the operator's call | TEST |
| `NFR.PERF.4` | Meta-MCP surface remains 14-16 tools; `server/discover` does not count against it | `benchmarks/public_claims.json:3-6` records `minimum: 14`, `readme_benchmark: 16`, `with_webhook_status: 17`. The 17th is `gateway_webhook_status`, pushed at `src/gateway/meta_mcp_tool_defs.rs:564-566` behind `webhooks_enabled`. Nothing clamps the count | how the 17th stops counting. The operator ruled on 2026-09-02 that the ceiling stands and the requirement is not widened; the mechanism holding it is unchosen | DESIGN |

## Bottom line

| class | rows |
|---|---|
| DESIGN | 5 — `HEADER.9a`, `HEADER.9b`, `CONTROL.3a`, `CONTROL.4`, `NFR.PERF.4` |
| TEST | 2 — `SCHEMA.1c`, `NFR.SEC.1` (`IDENT.1a` and `NFR.SEC.6` both left this bucket 2026-09-06: tested, met, no longer blocking) |
| CODE | 1 — `CONFIRM.2` (`NFR.SEC.6` left this bucket 2026-09-06: all four tickets closed in code, one test composition outstanding) |
| DECISION | 0 |
| MEASUREMENT | 0 |
| COVERED | 0 |
| UNKNOWN | 0 |

`CODE` was not in the class set this triage started with. `NFR.SEC.6` is why it was
added and no longer why it is kept: on 2026-09-06 that row was mutation-probed and the
fix IS reachable — `creates_caller_addressed_external_state` returns the declared value
above every inference, and `invoke.rs:927-938` refuses a non-admin caller on it. The row
moved back to `TEST`, where one missing composition is the whole of what is outstanding.
`CONFIRM.2` is now the only `CODE` row.

The class stays anyway, and the reason is worth keeping: a class set with no room for
"the fix is incomplete" pushes that answer into `TEST`, which is wrong in the direction
that CLOSES rows. It was right to add and it was right to leave this row in it until
somebody actually ran the probe.

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
`docs/design/2026-09-02-perf4-meta-tool-ceiling.md`. The third is now written too:
`docs/design/2026-09-03-header-9-era-conditional-outbound.md`.

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

Settled, reviewed: `docs/design/2026-09-03-header-9-era-conditional-outbound.md` shares the
same `Arc<EraCache>` down into `HttpTransport`, but the era is read at the two body-assembly
sites (`request_with_headers`, `notify_with_headers`) and passed *into* `build_mcp_headers`
rather than read there — which keeps the handshake and the era probe on today's shape. `None`
means legacy, matching `classify`'s positive-evidence rule. The rejected alternatives were
threading an era argument through every call site, and moving header construction up to
`Backend`; both are recorded there with their reasons.

One sub-question was open: for a Modern peer, is `MCP-Protocol-Version: 2026-07-28` emitted
or is the header omitted? `MCP-Session-Id` must not be sent to a Modern peer either way.
Recorded here as deferred, on the reading that only the external revision text could settle
it. **RESOLVED 2026-09-03, and not by that route** — the answer was already in this tree, in
the gateway's own inbound path, and the deferral's fallback ("revision unobtainable → emit
and pin it as an assumption") turned out to reach the right answer for the wrong reason. It
is a fact now, not an assumption.

| checkable | |
|---|---|
| question | for a Modern peer, is `MCP-Protocol-Version` emitted or omitted? |
| what was read | `src/protocol/meta.rs:99-104` (the doc comment on `classify_request`) and `src/gateway/router/handlers.rs:552-568` |
| what came back | the revision uses **mirrored headers**. `classify_request` reads body *and* header "because a request that declares itself modern in one and says nothing in the other is the exact split this revision's mirrored headers exist to close" (`meta.rs:99-104`), and the router "refuses a modern request that omits `MCP-Protocol-Version`, so every modern request that survives carries it" (`handlers.rs:555-556`) |
| what it changed | removed the omit option outright. Omitting it outbound would have the gateway send modern requests its own inbound path refuses — an asymmetry with a citation, not a preference. The emitted value is `MODERN_VERSIONS[0]` (`src/protocol/meta.rs:216`), a constant, which is also what satisfies `HEADER.9b`'s "not derived from the legacy handshake version" |

Confirmed by the team lead 2026-09-03, who re-read both anchors at source before answering.
The question had been routed as askable because no rule deciding it had been found; finding
the rule moved it to checkable. Which form applies turns on whether the answer depends on
what the product should *do* or on what the system already *requires* — this is the second.

Design: `docs/design/2026-09-03-header-9-era-conditional-outbound.md`.
