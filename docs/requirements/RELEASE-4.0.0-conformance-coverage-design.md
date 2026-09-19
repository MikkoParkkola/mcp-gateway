# Conformance coverage design — v4.0.0 release blocker (operator decision 19)

**Status**: design only. No test code, no harness change, no commit is part of this
document. It says what must be built, in what order, and what would make each piece
wrong.

**Authority**: `tests/mik_7272_conformance.rs` (1420 lines, self-contained, no crate
deps). Every number below is recomputed from that file, not read out of prose.

- Population generator: `fn cells()` at `tests/mik_7272_conformance.rs:810`
- Row tables: `const MAJOR` at `:239`, `const MINOR` at `:579`, `fn all_rows()` at `:805`
- Classification precedence: `fn every_cell_is_covered_or_exempt()` at `:1113`
- Exemption table: `const EXEMPTIONS` at `:901`
- Gap table: `const TRACKED_GAPS` at `:958`

## 1. The population, and the 202 / 282 discrepancy

Recomputed over `cells()` with the precedence the guard at `:1113` uses
(evidenced > exempt > tracked):

| bucket | cells |
|---|---|
| evidenced | 124 |
| exempt only | 194 |
| **tracked only — no test, no exemption** | **282** |
| tracked *and* exempt | 280 |
| naked (neither) | 0 |
| total | 880 = 22 statements x 2 roles x 2 transports x 5 revisions x 2 outcomes |

Corroborated independently by the body of `fa0af988`: "Every cell is evidenced (124),
exempt with a witness (474) or held by a named tracked gap (282); none is naked."
474 = 194 + 280.

**The discrepancy is not a typo.** No document in the tree states 202; the
decomposition below was reconstructed from the gap table and reproduces it
exactly, and the gap owner strings corroborate the split. The provenance is
reconstructed, not sourced:

```
282  tracked-only cells
- 40  MIK-7272.EXT.1     — owner: "Cluster B writes E1-E5 of
                            docs/design/2026-08-31-cluster-b-capability-and-trace-metadata-test-plan.md"
- 40  MIK-7272.ELICIT.1  — owner: "MIK-7387.STDIO.1-.3 and CONFORM.2 wire the modern
                            MRTR continuation; until the modern arm exists there is
                            nothing to contrast the retained legacy
                            elicitation/create against"
= 202  cells this task can act on
```

Both subtracted rows are owned by work outside this task. The third whole-row gap,
`MIK-7272.STRUCT.1`, is **not** subtracted — its owner string ends "No ac_* test in
this tree names them", i.e. this suite's own debt. So:

- **282** is the honest count of cells with no real test behind them.
- **202** is the count this task is accountable for.

**Both numbers have a shelf life.** They describe the population *before* stage 1
(§8) fixes the classification mechanics. After stage 1 the tracked-only population
is 282 − 35 = **247**, and in-scope test work is 247 − 48 = **199**: the 3 OAuth
stdio cells leave the in-scope set by becoming exemptions rather than tests. Quote
282 / 202 as the pre-stage-1 figures, or the release note drifts silently when
stage 1 lands.

Both belong in the release note. Reporting either alone misleads: 202 hides two
unowned rows behind someone else's ticket, 282 implies this task can close cells
that are blocked on Cluster B and on an unwired product path.

## 2. The real work currency: 117 intents, not 282 cells

The revision axis has 5 values (`MODERN` at `:68` plus four in `LEGACY` at `:71`), but
`Evidence.revisions` is the 3-valued `enum Revisions { Modern, AnyLegacy, Both }` at
`:90`. One `AnyLegacy` citation closes all four legacy cells at once. Collapsing the
282 on (statement x role x transport x era-class x outcome) gives **117 distinct test
intents**. Legacy inflates 4x; that is an artefact of cell counting, not of work.

Plan and report in intents. Cell counts are the release-note currency; intents are the
delivery currency.

## 3. The five axes

Axis spellings and cardinalities, from the authority file: `enum Role { Server, Client }`
at `:34` (2), `enum Transport { Http, Stdio }` at `:51` (2, WebSocket excluded by
ruling D1), `enum Outcome { Positive, Negative }` at `:58` (2), revisions at `:68`/`:71`
union via `fn revisions()` at `:74` (5).

The 282 tracked-only cells split across the five axes as follows. These are
**tracked-only** figures — not the gap table's self-reported `matched` scopes, which
overcount badly (see 4.2).

| axis | split of the 282 | evidenced today |
|---|---|---|
| transport | stdio 158 / http 124 | stdio 38 / http 86 |
| era | legacy 220 / modern 62 | legacy 76 / modern 48 |
| role | client 94 / server 188 | client 42 / server 82 |
| direction | negative 159 / positive 123 | negative 44 / positive 80 |

Per statement (tracked-only): ELICIT.1 40, EXT.1 40, STRUCT.1 40, MRTR.1-.10 28,
DISCOVER.1/.2 28, RESULT.1/.2 19, STATELESS.6/.7 14, STATELESS.3 + ORDER.2 13,
ERROR.1 13, TASK.1 13, ORDER.1 10, STATELESS.1/.2/.8/.9 9, OTEL.1 4, SCHEMA.1 2,
ERROR.2 2, OAUTH.1 2, OAUTH.2 2, OAUTH.3 2, SUB.1/.2 1.

## 4. Findings that constrain the design

Five problems in the existing matrix mechanics. Each changes what a "filled cell"
has to mean, so each is a design input, not a follow-up.

### 4.1 The stdio axis is over-claimed — the honest hole is larger than 158

29 evidence entries claim stdio coverage (`EITHER_TRANSPORT` x29, `STDIO` x1;
`HTTP` x25). **23 of those 29 are defined in files that contain no stdio construct at
all** — no `CARGO_BIN_EXE`, no `tokio::process`, no `ChildStdin`, no `stdio`/`Stdio`
token anywhere in the file.

By file: 4 in `tests/mik_7272_exploit_acs.rs`, 4 in `tests/mik_7212_acs.rs`, 4 in
`tests/mik_7213_acs.rs`, 4 in `tests/mik_7272_oauth_acs.rs`, 3 in
`tests/mik_7215_acs.rs`, 2 in `tests/mik_7272_result_2.rs`, 1 in
`src/gateway/router/tests.rs`, 1 in `tests/mik_7272_subscriptions_acs.rs`.

Worked example: the MRTR row at `:467-477` cites
`mik_7212_acs::retry::ac_mrtr_1_a_retry_carries_its_inputs_and_state` with
`EITHER_TRANSPORT`, and `tests/mik_7212_acs.rs` has zero stdio anywhere in it.

**Claim only the sound half.** "No stdio token in the defining file" is a reliable
negative: the test cannot be driving stdio. The remaining 6 entries whose files *do*
show a stdio token (3 `src/gateway/meta_mcp/tests.rs`, 2 `tests/mik_7217_acs.rs`,
1 `src/gateway/server/mod.rs`) are **not** thereby verified — a bare `Stdio` token can
be `process::Stdio::piped()` in an unrelated helper. They are unresolved, not sound.
Two caveats on the method: file-level granularity (a token elsewhere in the file does
not reach the cited function), and the resolver takes the first tree-wide `fn name(`
match, so attribution is approximate.

Consequence for the plan: the true stdio hole is up to **158 + 38 ≈ 196 cells**, and
`fn every_cited_test_exists()` at `:1350` cannot catch this. That guard concatenates
all `.rs` under `src/` and `tests/`, requires `::` in the cited path, requires the leaf
to start with `ac_`, and then only checks `sources.contains(&format!("fn {function}("))`.
It is a **name-existence** oracle. Nothing in the suite checks that a cited test drives
the axis it is cited for.

### 4.2 Empty axis filters make broad gaps self-perpetuating

`Gap::matches` at `:842` (and `Exemption::matches` likewise) treats an **empty axis
list as "every value"**. Three of eight tracked gaps — EXT.1, ELICIT.1, STRUCT.1 — have
every axis filter empty, so each claims all 40 cells of its row.

`fn a_tracked_gap_is_still_a_gap()` at `:1234` fails only when `matched == 0` or
`evidenced == matched`. A gap spanning 40 cells therefore stays "valid" while a single
cell of its row is unevidenced. Whole categories read as owned for the wrong reason.

Design item: narrow those three to the axes they actually describe, and tighten the
guard so a gap must name at least one axis — mirroring
`fn an_exemption_rule_is_scoped_on_at_least_one_axis()` at `:1175`, which already
imposes exactly this discipline on the exemption side.

### 4.3 280 cells are matched by both a gap and an exemption

`Gap::matches` ignores exemptions entirely, so a gap whose scope is wholly exempt looks
live forever. The stdio gap reports `matched = 320` while only 158 tracked-only stdio
cells exist across all gaps; the legacy gap reports 256 against 220. The gap table's
own numbers cannot be quoted as work.

Design item: subtract exempt cells from `matched` before the `:1234` assertion, or add
a guard refusing a gap whose matched set is entirely exempt. Every figure in this
document already uses tracked-only counts.

### 4.4 Evidence cannot express a partial era — this fork must be decided before any test lands

`Evidence.revisions` is the coarse 3-valued `enum Revisions` at `:90`
(`Modern` / `AnyLegacy` / `Both`). `Gap.revisions` at `:836` and `Exemption.revisions`
are `&[&'static str]` — lists of concrete revision strings. The exemption side can
exempt two of the four legacy revisions; the evidence side cannot cite two of four.

So the moment a row carries a partial-era exemption *and* an `AnyLegacy` citation,
`fn a_cell_carrying_evidence_matches_no_exemption_rule()` at `:1191` fails: the coarse
evidence covers the exempted revisions.

**Decide one, in this document, before the first test:**

- **(A) Fine-grained evidence.** Add a variant to `Revisions` carrying explicit
  revision strings. Declared cost: a harness change to the authority file plus a
  re-audit of all 29 legacy citations, which currently mean "some legacy" and would
  need to state which.
- **(B) Forbid partial-era exemptions on any row that will carry legacy evidence.**
  A row is either wholly exempt for an era or wholly testable in it. No harness change;
  the price is that a genuinely partial introduction cannot be modelled and its
  pre-introduction cells stay gaps.

**Recommendation: (B) for this release, (A) recorded as the follow-up.** (B) keeps the
authority file's semantics frozen while cells are filled, which matters because a
harness change and a coverage change landing together make a red test unattributable.
Nothing in the 202 requires partial-era modelling today.

### 4.5 Reachability: three of the whole-row gaps are not the same kind of thing

Checked against the product tree, because a cell that cannot be reached must not be
planned as a test.

| row | finding | correct disposition |
|---|---|---|
| EXT.1 | `src/protocol/extensions.rs` exists; its doc comment reads ":4 Protocol extensions, declared and negotiated (MCP 2026-07-28)" and ":6 The revision added an `extensions` field to client and server capabilities" | **Reachable, and 32 of its 40 cells are misclassified.** Extensions are a 2026-07-28 addition, so the legacy cells are `REVISION-PREDATES-STATEMENT` exemptions, not gaps. EXT.1 is absent from `const MODERN_INTRODUCTIONS` at `:884`. Witness is in-tree. |
| ELICIT.1 | `notifications/elicitation/complete` appears **nowhere** in `src/` or `tests/` — only in comments at `:786` and `:970` of the authority file | **Product gap, not suite gap.** No test can close the modern arm. The gap entry is the honest artefact, as its own comment argues. Do not plan tests here. |
| STRUCT.1 | `output_schema` appears in 45 `src/` files (`src/protocol/types.rs`, `src/tool_registry.rs`, `src/protocol_imports/*`, `src/validator/rules_schema.rs`, `src/context_compression.rs`, …); `structured_content`/`structuredContent` in `src/protocol/messages.rs`, `src/provider/mod.rs`, `src/capability/backend.rs` | **Reachable, no product fix needed.** This row is real, actionable test debt. |

Also: OAuth over stdio is unreachable — there is no authorization server or redirect
in a stdio session. OAUTH.1 Client/Stdio/MODERN/Positive plus OAUTH.2 and OAUTH.3
Client/Stdio/MODERN/Negative are 3 `TRANSPORT-LACKS-MECHANISM` exemption candidates,
not tests.

The witness form differs by code, and `every_exemption_names_a_known_code_and_a_witness`
at `:1151` only enforces non-emptiness. The existing `TransportLacksMechanism` entry at
`:926-929` spells its witness as the *absence* of the construct ("stdio frames carry no
HTTP headers, no status codes and no GET endpoint…"), not as a file:line. The OAuth
stdio cells may therefore be exempted in that same prose form; `REVISION-PREDATES-STATEMENT`
is the code that does need a concrete file:line, because it asserts a positive fact about
when an obligation appeared.

**The exemption rule that keeps this honest: no in-tree witness, no exemption.** EXT.1
has one (`src/protocol/extensions.rs:4`, naming 2026-07-28) and is therefore
exemptable. STRUCT.1 does **not** — recalled spec history about `structuredContent`
arriving in 2025-06-18 is not a witness, and 16 cells must not be exempted on it. A
witness search is a *prerequisite step* of the revision-era stage, and any cell whose
witness search comes up empty stays a gap with a named open question.

## 5. Harness reuse — what exists before anything new is written

A real stdio harness already drives the shipped binary and is the reuse target for the
whole stdio axis:

`tests/mik_7212_mrtr7_stdio_acs.rs` — `Command::new(env!("CARGO_BIN_EXE_mcp-gateway"))`
at `:203`, `.spawn()` at `:225`, `fn spawn_fixture_backend()` at `:103`,
newline-delimited JSON framing over
`tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines}` and
`tokio::process::{Child, ChildStdin, ChildStdout, Command}` at `:49-50`. Three `ac_`
tests: `ac_mrtr_7a_stdio_client_answers_while_serve_loop_reads` at `:356`,
`ac_mrtr_7a_bridged_request_follows_the_initialize_response` at `:421`,
`ac_mrtr_7a_concurrent_bridged_requests_write_whole_frames` at `:471`.

Positive control on the sweep (so a null result means a broken search, not a bare
repo): `rg --hidden --no-ignore -l 'CARGO_BIN_EXE_mcp-gateway' tests/` returns 15+
files including `tests/mik_7212_mrtr7_stdio_acs.rs`,
`tests/nfr_compat_2_stdio_client_session.rs`, `tests/stdio_tests.rs`,
`tests/message_signing_stdio_coverage.rs`, `tests/stdio_account_startup.rs`.

**Extraction, not plain reuse.** `tests/common/` holds only `mod.rs`,
`signing_gateway.rs` and `signing_verifier.mjs`. `fn spawn_fixture_backend` is defined
twice — in `tests/mik_7212_mrtr7_stdio_acs.rs` and
`tests/mik_7212_mrtr_component_acs.rs` — and the stdio child-process plumbing lives
inside the integration test file, not in `tests/common/`. The client-role axis
(94 cells, where the gateway is the one asking) needs this plumbing shared, so the
first stage is an **extraction into `tests/common/`** with the existing three stdio ACs
as the behaviour-preserving check. Reuse-before-create applies: nothing new is written
until that extraction is in place, and 356 existing `fn ac_*` sites are the naming and
structure precedent.

## 6. Oracles — what a filled cell must assert

A cell is filled only when its test would fail if the behaviour regressed. Two
directions, and each has a specific way of passing for the wrong reason.

### 6.1 Negative cells (159 of the 282) — refusal must be distinguishable from absence

A negative cell asserts a refusal. The oracle must pin **the specific JSON-RPC error
code** and that the refusal **names its reason**; `is_err()` is not an oracle.

The trap is sharpest on the legacy axis: an unwired method returns
method-not-found (-32601), which reads exactly like a refusal. A real refusal of a
present-but-disallowed operation is an internal/invalid-request error (-32603). A test
asserting "errors" passes identically whether the gateway refused correctly or the
method does not exist at all — and keeps passing if the feature is deleted outright.

**Therefore every negative cell requires a paired positive control**: the same request
succeeds when the precondition holds. Without the control the test cannot tell
"refused" from "absent", and the negative-direction gap is exactly where that
distinction was never made.

### 6.2 Positive cells (123 of the 282) — success must be distinguishable from permissiveness

The success-direction gap (`SCHEMA.1`, `STATELESS.6/.7`, `ERROR.2`; 60 cells matched,
4 already evidenced) is the mirror image: those rows are verified **only** by refusal
today. The new test is the positive one, and its guard against passing for the wrong
reason is that **the refusal path still refuses** — a gateway that accepted everything
would satisfy a lone positive assertion.

So: negative cells get a positive control, positive cells get a negative control. The
pair is the unit of work, which is another reason to count 117 intents rather than 282
cells.

### 6.3 The transport oracle (new guard, expected to go red)

`fn every_cited_test_exists()` at `:1350` checks names only. A cell citing `STDIO` or
`EITHER_TRANSPORT` should additionally require that the cited test demonstrably drives
that transport — the defining file spawning `CARGO_BIN_EXE_mcp-gateway` or using
`tokio::process` framing is the minimum signal.

**This guard turns existing rows red on the day it lands** — at least the 23 entries in
4.1, possibly 29. That red is expected and must be attributed in the commit that
introduces the guard, which is why it is its own stage, separate from cell filling. A
guard landing in the same change as new tests makes the red unattributable.

## 7. Freeze list and pass band

Two artefacts must land in a commit **strictly before** the implementation they grade.
Authoring either by reading the implementation makes it training data, not a test.

1. **The revision-introduction witness table** — for each statement, the revision that
   introduced it plus the in-tree witness (file:line) proving it. This drives every
   per-revision exemption, including the EXT.1 reclassification in 4.5 and any
   additions to `const MODERN_INTRODUCTIONS` at `:884`.
2. **The expected refusal codes and messages** for the negative cells — the -32601 /
   -32603 distinction in 6.1, written down per statement before the tests are written.

**Expected pass band: not 100%.** A frozen refusal-code set that scores 100% on first
run is evidence the codes were copied out of the source. Some frozen expectations
should be wrong and should be corrected as findings, with the correction recorded
against the witness table rather than silently edited to match observed output.

## 8. Stages

Ordered by dependency. No stage starts before the one it depends on is green. Sizes are
in intents, never in time.

| # | stage | scope | depends on | expected signal |
|---|---|---|---|---|
| 0 | Freeze | Witness table + refusal-code table committed (§7) | — | green; no behaviour change |
| 1 | Fix the mechanics | Narrow the three empty-filter gaps (4.2); subtract exemptions from gap `matched` (4.3); decide 4.4 and record it; reclassify EXT.1's 32 legacy cells and the 3 OAuth stdio cells as exemptions with witnesses (4.5) | 0 | green; population drops by ~35 cells with no new test |
| 2 | Transport guard | The 6.3 oracle | 0, 1 | **red, attributed** — 23+ over-claimed citations surface |
| 3 | Harness extraction | `spawn_fixture_backend` and the stdio framing into `tests/common/`; the three existing stdio ACs as the check | 1 | green; no coverage change |
| 4 | stdio axis | 158 tracked cells = **65 intents**, plus the citations stage 2 turns red (~196 cells honest hole) | 2, 3 | the largest stage; report in intents |
| 5 | Client role | 94 cells = **46 intents**; needs the extracted harness for the asking direction | 3 | — |
| 6 | Legacy era | 220 cells = **55 intents** (4x inflation, §2); gated on the 4.4 decision and the witness table | 0, 1 | — |
| 7 | Refusal direction | 159 cells = **66 intents**, each with its positive control (6.1) | 0 | — |
| 8 | Success direction | 123 cells = **51 intents**, each with its negative control (6.2) | 0 | — |

**The cell column does not sum.** Stages 4-8 are axis *views* of the same 282 cells,
not disjoint buckets: one cell can be stdio, legacy, client-role and negative at once
and is counted in four of those rows. Adding the column gives ~792 against a real
population of 282. The delivery total is **117 intents** (62 modern at one intent each
plus 55 legacy groups), not the column sum.

Out of scope for every stage: **80 cells of test work** — EXT.1's 40 (Cluster B) and
ELICIT.1's 40 (product path unwired, 4.5). Stage 1's ~35 reclassifications are
population bookkeeping, not test work: EXT.1's 32 legacy cells become exemptions, so
they never were part of the 202, and subtracting them twice would double-count.

## 9. Open questions for the operator

1. **Which number goes in the v4.0.0 release note?** The recommendation is both, with
   the decomposition of §1: 282 cells with no test, of which 202 are in scope and 80
   are owned elsewhere. Confirm, or name the single number.
2. **4.4 — fine-grained evidence revisions, or forbid partial-era exemptions?**
   Recommendation (B) for this release. This must be settled before stage 6.
3. **Is the stage 2 red acceptable in CI?** A guard that surfaces 23+ over-claimed
   citations makes the suite red until stage 4 lands. The alternative is landing the
   guard behind an allow-list of the known 23, which is a documented liability rather
   than a red one.
4. **Is the release gate "every cell evidenced or witness-exempt", or "every in-scope
   cell"?** With ELICIT.1 unwired in the product, the first gate cannot be met by test
   work at all.
5. **Do the 6 unresolved stdio citations (4.1) get audited individually before stage 4
   scoping?** They move the honest hole between 158 and 196 cells.

## 10. Exit criteria

This design is satisfiable when:

- The mechanics of §4.2, §4.3 and §4.4 are fixed, so the matrix's own numbers can be
  quoted without recomputation.
- Every remaining tracked gap names at least one axis, and no gap's matched set is
  wholly exempt.
- Every cell citing a transport has a test that demonstrably drives that transport.
- Every exemption names an in-tree witness; any cell whose witness search came up empty
  is a gap with a named open question, not an exemption.
- Every negative cell has a positive control and every positive cell has a negative
  control.
- The freeze-list artefacts are in commits that precede the tests they grade, and the
  corrections made to them are recorded as findings.

## 11. What this document deliberately does not do

No test code. No harness edit. No commit, no push. No duration or velocity estimate —
stage sizes are in intents, and §2 explains why cell counts are the wrong currency for
planning. No exemption is proposed on recalled spec history; §4.5 names the one row
(STRUCT.1) where that temptation exists and rules it out.
