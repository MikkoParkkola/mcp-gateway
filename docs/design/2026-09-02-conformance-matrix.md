<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: MIT
-->

# Design — the 4.0.0 conformance matrix

Status: proposed. NO CODE in this document by design (`development-process.md` §P1).

## Problem

`RELEASE-4.0.0-requirements.md:320` acceptance 2 says the conformance matrix has
"no empty evidence cell. An empty cell is the finding." Nothing in the tree is
that matrix. `NFR.OBS.5` (`requirements.md:243`) already spends the matrix as
currency — modern-protocol serving stays flag-off "until the conformance matrix
is complete" — so an artefact that does not exist is gating a shipping decision.

This document decides what the matrix IS, before anyone builds one.

## Measured constraints

Every number here was read out of the tree, not estimated.

| # | constraint | evidence |
|---|---|---|
| 1 | Population is 95 declared criteria over 100 ledger rows — a criterion may already split into sub-rows (`MRTR.9a`, `MRTR.10a`, `MRTR.10b`) | `python3 scripts/release/count-release-criteria.py` → `Coverage: 95 criteria, 100 rows, 66 met or non-blocking, 34 blocking.` |
| 2 | "Outcome" is a fourth axis, not a cell attribute: "crossed with role (server ‖ client), transport, revision, and outcome (positive ‖ negative)" | `RELEASE-4.0.0-test-plan.md:394` |
| 3 | The revision axis is the union of TWO declared sets, each with its own serving path: `SUPPORTED_VERSIONS` (four legacy-negotiable revisions) and `MODERN_VERSIONS` (`2026-07-28`). The modern revision is absent from the first BY DESIGN and present in the second — it is unreachable through legacy `initialize`, not unserved | `src/protocol/mod.rs:38,43`, `src/protocol/meta.rs:215-219`, `src/gateway/meta_mcp/mod.rs:1088-1092` |
| 4 | The axis set cannot be read off requirement text. A token scan over the 95 criteria finds a client/backend token in 15, a transport token in 12, a revision token in 4 | token scan, this session |
| 5 | Hand-maintained headline numbers in this document family have drifted three times | `scripts/release/count-release-criteria.py:5-7` |

Constraint 1 and 2 together kill the brief's own sizing. The brief assumed
"22 requirements × 2 roles × 2 transports × 5 revisions ≈ 440 cells". The real
population is 100 rows, and outcome is a fourth axis, so the naive product is
~4,000 cells. A 4,000-cell artefact maintained by hand is not an artefact, it is
a promise.

## Decisions

### Q1 — what is a row?

**One row per normative statement, sub-rowed where a statement carries
independently verifiable clauses.** Row ≠ criterion, and that is not an
invention: `MRTR.9a/10a/10b` already exist, which is why 95 criteria produce 100
rows (constraint 1).

**The population derives from the REQUIREMENTS file; the ledger is a
cross-check.** The 100-row count above was read out of `criteria-status.md`,
which records *status* — its clause splits happened where someone needed to
track two verdicts, not wherever a statement carries two independently
verifiable obligations. Those two sets are not guaranteed equal, and where the
ledger has not split a compound obligation, evidence for one clause stands in
for its sibling and the sibling never appears as missing.

So each independently verifiable clause gets a stable subcriterion ID in
`RELEASE-4.0.0-requirements.md`, in the `<TICKET>.<COMPONENT>.<NUM>` form the
acceptance-criteria convention already uses, and the population is exactly that
ID set. The ledger's 100 rows become a reconciliation target: a divergence
between the two counts is a finding in one of them — a check the current design
cannot perform at all, because both numbers come from the same file.

### Q2 — which axes apply to which row?

**All four, to every row. The product is TOTAL.** Acceptance condition 2 states
the matrix as one row per normative statement *crossed with* role, transport,
revision and outcome. A cross product with per-row opt-outs is not a cross
product, and a row that declares an axis away removes its own cells from the
population `--check` then reports as complete.

Two candidate mechanisms were considered, and both are rejected:

- *Derive membership from requirement text* — rejected by constraint 4. Only 15
  of 95 criteria name a role, so derivation drops the axis from ~80 rows and
  calls the result complete.
- *Declare membership per row* — rejected because it relocates that judgement
  rather than removing it. The implementer who fills the matrix also decides
  which cells the matrix is graded on, in the same pass, and every omission is
  invisible by construction: an absent cell and an absent axis are the same
  absence.

What is left is totality. Every row emits every cell, and a combination that
genuinely cannot apply is `EXEMPT` with a named rule and a witness (Q3) — a
claim a reviewer can read and disagree with, which is exactly what neither
rejected mechanism could produce.

**Size is not the objection it looks like.** The total product is ~4,000 cells,
and the line above about a 4,000-cell artefact being a promise rather than an
artefact applies to a HAND-MAINTAINED one. Nothing here is hand-maintained:
cells are generated (Q4), and a human authors two things only — exemption RULES,
of which a handful cover thousands of cells, and EVIDENCE, which exists only for
cells genuinely in play. Cell count is the renderer's problem. Authoring count
is the human's, and it does not scale with the product.

### Q3 — how is "not applicable" represented?

Three cell states. The third is **emitted by the renderer, never typed by a
human**, so a cell cannot vanish quietly.

| state | means | for a **T** row requires |
|---|---|---|
| `EVIDENCE` | the obligation is verified | BOTH a test reference AND a production call site outside `tests/` |
| `EXEMPT` | covered by a named rule from the declared exemption vocabulary | the rule code AND its witness — never a bare "N/A" |
| `EMPTY` | neither of the above | nothing; it is generated, and it is the finding |

`M`/`I`/`D` rows take the measurement, inspection or demonstration artefact
reference in place of the test-plus-call-site pair.

Why `EVIDENCE` demands a production call site: `MRTR.5`, `.6`, `.7` and `.8` are
unit-tested and unwired in this repo — four measured instances in one cluster.
A test-only cell is exactly the artefact acceptance 2 exists to prevent, and
DoD `D7:WIRED` already says so for code. `EXEMPT` carrying its rule code is
acceptance 1's requirement ("an N/A without a reason is a skipped requirement
wearing a label", `requirements.md:319`) applied per cell.

### Q4 — what form does it take?

**A checked-in data file plus a renderer plus a `--check` mode.**

- data: `docs/requirements/conformance-matrix.toml` — hand-editable, diffable,
  reviewable per row. TOML over JSON because the repo is Cargo-native and the
  file is edited by hand in review; `benchmarks/public_claims.json` is the JSON
  precedent and is machine-written, which is the opposite case.
- rendered: `docs/requirements/RELEASE-4.0.0-conformance-matrix.md`, checked in.
- checker: `--check`, the same shape as `count-release-criteria.py`.

The rendered file is checked in and not merely generated on demand because one
of the two review legs always runs isolated from the tree — `grok-review` from
an empty working directory for Claude-authored work, a Claude Code CLI run
under `--safe-mode` for Grok-authored work. Either way that reviewer cannot
render anything for itself, so the rendered markdown is what travels in the
review material. A data file alone is unreviewable by half the gate.

### Q5 — how does it stay honest over time?

`--check` asserts four things:

1. **Population is derived FROM the requirements file, not from the matrix.**
   Adding a requirement without a row fails the check. A matrix that defines its
   own population can always be complete.
2. Every evidence reference resolves — the test exists AND the production call
   site exists.
3. Every `EXEMPT` carries a vocabulary code and its witness.
4. Headline numbers are owned by the script, never hand-decremented
   (constraint 5).

**The exemption vocabulary is CLOSED, and adding to it is a design event.**
Totality (Q2) stopped the population being shrunk by judgement, and without this
the same judgement simply moves up a level: mint a rule code, apply it to five
hundred cells, and every check still passes — code present, witness present,
`EMPTY` falls, `cells-in-scope` unchanged. The codes therefore live in this
document, ratified with it, and `--check` REFUSES an unknown code rather than
accepting any string. A new code is a change to what the release is graded on,
which is exactly the kind of decision that should cost a review and not a commit.

Three worked codes, enough to calibrate what a rule looks like:

| code | applies when | witness |
|---|---|---|
| `NO-SURFACE-IN-ROLE` | the requirement has no manifestation in that role | the statement text, showing it constrains only the other role |
| `TRANSPORT-LACKS-MECHANISM` | the transport has no mechanism the requirement could constrain | the transport's capability declaration |
| `REVISION-PREDATES-STATEMENT` | the revision was frozen before the statement existed | the revision's `SUPPORTED_VERSIONS`/`MODERN_VERSIONS` entry and the statement's introducing change |

A rule is a claim about a SET of cells, which is what makes the authoring burden
sublinear in the product — and also what makes a wrong rule expensive, hence the
ratification.

**The ratchet needs three numbers, not one.** Totality (Q2) already removes the
easy way to game it — `cells-in-scope` is now a pure function of the requirement
ID set and the two axis-value constants, so no judgement made while filling the
matrix can shrink it. What remains is the hard way: editing the requirements
file, or the version constants, to change the inputs. That is a legitimate act
which must not be silently indistinguishable from progress, so publish
`cells-in-scope`, `EMPTY` and `EXEMPT`
separately. "EMPTY must never increase" alone is gameable by shrinking the
population: amend a requirement, cells vanish, `EMPTY` falls, and the graph reads
as progress. A fall in `cells-in-scope` is a scope move and needs a §P0 receipt;
a fall in `EMPTY` is work.

Cadence: advisory print on every PR, ratchet enforced continuously, blocking at
tag. `NFR.OBS.5` already gives incompleteness a live consequence, so the gate
does not have to be a red PR on day one to bite.

## Options rejected

| option | why not |
|---|---|
| (a) one giant markdown table | 100 rows × up to 20 cells. Unreviewable in a diff, unmergeable between two authors, and hand-maintained headline drift is documented three times over (`count-release-criteria.py:5-7`) |
| (b) several markdown tables, one per requirements section | Readable, but nothing is mechanically checkable, and ~4,000 generated cells (Q2) are not something a human splits across section tables by hand |
| (d) generate the matrix from test annotations or a `#[test]` harvest | **Strongest rejection.** It can only report cells that HAVE tests, so a missing test yields a missing ROW, not an `EMPTY` cell. That is precisely the failure acceptance 2 forbids: the artefact would be most complete exactly where the work is least done |

Option (c) — data file plus renderer plus check — is chosen. Precedent exists
twice in this repo: `scripts/release/count-release-criteria.py` (derive the
headline, check it) and `benchmarks/public_claims.json` (checked-in claims with a
CI drift check).

## Ownership boundary — matrix vs `criteria-status.md`

The two documents answer different questions and must not overlap.

| | `RELEASE-4.0.0-criteria-status.md` | the conformance matrix |
|---|---|---|
| unit | one criterion | one cell |
| carries | a VERDICT (met / absent / blocking) | EVIDENCE only |
| satisfies | acceptance 1 | acceptance 2 |

**A matrix cell never carries a verdict.** "Outcome" in the axis list is a
spec-behaviour axis (positive ‖ negative input), NOT a pass/fail column. Without
this line the matrix becomes `criteria-status.md` rebuilt with more columns, and
this repo already carries two drifted copies of its own gate files (MIK-7193).

## Language choice — named, not slipped through

The renderer is Python under `scripts/release/`, with a unit test beside it,
matching `count-release-criteria.py` and `test_count_release_criteria.py`.

DoR C8/C9 says string and parsing work goes to Rust. This deviates. The stated
reason: it is not a CPU-bound path, it ships with the docs rather than the
binary, and there is direct precedent plus an existing test harness in the same
directory. Named here so a reviewer can refuse it, rather than passing silently.

## Out of scope

- Populating the matrix. This decides the shape; filling it is the work it gates.
- Wiring `--check` as a blocking CI job (see U-C).
- Any change to `SUPPORTED_VERSIONS`, `MODERN_VERSIONS`, or the modern request path.
- Any change to what `criteria-status.md` records.

## Open questions — answered

| question | what was run | what came back | what it changed |
|---|---|---|---|
| Is the revision axis flat? | read `src/protocol/mod.rs:26,38,43`, `src/protocol/meta.rs:215-219`, `src/gateway/meta_mcp/mod.rs:1088-1092` | TWO constants, not one list with a hole: `SUPPORTED_VERSIONS` (4 legacy) and `MODERN_VERSIONS` (`2026-07-28`), the second deliberately separate | Axis = the union of both sets. The first reading of this — that every `2026-07-28` cell is dead by construction — was WRONG, and would have written a whole column off as unservable while the modern path serves it |
| Is "outcome" an axis or a cell attribute? | read `docs/requirements/RELEASE-4.0.0-test-plan.md:394` and `docs/requirements/RELEASE-4.0.0-requirements.md:320` | "crossed with role …, transport, revision, and outcome (positive ‖ negative)" | It is a fourth axis, cardinality 2 — the sizing had to use it |
| Does the repo already split a criterion into sub-rows? | `rg` over `docs/requirements/`, plus the counter's output | `MRTR.9a/10a/10b` exist; 95 criteria vs 100 rows | Q1's row-is-not-criterion is established practice here, not invented |
| Is there precedent for a checked-in data file plus a drift check? | listed `scripts/` and `benchmarks/`; read `scripts/release/count-release-criteria.py` | Two precedents | Chose option (c) over hand-maintained markdown |
| Can the axis set be read off requirement text? | token scan over all 95 criteria | 15 role / 12 transport / 4 revision | NO — this killed derivation as a mechanism, and per-row declaration fell to review for relocating the same judgement, leaving Q2's total product |
| Must an evidence reference resolve to an EXECUTED test, or is an existing test name enough? (U-B) | asked of the operator, 2026-09-02 | EXISTENCE for 4.0.0 — a named test that exists and is WIRED (a production call site outside `tests/`, per DoD D7); the executed-run bar becomes a tracked follow-up, not a deferred intention, filed as MIK-7359 before the release rather than after it | `--check` needs no CI-artefact access, so it runs on any machine and can go blocking inside this release. The weaker bar is stated as weaker: a named test that is skipped or quarantined still reads as evidence, and closing that is the follow-up's job |
| Does the `NFR.COMPAT.4` role clause stay unqualified? (U-A) | asked of the operator, 2026-09-02, with the 15-of-95 number | YES — the criterion text is not edited, and a requirement with no client-role surface is exempted AT THE CELL with its reason | `NO-SURFACE-IN-ROLE` stays in the vocabulary. It also corrected this document: the branch table below had treated "criterion unqualified" and "no exemption code" as one branch, and they are separable |

## Open questions — deferred

| id | question | owner | resolved by | when | if it resolves badly |
|---|---|---|---|---|---|
| U-C | Does `--check` block pre-tag on non-zero `EMPTY`? | release owner | confirmation of the proposal in Q5 | before `--check` is wired | Blocking from day one turns every PR red while the modern path is unbuilt |

U-C blocks nothing in this document; it blocks WIRING the checker, which is not
in scope here.

**The evidence bar is deliberately weaker than it should end up, and the gap is
named rather than absorbed.** `--check` verifies that a cell's reference resolves
to a test that EXISTS and is WIRED. It does not verify the test RAN or PASSED, so
a skipped or quarantined test satisfies the checker. Nothing in this design
pretends otherwise, and the ratchet numbers (Q5) do not conceal it: they count
cells, not green runs.

## `NFR.COMPAT.4` — ruled on, 2026-09-02

The role clause **stays unqualified**. `NFR.COMPAT.4` continues to demand both
roles without exception, and a requirement with no client-role surface is
exempted at its matrix CELL, under `NO-SURFACE-IN-ROLE`, with the statement text
as witness.

The ruling also corrected this design. The question had been framed as one
branch — unqualified criterion *therefore* no exemption code, cells fall to
`EMPTY` — and those are two decisions, not one. Where the inapplicability
judgement is EXERCISED and whether the criterion ADMITS it are independent, and
the ruling separates them: the judgement is unavoidable (something must decide
that a server-only requirement has no client half), so it is placed where it
leaves a trace a reviewer can disagree with, rather than in the criterion where
it would be exercised silently. Editing the criterion instead would have let
whoever fills the matrix decide, in the same pass, what the matrix is graded on.

Consequence for the ratchet (Q5): `EXEMPT` absorbs these cells rather than
`EMPTY`, which is precisely why Q5 publishes `EXEMPT` as its own number. 15 of
95 criteria carry a client or backend token, so the exempted population is
large, visible, and ratcheted — not a rounding error hidden inside a total.

## Contradictions found while designing this

Recorded because each is a live inconsistency in the release documents, not a
byproduct of this design.

1. The brief's sizing — "22 requirements × 2 × 2 × 5 ≈ 440 cells" — contradicts
   the repo: 95 criteria over 100 rows, and outcome is a fourth axis, giving
   ~4,000 naive cells.
2. `docs/requirements/RELEASE-4.0.0-requirements.md:213` qualifies the TRANSPORT
   clause of `NFR.COMPAT.4` ("on every transport that implements it") but leaves
   the ROLE clause unqualified. Internally asymmetric;
   `docs/requirements/RELEASE-4.0.0-criteria-status.md:257` records it as
   deliberately unresolved.
3. `docs/requirements/RELEASE-4.0.0-requirements.md:207` (`NFR.COMPAT.1`) says
   `2026-07-28` MUST be served, while `src/protocol/mod.rs:38,43` deliberately
   excludes it. Expected mid-release, not a documentation bug — but it makes the
   whole `2026-07-28` revision column `EMPTY`-or-`EXEMPT` at matrix creation, and
   that should be stated as the honest starting number rather than discovered
   later.
4. `docs/requirements/RELEASE-4.0.0-test-plan.md:394` records its own prior
   error: the population was once narrowed to changelog-introduced statements,
   which would have dropped `NFR.COMPAT.1` and `.2`. The corrected population —
   every normative statement in the requirements — is what Q5's derivation rule
   enforces mechanically.
