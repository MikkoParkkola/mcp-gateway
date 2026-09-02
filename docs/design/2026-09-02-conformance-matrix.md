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
| 3 | The revision axis is two-class, not flat: four negotiable revisions, plus `2026-07-28` which is deliberately absent from `SUPPORTED_VERSIONS` until the modern request path exists | `src/protocol/mod.rs:38,43` |
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
invention: `MRTR.9a/10a/10b` already exist in the ledger, which is why 95
criteria produce 100 rows (constraint 1). A row carries its own axis set.

### Q2 — which axes apply to which row?

**Invert the default: axis membership is per-row DATA, declared explicitly, not
derived from the requirement text.** Constraint 4 is the reason — only 15 of 95
criteria name a role at all, so a derivation rule would silently drop the axis
from 80 rows and call the result complete. Declaring membership costs one field
per row and makes an omission visible as an omission.

This also caps the size. Cells exist only where the row declares the axis;
~4,000 is the naive product, never the population.

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
of the two review legs is a Claude Code CLI run under `--safe-mode`, which
cannot read the tree. The rendered markdown is what travels in review material.
A data file alone is unreviewable by half the gate.

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

**The ratchet needs two numbers, not one.** Publish `cells-in-scope` and `EMPTY`
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
| (b) several markdown tables, one per requirements section | Readable, but the axis set is per-row (Q2), so a section table cannot carry it uniformly — and nothing is mechanically checkable |
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
- Any change to `SUPPORTED_VERSIONS` or the modern request path.
- Any change to what `criteria-status.md` records.

## Open questions — answered

| question | what was run | what came back | what it changed |
|---|---|---|---|
| Is the revision axis flat? | read `src/protocol/mod.rs:26,38,43` and `src/protocol/meta.rs:218-219` | 4 negotiable revisions plus 1 handshake-unreachable modern one | Axis is two-class; every `2026-07-28` cell is `EMPTY`-or-`EXEMPT` by construction today |
| Is "outcome" an axis or a cell attribute? | read `docs/requirements/RELEASE-4.0.0-test-plan.md:394` and `docs/requirements/RELEASE-4.0.0-requirements.md:320` | "crossed with role …, transport, revision, and outcome (positive ‖ negative)" | It is a fourth axis, cardinality 2 — the sizing had to use it |
| Does the repo already split a criterion into sub-rows? | `rg` over `docs/requirements/`, plus the counter's output | `MRTR.9a/10a/10b` exist; 95 criteria vs 100 rows | Q1's row-is-not-criterion is established practice here, not invented |
| Is there precedent for a checked-in data file plus a drift check? | listed `scripts/` and `benchmarks/`; read `scripts/release/count-release-criteria.py` | Two precedents | Chose option (c) over hand-maintained markdown |
| Can the axis set be read off requirement text? | token scan over all 95 criteria | 15 role / 12 transport / 4 revision | NO — forced Q2's invert-the-default |

## Open questions — deferred

| id | question | owner | resolved by | when | if it resolves badly |
|---|---|---|---|---|---|
| U-A | Does the `NFR.COMPAT.4` role clause stay unqualified? | operator (cluster F decision 3, `docs/requirements/RELEASE-4.0.0-criteria-status.md:257`) | an operator ruling | before the matrix is first populated | If unqualified: every client-role cell on a server-only requirement becomes a finding, so either client-role code or a requirement amendment lands in this release |
| U-B | Must an evidence reference resolve to an EXECUTED test (a green CI run id), or is an existing test name enough? | release owner | a decision on how much CI plumbing is in scope | before `--check` is wired blocking | If executed is required, the checker needs CI-artefact access and the gate slips to tag-time only |
| U-C | Does `--check` block pre-tag on non-zero `EMPTY`? | release owner | confirmation of the proposal in Q5 | before `--check` is wired | Blocking from day one turns every PR red while the modern path is unbuilt |

U-A and U-B block nothing in this document; they block POPULATING the matrix and
WIRING the checker respectively, and neither is in scope here.

## `NFR.COMPAT.4` — designed for either answer

U-A is left open deliberately, and the design is built so that either ruling is a
DATA change, never a redesign. Role-axis membership is per-row data (Q2) and the
exemption vocabulary is data (Q3):

- Operator says the role clause stays **unqualified** → the `NO-SURFACE-IN-ROLE`
  code is deleted from the vocabulary, and those cells become `EMPTY`. That is the
  honest outcome: findings, forcing client-role code or a requirement amendment.
- Operator says **qualify it** — mirroring the transport clause's "that
  implements it" — → `NO-SURFACE-IN-ROLE` stays, with its witness rule.

Give the operator the number when asking: 15 of 95 criteria carry a client or
backend token, so the ask should quantify cells created and removed by each
answer rather than describing them.

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
