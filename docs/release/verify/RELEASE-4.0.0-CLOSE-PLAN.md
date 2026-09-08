# 4.0.0 release-readiness — gap-closure plan (draft for adversarial review)

## Goal

PR #473 merged and 4.0.0 shippable with the FULL scope: every blocking release
criterion met with evidence, no red checks, no unreviewed code.

## Where the release actually stands

| fact | evidence |
|---|---|
| branch compiles; 4054 lib tests pass | `cargo test --lib` on the branch |
| ONE red test | `honest_task_tokens::tests::schema_only_100_tools_matches_readme_model` |
| CodeQL FAILURE on #473 | the only red check on the PR |
| 21 blocking criteria of 183 rows | `rg -c '\| yes \|' docs/requirements/RELEASE-4.0.0-criteria-status.md` = 21; `\| no \|` = 162 |
| 326 of 329 changed files never reviewed by anyone | PR473-REVIEW-BRIEF.md, operator decision 2026-09-08 |
| shard reports written, verdicts mostly PENDING | `docs/release/verify/pr473-*.md` |

## Buckets

- **B1 — blocking criteria.** 21 rows. Each needs met/not-met with evidence, and a
  test that can fail. Not yet determined: how many are already met, because
  `count-release-criteria.py --blocking` is malformed on `MIK-7272.EXT.1` and cannot
  enumerate them mechanically.
- **B2 — red signals.** CodeQL failure plus the one failing lib test.
- **B3 — unreviewed code.** ~27K insertions across the shards; verdicts still PENDING
  in most shard reports. Expected to add findings; how many is not yet established.
  Covers the whole changed surface INCLUDING the 21.6K-line test diff, at two depths:
  a deep can-this-test-fail audit of the AC tests backing the 21 blocking rows, and a
  proportionate pass over the remaining tests. Depth varies with risk; coverage does
  not, because a release that claims no unreviewed code cannot carve out a third of
  the diff.
- **B4 — release paperwork.** DoD §1-§13 verdicts, AC pass/fail table posted to the
  issue, dual-vendor final review, functional pass, delivery-chain steps 1-5.

## Critical path

```
  repair the criteria counter (gates reconciliation) -+
  triage CodeQL + the red test (B2)                  -+
  finish shard reviews, land verdicts (B3)           -+- parallel
  assess and repair blocking criteria (B1)           -+
  functional pass as soon as a surface runs (B4)     -+
                    |
                    v
  fold B3 findings into the blocking set
                    |
                    v
  fold B3 findings into the blocking set
                    |
                    v
  CLOSE each blocking criterion (test that can fail + evidence)
                    |
                    v
  refresh B4 evidence against the final candidate, dual-vendor review, merge
```

## Sequencing rationale

1. **The counter gates final RECONCILIATION, not every criterion.** Rows that are
   already identifiable by id can be worked now; what the broken enumeration prevents
   is the closing claim that all 21 are accounted for, and hand transcription has
   already produced two disagreeing counts in this repo (37 vs 31). Diagnosed
   2026-09-08: the blocking cells are fine. `rows()` anchors its id regex with `$`
   (`scripts/release/count-release-criteria.py:31`), so the ledger's clause-qualified
   form `MIK-7272.EXT.1 (clause: declare)` fails the match, falls to the
   `ID_PREFIX` branch (`:158-160`), and is reported under a message naming the wrong
   column. Two rows, one regex.
2. **B2 is cheap and gates the merge absolutely.** A red check blocks the merge
   regardless of criteria state. The failing test is one assertion about a documented
   token model; either the model or the assertion is wrong, and deciding which is a
   read, not a project.
3. **B3 gates criterion CLOSURE, not criterion WORK.** A reviewer finding that lands
   after a criterion is closed reopens it, so closure waits. Assessment and repair do
   not: they run concurrently with B3, and only the criteria a later finding actually
   touches get reworked. The earlier draft put a global barrier here and paid for it
   across all 21 rows to protect the few that a finding would reach.
4. **B4 is assembled incrementally, not at the end.** The functional pass runs as soon
   as there is something runnable, because an integration failure found at the last
   stage costs a whole cycle. Evidence collected early is refreshed against the final
   candidate rather than gathered from scratch.

## What is deliberately NOT on the critical path

- Paperwork audits of the criteria ledger's non-blocking 162 rows. They do not gate
  ship. The `shard-5` agent doing that audit has been stopped.

(An earlier draft excluded most of the test diff from review. That contradicted the
release's own no-unreviewed-code requirement and has been withdrawn — see B3.)

## Open questions this plan does not answer

- How many of the 21 blocking criteria are already met? Not established until the
  counter is fixed. The plan's shape does not depend on the answer; its size does.
- Will B3 add blocking findings? Not established. Historical rate in this repo:
  roughly 1 in 4 reviewer findings dies at source, so a raw finding count overstates
  the work.
- Is the CodeQL failure a real defect or a scanner artifact? Untriaged.

## Review question

Is this the fastest correct order, or does it serialise something that could run
concurrently? Attack the sequencing, not the prose.
