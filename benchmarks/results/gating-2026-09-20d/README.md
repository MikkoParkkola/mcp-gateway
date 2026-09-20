<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# NFR.WORKLOAD.1 — the six-rep run, 2026-09-20

`gating-2026-09-20d`, Spark, 30 measured reps (A1-6, B1-6, C1-6, D1-6, E1-6) plus the
A0/B0/C0 warm-ups. Zero voids, zero HTTP errors.

**Recorded verdict: INCONCLUSIVE** (`eval_workload.py` exit 2, `verdict.json`).

Second INCONCLUSIVE in two runs, and the reason changed. `gating-2026-09-20c` was
inconclusive because three reps cannot support a median interval *at all*. This run has
intervals, and the honest summary is narrower and less satisfying: the p50 point estimate
is over budget again, on a later commit, and the interval arithmetic does **not** settle
it at the gate's confidence level.

## What six reps bought

At n=3 the gate failed by insufficiency: the distribution-free median interval does not
exist at that rank, so no comparison was gradeable. At n=6 it exists — `_max_rank(6)`
selects the sample extrema, coverage 96.875% — and **four of the six gated stability
checks pass** (three cells × p50/p99). Two remain over margin:

| Unstable | Half-width | Margin |
|---|---|---|
| `A.p50` | 0.059 | 0.050 |
| `C.p99` | 0.220 | 0.100 |

## The point estimate

The budget is the faster legacy arm plus 5% for p50, plus 10% for p99
(`eval_workload.py:29-30,268-276`). Baseline is taken per metric as `min(A, B)` over the
pooled cell values.

| | Value (s) | Limit (s) | |
|---|---|---|---|
| Baseline p50 | 0.663810 (B, 3.5.1) | — | |
| **Candidate p50 (C, 4.0.0)** | **0.740489** | **0.697001** | **+6.24% over the limit** |
| Candidate p99 (C, 4.0.0) | 1.413594 | 1.592950 | within budget, 11.26% headroom |

## The interval arithmetic does not settle it

`median_interval` returns an order-statistic pair `(ordered[k-1], ordered[n-k])`
(`eval_workload.py:155-169`) — asymmetric about the pooled value. `rel_half_width` is a
width *summary*, so endpoints cannot be reconstructed as `median × (1 ± w)`; the actual
p50 intervals at n=6 are:

| Cell | Interval (s) | Pooled (s) |
|---|---|---|
| A (3.5.0) | (0.610162, 0.689281) | 0.669187 |
| B (3.5.1) | (0.650978, 0.693697) | 0.663810 |
| C (4.0.0) | (0.697810, 0.750274) | 0.740489 |

Two readings, and they disagree:

- **Against the fixed limit**, C clears it everywhere: C's floor is 0.697810 against a
  0.697001 limit. The margin is **0.000810 s — 0.12%**. Every measured C rep is over
  budget, but by a hair at the bottom of the range, not with room to spare.
- **Allowing the baseline its own uncertainty**, the breach does not hold. B's interval
  reaches 0.693697, which yields a limit of 0.728382 — above C's floor of 0.697810. The
  candidate interval and the plausible-limit range overlap, so the comparison is not
  resolved at this confidence level.

The second reading is the one the gate is entitled to. **INCONCLUSIVE is correct here, not
merely conservative** — and more reps could move it either way. Nothing in this run
licenses the claim that the sign is fixed.

## What is nonetheless established

- The p50 point-estimate overrun **reproduces**, at n=6, on `dbd4deae5bda` — a *later*
  release-line commit than the `5e557e08` that 20c measured. Two runs, two builds, same
  direction. That is not an artifact of a single build.
- The candidate's own p50 spread is inside margin (half-width 0.0354), so the overrun is
  not noise in the candidate cell.
- p99 is not implicated: it passes with 11.26% headroom, and `C.p99`'s instability is on
  the metric that passes.

## What this asks of the release owner

A bisect between 3.5.1 (`e138680a542b`) and `dbd4deae5bda` is justified by the reproduced
point estimate. It is an investigation trigger, not a proven regression — and the budget
question cannot be closed PASS or FAIL on this data.

The remaining gate-design observation from `gating-2026-09-20c` still stands and is still
not actioned here: changing a release gate while grading against it is what the
ratification rule forbids. Recorded, not fixed.

## Provenance

`pins.json` records the k6 image digest and the per-cell checkout SHAs: A = 3.5.0
`32f135a61fb5`, B = 3.5.1 `e138680a542b`, C/D/E = 4.0.0 `dbd4deae5bda`. D and E share C's
SHA and health version, so the C→D comparison isolates protocol era against a
byte-identical binary; both are report-only and neither is gated.

The 265 raw artifacts — per-rep `*.summary.json`, `*.meta.json`, `*.health.json`, gateway
stdout/stderr and k6 output — are archived on Spark at
`~/perf-workload/results/gating-2026-09-20d/`, outside any checkout so they survive branch
and worktree cleanup. They were produced in the `mcp-gateway-wt-6rep` worktree and copied
out; do not cite the worktree path.

Interval endpoints above were computed from `verdict.json`'s `per_rep` block, not from
`rel_half_width`. An earlier draft of this note reconstructed them symmetrically and
overstated the result; the order-statistic endpoints are the authority.
