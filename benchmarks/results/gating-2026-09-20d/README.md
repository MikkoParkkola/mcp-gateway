<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# NFR.WORKLOAD.1 — the six-rep run, 2026-09-20

`gating-2026-09-20d`, bench-host, 30 measured reps (A1-6, B1-6, C1-6, D1-6, E1-6) plus the
A0/B0/C0 warm-ups. Zero voids, zero HTTP errors.

**Recorded verdict: INCONCLUSIVE** (`eval_workload.py` exit 2, `verdict.json`).

Second INCONCLUSIVE in two runs, and the reason changed. `gating-2026-09-20c` was
inconclusive because three reps cannot support a median interval *at all*. This run has
intervals, and the honest summary is narrower and less satisfying: the p50 point estimate
is over budget again, on a later commit, and two cells are still too noisy for the gate to
grade.

## What six reps bought

At n=3 the gate failed by insufficiency: the distribution-free median interval does not
exist at that rank, so no comparison was gradeable. At n=6 it exists — `_max_rank(6)`
selects the sample extrema (k=1), so every published interval below is the **sample
range**, coverage 96.875%, not a tight band around the pooled median. Any endpoint
comparison in this note is therefore a range comparison.

**Four of the six gated stability checks pass** (three cells × p50/p99):

| Check | Half-width | Margin | |
|---|---|---|---|
| `A.p50` | 0.059 | 0.050 | **unstable** |
| `A.p99` | 0.047 | 0.100 | pass |
| `B.p50` | 0.032 | 0.050 | pass |
| `B.p99` | 0.081 | 0.100 | pass |
| `C.p50` | 0.035 | 0.050 | pass |
| `C.p99` | 0.220 | 0.100 | **unstable** |

**Those two rows are the whole of the recorded verdict.** `evaluate()` sets INCONCLUSIVE
whenever the unstable list is non-empty, before and regardless of the budget comparison
(`eval_workload.py:288-306`). The budget comparison itself is done on point estimates
against a point `min(A, B)` baseline (`eval_workload.py:267-281`) — the gate never
compares intervals, and no interval arithmetic in this note contributed to the verdict.

## The point estimate

The budget is the faster legacy arm plus 5% for p50, plus 10% for p99
(`eval_workload.py:29-30,268-276`). Baseline is taken per metric as `min(A, B)` over the
pooled cell values.

| | Value (s) | Limit (s) | |
|---|---|---|---|
| Baseline p50 | 0.663810 (B, 3.5.1) | — | |
| **Candidate p50 (C, 4.0.0)** | **0.740489** | **0.697001** | **+6.24% over the limit** |
| Candidate p99 (C, 4.0.0) | 1.413594 | 1.592950 | within budget, 11.26% headroom |

## Nor would a stable run have settled the p50 breach

This section is an observation about the data, **not** a description of what the gate did.
The gate compares points, as above. But a reader asking "so is 4.0.0 over budget?" should
know that the point breach does not survive giving the baseline its own spread.

`median_interval` returns an order-statistic pair `(ordered[k-1], ordered[n-k])`
(`eval_workload.py:155-169`) — asymmetric about the pooled value. `rel_half_width` is a
width *summary*, so endpoints cannot be reconstructed as `median × (1 ± w)`; the actual
p50 sample ranges at n=6 are:

| Cell | Range (s) | Pooled (s) |
|---|---|---|
| A (3.5.0) | (0.610162, 0.689281) | 0.669187 |
| B (3.5.1) | (0.650978, 0.693697) | 0.663810 |
| C (4.0.0) | (0.697810, 0.750274) | 0.740489 |

Two readings, and they disagree:

- **Against the fixed limit**, C clears it everywhere: C's floor is 0.697810 against a
  0.697001 limit. The margin is **0.000810 s — 0.12%**. Every measured C rep is over
  budget, but by a hair at the bottom of the range, not with room to spare.
- **Allowing the baseline its own spread**, the breach does not hold. B's range reaches
  0.693697, which yields a limit of 0.728382 — above C's floor of 0.697810. The candidate
  range and the plausible-limit range overlap.

So even a fully stable run at this sample size would leave the budget question open at the
margins. Nothing here licenses the claim that the sign is fixed.

## What is nonetheless established

- The p50 point-estimate overrun **reproduces**, at n=6, on `dbd4deae5bda` — a *later*
  release-line commit than the `5e557e08` that 20c measured. Two runs, two builds, same
  direction. That is not an artifact of a single build.
- The p50 samples separate completely: C's slowest-to-fastest range (0.697810–0.750274)
  sits entirely above both legacy cells' ranges (A tops out at 0.689281, B at 0.693697).
  Every C rep is slower than every legacy rep, so the direction versus 3.5.1 does not
  depend on which order statistic is picked, nor on the single tight C rep near the limit.
- The candidate's own p50 spread is inside margin (half-width 0.0354), so the overrun is
  not noise in the candidate cell.
- p99 is **not** clean, though the pooled number passes. Pooled `C.p99` is 1.413594 against
  a 1.592950 limit — 11.26% headroom — but the n=6 range is the sample extrema and its top
  rep is 1.928 s, over the limit. That spread is exactly why `C.p99` is a recorded unstable
  reason and half of why this run is INCONCLUSIVE.

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
stdout/stderr and k6 output — are archived on bench-host at
`~/perf-workload/results/gating-2026-09-20d/`, outside any checkout so they survive branch
and worktree cleanup. They were produced in the `mcp-gateway-wt-6rep` worktree and copied
out; do not cite the worktree path.

Interval endpoints above were computed from `verdict.json`'s `per_rep` block, not from
`rel_half_width`. Two corrections are folded into this note. An earlier draft
reconstructed the endpoints symmetrically as `median × (1 ± w)` and overstated the result;
the order-statistic endpoints are the authority. A later draft then attributed the
INCONCLUSIVE verdict to interval overlap — `evaluate()` never compares intervals, and the
verdict comes from the two unstable half-widths alone (`eval_workload.py:288-306`). The
overlap observation is retained above as analysis of the data, clearly separated from what
the gate computed.
