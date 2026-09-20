# NFR.WORKLOAD.1 — first gradeable run, 2026-09-20

`gating-2026-09-20c`, Spark, 15 measured reps (A1-3, B1-3, C1-3, D1-3, E1-3) plus the
A0 warm-up. Zero voids, zero HTTP errors, semantic assertion rate 1.0 in every rep.

**Recorded verdict: INCONCLUSIVE** (`eval_workload.py` exit 2, `verdict.json`).

Read the rest of this note before quoting that verdict. INCONCLUSIVE is the grade the
stability gate produced; underneath it sits a p50 figure that is over the budget under
every baseline this run's own data supports.

## Why this run matters

Every previous attempt was VOID. `evaluate()` calls `check_rep` for D and E as well as
A/B/C, so the modern-era admission wall — cells D and E refused at the pinned `tools/call`
because the unauthenticated workload client carries no idempotency key — voided the whole
run before any cell could be graded. That wall is gone (PR #611, `workload_probe` declared
read-only in both gating configs). D and E produced 8228, 8224, 8226 and 8216, 8214, 8213
iterations with zero failures. This is the first run in the project's history that reached
a grade at all.

## The comparison is valid now, and it was not before

The 2026-09-14 rehearsal graded the budget row **NOT EVALUABLE**: the 3.5.0/3.5.1 arms
answered from the response cache under the header shape k6 sends, so the baseline was not
doing backend work (`../rehearsal-2026-09-14/06-finding-response-cache.md`). `cache.enabled:
false` in both gating configs was the fix.

The numbers confirm the fix took effect on the legacy binaries, which is not otherwise
observable — the fixture backend does no per-call I/O, so invocations cannot be counted
from a log:

| cell | p50, 2026-09-14 (cache active) | p50, this run (cache disabled) |
|---|---|---|
| A (3.5.0) | 0.38 ms | 0.676 ms |
| C (4.0.0) | 0.67 ms | 0.732 ms |

A's p50 rose 78% once the cache was disabled; C's barely moved, because C was already
hitting the backend in both runs. That asymmetry is the signature of a cache that was
serving A and not C. The apparent 76% gap was the cache. What survives is 8.3%.

## The result

All figures are `mcp_tools_call_latency`, the metric the grader reads — not
`http_req_duration`, which is roughly 0.56 ms across every cell and is not the gated
quantity.

| cell | version | p50 | p50 spread | p99 | p99 spread |
|---|---|---|---|---|---|
| A | 3.5.0 | 0.6761 | 0.031 | 1.5252 | 0.093 |
| B | 3.5.1 | 0.6681 | 0.150 | 1.4668 | 2.549 |
| C | 4.0.0 | 0.7321 | 0.013 | 1.5146 | 0.138 |
| D | 4.0.0, modern era | 0.7491 | 0.035 | 1.5551 | 0.612 |
| E | 4.0.0, modern era, mixed | 0.8385 | 0.294 | 3.8150 | 4.706 |

Baseline `min(A.p50, B.p50)` = 0.6681, limit at the 5% budget = 0.7015.
Candidate C = **0.7321, which is 4.4% over the limit** — 8.3% slower than A, 9.6% slower
than B. p99 passes: 1.5146 against a 1.6135 limit.

**The overrun does not depend on which baseline you pick from this run's data.** B1 is a
contaminated rep (p50 0.5903 low, p99 4.9451 high against 1.4668/1.3933 in its siblings)
and it is currently *depressing* the baseline. Discard it and the baseline rises to 0.6734,
the limit to 0.7071 — still under C. Take A alone, the most stable legacy cell at 3.1%
spread, and the limit is 0.7099 — still under C. C is itself the most stable cell in the
run at 1.3% spread, so the candidate figure is the best-resolved number here.

That is a statement about re-analysing this run, not a prediction about the next one. A
re-run re-measures A and B, and the limit moves with them; it does not carry over. What
this run establishes is an observed overrun on three reps per cell, not a settled
expectation for future runs.

The grade is INCONCLUSIVE rather than FAIL because the stability gate trips first, on
`B.p50` 0.150 > 0.050, `B.p99` 2.549 > 0.100 and `C.p99` 0.138 > 0.100. Two independent
things must land for any verdict at all: a clean B, and a C whose p99 spread fits inside
the margin it is judged against.

## Shape of the regression

+0.056 ms at p50 (8.3%) against a 5% budget, but only +3.3% at p99 against a 10% budget.
A cost that lands on the median and not on the tail is more consistent with fixed per-call
overhead than with contention or queueing, which widen the tail first. That is a hypothesis
worth bisecting, not a diagnosis — three reps per cell, with B and C both failing the
stability gate, cannot establish a mechanism. What is on the release line either way: cell
C is `5e557e08`, an ancestor of `origin/main`.

## What D and E priced

C→D is **+2.3% p50** (0.7321 → 0.7491). That is the modern-protocol-era cost the D cell was
built to measure, and it has never been produced before. Both cells take the same
`SyncAdmission::Unprotected` arm — C via `!is_modern`, D via the read-only exemption — so
the delta is protocol handling for an unauthenticated read-only call. It is not evidence
about the authenticated retry path; the admission store is bypassed on both sides.

E's p99 spread of 4.706 (E3 alone reaches 12.3 ms) means the mixed-config cell is not
resolving anything at this rep count. D and E are report-only and do not enter the verdict —
`unstable` is computed over the legacy cells only — so neither figure affects the grade.

## Two things to file, neither fixable here

1. **The p50 budget overrun.** Release-line finding, needs a bisect between 3.5.1 and
   `5e557e08` and a decision from the release owner: fix the regression, or ratify a wider
   budget with the evidence attached.

2. **`spread()` cannot be satisfied by collecting more evidence.** It is `(max-min)/min`
   over the reps, a range statistic that widens monotonically with rep count. Raising N to
   beat the noise makes the stability gate *harder*, not easier, so the 10% p99 margin may
   be unreachable on this harness at any N. That is a gate-design defect. It is deliberately
   not fixed in this run: changing a release gate while grading against it is exactly what
   the ratification rule forbids.

## Provenance

`pins.json` records the k6 image digest and the per-cell checkout SHAs. D and E carry C's
SHA `5e557e08` and health version 4.0.0 — they are symlinks to C's build, so the C→D
comparison isolates protocol era against a byte-identical binary. The 145 raw artifacts —
per-rep `*.summary.json`, `*.meta.json`, `*.health.json`, gateway stdout/stderr and k6
output — are archived on Spark at `~/perf-workload/results/gating-2026-09-20c/`, outside
any checkout so they survive branch and worktree cleanup.
