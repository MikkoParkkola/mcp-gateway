# Design: replace the range-based stability gate (#614)

Status: proposed, pre-implementation. Scope is the stability gate in
`benchmarks/workload/eval_workload.py` only. Explicitly out of scope: the budgets
`P50_BUDGET` / `P99_BUDGET`, the baseline rule `min(A, B)`, the pooling function, and the
`check_rep` void conditions. None of those change.

## The defect

`spread(values) = (max - min) / min` (`eval_workload.py:130-132`) is compared against the
budget margin (`:176-187`) to decide whether a run can resolve the question it was asked.

The comparison is against the right *quantity* — the margin is 0.05 at p50 and 0.10 at p99 —
but `spread` is a **range** statistic. Each added repetition can only move `max` up or `min`
down. Its expected value under pure noise grows without bound in N (for a normal sample the
expected range grows roughly as `2σ·sqrt(2 ln N)`). So:

- The instinctive remedy for a noisy run — collect more repetitions — makes the gate
  **strictly harder**.
- There may be no N at which the gate is satisfiable on this harness. Passing it is a matter
  of getting lucky with 3 draws, not of gathering evidence.

A gate that cannot be satisfied by evidence is not a measurement gate. The 2026-09-20 run
tripped it on `B.p50` 0.150, `B.p99` 2.549 and `C.p99` 0.138, and recorded INCONCLUSIVE.

## What the gate is actually asking

The comment at `:174-176` states the intent exactly: "A per-rep spread wider than the margin
it is being judged against means the run cannot resolve the question." That is a question
about the **precision of the pooled estimate**, not about the dispersion of individual
repetitions. The verdict is computed from `pooled()` (the median of the reps), so the
quantity whose uncertainty matters is the median — and the uncertainty of a median shrinks
as roughly `1/sqrt(N)`.

Restated as testable properties. **P1 alone is not an acceptance criterion** — review
established that it admits degenerate statistics, since a constant 0 or `1/N` is also
non-increasing in N while measuring nothing. All three properties are required:

> **P1 (monotone in evidence).** Holding the distribution fixed, the statistic must be
> non-increasing *in expectation over repeated samples* at each N. This is a statement about
> the sampling distribution, not about any single run: a new repetition that reveals genuine
> spread may legitimately widen the interval, and must be allowed to.
>
> **P2 (calibrated coverage).** The interval must attain its stated coverage under explicit
> assumptions, verified by simulation against a known population — not assumed from an
> asymptotic formula.
>
> **P3 (resolving power).** The interval must be narrow enough to discriminate a difference
> of `margin`, otherwise a well-calibrated but useless gate passes P1 and P2.

`spread` violates P1. The first draft of this design satisfied P1 but failed P2, which is
what review caught.

## Proposal

Replace `spread` with the relative half-width of a **distribution-free order-statistic
interval** on the pooled median, and gate on that half-width fitting inside the margin.

For a sample of size `n` sorted ascending, the interval `[x_(k), x_(n+1-k)]` covers the
population median with exact probability `1 - 2·P(Binomial(n, 0.5) < k)`, under IID sampling
and no other distributional assumption. Pick the largest `k` whose coverage is still ≥ 0.95:

```
k              = max{ k : 1 - 2*binom_cdf(k-1, n, 0.5) >= CONF }     # CONF = 0.95
half_width     = (x[n-k] - x[k-1]) / 2
rel_half_width = half_width / pooled(values)
unstable if rel_half_width > margin
```

If no `k ≥ 1` satisfies the coverage requirement, the cell is **unstable by insufficiency**:
the sample cannot support a 95% interval at any width, and the gate says so rather than
inventing one.

The earlier draft used `t(0.95, n-1) · stdev/sqrt(n) · sqrt(pi/2)`. Review refuted it
empirically: 100,000 trials at n=3 from a bimodal population gave **85.5% coverage, not
95%** — the `sqrt(pi/2)` median-SE ratio is asymptotic and the normal approximation does not
hold at n=3. The order-statistic form has exact coverage by construction, at every n.

### The n=3 consequence, which is the release-relevant finding

At n=3 the widest available interval is `[min, max]`, `k=1`, whose coverage is
`1 - 2·(1/2)^3 = 0.75`. **No statistic on 3 repetitions can certify a 95% interval on a
median** — not this one, not a bootstrap, not the t-form. The smallest n for which even the
full-range interval clears 95% is:

| n | coverage of `[min, max]` = `1 - 2^(1-n)` |
|---|---|
| 3 | 0.750 |
| 4 | 0.875 |
| 5 | 0.9375 |
| **6** | **0.96875** ✅ |

So `REPS >= 6` is a **hard floor** for the gate to be able to return anything but
"insufficient", and a floor is not a target: clearing it only makes the interval *exist*,
not fit inside a 5% margin. The N that actually resolves 5% follows from the observed
dispersion and belongs in the rerun plan, not here. This is a harness requirement the old
gate concealed — `spread` returned a finite number at n=3 and read as a measurement.

### Why this and not the alternatives

| Candidate | P1 | P2 | Verdict |
|---|---|---|---|
| `(max-min)/min` (current) | No — grows in N | No — not an interval | The defect |
| IQR / median | No — flat in N | No | Population dispersion, not estimator precision |
| t-CI half-width on the median (first draft) | Yes | **No — 85.5% at n=3** | Refuted by simulation |
| Bootstrap CI on the median | Yes | Not at n=3 — resampling 3 points adds no information | Reconsider above n≈20 |
| Order-statistic interval (**proposed**) | Yes | Yes — exact under IID | Exact, deterministic, and honest about small n |

### Consequences to state plainly

This does **not** rescue the 2026-09-20 run, and cannot: at n=3 it reports insufficiency.
The fix makes the gate *reachable*, not the existing evidence *sufficient*. A verdict needs
a rerun at `REPS >= 6`.

**The IID assumption is stated, not assumed away.** Exact coverage holds if repetitions are
independent draws from one population. Benchmark reps are ordered in time and can drift
(thermal, cache warming, a noisy neighbour), which breaks it. The harness already discards
the A0 warm-up for this reason. Any drift beyond that biases coverage in an unquantified
direction, and detecting it is separate work — out of scope here, and recorded as a known
limitation rather than a solved problem.

## Test plan (failing tests first)

Tests are seeded and deterministic; the seed is a constant in the test file, and the
populations are synthetic with a **known** median, so each assertion has a ground truth
rather than a reference to whatever the harness happened to produce.

1. **Coverage calibration (P2).** Monte Carlo at n ∈ {6, 8, 10, 25} over several known
   populations — including the bimodal `0.49·U(0.99,1.01) + 0.51·U(1.99,2.01)` that refuted
   the first draft — asserting empirical coverage ≥ 0.95 minus Monte-Carlo error. This test
   fails against the t-form at 85.5% and is the reason the design changed.
2. **Expected monotonicity (P1).** Draw many independent samples at each N and assert the
   **mean** relative half-width is non-increasing in N. Explicitly *not* a per-sample
   assertion: appending `2` to `[1,1,1]` legitimately raises the half-width from 0 while the
   median is unmoved, and a test forbidding that would be asserting a false property.
3. **Resolving power (P3).** Two synthetic populations with known dispersion: one tight
   enough that the margin is resolvable at the tested N — assert **stable**; one too wide —
   assert **unstable**. This is the pair that a degenerate always-INCONCLUSIVE gate fails.
4. **Insufficiency floor.** n ≤ 5 reports unstable-by-insufficiency regardless of the values,
   *including* identical repetitions. This is a deliberate behaviour change: `spread` graded
   a zero-variance cell at n=3 as stable, and that was never a 95% statement.
5. **Degenerate input.** n=1 and a zero pooled value must fail closed, not raise — assert the
   existing `float("inf")` path is preserved.
6. **Verdict wiring.** Re-grade the archived 2026-09-20 run and assert both the exit status
   (2, INCONCLUSIVE) **and** that the recorded reason is insufficiency at n=3, not a spread
   comparison. The assertion is on the wiring, not on the old verdict being right.

## Fail-fast

The discriminating check is **test 3**, not the archived run. A gate that returns
INCONCLUSIVE unconditionally would satisfy "the archived run still fails" perfectly while
being useless, so that condition cannot be the correctness oracle — it only establishes
provenance, that the change did not retroactively turn an unresolved run green.

The change must not land if either half of test 3 fails: an adequately-precise population
that grades unstable means the gate cannot ever pass, and an insufficiently-precise one that
grades stable means it cannot ever fail.

## Dependency: the harness must be able to produce n ≥ 6

This change makes the gate *correct*; it does not make it *usable* on the current harness.
The rep count is hardcoded in two places:

- `benchmarks/workload/eval_workload.py:33` — `MEASURED_REPS = (1, 2, 3)`
- `benchmarks/workload/run_workload.sh:281` and `:286` — `for n in 1 2 3`

Both must rise together, and that is a **separate change** with a real cost: the run goes
from 3 warm-up + 9 compared (A/B/C × 3) + 6 report-only (D/E × 3) = 18 reps, to 3 + 18 + 12
= 33 reps at n=6. Interleaving must be preserved — the arms share Spark and have to see the
same machine conditions — so the reps cannot be parallelised away.

Merging that into this change would conflate a statistic fix with a benchmark-cost decision.
It is tracked separately in #615. Until it lands, this gate reports insufficiency on every run, which
is the accurate answer for a 3-rep sample and is strictly better than the current behaviour
of returning a number that reads like a measurement.

## Ratification note

This is a release gate. It is being changed **after** the 2026-09-20 run was graded,
archived and recorded, and **before** any subsequent scored run — never during grading. The
2026-09-20 verdict stands as recorded and is not re-derived under the new gate.
