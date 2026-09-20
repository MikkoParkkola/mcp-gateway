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
down, so it is **pathwise non-decreasing in N**: it never shrinks, for any sample, ever.

- The instinctive remedy for a noisy run — collect more repetitions — makes the gate
  **strictly harder**. A cell that failed cannot be rescued by more evidence; only by a
  luckier draw.
- Planning a larger N to "settle" a noisy result makes a fresh pass *less* likely, which is
  the exact opposite of what the plan intends.

Stated precisely, because an earlier draft of this document overstated it: the gate is **not**
unsatisfiable. The 2026-09-20 run passed it on three cells — A.p50 at 0.031, A.p99 at 0.093
and C.p50 at 0.013, all inside their margins. The defect is not that passing is impossible;
it is that passing is a property of the draw rather than of the evidence, and that the one
lever an engineer has — run it more times — pushes the wrong way.

A gate whose pass probability *decreases* in the amount of evidence is not a measurement
gate. The 2026-09-20 run tripped it on `B.p50` 0.150, `B.p99` 2.549 and `C.p99` 0.138, and
recorded INCONCLUSIVE.

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

> **P1 (monotone in evidence).** ~~Holding the distribution fixed, the statistic must be
> non-increasing *in expectation over repeated samples* at each N.~~ **WITHDRAWN — see
> "P1 is false for this statistic" below.** The replacement property is stated there.
>
> **P2 (calibrated coverage).** The interval must attain its stated coverage under explicit
> assumptions, verified by simulation against a known population — not assumed from an
> asymptotic formula.
>
> **P3 (resolving power).** The interval must be narrow enough to discriminate a difference
> of `margin`, otherwise a well-calibrated but useless gate passes P1 and P2. Note this is
> stated about a *comparison between two cells*, while the gate evaluates *one cell's
> precision*; two cells each at half-width 0.049 feed a ratio carrying roughly twice that
> uncertainty. Resolved by narrowing P3 to per-cell precision and tracking the comparison
> question separately — the gate's job is to refuse to grade an imprecise run, not to
> perform the comparison.

`spread` violates monotonicity pathwise. The first draft of this design satisfied it in
expectation but failed P2, which is what the first review caught. The order-statistic form
satisfies P2 exactly — and, as recorded below, does **not** satisfy monotonicity either.

### P1 is false for this statistic, and the design does not hide it

The interval's rank `k` is an **integer**, and it is constant across runs of `n`. Largest `k`
whose coverage still clears 95%:

| n | k | coverage |
|---|---|---|
| 3–5 | — | insufficient |
| 6, 7, 8 | 1 | 0.969, 0.984, 0.992 |
| 9, 10, 11 | 2 | 0.961, 0.979, 0.988 |
| 12, 13 | 3 | 0.961, 0.978 |

Inside a plateau `k` is pinned, so the interval **is the range**, and its expected width grows
with `n` exactly as `spread` does. Measured mean relative half-width, `Gauss(1, 0.02)`,
20,000 trials, seed 614:

| n | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 |
|---|---|---|---|---|---|---|---|---|
| mean | 0.02538 | 0.02705 ↑ | 0.02855 ↑ | **0.01866** | 0.02001 ↑ | 0.02125 ↑ | **0.01590** | 0.01703 ↑ |

The statistic is a **sawtooth**: rising within each plateau, dropping only when `k`
increments. So P1 as originally written is false, and the honest replacement is narrower:

> **P1' (evidence eventually helps).** The statistic must be non-increasing in expectation
> **along the subsequence of `k`-increments** — n = 6 → 9 → 12 — and the gate's documented
> guidance must direct reruns to those n, not to intermediate values.

This is weaker than what the design first claimed, and it is a genuine limitation rather than
a restatement: at n = 6, 7, 8 the pathwise-non-decreasing defect that motivated this whole
change **survives**. What n ≥ 6 buys is *exact coverage*, not shrinkage. The first `n` at
which more evidence can actually narrow the interval is **n = 9**.

An alternative that would restore true monotonicity is to interpolate between order
statistics (Hettmansperger–Sheather) rather than snapping `k` to an integer. That trades
exact coverage for approximate coverage and is not taken here; it is recorded as the option
to revisit if the sawtooth proves operationally confusing.

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

`spread` is **retained as a reported diagnostic**, just no longer as the gate. It is the
signal that makes a dirty Spark run legible — a cell whose range blows out while its
interval stays tight is a machine-conditions story, not a code story — and dropping it would
cost that visibility for nothing. Both appear per cell in `report["cells"]`; only the
interval decides the verdict.

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

**n ≥ 6 buys exact coverage, not shrinkage.** Because the interval rank `k` stays at 1 for
n = 6, 7 and 8, the interval there *is* `[min, max]` and still widens with every added
repetition. The first n at which more evidence can narrow it is **n = 9** (`k` = 2). A rerun
commissioned at 6 would pay double the benchmark cost for an honestly-calibrated statistic
that is no more resolvable than today's. See "P1 is false for this statistic" above.

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
2. **Observed k-plateau sawtooth — explicitly NOT P1.** P1 is withdrawn above, so this test
   pins what the statistic actually does instead of a property it lacks: the `n → k` table
   with its exact closed-form coverage, the mean half-width *rising* inside each k-plateau
   (6→7, 7→8, 9→10, 10→11, 12→13), and *dropping* at each k increment (6→9, 9→12). Choosing
   an n-grid that makes a monotonicity assertion pass would hide the defect — that grid was
   written once and removed, and this note exists so it is not written again. The narrower
   P1' is covered by the k-increment drops.
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
It is tracked separately in #615, which also owns deriving the N that actually resolves each
margin from the observed dispersion — n=6 is the coverage floor, and the p99 margin will
plausibly need more than the p50 one. Commissioning a rerun at the floor alone risks a second
ungradeable run. Until that lands, this gate reports insufficiency on every run, which
is the accurate answer for a 3-rep sample and is strictly better than the current behaviour
of returning a number that reads like a measurement.

## Ratification note

This is a release gate. It is being changed **after** the 2026-09-20 run was graded,
archived and recorded, and **before** any subsequent scored run — never during grading. The
2026-09-20 verdict stands as recorded and is not re-derived under the new gate.
