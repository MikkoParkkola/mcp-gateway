# NFR.PERF.1 — the bisect cannot resolve the question it is being asked

Status: **finding, measured at source 2026-09-21.** Applies to the running bisect at
`spark:~/perf-workload/results/bisect-2026-09-21/`.

## The claim

Two independent problems, either of which alone invalidates the run:

1. **The verdicts near the budget are not reproducible.** Both BAD verdicts — the only
   two calls that set the bisect's direction — sit inside the measurement's own 95%
   confidence band.
2. **The BAD anchor coincides exactly with a change to the measurement procedure.** The
   symptom was first declared present at a commit that changed no gateway source and
   only changed how many reps the workload measures.

The run will still emit a "first bad commit". That commit will be an artefact.

## How the bisect decides

`bisect_step.sh` builds the candidate, runs it interleaved against a **fixed prebuilt
baseline binary** (`B_BIN=~/perf-workload/arms/B/target/release/mcp-gateway`, `:18`),
three reps each, and compares p50: `ratio = median(cand) / median(baseline)`, budget
`1.05`, `ratio <= 1.05` is GOOD (`:142-168`). The workload itself is driven from a fixed
`$HARNESS` directory through a pinned k6 image, **not** from the checked-out tree — so the
measurement procedure does not drift between steps. That part of the design is sound.

## Problem 1 — resolution

Noise is estimated two independent ways, and they agree.

**(a) Paired per-sample ratios** (`c_i / b_i`), which assumes nothing about the two arms
being independent: pooled CV across 9 steps / 27 pairs = **1.16%**.

**(b) The fixed baseline arm across steps.** Because `B_BIN` is the same binary every
step, the spread of baseline medians *is* run-to-run reproducibility, with no model at
all. Excluding the excursion below: 8 medians, mean 0.68947, sd 0.00799, **CV 1.16%** —
the same number from a completely different direction.

| quantity | value |
|---|---|
| paired-ratio CV / fixed-baseline CV | 1.16% / 1.16% |
| SE of a median of n=3 (`1.16·σ/√3`) | 0.78% |
| **95% CI halfwidth on one step's ratio** | **±1.52%** |
| highest GOOD (1.0487) to lowest BAD (1.0595) | 1.03% |

The separation between the GOOD and BAD populations is **smaller than the uncertainty on
a single measurement**. Pairing buys almost nothing (1.16% against a 1.30% mean
within-arm CV), which is itself a finding: interleaving is not cancelling shared
machine noise.

### Every verdict scored against its own band

| sha | ratio | dist from budget | 95% band | resolvable |
|---|---|---|---|---|
| `ad788585` | 1.0228 | −2.59% | [−4.11, −1.07] | yes — GOOD |
| `335198dc` | 1.0332 | −1.60% | [−3.12, −0.08] | yes — GOOD (barely) |
| `4009004e` | 1.0595 | **+0.90%** | [−0.62, +2.42] | **no — BAD is a coin flip** |
| `ce848ca9` | 1.0419 | −0.77% | [−2.29, +0.75] | no |
| `5b27f95c` | 1.0620 | **+1.14%** | [−0.38, +2.66] | **no — BAD is a coin flip** |
| `3776027e` | 1.0487 | −0.12% | [−1.64, +1.40] | no |
| `f0f10899` | 1.0442 | −0.55% | [−2.07, +0.97] | no |
| `81fe1875` | 1.0236 | −2.51% | [−4.03, −0.99] | yes — GOOD |
| `4302749f` | 1.0186 | −2.99% | [−4.51, −1.47] | yes, but see excursion |

**5 of 9 verdicts, including both BADs, could flip on a re-run.**

### One step ran under different machine state

Step `4302749f` measured its baseline at p50 **0.9024** against 0.68947 ± 0.00799 for the
other eight — a **+31% excursion, 26σ out**. Its ratio (1.0186) is the lowest of the nine
and it is the most recent step, so it carries disproportionate weight in the endgame. The
A/B interleaving did protect the ratio from the absolute shift, which is evidence the
design works — but the step should be re-run rather than trusted, because nothing
explains what else was on the box.

## Problem 2 — the anchors

`git bisect log` shows both endpoints were **declared, never measured under this
harness**:

| role | commit | what it changes |
|---|---|---|
| good | `e138680a` `chore(release): 3.5.1 (#476)` | version bump — CHANGELOG, Cargo.toml, Helm charts |
| bad | `dbd4deae` `feat(workload): measure six reps per cell and declare the sample (#618)` | `benchmarks/workload/run_workload.sh`, `benchmarks/workload/test_eval_workload.py` — **no Rust, no `src/`, no `Cargo.*`** |

A `git bisect bad X` marks where the symptom is *observed*, not what caused it, so a
non-code anchor is not by itself an error. But the BAD observation lands on precisely the
commit that **changed the measurement to six reps per cell**. The most parsimonious
reading is that the rep-count change moved the estimate across the budget line, not that
gateway code regressed somewhere in between.

That reading also explains Problem 1's data: if there were a real step change in the
code, the bisect should be separating GOOD from BAD by more than noise somewhere in 579
revisions. It never does.

Note the two procedures are not the same measurement: the anchor was declared under the
in-repo six-rep workload, while every bisect step runs three reps through the fixed
`$HARNESS` k6 path. Comparing verdicts across them is not valid.

## What would resolve it

Required per-arm sample count to separate a 1% effect at 95% with CV 1.16%, using the
paired quantity (no √2 — pairing already collapsed the two arms into one):
`√n = 1.96 · 1.16 · 1.16 / 0.5` → **n ≈ 28** (≈33 using the asymptotic `√(π/2)` median
factor rather than the n=3-specific 1.16). Against the current 3.

In order of what to do:

1. **Measure the two anchors** at n≈30 under the harness the bisect actually uses. This
   is two runs and it tests the premise everything else rests on. If `dbd4deae` is not
   reproducibly above budget under the k6 path, there is no regression to bisect and
   NFR.PERF.1 closes on measurement rather than a code fix.
2. **Re-measure the two BAD steps** (`4009004e`, `5b27f95c`) at n≈30, and re-run
   `4302749f`, only if step 1 confirms a real gap.
3. **Widen the budget** so the decision sits outside the noise band — a requirement
   change, and the release owner's call, not the measurement's.
4. Failing all that, record NFR.PERF.1's residual against a stated detection floor: this
   harness at n=3 cannot distinguish anything below roughly **7.5%** (budget + CI
   halfwidth).

Step 1 is the recommendation. It is the smallest experiment that can falsify the premise.

## Caveats

- The `1.16·σ/√n` factor for the SE of a median assumes approximate normality of the
  per-sample ratios; 27 pairs is not enough to check the tails.
- The fixed-baseline CV in (b) is the spread of step-level *medians*, so it corroborates
  the noise scale but is not a drop-in replacement for the within-step ratio band — the
  verdict is a per-step comparison against a fixed budget, so ±1.52% is the figure that
  governs it.
- None of this says a regression does not exist. It says this run cannot tell us.
