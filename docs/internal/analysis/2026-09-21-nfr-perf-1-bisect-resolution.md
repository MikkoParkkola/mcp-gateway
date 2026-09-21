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

## The bisect is answering a question the residual did not ask

`RELEASE-4.0.0-criteria-status.md:415` records what NFR.PERF.1 actually still owes. The
row is **PARTIAL**, its blocking flag was **lifted 2026-09-05**, and the release owner
ruled that 4.0.0 ships on the headroom argument (worst shared case +6.07% against a 10%
P99 bound). What survives that ruling is one residual:

> no P50 or P99 for this release may be quoted publicly until an end-to-end run produces one

The row also states plainly that the criterion bench cannot supply it — it measures
in-process component work, so there is no latency distribution to take percentiles from.
The k6 workload this bisect runs is the end-to-end harness built to close exactly that
gap (`#618`, the BAD anchor).

So the outstanding deliverable is **a quotable end-to-end P50/P99 for the release**, not
a regressing commit. A bisect cannot produce that number no matter how it converges. And
the two goals have very different costs: the bisect has already spent 9 steps × 8 runs =
**72 workload runs** and has produced no quotable percentile, while a single adequately
powered A/B — `HEAD` against `v3.5.0` (`32f135a6`), n≈30 per arm — costs about **60 runs**
and yields the number the residual demands, with an interval attached.

That measurement is also strictly more informative than the bisect: if it shows no
regression beyond budget at adequate n, the residual discharges and there is nothing to
bisect; if it does show one, it establishes a real, powered target and the bisect can be
restarted from anchors that were measured rather than declared.

**Recommendation, revised:** stop treating "find the regressing commit" as the task. Run
one powered end-to-end A/B at `HEAD` vs `v3.5.0`, n≈30, report P50 and P99 with
intervals. Bisect only if that run confirms a regression larger than the ±1.52% band.

## Caveats

- The `1.16·σ/√n` factor for the SE of a median assumes approximate normality of the
  per-sample ratios; 27 pairs is not enough to check the tails.
- The fixed-baseline CV in (b) is the spread of step-level *medians*, so it corroborates
  the noise scale but is not a drop-in replacement for the within-step ratio band — the
  verdict is a per-step comparison against a fixed budget, so ±1.52% is the figure that
  governs it.
- None of this says a regression does not exist. It says this run cannot tell us.
- **Within-pair order is fixed in both designs.** The bisect always ran the candidate
  first and the baseline second; the replacement run does the same with the release line
  and 3.5.1. If the machine warms measurably across a pair, the second arm inherits the
  warmer machine every time, which biases the ratio in one direction rather than
  averaging out. This does not invalidate the single-arm percentiles, which are the
  deliverable, but neither are they position-free: the release arm sat first in every
  pair, and that is recorded alongside the number rather than argued away. The caveat
  binds hardest on the drift-control comparison, which is why that arm is recorded as a
  control and not as a gate. **No direction is claimed for the effect.** An earlier draft
  argued the observed gap ran counter to a warming bias by assuming a warmer machine is
  slower; a later draft reversed that and called it consistent. Both readings were
  reaching for a sign the data cannot supply — in a continuously alternating sequence the
  warming argument is weak in either direction. What stands is the structural point: the
  order is fixed, so any release-line-vs-3.5.1 claim requires the order-reversal check
  below before it may be quoted.

## What the replacement run establishes, and what it does not

Three checks were run against the live measurement rather than assumed.

**Arm identity is verified, not trusted.** An adversarial review of the harness found
that the health probe confirms only that *something* answers on the shared port, so a
leftover process could in principle be scored as the release arm. The gateway's
`/health` response carries a `version` field, which turns that into a checkable fact:
every release-line rep recorded `4.0.0` and every control rep recorded `3.5.1`, with no
duplicate `rep,arm` rows and no VOID reps. The design weakness is real and worth fixing
before the harness is reused; it did not fire in this run.

**The interval is distribution-free, because a CV-based one would not be honest.** The
per-rep percentiles are reduced by `scripts/release/summarize-powered-ab.py` to a median
plus an order-statistic interval, with the realised coverage printed rather than rounded
to 95%. A normal error bar derived from the 1.16% CV — the obvious method, and the one
the harness comments reach for — assumes approximate normality with known spread. That
is defensible for a median of a dense sample and **not** defensible for P99, where each
rep's estimate rests on roughly the top 1% of its own requests. The order-statistic
interval assumes nothing, so one method covers P50 and P99 alike. It also reproduces the
known floor: at n=3 it yields no interval at all and the script refuses to quote.

**P99 between arms is a low-power null, not a finding of no difference.** The two P99
intervals overlap almost entirely. That is the same structure as the nine bisect
verdicts ruled unresolvable above — separation smaller than uncertainty — and it must be
written as *this run cannot distinguish P99 between arms at this n*, never as *P99 is
unchanged*.

Two further limits bind the write-up:

- **The single-arm percentiles are the deliverable, and the position they were measured
  in is disclosed rather than argued away.** The release arm occupied the first slot of
  every pair, so its absolute number carries whatever position effect the sequence
  imposes; that is a stated property of the quoted figure, not a defect in it. The
  residual asks that an end-to-end run *produce* a P50 and a P99, not that it produce a
  position-effect-free steady-state estimate. The release-line-against-3.5.1 *ratio* is a
  different claim: it is the quantity the fixed order actually threatens, and it is
  quotable only after a reversed-order block confirms it.
- **The component bench's 10% P99 bound does not govern this number.** That bound was
  written for `session_sandbox/check_tool_denied`, in-process work at roughly 86
  nanoseconds; this run measures end-to-end request latency at roughly 0.7
  milliseconds. Grading one against the other repeats exactly the incomparable-procedure
  error that invalidated the bisect anchors.

## Result — the run completed 2026-09-21

Twenty pairs, 1,300,456 requests, both arms at n=20. The release line is commit
`e82d7ee46b8e6edccfb1c1bee0f8bb8526194e5b`, which is **13 `src/` commits ahead of
`a2505be0`**, the commit `NFR.PKG.1` names as the release cut point. The number below
belongs to the commit it was measured at, and is quoted that way.

| arm | reps | requests | P50 (95% CI) | P90 | P95 | P99 (95% CI) |
|---|---|---|---|---|---|---|
| release line `e82d7ee46b` | 20 | 650,804 | **0.7310** [0.7140, 0.7543] | 1.3062 | 1.8543 | **2.8756** [2.6615, 3.1234] |
| 3.5.1 drift control | 20 | 649,652 | 0.6758 [0.6526, 0.6999] | 1.2212 | 1.7128 | 2.7640 [2.5869, 3.9305] |

All figures in milliseconds; realised interval coverage 0.959, printed rather than
rounded to "95%".

**The contention event did not move the estimate.** A peer build took load average from
7.09 to 19.76 mid-run; two reps degraded to p99 10.46 ms with a 51 ms max. No rep was
dropped — filtering on observed values after seeing them is outcome-dependent and
corrupts the interval as thoroughly as the contention would. The pre-specified clean
prefix (reps 1-14) is the disclosed sensitivity check and agrees: P50 0.7261
[0.7113, 0.7543], P99 2.7218 [2.6143, 2.9111]. The order-statistic interval absorbed the
excursion; the separately printed observed spread (P99 up to 17.44 ms on the release arm,
22.57 ms on the control) keeps the event visible instead of buried.

**Arm identity was checked, not assumed.** Every rep's `/health` `version` field was
recorded: 20 reps `4.0.0`, 20 reps `3.5.1`, exactly two distinct arm/sha combinations
across the CSV, no duplicate `rep,arm` rows, no VOID reps. Note the summariser prints only
the first row's sha per arm, so the uniqueness check is a separate pass over the file
rather than something the tool guarantees — worth folding into the script before reuse.

**The paired ratio, not the disjoint intervals, is the figure to read.** An earlier pass
reported that the two P50 intervals are disjoint (0.6999 < 0.7140). That is true but it is
the unpaired read of a paired design: the arms are interleaved within a rep, so comparing
two independently-computed per-arm intervals throws away the pairing that the run was
built to exploit. Keyed by arm, the per-rep ratio `p50_rel / p50_b` gives **1.0885, 95% CI
[1.0726, 1.1125]**, with 18 of 20 reps above 1.0. P90 is 1.0622 [1.0403, 1.1252] and P95
1.0938 [1.0493, 1.1296]. P99 is **1.0520 [0.9823, 1.0649]**, 14 of 20 above — the interval
covers 1.0, so P99 remains the low-power null described below and the paired view does not
rescue it.

The ratio is defined on the arm, never on the slot position. That is what makes a
reversed-order block comparable at all: a position-keyed ratio inverts silently when the
order flips, and nothing in the output would mark it as inverted.

This is **not** yet a code effect. The release arm held the first slot in every pair, so
the forward ratio carries code and position together. Under multiplicative effects the
reversed block yields the complementary combination, so the geometric mean of the two
median ratios isolates the code effect and the square root of their quotient isolates the
position effect. That block has since run, and the next section reports it: 1.0885 was an
upper bound on the code difference at the time it was written, and the crossover puts the
code effect at +8.73% with position contributing +0.12%. It is worth noting either figure
is larger than the +6.07% component-bench figure the release owner ruled on.

One disclosure about that block: the CSV schema carries no load column, so its contention
detection is coarser than this run's. The excursion here was caught by watching load
average from outside the harness, and the reversed block inherits the same external-only
view rather than a per-rep record. It reuses the identical two binaries — the `rel` arm is
pinned to the same sha rather than rebuilt from a branch name, and the summariser now
rejects an arm whose reps span more than one sha, so a silently moved control fails the
run instead of passing unnoticed.

## The reversed block resolved it: the P50 gap is code, not measurement position

Six pairs ran with the arms reversed (`b` first in every rep), pinned to the same two
binaries. Cross-block identity was checked rather than assumed: both CSVs carry exactly
`rel = e82d7ee46b8e6edccfb1c1bee0f8bb8526194e5b` and `b = v3.5.1`, so the crossover
compares the same pair of builds in both orders.

| block | order | pairs | P50 paired ratio | reps above 1.0 |
|---|---|---|---|---|
| forward | `rel` first | 20 | 1.0885 [1.0726, 1.1125] | 18/20 |
| reversed | `b` first | 6 | 1.0860 [1.0762, 1.1149] | **6/6** |

Under multiplicative effects the forward ratio carries code × position and the reversed
one carries code ÷ position, so:

- **code effect = √(1.0885 × 1.0860) = 1.0872, or +8.73%**
- **position effect = √(1.0885 ÷ 1.0860) = 1.0012, or +0.12%**

Position is nil. The two blocks agree to within 0.25% on a quantity that would have
diverged in opposite directions had slot order been driving the gap, which is the specific
thing the reversed block was run to test. The release line is genuinely slower than the
3.5.1 control at P50 by roughly 8.7%, and that is **2.7 percentage points above the
+6.07% component-bench figure the release owner ruled on**.

Two limits on that conclusion, both real:

**It is P50 only.** In the reversed block P90, P95 and P99 all split 3/6 with intervals
spanning 0.53 to 2.59 — noise, not signal. The tail says nothing at this n and should not
be quoted either direction.

**The reversed block ran contended.** Load average reached 17.50 and one control rep
recorded p99 22.4 ms against a max of 83.8 ms. No rep was dropped, because deciding to
discard reps after seeing their values is the same outcome-dependent filtering that
corrupts an interval. The relevant observation is that the P50 ratio came through anyway —
unanimous at 6/6 and within 0.25% of the forward block measured at roughly half the load.
That is the paired design doing its job: contention inside a rep hits both arms and
largely divides out, which is exactly why the ratio is the figure to read and the per-arm
percentiles are not.

At n=6 the order-statistic interval degenerates to [min, max], so the interval printed for
the reversed block is not doing inferential work. The unanimous sign is: 6 of 6 on one
side of 1.0 is p ≈ 0.031 under the null, which is the only outcome at this n that carries.

**P99 between the arms is a low-power null.** The intervals overlap heavily. This run
cannot distinguish P99 between arms at this n — which is a statement about the run, not a
finding that P99 is unchanged, and it has the same shape as the nine bisect verdicts ruled
unresolvable above.
