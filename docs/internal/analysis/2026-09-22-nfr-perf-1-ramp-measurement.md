# NFR.PERF.1 — where the P50 regression comes from: a ramp measurement

**Date:** 2026-09-22 · **Host:** Spark (20 cores, aarch64) · **Status:** RESULTS PENDING

Supersedes the attribution attempt in
`2026-09-21-nfr-perf-1-bisect-resolution.md`. That bisect's verdict is an
artefact and is not cited here as evidence for anything.

---

## 0. Why not another bisect

A `git bisect run` on 2026-09-21 named a merge commit. Four things say the
verdict was noise, not signal:

| Observation | Value |
|---|---|
| Commit classified BAD with zero `.rs` files changed (`4009004e`, 9 lines of markdown) | ratio 1.0595 |
| Docs-only commits *descending from* the alleged culprit that measured **better** | 3 of them; best 0.9994 |
| Spearman correlation of commit date vs ratio across all 12 tested commits | rho = 0.105 |
| Worst BAD ratio vs the independently measured effect | 1.0660 vs 1.0873 — never reproduced |

Root cause: `bisect_step.sh` took the **median of 3 reps** per arm against a
1.05 threshold. The decision band was ~1 percentage point wide while
within-step scatter reached 34% between consecutive reps of the same binary.
Every step was close to a coin flip, and one flipped step sends bisection into
the wrong half permanently and silently.

Bisection also **assumes a step change**. If the effect is spread across many
commits, bisection converges on wherever the running total crosses the
threshold — a fact about the threshold, not about the code. Establishing
*which* of those two worlds we are in is the point of this measurement, so the
method must not presuppose either.

---

## 1. Method

### 1.1 Shape, not culprit

Six binaries are measured **in one rotated round-robin**: each cycle touches
every arm exactly once, and the arm that goes first rotates by one slot each
cycle. Launch order, `n = 18` cycles:

```
ARMS="A B P3 Aprime P4 REL"   REPS=18
```

| Arm | Commit | First-parent index from v3.5.0 | Role |
|---|---|---|---|
| `A` | `32f135a6` (v3.5.0) | 0 | denominator — the baseline `NFR.PERF.1` actually names |
| `B` | `e138680a` (v3.5.1) | 27 | ties this run to the existing +8.73% number |
| `P3` | `c8803f06` | 69 | ramp point |
| `Aprime` | `32f135a6` | 0 | **byte-identical copy of `A`** — self-versus-self control |
| `P4` | `9e5a5651` | 92 | ramp point |
| `REL` | `35d94814` | 115 | release line (`origin/main`) |

Five measured points at indices 0/27/69/92/115. Two further binaries were built
and **deliberately not measured**: index 23 (`2ff8fedc`), which sits 4 commits
from `B` and would have added 17% to every cycle for no resolution gain; and
index 46 (`bd1adbb4`), which cannot be measured at all (§1.8). On a host where
cycle duration *is* the noise mechanism, shorter cycles are worth more than a
redundant point.

`Aprime` sits at **cyclic distance 3 = `NARM`/2 from `A`** — §1.3 explains why
that placement, and not "the far end of the list", is what the control needs,
and §1.3.3 explains the one thing that placement cannot detect.

**Where 4.0.0 begins.** `Cargo.toml` steps 3.5.0 → 3.5.1 at first-parent index
27, and 3.5.1 → **4.0.0 at index 39**. So question 3 ("does the regression
predate 4.0.0?") is answered by **`B/A`**, not by any segment boundary: `B` is
v3.5.1, the last release *before* the 4.0.0 development line opens. Any excess
in `B/A` is regression that 4.0.0 inherited rather than caused. With index 46
unmeasurable, index 39 falls inside the merged `B`(27) → `P3`(69) segment, so
that segment straddles the version boundary and cannot be attributed to either
line.

Read the shape of the point ladder:

- **step** — one segment jumps and every later point stays up;
- **ramp** — a monotone rise spread across many segments;
- **noise** — flat scatter, no trend.

None of the three is distinguishable at n=3. All three are at adequate n.

### 1.2 Equal commit counts are not equal weight

The arms are spaced evenly by **commit count**, which is a property of the
x-axis and not of the code. A reader who sees equal per-segment ratios on an
evenly-spaced axis will infer a uniform ramp that may not exist. So every
segment is reported with its source-diff volume and its dependency churn
alongside its ratio:

| segment | commits | `src/**.rs` lines +/− | `Cargo.lock` commits |
|---|---|---|---|
| idx0→27 (v3.5.0 → v3.5.1) | 27 | 2,792 / 240 | 6 |
| idx27→46 | 19 | 36,954 / 1,968 | 3 |
| idx46→69 | 23 | 70,792 / 2,955 | 6 |
| idx69→92 | 23 | 7,024 / 1,259 | **0** |
| idx92→115 | 23 | 1,706 / 837 | 4 |

Two things fall out of this table before any measurement:

- **Segment idx46→69 carries 25× the source churn of idx0→27 for a comparable
  commit count.** A "ramp" that is really one heavy segment plus three light
  ones is a step wearing a ramp's clothes, and only this column distinguishes
  them.
- **idx69→92 is the one window with zero dependency churn.** It is therefore
  the only segment where a ratio can be attributed to gateway source rather
  than to a dependency bump. Everywhere else, source and lockfile move
  together and a step landing there implies a *dependency* bisect, which is a
  different investigation from a source one.

### 1.3 What the interleaving buys, and what it does not

The interleaved A/B structure is inherited from `bisect_step.sh` — it is the
part of that script that was right, and it held the position effect to +0.12%
in the reversed-pair control. Only `n` was wrong.

**Within-cycle drift is the dominant noise term on this host, not rep-to-rep
scatter.** The clearest single measurement of it comes from a run that was
killed and is retained as evidence at `results/ramp-v1-slotbug/`: in its cycle
4, `REL` at slot 2 read **1.226 ms** while `A` at slot 4 read **0.947 ms** —
a ratio of **1.29**, a 29% "regression" manufactured entirely by position,
between two binaries whose real difference is a few percent. A CI burst decayed
across that one cycle.

That fact reframes the whole measurement, and it retroactively explains the
bisect: median-of-3 at uncontrolled time separation was sampling a
29%-capable position effect against a 5% budget.

**The general invariant, which is the one worth remembering:**

> **Rotation neutralises position and nothing else.** Every *cyclic*
> relationship is invariant under it — predecessor, successor, and the distance
> to any fixed arm. Rotating the start arm changes which slot an arm occupies
> and changes nothing else about its neighbourhood.

That single sentence would have prevented all three errors made in building this
measurement. They were all the same mistake: fixing position and assuming the
rest followed.

**What to do about it, and these are not two constraints but two eras:**

- **This run used rotation**, with `Aprime` at cyclic distance `NARM/2` from `A`
  (3 of 6), giving a constant 3-slot separation. Because each test arm's
  separation alternates between `d` and `NARM−d`, every test arm averages
  exactly 3 too — so the control matched the *mean* separation of the arms it
  bounds. That is the best rotation can do.
- **Future runs should use `RANDOMIZE=1`**, which draws a fresh permutation per
  cycle. This **subsumes and replaces** the constant-distance rule; the two are
  mutually exclusive, because under a fresh permutation the `Aprime`-to-`A`
  separation is a random variable and cannot also be a constant 3.

Randomisation is strictly better, and the reason is worth stating precisely:
under a fresh permutation `Aprime` **samples the same separation distribution as
every test arm**, rather than merely matching its mean. Matching a mean bounds
the average case; sampling the same distribution bounds the whole of it,
including the tail cycles where drift is worst — which on this host are the
cycles that matter. Randomisation also removes the fixed-predecessor problem,
which rotation cannot touch at any distance.

**Do not reintroduce the constant-distance rule as an extra constraint on top of
randomisation.** It would silently defeat it.

Both errors were found the hard way. The adjacency one was found after a run had
already started: placing `Aprime` at the far end of the *list* puts it
immediately *before* `A` in the *cyclic* order, so it was adjacent to `A` in six
cycles out of seven — the killed run's slot table reads 6, 1, 1, 1. A validity
gate measured at *tighter* separation than the arms it bounds is worse than no
gate, because it produces confident output.

### 1.3.1 A settling transient, and what it implies about the kept set

`Aprime/A` over the first six cycles, against that cycle's 1-minute load
average:

| cycle | load1 | `Aprime/A` |
|---|---|---|
| 1 | 21.57 | 0.8971 (excluded by rule (c)) |
| 2 | 10.40 | 0.9499 |
| 3 | 10.53 | 0.9568 |
| 4 | 9.22 | 0.9887 |
| 5 | 8.62 | 0.9953 |
| 6 | 7.12 | 1.0081 |

Two byte-identical binaries (sha256 `809093be…` for both, and both report
`mcp-gateway 3.5.0` to `--version`), so the spread is environmental.

**The fixed-predecessor hypothesis is LIVE, not refuted.** An earlier draft of
this section claimed the opposite, and the claim did not survive cycle 7.

`Aprime/A` by cycle: 0.897, 0.950, 0.957, 0.989, 0.995, 1.008, **0.817**.

The refutation rested on the first six points looking monotone: the predecessor
was `REL` in every one of cycles 2–6 (`A` occupied slots 5, 4, 3, 2, 1, never
slot 0), and a constant cause cannot produce a trend. That argument is valid
only if the movement *was* a trend. Cycle 7 says it was scatter — and on
scatter, "fixed bias plus noise" explains the whole sequence.

The mean is also persistently off: **`Aprime/A` averages ~0.95 and sits below
1.0 in six of seven cycles.** An earlier draft attached a one-tailed sign-test
p-value to that (8/128 ≈ 6.25%) — **that argument is withdrawn.** A sign test
assumes independent observations, and these cycles are documented in this very
section as serially correlated by load and drift. A sign test on correlated
observations overstates its own significance, so it is not leaned on.

The correct framing needs no p-value at all. **`A` and `Aprime` are
byte-identical**, so *any* systematic `Aprime/A ≠ 1` is measurement artefact by
construction. The live question is therefore not "is the control biased" — it
must be — but **which artefact carries it**. Slot, predecessor and load are
recorded per rep, so that is answerable.

### 1.3.2 Which artefact carries the deficit — diagnosis, not inference

**This subsection is post-hoc and does not touch the verdict.** Explaining an
artefact after seeing it is legitimate; *deciding* a verdict after seeing it is
not. The verdict stays on the pre-registered rule in §1.3.1 and is reported in
§5.

| cycle | `load1` | `A` slot | `A` predecessor | `Aprime/A` |
|---|---|---|---|---|
| 1 | 21.57 | 0 | *cycle head* | 0.8971 (excluded) |
| 2 | 10.40 | 5 | `REL` | 0.9499 |
| 3 | 10.53 | 4 | `REL` | 0.9568 |
| 4 | 9.22 | 3 | `REL` | 0.9887 |
| 5 | 8.62 | 2 | `REL` | 0.9953 |
| 6 | 7.12 | 1 | `REL` | 1.0081 |
| 7 | 13.53 | 0 | *cycle head* | 0.8170 (excluded) |

Three readings, in descending order of support:

- **Position accounts for the variation.** `Aprime/A` is monotone in `A`'s slot
  across cycles 2–6 — slot 5 → 0.950, 4 → 0.957, 3 → 0.989, 2 → 0.995, 1 →
  1.008 — and in every one of those cycles `A`'s predecessor is `REL`, held
  constant. So slot explains the variation *with predecessor fixed*, which
  predecessor cannot.
- **Predecessor is confounded with the cycle head and cannot be separated
  here.** `A` is either at slot 0 (no in-cycle predecessor) or preceded by
  `REL` — there is no third case in this design. So this run cannot rule a
  predecessor effect in or out; it can only say position accounts for the
  observed variation without needing one. `RANDOMIZE=1` (§4a) separates them.
- **The two extreme cycles are the two highest-load cycles.** Cycles 1 (load
  21.57) and 7 (load 13.53) carry the two most extreme readings, and both were
  excluded by rule (c) independently of this analysis.

**Retracted: an earlier draft claimed "slot 0 is the slow slot".** That was
arm-confounded — and the analyzer's own CONFOUNDED warning (§1.5) was printing
at the time, saying exactly that. **A guard that fires and is ignored is a
different failure from a guard that never fires, and only one of them is fixed
by writing more guards.** Estimated properly, pooled across all six arms with
each cycle normalised by its own geometric mean so cycle-level drift cannot
leak in:

| slot | 0 | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|---|
| relative cost | 1.000 | 1.016 | 0.970 | 1.012 | **1.037** | 0.982 |

Non-monotone, 6.9% spread, and **slot 0 is unremarkable**. Slot 4 is the
slowest. The single-arm reading that produced the retracted claim was noise.

### 1.3.3 Median pooling retains a position term — mechanism real, magnitude not established

A multiplicative position cost enters each paired ratio as
`cost(slot_X)/cost(slot_A)`. Two facts about that, established noiselessly
against the measured profile:

- **Geometric-mean pooling over a complete rotation cancels it exactly**
  (0.0000% error). Over a full rotation `slot_A` takes every value once, so
  `∏cost(s+k) = ∏cost(s)`.
- **Median pooling does not, and the residual is deterministic** — identical at
  6 and 18 cycles, so more rotations never remove it. In a position-only world
  with *zero* code difference and the measured profile, median pooling
  manufactures `B` 1.0168, `P3` 0.9836, `P4` 1.0169, `REL` 0.9835: a spurious
  `P3`→`P4` step of **+3.33pp** and a `P4` > `REL` gap of **3.34pp**.

**The consequence that stands regardless of magnitude: the control is blind to
this class of error by construction.** `Aprime` sits at `k = NARM/2 = 3`, the
unique geometry whose median bias is ~0 (+0.01%). Distance 3 was chosen for
separation (§1.3); that it is also the one position immune to this bias is
coincidence. **So a passing G1 certifies nothing against position bias in the
test arms.** That is a genuine hole in the gate.

**But the effect is not measurable on this host at this `n`.** The load-bearing
evidence is a direct measurement with a clear scale:

- **Median and geometric mean agree to ≤0.24pp on live data** for every test arm
  (largest: `REL`, −0.0024), against the **±1.7%** the noiseless model predicts
  for the measured profile. The two estimators differ by a factor of ~7 less
  than the effect would require. This is the number to cite.

Supporting, and weaker than it first appears:

- The slot profile does not replicate across a split-half of the complete
  cycles (Pearson r = −0.868). **This figure should not be quoted as
  diagnostic.** Per-cycle normalisation forces the six slot deviations to sum to
  ~0, which induces a negative split-half correlation under *pure noise* of
  about `−1/(k−1) ≈ −0.2`; and the estimate itself rests on splitting 8 cycles
  into 4 and 4, which is far too thin to distinguish −0.87 from −0.2 with any
  confidence. It is consistent with "no stable profile" and is not evidence for
  it beyond that.

So no correction is applied. What ships instead is a **cross-check**:
geometric-mean pooling runs always, on the pre-registered balance-exact subset,
reported **alongside** the median and never instead of it, with **no interval
claimed for it** rather than fabricating one. If the two agree, position bias is
not driving the result — and the check is informative precisely because it could
have disagreed and did not.

The geometric-mean cancellation requires *complete* rotations, which is exactly
what the pre-registered secondary window provides. That window therefore has a
second, independent justification it did not have when it was registered.

Two methodological lessons, both recorded against this measurement rather than
explained away:

- A six-point apparent trend on a host already documented as swinging load
  13 → 48 was never strong enough to carry a structural conclusion.
- The pre-registered slope statistic **inverted from +0.0207 to −0.0031 on the
  arrival of one observation**. A statistic that flips sign on a single data
  point is measuring noise, not trend. That instability is itself the finding
  about this host.

An earlier draft also used "flat versus decaying" as the discriminator, which
was wrong for a different reason: page-cache and CPU-frequency carry-over decay
as load falls, so a predecessor effect would *also* decay and both hypotheses
predicted the same curve.

**A rising ratio is `A` speeding up, not `Aprime` slowing down.** The ratio
alone cannot distinguish those, so the raw medians are reported:

| cycle | `A` | `Aprime` |
|---|---|---|
| 1 | 0.7886 | 0.7075 |
| 2 | 0.7319 | 0.6953 |
| 3 | 0.7210 | 0.6898 |
| 4 | 0.7277 | 0.7195 |
| 5 | 0.7230 | 0.7196 |
| 6 | 0.6931 | 0.6987 |

An earlier draft read this as a slot-0 effect — `A` hit slot 0 in cycle 1
(0.7886, its worst reading) and `Aprime` hit slot 0 in cycle 4 (0.7195, its
worst). **That reading is retracted**: pooled properly across all six arms,
slot 0 is unremarkable and slot 4 is the slowest (§1.3.3). Two single-arm
observations were not evidence of a position profile, and the analyzer's own
CONFOUNDED warning was telling me so at the time.

**The settledness call is made by a pre-registered rule, not by reading the
sequence** — precisely because reading the sequence is what went wrong above.
Fixed in `analyze_ramp.py` before cycle 7 existed: the statistic is the OLS
slope of `Aprime/A` on cycle index plus the mean over the final `NARM` cycles;
`|slope| ≤ 0.005`/cycle with `|mean − 1| ≤ 0.02` reads SETTLED, flat-but-off
reads BIASED, `|slope| > 0.005` reads DRIFTING and makes every ratio
provisional, anything else reads AMBIGUOUS. All four branches were checked
against synthetic data before shipping.

**A disclosed defect in that rule, left uncorrected on purpose.** It computes
the slope over *all observed* cycles, including cycle 1 — which rule (c) already
excludes for drift. A drift-trend statistic therefore counts a cycle rejected
for drift. On kept cycles only, the slope is −0.0144 rather than −0.0031. The
registered version is the one reported; the kept-only figure is a labelled
sensitivity check and **not** a substitute. Switching after seeing which answer
each version gives is exactly what pre-registration exists to prevent. Fix it in
the next pre-registration, not this one.

**The shape survives the denominator being under suspicion — but it is not a
clean ramp.** `Aprime` is byte-identical to `A`, so it is an independent second
baseline measured in the same cycles. Swapping the denominator shifts every arm
up and leaves the ordering unchanged. Interim values at 5 kept cycles, to be
recomputed at final `n` in §4:

| arm | X/`A` | X/`Aprime` | delta |
|---|---|---|---|
| `B` (idx 27) | 1.0130 | 1.0214 | +0.008 |
| `P3` (idx 69) | 1.0838 | 1.1316 | +0.048 |
| **`P4` (idx 92)** | **1.1609** | **1.1720** | +0.011 |
| `REL` (idx 115) | 1.1010 | 1.1136 | +0.013 |

**`P4` sits above `REL` under both denominators.** Between index 92 and index
115 the measurement gets ~5 points *faster*, so the ladder is **not monotone**
and this is not a clean ramp. At this `n` that gap is inside the resolvable
effect and is most likely scatter — but it is stated rather than smoothed,
because a reader given "`B` lowest, 4.0.0-era arms 8–17% above" will infer a
monotone rise the numbers do not show.

What *is* robust is the **ordering under either denominator**: `B` lowest, the
4.0.0-era arms well above it. That is a statement about invariance to a design
choice, and it does **not** depend on G1 passing — a bias common to both
denominators cannot reorder the arms. It therefore gets its own verdict line in
§5, separate from the gate outcome.

Note a mechanical point that looks like an inconsistency and is not:
`(B/A)/(Aprime/A)` = 1.0130/0.9660 = 1.0487, while the directly-pooled
`B/Aprime` = 1.0214. These disagree because the identity holds **per cycle but
not after taking medians** — `median(x/z) ≠ median(x/y)/median(y/z)`. Ratios
are pooled per cycle by design, so the algebraic identity is *expected* to fail
on pooled values. It is not an arithmetic error.

What the drift *does* track is **load**: position cost runs ~10% at load 21.6
and ~1% at load 7.1. Same mechanism as the 29% artefact above, measured as a
dose-response rather than a single anecdote, and what rule (c) was written to
catch.

**The consequence is a scope boundary, not a bias — and the direction matters.**
Rule (c) excludes cycles by within-cycle drift, drift scales with load, so the
rule preferentially excludes high-load cycles. The kept set is therefore
low-load by construction.

The obvious worry is that this selects cycles agreeing with the conclusion. **The
data says the opposite.** At high load the drift **swamps** the code difference
rather than exaggerating it:

- Cycle 1, at load 21.57 — by far the highest — is the **only** cycle in which
  `REL/A` shows no regression at all (0.9946).
- Cycle 7, at 13.53, the next highest, carries the weakest `P3/A` of any cycle
  (0.9103).

So high load does not manufacture a false positive here; it destroys a true one.
Rule (c) is not removing cycles that disagree with the conclusion — it is
removing cycles where **the instrument has no resolution**, and those happen to
be the cycles that would *understate* the effect. The distinction a reviewer
will ask about directly:

> This is "we measured where the instrument could resolve", not "we excluded
> what disagreed". The excluded cycles point the other way from the conclusion.

What the run therefore answers is: **is there a code regression, measured where
the environment is quiet enough to see one.** What it does not answer is **what
latency a user sees under load** — a capacity question needing a different
design, which nobody asked. `rho(load1, |Aprime/A − 1|)` is reported to size
that boundary rather than to confess to it.

Cycles 2–3 sit inside the 0.10 tolerance and are **kept**, so they bias
`Aprime/A` low. That is left in rather than trimmed: selecting a post-transient
subset after seeing the data is exactly what pre-registration exists to
prevent. The full sequence is printed so a reader can judge it.

Rule (c) has now fired twice, in both directions, on data it was not tuned to —
v1 cycle 4 at 1.1017 and v2 cycle 1 at 0.8971. A rule written before any data
existed, firing correctly on real data, is what pre-registration buys.

### 1.3.4 Arm identity is checked, not assumed

All arms share one port, and `stop_gateway` gives up waiting after 20s without
failing — so "slot 3 measured `P4`" would otherwise be an assertion rather than
a fact. The prior run's own adversarial review made this point: `/health`
confirms only that *something* answers the port.

Two checks, both cheap:

- **Per-binary version, off the measurement path** (`--version`, no server, no
  load): `A` and `Aprime` report 3.5.0, `B` reports 3.5.1, and `P2`/`P3`/`P4`/
  `REL` report 4.0.0. Every label matches its binary.
- **A live `/health` version trace** polled every 5s for the run's duration,
  cross-referenced against the `ts` column already recorded per rep. It
  distinguishes the 3.5.0, 3.5.1 and 4.0.0 arms, so a stale gateway surviving
  across a version boundary into another arm's slot is detectable. It cannot
  separate the three 4.0.0 arms from each other, which is stated as a residual
  limit rather than glossed.

### 1.4 Pairing and the interval

Two rules, both pre-registered in `analyze_ramp.py` before any ramp data
existed:

- Every ratio is formed **within one cycle**: `arm_p50 / A_p50`, the two
  measured minutes apart under the same machine conditions. Never
  median-of-arm ÷ median-of-`A` — that throws away the pairing that cancels
  common-mode drift.
- Exclusions are **whole-cycle only**, never individual arm reps; dropping one
  arm of a cycle breaks the pairing. A cycle is excluded if **(a)** any arm
  VOIDs, **(b)** `A`'s p50 exceeds 1.25× the median of all `A` p50s, or
  **(c)** that cycle's `Aprime/A` deviates from 1.0 by more than 0.10.

Rule (c) exists because rule (b) has a blind spot this specific machine will
exercise. (b) keys only on `A`, which runs in slot 0. A CI burst that starts
*mid-cycle* leaves `A` clean and contaminates slots 4–6, and (b) waves that
cycle straight through with `REL` corrupted. `Aprime` and `A` are the same
bytes, so `Aprime/A` is pure within-cycle drift and is **independent of the
arms under test** — excluding on it therefore cannot select on the outcome,
which an exclusion rule keyed on `REL` obviously could.

The interval on each arm's median ratio is a **distribution-free
order-statistic interval** with its exact realised coverage reported. A P50 is
an order statistic; a confidence interval describes a mean. Conflating the two
is a documented past error on this workstream, so no bootstrap-about-a-mean
interval appears anywhere in this report.

| n | interval | realised coverage |
|---|---|---|
| 9 | [x₍₂₎, x₍₈₎] | 96.1% |
| 12 | [x₍₃₎, x₍₁₀₎] | 96.1% |
| 15 | [x₍₄₎, x₍₁₂₎] | 96.5% |

### 1.5 Choice of n

**n = 18, and the structural reason outranks the power reason.**

With `NARM` arms under rotation, each arm occupies each slot exactly once per
`NARM` cycles — so **slot effects cancel exactly when the cycle count is a
multiple of the arm count.** 18 gives each of 6 arms each of 6 slots three
times. An earlier plan of 15 cycles over 7 arms was not a multiple of anything
and left a residual position imbalance that would never have shown up in the
output table. Dropping the unmeasurable `P2` arm (§1.8) is what made six divide
evenly; the arm that could not be measured paid for itself.

Note the tension this creates with exclusions: **every excluded cycle breaks
the exact-balance property.** The analyzer therefore checks balance per
*arm × slot*, not per slot — equal counts per slot hold at any multiple of
`NARM` even when one slow arm landed in one slot more often, which would read
arm effect as position effect. When balance is not exact the slot column is
printed with a CONFOUNDED warning rather than silently.

**Two windows, both pre-registered before the final cycle count existed:**

- **Primary: the full kept set.** No choice is made, so no choice can be
  second-guessed.
- **Secondary, for the balance property only: the most recent multiple of
  `NARM` kept cycles.** A *suffix*, deliberately. Recency is clock-determined
  and outcome-independent, whereas taking the *earliest* cycles would select
  precisely the transient-contaminated ones and therefore correlate with
  `Aprime/A` — the quantity under test. The choice looks arbitrary and is not.

The secondary window's justification **strengthened mid-run**, once slot 0 was
identified as the largest position effect: a complete-slot-coverage window is
better motivated than it was when registered. That is exactly why it is **not**
promoted to primary. Switching the headline after the data supplies a reason is
selection however good the reason reads. Both are reported; if they disagree
materially, the disagreement is the finding.

The power reason is secondary: the 2026-09-21 powered run lost **6 of 20
cycles** to a load excursion, and n≥6 is the floor for an order-statistic
interval to exist at all with n≥9 for it to narrow. 18 carries margin for the
observed exclusion rate.

### 1.6 Two validity gates, read before any shape claim

- **G1 — self versus self, at maximum slot separation.** `Aprime/A` must
  bracket 1.0 with a tight interval.

  The placement matters more than the comparison. Rotating the start arm moves
  which *slot* each arm occupies, but the **distance between any two arms is
  invariant** — rotation can never separate a pair. Had `Aprime` sat next to
  `A`, it would have measured drift across ~60 seconds while `REL` pairs across
  ~6 minutes of CI-burst drift, and G1 would have certified the tightest pair
  in the run while saying nothing about the pair that carries the verdict. At
  the far end, `Aprime` suffers the same separation as `REL`, so **G1 is an
  upper bound on the pairing penalty every arm pays.** Pass there, pass
  everywhere.

  Every other number in this report is meaningless if the noise floor exceeds
  the decision band; that is precisely how the bisect produced a confident
  wrong answer.

- **G2 — endpoint reproduction.** `REL/A` must reproduce a clear regression.
  The bisect's tell was that its worst BAD (1.0660) never reached the measured
  1.0873. If the endpoints do not reproduce here, the middle points mean
  nothing and the verdict is INCONCLUSIVE.

### 1.7 Predictions registered before this run finished

Both derive from *independent* earlier data, recomputed from the raw CSVs:

| Prediction | Value | Source |
|---|---|---|
| `REL/A` | ≈ **1.108** | `perf1-v350-20260921` ABBA run, paired, n=7 after excursion exclusion (against `0c93384b`, not `35d94814`) |
| `B/A` | ≈ **1.016** | implied by 1.108 ÷ 1.091, the latter being the `powered-ab` paired median vs v3.5.1 |

If the ramp reproduces both from a fresh, differently-structured measurement,
that is strong corroboration. `B/A` is the direct answer to "does the
regression predate 4.0.0": at 1.016, roughly 1.6 of the ~11 points landed
between v3.5.0 and v3.5.1.

### 1.8 The index-46 arm could not be measured

`P2` (`bd1adbb4`) VOIDs reproducibly on a **correctness** check, not a timing
one: semantic assertion rate **0.492** on its warmup and **0.488** on cycle 1,
with zero HTTP errors and healthy latencies (median 672µs). About 51% of
`tools/call` requests come back `-32601: … tool: workload_probe`, the code
this gateway uses for a name that is absent from the catalogue outright.

This is not a startup race. The harness's `setup()` proves the pinned tool
resolves *and* returns the pinned payload before any measured rep, aborting the
run otherwise — and setup passed. The tool resolved at startup and then
**vanished mid-run**: the catalogue loses the backend under 50-VU load. Gateway
stdout and stderr are **0 bytes** at `RUST_LOG=error`. `A`, `B`, `P3`, `P4`,
`REL` and `Aprime` all pass the identical check with the identical config and
fixture, so this is the binary, not the harness.

**Treated as an arm-level exclusion, applied wholesale and stated once.** That
is categorically different from dropping an arm's rep inside a cycle, which
would break pairing (§1.4). Every surviving arm remains paired against `A`
within its own cycle, untouched. Verified against synthetic data before
applying: with a systematically-VOID arm and no drop rule, **all 15 cycles are
excluded and the run yields nothing**.

**What it costs, stated rather than papered over.** Segments idx27→46 and
idx46→69 merge into one 42-commit segment — and by §1.2 that is the heaviest
region in the entire window, 107,746 `src` lines added against 2,792 for all of
idx0→27. The resolution loss lands exactly where the change volume is.

The failure is also worth a ticket on its own account, independent of this
measurement: a tool silently dropping out of the catalogue under concurrency,
with no log line, is a poor failure mode.

---

## 2. Environment

Spark carries sustained background load from other tenants. Measured
immediately before the run:

- load average 13–22 on 20 cores, **spiking to 48** within ten minutes;
- `mpstat -P ALL`: **3.25% idle averaged across all 20 cores**, and no single
  core materially idler than the others;
- the two week-old near-full-core processes (pids 422368 at 7d, 945144 at 16d)
  have affinity `0-19` — **nothing is pinned**.

**The load source is not what the earlier write-ups assumed.** `ps` during the
spike shows it is dominated by **self-hosted GitHub Actions runners on this
same box** — `actions-runner/claude-elite`, `botnaut-engine-2`,
`botnaut-client` — running `pytest` and `rustc`. The two long-lived processes
are a floor, not the mechanism. CI is bursty and uncorrelated with anything we
control, which is a better explanation of the 34% consecutive-rep scatter than
steady contention, and it is why rule (c) in §1.3 exists.

**Decision: no CPU pinning.** `cset` is not installed; `taskset` only
*restricts* your own processes, it does not *reserve* cores from anyone else.
With ~3% idle spread evenly, confining the gateway to a 4-core subset would
hand it four cores that are already ~95% busy — a new contention source, not a
fix. The lever that actually works under this load is the paired, rotated
interleave, which converts machine noise into common-mode noise the ratio
cancels. G1 is the test of whether that is sufficient; it is not assumed.

## 3. Instrument provenance

Everything below was verified, not assumed:

- **Harness is the shipped one.** `benchmarks/workload/{k6_workload.js,
  gateway.workload.yaml, mcp_backend.py}` on Spark are byte-identical
  (sha256) to the repo's current files, and are held fixed across every arm.
- **Builds are reproducible.** Every arm was built from **one worktree**
  with **one identical** `cargo build --release --locked --features
  "a2a,webui,config-export,cost-governance,firewall,discovery,semantic-search,tool-profiles,metrics"`
  line, under `rustc 1.98.1 (48a229cea 2026-09-01)`. No arm can differ from
  another by toolchain, feature set, or profile.
- **The rebuilt v3.5.0 is byte-identical to the prebuilt `arms/A`** used by the
  earlier runs (sha256 `809093be…`). This answers the
  "are the prebuilt binaries comparable?" question without spending a single
  measurement rep, and bridges this run to the existing +8.73% figure.
- **No toolchain confound.** `git log v3.5.0..origin/main -- rust-toolchain.toml`
  is empty: the pinned compiler did not move inside the measured window, so a
  smooth ramp cannot be a compiler bump. 22 Cargo.lock commits and 537 `src/**.rs`
  commits remain in the window; dependency drift is *not* excluded.

---

## 4. Results

*(pending — filled from `ramp/analysis.json`)*

## 4a. What the next run should start with

None of these were applied mid-flight: `n` is fixed in advance and a geometry
change partway would split the kept set into two incomparable halves. They are
recorded as the starting configuration for the next measurement, in priority
order.

1. **`RANDOMIZE=1` — a fresh permutation per cycle. One change, four defects.**

   This is the headline recommendation, and the case for it is not "rotation is
   insufficient" but that **rotation is too structured**. Every defect below
   survived precisely by being *invariant* under rotation:

   | defect | how rotation preserved it |
   |---|---|
   | control adjacent to its own baseline | cyclic distance is invariant, so "far end of the list" was distance 1 |
   | every arm's predecessor fixed forever | rotation permutes position, never neighbours |
   | median-pooled ratios retain a deterministic position term | distance-to-denominator barely varies, so the term never averages out — and it does **not** shrink with more cycles |
   | the control is blind to that term | `Aprime` sits at the one distance where the term vanishes (§5.1) |

   A fresh permutation makes distance a **random variable**. Every quantity that
   survived by being invariant now averages out, and `Aprime` samples the same
   separation distribution as the arms it bounds rather than one privileged
   point of it. Already implemented and syntax-checked in `run_ramp.sh`.
2. **One discarded warm-up rep at the head of each cycle.** Slot 0 is slow for
   *whichever* arm lands there, because it follows the previous cycle's tail
   with no settling gap — measured at 0.7886 for `A` in cycle 1 and 0.7195 for
   `Aprime` in cycle 4, each arm's single worst reading. A leading throwaway rep
   gives slot 0 the settling gap every other slot gets from its predecessor.
   This **eliminates** the largest identified position effect rather than
   cancelling it in expectation: averaging requires `n` to be an exact multiple
   of `NARM` and still leaves slot 0's variance in every ratio. Cost is one rep
   per cycle — ~17% at six arms — against a term contributing up to 12%.
4. **An arm at first-parent index 39 — this answers question 3 at achievable
   `n`.** Narrowing `B/A` to resolve a ~1.6% effect needs n≈141 and is out of
   reach. But **locating a step does not require resolving small differences**:
   the idx27→69 step is ~10.5pp, which already clears the noise floor. `4.0.0`
   opens at **index 39, inside that window**, so one arm there splits it exactly
   at the version boundary — a step in idx27→39 predates 4.0.0, a step in
   idx39→69 belongs to it. That is question 3, answered rather than retired.

   A seventh arm was expensive under rotation because it forced `n` to a
   multiple of 7. **Randomisation removes that constraint** — slot balance then
   holds in expectation rather than by exact construction — so this arm is
   nearly free once change 1 is in.

   Worth recording because it generalises past this run: the seventh arm looked
   costly only because **the arm count was being treated as fixed by the
   geometry, when the geometry was the thing already being replaced.** A
   constraint inherited from a design you are discarding is not a constraint.

5. **A measurable replacement near first-parent index 46.** `P2` is unmeasurable
   (§1.8) and its loss merges the two heaviest segments. Pick a nearby commit,
   verify it passes the harness's semantic check *before* enrolling it.

6. **Make the excursion rule two-sided.** As registered, rule (b) is
   `A > 1.25 × median(A)` — it has **no lower bound**. A denominator that is
   anomalously *fast* inflates every numerator ratio exactly as a slow one
   deflates them, and rule (c) misses it whenever `Aprime` moves with `A`. The
   rule should be symmetric: `0.8 × median(A) ≤ A ≤ 1.25 × median(A)`.

   **Not applied here**, because the defect was found by seeing the value it
   would exclude. The registered rule stays primary and §4 reports a labelled
   sensitivity against the two-sided version.

   **The defect is real; its impact on this run is measured and negligible**,
   which is a stronger statement than a caveat and is worth separating from the
   rule design point:

   - Cycle 10 produced `A = 0.6002` against a kept median of ~0.723, ~17% fast.
   - **Every arm in that cycle ran 12–18% fast** (0.816–0.880 of its own kept
     median, spread across arms only 7.8%). The shift was **common-mode**, and
     a common-mode shift cancels in a within-cycle ratio. That is the entire
     reason the design pairs, and this is it working rather than an apology for
     the rule.
   - `B/A`, `P4/A` and `REL/A` in cycle 10 all sit *inside* their kept-cycle
     spreads, with `P4/A` below its own mean. Genuine denominator inflation
     would push all three toward their upper bounds together; it did not.
   - The symmetric counterpart would **not** have excluded cycle 10 anyway:
     `0.8 × 0.723 = 0.579`, and 0.6002 sits inside it. A bound tight enough to
     catch this instance would have to be tuned to a value already seen, which
     is exactly what must not be done.

7. **Fix the settledness statistic's scope.** As registered it regresses over
   *all observed* cycles including those rule (c) rejected for drift, so a
   drift-trend statistic counts cycles already rejected for drift. Register
   "kept cycles only" next time. Not changed here (§1.3.1).

8. **Derive `n` from this run's realised scatter**, not from a plan — §4 reports
   the arithmetic.

## 5. Verdict

*(numbers pending final `n`; the structural caveats below are fixed and apply
whatever the numbers come out as)*

### 5.1 What G1 passing does and does not certify

**If G1 passes, it must be cited with this caveat attached, in the same
breath:**

> **G1 passed — and G1 is structurally blind to median position bias in the
> test arms. The geometric-mean cross-check (§1.3.3) is what covers that
> class.**

The reason is geometric, not statistical. `Aprime` sits at cyclic distance
`k = NARM/2 = 3` from `A`, and that is the **unique** geometry whose
median-pooling position bias is ~0 (+0.01% against ±1.7% for every test arm).
Distance 3 was chosen so the control's separation would match the arms it
bounds (§1.3); that it is also the one position immune to this particular bias
is coincidence, and an unlucky one.

So a `G1` pass cannot see a failure mode that afflicts every arm it is meant to
vouch for. This is a fact about **what the gate can detect**, not about this
run's data, which is why it lives here and not in the diagnosis section: a gate
whose limits are recorded only in an appendix will be cited without them.

The transferable lesson, and the most portable thing in this document:

> **A control placed for one good reason may be immune to the failure it is
> meant to catch — and immunity looks identical to absence.**

### 5.2 On the 2026-09-21 powered run: not used as corroboration

An earlier draft framed this run as cross-validating the 20-rep powered run's
`REL/v3.5.1 = 1.0873`. **That framing is cut, not weakened.**

Measured directly, per cycle then pooled, `REL/B = 1.1627` at n=7 — a **7.5pp**
gap from 1.0873, not an agreement. And the interval at that `n` is the full
observed range (k=1, coverage 98.4%), so "1.0873 falls inside it" is close to
unfalsifiable. **A wide interval excludes nothing**, including when the reading
it fails to exclude is the convenient one.

The route that made the two look close — `(REL/A)/(B/A)` = 1.1043/0.9871 =
1.1187 — is the median non-identity documented in §1.3.3 and is invalid. It was
attractive only because it flattered the convergence.

More importantly, **the corroboration was never worth having.** The powered run
measured against **v3.5.1**, which is the wrong baseline for this criterion —
that mismatch is precisely why the row has sat PARTIAL. `REL/A` measures the
criterion's own question against the baseline it names. Corroborating a correct
measurement with one made against the wrong baseline adds nothing.

**Held open as a question for §5.3, not a claim:** the two designs disagree in a
specific direction, this run reading *higher*. If the intervals still fail to
overlap tightly at final `n` — where they become genuine sub-ranges rather than
min-max — that is a finding about the *instruments*, not the code. A plausible
mechanism exists: the powered run divided by a **prebuilt** 3.5.1 binary, while
`REL/B` here divides by this run's own `B` arm, which is subject to the same
drift measured in `A` (−8.2% across the run). A moving denominator moves the
ratio. `REL/A` does not inherit that problem for the criterion question, because
`A` *is* the named baseline and is measured in the same cycle as its numerator.

### 5.3 Findings

*(pending)*

## 6. Honest limits

### 6.1 Disclosure ledger

**Every defect below was found by this method's own machinery or by applying
its own stated standards, and none was applied mid-run.** A pre-registered
method that produced *zero* disclosed defects under this much scrutiny would be
less credible, not more — it would mean nobody looked. Three found, three
disclosed, three not applied, each with a labelled sensitivity, is the evidence
that the discipline is real rather than decorative.

| # | Defect in the pre-registered method | Disposition |
|---|---|---|
| 1 | The settledness statistic regresses over *all observed* cycles, including those rule (c) rejected for drift — a drift-trend statistic counting cycles rejected for drift (§1.3.1) | Registered version reported. Sensitivity: kept-cycles-only slope −0.0144 against the registered −0.0031. Fix registered for the next run. |
| 2 | Rule (b) is one-sided (`A > 1.25 × median`), so an anomalously *fast* denominator is not excluded (§4a.6) | Registered version reported. Sensitivity: two-sided rule drops no kept cycle. Impact separately measured and negligible — cycle 10's shift was common-mode, all arms 12–18% fast, inter-arm spread 7.8%. |
| 3 | G1 is structurally blind to median position bias, because `Aprime` sits at `k = NARM/2`, the one distance where that bias vanishes (§5.1) | Stated as a **verdict-level** caveat, not an appendix note. Covered by the geometric-mean cross-check, which reads clean (≤0.24pp). |

Three further errors were made and corrected *during* the exercise, and are
recorded in place rather than tidied away: the control's adjacency to its
baseline (§1.3), a retracted slot-0 claim made while the analyzer's own
CONFOUNDED warning was printing (§1.3.2), and a cross-validation framing that
rested on the median non-identity it was itself documenting (§5.2).

### 6.2 What the sample size can and cannot exclude

*(interval values pending; the framing below was fixed before results existed)*

A wide G1 does **not** make this run uniformly worthless — it degrades the
questions unevenly, because they differ by an order of magnitude in effect
size. This is the frame to read the results through, rather than a single
blanket INCONCLUSIVE:

| # | Question | Effect size it needs to resolve | Survives a wide G1? |
|---|---|---|---|
| 4 | self-versus-self control | — | it **is** G1 |
| — | endpoint: is `REL` slower than v3.5.0 at all? | ~8–11% | **yes** — well clear of any plausible noise floor here |
| 3 | does the regression predate 4.0.0? (`B/A`) | ~1.6% | no — needs a tight interval |
| 1 | shape: step, ramp, or noise | ~1.7% per segment | no |
| 2 | which commit | ~1.7% | no, and it was never in reach at this n |

**Question 2 was not reachable by this design and is not promised.** The total
effect is ~8.7% spread over 115 first-parent commits. Across 5 segments that is
**~1.7% per segment**, which sits inside the per-point interval at any n this
box can deliver in an afternoon. If the shape is a step, the honest deliverable
is "step localised to a ~23-commit window" plus a targeted follow-up on that
window — not a culprit SHA. Naming one at this resolution is exactly the error
the 2026-09-21 bisect made.

**A wide interval excludes nothing.** Where a point's interval brackets 1.0,
the reading is INCONCLUSIVE for that point, never "no effect".
