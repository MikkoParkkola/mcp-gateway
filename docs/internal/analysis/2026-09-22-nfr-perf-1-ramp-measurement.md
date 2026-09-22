# NFR.PERF.1 — where the P50 regression comes from: a ramp measurement

**Date:** 2026-09-22 · **Host:** Spark (20 cores, aarch64) · **Status:** COMPLETE — 18 cycles, 15 kept, 108 reps

**Headline:** a P50 regression is reproduced against **v3.5.0**, the baseline
`NFR.PERF.1` actually names, at **1.1237 [1.1010, 1.1521]** (k=4, 96.5% coverage,
n=15) — excluding both 1.0 and the 5% budget. The rise is a **step in a
42-commit window**, not a ramp. **All numbers are provisional**: the
pre-registered settledness rule returned DRIFTING. Per-commit attribution
costs n≈195 against n≈7 for the endpoint and is retired on this host.

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
| **idx27→69 (measured)** | **42** | **107,746 / 4,923** | **9** |
| — idx27→46 *(unmeasured split)* | 19 | 36,954 / 1,968 | 3 |
| — idx46→69 *(unmeasured split)* | 23 | 70,792 / 2,955 | 6 |
| idx69→92 | 23 | 7,024 / 1,259 | **0** |
| idx92→115 | 23 | 1,706 / 837 | 4 |

**Four segments are measured**, not five: `P2` at index 46 is unmeasurable
(§1.8), so idx27→46 and idx46→69 merge into the single 42-commit idx27→69
segment. The two sub-rows are kept indented because the split is what a
replacement arm would restore (§4a.5), not because either was measured. The
per-segment ratios are in §4.5; this table is the weight to read them against.

Three things fall out before any measurement:

- **The merged idx27→69 segment carries 39× the source churn of idx0→27** for
  1.6× the commit count. A "ramp" that is really one heavy segment plus light
  ones is a step wearing a ramp's clothes, and only this column distinguishes
  them.
- **idx69→92 is the one window with zero dependency churn.** It is therefore
  the only segment where a ratio can be attributed to gateway source rather
  than to a dependency bump. Everywhere else, source and lockfile move
  together and a step landing there implies a *dependency* bisect, which is a
  different investigation from a source one.
- **The measured step lands in the segment with both the heaviest churn and 9
  lock changes** (§4.5, Finding 2), so it cannot be attributed to source rather
  than dependencies without the follow-up in §4a.

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

What the drift *appeared* to track in the first six cycles is **load**:
position cost ran ~10% at load 21.6 and ~1% at load 7.1, which looked like a
dose-response version of the 29% artefact above.

> **That reading does not survive the full sample and is withdrawn — see §6.3.**
> It was drawn from cycles 1–6; across all 18, the correlation between host load
> and within-cycle drift is **0.028**, i.e. none. The dose-response is recorded
> here because the narrative it produced shaped intermediate decisions, not
> because it holds.

**The consequence — also withdrawn at final `n`, and recorded because the
reasoning was load-bearing while it stood (§6.3).** The argument ran: rule (c)
excludes cycles by within-cycle drift, drift scales with load, so the
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
design, which nobody asked.

**At final `n` this whole passage is moot, and in the run's favour.** With
`rho(load1, |Aprime/A − 1|) = 0.028`, rule (c) is not selecting on load in
either direction, so the kept set is **not** load-biased and there is no scope
boundary to size. Cycle 15 was excluded at load 7.13, among the lowest in the
run, which shows it directly. The argument above is left standing because it
governed intermediate decisions and because **a caveat that turned out to be
unnecessary is still worth showing the working for** — a reader should be able
to see that the favourable resolution was not assumed.

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

**The interval's *structure* matters as much as its width, and it changed
during this run.** At n≤8 the only order statistic reaching 95% coverage is
k=1 — the **full observed range**. An interval that is the min-max of the
sample cannot fail to contain anything in the sample, so a bound derived from
it is close to unfalsifiable.

Concretely, for `REL/A`:

| n | interval | k | coverage | budget (1.05) |
|---|---|---|---|---|
| 7 | [1.0523, 1.1521] | **1 — min-max** | 98.4% | cleared by 0.2pp |
| 9 | [1.0775, 1.1358] | **2 — sub-range** | 96.1% | cleared by 2.8pp |

Only the n=9 form is a claim that could have failed and did not. Interim
statements made at n=7 about the budget being excluded were **premature**, and
a reader comparing interim numbers against the final should trust the later one
for that reason rather than because it is later.

This is the same principle applied for the third time in three directions —
**a wide interval excludes nothing**, whether the reading it fails to exclude
is unfavourable (§6.2), favourable to the measurement author (§5.2), or
favourable to the coordinator (this note). Any quotation of these intervals
should carry its `k` and coverage, because a bare pair of bounds invites the
question this note answers.

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

**18 cycles observed, 15 kept, 108 reps.** Raw data is committed alongside this
report at `docs/internal/evidence/nfr-perf-1-ramp-2026-09-22/`:
`reps.csv` (per-rep), `analysis.json`, `analysis.txt` (full analyzer output),
and `reps-v1-slotbug.csv` (the killed first attempt, retained as evidence for
§1.3). Source paths on the measurement host: `~/perf-workload/results/ramp-v2/`
and `~/perf-workload/results/ramp-v1-slotbug/`.

### 4.1 Exclusions

Three cycles excluded, **all three by pre-registered rule (c)** (within-cycle
drift, `|Aprime/A − 1| > 0.10`): cycle 1 at 0.8971, cycle 7 at 0.8170, cycle 15
at 1.1079. Realised exclusion rate **16.7%**, against the ~30% the design
budgeted for. The n≥9 target was therefore **met with margin** — 9 kept cycles
arrived at cycle 12, with six cycles still to run — rather than reached exactly.

Rule (b) excluded nothing. The **two-sided sensitivity** (§4a.6) also drops no
kept cycle, so the disclosed one-sidedness of rule (b) changed no number here.

### 4.2 Validity gates

| gate | value | interval | k | coverage | verdict |
|---|---|---|---|---|---|
| **G1** `Aprime/A` | 1.0081 | [0.9568, 1.0455] | 4 | 96.5% | **PASS** — brackets 1.0, width 8.88pp |
| **G2** `REL/A` | 1.1237 | [1.1010, 1.1521] | 4 | 96.5% | **regression reproduced** — excludes 1.0 |

G1 passing must be cited with §5.1's caveat attached.

### 4.3 Pre-registered settledness verdict: DRIFTING

| statistic | value | tolerance | pass |
|---|---|---|---|
| slope of `Aprime/A` on cycle index | **+0.00646**/cycle | ±0.005 | no |
| mean over final 6 cycles | **1.0309** | 1 ± 0.02 | no |

**Verdict: DRIFTING — the control did not settle, and every ratio in this
section is therefore provisional.** Both statistics fail, not one marginally,
so this is not a borderline call.

The decomposition shows why, and the magnitude is the point: across the run
`A` drifted **−25.4%** (0.7886 → 0.5880) and `Aprime` **−14.1%**. The host got
dramatically faster overnight as load fell. **Absolute latencies from this host
are worthless; only within-cycle ratios mean anything** — which is what the
design is built on, and the drift figure is the justification rather than an
embarrassment.

### 4.4 Per-cycle series

Printed in full because an INCONCLUSIVE verdict should be readable off the data
rather than taken on trust (`*` = kept):

| cyc | `A` raw | load1 | `A'/A` | `B/A` | `P3/A` | `P4/A` | `REL/A` |
|---|---|---|---|---|---|---|---|
| 1 | 0.7886 | 21.57 | 0.8971 | 0.9656 | 1.0217 | 1.0028 | 0.9946 |
| 2* | 0.7319 | 10.40 | 0.9499 | 0.9613 | 1.0679 | 1.1133 | 1.1521 |
| 3* | 0.7210 | 10.53 | 0.9568 | 1.0130 | 1.0838 | 1.1157 | 1.1075 |
| 4* | 0.7277 | 9.22 | 0.9887 | 0.9298 | 1.0327 | 1.1982 | 1.1010 |
| 5* | 0.7230 | 8.62 | 0.9953 | 1.0166 | 1.1411 | 1.1609 | 1.0775 |
| 6* | 0.6931 | 7.12 | 1.0081 | 1.0502 | 1.1408 | 1.2079 | 1.0523 |
| 7 | 0.7596 | 13.53 | 0.8170 | 0.9791 | 0.9103 | 1.0101 | 1.0777 |
| 8* | 0.7190 | 7.71 | 1.0160 | 0.9602 | 1.1007 | 1.1519 | 1.1237 |
| 9* | 0.7238 | 7.36 | 0.9990 | 0.9516 | 1.0859 | 1.0877 | 1.1064 |
| 10* | 0.6002 | 10.11 | 1.0455 | 1.0319 | 1.0938 | 1.1264 | 1.1212 |
| 11* | 0.6471 | 7.71 | 0.9476 | 0.9612 | 1.0285 | 1.0678 | 1.1358 |
| 12* | 0.5980 | 7.68 | 1.0703 | 1.0832 | 1.2020 | 1.1592 | 1.1494 |
| 13* | 0.5820 | 5.23 | 1.0643 | 1.0475 | 1.1568 | 1.2163 | 1.2505 |
| 14* | 0.5997 | 7.88 | 1.0196 | 1.0273 | 1.1278 | 1.1923 | 1.1449 |
| 15 | 0.6045 | 7.13 | 1.1079 | 0.9527 | 1.2562 | 1.1317 | 1.0890 |
| 16* | 0.6579 | 6.45 | 0.9074 | 0.9582 | 1.0224 | 1.0620 | 1.0925 |
| 17* | 0.6061 | 6.35 | 1.0526 | 1.0330 | 1.1940 | 1.1593 | 1.1676 |
| 18* | 0.5880 | 6.50 | 1.0339 | 1.0294 | 1.1518 | 1.1819 | 1.1719 |

Kept-cycle `A` spread: 0.5820 to 0.7319, a **25.8% range** — the drift of §4.3
seen directly in the denominator.

### 4.5 The ladder, against the noise floor

**Resolvable effect at n=15: 6.13%** (`2 · 1.96 · CV · 1.2533 / √n`, CV 4.83%).
Nothing smaller is distinguishable from noise.

| point | idx | `X/A` | segment | delta | clears 6.13% floor? |
|---|---|---|---|---|---|
| `A` | 0 | 1.0000 | — | — | — |
| `B` | 27 | 1.0166 | idx0→27 | +1.66pp | **no** |
| `P3` | 69 | 1.1007 | idx27→69 | **+8.42pp** | **YES** |
| `P4` | 92 | 1.1592 | idx69→92 | +5.84pp | **no** (just under) |
| `REL` | 115 | 1.1237 | idx92→115 | −3.55pp | **no** |

Ladder monotonicity: `rho(first-parent index, median ratio)` = **0.900**, the
`spearman_rho` field of `analysis.json`.

**Computed over the five measured ramp points only — `A`, `B`, `P3`, `P4`,
`REL` — with the control `Aprime` excluded.** The control is not a ramp point.
Including it would place a second observation at first-parent index 0 with a
different y (1.0081 against `A`'s 1.0000), which manufactures an x-axis tie the
design never contained *and* feeds the control's noise into a statistic meant to
describe the ramp. A six-point version of this figure reads 0.9276 and is not a
second estimate of the same quantity: it is an estimate of a quantity nobody
asked for, so it is not recorded here.

A rho with an unstated population is how that ambiguity arose in the first
place. Every correlation in this report names the set it is computed over — see
§6.3, where the same discipline applies to the load correlation.

This is **not** the load correlation of §6.3, and the two must not be confused —
§6.3 records that near-miss.

**Exactly one segment is resolvable: idx27→69, at +8.42pp, carrying 68% of the
total +12.37pp rise.** Everything else is inside the floor, including the
negative idx92→115 segment — so the non-monotonicity (`P4` above `REL`) is
**not** a resolvable finding and needs no explanation beyond noise.

### 4.6 Position cross-check

Median against geometric mean on the pre-registered balance-exact subset
(n=12, most recent multiple of 6):

| arm | median | geo-mean | delta |
|---|---|---|---|
| `Aprime` | 1.0178 | 1.0122 | −0.56pp |
| `B` | 1.0283 | 1.0117 | −1.67pp |
| `P3` | 1.1343 | 1.1191 | −1.52pp |
| `P4` | 1.1593 | 1.1467 | −1.26pp |
| `REL` | 1.1298 | 1.1318 | +0.20pp |

**Gaps are now material — up to 1.67pp, against ≤0.24pp at n=6.** That is the
magnitude the position model predicts (±1.7%), so an earlier claim that this
cross-check "reads clean" no longer holds at final `n` and is withdrawn.

But the **signs do not match the model**. It predicts median bias +1.68% for
`B` (k=1), −1.64% for `P3` (k=2), +1.69% for `P4` (k=4), −1.65% for `REL`
(k=5) — so geo-mean should sit *below* median for `B` and `P4` and *above* it
for `P3` and `REL`. Observed: below for `B` ✓, below for `P4` ✓, below for
`P3` ✗, marginally above for `REL` ✓. Two of four, with `P3` clearly wrong.

So the gaps are better read as **sampling difference between two estimators at
n=12 than as a confirmed position term**. What matters for the conclusion is
that both estimators agree on the shape: `B` lowest, `P4` highest, `P3` and
`REL` between them and ~1pp apart, which is inside the floor and flips order
between estimators accordingly.

### 4.7 Arm identity

**73 of 108 reps carry `/health` version-trace coverage; 0 mismatches** — no rep
where the expected version was never observed. Per-binary `--version` off the
measurement path matches every label (§1.3.4). The trace cannot separate the
three 4.0.0 arms from one another; that limit stands.

### 4.8 The headline ratio is not stationary across the run

Checked because load fell systematically — 21.57 early, then 7.88, 7.13, 6.35,
6.50 in the last cycles — and a trend is not noise.

| quantity | value |
|---|---|
| rho(cycle index, `REL/A`) within kept | **+0.482** |
| rho(load1, `REL/A`) within kept | −0.281 |
| kept first half, `REL/A` median | **1.1064** (mean load 8.71) |
| kept second half, `REL/A` median | **1.1472** (mean load 7.24) |

**`REL/A` rises about 4pp across the kept set**, and reads *higher* in the
quieter late cycles. So the headline 1.1237 is a median over a non-stationary
series, and the value depends on when in the night it was measured. Under lower
load the apparent regression is **larger**, not smaller.

This is a real qualification on Finding 1 and it points the same way as the
DRIFTING settledness verdict (§4.3): the control drifted, the denominator
drifted −25.4%, and the ratio drifted too. **The system was non-stationary, and
"provisional" is the honest label for every ratio here.** It also means the
lower bound of 1.1010 is the conservative end of a moving quantity rather than
a stable estimate — which does not rescue the budget breach from being
provisional, but does mean the breach is not an artefact of the quiet cycles.

### 4.9 Pairing gain, measured

The design rests on pairing, so its benefit is measured rather than assumed.
Per-arm coefficient of variation across the 15 kept cycles, unpaired (the arm's
own raw p50) against paired (its ratio to `A` in the same cycle):

| arm | unpaired CV | paired CV | gain |
|---|---|---|---|
| `Aprime` | 7.49% | 4.72% | 1.59× |
| `B` | 7.20% | 4.56% | 1.58× |
| `P3` | 7.94% | 5.13% | 1.55× |
| `P4` | 9.16% | 4.33% | 2.12× |
| `REL` | 7.32% | 4.16% | 1.76× |

`A` itself carries a 9.17% unpaired CV. **Pairing buys a 1.55–2.12× reduction
on the P50** here.

That matters because it does **not** hold universally. The `NFR.WORKLOAD.1`
12-rep gate (§5.2) finds pairing marginally *worse* than unpaired for its p50 —
cell `A` unpaired relative half-width 0.091 against paired `C/A` 0.1057 — while
buying roughly 30× on p99. The difference between the two harnesses is the one
this report is about: **that harness runs its cells in fixed order** (`for rep:
for cell in A B C D E`), so `C` sits two slots after `A` in every rep and each
ratio carries an uncancelled position term. This design rotates, so the term
averages out and the pairing gain survives.

So the sharper form of the lesson: pairing buys a great deal on tail statistics
in any design, and buys something on medians **only if the ordering is
randomised or rotated**. Under fixed ordering, a paired median can be worse
than an unpaired one — the ratio carries two noise sources and gains nothing
back.

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

**Resolved at final `n`.** `REL/B = 1.1385, interval [1.0866, 1.1816]`, k=4,
coverage 96.5%, n=15 — now a genuine sub-range rather than the min-max it was
at n=7. The powered run's **1.0873 sits just inside the lower bound of 1.0866**,
by 0.07pp. So the two instruments **marginally agree** and there is no
instrument-disagreement finding to report. Marginal agreement at a 0.07pp
overlap is not strong corroboration either, which is why §5.2's decision to cut
the cross-validation framing stands rather than being reinstated by this result.

### 5.2a A third instrument: admitted as a fourth ladder point, with limits

The `NFR.WORKLOAD.1` gating run `gating-2026-09-21-n12` reports a paired p50
median ratio of **C/A = 1.0882** (and C/B = 1.0886), computed per rep from an
interleaved design and then medianed — the same estimator family used here, not
the invalid ratio-of-medians route §5.2 rejects.

**The identity check passes on the denominator and fails on the numerator.**
Verified from `.checkout_sha` on the measurement host:

| cell | commit | is it this report's arm? |
|---|---|---|
| `A` | `32f135a6` | **yes — v3.5.0, the same baseline** |
| `B` | `e138680a` | **yes — v3.5.1, the same arm** |
| `C` | `dbd4deae` | **no** — first-parent index **99**, between `P4` (92) and `REL` (115) |

So `C/A` is not a replication of `REL/A`; it is a **measurement of a different
point on this report's own ladder**, against the same baseline. That makes it
admissible where the powered run was not — the powered run divided by v3.5.1,
the wrong baseline for this criterion, which is why §5.2 cut it.

Placed on the ladder (idx0 1.0000, idx27 1.0166, idx69 1.1007, idx92 1.1592,
**idx99 1.0882 external**, idx115 1.1237):

- It sits **well above parity**, corroborating the post-idx69 elevation and
  therefore Finding 2's step, from an independent harness on a different day.
- It is **3.6pp below** this run's `REL/A`, inside the 6.13% floor — consistent.
- It is **7.1pp below** this run's `P4`, marginally outside the floor. Given
  `P4` is the ladder's high point and `idx92`→`idx115` already reads −3.55pp,
  the external point is more consistent with `P4` being high than with a real
  fall between 92 and 99.

**One limit, and it is the limit this report exists to document.** That harness
runs cells in **fixed order** (`for rep: for cell in A B C D E`), so `C` is two
slots after `A` in every rep and its ratio carries an uncancelled position term
(§1.3). Its p50 is therefore subject to exactly the effect rotation was adopted
to remove — visible in its own numbers, where pairing fails to improve its p50
(§4.9). It is corroboration of direction, not of magnitude.

**Two independent findings from that run, which stand on their own:**

- Its rep 2 is a **common-mode machine excursion** — p99 of A=58.74, B=74.97,
  C=33.90 against ~3.0 typical, all cells elevated 10–25× together. That is
  independent confirmation of §4a.6's cycle-10 observation, in a different
  harness, arrived at without being looked for.
- Its **paired p99 median ratio is 0.9789 — no p99 regression** — with paired
  relative half-widths ~30× tighter than unpaired (C/A 0.3135 against A 9.45).
  **This report makes no p99 claim**, so that is a corroborating negative on a
  question left open here rather than a result of this run.

### 5.3 Findings

Three separable results. **All three are provisional**, because the
pre-registered settledness rule returned DRIFTING (§4.3).

**Finding 1 — a P50 regression is reproduced against the baseline the criterion
names, and the 5% budget is excluded.**

`REL/A = 1.1237`, interval **[1.1010, 1.1521]**, k=4, realised coverage 96.5%,
n=15, against **v3.5.0** (`32f135a6`).

This is the first end-to-end measurement of this criterion against its own
named baseline; every prior run used v3.5.1, which is why the row has sat
PARTIAL. The interval's lower bound of 1.1010 excludes **1.0** and also
excludes the **1.05 budget, by 5.1pp**. A budget breach against the named
baseline, with the budget outside a falsifiable interval, is what this row has
never had.

**Finding 2 — the rise is a step localised to a 42-commit window, not a ramp.**

Exactly one segment clears the 6.13% noise floor: **idx27→69, at +8.42pp,
carrying 68% of the total +12.37pp**. The other three segments (+1.66, +5.84,
−3.55pp) are all inside the floor and carry no claim.

That window is 42 commits, is the heaviest in the run (107,746 `src` lines
added, §1.2), and **straddles the 4.0.0 version boundary at index 39**. It is
not a culprit commit and this design cannot produce one.

**Finding 3 — per-commit attribution is retired on this host, and that is the
answer to the question that prompted the exercise.**

From realised scatter (CV 4.83%), using the prior analysis's own formula
`n = (1.96·CV·k/(effect/2))²` with the asymptotic `k = 1.2533`:

| effect to resolve | required n |
|---|---|
| 8.7% (endpoint) | **7** |
| 1.7% (per segment) | **195** |
| 1.0% (prior analysis's target) | **564** |

**The endpoint costs 7 cycles; per-segment attribution costs 195.** A factor of
~28 in cost, on a host that yields ~6 cycles an hour under contention. This is
why the 2026-09-21 bisect could not have worked at any threshold, and why it
should not be re-attempted here rather than merely not re-attempted now.

**Question 3 — does the regression predate 4.0.0? INCONCLUSIVE.**

`B/A = 1.0166`, interval **[0.9602, 1.0330]**, k=4, coverage 96.5%, n=15.

The interval **brackets 1.0**, so this measurement **cannot distinguish** v3.5.1
from v3.5.0. That is not the same claim as "the regression does not predate
4.0.0", and the distinction is load-bearing: resolving question 3 needs ~1.6%
and this run resolves 6.13%, roughly four times too coarse.

Worth recording precisely because it is a near-miss rather than a hit: the
point estimate of **1.0166 lands almost exactly on the 1.016 registered in
§1.7 before the run reported.** A registered prediction matching to 0.06pp is
striking, and it is still not evidence — the interval brackets 1.0, so the
measurement cannot tell 1.0166 from 1.0000. **A point estimate agreeing with a
prediction inside an interval that admits the null is a coincidence until the
interval narrows.** Finding 2's step, whose *location* is resolvable, is the
route to answering question 3 — see §4a.4.

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
recorded in place rather than tidied away:

- **The control was adjacent to its own baseline** under rotation (§1.3) —
  measurement author's error, endorsed by the coordinator, caught by the
  measurement author from the run's own slot table.
- **A slot-0 claim was made and retracted** (§1.3.2) while the analyzer's own
  CONFOUNDED warning was printing at the time — measurement author's error
  entirely. *A guard that fires and is ignored is a different failure from a
  guard that never fires, and only one of them is fixed by writing more
  guards.*
- **A cross-validation was derived via the median non-identity this document
  itself documents** (§5.2) — the coordinator's derivation, computing
  `(REL/A)/(B/A)` and recommending it as the report's lead. Caught on direct
  recomputation, which gave 1.1627 against the 1.1187 the invalid route
  produced; the framing was then cut rather than downgraded. The measurement
  author's lesser part: an intermediate draft **kept a weakened version** in
  §5.2 instead of cutting it, which invites a reader to lean on it anyway.

The attribution is spelled out because this ledger exists so a reader can judge
whether the method's self-correction is real, and **an entry filed against the
wrong person is a small wrong fact in a document whose whole argument is that
its facts are checked.**

### 6.2 What the sample size can and cannot exclude

**Resolvable effect at n=15: 6.13%.** Anything smaller is INCONCLUSIVE, never
absent. A wide interval excludes nothing.

| question | effect needed | resolved? |
|---|---|---|
| self-versus-self control | — | yes, it *is* G1 |
| is `REL` slower than v3.5.0 at all | ~12% | **yes** |
| does `REL` breach the 5% budget | ~5% | **yes**, budget excluded by 5.1pp |
| which segment carries the rise | ~6% | **one** segment only (idx27→69) |
| does the regression predate 4.0.0 | ~1.6% | **no** — INCONCLUSIVE |
| which commit | ~1.7% | **no**, and not reachable at n≤195 |

### 6.3 Two of this report's own claims did not survive final `n`

Both were stated with more confidence than the data ultimately supported, and
both are withdrawn rather than quietly revised:

**Withdrawn — "within-cycle drift tracks host load".** At n=9 this read
`rho(load1, |Aprime/A − 1|) = 0.850` and was reported as promoting the
mechanism from plausible to measured. **At n=18 it is +0.028 — no relationship
at all.**

The provenance was checked rather than assumed, because a plausible alternative
explanation existed: that 0.850 had been the `spearman_rho` field of
`analysis.json`, which is **ladder monotonicity** — `rho(first-parent index,
median ratio)` across the arms, +0.9276 at final `n` — quoted as though it were
the load statistic. **It was not.** Recomputed from the committed `reps.csv`,
the load correlation over the first 9 observed cycles reproduces at **exactly
+0.850**, and its decay is a genuine statistic collapsing as `n` grows:

| observed cycles | `rho(load1, \|Aprime/A − 1\|)` |
|---|---|
| 9 | **+0.850** |
| 10 | +0.867 |
| 12 | +0.581 |
| 18 | **+0.028** |

So this is a real small-sample artefact, not a conflated quantity — and the
distinction matters, because the two failure modes have different fixes. A
conflated statistic is fixed by labelling; an artefact is fixed only by `n`.

**Every rho in this report names the set it is over, because the sets
disagree.** Over all 18 observed cycles the load correlation is **+0.028**; over
the 15 kept cycles alone it is **≈ −0.31** (−0.315 here, −0.304 on an
independent recomputation). "No relationship overall" and "mildly inverse among
the kept" are different statements, and at n=15 the second is not significant.
**No claim is made from it.**

**Why the correlation vanishes is visible in the three exclusions, and this is
a stronger answer than any single rho:**

| cycle | load1 | `Aprime/A` | |
|---|---|---|---|
| 1 | 21.57 | 0.8971 | `Aprime` **faster** |
| 7 | 13.53 | 0.8170 | `Aprime` **faster** |
| 15 | 7.13 | 1.1079 | `Aprime` **slower** |

**Opposite signs at opposite ends of the load range.** Rule (c) fires on the
*magnitude* of drift, which occurs in both directions and at both high and low
load — so the rule is not a load filter, and the kept set is not load-selected.

That has a consequence which cuts *in favour* of the run and must therefore be
stated carefully rather than gratefully: if drift does not track load, then
rule (c) is **not** preferentially excluding high-load cycles, so **the kept set
is not load-biased** and the scope-boundary caveat built on that premise
(earlier drafts of §1.3.1) was unnecessary. The exclusions confirm it directly —
cycle 15 was excluded at load 7.13, among the *lowest* in the run.

**The direction claim survives the retraction, by a better route.** That rule
(c) removed cycles which would have *understated* the effect does not need the
load correlation at all — it is verifiable by inspection. The three excluded
cycles read `REL/A` = **0.9946** (cycle 1), **1.0777** (cycle 7) and **1.0890**
(cycle 15), all three **below** the kept median of 1.1237. Including them would
have lowered the estimate. So rule (c) is demonstrably "we measured where the
instrument could resolve" and not "we excluded what disagreed" — established
from the per-cycle table in §4.4 rather than from a correlation that did not
hold. Note the mean load of excluded cycles (14.08) does exceed the kept mean
(7.92), but that is two cycles of three and, with rho ≈ 0 overall, is not a
mechanism. The
observation that cycle 1 at load 21.57 showed no regression remains true as a
single observation, but with rho ≈ 0 it cannot be generalised to "high load
destroys the signal".

**Withdrawn — "the position cross-check reads clean".** True at n=6 (gaps
≤0.24pp), false at final `n` (gaps to 1.67pp, §4.6). The gaps are the magnitude
the position model predicts, though their signs do not match it, so they are
read as estimator sampling difference rather than a confirmed position term.
Either way the earlier reassurance was premature.

The pattern in both is the same, and it is the same pattern as the interval
structure in §1.4: **a statistic computed at small `n` can be confidently
wrong, and confidence at n=6 or n=9 is not evidence about n=18.** Three
separate claims in this exercise were overturned by more data from the same
run.

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
