# The spread was the box. A/B/C is stable now, and it misses the p50 budget

Run `2026-09-16-quiet-v1`, the falsifier `09-modern-era-admission-wall.md`
named: a re-run on a compile-quiet box. The gate held for every sample of the
run. All three gating cells came inside the spread margins they are judged
against, for the first time this harness has run. The comparison they then
permit is a **p50 budget miss**, not a pass.

The run-level verdict is unchanged and still **VOID, exit 3, on D1** — the
modern-era admission wall, which is an owner decision and was not touched here.

## Verdict, stated three ways so none of them is mistaken for another

| Question | Answer | Authority |
|---|---|---|
| What does the evaluator exit? | **VOID (3)**, `D1: http_error_rate above zero` | `eval_workload.py`, unmodified |
| Do A/B/C's spreads still disqualify the comparison? | **No.** All six inside margin | scoped report, below |
| What does the stable comparison say? | **C misses p50**: 0.410 ms vs 0.392 ms limit | scoped report, below |
| Does NFR.WORKLOAD.1 grade? | **No**, on two independent grounds | §4 and §6 |

The two grounds are worth separating, because only one of them is new. §6:
"Nothing may grade this row from an exit status other than 0" — the evaluator
exits 3. §4: the gate is decided only by a post-merge interleaved run, and
`feat/v4-workload-harness` is unmerged, so nothing measured here can grade the
row even if it had exited 0. This is a rehearsal. It was always a rehearsal.

## Why a scoped report exists at all, and what it is not

`eval_workload.py:143` loops `LEGACY_CELLS + REPORT_ONLY_CELLS` and
`check_rep` raises on the first void, so the evaluator never reaches a verdict
for A/B/C while D/E cannot be admitted. Pointing it at a directory holding only
A/B/C does not help: `load()` raises `missing required file: D1.summary.json`,
the same exit 3. **No run, however quiet, produces an A/B/C exit status under
the pinned evaluator.** That was true before this run and is not a result of it.

So the A/B/C numbers below were produced by importing the pinned evaluator and
calling its own `check_rep`, `pooled`, `spread`, `P50_BUDGET`, `P99_BUDGET` and
margin rule over the three gating cells. Nothing is reimplemented; only the cell
set is narrowed. `eval_workload.py` was not edited — it is a §0 artefact and
§11-pinned, and scoping D/E out of grading is the release-owner question
`07-header-fix-and-rerun.md` consequence 2 already routed upward.

It is **not an evaluator exit status** and must not be recorded as one. It is
stronger than `07`'s hand arithmetic and weaker than a verdict.

Validation, before it was used on new data: run against `2026-09-14-hdrfix-v2`
it reproduces `07`'s published table exactly — per-rep p50/p99 to the digit, and
B 0.071/1.676, C 0.110/0.733 against `07`'s stated 0.070/1.677, 0.109/0.734
(`07` rounded from the same floats).

## Measured, nine gating reps

| rep | p50 (ms) | p99 (ms) | rep | p50 (ms) | p99 (ms) | rep | p50 (ms) | p99 (ms) |
|---|---|---|---|---|---|---|---|---|
| A1 | 0.374 | 2.068 | B1 | 0.374 | 2.071 | C1 | 0.410 | 1.995 |
| A2 | 0.380 | 2.078 | B2 | 0.373 | 1.992 | C2 | 0.406 | 2.057 |
| A3 | 0.373 | 2.058 | B3 | 0.382 | 2.095 | C3 | 0.412 | 2.098 |

Every rep passed all of `check_rep`'s voids: health version exact-string, argv
and checkout SHA written before the arm ran, k6 digest matching the pin,
`http_error_rate` 0, semantic assertion 1.0000, checks 1.0000.

| cell | pooled p50 | pooled p99 | p50 spread (≤0.05) | p99 spread (≤0.10) |
|---|---|---|---|---|
| A | 0.374 | 2.068 | 0.021 ok | 0.010 ok |
| B | 0.374 | 2.071 | 0.025 ok | 0.052 ok |
| C | 0.410 | 2.057 | 0.014 ok | 0.052 ok |

Six of six inside margin. `unstable` is empty, so the INCONCLUSIVE branch is
not taken and the pass rule is reached — the first time that has happened.

```
base p50 = min(A,B) = 0.374   limit = 0.392   C = 0.410   OVER
base p99 = min(A,B) = 2.068   limit = 2.275   C = 2.057   ok
```

C is **+9.6% on p50** against the faster legacy arm, where the budget is +5%.
p99 is inside its +10% budget with room — but against a baseline that itself
moved 80% since `hdrfix-v2`, which is the next section. One of the two
conditions in §6's conjunction fails, so the scoped verdict is FAIL, not PASS.

Direction agrees with `07`, which hand-forced the same comparison on contaminated
data and also found C over on p50 (+14.3% there, +9.6% here). Two runs agreeing
on the sign of an effect is not a graded result, and this is still a rehearsal.

### The p99 baseline moved too, and the relative test cannot see it

Pooled p99 on both legacy baselines rose about 80% between `hdrfix-v2` and this
run — A 1.145 → 2.068, B 1.187 → 2.071 — on identical binaries, identical pins
and identical rendered config, while pooled p50 stayed flat (A 0.371 → 0.374,
B 0.379 → 0.374). C moved with them, 1.612 → 2.057. `base p99 = min(A,B)` rose
with C, so C's tail comes in "ok" against a limit of 2.275 that was 1.260 on the
earlier run's baseline — the same 2.057 ms is ~63% over *that* limit.

The two halves of §6's conjunction are therefore not equally strong evidence.
The p50 OVER is a within-run comparison on a quantity that held its absolute
level across both boxes. The p99 ok is a within-run comparison on a quantity
whose level moved by 80% between boxes: it says C's tail tracks A/B's tail here,
and nothing about where that tail sits. Which p99 level the scored run
reproduces is not known, and a common-mode shift is invisible to a budget
expressed as a ratio.

## The quiet gate, before, during and after

Gate: `pgrep -c rustc` and `pgrep -c cargo` both 0, 1-minute load below 8.00.

**Before.** 14:11:53Z load 5.17, rustc 0, builds 0, 73 GB available — open.
Four minutes later, at 14:15:51Z, **load read 8.46, above the 8.00 line**, with
rustc and builds still 0. That excursion is recorded rather than skipped past.
A 20-second series established it as a decaying spike, not a fleet:

```
14:16:11Z 7.14   14:16:32Z 5.75   14:16:52Z 4.91   14:17:12Z 4.23   14:17:32Z 3.89
```

`ps` at the peak showed the load was peer Python and `pytest-xdist` work, no
Rust toolchain process of any kind. Launch went out at 14:19:51Z with load 3.43.

**During.** A 60-second sampler ran for the whole measure, 13 samples,
14:19:51Z–14:31:53Z, written to `<run>/quiet-gate.log`:

- 1-minute load: min 2.73, max 4.51 — every sample below 8.00
- `rustc` count nonzero in **0 of 13** samples
- build-tool count nonzero in **0 of 13** samples
- memory available: 70.1–78.4 GB

Per-rep `uptime`, recorded independently by the runner into each `meta.json`,
agrees: 1-minute load 2.68–4.04 across the nine measured reps.

**After.** 14:33:12Z load 2.93, rustc 0, builds 0.

**The gate held for the entire run.** No compile fleet appeared at any point,
and no reading was taken while one was present. The box was not idle — the peer
Python load above is real co-residency — but it is not the compile fleet the
gate keys on, and saying otherwise would overclaim the conditions.

(The raw log prints `rustc=0 0`: `pgrep -c` prints its own 0 and the `|| echo 0`
fallback adds a second. Both spellings mean zero.)

## Three runs, same pins, three load conditions

`09` withheld `modernfix-v1`'s A/B/C latencies because the run sat beside the
build fleet. They are computed here for the first time, by the same scoped
report, purely as the contaminated end of a comparison — **not** as a figure
for that run. `09`'s decision not to report them as results stands.

| run | conditions | A p50 / p99 spread | B p50 / p99 spread | C p50 / p99 spread |
|---|---|---|---|---|
| `hdrfix-v2` (09-14) | load 4.65/7.12/7.52 at A1; fleet not checked | 0.018 / 0.084 | **0.071** / **1.676** | **0.110** / **0.733** |
| `modernfix-v1` (09-14) | Rust build fleet present; B0 gateway aborted | **0.616** / **14.857** | **0.121** / **0.834** | **0.068** / **0.410** |
| `quiet-v1` (09-16) | gate held, 13/13 samples | 0.021 / 0.010 | 0.025 / 0.052 | 0.014 / 0.052 |

Bold is outside margin. The gradient runs the right way: worst under the known
fleet, middling on a box that had merely been busy (`hdrfix-v2`'s 5- and
15-minute averages were 7.12 and 7.52), clean under the held gate. On the fleet
run B's p99 reached 13.4 ms and A's p99 spread reached 14.857 — an order of
magnitude past anything measured here.

## What this rules out, and what it does not

> **Mechanism found.** The p50 FAIL recorded here is diagnosed in
> `03-finding-response-firewall-p50.md`: 4.0.0's new response-firewall scan on
> the delivered result, gated on `matches!(method, "tools/call" | "tools/list")`.
> `tools/call` is scanned twice there, `tools/list` goes from never scanned to
> scanned. Confirmed by ablation; the raw probe artefacts are in
> `04-fwprobe-artefacts.txt`. That file is a diagnosis only — it does not
> regrade this one.

**Ruled out — a structural warm-up deficiency.** In `hdrfix-v2` the first
measured rep of both failing cells was the outlier (B1 p99 2.979 against
B2/B3 ≈1.1–1.2; C1 highest of its three), which is the signature of one warm-up
rep per cell failing to absorb first-rep cost. That pattern **did not repeat**:
here A1/B1/C1 sit inside their cells' ranges, and the largest first-rep
deviation is C1's p99, which is the *lowest* of C's three. The schedule in §7
is not the cause.

**Ruled out — the spreads as a property of the gateway.** Identical binaries,
identical pins, identical rendered config, request bytes unchanged on A/B/C
since `03a21d63`. Only the machine differed, and the spreads collapsed by up to
two orders of magnitude. `07`'s INCONCLUSIVE was environmental.

**Supported, not proven — co-residency behind the `modernfix-v1` abort.** The
`memory allocation of 172000 bytes failed` in that run's B0 did not recur: every
`*.gateway.stderr` in this run is 0 bytes, B0 included. `09` left cgroup limits
unchecked as the rival explanation; they are checked now and are not in play —
`memory.max` and `memory.high` read `max` at both `user.slice` and
`user-1000.slice`, and the shell's `RLIMIT_AS` is ~90 TB. One non-recurrence
plus a ruled-out rival is consistent with co-residency; it is not a proof, and
the abort was never reproduced on demand in either direction.

**Not addressed — D/E.** Out of scope by instruction and unchanged: D1 returned
the same `-32602 An explicit idempotency key is required` at `setup()`, from the
same `admit_operation` path `09` documented. `idempotency.read_only_tools` was
not set and no authentication was configured. Report-only, and it remains the
run-level void.

**Not established — anything graded.** See the verdict table.

## Pins observed, not pins intended

Cell SHAs, health versions and k6 digest are copied verbatim to
`02-pins-quiet-v1.json.txt`: A `32f135a6`/3.5.0, B `e138680a`/3.5.1,
C/D/E `69ba9e03`/4.0.0, k6 image
`sha256:1f40432b1cbe7234e977f96c362c9bc550a2d2b583d014dd8669fe40d3e9e755`.
Every pin value is identical to `08-pins-hdrfix-v2.json.txt` and
`10-pins-modernfix-v1.json.txt`.

The arms were **not** rebuilt. `/home/<redacted>/perf-workload/arms/{A,B,C}` are the
binaries built 2026-09-13, with D and E symlinked to C, and each arm's
`.checkout_sha` was re-read by the runner into `pins.json` at this run's start
rather than assumed.

Two observations that differ from what a reader would assume, stated because §11
asks for observed values:

1. **The checkout is not at the branch tip; the artefacts are.**
   `perf-workload/harness` sits at `339ac7aae` with
   `benchmarks/workload/k6_workload.js` showing as modified. All seven §0
   artefact files were digested there, and all seven match branch tip
   `678ef103` byte for byte — the dirty `k6_workload.js` included:

   | artefact | sha256 observed in the harness checkout |
   |---|---|
   | `RELEASE-4.0.0-workload-contract.md` | `6bada5f908d5dbb18a6fe0b67b648ba855b651f79e9dc82eb5f0b1c034ec662b` |
   | `run_workload.sh` | `a8a28089e68969e9881ae7f168fb8d6bd124a469b7621582bd14e0b930b276ba` |
   | `eval_workload.py` | `80d2031be39a86f1cdc385d2268578ee0469cfd813897ca8869b83798f1fa509` |
   | `mcp_backend.py` | `41b26fca2c318de3d5927a532a3c76e1896f3c76d8f0fb4792e792af0211adf3` |
   | `k6_workload.js` | `79877b31b3c45d9f17ed03c1d2fddd5e8e409266e99bae865d51d6ceec91fc50` |
   | `gateway.workload.yaml` | `811b7a63557fac6ba4cf5bb66517a02c6ea47e0a8317a18090d0286c56d45727` |
   | `gateway.workload.mixed.yaml` | `bc775b8506b0f7cb3cbd4110ee06a6df04e86a8da93ca4358b08e16bd624a324` |

   Nothing in the contract pins the checkout, only the files, but a reader who
   runs `git log` in that directory will see an older commit and should know why.

   Six of those seven equal what `docs/requirements/workload-pins-observed.md`
   recorded on 2026-09-13. The seventh does not: that table still pins
   `k6_workload.js` at `9d3844c3…`, the script from before the header work
   (`13f12709`, `bfeec660`, `03a21d63`). Whoever ratifies §11 from that table
   would pin a script no run since 09-14 has used. Not fixed here — the file is
   an observed-values record, and correcting it is its owner's call, not a side
   effect of a rehearsal report.
2. **Rendered config is identical across runs.** `<run>/config.sha256` records
   `8b638a9e…` for the rendered `gateway.workload.yaml` and `39561094…` for the
   mixed one — the same two digests `2026-09-14-hdrfix-v2` recorded. Void 8
   (byte-identical config across A, B and C) holds, and it holds against the
   earlier run too, so the three-run comparison above is not comparing
   configurations.

Host state outside the contract, as `01-method.md` flagged: ports 39420–39424
were still reserved (`net.ipv4.ip_local_reserved_ports`), so no rep was lost to
an ephemeral-port collision. Still not recorded in `pins.json`.

## One run-level note

The first launch attempt died before any rep, at the pins step, on
`could not read version at 32f135a61fb50c20a044fb4c2347bc1cf8015d89`:
`do_measure` shells out to `git show <ref>:Cargo.toml` without `cd`-ing to
`$REPO`, so it only works when the runner is invoked from inside the harness
checkout. No gateway started, no k6 ran, no `pins.json` was written; the
directory was re-used and the run relaunched from `$REPO`. Recorded because it
is a real latent trap in `run_workload.sh` for anyone invoking it by absolute
path, not because it affected a measurement.

## Consequence

1. The spread objection that made `07` INCONCLUSIVE is answered: it was the
   machine. On a gate-held box all six spreads are inside margin and the §6 pass
   rule is reachable.
2. Reaching it does not pass it. C's pooled p50 is 0.410 ms against a 0.392 ms
   limit — a ~9.6% p50 regression where 5% is budgeted. p99 passes, on a
   baseline that moved 80% between boxes, so it is the weaker of the two
   readings. If the scored run reproduces this, NFR.WORKLOAD.1 fails on p50,
   and that is now the question worth investigating rather than the noise.
3. The run-level VOID is still D1 and still an owner decision. Nothing here
   moves it, and the `idempotency.read_only_tools` exception was not taken.
4. This is a rehearsal on an unmerged branch. §4 admits a gating number only
   from a post-merge interleaved run.

No PASS was observed. None is claimed.
