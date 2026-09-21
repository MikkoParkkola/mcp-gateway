# NFR.PERF.1 — pre-registration, 2026-09-21

**A new contract, not an amendment.** `RELEASE-4.0.0-performance-contract.md` says in its own
opening that if something in it turns out to be wrong, the run is void and a new contract is
written. This run departs from that contract on the workload, the arms' ports, the rep count and
the evaluator, so it is written fresh rather than bolted on as Amendment 7. The departures are
enumerated below; none of them is silent.

**Committed before the scored run exists.** The thresholds, the rep count and the void gate below
are fixed at the UTC timestamp in `registered_gate.json` and in this file's commit. A pass rule
chosen after the numbers arrive is not a measurement, it is a defence — and this criterion has
already been damaged once by exactly that, when a threshold picked after the data flipped P99
between PASS and INCONCLUSIVE on identical samples.

## The criterion, verbatim

`docs/requirements/RELEASE-4.0.0-requirements.md:292`:

> Tool-call latency through the gateway MUST NOT regress by more than 5% at P50 or 10% at P99
> against 3.5.0 on the same workload.

P50 and P99 are properties of a distribution. A criterion microbenchmark reports a bootstrap
interval about a **mean** and cannot produce a percentile at all, so no criterion run — however
many cases it covers — can settle this row. This is an over-the-wire measurement:
client → gateway → backend.

## Arms

| arm | ref | commit |
|---|---|---|
| baseline | `v3.5.0` | `32f135a61fb50c20a044fb4c2347bc1cf8015d89` |
| candidate | `fix/nfr-perf-1-harness-v350-arm` base | `0c93384b` |

`32f135a6` was verified to carry the `v3.5.0` tag before anything was built
(`git tag --points-at` returns `v3.5.0`). The harness re-checks it at startup and exits rather
than substituting a nearby commit. **This matters here specifically**: a prior run of this
harness measured against **v3.5.1**, so every number it produced answered a question the
criterion does not ask.

Both binaries are built from source on the same host, in the same session, minutes apart, with
one toolchain. Both SHAs and both binary sha256 digests are recorded in `run_record.json`, and
the harness refuses to score if the two digests are equal.

## Host — and the one instruction that could not be followed

`spark`, aarch64-unknown-linux-gnu, 20 cores, rustc 1.98.1. The brief for this run asked for
`--target aarch64-apple-darwin` **and** for heavy benches to go to spark and never to the Mac.
Those cannot both hold: a darwin binary does not execute on a linux host. Spark was chosen
because the standing contract pins it (`host = spark ... a Mac number would be rejected,
correctly`), the global operating rules pin it, and the brief's own routing rule agrees. The
conflict was raised with the release lead rather than resolved silently.

## Workload

`benchmarks/workload/k6_workload.js`, scenario `load` (50 VUs: 10 s ramp, 40 s hold, 10 s ramp
down), driven by the pinned k6 image
`grafana/k6@sha256:1f40432b1cbe7234e977f96c362c9bc550a2d2b583d014dd8669fe40d3e9e755`. One copy of
the script drives both arms, supplied by the runner rather than taken from either checkout, so
"the same workload" is a fact by construction.

The tool under call is **pinned by name** (`workload_probe`), never discovered as
`tools[0].name`. That hazard is named in the standing contract and it is closed here by
construction rather than by a post-run check.

## Design — paired, counterbalanced, one gateway at a time

One pair = one baseline rep and one candidate rep, adjacent. Odd pairs run the candidate first,
even pairs run the baseline first, so position is balanced **inside one CSV** rather than
reconciled across two runs. Only one gateway process runs at a time, and the arms bind different
ports (39425 baseline, 39426 candidate).

Interleaving is what handles a shared machine's drift: pairing cancels common-mode load, and a
pair is the unit of analysis. Consequently **a void on either arm voids the pair**, never one
side — dropping one arm destroys the pairing that is the whole reason the arms alternate.

## Void conditions — a rep produces a number or a reason, never silence

Each declared before any scored rep, each carried in the CSV as a reason string:

| condition | reason recorded |
|---|---|
| gateway never becomes healthy | `gateway-never-healthy` |
| gateway exits during startup | `gateway-died-at-startup` |
| the listening socket is not owned by the PID the runner launched | `port-N-not-owned-by-launched-pid` |
| the port never frees before the next rep | `port-N-never-released` |
| k6 exits non-zero | `k6-exit-N` |
| no summary or no raw sample file | `no-summary-export` / `no-raw-samples` |
| any http error on the rep | `http-errors-<rate>` |
| any failed semantic assertion | `semantic-assertion-rate-<rate>` |
| fewer than 1000 tool-call samples | `too-few-samples-N` |

The port-ownership check is the one the standing contract's Amendment 3 had to add after a
rehearsal that would have measured a stranger's gateway. A free port is a fact with a shelf
life; reading back the owning PID is what makes it durable.

## Primary metric and how the percentiles are formed

Primary: **`mcp_tools_call_latency`**, the k6 Trend around the `tools/call` request — the literal
subject of the criterion.

P50 and P99 are **order statistics read off the sorted raw per-request samples** that k6 writes
with `--out csv`. They are nearest-rank, uninterpolated, and computed per rep. They are never
taken from a summary block, never averaged across reps, and never inferred from a mean or from a
bootstrap interval about a mean. Averaging three p99 values is not the p99 of three reps.

Each rep must deliver **at least 1000 tool-call samples**, or it is void. Below that a p99 is one
of the last handful of samples and moves by whole ranks rather than by latency.

## The pass rule — fixed before the scored run

For each metric the paired candidate/baseline ratio is taken per pair, aggregated in log space
across pairs, and given a 95% interval. Log space because the criterion is written
multiplicatively, so the interval should be symmetric on the scale the budget lives on.

```
budget:  P50 -> 1.05      P99 -> 1.10

FAIL          if the interval's LOWER bound exceeds the budget
PASS          if the interval's UPPER bound is at or below the budget
INCONCLUSIVE  otherwise
```

Overall: **FAIL** if either metric fails; else **INCONCLUSIVE** if either is inconclusive; else
**PASS**.

**Underpowered is INCONCLUSIVE, never "no effect".** If fewer pairs are scored than registered,
the verdict is forced to INCONCLUSIVE — except that a FAIL stands, because no amount of extra
power undoes an interval that already excludes the budget. This is written down because a prior
run of this criterion called a 3-rep result "underpowered, not a regression", which are not the
same sentence. At n=3 the 95% halfwidth on the paired ratio is about ±10.5% against a 5% budget:
that design could not have detected the effect it declared absent.

The rule is implemented in `benchmarks/workload/powered_ab_score.py` and the thresholds are read
back from `registered_gate.json` at scoring time. The evaluator cannot re-derive them from the
data it is scoring. Identical inputs give an identical verdict, which is the only version of "the
rule was not chosen afterwards" that a reader who was not there can check.

## Power and rep count

The scored run uses **n ≥ 52 paired reps**, with ≥ 1000 tool-call samples per arm per rep. The
exact registered count is derived from the calibration pairs — the 95% halfwidth on the paired
ratio must fit inside a third of the budget — and written into `registered_gate.json` with a UTC
timestamp **before the first scored rep runs**. The calibration pairs are numbered below 1000 and
the scored pairs from 1000 up, so calibration data cannot leak into the score.

## What this run will not establish

- It measures one workload at one load level on one shared host. Nothing here licenses a public
  throughput or latency claim.
- It settles `NFR.PERF.1` only.
- A regression it finds is attributable to the diff between the two SHAs, not to any one commit
  in that range.

## Departures from `RELEASE-4.0.0-performance-contract.md`

| | standing contract | this run |
|---|---|---|
| workload | `tests/load/k6_gateway.js`, no backends registered | `benchmarks/workload/k6_workload.js`, real backend, pinned tool |
| reps | 3 measured per arm | ≥ 52 paired |
| percentiles | per-rep, from `--summary-export` | order statistics from raw samples |
| ports | 39400 / 39401 | 39425 / 39426 |
| aggregation | pooled per arm | paired ratio per pair, aggregated in log space |

The workload change is the substantive one: the standing contract measures the Meta-MCP surface
with no backends registered, which is a harsher test of gateway overhead but not a tool call
through to a backend. The criterion says "tool-call latency through the gateway", so this run
crosses the backend boundary the criterion names.

## Amendment 1 — 2026-09-21, before any scored rep

Legal because no scored rep has run: the scored pairs are numbered from 1000 and
`reps.csv` at the time of writing contains only calibration pairs 1-4. Recorded as an
amendment rather than folded into the text above, because silently rewriting a
pre-registration is the exact move a pre-registration exists to prevent.

### A1.1 — the iteration void gate was registered but never enforced

`registered_gate.json` carries `void_gate_min_iterations`, and the harness header advertised
it as a control, but nothing read it back. A control that does not execute is worse than no
control, because it is quoted as though it did. The evaluator now applies it: a pair in which
either arm delivered fewer iterations than the registered floor is dropped whole, and
`verdict.json` reports the dropped count under `pairs_dropped.below_iteration_gate`.

The floor is 90% of the lowest per-rep iteration count seen in calibration. The gate is
almost uncoupled from what is being measured — an iteration is roughly 200 ms of scheduled
sleep plus a fixed overhead, so a 9% latency regression moves the iteration count by well
under 1%, while a rep that spent its time blocked on a busy host misses it by far more.

Added to the void table above:

| condition | reason recorded |
|---|---|
| either arm below the registered iteration floor | pair dropped, counted in `pairs_dropped` |

### A1.2 — the counterbalance is now reported, not merely performed

The harness alternates which arm runs first, and the CSV records the position, but nothing
read that column. The verdict now reports the same paired ratio computed separately over the
candidate-first pairs and the baseline-first pairs. If those two disagree materially, the
number is position rather than version, and a reader can see that instead of taking the
design on trust.

### A1.3 — the rep-count floor is held at 52

`--register` derives a rep count and takes the larger of it and a floor. The floor is set to
**52** to match the `n ≥ 52` already committed in the body of this document at `f771556c`,
which predates the existence of any gate file. Only the floor is involved: the budgets
(5% P50, 10% P99) and the decision rule are untouched, and neither has been looked at against
scored data. Raising a rep-count floor to match an already-committed document is conformance
with the pre-registration, not a threshold chosen after the numbers.

## Amendment 2 — 2026-09-21, after the scored run started

Declared mid-run, which is the part that needs justifying. The scored run began at
2026-09-21T10:14:24Z, four minutes after the gate was stamped, and this amendment lands
while it is still producing pairs. Two changes,
neither touching a threshold, the decision rule, the pair count or the baseline pin:

### A2.1 — the counterbalance split reported its two groups inverted

`order` in `reps.csv` is the slot an arm occupied inside its pair, 1 or 2. A pair whose
baseline sat in slot 2 is a pair the **candidate** opened. The reporting code read the
baseline's slot without inverting, so the candidate-first group would have been printed
under `baseline_first` and vice versa. The diagnostic that exists to expose a position
effect would have exposed its mirror image.

Found by writing the test below, not by reading the code again.

### A2.2 — the iteration gate and the order split now carry a runnable check

`powered_ab_score.py --selftest` asserts, against a fixture CSV: a pair one iteration
under the floor is dropped; a pair exactly on the floor is kept; the drop removes the
whole pair rather than the offending arm; either arm can trip it; the dropped count is
reported under its own reason; `min_iters=0` leaves calibration scoring untouched; and
the order labels follow the baseline's slot inverted. A control that decides which data
reaches the verdict is not shippable on inspection alone — A1.1 said exactly that about
a gate that was registered but never read back, and then added the gate untested.

### Why this is legal mid-run

The pass rule, the budgets, the registered pair count and the baseline commit are
unchanged and remain in `registered_gate.json` as stamped at 10:10:21Z. The scored
samples are untouched: `--read-rep`, which converts a rep into numbers, is not modified,
so every pair already on disk keeps the value it had. What changed is how the finished
pairs are labelled in the report and whether the evaluator has a test. Neither could be
selected to favour an outcome, because no verdict has been computed and no scored pair
has been looked at. Recorded here rather than folded in silently, on the same principle
as Amendment 1.
