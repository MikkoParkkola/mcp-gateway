# 3.5.0 workload reference figure — reference, not gating

> **Caveat added 2026-09-14 after review, and hardened the same day after
> measurement.** These figures do not measure what they appear to. They are
> cache-hit service time. The workload sends one constant argument, and the
> 3.5.0 binary answers it from the response cache under the header shape k6
> sends: 319 of 320 calls served from cache, **1** backend invocation, measured
> on the arm-A binary with the runner's own pinned config and offered rate. The
> same probe on 4.0.0 with those headers caches nothing. This is no longer an
> undetermined fraction and no longer a caveat attached to an otherwise usable
> number — it is a reason the figure cannot be promoted to a gating baseline at
> all, and a reason it cannot be compared against a 4.0.0 run.
> See `rehearsal-2026-09-14/06-finding-response-cache.md`.

**This is not a gating baseline.** §4 of the workload contract admits a gating
number only from a post-merge interleaved scored run. `feat/v4-workload-harness`
is unmerged, so no number produced from it can gate anything. §4 names exactly one
thing that is legitimate before the merge: a rehearsal-recorded 3.5.0 number,
stored here, labelled `reference, not gating`. This is that file and nothing more.

## Figure

Cell A — `v3.5.0` at `32f135a61fb50c20a044fb4c2347bc1cf8015d89`, legacy protocol
revision `2025-06-18`, 50 virtual users, `mcp_tools_call_latency` in milliseconds.

| Rep | p50 | p90 | p99 | semantic rate | http error rate |
|---|---|---|---|---|---|
| A1 | 0.40 | 0.81 | 2.13 | 1.0000 | 0 |
| A2 | 0.38 | 0.83 | 2.07 | 1.0000 | 0 |
| A3 | 0.38 | 0.76 | 2.01 | 1.0000 | 0 |

Median across the three reps: **p50 0.38 ms, p90 0.81 ms, p99 2.07 ms.**

This is a median of three per-rep percentiles, not a percentile of pooled samples.
The two are not the same statistic and the distinction matters if anyone later
computes a ratio against it. The per-rep rows are given so the pooled figure can be
recomputed from the raw summaries if that is what a future comparison needs.

## Provenance

- Run: `2026-09-14-rehearsal2`, Spark, all three A reps completed.
- Evidence: `benchmarks/results/rehearsal-2026-09-14/`.
- k6 image pinned by digest `sha256:1f40432b1cbe7234e977f96c362c9bc550a2d2b583d014dd8669fe40d3e9e755`.
- The run this figure came from was graded **VOID** (exit 3) on cell C. That void
  is about 4.0.0's behaviour, not 3.5.0's: cell A served every call, its semantic
  assertion rate was 1.0, and its http error rate was 0. The A figure is sound
  evidence; the run as a whole still yields no scored verdict.

## Known gap

The cell ports (39420-39424) were reserved on the host before this run, because an
earlier rehearsal lost a rep to an ephemeral-port collision. That reservation is
host state and is **not** recorded in `pins.json`. A future run reproducing this
figure on an unreserved host can lose a rep with nothing in the run directory
explaining why.
