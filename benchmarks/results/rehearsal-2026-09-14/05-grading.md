# NFR.WORKLOAD.1 — conjunct grading after rehearsal 2

The criterion is a conjunction: every part must hold. Grades below are against
what this rehearsal actually demonstrates. A rehearsal cannot produce a scored
verdict at all (§4 requires post-merge), so no grade here says "release-ready".

| # | Conjunct | Grade | Basis |
|---|---|---|---|
| C1 | Deterministic real-backend workload with successful semantic results | **MEASURED, fails at 4.0.0** | Backend, tool and payload are pinned and deterministic; A and B return the expected payload on every call, C/D/E on 66.9%. |
| C2 | Semantic assertion holds at 100% | **NOT MET at 4.0.0** | 0.6685-0.6692 across C, D, E. Void 2. Met at 3.5.0 and 3.5.1 (1.0000). |
| C3 | Legacy, modern and mixed measured separately | **MET** | All five cells ran three reps each; D and E are recorded separately and stay report-only. |
| C4 | Preserves the P50 ≤5% and P99 ≤10% budgets | **NOT EVALUABLE** | C's latency distribution blends served calls with short-circuited rejections. See `02-results.md`. Not a pass and not a fail — the data cannot answer the question. |
| C5 | Frozen 3.5.0 baseline | **ARTIFACT PRODUCED, RULING OPEN** | `benchmarks/results/baseline-3.5.0-reference.md` now exists, labelled `reference, not gating`. Whether that satisfies "frozen baseline" is the release owner's ruling, not this harness's. Do not read this row as MET. |
| C6 | 3.5.1 available as upgrade/comparison source | **MET** | Arm B built at `e138680a`, health version 3.5.1, three clean reps. |

## What blocks a scored verdict

1. **The 4.0.0 defect.** Any scored run reproducing the breaker behaviour is VOID
   by construction. Fixing the harness cannot convert it; the harness is reporting
   correctly. See `03-finding-breaker.md`.
2. **The merge.** §4 admits a gating number only post-merge. The branch is
   unmerged and merging it is not this agent's call.
3. **§11 of the contract is still empty.** The evaluator reads the runner-written
   `pins.json`, never the table in the contract, so the empty table does not block
   execution — it blocks human ratification. Filling it is the lead's, from the
   sidecar.

## What the rehearsal did prove

The harness works. It caught a real behavioural difference between 3.5.1 and
4.0.0 that no existing test caught, on a byte-identical config with only the
binary changing, and it refused to grade the run rather than reporting a number
that would have read as a 76% latency regression. The semantic assertion has
teeth; C2 earned its place in the criterion.
