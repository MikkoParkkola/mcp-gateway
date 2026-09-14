# NFR.WORKLOAD.1 — conjunct grading after rehearsal 2

The criterion is a conjunction: every part must hold. Grades below are against
what this rehearsal actually demonstrates. A rehearsal cannot produce a scored
verdict at all (§4 requires post-merge), so no grade here says "release-ready".

| # | Conjunct | Grade | Basis |
|---|---|---|---|
| C1 | Deterministic real-backend workload with successful semantic results | **MEASURED, fails at 4.0.0 — and "real-backend" is now in doubt** | Backend, tool and payload are pinned and deterministic; A and B return the expected payload on every call, C/D/E on 66.9%. But the workload's constant argument is cacheable: a 300-call probe produced 1 backend invocation and 299 cache hits. A run can satisfy the semantic assertion while barely exercising the backend. See `06-finding-response-cache.md`. |
| C2 | Semantic assertion holds at 100% | **NOT MET at 4.0.0** | 0.6685-0.6692 across C, D, E. Void 2. Met at 3.5.0 and 3.5.1 (1.0000). |
| C3 | Legacy, modern and mixed measured separately | **MET** | All five cells ran three reps each; D and E are recorded separately and stay report-only. |
| C4 | Preserves the P50 ≤5% and P99 ≤10% budgets | **NOT EVALUABLE** (two independent reasons) | (a) C's latency distribution blends served calls with short-circuited rejections — `02-results.md`. (b) An unmeasured fraction of every arm's calls may be cache hits rather than backend work — `06-finding-response-cache.md`. Not a pass and not a fail. |
| C5 | Frozen 3.5.0 baseline | **ARTIFACT PRODUCED, RULING OPEN** | `benchmarks/results/baseline-3.5.0-reference.md` now exists, labelled `reference, not gating`. Whether that satisfies "frozen baseline" is the release owner's ruling, not this harness's. Do not read this row as MET. |
| C6 | 3.5.1 available as upgrade/comparison source | **MET** | Arm B built at `e138680a`, health version 3.5.1, three clean reps. |

## What blocks a scored verdict

1. **The response cache (new, and the most serious).** The workload sends one
   constant argument, which is cacheable; a probe on the arm-C binary with the
   pinned config answered 299 of 300 calls from cache. Until the contract states
   whether NFR.WORKLOAD.1 measures the cached path or backend round-trip work,
   the latency figures do not have a defined meaning. Resolving it changes the
   pinned config or the pinned k6 script, so it is a §5 ratification.
   See `06-finding-response-cache.md`.
2. **The 4.0.0 rejections.** Any scored run reproducing them is VOID by
   construction, and the harness is reporting correctly. Their *cause* is not
   established: the earlier breaker diagnosis is withdrawn, because the gateway
   returns the same `Circuit breaker open` error for a rate-limiter denial as
   for a genuine trip. See `03-finding-breaker.md`.
3. **The merge.** §4 admits a gating number only post-merge. The branch is
   unmerged and merging it is not this agent's call.
4. **§11 of the contract is still empty.** The evaluator reads the runner-written
   `pins.json`, never the table in the contract, so the empty table does not block
   execution — it blocks human ratification. Filling it is the lead's, from the
   sidecar.

## What the rehearsal did prove

The harness works as a detector. It caught a real behavioural difference between
3.5.1 and 4.0.0 that no existing test caught, on a byte-identical config with only
the binary changing, and it refused to grade the run rather than reporting a
number that would have read as a 76% latency regression. The semantic assertion
has teeth; C2 earned its place in the criterion.

What the rehearsal did **not** prove is that the harness measures what the
requirement is about. The cache finding says the latency path may not be the one
NFR.WORKLOAD.1 cares about, and that gap was invisible until the binary was
probed directly. A rehearsal that had produced clean numbers would have hidden
it — which is the argument for rehearsing at all.
