# NFR.WORKLOAD.1 — conjunct grading after rehearsal 2

The criterion is a conjunction: every part must hold. Grades below are against
what this rehearsal actually demonstrates. A rehearsal cannot produce a scored
verdict at all (§4 requires post-merge), so no grade here says "release-ready".

| # | Conjunct | Grade | Basis |
|---|---|---|---|
| C1 | Deterministic real-backend workload with successful semantic results | **MEASURED, fails at 4.0.0 — and "real-backend" is in doubt at 3.5.0/3.5.1** | Backend, tool and payload are pinned and deterministic; A and B return the expected payload on every call, C/D/E on 66.9%. The "real-backend" doubt lands on **A and B**, not C/D/E: under the header shape k6 sends, 3.5.0 and 3.5.1 answer from the response cache (measured: 319 of 320 calls, 1 backend invocation), so ~8156 passing semantic assertions per rep rest on roughly one invocation — C1 satisfied in form only. C, D and E hit the backend on every call (0 cache hits, 320/320). See `06-finding-response-cache.md`. |
| C2 | Semantic assertion holds at 100% | **NOT MET at 4.0.0** | 0.6685-0.6692 across C, D, E. Void 2. Met at 3.5.0 and 3.5.1 (1.0000) — but those arms were answering from cache, so the 1.0000 is not evidence the backend path holds at 100%. |
| C3 | Legacy, modern and mixed measured separately | **MET** | All five cells ran three reps each; D and E are recorded separately and stay report-only. |
| C4 | Preserves the P50 ≤5% and P99 ≤10% budgets | **NOT EVALUABLE** — one reason per side of the comparison | (a) C/D/E: the latency distribution blends served calls with short-circuited rejections — `02-results.md`. (b) A/B: the figures are cache-hit service time, ~1 backend invocation per rep — `06-finding-response-cache.md`. The budget compares a baseline that did not do backend work against a candidate that did, so it is not a pass and not a fail; it is not a comparison. |
| C5 | Frozen 3.5.0 baseline | **ARTIFACT PRODUCED, RULING OPEN** | `benchmarks/results/baseline-3.5.0-reference.md` now exists, labelled `reference, not gating`. Whether that satisfies "frozen baseline" is the release owner's ruling, not this harness's. Do not read this row as MET. |
| C6 | 3.5.1 available as upgrade/comparison source | **MET** | Arm B built at `e138680a`, health version 3.5.1, three clean reps. |

## What blocks a scored verdict

1. **The response cache diverges across the arms (the most serious).** Measured
   on all three binaries with the header shape k6 sends: 3.5.0 and 3.5.1 answer
   319 of 320 calls from cache (1 backend invocation); 4.0.0 answers none from
   cache (320 invocations). A/B and C/D/E therefore did not run the same
   experiment, and the cross-version comparison is void by construction. Note
   that raising `requests_per_second` in the pinned config would remove the
   rejections and leave the comparison just as void — the change that matters is
   eliminating the cache divergence, not the throttling.
   See `06-finding-response-cache.md`.
2. **The 4.0.0 rejections.** Any scored run reproducing them is VOID by
   construction, and the harness is reporting correctly. Their cause **is** now
   established: the workload offers up to ~162 calls/s against the shipped
   default rate limit (100 rps, burst 50) that the pinned config never
   overrides, reached at 4.0.0 only because these calls stopped being cached.
   The model is fitted at two offered rates, within 0.2% and one call. The
   earlier breaker diagnosis stays withdrawn — the gateway returns the same
   `Circuit breaker open` error for a rate-limiter denial as for a genuine trip.
   See `03-finding-breaker.md`.
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
requirement is about. The behavioural difference it caught turned out to be a
cache divergence rather than a regression, and the baseline arms were not
exercising the backend at all — a gap invisible until the binaries were probed
directly and side by side. A rehearsal that had produced clean numbers would have hidden
it — which is the argument for rehearsing at all.
