# Rehearsal 2 — measured numbers

Run directory: `/home/mikko/perf-workload/runs/2026-09-14-rehearsal2` (Spark).
All 15 measured reps completed; `MEASURE2_EXIT=0`. The three warm-up reps
(A0/B0/C0) are discarded by the runner and are not below.

`mcp_tools_call_latency` in milliseconds. `sem` = `semantic_assertion_rate`
(the fraction of calls whose payload contained the pinned expected text).

| Rep | p50 | p90 | p99 | sem rate | sem pass | sem fail | check rate | http error rate |
|---|---|---|---|---|---|---|---|---|
| A1 | 0.40 | 0.81 | 2.13 | 1.0000 | 8156 | 0 | 1.0000 | 0 |
| A2 | 0.38 | 0.83 | 2.07 | 1.0000 | 8157 | 0 | 1.0000 | 0 |
| A3 | 0.38 | 0.76 | 2.01 | 1.0000 | 8162 | 0 | 1.0000 | 0 |
| B1 | 0.39 | 0.81 | 2.23 | 1.0000 | 8155 | 0 | 1.0000 | 0 |
| B2 | 0.39 | 0.81 | 2.62 | 1.0000 | 8148 | 0 | 1.0000 | 0 |
| B3 | 0.39 | 0.78 | 2.08 | 1.0000 | 8162 | 0 | 1.0000 | 0 |
| C1 | 0.67 | 1.20 | 2.70 | 0.6692 | 5444 | 2691 | 0.9173 | 0 |
| C2 | 0.66 | 1.20 | 2.43 | 0.6685 | 5444 | 2700 | 0.9171 | 0 |
| C3 | 0.67 | 1.17 | 2.43 | 0.6685 | 5445 | 2700 | 0.9171 | 0 |
| D1 | 0.66 | 1.14 | 2.41 | 0.6685 | 5445 | 2700 | 0.9171 | 0 |
| D2 | 0.66 | 1.22 | 2.44 | 0.6687 | 5446 | 2698 | 0.9172 | 0 |
| D3 | 0.66 | 1.16 | 2.42 | 0.6682 | 5443 | 2703 | 0.9170 | 0 |
| E1 | 0.67 | 1.21 | 2.43 | 0.6685 | 5444 | 2700 | 0.9171 | 0 |
| E2 | 0.67 | 1.21 | 2.56 | 0.6683 | 5441 | 2701 | 0.9171 | 0 |
| E3 | 0.66 | 1.20 | 2.47 | 0.6683 | 5446 | 2703 | 0.9171 | 0 |

A and B (3.5.0, 3.5.1) serve every call. C, D and E (4.0.0) reject a third of
them. D and E are report-only cells, but their agreement with C to four decimal
places is itself evidence: the defect is indifferent to which protocol revision
the client speaks.

## Verdict

```
$ python3 benchmarks/workload/eval_workload.py /home/mikko/perf-workload/runs/2026-09-14-rehearsal2
VERDICT: VOID  (exit 3)
  C1: semantic assertion rate below 100%
EVAL_EXIT=3
```

The exit status is the verdict. Void 2 (semantic assertion below 100%) fires at
the first scored 4.0.0 rep. C, D and E would also trip void 4 (check rate 91.7%,
below the 99% floor); void 2 is reported because the evaluator stops at the first.

A void is not a failing benchmark result. It means no number from this run may be
scored — including the latency numbers, which are in the table only as evidence
about the defect, never as a performance claim.

## The latency columns are not a latency comparison

C's p50 of 0.67 ms against A's 0.38 ms looks like a 76% regression. It is not a
measurement of anything. A rejected call returns a short canned error without ever
reaching the backend, so a third of C's samples are cheaper than a served call
and the remaining two thirds are ordinary. The distribution is a blend of two
different operations. Any ratio computed from it is meaningless in both directions.
The P50 ≤5% / P99 ≤10% budgets are **not evaluable** on this data — neither met
nor missed.
