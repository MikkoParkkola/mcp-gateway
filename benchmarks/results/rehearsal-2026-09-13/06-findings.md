# Rehearsal findings — NFR.WORKLOAD.1

Run: `~/perf-workload/runs/2026-09-13-rehearsal` on Spark. Build exit 0, all five
arms. Nine reps completed (A0 B0 C0 warm-ups, A1 B1 C1, A2 B2 C2) before the run
stopped at A3.

## Measured latency, `mcp_tools_call_latency` (ms)

| Rep | p50 | p90 | p99 | k6 checks passed | failed |
|---|---|---|---|---|---|
| A1 (v3.5.0) | 0.46 | 2.77 | 12.19 | 32044 | 0 |
| A2 (v3.5.0) | 0.42 | 1.43 | 5.11 | 32448 | 0 |
| B1 (v3.5.1) | 0.43 | 1.73 | 5.94 | 32384 | 0 |
| B2 (v3.5.1) | 0.41 | 1.20 | 4.04 | 32500 | 0 |
| C1 (4.0.0) | 0.74 | 2.51 | 8.87 | 29625 | 2623 |
| C2 (4.0.0) | 0.67 | 1.39 | 3.56 | 29811 | 2681 |

Cell C's latency figures are **not usable as latency data**: a third of its calls
never reached the backend, and a rejected call returns faster than a served one.

## Finding 1 — cell C fails the semantic assertion (void 2)

`semantic_assertion_rate` on C1 is `0.6746`; on A1 and B1 it is exactly `1`.
The failing check is `tools/call: semantic payload matches the pin`, 67% on C.

Cause: the gateway's circuit breaker opens on the `workload` backend under the
contract's 50-VU load and returns

    "Circuit breaker open for backend 'workload'", isError: true,
    error_code: CIRCUIT_OPEN

Reproduced standalone against the C arm, outside k6: 241 of 300 concurrent calls
mismatched, with the breaker open ~700ms after startup
(`mcp_gateway::backend::ops: Request rejected by circuit breaker
backend=workload key=Shared`).

A/B/C load a byte-identical rendered config (§5.1, digests in `config.sha256`)
and the same backend script, so the only difference between the arms is the
binary. The breaker exists in all three refs; only 4.0.0 trips it here. **What
makes 4.0.0 fail where 3.5.x does not is not yet established** — the failures
that open the breaker happen inside the first ~700ms and were not isolated.

Harness gap this exposes: the check `tools/call: no error` passes 100% on C,
because a breaker rejection is a JSON-RPC *success* whose body carries
`isError: true`. Only the semantic assertion caught it. An error-shaped result
should not be able to satisfy a "no error" check.

## Finding 2 — void 4 was unconditional (fixed)

`eval_workload.py` read `metrics.checks.rate`. k6's `--summary-export` writes
`{"passes", "fails", "value"}` for a Rate metric and never `"rate"`, so the read
was `None` on every real run and void 4 raised on the first measured rep. The
evaluator could not return PASS, FAIL or INCONCLUSIVE against real output at all.

The self-check did not catch it: its fixtures built `{"rate": x}`, a shape the
load generator never emits. Voids 2 and 3 already used the tolerant `rate()`
helper; only void 4 bypassed it. Fixed, and the fixtures now use k6's spelling.

## Finding 3 — the pinned cell ports sit in the ephemeral range

A3 died with `Gateway error: IO error: Address already in use (os error 98)`.
Spark's `ip_local_port_range` is `32768 60999` and nothing was reserved, so the
contract's pinned ports 39420-39424 are inside the range the kernel hands out as
client source ports. k6's connection churn can take 39420 as a source port, after
which the next gateway cannot bind it.

The runner's pre-check cannot see this: `port_open` (run_workload.sh:128) is a
TCP *connect* probe, so it detects a listener and never an ephemeral client
socket. `stop_gateway` also gives up its wait loop after 20s and proceeds anyway
(run_workload.sh:140-143).

Worked around for the re-run with
`sysctl net.ipv4.ip_local_reserved_ports=39420-39424`, which keeps the contract's
pinned port numbers intact. A durable fix belongs in the contract or in the
runner's preflight, not in one operator's sysctl.
