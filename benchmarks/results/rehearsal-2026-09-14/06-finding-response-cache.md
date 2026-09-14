# Finding — the workload's calls are cacheable, so the latency figures may not measure the backend

This one is the harness's own defect, not the product's. It was found while
testing the breaker hypothesis (`03-finding-breaker.md`) and it is the more
consequential of the two, because it undermines the numbers rather than their
interpretation.

## What was measured

Arm-C binary, pinned `gateway.workload.yaml`, a single client issuing 300
`gateway_invoke` calls with the workload's own pinned argument
(`{"case_reference": "042"}` — the constant the k6 script sends), at ~1430
calls/s. Afterwards, `gateway_get_stats`:

```
"invocations":  1,
"cache_hits":   299,
"top_tools":  [{ "server": "workload", "tool": "workload_probe", "count": 1 }]
```

**300 calls, one backend invocation.** The gateway answered 299 of them from its
response cache without touching the backend process.

## Why this matters for NFR.WORKLOAD.1

`benchmarks/workload/workload.js` sends one constant argument for every
iteration of every VU:

```js
arguments: { case_reference: "042" }
```

Identical arguments are exactly the condition that makes a response cacheable.
So an unmeasured fraction of the 8145 calls per measured rep may never have
reached the backend, and `mcp_tools_call_latency` may be measuring cache-hit
service time rather than gateway→backend→gateway work. A p50 of 0.38 ms is
consistent with that reading.

This is not a small caveat. It bears directly on the contract's own conjuncts:

- **C1** ("deterministic real backend, successful semantic results") is weakened.
  The semantic assertion still passes on a cached response, so a run can satisfy
  C1 while barely exercising the backend.
- **C4** (P50/P99 budgets) was already `NOT EVALUABLE` for a different reason.
  This gives a second, independent reason: a latency budget over a cache hit is
  not a latency budget over the work the requirement is about.
- The **§4 reference figure** in `benchmarks/results/baseline-3.5.0-reference.md`
  inherits the same doubt. It remains labelled *reference, not gating*; this
  finding is a further reason not to promote it.

It is also a live confound for the A/B-versus-C/D/E difference in
`03-finding-breaker.md`: if cache behaviour differs across the three versions,
the served/rejected split could follow from that rather than from any change in
gating.

## What is *not* claimed

The cache-hit fraction during the actual k6 reps was not measured —
`gateway_get_stats` was not captured per rep, and the run is finished. The
300-call probe proves the mechanism is active on this binary with this config and
this argument; it does not quantify what happened inside the measured reps. That
measurement is the first thing a next rehearsal should capture.

Varying the argument is not an available workaround: the fixture pins arguments
and answers anything else with
`JSON-RPC error -32602: arguments did not match the pin` (confirmed by probe).
So this cannot be fixed by making each call distinct without also changing the
fixture's pin — i.e. it is a contract-level change, not a script tweak.

## Consequence

A scored run should not be taken from this workload until the contract says
explicitly which of these it wants:

1. the gateway's cached-response path (then say so, and the current script is
   right), or
2. gateway→backend round-trip work (then the cache must be disabled in the
   pinned config, or the fixture's argument pin widened so calls are distinct).

Either way the pinned config and/or the pinned k6 script change, which is a §5
ratification, not a harness decision. Recorded here; not acted on.
