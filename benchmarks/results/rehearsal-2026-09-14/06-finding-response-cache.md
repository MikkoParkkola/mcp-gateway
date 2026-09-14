# Finding — the response cache is active on 3.5.0/3.5.1 and inactive on 4.0.0 under the harness's own headers

> **Revised 2026-09-14 after measurement.** The first revision of this file put
> the cache doubt on the 4.0.0 cells (C/D/E) on the strength of a probe run with
> a full MCP header set. Running the same probe with the header shape k6 actually
> sends inverts the result. The doubt belongs on cells A and B. The revised
> claim is measured on all three arm binaries, not inferred.

## What was measured

Each arm's own release binary, the pinned `gateway.workload.yaml`, one client,
320 `gateway_invoke` calls with the workload's pinned argument
(`{"case_reference": "042"}`) paced at 160 calls/s — the harness's own offered
rate. Each shape ran in a fresh process. `gateway_get_stats` afterwards:

| arm | version | headers | served | rejected | cache_hits | backend invocations |
|---|---|---|---|---|---|---|
| A | 3.5.0 | k6's (`Content-Type` only) | 320 | 0 | 319 | **1** |
| A | 3.5.0 | full (`Accept` + `MCP-Protocol-Version`) | 320 | 0 | 319 | **1** |
| B | 3.5.1 | k6's | 320 | 0 | 319 | **1** |
| B | 3.5.1 | full | 320 | 0 | 319 | **1** |
| C | 4.0.0 | k6's | 249 | 71 | **0** | **320** |
| C | 4.0.0 | full | 320 | 0 | 319 | **1** |

Two independent facts fall out, and they are separable because the matrix is
crossed rather than paired.

**1. The header that decides is `MCP-Protocol-Version`, not `Accept`.** A
four-way isolation on the 4.0.0 binary, fresh process per shape:

```
both_hdrs    (Accept + MCP-Protocol-Version)  cache_hits=319  invocations=1
proto_only   (MCP-Protocol-Version)           cache_hits=319  invocations=1
accept_only  (Accept)                         cache_hits=0    invocations=320
k6_neither   (neither)                        cache_hits=0    invocations=320
```

Caching follows the protocol-version header exactly. `Accept` makes no
difference in either direction.

**2. The arms differ.** 3.5.0 and 3.5.1 serve from cache whether or not the
header is present. 4.0.0 serves from cache only when it is present. k6 never
sends it.

## What this does to the numbers

The cache contaminates **A and B**, not C/D/E. Two independent grounds, and
neither extrapolates the 2.00 s probe onto a 60 s rep:

**1. Measured at the rep's own rate and duration.** The arm-A binary, k6's header
shape, 9720 calls paced at 162/s over 60.00 s — against a measured rep window of
60.02 s:

```
arm=A  n=9720  elapsed=60.00s  ok=9720  rej=0  err=0  cache_hits=9719  invocations=1
```

One backend invocation across a full rep-length window. Whatever the cache's TTL
is, it does not expire inside a rep at this rate.

**2. Rep-level corroboration, from the run itself.** Cache hits bypass the rate
limiter — arm C with the protocol header served 320 and rejected **0**; the same
binary without it rejected 71 of 320. Cells A and B took **zero** rejections in
every measured rep while offering up to ~162 calls/s against a 100 rps limit. Had
their traffic taken the backend path in any volume it would have been throttled
exactly as C's was. It was not.

Per-rep `cache_hits` was **not** captured during the reps themselves —
`gateway_get_stats` was not sampled per rep. The rep-side claim is therefore
"predominantly cache-served", carried by the rejection argument and the 60 s
replication, not read off a rep counter.

Cells C, D and E hit the backend on every call.

That reverses three things written elsewhere in this directory:

- The A/B-versus-C/D/E comparison is **void by construction**. The two sides did
  not run the same experiment: one measured the gateway's cached-response path,
  the other measured gateway→backend→gateway work. No conclusion about 4.0.0
  versus 3.5.x survives this, in either direction. Corrected in
  `03-finding-breaker.md`.
- The **§4 reference figure** (`baseline-3.5.0-reference.md`, p50 0.38 ms) is
  cache-hit service time. This is now proven on the arm-A binary under
  runner-identical config, not suspected. It is a reason the figure cannot be
  promoted at all, not a caveat attached to it.
- **C1** ("deterministic real backend, successful semantic results") is in
  doubt at **3.5.0 and 3.5.1**, where it is satisfied in form only. C/D/E are
  the arms that demonstrably exercised the backend.

## Why C's rejections follow from this

Once 4.0.0 stops serving these calls from cache, every call reaches the backend
path and meets the shipped default rate limit (100 rps, burst 50) that the
pinned config never overrides. The 320-call probe above is a second, independent
fit of that model at a different rate from the rep fit in
`03-finding-breaker.md`: 320 offered at a constant 160/s over 2.00 s predicts
`50 + 100 × 2.00 = 250` served and 70 rejected; observed 249 and 71.

## What is *not* claimed

- **Which code change** between 3.5.1 and 4.0.0 made the cached path conditional
  on the header. Not investigated.
- **Which behaviour is correct** — 3.5.x caching a request that declares no
  protocol revision, or 4.0.0 declining to. That is a release-owner call, and it
  is the question this finding routes.

## Consequence

A scored run cannot be taken from this workload until the contract says which
path it means to measure, and the pinned artifacts make all arms take the same
one. Note that raising `requests_per_second` in the pinned config would remove
the rejections and **still leave the comparison void**, because A/B would go on
answering from cache while C/D/E did backend work. The change that matters is
eliminating the cache divergence — cache disabled in every arm, or client
headers that cache in every arm. Either is a §5 ratification, not a harness
decision. Recorded here; not acted on.

## Recorded, not chased

During the full-header phase the gateway answered with `Capability
'workload_probe' ... temporarily disabled due to a high error rate`, blocking
even the cached path. The gateway's own denials appear to feed an error-rate
quarantine against a backend that never failed — which sharpens the
observability defect already routed in `03-finding-breaker.md`. It did not fire
during the measured reps (`http_error_rate` 0, every semantic failure was
`Circuit breaker open`), so it does not touch the grading. The accounting path
was not established.
