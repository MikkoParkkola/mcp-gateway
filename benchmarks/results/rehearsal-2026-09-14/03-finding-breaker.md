# Finding — 4.0.0 rejects one call in three; the cause is the shipped default rate limit, not a breaker trip

> **Corrected twice on 2026-09-14.** An earlier revision of this file
> reported the rejections as a silent circuit-breaker trip and routed them to the
> release owner as a confirmed product defect. That conclusion was not supported
> by the evidence and is withdrawn here. What replaces it is narrower, and one
> part of it lands on the harness rather than the product. A second pass then
> withdrew the token-bucket arithmetic that revision used — it was circular — and
> replaced it with a model tested at two offered rates; and it closed the open
> question about cells A and B, at the cost of the cross-version comparison.
> See `06-finding-response-cache.md`.

## What is observed (unchanged)

At 4.0.0 (cells C, D, E) roughly one call in three is answered with
`CIRCUIT_OPEN` / `Circuit breaker open for backend 'workload'` instead of the
backend's result. At 3.5.0 and 3.5.1, on a byte-identical config and the same
backend process, every call is served. The backend is a deterministic local
script that cannot fail.

## Why "the breaker opened" does not follow from that message

Read at the pinned HEAD (`69ba9e03`):

- `src/backend/ops.rs:305` gates every backend request on
  `entry.failsafe.can_proceed()`, and on `false` returns `Error::CircuitOpen`
  (`ops.rs:311-312`) and logs `Request rejected by circuit breaker`.
- `src/failsafe/mod.rs:48-50` defines that gate as
  `circuit_breaker.can_proceed() && rate_limiter.try_acquire()`.

**One gate, two causes, one error.** A rate-limiter denial and a breaker trip are
indistinguishable in the message, the error code and the log line. The string
`Circuit breaker open` is not evidence that the breaker opened.

The rate limiter is on by default and the workload never turns it off:
`src/config/features/failsafe.rs:20-21,123-130` — `enabled: true`,
`requests_per_second: 100`, `burst_size: 50`. The pinned
`gateway.workload.yaml` sets no `failsafe:` keys at all, so those defaults apply
to every arm. Both the gate and the defaults are byte-identical at 3.5.1
(`git show e138680a:src/failsafe/mod.rs`, `:src/config/features/failsafe.rs`).

## Positive evidence, not absent log lines

The earlier revision argued "no failure preceded the trip" from the absence of a
state-transition log line. The breaker does not require that inference: it keeps a
structured trip record (`BreakerOpenEvent`, `trips_count`, `last_trip_ms`,
`src/failsafe/circuit_breaker.rs:86-120,306-318`) precisely so a trip is provable
post-hoc. It is readable live through `gateway_get_stats`.

Probe, arm-C binary + pinned config, 300 `gateway_invoke` calls at ~1430 calls/s:

```
circuit_breakers: [{ server: "workload", state: "closed",
                     trips_count: 0, current_failures: 0, failure_threshold: 5 }]
```

Caveat, and it is a real one: it is not confirmed that this stats surface reads
the *same* per-identity pool slot that `ops.rs` gates on (`pool_key_for` →
`PoolKey::Shared`, `src/backend/pool.rs:173-181`). Treat `trips_count: 0` as
strong but not conclusive — the load-bearing evidence for this file's title is
the two-rate rate-limit fit below, not the stats read.

## The rates — which cut against the earlier framing

| Condition | Offered rate | Result |
|---|---|---|
| k6 measure rep, cell C | ~136 calls/s mean (8135 calls / 60.02 s), ramping | ~1/3 rejected |
| "serial" 300-call probe | ~200 calls/s | 117/300 rejected |
| paced probe, 200 calls @ 50 ms | 20 calls/s | **200/200 served** |

The single-worker probe was **faster** than the k6 load, not gentler. It therefore
never tested a milder condition, and the hypothesis table's "fails anyway" row
means only "fails when a single caller drives it harder than k6 did".

**Withdrawn:** the sentence "a single well-behaved client making steady calls
would hit it". The measurement says the opposite — at 20 calls/s nothing is
rejected. The defensible statement is that rejections appear only above some rate
between 20 and 150 calls/s.

**Withdrawn:** the earlier flat-rate fit ("cell C served 5445 ≈ 50 + 100 × 54 s";
"the fast probe served 183 ≈ 50 + 100 × 1.33 s"). It was circular. The 54 s and
1.33 s were solved for from the served counts, not measured; the rep window read
from the k6 summary is 60.02 s, at which the arithmetic does not hold. A fit
whose duration is derived from the number it predicts is not evidence.

What replaces it is the same 100 rps / burst 50 model integrated over the load
profile the script actually drives, tested at two different offered rates:

| condition | offered | window | predicted served / rejected | observed |
|---|---|---|---|---|
| cell C measure rep | 8135 over the script's ramping-VUs stages | 60.02 s | 5435 / 2700 | 5444 / 2691 |
| 320-call probe, arm C, k6 headers | 320 at a constant 160/s | 2.00 s | 250 / 70 | 249 / 71 |

Two fits of one model with the same constants — the shipped defaults, 100 rps
and burst 50 — at rates differing by a factor of the ramp, both within 0.2% and
one call respectively. That is a tested model, not a fitted curve. The paced
probe stayed under 100/s and was never throttled, as the same model requires.

## What explains cells A and B — and what it costs the comparison

Cells A and B offered the same load against the same defaults and were never
throttled. That is now measured, not open: they answered from the gateway's
response cache. `06-finding-response-cache.md` records the crossed matrix —
3.5.0 and 3.5.1 serve these calls from cache whether or not the client sends
`MCP-Protocol-Version`; 4.0.0 serves them from cache only when it is present,
and k6 never sends it. Per rep, A and B hit the backend about **once**; C, D and
E hit it on every call.

So the rejections at 4.0.0 need no regression to explain them. Once the calls
stop being cached they meet a rate limit that was always there and was never
reached before.

**The cross-version comparison is void by construction.** A/B and C/D/E did not
run the same experiment, so no conclusion about 4.0.0 versus 3.5.x is available
from this rehearsal in either direction — neither "4.0.0 regressed" nor "4.0.0
is fine". Which of the two cache behaviours is correct is a release-owner
question, routed there, not decided here.

## What to route, and where

- **To the release owner, confirmed:** one error for two causes. A rate-limit
  denial reports itself as `Circuit breaker open`, with the same error code and
  log line as a genuine trip, and `mcp_backend_circuit_state` is set to 0 for
  both (`ops.rs:305-310`). Any operator diagnosing a throttled backend is sent
  to the wrong subsystem. This is an observability defect independent of the
  workload contract.
- **Not routed:** "4.0.0 opens the breaker against a healthy backend". Not
  established. Do not cite the earlier revision.
- **To this harness:** the workload offers up to ~162 calls/s (mean ~136/s)
  against a default 100 rps limit it never configures. Whether NFR.WORKLOAD.1 intends to measure a
  throttled gateway is a contract question, and it is open. See `05-grading.md`.

## Second-order: the harness under-reports the rejection

`tools/call: no error` passes on such a rejection, because it arrives as a
well-formed JSON-RPC result carrying `isError: true` rather than a protocol
error. Only the semantic assertion catches it. Left as a recorded gap,
deliberately unpatched: §5.2 pins the k6 script's assertions, and the semantic
check already detects the condition.
