# Finding — 4.0.0 opens the backend circuit breaker against a healthy backend

## What is observed

At 4.0.0 (cells C, D, E) roughly one call in three is answered with
`CIRCUIT_OPEN` / `Circuit breaker open for backend 'workload'` instead of the
backend's result. At 3.5.0 and 3.5.1, on a byte-identical config and the same
backend process, every call is served. The backend is a deterministic local
script that cannot fail.

The gateway log shows the breaker opening **with no preceding backend failure**.
Every request logged before the first rejection reads
`Request completed successfully latency_ms=0`. There is no state-transition log
line at all — the breaker opens silently and only the rejections are visible.

## What it is not

Four hypotheses were tested directly against the arm-C binary, each with the
pinned config and the same 300-call probe.

| Hypothesis | Test | Result |
|---|---|---|
| Induced by 50-VU concurrency | 1 worker, 300 serial calls | **Fails anyway** — 117/300 rejected. Not concurrency. |
| Induced by protocol negotiation | cells D (modern) and E (mixed) | Identical to C to 4 decimals. Not protocol. |
| Attestation observe-mode audit counted as backend error | `GATEWAY_ATTESTATION_MODE=off` | **Unchanged** — 113/300 rejected. Not attestation. |
| Triggered by cumulative call count | 1 worker, 200 calls paced 50 ms apart | **200/200 served, zero rejections.** Not a count. |

The paced run is the discriminating one. Same binary, same config, same single
caller, same order of magnitude of calls — only the request rate differs, and the
defect disappears entirely. At roughly 185 calls/second the breaker opens about
1.1 seconds in; at 20 calls/second it never opens.

## What this means

The trip is **rate-dependent and not failure-driven**: sustained throughput against
a healthy, zero-error backend is sufficient to open the breaker. Because it
reproduces with one caller, this is not an artifact of the workload's 50-VU
design — a single well-behaved client making steady calls would hit it.

None of this is configured by the workload contract. The pinned config contains no
attestation, error-budget or circuit-breaker settings; the gateway reports
`backend_threshold=0.8 backend_window_size=100 backend_min_samples=10` from its own
defaults. Whatever opens the breaker is default-on behaviour introduced after 3.5.1.

Root cause inside the breaker is not established here and is not this harness's
call to make. What is established is the routing: this is a product-level defect at
HEAD, not a workload-design problem, and it belongs with the release owner.

## Second-order: the harness under-reports it

`tools/call: no error` passes on a breaker rejection, because the rejection is a
well-formed JSON-RPC result carrying `isError: true` rather than a protocol error.
Only the semantic assertion catches it. Left as a recorded gap, deliberately
unpatched: §5.2 pins the k6 script's assertions, and the semantic check already
detects the condition. Changing a pinned assertion mid-flight would be the
harness marking its own homework.
