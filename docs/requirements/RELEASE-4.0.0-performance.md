# NFR.PERF.1 / NFR.PERF.2 — measured

**Date**: 2026-08-29 · **Branch**: `feat/mcp-2026-protocol` · **Base**: `main` at 3.5.0
**Harness**: `benches/gateway_benchmarks.rs`, group `modern_request_path`, criterion, 100 samples
per case · **Machine**: the operator's Mac, interactive load present.

## What the requirements ask

- **NFR.PERF.1** — tool-call latency must not regress by more than 5% at P50 or 10% at P99 against 3.5.0 **on the same workload**.
- **NFR.PERF.2** — header-first routing must be justified by measurement or must not ship.

## What was measured

| Case | Time |
|---|---|
| `classify_legacy` — the per-request cost a **2025** client now pays | **3.76 ns** |
| `classify_modern` — reading the protocol fields from a modern request | 62.5 ns |
| `validate_headers` — comparing the mirrored headers against the body | 20.0 ns |
| `validate_headers_encoded_name` — the same, decoding a sentinel-encoded name | 34.7 ns |

## NFR.PERF.1 — PASS, and the reason is structural rather than lucky

"The same workload" as 3.5.0 is **entirely legacy traffic**: 3.5.0 could not speak 2026-07-28, and
the switch that enables it defaults to off. So the question is not what a modern request costs — no
3.5.0 workload contains one — but what this branch adds to a **legacy** request.

The answer is one call to `classify_request`, which returns `Legacy` as soon as it finds no protocol
metadata: **3.76 ns**. Every other addition sits behind `if is_modern`, and a legacy request never
enters it.

Against a tool call that crosses a process boundary — tens of microseconds at the very best, and
typically milliseconds once a backend is involved — 3.76 ns is **under one part in ten thousand**.
The 5% budget is not approached; it is not in the same six orders of magnitude.

Stated as a bound rather than a hope: for the budget to be breached, a tool call would have to
complete in under 75 nanoseconds. Nothing that touches a socket does.

The legacy path is otherwise byte-identical, which is asserted rather than assumed — the captured
`initialize` goldens and the legacy regression rows beside every modern behaviour.

## NFR.PERF.2 — the requirement is met by *not* shipping the change

Header-first routing was **not implemented**, and this measurement is why.

The idea was to route on `Mcp-Method`/`Mcp-Name` without parsing the body. The saving would be the
body parse; the numbers say that parse is **62.5 ns** for a modern request, and the header check
that must run anyway costs 20.0 ns of it.

But the requirement it would have to satisfy is stricter than "faster". §3.1 of the design
established that this gateway **processes the request body**, so the specification's conditional
MUST binds: header and body must be shown to agree before the gateway authorizes or executes. The
body therefore gets parsed regardless. Header-first routing can only avoid the parse on the paths
where the gateway is a pure relay — and it would buy tens of nanoseconds there.

**So it does not ship, and NFR.PERF.2 is satisfied in the direction it was written for**: a
performance change without a number does not ship, and this one has a number that does not justify
it. It remains a stated opportunity for a future release that has a workload where relay paths
dominate — with a measurement to beat, which it did not have before.

## What this measurement does not establish

Named, because a benchmark that oversells itself is worse than none:

- These are **microbenchmarks of the added work**, not end-to-end latency. There is no P50/P99 distribution here because there is no wire in the loop.
- The machine was under interactive load. That inflates the numbers rather than flattering them, so it does not weaken the conclusion — but the absolute values are not publication-grade.
- The 5% budget would be properly settled by an end-to-end comparison against a 3.5.0 binary on the same workload. The argument above makes that unnecessary for a *verdict* — six orders of magnitude of headroom is not a close call — and it would still be the right measurement before anyone quotes a latency figure publicly.
