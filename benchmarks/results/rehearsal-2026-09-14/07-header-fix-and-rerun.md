# Header fix verified, rerun still VOID — different cause

## What changed

`benchmarks/workload/k6_workload.js`: every HTTP request on the legacy cells
(A, B, C) now carries `MCP-Protocol-Version: $PROTOCOL_VERSION` (previously
only `initialize`'s JSON-RPC body carried a protocol version, and only inside
`params`, which `cache_protocol_revision` never reads). D/E (modern era,
`2026-07-28`) are explicitly excluded — see "Why D/E were left alone" below.
Two commits: `13f12709` (send it on every call), `bfeec660` (scope it to
legacy cells after D1 broke — see next section).

## The A/B/C fix is confirmed by measurement

Run `2026-09-14-hdrfix-v2`, same arm binaries as rehearsal 2
(`pins.json`: A=`32f135a6`/3.5.0, B=`e138680a`/3.5.1, C/D/E=`69ba9e03`/4.0.0 —
unchanged, because the fix is harness-only: `git diff --stat 69ba9e03..bfeec660
-- src/` is empty), three measured reps each:

| rep | p50 (ms) | p99 (ms) | semantic | http_err | checks |
|---|---|---|---|---|---|
| A1 | 0.365 | 1.152 | 1.0000 | 0 | 1.0000 |
| A2 | 0.371 | 1.063 | 1.0000 | 0 | 1.0000 |
| A3 | 0.372 | 1.145 | 1.0000 | 0 | 1.0000 |
| B1 | 0.395 | 2.979 | 1.0000 | 0 | 1.0000 |
| B2 | 0.369 | 1.187 | 1.0000 | 0 | 1.0000 |
| B3 | 0.379 | 1.113 | 1.0000 | 0 | 1.0000 |
| C1 | 0.467 | 2.462 | 1.0000 | 0 | 1.0000 |
| C2 | 0.424 | 1.612 | 1.0000 | 0 | 1.0000 |
| C3 | 0.421 | 1.420 | 1.0000 | 0 | 1.0000 |

C took **zero** rate-limit rejections across 3 reps at the harness's offered
rate (~137 iterations/s, ~8200 iterations/rep) — the exact condition that
produced 71/320 rejections and 66.9% semantic assertion in rehearsal 2's
06-finding. Semantic assertion is 100% on all three gating cells, for the
first time this harness has run. The cache-divergence finding in
`06-finding-response-cache.md` is resolved for the cells it gates.

## Rerun is still VOID — D1, not A/B/C

```
$ python3 eval_workload.py /home/<redacted>/perf-workload/runs/2026-09-14-hdrfix-v2
VERDICT: VOID  (exit 3)
  D1: semantic assertion rate below 100%
```

`check_rep()` loops `LEGACY_CELLS + REPORT_ONLY_CELLS` and raises on the first
void, so this aborts before a `verdict.json` is written and before A/B/C's own
numbers are graded — a run-level void, not a cell-level one, per §8's
unscoped wording ("any measured rep").

D1 (and D2/D3/E1-3) measured **0.6630-0.6636** semantic assertion,
**0.9158-0.9159** checks pass rate, 0 http errors — the same magnitude
rehearsal 2 measured on D **before any of these fixes existed**
(`02-results.md`: D1 sem=0.6685). This is not a regression introduced by this
change; it is unaddressed.

### Why D/E were left alone, and what happened when they weren't

The first version of this fix (`13f12709`) sent the header unconditionally.
D1 then failed at `setup()`, before any measured request:

```
initialize failed: {"error":{"code":-32602,"message":"missing required
request metadata: io.modelcontextprotocol/protocolVersion,
io.modelcontextprotocol/clientCapabilities"}}
```

`declares_modern_era("2026-07-28")` is true, so the header alone flips
`classify_request`'s shape decision to `Modern` — which then requires
`_meta.protocolVersion` and `_meta.clientCapabilities` on the request body.
This script's bodies never carry `_meta` (the `initialize` call's
`protocolVersion` is a top-level JSON-RPC param, unrelated to the meta-mcp
`_meta` block `classify_request` reads). `bfeec660` scoped the header to
`!PROTOCOL_VERSION.startsWith("2026-")`, restoring D/E to their pre-existing
behaviour: no header, body carries no `_meta` either, so `classify_request`
falls through to `Legacy` with no header and no session-bound revision (every
`rpc()` call is a fresh, unlinked session — no `Mcp-Session-Id` is ever
captured or replayed) → `cache_protocol_revision` returns `None` → every call
reaches the backend → the shipped 100 rps / burst 50 default throttles the
harness's ~137/s offered rate, same mechanism as `03-finding-breaker.md`.

Making D/E cache-eligible would mean adding `_meta.protocolVersion` /
`_meta.clientCapabilities` to every `tools/call` body for those two cells —
a materially different, larger change than "send a header", and one that
would stop D/E from measuring what §3 says they exist to measure ("the
genuinely new component is the deterministic real-backend arm" — caching
them removes the real-backend property, not just the throttling). That is
out of scope for this fix and is not attempted here. Raising the rate limit
was ruled out explicitly by the same reasoning `06-finding-response-cache.md`
already gave for C: it doesn't touch the actual mismatch (D/E were never
supposed to be cached in the first place — they're the arms with no
counterpart, measured for their own sake).

## What the numbers say if the run had not voided

Not an evaluator output — `check_rep` never reaches the point of building
`verdict.json` once D1 voids. Computed by hand from the same summary.json
files, using the evaluator's own formulas (`pooled` = per-cell median of 3
reps, `spread` = `(max-min)/min`):

| cell | p50 (pooled) | p99 (pooled) | p50 spread | p99 spread |
|---|---|---|---|---|
| A | 0.371 | 1.145 | 0.019 (≤0.05 ok) | 0.084 (≤0.10 ok) |
| B | 0.379 | 1.187 | **0.070 (>0.05)** | **1.677 (>0.10)** |
| C | 0.424 | 1.612 | **0.109 (>0.05)** | **0.734 (>0.10)** |

B and C both exceed the spread margin they'd be judged against (driven by an
outlier first measured rep in each — B1 p99=2.979ms vs B2/B3 ~1.1-1.2ms, C1
p50/p99 both the highest of its three reps) — §6's own rule reads this as
**INCONCLUSIVE**, not decided in either direction, before the pass/fail
comparison is even reached.

Forcing the comparison anyway: `base_p50=min(A,B)=0.371ms`,
`limit_p50=0.390ms`, `C.p50=0.424ms` → **fails** the budget.
`base_p99=min(A,B)=1.145ms`, `limit_p99=1.260ms`, `C.p99=1.612ms` → **fails**.
Neither number should be read as the row's verdict — it is hand-computed,
not evaluator output, and the spread already disqualifies it as inconclusive
first. Recorded because the contract asks for observed values, not because it
settles anything.

## Consequence

1. The cache-divergence defect this task was scoped to (A/B/C) is fixed and
   measured fixed. That part of NFR.WORKLOAD.1's blocker is closed.
2. The run is still VOID, for a different, pre-existing reason (D1/D2/D3 —
   and E1/E2/E3 — never reach 100% semantic assertion because the modern-era
   cells were never cache-eligible under this harness, by design, both before
   and after this fix). §8's void condition 2 is unscoped across all five
   cells while §6's pass rule and §3's "no counterpart, never compared"
   language both scope D/E out of grading — that tension is what turns a
   report-only cell's expected behaviour (real backend work meeting a real
   rate limit) into a run-level VOID. This is a contract/evaluator scoping
   question, the same kind of call `06-finding-response-cache.md` routed to
   the release owner rather than deciding unilaterally in the harness.
3. Even setting the D1 void aside, the gating comparison itself would land on
   INCONCLUSIVE (B and C's per-rep spread), not PASS — see above.

No PASS was observed. None is claimed.
