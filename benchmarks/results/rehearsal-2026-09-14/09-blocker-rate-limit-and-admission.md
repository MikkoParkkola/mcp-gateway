# 09 — D/E have two walls, not one; and the peer's ruling rests on a false premise

Author: `workload-d`. Read-only investigation, 2026-09-14. No Spark run was
started for this document and none is needed to justify it — every claim below
is either source or a number already measured in `07-header-fix-and-rerun.md`.

## Verdict

NFR.WORKLOAD.1 does not close. Two separate findings:

1. **D/E cannot be graded by clearing admission alone.** A second, independent
   wall — the shipped rate limit — throttles the modern cells below the offered
   load, which voids them under §8 regardless of what admission does.
2. **The ruling routed in `678ef103` rests on a technical premise that is
   false.** `idempotency.read_only_tools` does *not* make a call cache-eligible.
   That does not make option (a) safe — it is unsafe for a different reason
   (below) — but the owner was given the wrong reason.

A/B/C grade **INCONCLUSIVE (exit 2)** on the complete run. That is unchanged by
anything D/E do.

## Wall 1 — admission (known)

`src/gateway/meta_mcp/admission.rs:130-180`. A modern-shape `tools/call` with no
idempotency key is rejected `-32602`; supplying one then demands a verified
principal, `-32003`. D1's verbatim failure:

```
level=error msg="Error: void: pinned tool workload_probe did not return the pinned payload;
got {\"jsonrpc\":\"2.0\",\"id\":\"3-tools/call\",\"error\":{\"code\":-32602,
\"message\":\"JSON-RPC error -32602: An explicit idempotency key is required\"}}"
```

`idempotency.read_only_tools` would clear this wall. It is the only wall the
peer's ruling accounts for.

## Wall 2 — the rate limit (new, decisive)

`benchmarks/workload/gateway.workload.yaml` does not set `requests_per_second`.
The whole file is a host binding and one backend command. So the shipped
defaults apply — `src/config/features/failsafe.rs:20-21`:

```rust
const DEFAULT_RATE_LIMIT_RPS: u32 = 100;
const DEFAULT_RATE_LIMIT_BURST: u32 = 50;
```

k6 offers roughly 137/s: `ramping-vus`, 10s ramp to 50 VUs, 40s held, 10s down
(`benchmarks/workload/k6_workload.js:57-62`), closed-loop.

On the **real-backend** path the modern cells are therefore throttled, the
semantic assertion lands below 100%, and §8 voids them — with or without
admission cleared. Clearing wall 1 alone does not yield gradeable D/E.

This is corroborated by measurement, not only by arithmetic.
`07-header-fix-and-rerun.md` recorded D1/D2/D3 and E1/E2/E3 at semantic
**0.6630-0.6636**, checks **0.9158-0.9159**, zero HTTP errors — the same
magnitude as rehearsal 2's pre-fix D1 at 0.6685. Zero HTTP errors with a third
of the assertions missing is the signature of shed load, not of a broken client.

## Correction to `678ef103`

The peer's ruling states that declaring `workload_probe` read-only "makes calls
cache-eligible". That is false, and the disagreement is material because it is
the stated reason the option was disfavoured.

- `is_read_only` has exactly **one** production consumer: `admission.rs:96` and
  `:98`, both inside `read_only_target`. (`src/config/features/idempotency.rs:26`
  is the definition; `src/security/data_flow.rs:425,433` are unrelated test
  function names.)
- Its only effect is to return `SyncAdmission::Unprotected`. The production
  `Unprotected` sites are `src/gateway/server/mod.rs:2832` → `None` and
  `src/gateway/router/handlers.rs:1580` → `(None, None)`. No lease, no replay,
  no cache is reachable from there.
- The response cache is a **separate mechanism**, keyed on
  `cache_protocol_revision` — the `MCP-Protocol-Version` header or the session
  revision (`src/protocol/meta.rs`). `read_only_tools` cannot enable it.

Declaring the probe read-only is also accurate rather than a loophole:
`benchmarks/workload/mcp_backend.py` is a frozen fixture with one tool, one
fixed argument, one fixed payload and, per its own docstring, "no per-call I/O
of any kind — nothing is logged, opened or flushed to disk inside a
`tools/call`". Contract §5 asserts the same.

## Why option (a) is still wrong — the real reason

`cache_protocol_revision` returns `Some` for a modern request whose
`_meta` protocol version is in `MODERN_VERSIONS` (`= ["2026-07-28"]`,
`src/protocol/meta.rs:248`), via `accepted_modern_revision`. The peer's modern
block supplies exactly that. So with admission cleared, D/E plausibly land in
the response cache.

`06-finding-response-cache.md` measured what that looks like on the 4.0.0
binary: `proto_only cache_hits=319 invocations=1`, and a full rep at
`n=9720 ok=9720 cache_hits=9719 invocations=1`. One backend invocation per rep.

D/E would then report 100% semantic and a flattering latency while measuring the
cache — which is precisely what §3 says the modern cells exist not to measure.
Reachable, and worthless. (Source inference for the modern shape; the
`proto_only` numbers above are measured on the legacy path.)

## Options for the release owner

This is the owner's call. I have not edited the config, the budgets, or the
evaluator.

- **(a) `read_only_tools` + modern block.** Non-void, but measures the response
  cache. Defeats §3's purpose. Not recommended.
- **(b) Authenticated principal + per-call idempotency key.** Preserves the
  backend path, but wall 2 still applies — **still void**. This option does not
  work.
- **(c) Raise `requests_per_second` in the pinned config.** D/E would measure the
  real backend at 100% semantic. But the config is declared byte-identical
  across cells, so re-pinning invalidates A/B/C and costs a full five-cell
  re-run.
- **(d) Scope §8's void condition to the gating cells.** D/E's throttled 0.663
  records as observed report-only behaviour; the run grades on A/B/C alone.
  Costs nothing, changes no measurement, and `07` already flagged the drafting
  tension: §8 is unscoped while §3 and §6 both scope D/E out of grading.

**(d) is the cheapest and best-supported.** It needs a ratification, not a code
change, and I must not make it true by editing the evaluator's loop.

## Grading the run that exists

`2026-09-14-modernfix-v1` is dead and partial (A1-A3, B1-B3, C1-C3, D1; D2, D3,
E1-E3 missing) → VOID(3). The complete run is `2026-09-14-hdrfix-v2`, written up
in `07`. Hand-computed there, because `check_rep` aborts at D1 and no
`verdict.json` is produced:

| cell | p50 | p99 |
|---|---|---|
| A1 | 0.365 | 1.152 |
| A2 | 0.371 | 1.063 |
| A3 | 0.372 | 1.145 |
| B1 | 0.395 | 2.979 |
| B2 | 0.369 | 1.187 |
| B3 | 0.379 | 1.113 |
| C1 | 0.467 | 2.462 |
| C2 | 0.424 | 1.612 |
| C3 | 0.421 | 1.420 |

All semantic 1.0000, checks 1.0000, zero HTTP errors.

Pooled: A p50 0.371 / p99 1.145, spread 0.019 / 0.084 — within margin.
B p50 0.379 / p99 1.187, spread **0.070** / **1.677** — over margin.
C p50 0.424 / p99 1.612, spread **0.109** / **0.734** — over margin.
Margins are p50 0.05, p99 0.10. Two cells exceed → **INCONCLUSIVE, exit 2**.

Forced through anyway: `base_p50 = min(A,B) = 0.371`, limit 0.390, C 0.424 →
FAIL; `base_p99 = 1.145`, limit 1.260, C 1.612 → FAIL. `unstable` is computed
over the legacy cells only, so D/E cannot flip the verdict either way.

## Task line item I cannot deliver

Promoting D/E thresholds is **blocked**. Those reps measured 0.663 semantic. A
threshold derived from voided data would be a fabricated ceiling. It is not
deferred for convenience; there is no valid input for it until (c) or (d) lands.

## No PASS

No PASS was observed and none is claimed.
