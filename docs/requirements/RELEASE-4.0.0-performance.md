# NFR.PERF.1 / NFR.PERF.2 — measured

**Date**: 2026-08-29 · **Branch**: `feat/mcp-2026-protocol` · **Base**: `main` at 3.5.0
**Harness**: `benches/gateway_benchmarks.rs`, group `modern_request_path`, criterion, 100 samples
per case · **Machine**: the operator's Mac, interactive load present.

> **Superseded 2026-09-03.** The numbers in this section were taken on a loaded Mac and cover only a group that has no
> 3.5.0 counterpart. A cross-version run on Spark is recorded at the end of this file and carries the verdicts. The
> reasoning here still holds; do not quote the values.

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

---

# NFR.PERF.1 / NFR.PERF.2 — re-measured on Spark, cross-version

**Date**: 2026-09-03 · **Machine**: `spark`, Linux 6.17.0-1014-nvidia, aarch64, 20 cores, no interactive load
**Before**: `v3.5.0` = `32f135a61fb50c20a044fb4c2347bc1cf8015d89` · **After**: `5c29494a` (`fix/mrtr2-continuation-handle`)
**Harness**: `benches/gateway_benchmarks.rs`, criterion, 100 samples per case, default features on both sides
**Command**: `cargo bench --bench gateway_benchmarks`, both refs in one session, one clone, one target directory,
3.5.0 first so criterion's own `change:` line compares 4.0.0 against a 3.5.0 baseline collected on the same box minutes earlier.

This section supersedes the numbers above it. Those were taken on the operator's Mac under interactive load and
covered only the `modern_request_path` group, which does not exist at 3.5.0. The reasoning above still stands; the
absolute values do not.

## Shared cases — every group that exists on both sides

All nine groups present at 3.5.0 compiled live on both sides (`firewall`, `cost-governance` and `semantic-search`
are default features in both manifests, so none of the `#[cfg(not(...))]` empty-function fallbacks was reached).
47 cases, all present on both sides, none dropped.

| case | 3.5.0 | 4.0.0 | point delta | criterion change [lo, hi] |
|---|---:|---:|---:|---|
| `budget_enforcer/check_disabled` | 3.94 ns | 4.22 ns | +6.93% | +2.52% [+0.11%, +4.90%] |
| `budget_enforcer/check_free_tool` | 20.50 ns | 20.25 ns | -1.25% | — |
| `budget_enforcer/check_paid_tool_within_limit` | 54.96 ns | 54.54 ns | -0.76% | — |
| `budget_enforcer/daily_accumulator_add` | 31.93 ns | 33.76 ns | +5.73% | +4.45% [+4.12%, +4.82%] |
| `cache_key/from_context` | 172.49 ns | 172.80 ns | +0.18% | +0.21% [+0.11%, +0.32%] |
| `cache_key/from_header` | 125.99 ns | 126.59 ns | +0.48% | +1.07% [+0.70%, +1.43%] |
| `cache_key/from_session_and_user` | 228.62 ns | 210.44 ns | -7.95% | — |
| `cache_key/key_for_slot` | 27.52 ns | 26.88 ns | -2.30% | — |
| `cache_key/schema_fingerprint/10` | 1,710 ns | 1,753 ns | +2.50% | +2.14% [+2.02%, +2.27%] |
| `cache_key/schema_fingerprint/200` | 43,738 ns | 45,000 ns | +2.89% | +2.26% [+1.90%, +2.67%] |
| `cache_key/schema_fingerprint/50` | 9,297 ns | 9,520 ns | +2.41% | +1.69% [+1.48%, +1.90%] |
| `cache_key/stable_tool_order/10` | 2,424 ns | 2,437 ns | +0.55% | +0.44% [+0.29%, +0.58%] |
| `cache_key/stable_tool_order/200` | 71,915 ns | 77,387 ns | +7.61% | +4.31% [+3.49%, +5.12%] |
| `cache_key/stable_tool_order/50` | 17,872 ns | 19,025 ns | +6.45% | +3.43% [+2.63%, +4.14%] |
| `input_scanner/scan_clean_args_5_fields` | 2,566 ns | 844.86 ns | -67.07% | — |
| `input_scanner/scan_injection_args_5_fields` | 2,552 ns | 1,364 ns | -46.54% | — |
| `mcp_frame/parse_notification` | 395.12 ns | 373.63 ns | -5.44% | — |
| `mcp_frame/parse_ping` | 69.91 ns | 70.78 ns | +1.25% | +1.15% [+0.69%, +1.54%] |
| `mcp_frame/parse_request` | 712.37 ns | 720.76 ns | +1.18% | +0.84% [+0.66%, +1.02%] |
| `mcp_frame/parse_response` | 695.40 ns | 616.48 ns | -11.35% | — |
| `redactor/scan_and_redact_clean_response` | 549.84 ns | 544.87 ns | -0.90% | — |
| `redactor/scan_and_redact_credential_response` | 644.21 ns | 654.16 ns | +1.54% | +1.64% [+0.50%, +2.82%] |
| `semantic_search/index_build_500_tools` | 1,170,000 ns | 1,166,400 ns | -0.31% | — |
| `semantic_search/index_tool_insert_into_499_tool_corpus` | 1,169,200 ns | 1,165,500 ns | -0.32% | — |
| `semantic_search/query_all_matches_500_tools` | 32,390 ns | 32,765 ns | +1.16% | +1.24% [+1.15%, +1.33%] |
| `semantic_search/query_top10/200` | 8,500 ns | 9,140 ns | +7.52% | +7.76% [+7.43%, +8.09%] |
| `semantic_search/query_top10/50` | 2,888 ns | 2,856 ns | -1.11% | — |
| `semantic_search/query_top10/500` | 19,067 ns | 18,947 ns | -0.63% | — |
| `session_sandbox/check_all_limits_passing` | 101.08 ns | 100.29 ns | -0.78% | — |
| `session_sandbox/check_backend_denied` | 86.63 ns | 90.11 ns | +4.02% | — |
| `session_sandbox/check_payload_too_large` | 110.13 ns | 111.66 ns | +1.39% | +1.19% [+0.33%, +2.04%] |
| `session_sandbox/check_tool_denied` | 86.27 ns | 94.18 ns | +9.16% | +6.07% [+5.05%, +7.11%] |
| `session_sandbox/check_unrestricted` | 4.78 ns | 4.75 ns | -0.74% | — |
| `simhash/compute/16` | 120.78 ns | 120.82 ns | +0.03% | — |
| `simhash/compute/4` | 34.94 ns | 34.95 ns | +0.03% | — |
| `simhash/compute/64` | 478.84 ns | 471.52 ns | -1.53% | — |
| `simhash/hamming_distance` | 0.25 ns | 0.26 ns | +1.29% | +1.24% [+1.10%, +1.38%] |
| `simhash/index_find_similar/10` | 15.19 ns | 15.45 ns | +1.72% | +1.63% [+1.38%, +1.86%] |
| `simhash/index_find_similar/100` | 56.77 ns | 58.31 ns | +2.72% | +2.27% [+2.02%, +2.53%] |
| `simhash/index_find_similar/500` | 278.67 ns | 282.02 ns | +1.20% | +1.20% [+1.12%, +1.28%] |
| `tool_registry/contains_hit` | 29.92 ns | 30.73 ns | +2.70% | +2.86% [+2.77%, +2.95%] |
| `tool_registry/get_hit/10` | 259.89 ns | 255.14 ns | -1.83% | — |
| `tool_registry/get_hit/100` | 257.14 ns | 255.72 ns | -0.55% | — |
| `tool_registry/get_hit/1000` | 257.14 ns | 256.69 ns | -0.18% | — |
| `tool_registry/get_miss` | 97.39 ns | 96.33 ns | -1.10% | — |
| `tool_registry/insert_one` | 275.21 ns | 280.55 ns | +1.94% | +2.11% [+1.89%, +2.30%] |
| `tool_registry/replace_server_50` | 26,139 ns | 26,848 ns | +2.71% | — |

Times are criterion's point estimate in nanoseconds. `point delta` is computed from those two estimates;
`criterion change` is criterion's own comparison against the stored 3.5.0 baseline, which uses the full sample
distribution and is the more trustworthy of the two where they disagree. Criterion emitted a change line for
23 of the 47 cases.

## Cases added since 3.5.0 — no before side exists

| case | 4.0.0 | [lo, hi] |
|---|---:|---|
| `modern_request_path/classify_legacy` | 4.62 ns | [4.52, 4.72] |
| `modern_request_path/classify_modern` | 44.71 ns | [44.70, 44.73] |
| `modern_request_path/validate_headers` | 11.04 ns | [11.03, 11.05] |
| `modern_request_path/validate_headers_encoded_name` | 27.43 ns | [27.38, 27.48] |

These are the added work of the 2026 request path, measured on Spark. They are **not** a before/after comparison
and must not be quoted as one.

## Verdict — NFR.PERF.1

> Tool-call latency through the gateway MUST NOT regress by more than 5% at P50 or 10% at P99
> against 3.5.0 on the same workload.

**PARTIAL** — in this file's own ledger vocabulary (`RELEASE-4.0.0-criteria-status.md`), not PASS.
Nothing regressed near either budget, and neither of the two estimators the clause names has a value.

- No shared case regressed by more than 10% on either estimator. Worst regression: `session_sandbox/check_tool_denied`,
  +6.07% by criterion's own comparison (`[+5.05%, +7.11%]`), +9.16% by point estimate — 86.27 ns to 94.18 ns, a delta of 8 ns.
- Two cases exceed 5% on criterion's comparison (`semantic_search/query_top10/200` at +7.76%, `session_sandbox/check_tool_denied`
  at +6.07%); six exceed it on the cruder point-estimate diff. Neither set contains anything near the 10% bound.
- The largest movement in the whole set is an improvement. `input_scanner/scan_clean_args_5_fields` fell 67%
  (2,565.90 ns to 844.86 ns) and `input_scanner/scan_injection_args_5_fields` fell 47% (2,551.80 ns to 1,364.20 ns).
- Composite of the components that run once per tool call — `mcp_frame/parse_request`, `input_scanner/scan_clean_args_5_fields`,
  `session_sandbox/check_all_limits_passing`, `budget_enforcer/check_paid_tool_within_limit`,
  `redactor/scan_and_redact_clean_response`, `mcp_frame/parse_response`: **4,679.55 ns at 3.5.0, 2,881.80 ns at 4.0.0, −38.4%.**
  That composite is a model, stated so it can be disputed: it assumes one of each per call and weights them equally. The
  per-case table above is the evidence; the composite is one reading of it.

The gap, stated rather than papered over: **this harness cannot produce a P50 or a P99 of tool-call latency.** Criterion
reports a point estimate with a bootstrap confidence interval over in-process component work. There is no wire, no backend
and no queue in the loop, so there is no latency distribution to take percentiles from. A criterion confidence interval is
not a P99 and must not be quoted as one. Settling the row at its own wording needs an end-to-end client-to-backend
comparison against a 3.5.0 binary on a fixed workload, which does not exist in this repository at any version.

What has changed since the ABSENT ruling is the class of evidence, not the class of measurement: there is now a
same-machine, same-session, cross-version comparison on every component both versions share, and it does not show a
regression anywhere near either budget.

That is why the row moves ABSENT to PARTIAL and no further, and why it stays blocking.

## Verdict — NFR.PERF.2

> Header-first routing MUST be justified by measurement against the current full-parse path, or MUST NOT ship.
> A performance change without a number is not a performance change.

**MET — satisfied in the direction the row was written for, and the Spark numbers confirm the earlier Mac reasoning.**

Header-first routing did not ship. The requirement's own remedy for an unmeasured performance change is that it does not
ship, so the row is met. The number that would have justified it, now taken on an unloaded machine:
`modern_request_path/classify_modern` costs 44.71 ns and `modern_request_path/validate_headers` costs 11.04 ns. The header
check is mandatory in either design — header and body must be shown to agree — so the most header-first could save is
33.67 ns, about **1.2% of the ~2.9 µs per-call composite above**, before any backend or network cost. That is not a
justification, and the row correctly refuses it.

## What this measurement still does not establish

- No end-to-end P50/P99, as set out under NFR.PERF.1 above. This is the same limit the Mac run declared; better hardware
  did not change the class of number.
- One run per side. There is no run-to-run variance figure, only criterion's within-run confidence interval. A second
  full pass would be needed before publishing any absolute value.
- `modern_request_path` has no 3.5.0 counterpart, so its four cases are HEAD-only cost, never a comparison.
