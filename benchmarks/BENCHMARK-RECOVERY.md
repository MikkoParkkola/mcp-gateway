# Capacity Benchmark — Recovered State (post-incident 2026-07-19)

The uncommitted benchmark files (METHODOLOGY-v2.md, capacity_bench.py,
e2e_token_bench.py, capacity_results.json, m5_results.json,
discoverability_results.json, live_footprint.*) were lost in the 2026-07-18
data-loss event (never committed). This document reconstructs their essential
state from session context so the work can resume. **Commit this file.**

## Axis (corrected twice with the operator)

The product's value is CONTEXT-WINDOW CAPACITY, not per-task token/dollar
throughput. Unused tool schemas are NOT resident; they load on demand via
search→invoke. An earlier throughput framing ("gateway is 37.7% more expensive")
was WITHDRAWN as the wrong axis.

Four effects, priority order:
1. Resident footprint (headline): gateway surface is ~flat as N grows; eager
   loading is linear.
2. Per-request carrying cost: resident schemas are re-billed every request.
3. Compaction avoidance: idle schemas shrink working space → auto-compact sooner.
4. Tool search = minor, transient overhead (do not headline).

## Measured numbers (PROVISIONAL — see GPT BLOCK below)

Resident footprint, YAML-projection proxy, real Anthropic tokenizer:
| N | Eager (direct) | Gateway README-16 | Savings | Gateway Code-Mode-2 | Savings |
|---:|---:|---:|:--:|---:|:--:|
| 10  | ~4,828  | 3,039 | 37% | 699 | 86% |
| 50  | ~18,489 | 3,039 | 84% | 699 | 96% |
| 100 | ~35,214 | 3,039 | 91% | 699 | 98% |
Per-tool median ~371 tok (real capability YAMLs). Gateway surface flat.

- Per-request carrying cost: ~1.6M tokens of window-pressure avoided over a
  50-request session at N=100.
- Compaction: ~+21 turns runway at N=100; ~1 event/500 turns avoided
  (assumptions W=200k, f=0.85, 1500 tok/turn — present as a sensitivity band).
- Tool-search overhead: +1.67 turns/task, ~1,800-tok transient droppable payload.
- Crossover / payback: ~8 tools (README-16) or ~2 tools (Code-Mode) = LESS THAN
  ONE typical ~10-12-tool MCP server.
- M5 accuracy: gateway search→invoke reached the right tool 4/4, including
  adversarial synonym-gap tasks.

## Native-client comparison (eager vs Claude Code native deferral vs gateway)

- vs EAGER clients: gateway saves ~91% resident footprint at N=100. Real, large.
- vs NATIVELY-DEFERRING client (Claude Code 2.x, names-only): footprint PARITY,
  not a win — names-only (~743 tok at N=100) is actually LOWER than gateway
  README-16 (3,039). Against such clients the gateway's value is aggregation,
  routing/ranking, policy/governance, and cross-client reach — NOT footprint.
- DISCOVERABILITY (operator's key follow-up, MEASUREMENT INTERRUPTED by incident):
  names-only deferral has a WEAK retrieval key (tool names only) — may miss a
  tool whose name doesn't match the task, or forget tools at scale. The gateway's
  SEMANTIC search bridges the synonym gap. Hypothesis: gateway wins on
  discoverability even where footprint is parity. 3C test (names-only vs gateway
  semantic search on synonym-gap tasks, N=50/100) was RUNNING when data was lost.

## GPT-5.6-sol adversarial verdict: BLOCK (must fix before backing a public claim)

1. BLOCKING — M1 counts a name+description+inputSchema YAML projection, NOT the
   actual serialized `Tool` objects a client receives (which also carry
   outputSchema, annotations, titles). Omissions differ per arm → direction of
   ratio error unknown. FIX: measure the real serialized payload from the live
   gateway (127.0.0.1:39401, ~91+ tools incl private caps) — this was the
   in-flight "live-footprint" task.
2. MAJOR — "~370 tok/tool median" is a median of cumulative means, not a real
   per-tool median (~242).
3. MAJOR — M3 "1 event avoided" is assumption-driven; present as a band.
4. MAJOR — Arm-2 native estimates aren't bounds; "parity" doesn't follow from a
   743–7,045 range.
5. MAJOR — M2 conflates cumulative throughput with capacity.
6. MAJOR — prose numbers drift from JSON (3,035 vs 3,039; ~9 vs ~8 crossover).
7. MAJOR — §4 asserts eager clients are "the majority" without evidence; 89%
   depends on avg tool size (~80% at 150 tok/tool). Scope to capacity axis +
   eager clients only.
8. MINOR — exact flatness (3,039) computed once, copied across N, not measured.

## Open work (resume order)

1. Source-faithful M1: dump the live gateway's real serialized Tool payload
   (eager) vs meta-surface, count with real tokenizer. Endpoint 127.0.0.1:39401.
   Keep private schemas out of committed files (aggregate counts only).
2. Complete the 3C discoverability measurement (names-only vs semantic search).
3. Apply GPT fixes 2–8; regenerate prose from JSON.
4. Re-run GPT adversarial pass to clear the BLOCK.
5. Open the benchmark PR; deprecate the old char/3.5 token_savings.py.
6. Only then consider whether the public "~89%" README claim needs qualifying
   (capacity axis, vs eager clients) — a separate ratified decision.

The public claim's phrasing ("flat tool-token cost as servers scale") is
defensible on the capacity axis; the exact % needs the source-faithful rerun.
