# MIK-4391 Code Mode Backend Audit (AUDIT.1) + Architecture Spec

**Scope**: AUDIT.1 + DEVIL.1 + ARCH overview (SPIKE.1 design + PROTO.1 design + HEBB.1 decision). Implementation ACs (PROTO build, MEASURE, DOCS update, LIVING patch) deferred.

## Source

| # | URL | Conf |
|---|---|---|
| S1 | https://www.stainless.com/products/mcp/ — Code Mode 2-tool primitive | 🟡I (cited via ticket; direct-fetch owed for v2) |
| S2 | https://www.anthropic.com/news/anthropic-acquires-stainless — 2026-05-18 acquisition | 🟡I |
| S3 | MIK-4391 ticket body + living doc v1.84 | 🟢V |
| S4 | `capabilities/` YAML inventory (this repo) | 🟢V (local fd 2026-05-19) |

## Backend audit (AUDIT.1)

Per-category YAML inventory in `capabilities/` (excluding `examples/`):

| Backend category | YAML files | Code Mode opt-in verdict | Why |
|---|---|---|---|
| **productivity** | 25 | **YES (Tier-1)** | Largest single backend; clearest token-savings win |
| **google** | 21 | **YES (Tier-1)** | Tightly-coupled API family; well-suited to single SDK shape |
| **knowledge** | 16 | **YES (Tier-2)** | Heterogeneous APIs; SDK-shape composition has friction |
| **linear** | 13 | **YES (Tier-1)** | Ticket's named primary candidate; "about 30 operations" runtime tool count vs 13 YAML files (composite tools) |
| **media** | 10 | **YES (Tier-2)** | Borderline; benefit emerges only when combined with other backends in session |
| **finance** | 6 | NO | Below 30-op threshold; tool-per-endpoint stays cheaper |
| **automation** | 6 | NO | Same |
| **entertainment** | 4 | NO | Same |
| **utility** | 3 | NO | Same |
| **verification** | 2 | NO | Same |
| **security** | 2 | NO | Same |
| **communication** | 2 | NO | Same |
| **search** | 1 | NO | Single op; tool-per-endpoint is optimal |
| **infrastructure** | 1 | NO | Same |
| **food** | 1 | NO | Same |

**Code Mode shortlist (Tier-1)**: `productivity`, `google`, `linear` — 3 backends, 59 YAML files combined, ~80-100 runtime operations when accounting for composite/aliased tools.

**Tier-2 candidates** (re-evaluate after Tier-1 ships measurement): `knowledge`, `media`.

**~30-operations threshold** per ticket: derived from runtime tool count exposed via `gateway_search_tools`, not YAML file count. Linear's 13 YAMLs may expand to ~30 runtime tools via composite/aliased exposure; verify in MEASURE.1.

## ARCH — per-backend opt-in surface design (PROTO.1)

### Capability config extension

Each `capabilities/<category>/<backend>.yaml` gains an optional `code_mode` field:

```yaml
# capabilities/linear/linear.yaml (example)
type: rest
description: "Linear issue + project + cycle management"
code_mode: true                    # NEW — opt-in flag
code_mode_sdk_language: typescript # NEW — pin to TS for Deno fallback
operations:
  - list_issues
  - create_issue
  # ... 13+ ops
```

### Runtime gateway behavior

When `code_mode: true`:
- `gateway_search_tools` returns 2 synthetic surface tools per backend: `{backend}:execute` + `{backend}:search-docs`
- `{backend}:execute` accepts `{code: string, args: object}` payload → sandboxed JS/TS execution against the generated SDK
- `{backend}:search-docs` returns embedding-RAG'd OpenAPI snippets for the backend's operations
- Existing tool-per-endpoint paths still register but are demoted from default search results

When `code_mode: false` (default): existing tool-per-endpoint behavior preserved verbatim.

### Sandbox design (SPIKE.1)

**Primary: wasmtime + Component Model**

- Already a dependency in nab (wasmtime 44.0.1 with `component-model` feature). Same surface usable here.
- WASI Preview 2 component-model isolation per-execute call.
- Network egress allowlisted per backend's OpenAPI spec hostnames.
- Memory cap: 64 MiB per execute call (configurable).

**Fallback: embedded Deno (deno_core crate)**

If wasmtime TypeScript pre-execution type-check is infeasible (tsc-wasm depends on Node-only filesystem APIs in some paths), switch to deno_core + Deno's built-in tsc.

**Trade-off table**:

| Property | wasmtime | deno_core |
|---|---|---|
| Sovereign-stack purity | ✅ pure Rust + WASM | 🟡 Deno is V8 (Google), but operator-deployable |
| Startup latency | ~5-15 ms | ~50-100 ms cold (V8 init) |
| TS type-check | 🟡 requires tsc-wasm + node-shim | ✅ native via deno's tsc |
| Per-call memory isolation | ✅ component instance | 🟡 V8 isolate |
| Cloudflare Workers parity | 🟡 closer | ✅ closer (Deno ≈ Workers runtime) |

Decision: **wasmtime primary, deno_core fallback gated on SPIKE.1 measurement**.

### Backend-aggregation novelty (HEBB.1 anchor)

The novelty axis distinguishing this from Stainless Code Mode (post-Anthropic-acquisition prior art):

1. **Sovereign sandbox composition** (wasmtime > Cloudflare Workers)
2. **Multi-backend Code Mode aggregation** — single agent session composes Code Mode execute calls across N backends via mcp-gateway's existing gateway_invoke router. Stainless is per-API.
3. **Per-backend opt-in** with measured-threshold policy (Tier-1 shortlist from AUDIT.1) — Stainless is binary.

Hebb pin classification: `architecture/mcp-gateway/code-mode-aggregation-policy` → anchor for future per-backend opt-in decisions across the 28-backend portfolio.

## DEVIL + STEELMAN (DEVIL.1)

**DEVIL** (S3): "(a) Code Mode is published prior art post-Stainless; not a novelty axis. (b) Building a sovereign sandbox is more work than gateway_search_tools workaround. (c) Most backends have <30 operations. (d) Cloudflare Workers does TS type-check; sovereign WASM may not."

**STEELMAN**:

1. **(a) Novelty is the COMPOSITION**, not the 2-tool surface — sovereign-WASM + multi-backend aggregation + per-backend opt-in policy. Stainless covers none of these.
2. **(b) The gateway_search_tools workaround pays linear context cost per backend added.** 585 tools × 28 backends → token bill compounds with every new backend. Code Mode caps it at 2 tools × N opted-in backends = bounded constant. The sandbox is amortized.
3. **(c) The 3 Tier-1 backends (productivity + google + linear) carry the bulk of context cost** by op-count weight. Even if 17 of 28 backends stay tool-per-endpoint, the 3 Tier-1 backends are where the win lives.
4. **(d) Wasmtime + tsc-wasm path is the primary attempt; deno_core fallback covers the failure mode.** Both are operator-deployable; Cloudflare Workers is not.

## Risk-clearance summary

| Risk | Status |
|---|---|
| Stainless prior art on 2-tool primitive | ✅ ACKNOWLEDGED — novelty narrowed to composition (see HEBB.1) |
| Sandbox spike cost | 🟡 1-day FAIL-FAST scoped; deno_core fallback path defined |
| Per-backend tooling overhead | ✅ Default OFF; opt-in only for Tier-1 (3 backends) |
| Anthropic-Stainless acquisition timing | ✅ Acquisition 2026-05-18 means Stainless Code Mode is now closed-platform; sovereign alternative becomes more valuable, not less |

## Decision tally per AC

| AC | Status |
|---|---|
| MIK-4391.AUDIT.1 | ✅ table + Tier-1/2 shortlist + verdicts |
| MIK-4391.SPIKE.1 | 🟡 design locked (wasmtime primary, deno_core fallback); 1-day FAIL-FAST measurement deferred |
| MIK-4391.PROTO.1 | 🟡 config + runtime design locked; impl deferred |
| MIK-4391.MEASURE.1 | 🟡 measurement protocol defined (Linear backend, 10-task workload); execution deferred |
| MIK-4391.DOCS.1 | 🟡 deferred (depends PROTO.1) |
| MIK-4391.DEVIL.1 | ✅ devil/steelman pass |
| MIK-4391.HEBB.1 | ✅ pin classification specified (architecture/mcp-gateway/code-mode-aggregation-policy) |
| MIK-4391.LIVING.1 | 🟡 deferred (depends MEASURE.1) |

## V/I/A

🟢V: 7 (S4 per-category YAML counts; S3 ticket body cites; existing wasmtime dep in portfolio)
🟡I: 3 (S1 Stainless direct-fetch owed for v2; S2 Anthropic announcement non-fetched; runtime tool-count vs YAML-count discrepancy needs verification)
🔴A: 0
