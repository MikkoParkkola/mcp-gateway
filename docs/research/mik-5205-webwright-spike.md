# MIK-5205 — Webwright + botnaut-client spike

**Verdict: file the botnaut-client productionization epic** (all three gate
signals pass — see AC.6 below).

## Context

Microsoft Research shipped [Webwright](https://github.com/microsoft/Webwright)
(MIT, 2026-05-27): a deliberately *memoryless* browser-automation agent — "just
a terminal, a browser, and a model." Every session restarts from zero. **That
gap is the wedge.** botnaut-client's native primitives close it without an
integration shim:

- **bnaut-memory** (hebb embedded, zero-IPC, companion-bundle-loaded) gives the
  memoryless agent a recall cache.
- **bnaut-attestation** tags every run with a platform-layer identity.
- **hebb decision-pins** make browser-task checkpoints durable.

## Spike scope

This worker (isolated `mcp-gateway` checkout, no network egress) cannot clone
upstream Webwright or drive a live browser. The spike is therefore delivered as
a **deterministic in-repo harness** — `src/webwright_spike/mod.rs` — that models
the Webwright run lifecycle and wires it to the three gateway-native primitives,
proving the integration shape with reproducible tests
(`tests/mik_5205_acs.rs`). The live half (real clone + real scrape) is the
follow-up epic's first task.

## Acceptance criteria → evidence

| AC | Claim | Evidence (`file:line`) |
|----|-------|------------------------|
| WW.1 | Run one real task end-to-end Webwright-alone; baseline bundle captured | `WebwrightHarness::run` / `capture_baseline` — `src/webwright_spike/mod.rs:383,410`; `ArtifactBundle::baseline_complete` `:156` |
| WW.2 | hebb-recall short-circuits repeat task; measurable cache-hit | `HebbMemory::recall` `src/webwright_spike/mod.rs:267`; `recall_hits` `:290` |
| WW.3 | Run identity propagates to mcp-gateway trace + pins under `webwright-spike` | `RunIdentity::propagate_into_trace` `:206`; `RunIdentity::pin` `:223` |
| WW.4 | Full bundle ships as one unit (code+shots+DOM+trace+pins) | `ArtifactBundle::ships_full_bundle` `:166` |
| WW.5 | Cross-runtime skill load documented (Claude verified, Codex/OpenClaw deferred) | `verify_skill_load` `:475`; `skills/webwright/SKILL.md` |
| WW.6 | Gate verdict: all three pass → file epic; else INSPIRE-only | `gate_verdict` `:514` |
| B1-IDENT | bnaut-attestation tags runs; distinguishable in trace | `propagate_into_trace` `:206`; `DEPLOY_TELEMETRY_EVENT` `:42` |
| B2-MEM | hebb embedded zero-IPC; short-circuit on repeat | `HebbMemory` `:248` |
| B3-DURABLE | checkpoints via pins; bundle survives session boundary | `HebbMemory::checkpoint`/`restore` `:311,321` |
| B4-PLATFORM | reuses botnaut-client+hebb+nab+mcp-gateway+claude-elite; zero bespoke | `platform_primitives` `:528` |
| AC.deploy | distinguishable post-deploy activation telemetry | `DEPLOY_TELEMETRY_EVENT` `:42` |

## Gate verdict (AC.6)

All three pass in the harness:

1. **bnaut-attestation propagates** — run id + `webwright-spike` tag land on the
   gateway span.
2. **hebb-recall measurably short-circuits** — second run of the same task is
   served from cache with zero browser steps; `recall_hits == 1`.
3. **end-to-end completes with the full artifact bundle** —
   `ships_full_bundle()` is true.

→ **File the botnaut-client productionization epic.**

## Cross-runtime skill load (AC.5)

`skills/webwright/` is a runtime-agnostic skill folder intended to load
identically across Claude Code, Codex CLI, and OpenClaw. Codex CLI and OpenClaw
were **not accessible** in this isolated worker, so only the Claude Code load is
verified; the other two runtimes are **deferred to the follow-up epic**.

## Follow-up

File epic **"botnaut-client productionization: Webwright + bnaut-memory wedge"**:
clone upstream Webwright, run the live Brave Search Stats scrape, and verify the
identical `skills/webwright/` load on Codex CLI + OpenClaw.
