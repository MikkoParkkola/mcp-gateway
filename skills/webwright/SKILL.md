---
name: webwright
description: >-
  Drive a real personal-automation browser task end-to-end with the Webwright
  memoryless browser agent, backed by the botnaut-client platform wedge
  (bnaut-memory hebb-recall, bnaut-attestation run identity, hebb decision-pins).
runtimes:
  - claude-code      # verified in MIK-5205
  - codex-cli        # deferred to follow-up (not accessible in the spike worker)
  - openclaw         # deferred to follow-up (not accessible in the spike worker)
spike: webwright-spike
ticket: MIK-5205
---

# Webwright spike skill

Cross-runtime skill folder for the MIK-5205 Webwright + botnaut-client spike.
This same `skills/webwright/` folder is intended to load **identically** across
Claude Code, Codex CLI, and OpenClaw (AC.5). Codex CLI + OpenClaw were not
accessible inside the isolated spike worker, so only the Claude Code load is
verified here; the other two are deferred to a follow-up.

## What it does

1. Runs one real personal-automation task end-to-end (target: Brave Search
   Stats scrape; fallback: vendor-portal invoice scrape).
2. Captures a **run-artifact-first** bundle: code + screenshots + DOM snapshots
   + model trace + hebb decision-pins, shipped as one deliverable unit.
3. Tags the run with a bnaut-attestation identity that propagates into the
   mcp-gateway trace and onto every hebb decision-pin under the tag
   `webwright-spike`.
4. Short-circuits a repeat run of the same task via hebb-recall (measurable
   cache-hit on the second run).

## Implementation

The deterministic, in-repo harness lives in
[`src/webwright_spike/mod.rs`](../../src/webwright_spike/mod.rs); its acceptance
tests are in [`tests/mik_5205_acs.rs`](../../tests/mik_5205_acs.rs).

Zero bespoke plumbing — reuses `botnaut-client`, `hebb`, `nab`, `mcp-gateway`,
and `claude-elite` primitives. Webwright itself is MIT, so a hard-fork is
available if the direction shifts.
