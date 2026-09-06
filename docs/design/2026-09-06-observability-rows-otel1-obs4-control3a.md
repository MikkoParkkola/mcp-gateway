# OTEL.1 / CONTROL.3a — one source correction, not a fourth design

Status: proposed. Author: agent. Reviewers: grok + kimi (dual, §P4).
Supersedes this file's own round-1 content, which restated three decisions that
were already made elsewhere. Round 1 (grok, G4) called that duplication and it
was eliminated rather than repaired: a design that repeats a reviewed design is
a second copy that drifts (H3), and the copy is what an implementer reads.

## What decides each row — this document decides none of them

| row | decided by | what it decides |
|---|---|---|
| `MIK-7272.OTEL.1` | `docs/design/2026-08-31-cluster-b-capability-and-trace-metadata.md` §3.3, §3.4, §3.4a, §3.4b | `_meta` is the carrier; per-field rules; never minted; unconditional write at `dispatch_to_backend` as a sibling of `inject_cache_key`; W3C-grammar predicate; numeric bounds deferred §4.2 |
| `NFR.OBS.4` | `docs/design/2026-09-01-continuation-telemetry.md` | four counters; `phase` separates forgery from refusal; the `reason` set IS the refusal set; `expired` is not a `reason`; payload never a label; the reclaimer belongs to `2026-09-01-nfr-perf3-reclamation.md` |
| `MIK-7215.CONTROL.3a` | `docs/design/2026-09-03-post-session-caller-identity.md` | the correlation key is per-invocation and the lifecycle key per-principal; the rung that fired is recorded; TTL answered by the operator (300s, shared with `PER_USER_IDLE_TTL`) |

## §P0 Scope

FOR: recording one fact about source that the OTEL.1 and CONTROL.3a designs
assume and neither states — the read side of `_meta` on the meta-MCP route.
NFR.OBS.4 does not depend on it: `2026-09-01-continuation-telemetry.md` never
mentions `_meta`. Its row stays in the table above as a pointer, nothing more.

OUT: re-deciding anything in the table above; the counter schema; the carrier;
the TTL; the reclaimer's owner; any code.

## The correction — pointer only

The measured correction lives in
`docs/design/2026-08-31-cluster-b-capability-and-trace-metadata.md` §2.7, which
owns it. It is deliberately not restated here: a second copy drifts, and the two
copies had already begun to disagree on how strong the claim is. Round 1
eliminated exactly this defect one scale larger. Read §2.7 for the facts, their
citations and the consequences.

## Open — one question, and it is not new

`POST /mcp/{name}` (`src/gateway/router/backend_handlers.rs:432`): does OTEL.1
close on the meta-MCP route alone, or must the direct route carry trace `_meta`
too? This is **cluster-b §4.4.3**, inherited from SUB.4 and already collected as
operator-only. Cluster-b §7 says it is the only thing that moves the estimate.
It is not re-asked here; a second copy of an open question is the same defect
one scale smaller.

WITHDRAWN, each answered at source rather than by the operator:
- *Does the minted trace id plus a rung marker satisfy CONTROL.3a?* Decided in
  `2026-09-03-post-session-caller-identity.md` §"The decision" — the chain, the
  rungs and the recorded marker are settled there. Naming the field is
  implementation.
- *Does OBS.4 require a sweep, or counting at detection?*
  `2026-09-01-continuation-telemetry.md` answers both: `detected` distinguishes
  the populations, and the reclaimer is owned by
  `2026-09-01-nfr-perf3-reclamation.md`.

## Findings against the status ledger — withdrawn, both died at source

Round 2 re-checked the two citations this file had called stale. Both are current:
`RELEASE-4.0.0-criteria-status.md:174` cites `invoke.rs:1845-1849`, and `:232` cites
`invoke.rs:2548` together with `src/provider/mcp_provider.rs:83-86` for the outbound
gap. The observations are withdrawn. A finding that dies at source closes without a
repair and without a disposal (§P4) — the ledger has no drift for a row owner to fix.

## Next

Test plan (§P2), one row per criterion clause, against the three designs above
plus this correction. No code before that plan is reviewed.
