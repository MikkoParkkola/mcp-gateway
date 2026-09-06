# OTEL.1 / NFR.OBS.4 / CONTROL.3a — one source correction, not a fourth design

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

FOR: recording one fact about source that all three of those designs assume and
none of them states — the read side of `_meta` on the meta-MCP route.

OUT: re-deciding anything in the table above; the counter schema; the carrier;
the TTL; the reclaimer's owner; any code.

## The correction — the inbound `_meta` a client sends is never the one that is read

Four measured facts, at HEAD of `fix/mrtr2-continuation-handle`:

1. `extract_tools_call_params` (`src/gateway/router/helpers.rs:185-195`) returns
   `params.name` and `params.arguments` and nothing else. Protocol-level
   `params._meta` — the carrier cluster-b §3.3 decides on — is discarded at both
   callers: `src/gateway/router/handlers.rs:976` (HTTP) and
   `src/gateway/server/mod.rs:1827` (stdio).
2. `TraceContext::from_meta` has exactly one production caller,
   `src/gateway/meta_mcp/invoke.rs:1845-1847`, and it reads
   `args.get("_meta")` — a field of `gateway_invoke`'s **argument object**, one
   level below the protocol carrier. No meta-tool input schema declares `_meta`
   (`src/gateway/meta_mcp_tool_defs.rs`), and nothing anywhere copies
   `params._meta` into `arguments`.
3. Consequently CONTROL.3a's first rung is unreachable today for a
   spec-conformant client: `otel_trace_id` at `invoke.rs:1846` is always `None`,
   and the transparency log always falls to the minted id or the session id.
   `src/gateway/meta_mcp/trace_correlation_tests.rs:104-130` passes because its
   fixture puts `_meta` inside the argument object — the shape the code reads,
   not the shape a client sends. That is a fixture staging its own condition
   (§P2 `test-plan-honesty`), and it is why the gap survived a green suite.
4. The seam for the fix already exists and is used for exactly this shape:
   `RetryFields::from_params(params.as_ref())` (`handlers.rs:990`) reads
   params-level siblings and carries them to the invoke funnel on the caller
   context. A trace read belongs beside it, not inside `arguments`.

Second-transport consequence, and it has a precedent in this repo: the stdio
path builds no such context — `retry: &crate::protocol::mrtr::NO_RETRY`
(`src/gateway/server/mod.rs:1862`), with an ignored watcher test at `:3601`
recording that gap. A params-level read wired only at `handlers.rs:990` closes
OTEL.1 and CONTROL.3a on one transport of two. CONTROL.3a's own design already
refused that shape once, for the reaper: "in both serve modes".

Where this belongs: as a measured constraint in cluster-b §2, not here. An
implementer reading cluster-b alone still walks into `args["_meta"]` and gets
nothing. Filed as a post-review source correction against a reviewed document,
flagged to the team lead — see the companion commit.

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

## Findings against the status ledger (observations, per §P0 — not filed)

- `CONTROL.3a`/`3b` (`docs/requirements/RELEASE-4.0.0-criteria-status.md:174`)
  cite `invoke.rs:1339-1345`; the live site is `invoke.rs:1845-1852`.
- `OTEL.1` (`:232`) cites `invoke.rs:2019` for the outbound path; outbound
  params are built at `invoke.rs:2547-2552`, which is also where cluster-b
  §3.4a's sibling-of-`inject_cache_key` write lands.
- Disposal: recorded as observations for the row owner. Not filed — §P0's
  filing test (a HUMAN must decide something) does not hold, and filing is the
  most expensive disposal.

## Next

Test plan (§P2), one row per criterion clause, against the three designs above
plus this correction. No code before that plan is reviewed.
