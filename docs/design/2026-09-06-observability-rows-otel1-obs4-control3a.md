# Design — three unowned observability rows (OTEL.1, NFR.OBS.4, CONTROL.3a)

Status: proposed. Author: agent. Reviewers: grok + kimi (dual, §P4).
Rows: `MIK-7272.OTEL.1`, `NFR.OBS.4`, `MIK-7215.CONTROL.3a` — all three
`blocking=yes` for the 4.0.0 release criteria.

## §P0 Scope

FOR: make the three blocking observability rows true at source — trace context
crosses the gateway hop, continuation lifecycle events are counted with a
reason, and the transparency log keeps a correlation key that says where it
came from.

OUT (findings here get disposed per §P0, never silently fixed):
- `CONTROL.3b`, `CONTROL.4`, `CONTROL.5` — separate rows, separate owners.
- Wiring `ContinuationLedger::evict_expired` into a sweep task. See Q-2.
- Any change to the transparency log's on-disk format beyond adding fields.
- Any change to `TraceContext` parsing/validation (`trace.rs:33-74`).
- Backend-side consumption of `_meta` (we control the send, not the receive).
- Retro-fitting counters onto paths other than continuation mint/redeem/
  expiry/rejection.
- Fixing the stale line citations in the status ledger (reported, not fixed —
  see Findings).

## Measured constraints (all V, file:line at HEAD of `fix/mrtr2-continuation-handle`)

Trace substrate:
- `src/gateway/trace.rs:32-37` — `tokio::task_local!` holding `TRACE_ID: String`.
- `trace.rs:48` `generate()` mints `"gw-<uuid4>"`; `:56` `current() -> Option<String>`;
  `:64` `with_trace_id(id, fut)` scopes it.
- `invoke.rs:767-775` — `invoke_tool` mints a gateway id and wraps the ENTIRE
  `invoke_tool_traced` body in `with_trace_id`. Verified: the provider hop at
  `provider/mcp_provider.rs:83-88` executes inside that scope.
- `src/protocol/trace.rs:23,33,64,76,81` — `TraceContext` carries
  `traceparent`/`trace_id`/`tracestate`/`baggage`; `from_meta` at `:33`,
  `to_meta` at `:76`.
- `to_meta()` has ZERO production callers. Its only callers are its own unit
  tests (`trace.rs:111,:124`) and `tests/mik_7272_exploit_acs.rs:81`.
- `from_meta`'s sole production caller is `invoke.rs:1847`.

Outbound request construction:
- `provider/mcp_provider.rs:83-86` builds `{"name": tool, "arguments": args}` and
  `:88` sends `tools/call`. This is the ONLY place the outbound params are
  assembled. The status row's citation (`invoke.rs:2019`) is stale.
- `:70-81` is a fail-closed identity-propagation refusal (MIK-6741 IDP.2) —
  the new code must not be able to bypass it.

Transparency log:
- `invoke.rs:1846-1849` — the correlation key is the `_meta` OTel trace id,
  else the session id, else a hardcoded placeholder literal; `:1851` calls
  `log_invocation`.
- `security/transparency_log.rs:222-224` `log_invocation(session_id: &str, ...)`,
  `:240` writes the field `"session_id"`, `:578-599` `show_session_entries`
  filters on it. There is no trace-id or key-source field in that file.

Continuation:
- `protocol/continuation.rs:161` `Payload::mint`, `:202` `redeemable_by`,
  `:240/:276` `ContinuationError::Expired`, `:408` keyring `mint`, `:509`
  `Expired` returned, `:619` `evict_expired`.
- `evict_expired` has ZERO production callers (`rg src/` returns only its own
  definition and the doc line at `:592`).
- Gateway call sites: mint `invoke.rs:397`; rejection `:468`; redeem
  `:529-615` (not-redeemable warn at `:570`, `NotAuthentic` at `:562/:591/:606`);
  mint refusal warn at `:1571`.

Counting substrate:
- `telemetry_metrics` (the `metrics` crate) is an UNCONDITIONAL dependency
  (`Cargo.toml:166`), not behind the `metrics` feature.
- Existing counters use a `reason`/`kind` label: `invoke.rs:1902`
  `mcp_error_budget_suppressed_total` with `"reason" => "rate_limited"`;
  `:1183/:1236` `mcp_cache_hits_total` with `"kind"`.
- `crate::metrics::install()` + `crate::metrics::render()` give a testable
  Prometheus text surface; the pattern is already used at `invoke.rs:4628-4654`.
- Structured-log target `mcp_gateway::observed` exists (`protocol/meta.rs:529`,
  `protocol/era.rs:196..349`, `gateway/server/mod.rs:3447`) with a test capture
  subscriber filtering it (`gateway/server/mod.rs:3353,:3371`).

## R1 — OTEL.1: propagate `traceparent`/`tracestate`/`baggage` across the hop

Requirement (`RELEASE-4.0.0-requirements.md:245`): the three fields MUST be
propagated through `_meta` across the gateway hop.

Today the inbound context is parsed once at `invoke.rs:1847` for the
transparency-log key and then dropped. Nothing writes `_meta` outbound;
`to_meta()` is dead in production. The row is correct that OTEL.1 is UNWIRED,
and wrong about where the outbound request is built.

Chosen: a SECOND task-local beside `TRACE_ID` holding the inbound
`TraceContext`, set in the same `with_trace_id` scope at `invoke.rs:767-775`
(parse `_meta` once, there, instead of at `:1847`); read at
`provider/mcp_provider.rs:83-86`, which merges `to_meta()` into a
params-level `_meta` key on the `tools/call` object.

Why params-level and not inside `arguments`: `_meta` is a protocol field of the
request, not a tool argument. Writing it into `arguments` would hand the
backend tool a parameter its schema does not declare, and a strict backend
would reject the call.

Options rejected:
- Thread `TraceContext` through the provider trait signature. Rejected: changes
  a public trait implemented by several providers, forces every implementation
  to care about tracing, and blows past the row's blast radius for no gain over
  a task-local that is already the established mechanism in this file.
- Inject at the invoke layer (`dispatch_to_backend`, `invoke.rs:2419`).
  Rejected: `dispatch_to_backend` does not build the `tools/call` params; the
  provider does. Injecting upstream means mutating `args`, which is the
  `arguments` object — the wrong place, per above.
- Re-mint a trace context when the caller supplies none. Rejected: explicitly
  refused by `protocol/trace.rs:11-13` ("Propagated, never re-minted") — a
  gateway that started a fresh trace makes its own hop the root and hides the
  caller. No inbound context means no `_meta` written.

Absent-signal risk: `to_meta()`'s existing unit tests prove the function
serialises, not that anything receives it. The test for this row MUST capture
the outbound `tools/call` params at a fake backend. A green `to_meta` unit test
is not evidence for OTEL.1.

## R2 — NFR.OBS.4: count continuation mint, redeem, expiry and rejection, with reason

Requirement (`:293`). The status row says no counters exist; that is confirmed
at source for these four paths.

"Counted" is read as a real counter, not a log line. Justification: OBS.1-3 say
*record* and are served by the `mcp_gateway::observed` target; OBS.4 says
*counted*, `telemetry_metrics` is an unconditional dependency, and this repo
already ships counters with a `reason` label (`invoke.rs:1902`) that tests
assert against through `metrics::render()`. Reading "counted" as a log line
would make the verb difference meaningless.

Chosen: one counter, four outcomes, reason as a label —
`mcp_continuation_events_total{event, reason}` where `event` ∈
{mint, redeem, expiry, rejection} and `reason` names the discriminating cause
(mint: ok / refused-caller / budget-exhausted; redeem: ok / not-redeemable /
not-authentic / expired; rejection: the existing rejection cause). Emitted at
`invoke.rs:397, :468, :529-615, :1571`. A `tracing::info!` on
`mcp_gateway::observed` accompanies each, for the operator who reads logs
rather than scrapes — the counter is the thing the requirement asks for.

Options rejected:
- Four separate counters. Rejected: a per-event metric name makes
  "count me every continuation outcome" a four-query dashboard, and the label
  set is identical.
- Count inside `protocol/continuation.rs` rather than at the gateway sites.
  Rejected: the protocol module is used by tests and by the keyring directly;
  counting there would double-count and would bind a protocol type to a
  metrics backend.
- Log-only on `mcp_gateway::observed`. Rejected: see the verb argument above.

Absent-signal risk: the test MUST assert PER REASON. A single "some
continuation metric was emitted" assertion stays green with three of the four
emit sites deleted, and that is exactly the mutation probe this change will be
held to.

## R3 — CONTROL.3a: retain a correlation key across session removal

Requirement (`:204`). Today the key degrades to a hardcoded placeholder when
neither an OTel trace id nor a session id is present (`invoke.rs:1849`), and
nothing downstream can tell a client-supplied key from a gateway one.

Chosen: (a) last-resort fallback becomes the gateway-minted trace id, already
in scope as `trace_id` at `invoke.rs:767` and already returned to the client at
`:1869` via `augment_with_trace`, so the key an operator sees in the log is one
the client also holds; (b) `log_invocation` gains a `key_source` argument
({otel, session, gateway}) written as its own field at
`transparency_log.rs:240`.

Why (b) is not gold-plating: without it the row can be satisfied by any
non-empty string, and an operator cannot tell whether cross-hop correlation is
actually possible or only gateway-internal. "A key is present" and "the key
correlates" are different claims and the requirement means the second.

Options rejected:
- Swap the placeholder for the gateway id and stop there. Rejected: a
  better-mannered placeholder; see above.
- Rename the `session_id` field to `correlation_key`. Rejected: `:578-599`
  `show_session_entries` filters on that field name and the log is append-only
  on disk — a rename breaks every historical entry's readability for no gain
  that `key_source` does not already deliver.
- Store the whole `TraceContext`. Rejected: out of scope, and the transparency
  log is not a trace store.

`log_invocation` is a public symbol; `impact` runs before the edit (see Q-3).

## Open questions — each scheduled, none assumed (§P1)

Format: `question — check run / asked of — what came back — what it changed`.

RESOLVED:

- Q-A: does "counted" mean a metrics counter or a `mcp_gateway::observed`
  record? — `rg 'counter!' src/` plus `rg -l counter tests/` plus
  `rg telemetry_metrics Cargo.toml` — real counters exist on ten-plus paths,
  tests assert them via `metrics::render()`, and the dependency is
  unconditional — R2 counts with `telemetry_metrics`, not with a log line
  alone. Had this come back empty, R2 would have been log-only.
- Q-B: does the provider hop execute inside the `with_trace_id` scope? —
  `sed -n '760,775p' src/gateway/meta_mcp/invoke.rs` — `invoke_tool` wraps the
  whole of `invoke_tool_traced` in `with_trace_id`, and the provider call is
  reached from inside it — R1 uses a task-local and does NOT change the
  provider trait signature. Had it been outside, R1 would have had to thread
  the context through the trait, a much larger change.
- Q-C: where is the outbound `tools/call` actually built? —
  `rg -n 'tools/call' src/provider/` — `mcp_provider.rs:83-88`, not
  `invoke.rs:2019` as the status row claims — R1 injects at the provider, and
  the stale citation is reported as a finding.
- Q-D: is `to_meta()` wired anywhere in production? — `rg -n 'to_meta' src/
  tests/` — three callers, all tests — confirmed the row's UNWIRED verdict and
  set the absent-signal rule for R1's test.

OPERATOR QUESTIONS (asked of team-lead; blocking the parts they name):

- Q-1 (blocks R3's acceptance, not its shape): does swapping the placeholder
  for the gateway-minted trace id plus a `key_source` field satisfy "retain a
  correlation key across the removal of sessions", or does the row need
  `CONTROL.5`'s shipping ruling first? Recommendation: it satisfies it — the
  gateway id is minted per call, survives session removal by construction, and
  reaches the client. Fallback if the answer is no: R3 becomes design-only and
  the row stays PARTIAL with a recorded reason.
- Q-2 (blocks the "expiry" quarter of R2): `evict_expired` has no production
  caller, so an expiry is only ever DETECTED lazily at redeem. A continuation
  that expires and is never retried is counted never. Does OBS.4 mean
  counted-at-detection (what is achievable without wiring a sweep), or does it
  require the sweep? Recommendation: counted-at-detection, with the sweep gap
  recorded as residual risk on the row — wiring a sweep is a behaviour change
  well outside three observability rows. Fallback if the answer is "requires
  the sweep": R2 splits, the sweep gets its own scope statement and its own
  review, and OBS.4 does not close in this change.

DEFERRED: none. Nothing below implementation depends on an open item other
than Q-1 and Q-2, and the work they gate does not start until they are
answered.

- Q-3 (procedural, not deferred): `impact` on `log_invocation` and on
  `McpProvider::call_tool` runs BEFORE the first edit, per CLAUDE.md. A
  HIGH/CRITICAL result is reported to the team lead before proceeding.

## Findings against the status ledger (reported, out of scope to fix here)

- `CONTROL.3a`/`3b` (`RELEASE-4.0.0-criteria-status.md:174`) cite
  `invoke.rs:1339-1345`; the live site is `invoke.rs:1846-1849`.
- `OTEL.1` (`:232`) cites `invoke.rs:2019` for the outbound path; the outbound
  `tools/call` is built at `provider/mcp_provider.rs:83-86`.
- Both are the failure mode the team lead named: a status row is not evidence
  about source. Disposal: recorded as observations for the row owner; not
  filed, not fixed in this change.

## Order of work

CONTROL.3a → NFR.OBS.4 → OTEL.1. Each lands as its own commit with its own
tests, so an interrupted run leaves a coherent partial delivery rather than
three half-wired rows.

## Explicitly NOT in this document

No code. Test cases live in the test plan (§P2), one row per requirement
clause, written after this design is reviewed.
