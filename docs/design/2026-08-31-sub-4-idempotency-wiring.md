# MIK-7272.SUB.4 — idempotency protection for reissued side-effecting calls

Status: proposed. No code written. Awaiting dual-vendor review.

## Scope

FOR: deciding how a side-effecting call, reissued after a broken stream with a new request
id, becomes protected — which is what MIK-7272.SUB.4 requires.

OUT:
- the tasks extension (MIK-7272.TASK.1, ABSENT). It is the criterion's other branch and a far
  larger surface; this design neither builds it nor depends on it.
- idempotency key *derivation*. `derive_key` and `RetryFields` exist, are tested
  (`tests/mik_7216_mrtr_10_acs.rs`, `src/idempotency.rs` unit tests), and are not in question.
- MIK-7212.MRTR.10a (`inputResponses`/`requestState` inside the key), a separate ABSENT
  criterion about what goes *into* a key this design only decides to *use*.

## Problem

The idempotency machinery is complete and unreachable.

- `MetaMcp::idempotency_cache` is initialised to `None` (`src/gateway/meta_mcp/mod.rs:393`).
- Its only populator, `MetaMcp::enable_idempotency` (`src/gateway/meta_mcp/mod.rs:580`), is
  marked `#[allow(dead_code)]` and has zero callers: `rg --hidden --no-ignore
  'enable_idempotency' .` returns one hit, its own definition.
- `IdempotencyCache::new` is constructed only in `tests/mik_7216_mrtr_10_acs.rs` and in
  `src/idempotency.rs`'s own doc-example and unit tests. Never in production code.
- No configuration key gates it: `rg -n 'idempotency' src/config/mod.rs` returns nothing.

So the enforcement site `if let (Some(idem_cache), Some(key)) = (&self.idempotency_cache,
&idem_key)` (`src/gateway/meta_mcp/invoke.rs:792`) takes the `None` branch in every build that
has ever shipped. `resolve_idempotency_key` runs, derives a key, and nothing consumes it.

The `#[allow(dead_code)]` attribute is why this survived the `-D warnings` clippy gate: it
silences the exact warning that would have reported the unused setter.

A second, independent gap compounds it. `POST /mcp/{name}` — the direct backend route,
`src/gateway/router/backend_handlers.rs:338-353,816-827` — bypasses `invoke_tool_traced` by
design (ADR-008 rung 2, per its own comment at `backend_handlers.rs:724`). That route
deliberately re-enforces OAuth isolation and tool policy locally, but never calls
`resolve_idempotency_key`, whose sole call site is `meta_mcp/invoke.rs:782`. Even with the
cache enabled, that ingress stays unprotected.

## Constraints, measured

- The response cache is NOT optional (`meta_mcp/mod.rs:391`, a plain field). Whatever is
  decided here must not let idempotency's lifecycle diverge from it in a way that serves a
  non-final result as final — MIK-7212.MRTR.10b currently rests on `ResponseCache::set`
  (`src/cache.rs:153`) alone, precisely because the `mark_completed` guard is inert.
- `enable_idempotency` spawns a background cleanup task. Enabling it unconditionally starts
  that task in every process constructing a `MetaMcp`, including short-lived stdio invocations.
- Two HTTP ingresses exist and ADR-008 chose the asymmetry deliberately. Changing it is an ADR
  amendment, not an edit.

## Options

**A. Config-gated, default off.** Add an `[idempotency]` section; call `enable_idempotency`
from server startup when enabled. Smallest change. Rejected as the whole answer: a criterion
saying a reissued call MUST be protected is not satisfied by protection that is off by
default. It leaves SUB.4 MET only for operators who opt in — today's state with extra steps.

**B. On by default, config to disable.** Same wiring, inverted default. Satisfies the criterion
for the meta route. Cost: a cleanup task in every process, and a behaviour change for
deployments where a reissue currently re-executes. That change is the point of the criterion,
but it is a change and belongs in the release notes.

**C. B, plus covering the direct backend path.** Closes both ingresses. Requires revisiting
ADR-008 rung 2, whose stated rationale for the bypass is not about idempotency; the
OAuth-isolation precedent at `backend_handlers.rs:724` shows the established pattern is to
re-enforce a guard locally on that route rather than remove the bypass.

Recommendation: **C**, landed as B first so the two halves are separately reviewable and
separately revertible. B alone leaves a documented hole a client can reach.

## Unknowns — each scheduled, none assumed

| unknown | how it is settled | state |
|---|---|---|
| Is on-by-default acceptable, given it changes reissue behaviour for existing deployments? | ASK the operator. Only they can weigh a silent behaviour change against an unmet criterion. | OPEN — blocks the choice between A and B |
| Does ADR-008 rung 2's rationale forbid idempotency on the direct route, or is it silent on it? | CHECK: read the ADR end to end. The in-code comment cites isolation, not idempotency. | OPEN — blocks C |
| What TTL and cleanup interval? | CHECK: read what `IdempotencyCache` and the response cache already use; match unless there is a reason not to. | OPEN — not blocking; a default can follow the response cache |
| Does enabling this change MIK-7212.MRTR.10b's status? | CHECK: re-run its tests with the cache enabled. Its second guard goes from inert to live, which can only tighten it. | OPEN — not blocking |

Nothing here is deferred. No code is written until the first two are answered.

## Test plan — one row per acceptance criterion, before any code

| criterion | case | level | can it fail? |
|---|---|---|---|
| SUB.4, meta route | POST `tools/call` twice with the same idempotency key and a new request id; the second is served from the cache and the backend is invoked once | integration, HTTP | yes — with the cache `None` the backend is invoked twice, which is today's behaviour, so the test is red before the fix |
| SUB.4, direct route | the same reissue through `POST /mcp/{name}` | integration, HTTP | yes — currently unprotected under both halves of the criterion's "or" |
| no regression | a call carrying no idempotency key still executes every time | integration | yes — a too-eager key would dedupe unrelated calls |

The assertion is the backend-invocation count, not the response body: two identical responses
are also what executing twice produces.
