<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# GH475.RL.10 — why a capability backend's 429 is counted as a healthy call

Status: **design, revision 2**, awaiting dual review. Question 1 resolved by
check (see 4.1); question 2 remains open with a stated fallback. No code written.

## 0. The ledger's stated reason is wrong, and the correction changes the fix

`RELEASE-4.0.0-blocking-rollup.md:111` records the criterion as blocked because
"the capability executor classifies rate limits nowhere, so that criterion
presupposes an exclusion that was never built."

The first clause is true about the directory and false about the system.
Classification is not the executor's job and never was: it happens once, at the
shared dispatch seam, for every backend kind.

| step | site |
|---|---|
| every tool call, MCP or capability, dispatches through one function | `src/gateway/meta_mcp/invoke.rs:1343` (`dispatch_to_backend`) |
| its result is classified immediately after | `src/gateway/meta_mcp/invoke.rs:1384`, `BudgetOutcome::of(&dispatch_result)` |
| the predicate is shared with the circuit breaker, deliberately | `src/gateway/meta_mcp/invoke.rs:2993`, `:3005` calling `crate::gateway::recovery::is_rate_limited` |
| capability calls reach that seam | `src/gateway/meta_mcp/invoke.rs:2456`, `call_capability_tool_with_identity(...).await?` inside `dispatch_to_backend` |

So the exclusion mechanism **was** built, it is protocol-agnostic, and a
capability result passes through it on every call. Accepting the ledger's
reason would have produced a second classifier inside
`src/capability/executor/`, duplicating a decision the codebase deliberately
keeps in one place — and it would not have fixed anything, for the reason
below.

## 1. The actual defect

`BudgetOutcome::of` (`invoke.rs:2983-3011`) reads the MCP envelope, because MCP
carries tool-level failure *inside* a successful response:

```rust
if is_error && crate::gateway::recovery::is_rate_limited(&response.to_string()) {
    Self::IgnoredRateLimit
} else {
    Self::Success
}
```

`is_error` gates the text scan, and the comment at `:2990-2992` says why: on a
genuinely successful result the same digits are ordinary payload and must not
exempt anything. That gate is correct.

The capability path never passes it. Across `src/capability/backend.rs` the
only two sites that set `is_error: true` are **schema-validation failures**
(`:432` input-schema violation, `:539` selector-parameter violation). Every
outcome that reaches the HTTP boundary is wrapped by
`build_success_tool_result` (`:545-556`) with `is_error: false`, and the
executor contract states that HTTP error statuses are deliberately
"returned unchanged (never retried)" (`src/capability/executor/mod.rs:94`).

Composing those: a capability backend answering `429 Too Many Requests`
produces `Ok(response)` with `isError` absent, `BudgetOutcome::of` takes the
`else` arm, and the throttled call is recorded as `Success`. It is not
excluded from the error budget, and it does not increment
`mcp_error_budget_suppressed_total`.

The criterion is therefore unmet for exactly one backend kind, and the failure
is silent: the metric that would show it is the metric that is not written.

## 2. Why this is the same shape as the MCP bug already fixed

`GH475.RL.14` (`invoke.rs:4490`) exists because an MCP backend reporting its
429 "the protocol's own way" — `isError: true` plus text — would otherwise be
sampled as healthy. That defect was closed by reading the envelope.

The capability path has the identical defect one layer earlier: it never
*writes* the envelope field the fix reads. Closing it in `BudgetOutcome` again
would mean deleting the `is_error` gate, which reintroduces the payload
false-positive the gate exists to prevent.

## 3. Options

| # | option | verdict |
|---|---|---|
| a | classify rate limits inside `src/capability/executor/` | **rejected** — a second classifier disagreeing with the circuit breaker is the outcome `invoke.rs:2975-2977` was written to prevent |
| b | drop the `is_error` gate in `BudgetOutcome::of` and scan every response body | **rejected** — a tool legitimately returning the text `429` in its payload would exempt itself from the error budget |
| c | set `is_error: true` on a capability result whose HTTP status is an error status | **selected** |

Option (c) puts the fact where the existing, shared classifier already looks,
adds no second opinion about what a 429 is, and leaves the payload
false-positive closed because the gate stays.

Afterwards the finding cannot be restated: there is no capability outcome that
carries an error status and an `is_error: false` envelope.

## 4. Open questions — scheduled, not assumed

| # | question | form | state |
|---|---|---|---|
| 1 | Does any existing consumer depend on a 4xx capability response arriving with `isError: false`? | checkable | **resolved**, see 4.1 |
| 2 | Does the criterion want every error status marked, or only 429? | askable — operator | **open** |

Question 2's fallback: the narrow reading is implemented, since it is a subset
of the wide one and cannot be wrong under it. Owner: the operator. Trigger:
before implementation. Nothing depending on it is written.

### 4.1 Answer to question 1 — resolved by check, not deferred

**No consumer depends on a 4xx capability response arriving with
`isError: false`.** Two sites read the field on the response path, and neither
is harmed by the change:

| site | what it does | effect of setting `is_error: true` on an error status |
|---|---|---|
| `src/gateway/meta_mcp/invoke.rs:308` | reads `isError` into the projection A/B telemetry event, defaulting to `false` when absent | the emitted log becomes **more** accurate; nothing branches on it |
| `src/gateway/meta_mcp/invoke.rs:2145` | refuses a response whose `isError` is present and **not a boolean**, then copies it verbatim into the envelope | `true` is a boolean, so the guard passes and the value is preserved |

The guard at `:2145` rejects malformedness, not truth: it never inspects
whether the flag is set, only whether it is a boolean. Setting it is inside the
contract the transform enforces.

Question 1's fallback — narrowing the marking to 429 alone — is therefore **not
required on this question's account**. Question 2 remains open and its own
fallback stands.


## 5. Test obligations (plan, not tests)

| AC | case | level |
|---|---|---|
| RL.10.1 | a capability backend answering HTTP 429 records `IgnoredRateLimit`, not `Success` | unit at the dispatch seam |
| RL.10.2 | the same call increments `mcp_error_budget_suppressed_total` exactly once | unit, mirroring `GH475.OBS.1`'s three cases |
| RL.10.3 | a capability success whose *payload text* contains `429` still records `Success` | unit — the regression option (b) would have caused |
| RL.10.4 | a capability 4xx that is not a rate limit records `Failure`, not `Success` | unit |

RL.10.1 can fail and does fail today; RL.10.3 is the case that can only fail if
the fix is implemented as a body scan.
