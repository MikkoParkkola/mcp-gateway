<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# GH475.RL.10 — why a capability backend's 429 is counted as a healthy call

Status: **revision 2, reviewed — premise falsified, no code change required**. See §6.
Sections 1-5 are retained as the record of a wrong diagnosis, not as a plan.

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

## 6. Revision 2 review: the defect does not exist, and option (c) is withdrawn

Dual review of revision 2 returned SHIP-WITH-FIXES from the Claude Code CLI leg
(the Codex leg produced no verdict row and is recorded `MISSING`, per §PA). Its
first HIGH finding asked a question this design had never asked: does a wrapped
capability 429 actually trip `is_rate_limited`? Checking it falsified the
document.

### 6.1 An error status never reaches the envelope at all

Every capability executor bails on a non-success HTTP status **before** any
`ToolsCallResult` is built:

| executor | site |
|---|---|
| REST (`params.rs`) | `:45` `if !status.is_success() { ... return Err(Error::Protocol(format!("API returned {status}: {error_text}"))) }` |
| JSON-RPC | `src/capability/executor/jsonrpc.rs:199` |
| GraphQL | `src/capability/executor/graphql.rs:255` |
| credentials | `src/capability/executor/credentials.rs:221` |

`build_success_tool_result` (`src/capability/backend.rs:543-553`) serialises the
parsed body only, and it is reached **exclusively on success**. So the premise
in §1 — "a capability backend answering `429` produces `Ok(response)` with
`isError` absent" — is false. It produces `Err`.

### 6.2 The `Err` arm already classifies rate limits

`BudgetOutcome::of` has a second arm this design quoted around
(`invoke.rs:3003-3010`):

```rust
Err(error) => {
    if crate::gateway::recovery::is_rate_limited(&error.to_string()) {
        Self::IgnoredRateLimit
    } else {
        Self::Failure
    }
}
```

`is_rate_limited` (`src/gateway/recovery.rs`) matches `"too many requests"`
case-insensitively **and** `429` as a standalone alphanumeric token. The
executor's message — `API returned 429 Too Many Requests: …` — trips both,
independently. The `Err` propagates unchanged: `call_capability_tool_with_identity(...)?`
at `invoke.rs:2456` is a bare `?` inside `dispatch_to_backend`, and
classification happens on that `Result` at `:1384`.

**A capability backend's 429 is already recorded `IgnoredRateLimit` and already
excluded from the error budget.** `GH475.RL.10` is met in mechanism.

### 6.3 What is actually left

A test, not a fix. The criterion has never been exercised for the capability
kind, and the mechanism it depends on is a string predicate over an error
message — the most fragile way this could be true. RL.10.1 can fail: wrapping
error statuses into `Ok` results, or dropping the status from the message text,
breaks it silently and nothing else would notice.

| AC | case | level | state |
|---|---|---|---|
| RL.10.1 | a capability backend answering HTTP 429 records `IgnoredRateLimit` | unit at the dispatch seam | the criterion's evidence |
| RL.10.2 | the same call increments `mcp_error_budget_suppressed_total` exactly once | unit, mirroring `GH475.OBS.1` | retained |
| RL.10.4 | a capability 4xx that is not a rate limit records `Failure` | unit | retained; passes today via the `else` arm |

RL.10.3 (payload text containing `429` on a success) is retained as a **gate
guard**, relabelled per the review: it records why option (b) was rejected and
can only fail against a future edit, not against this change.

### 6.4 Dispositions

| finding | verified | disposition |
|---|---|---|
| the wrapped 429 may not trip `is_rate_limited` | **confirmed, and larger than reported** — §6.1, §6.2 | the design's premise is false; options (a), (b), (c) all withdrawn |
| Q2's fallback contradicts RL.10.4 | **confirmed** by the document's own text: marking 429 alone leaves other 4xx `Success` | moot — Q2 is withdrawn with the options |
| RL.10.3 passes by construction | confirmed | relabelled as a gate guard, §6.3 |
| write §0's refutation back into the rollup | accepted | `RELEASE-4.0.0-blocking-rollup.md:111` corrected |

### 6.5 Assumption rank (G10), cheapest falsifier first (G11)

| rank | assumption | impact | uncertainty | cheapest falsifier | state |
|---|---|---|---|---|---|
| 1 | an error status reaches `BudgetOutcome::of` as `Ok` | **critical** — the whole design | was low, wrongly | read one executor's non-success branch | **falsified**, §6.1 |
| 2 | the `Err` arm's predicate matches the executor's message | high | was unasked | read `is_rate_limited` against the format string | **confirmed**, §6.2 |

Both checks cost one file read each and neither was run before two revisions
were written. Same G11 failure as `NFR.PERF.4`, found the same way — by a
reviewer asking what the document had assumed rather than what it argued.
