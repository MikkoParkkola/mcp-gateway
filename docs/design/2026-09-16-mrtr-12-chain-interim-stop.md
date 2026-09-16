<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# MRTR.12: stopping a `gateway_execute` chain at an interim round

## The defect

`execute_chain` (`src/gateway/meta_mcp/search.rs:505-555`) treats every `Ok`
as a completed step:

```rust
Ok(result) => results.push(json!({"step": idx, "tool": tool_ref, "result": result})),
```

A tool that comes back asking a question — `resultType: "input_required"` —
returns `Ok`, because a question is a successful result and not an error. Only
`Err` stops a chain. So the chain records the question as a completed step and
runs step `idx + 1`.

The worst case is a step held at the destructive-operation confirmation gate.
That step does not perform its action, and its successors execute as if it had.
Nothing in the response tells the caller which of the two happened.

This is not fixed by MRTR.11a. That row changes how a round is *presented*; it
does not change whether the loop continues.

## What the fix must do

1. Stop the chain at the first step whose result validates as an interim round.
2. Surface that round at the top level of the chain response, so the caller can
   answer it.
3. Let the caller answer and resume — running the steps that have not run, and
   **not** re-running the steps that have.

Point 3 is the whole difficulty. Re-running is not a conservative fallback: a
chain stops precisely when a step needs a human decision, and the steps before
it are exactly the ones most likely to have had effects.

## Design

### Reuse the sealed continuation envelope

`src/protocol/continuation.rs` already provides everything a resume needs, and
it is already the mechanism a single-tool interim round uses:

| Existing field | What it gives the chain |
|---|---|
| `principal_fingerprint` | only the caller who started the chain may resume it |
| `original_request_digest` | the resume must present the same chain, or it fails |
| `jti` + `ConsumedLedger` | single-use: a resume token cannot be replayed |
| `expires_at` | a stalled chain does not stay resumable forever |
| `backend_request_state` | the asking backend's own opaque state, verbatim |
| `hold_key` → `InFlight` | which exchange is open, carried not looked up |
| `purpose` | domain separation; a confirmation grant cannot resume a chain |

The chain adds **one** field to `Payload` and **one** variant to
`ContinuationPurpose`:

```rust
pub enum ContinuationPurpose {
    BackendInput,
    DestructiveConfirm,
    ChainResume,          // new
}

pub struct Payload {
    // …
    /// Index of the chain step that asked. Steps `0..next_step` have run.
    /// Absent on every envelope that is not a `ChainResume`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_step: Option<usize>,
}
```

`next_step` is sealed, like everything else in the payload. A caller cannot
move it, so a caller cannot make the gateway skip a step that never ran.

### What a resume may skip, and why that is safe

A resume skips steps `0..next_step` and runs `next_step..n`.

That is safe on three bindings, all of which already exist:

- `original_request_digest` covers **the whole `chain` array**, so a resume
  presenting a different chain — reordered, shortened, a substituted tool —
  does not redeem. Skipping is only ever relative to the chain that produced
  the token.
- `principal_fingerprint` binds the resume to the caller who ran those steps.
- `jti` is consumed on redemption, so a resume runs `next_step..n` once.

What the design deliberately does **not** do: it does not store the results of
steps `0..next_step` server-side. They are returned to the caller in the
stopping response (below), so nothing needs holding and the envelope does not
grow with the size of a tool's output.

### The stopping response

The chain stops and returns, at the top level of the tool result:

```json
{
  "steps": 2,
  "results": [ {"step": 0, …}, {"step": 1, …} ],
  "resultType": "input_required",
  "inputRequests": [ … ],
  "requestState": "<sealed continuation token>",
  "pendingStep": 2,
  "pendingTool": "server:tool_name"
}
```

`results` carries the steps that genuinely ran. `pendingStep` names the step
that asked — without it a caller reading `steps: 2` cannot tell whether step 2
failed, was skipped, or is waiting. The resumed call returns the same shape for
`next_step..n`; a caller that wants the whole chain concatenates the two. No
server-side result storage, no stitching in the gateway.

### Validation before promotion (the MRTR.11b rule, applied here)

A step's result becomes an interim round only if `InputRequired::from_result`
(`src/protocol/mrtr.rs:225`) accepts it. A backend that merely writes
`resultType: "input_required"` into its output does **not** get to stop a
chain or mint a continuation; that result is answered with an upstream tool
error naming the step. Two independent review seats rated the unvalidated
discriminator HIGH on the single-tool path, and a chain is the more valuable
target: stopping a chain mid-way is more disruptive than returning one bad
result.

### Bounding

A chain of `n` steps can stop at most `n` times, because each stop seals a
strictly larger `next_step`. A single step asking repeatedly is bounded by the
existing per-exchange round bound, which the chain does not widen. There is no
new unbounded loop.

### Interaction with the destructive-confirmation gate

`ContinuationPurpose` keeps the two apart. A `DestructiveConfirm` grant cannot
be presented as a chain resume, and a `ChainResume` token cannot stand in for a
confirmation. A step held at the gate stops the chain like any other interim
round; answering it resumes at that step, which then runs its confirmation
redemption normally.

## Failing tests this design owes

1. A chain whose step 1 of 3 asks: step 2 does not run, and the response
   carries `pendingStep: 1`.
2. A resume with a valid token runs steps 1..3 and does not re-run step 0.
3. A resume presenting a *different* chain is refused (digest binding).
4. A resume presented by a different caller is refused (fingerprint binding).
5. A resume presented twice is refused the second time (`jti` consumed).
6. A step whose result claims `input_required` but fails
   `InputRequired::from_result` does not stop the chain and does not mint a
   token; the caller gets an upstream tool error naming the step.
7. A step held at the destructive-confirmation gate stops the chain; its
   successors do not run.

## Open questions for review

1. **Is returning the completed results in the stopping response the right
   call**, versus holding them and emitting one array at the end? The design
   takes the former because it needs no new storage and no eviction policy, at
   the cost of making the caller concatenate.
2. **Should a resume be allowed to shorten the tail** — a caller who, having
   seen steps 0..1, no longer wants step 3? Today the digest forbids it. That
   is the conservative choice; it may be the wrong one.
3. **Legacy clients.** A caller that cannot read a top-level interim round sees
   a chain that stopped early with no readable reason. MRTR.11b's fallback rule
   must cover the chain response too, and this design does not yet state it.
