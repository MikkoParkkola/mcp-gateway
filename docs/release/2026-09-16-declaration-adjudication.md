<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# Ten removed declarations: moved, or lost?

Ten top-level declarations disappeared from the v4 line during the meta-MCP
rework. A removal is only safe if the behaviour moved somewhere a caller still
reaches. This adjudicates each one against source on the release branch.

Nine moved. One is a real loss and is tracked below.

## Moved

| Declaration | Where the behaviour lives now |
| --- | --- |
| `is_mcp_envelope` | `src/gateway/meta_mcp/invoke.rs:231` |
| `decorate_modern_result` | renamed `shape_modern_response`, `src/gateway/router/handlers.rs:2025` |
| `redeem_carried_confirmation` | inlined into `destructive_confirmation_gate`, `src/gateway/meta_mcp/mod.rs:2633-2660`; see also `redeem_confirmation` (`:2487`) and `CONFIRMATION_INPUT_KEY` (`:2439`) |
| `REQUEST_CANCELLED` | replaced by `TaskStatus::Cancelled`, `src/protocol/tasks.rs:32,281`; the `-32800` arm went with it, asserted at `src/gateway/router/tests/task_execution_adapter/lifecycle.rs:85-92` |
| `SseExchange` | `notification_sink::publish`, `src/transport/http/sse_decoder.rs:262`, with `decode_sse_exchange` at `:281` |
| `task_view` | `Task::wire`, `src/protocol/tasks.rs:238`, consumed at `src/gateway/router/handlers/tasks.rs:70` |
| `fail_with_code` | `Task::fail(error: JsonRpcError)`, `src/protocol/tasks.rs:248` — a superset, it preserves `data` |
| `BridgeDispatcher` | `src/gateway/meta_mcp/invoke.rs:848`, with `ChallengeGate` (`:869`) and `BackendInvoker` (`:899`) |
| `TracingBridgeObserver` | `src/gateway/meta_mcp/invoke.rs:1012,1016` |

The `REQUEST_CANCELLED` case is a deliberate redesign, not an omission: the
status enum carries what the error code used to, and a test asserts the new
shape.

## Lost: `promote_interim_envelope`

Top-level promotion of an interim round — one whose `resultType` is
`input_required` — is absent from the synchronous meta-tool path.

Verified at source on this branch:

- `wrap_tool_success` (`src/gateway/meta_mcp_helpers.rs:748`) serialises the
  whole value with `to_string_pretty` into `content[0].text`. It promotes
  nothing. `structuredContent` is populated only when the tool declares an
  output schema, which today is `gateway_search_tools` alone.
- Every synchronous meta-tool result goes through it:
  `ResultShape::Wrapped => wrap_tool_success(...)` at
  `src/gateway/meta_mcp/mod.rs:2153-2155`.
- `ResultShape::Native` (`:2156`) skips the wrapper, but only the task worker
  selects it (`:2033`). It escapes the defect by not wrapping, not by fixing it.
- No promotion helper exists: a repository-wide search for `promote` finds no
  candidate in `src/`.

Effect: on a non-task `gateway_invoke` or `gateway_execute`, an interim round
arrives with `resultType`, `inputRequests` and `requestState` buried inside a
pretty-printed string. A protocol client that keys on those fields cannot see
them, so it cannot answer the round. The task path is unaffected.

This is protocol-visible behaviour on a shipped meta-tool surface, so it is a
release question rather than a cleanup: either promote the interim fields on the
`Wrapped` arm, or state in the release notes that interim rounds require the
task path.

## Grading the loss

**Blocker.** Not on the strength of a requirement row — no MRTR row covers it.
`MIK-7212.MRTR.1a` through `.10a` cover carrying the retry pair, minting and
verifying `requestState`, binding and bounding a continuation, and bridging to a
legacy client. None of them says a meta-tool result must present an interim
round at the top level. This is a scope gap, so it needs a row before it can be
graded at all.

It grades as blocking on two facts read at source:

1. The same failure was already treated as a defect on the direct `tools/call`
   path. `shape_modern_response` inserts `resultType` with
   `.entry().or_insert_with(...)` (`src/gateway/router/handlers.rs:2038-2041`)
   precisely because an unconditional insert once relabelled an interim result
   `complete` — its comment: *"a client saw a finished call where the server was
   waiting for an answer and could no longer supply one."* The meta-tool surface
   still produces that outcome, by wrapping rather than by relabelling.
2. The Meta-MCP surface is the product's primary surface, not a side path. A
   defect that only bites `gateway_invoke` and `gateway_execute` bites the way
   the gateway is meant to be used.

The source already names the behaviour. The doc comment on
`dispatch_below_gate_native_result` (`src/gateway/meta_mcp/mod.rs:2011-2017`)
says the wrapper *"hides an interim round — `resultType: "input_required"`
inside a JSON string is not a claim the settlement classifier can read, so a
question would be committed as an answer."* The task worker was given
`ResultShape::Native` to escape it; the synchronous path was not.

### Shape of the fix

Do not wrap an interim result. In the `Wrapped` arm
(`src/gateway/meta_mcp/mod.rs:2153-2155`), a result whose `resultType` is
`input_required` takes the `JsonRpcResponse::success(id, content)` branch that
`Native` already takes. The supporting machinery exists:
`ResponseMutationPolicy::PreserveInputRequired` and the native interim delivery
test (`src/gateway/meta_mcp/response_delivery_tests.rs:537`).

Open question for the design review: whether a legacy client calling a meta-tool
must instead keep the wrapped text, which would make the shape depend on the
caller's declared capabilities rather than on the result alone.

## Design review, 2026-09-16 (gpt seat; grok down on an exhausted balance)

Verdict `SHIP-WITH-FIXES`. Two findings, both verified here at source rather
than taken on the reviewer's word.

### The chain path is worse than the wrapper — CONFIRMED

`gateway_execute` runs a chain in a loop at `src/gateway/meta_mcp/search.rs:505-555`.
`invoke_tool` answers an interim round with `Ok(result)`, because a question is
a successful result and not an error. The loop therefore pushes it as

```rust
Ok(result) => results.push(json!({"step": idx, "tool": tool_ref, "result": result})),
```

and proceeds to step `idx + 1`. Nothing in the loop inspects `resultType`. Only
`Err` stops a chain, and the two error arms below it exist to preserve a refusal
and to wrap a failure.

So a chain step that asks a question is recorded as a completed step and the
chain keeps running. A step gated on a destructive-tool confirmation does not
perform its action, yet its successors execute as if it had. Not wrapping the
interim result fixes how the round is *presented* and does nothing about this.

### Discriminating on the bare string is not enough — accepted

Promoting on `resultType == "input_required"` alone lets an untrusted backend
turn any result into an interim round the client cannot complete. Promote only
what `InputRequired::from_result` accepts, and answer a rejected claim with an
upstream tool error.

### Consequence for the fix

The one-arm change is necessary and insufficient. The work is:

1. Promote a *validated* interim result on the `Wrapped` arm.
2. Stop a chain at the first validated interim, and lift it to the top level
   with gateway-owned continuation state so a retry resumes rather than replays
   the steps already run.

Step 2 needs its own design: what the continuation carries, and what a retry is
allowed to skip. Recorded here so the scope is not quietly narrowed back to the
single match arm.

Reviewer improvements accepted as scope, not blockers: synchronous
`gateway_invoke` / `gateway_execute` delivery tests, and keeping the wrapped-question
test (`response_delivery_tests.rs:510`) under a name that marks it as legacy
bridge coverage rather than obsolete behaviour.

### Second seat (kimi), same verdict

`SHIP-WITH-FIXES`. It reaches the untrusted-discriminator finding independently
and rates it HIGH: a hostile backend could turn any completed answer into a
client-facing question loop carrying attacker-authored prompts. Two reviewers
arriving at that separately settles it — validation before promotion is part of
the design, not a hardening pass afterwards.

Two findings gpt did not raise:

- **No fallback rule for a client that cannot act on a top-level interim
  result.** The wire shape would flip per payload with nothing negotiated. Such
  a client stalls on an opaque native result where today it at least receives
  readable text. This answers the open question above: the design must state the
  rule, and capability negotiation is the obvious place for it.
- **The `:510` test pins a property, not just a shape.** It asserts the firewall
  treats a wrapped question as trusted-immutable. Retarget it to the native
  interim shape; deleting it silently drops that assurance.

Both seats agree the direction is right — parity with the direct `tools/call`
path and with the task worker's `Native` arm. Neither found a reason to keep
wrapping interim results.

## Where this stands

Design reviewed, not yet implemented. Before code: write the validation rule and
the legacy-client fallback into the design, then a failing test first.
