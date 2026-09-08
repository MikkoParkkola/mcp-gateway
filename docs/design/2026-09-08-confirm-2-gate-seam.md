# CONFIRM.2 — the gate-side seam, handed to the bridge lane

Date: 2026-09-08 · Release: 4.0.0 · Author: lane `confirm-gate` · Owner of the work described: lane `bridge-mrtr7`

Written under ruling R4 (`docs/release/2026-09-08-team-lead-rulings.md:116`): `MIK-7246.CONFIRM.2`
stays with the bridge lane because the row is reachable-through-the-MRTR-path and that path is the
bridge lane's file. This note is the gate side of that seam, written by the lane that holds the gate
and handed over. **Nothing here is implemented against it.** No gate code changed for this note.

Mechanism is not re-opened here. The branch was taken on 2026-09-06 (Option I in
`docs/design/2026-09-06-confirm-2-destructive-confirmation.md`; the criterion text it must satisfy is quoted at
`docs/requirements/RELEASE-4.0.0-blocking-rollup.md:606`): a gateway-originated, in-band `InputRequired` result
carried over the MRTR continuation envelope and redeemed by the client's next call. The test plan
beside it (`...-test-plan.md`) already names the cases. This note only says what the gate looks like
from inside, so the bridge lane does not have to rediscover it.

Every line below was read at source on 2026-09-08 on `fix/mrtr2-continuation-handle`.

## Where the gate is, exactly

`destructive_confirmation_gate` — `src/gateway/meta_mcp/mod.rs:1905`. A **free function**, not a
method:

```
async fn destructive_confirmation_gate(
    id: &RequestId, tool_name: &str, arguments: &Value,
    session_id: Option<&str>, caller: &MetaMcpCallerContext<'_>,
) -> Option<JsonRpcResponse>
```

One production call site: `handle_tools_call`, `src/gateway/meta_mcp/mod.rs:1658`, after the admin
check and before `route_direct_backend_call`. It returns `Some(response)` to refuse and `None` to let
the call proceed. It is on the meta-MCP path; the dispatcher contributes only `caller.confirmation`.

## What the gate already has — more than the design assumed

`MetaMcpCallerContext` (`src/gateway/meta_mcp/mod.rs:113`) already carries both MRTR inputs:

| field | line | what it means at the gate |
|---|---|---|
| `input_capabilities: Declared` | `:142` | what this caller declared on this request; `Declared::NONE` means absent, and absent means never sent a continuation |
| `retry: &RetryFields` | `:156` | the redemption fields the call carried, already parsed — and still attacker-controlled until opened as one of the gateway's own sealed envelopes |

So the redeem side needs no new plumbing into the gate on HTTP: `RetryFields::from_params` runs at
`src/gateway/router/handlers.rs:1220` and the parsed value reaches `caller.retry`.

## The three things that are actually missing

1. **No reach to the continuation state, so the gate cannot mint.** Because the gate is a free
   function it has no `self`, and `MetaMcp::continuation()` (`src/gateway/meta_mcp/mod.rs:535`,
   returning `Arc<ContinuationState>`) is a method. Option I mints at the gate. Either the gate
   gains a parameter or it becomes a method — that choice is the bridge lane's, and it is the
   smallest real signature change in this row.
2. **Stdio can never redeem.** `src/gateway/server/mod.rs:2200` and `:2703` both construct the
   caller context with `retry: &crate::protocol::mrtr::NO_RETRY`, hardcoded. A watcher test already
   records this and is ignored on purpose: `src/gateway/server/mod.rs:3671`. Until those two sites
   parse real retry fields, an in-band confirmation on stdio mints a continuation nobody can ever
   redeem — which is worse than today's honest refusal, not better.
3. **No channel value means "ask in band".** `caller.confirmation` is
   `ConfirmationChannel<'a>` with two variants in use at the gate: `Unavailable` and
   `Elicit { proxy, policy }`. The modern sessionless caller arrives as `Unavailable` and is refused
   at `src/gateway/meta_mcp/mod.rs:1941`. Its comment there — "No asker can exist on this transport"
   — is precisely what Option I falsifies, so that comment is part of the bridge lane's change
   (§P4a), not a leftover to tidy later. The era edge that decides the variant is
   `src/gateway/router/handlers.rs:1413` and `:1416`.

## Four invariants the in-band path must not move

These are CONFIRM.1a's evidence. Breaking one turns a MET clause back into a regression, and the
tests that would catch it are named in the CONFIRM.1a cell of `docs/requirements/RELEASE-4.0.0-criteria-status.md`.

1. A modern caller that declared no input capabilities is still refused: JSON-RPC `-32001`, message
   containing `none could be obtained`, no `result`. `Declared::NONE` is the discriminator, and
   `ConfirmationPolicy::for_modern()` (`src/gateway/destructive_confirmation.rs:99`) returning
   `REFUSE` stays the fallback for it.
2. The refusal marker is not for the new result. `confirmation_refusal_response`
   (`src/gateway/meta_mcp/mod.rs:1896`) sets `response.confirmation_refusal = true`, which the
   accounting tail reads to tell a refusal apart from a client failure. An in-band `InputRequired`
   is neither — it must not travel through that constructor, or asking a question will walk callers
   toward a tripped breaker.
3. An operator decline stays a decline, distinct from unconfirmable: the `Declined` arm at
   `src/gateway/meta_mcp/mod.rs:1949` returns `Operator declined: {desc}`, and the two messages are
   what separate the branches in test assertions.
4. The 120-second `ELICITATION_TIMEOUT` (`src/gateway/destructive_confirmation.rs:63`) is the
   elicitation channel's bound and is not the in-band one. The in-band bound is the continuation's:
   the mint budget (`src/protocol/continuation.rs:340`), the expiry checked by
   `Keyring::open` (`:473`), and the in-flight ledger (`:664`). Reusing the constant would
   pin an unrelated number to a different mechanism.

## What this note does not decide

Where the `InputRequired` payload is shaped (`src/protocol/mrtr.rs:200`, with
`Bridge::to_legacy_client` at `:454` and `retry_params` at `:477`), what goes in the continuation
`Payload` (`src/protocol/continuation.rs:64`), and whether the gate mints before or after
`describe_destructive_action`. All of that is the bridge lane's, and this lane has no opinion it is
entitled to.

The row stays ABSENT and blocking until the in-band path is wired and tested. A seam note is not a
wiring.
