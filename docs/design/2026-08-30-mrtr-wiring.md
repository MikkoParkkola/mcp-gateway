# Wiring multi-round-trip tool calls

MIK-7325 (MRTR unwired) and MIK-7312 (continuation state is process-local) are one design.
Both are about the same thing: a tool call that spans more than one HTTP request, and the state
that has to survive between the two.

## Problem

The 2026 revision lets a backend answer a `tools/call` with an *interim* result — `resultType:
"input_required"` plus a set of questions and an opaque `requestState` — and wait to be retried
with the answers. The gateway sits between a backend that may do this and a client that may not
understand it.

Both halves of that mechanism are built and neither is reachable from production code (V,
2026-08-30):

| module | size | production call sites |
|---|---|---|
| `src/protocol/continuation.rs` — envelope mint/open, caller binding, single-use ledger, replica routing | 26.5K | **0** (`rg 'continuation::' src/ --glob '!*tests*'`) |
| `src/protocol/mrtr.rs::Bridge` and `InputRequired` | part of 8.6K | **0** |

`RetryFields::from_params` is the sole exception: `src/gateway/router/handlers.rs:860` calls it to
*detect* a retry and then refuses it — `"retry forwarding is not available on this build"`
(handlers.rs:884). The refusal is deliberate and correct for a build that cannot forward; it is
also the whole feature, declined at the door.

Consequence: a 2026 backend that asks a question cannot complete a call through this gateway.
The client receives the interim result verbatim (the response path does not recognise it either),
answers it, and gets HTTP 400. This is a DoD §2 WIRED violation on the branch's headline feature.

## Constraints, measured

- `AppState` (`src/gateway/router/mod.rs:50`) already carries `gateway_key_pair:
  Arc<GatewayKeyPair>`, so a keyring has an established place to live and an established
  construction path.
- `Keyring::open` takes `now` explicitly and `Payload::redeemable_by` already implements the caller
  binding, so neither has to be designed here — only called.
- `ConsumedLedger` (continuation.rs:437) and the mint budget (`with_mint_budget`, :292) are
  **per-process**. The gateway is deployed as a single process today; the moment it is not, a
  continuation minted by one replica is unopenable by another and the single-use guarantee holds
  per replica rather than globally. `Routing` and `InFlight` (:519, :548) exist to carry a replica
  hint — also unwired.
- The client's `requestState` is *not* the backend's. The gateway mints its own envelope and seals
  the backend's state inside it; forwarding the client's copy verbatim defeats the module
  (handlers.rs:846-852 states this).
- **Idempotency caches an interim result as a completed one.** `src/idempotency.rs` auto-generates
  a key from `SHA-256(tool_name || canonical_json(arguments))` for side-effecting tools and stores
  the result as `Completed`, replaying it for any later caller with the same arguments (:9-16).
  An `input_required` result is neither a completion nor replayable: cached, the tool can never
  finish, and a second principal calling the same tool with the same arguments is handed the first
  principal's continuation. This is a security defect, not only a correctness one, and it is
  reachable the moment the response side ships. RFC-0060:141 raised it; nothing has been done.

## What is in scope

FOR: a `tools/call` that returns `input_required` completes, through the gateway, in two round
trips, for a client that speaks the 2026 revision.

OUT, explicitly:

- the legacy-client bridge (`Bridge::to_legacy_client`) — asking a pre-2026 client a question
  mid-call needs a server-initiated request over the client's own transport, which is a second
  design. `to_legacy_client` stays unwired and stays out of the release claim.
- multi-replica continuation state (MIK-7312). Addressed here only by *deciding* it, below.
- more than one interim round trip per call. The envelope carries a round counter; the cap is a
  configuration value, not a mechanism to design.

## The shape

Two edits, one on each side of `dispatch_to_backend`.

**Response side (new).** After a backend result comes back on the `tools/call` path, read it with
`InputRequired::from_result`. `None` — the overwhelmingly common case, and every legacy backend —
falls straight through, unchanged. `Some` means: take `interim.request_state`, seal it in a
`Payload` bound to this caller, mint, and return the interim result to the client with the
gateway's token in `requestState`. The questions pass through untouched: they are the backend's,
and a client that speaks 2026 answers them directly.

**Retry side (replace the refusal).** `RetryFields` already parses. Where handlers.rs:884 returns
an error, instead: `Keyring::open` the client's token, `redeemable_by` the current caller,
`ConsumedLedger` to burn it, then `Bridge::retry_params` to build the sibling params from the
*backend's* unsealed state plus the client's answers, and dispatch. Every failure from `open`
maps through `ContinuationError::client_message`, which exists so a refusal cannot leak why.

## Options considered

**Seal the backend state in a token handed to the client** (chosen). No server-side session, so no
eviction policy and no cross-replica store on the happy path; the client holds the state and cannot
read or forge it. Cost: the token rides every retry, so the 8 KiB wire bound (continuation.rs:41)
is a real limit on backend state.

**Keep the backend state server-side, hand the client an opaque id.** Rejected: it converts a
stateless gateway into one with a session store, which is exactly the cross-replica problem in
MIK-7312 made mandatory rather than optional. The sealed-token design has that problem only for
the single-use ledger, and only when replicated.

**Forward the client's `requestState` untouched.** Rejected on the record at handlers.rs:846-852 —
it hands a backend a value the client controls.

## Decisions this design makes

1. **The response side ships; the legacy bridge does not.** A 2026 client gets a working
   multi-round-trip call. A pre-2026 client gets what it gets today, and the release notes say so.
   Shipping half is what makes the other half's absence honest rather than hidden.
2. **Single-use stays process-local for 4.0.0, and is documented as such.** The deployment is one
   process. A shared ledger is a real piece of work (a store, its failure mode when unreachable,
   and a decision about whether an unreachable store fails open or closed) and doing it badly under
   release pressure is worse than declaring the limit. MIK-7312 keeps it.
3. **An interim result is never stored as an idempotency completion.** The response side, on
   recognising `input_required`, must prevent the entry being written as `Completed` — the interim
   result is not a result. The narrower repair (extending the key to include `inputResponses` and
   `requestState`, as RFC-0060:143 suggests) is rejected: it makes the retry miss the cache, which
   is right, while still caching the *interim* answer under the original key, which is the
   dangerous half. Not caching it at all leaves the defect undescribable rather than unreachable.

## Unknowns, scheduled

| unknown | how it is settled |
|---|---|
| Does any backend fixture actually return `input_required`? | **Resolved — no.** `rg 'input_required'` across the tree returns only `mrtr.rs`, `handlers.rs`, two AC test files and the A2A translator's unrelated `TaskState::InputRequired`. No fixture backend produces one, so the test plan must add a backend that does; without it every response-side test would be asserting against a shape nothing emits. |
| Does the 2026 specification put `requestState` on the interim *result*, or in `_meta`? | **Resolved — on the result.** Read at source 2026-08-30, `https://modelcontextprotocol.io/specification/2026-07-28/server/tools` §"Input Required Tool Results": `requestState` is a top-level sibling of `resultType` and `inputRequests` in the result object, and `inputResponses`/`requestState` are siblings of `name`/`arguments` on the retry. `InputRequired::from_result` reads exactly that, so the assumption it was written on is correct and the response side is unblocked. Confirmed in the same read: an ordinary 2026 result carries `"resultType": "complete"`, which `from_result` already falls through on. |
| Is one interim round trip enough for the release claim, or must the cap be greater than one? | **Askable — operator.** Changes the AC, not the mechanism. |
| The specification says the JSON-RPC `id` **MUST** differ between the initial call and the retry. Does the gateway enforce or preserve that? | Checkable, and not yet checked. The gateway forwards ids; whether a backend sees two different ones depends on how the retry is dispatched. Cheap to settle once the retry side exists, and it belongs in the test plan rather than the mechanism. |

The first row changes what the release can claim: the response side no longer waits on anything,
and the retry side waits only on the review of this document.

## Test plan sketch

One row per behaviour; the plan proper follows the design review. All of them need the fixture
backend the first unknown says does not exist yet.

- a legacy (no `resultType`) result passes through byte-identical — the regression that matters most
- an `input_required` result yields an interim response whose `requestState` is *not* the backend's
- an `input_required` result leaves no `Completed` idempotency entry, and a second caller with
  identical arguments reaches the backend rather than the first caller's continuation
- a retry with a valid token reaches the backend with the backend's state and the client's answers
- a retry with a token minted for a different caller is refused, and the message says nothing useful
- a replayed token is refused the second time
- a malformed retry is refused without dispatching (the existing behaviour, kept)

