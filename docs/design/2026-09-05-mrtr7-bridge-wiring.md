# MRTR.7 — wiring `InputBridge::run` into the production path

Status: design, not implemented. Reviewed by: (pending).
Change: `fix/mrtr2-continuation-handle`, HEAD `33f64798`.

## Problem

`src/gateway/input_bridge.rs` implements `InputBridge::run` and 21 acceptance
rows drive it green through trait fakes. It has **no production call site**, so
`docs/requirements/RELEASE-4.0.0-criteria-status.md:130,:131` are honestly
marked UNWIRED. Tests-only reachability is a D7:WIRED failure, not done.

## Scope

FOR: giving `InputBridge::run` one production caller, so a legacy client is
asked the backend's question and the backend is retried with the answer.

OUT: the row-308 SSE delivery half (its own deferral, trigger is this commit);
the `NFR.OBS.4` counter name (`RELEASE-4.0.0-cluster-a-readiness.md:44` — "No
design, no counters"); any change to the MRTR.9 refusal or to the continuation
mint for modern callers.

## Where it goes

`src/gateway/meta_mcp/invoke.rs`, between the MRTR.9 undeclared gate (:1517)
and the continuation mint (:1543).

After the gate, not before: a question the client never declared is refused,
never bridged. Bridging first would relay the request the gate exists to stop.

Before the mint, and instead of it for a bridged call: a legacy client never
redeems a continuation. Minting one for an exchange the gateway is about to
complete itself leaves a redeemable envelope for a finished exchange — the
MRTR.2 replay surface, pointed at our own state.

On success `run` returns the backend's completed result, which replaces
`result` and flows through the response-contract gate below unchanged. On
`BridgeError` the call fails; the error's variants already distinguish a
person's refusal from a transport fault, which is what `NFR.OBS.4` needs.

## Blocker — the capability store this presupposes does not exist

`CallerContext::input_capabilities` is populated only from
`RequestShape::declared_capabilities()` (`src/protocol/meta.rs:406-408`), which
reads the **per-request** `_meta` of a `Modern` request. `RequestShape::Legacy`
yields `Declared::NONE` (asserted at `src/protocol/meta.rs:549`). The only
production write is `src/gateway/router/handlers.rs:705,1164`; the other three
construction sites pass `Declared::NONE` outright.

Two consequences, both fatal to the feature as specified:

1. A **legacy** client sends no `_meta` by definition, so it declares nothing,
   so `InputBridge::plan` asks it nothing. The bridge can never fire for the
   only client class it exists for.
2. Rows 311 and 325 assert the **session** store is authoritative and the
   per-request slice may only narrow it. There is no session store. `run`
   already takes `declared` and `slice` as separate arguments and pins that
   rule; production has one value, and it is the slice.

Verified on the write side rather than inferred from the read side: a search
for `declared_capabilities` across `src/` returns one producer.

MCP's `initialize` handshake is where a legacy client declares `elicitation`,
`sampling` and `roots`. The gateway does not retain it — a search for
`"capabilities"` across the router and server finds one test assertion and no
store.

## Options for the missing store

**A. Capture `initialize` client capabilities per session; pass as `declared`.**
The store the requirements already assume. `run`'s two arguments become two
real values: session store authoritative, per-request slice narrowing.
Pro: rows 311 and 325 become true statements about production, not about fakes.
Con: a new per-session store with its own lifetime and eviction; largest change.

**B. Derive "legacy" from `RequestShape::Legacy` and treat any legacy caller as
declaring everything.** Smallest diff.
Pro: unblocks the bridge today.
Con: fail-open. It asks a client for a capability it never claimed, which is
the exact inversion of the MRTR.9 gate one branch above. Rejected.

**C. Option A's store, plus `shape: RequestShape` on `CallerContext`, bridging
only for `Legacy`.** A modern caller that declared capabilities must get a
continuation, not a bridge, and `Declared` alone cannot tell the two apart.

Recommendation: **C**. Deriving the discriminator from `Declared` conflates
"declared nothing" with "cannot understand `input_required`", and those two
need opposite handling.

## Unknowns, scheduled

1. Does the gateway see `initialize` on every transport that can be bridged
   (stdio, SSE, streamable HTTP), or only some? — read the initialize handlers
   in `src/gateway/server/mod.rs` and `router/handlers.rs` — UNANSWERED, and it
   blocks where option A's store can live.
2. Is the `NFR.OBS.4` counter name decided anywhere? — deferred. Owner: the
   readiness doc's owner. Resolves when a counter design exists. Nothing here
   depends on it: `BridgeObserver` is a trait, and production can pass a no-op
   until the name is chosen, which is honest rather than inventing a literal.

## What is not claimed

The 21 bridge rows are reported green by two peer sessions (21 passed, 0
failed, 0.50s). This session could not run them: the test command is refused by
a circumvention guard latched on an earlier disk-pressure block. Evidence level
I — one independent run, reported — not V.
