# MRTR.7 — wiring `InputBridge::run` into the production path

Status: design, not implemented. Reviewed by: GPT-5.x and Kimi K2, both
SHIP-WITH-FIXES, both naming the same blocker. Findings disposed below.
Change: `fix/mrtr2-continuation-handle`, HEAD `33f64798`.

## Problem

`src/gateway/input_bridge.rs` implements `InputBridge::run` and 21 acceptance
rows drive it green through trait fakes. It has **no production call site**, so
`docs/requirements/RELEASE-4.0.0-criteria-status.md:130,:131` are honestly
marked UNWIRED. Tests-only reachability is a D7:WIRED failure, not done.

## Scope

FOR: giving `InputBridge::run` one production caller **on the HTTP transports**,
so a legacy client that declared a capability at `initialize` is asked the
backend's question and the backend is retried with the answer.

OUT OF THIS CHANGE, NOT OUT OF THE RELEASE: legacy **stdio** callers keep the
MRTR.9 refusal they get today. Ruled by the requester on 2026-09-05, on the
finding below that stdio's serial read loop deadlocks any bridged call. Stdio
concurrency is a **separate work package** — independently designed,
independently implemented, lower priority than this one — and whether it lands
in 4.0.0 is decided after that design exists and carries an effort estimate,
not now. Deferring it here is a sequencing decision, not a decision to drop it.

Also out: the row-308 SSE delivery half (its
own deferral, trigger is this commit); the `NFR.OBS.4` counter name
(`RELEASE-4.0.0-cluster-a-readiness.md:44` — "No design, no counters"); any
change to the MRTR.9 refusal or to the continuation mint for modern callers; the
two defects the review raised inside `input_bridge.rs` itself (unvalidated
params, request-kind-blind reply projection), which are that file's bugs and not
this change's wiring.

Consequence, stated rather than discovered later: rows :130 and :131 go green
for the HTTP transports only. Whether that reads as met, or as met with a named
limit, is the release owner's call and not this design's.

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

**The merge is conditional on shape, and that is load-bearing.** The MRTR.9
gate is shape-blind — `invoke.rs:1518` reads `caller.input_capabilities` with
no modern/legacy branch — so an unconditional merge would silently widen the
gate for modern callers too: one that declared `elicitation` at `initialize`
and sent no per-request `_meta` is refused today and would be minted a
continuation after the change. That is a fail-open move on a security gate
nobody asked for, and it is the same inversion option B was rejected for.
So `input_capabilities` is the session value **only for `Legacy`**, which has
no per-request channel at all — that absence is the whole reason the merge
exists. `Modern` keeps per-request semantics exactly as today. Every row of
the decision table below then holds as written.

Recommendation: **C**. Deriving the discriminator from `Declared` conflates
"declared nothing" with "cannot understand `input_required`", and those two
need opposite handling.

## Second blocker — stdio cannot answer a question it is being asked

Both reviewers returned SHIP-WITH-FIXES. One finding is fatal to the feature on
the transport it exists for, and it is verified at source rather than accepted
on the reviewer's word.

`src/gateway/server/mod.rs:1581` is `while let Ok(Some(line)) =
reader.next_line().await { … dispatch … }` — one reader, strictly serial, the
next line read only after the current dispatch returns. A bridged call blocks
inside that dispatch waiting for the client's answer, and the answer arrives on
the stdin nobody is reading. Every legacy stdio bridge deadlocks until
`BridgeBounds::DEFAULT` expires it: 30 s per prompt, 120 s aggregate.

This is not a defect in the bridge. It is the transport lacking the concurrency
the bridge presupposes, and no placement of the call inside `invoke.rs` avoids
it. Two honest responses, and the choice was not engineering's to make alone:

- **Make stdio concurrent** — dispatch off the read loop, route replies by id
  before dispatch, one serialized writer, an `initialize` barrier. A transport
  rewrite, several times the size of the wiring this design is for.
- **Bridge only where the concurrency already exists** — the HTTP transports
  have in-flight request correlation (`ProxyManager`'s pending-response path).
  Legacy stdio callers keep the MRTR.9 refusal they get today.

Asked of the requester, 2026-09-05. Answer: bridge on HTTP only. Stdio
concurrency becomes its own work package — designed and estimated separately,
kept at lower priority, and admitted to or excluded from the release once that
design shows what it costs. It narrowed this design's FOR to the HTTP
transports; stdio moves out of THIS change, above, and stays on the release's
open list until its own design is reviewed.

## Review findings, disposed

| finding | disposal |
|---|---|
| gate refuses before the bridge is reached (both vendors, HIGH) | confirmed as a **documentation** gap, not a mechanism one — see below |
| read side never verified: does the bridge site hold the session id (Kimi, HIGH) | **died at source.** The lookup belongs at `CallerContext` construction, where `session_id` is already in scope on both transports. Nothing new reaches `invoke.rs`, and the suggested fix — threading a store into the invoke path — is unnecessary |
| absent session capabilities leave the default unspecified (Kimi, HIGH) | confirmed. Pinned fail-closed below |
| store has no eviction or ownership (both vendors, HIGH) | confirmed. Bound to session lifecycle below |
| no production `ClientChannel` / `BackendInvoker` / `BridgeObserver` (GPT, HIGH, CERTAIN) | confirmed. This design understated its own change surface; see below |
| stdio serial dispatch deadlocks a bridged call (GPT, HIGH, CERTAIN) | confirmed at source. Second blocker, above |
| reply projection is not request-kind-aware; params forwarded unvalidated (GPT) | out of this scope — defects in `input_bridge.rs` itself, not in wiring it. Filed rather than fixed here |
| store as an injected trait (Kimi) | declined. A trait with one implementation is an abstraction nothing asked for. `BridgeObserver` earns its trait because production genuinely passes a no-op; a capability store does not |

### One capability value, two consumers

The gate at `invoke.rs:1514` reads `caller.input_capabilities`. So does the
bridge. Feeding that one field from the merged value — session store
authoritative, per-request slice narrowing — makes the gate consult the merged
set by construction, with no second consumer to keep in step. Stating it is the
fix; changing the gate would be the defect.

The merge happens where `CallerContext` is built, not where it is read:
`src/gateway/router/handlers.rs:705,1164` (HTTP, `session_id` in scope at :707)
and `src/gateway/server/mod.rs:1827` (stdio, `session_id` in scope from :1722,
constant `"stdio-session"` at :1579).

**Absent is fail-closed.** No captured capabilities for a session — evicted,
pre-store, restarted — means the client declared nothing, and the question is
refused. The rejected option B is exactly what a fail-open default would
reintroduce through the back door.

**The store is not a store.** Declarations are co-owned by each transport's
existing session state and cleared or replaced atomically on `initialize`,
disconnect, session `DELETE` and reap. A session id is client-supplied and
reusable; a declaration that outlives its session is inherited permission.

### Change surface, stated

Wiring one call is the smallest part of this.

- `Declared::parse` (`src/protocol/meta.rs:367`) already takes a plain
  capabilities map of exactly the `initialize` shape, and already reads the 2026
  elicitation modes from it — an empty `elicitation` object declares form mode.
  It is **private**. Rather than widening the parser itself, expose a named
  constructor — `Declared::from_initialize` — documenting the exact
  capabilities-map contract it accepts. The visibility change then reads as a
  designed API surface instead of a convenience opening.
- stdio still captures its client's declaration at `initialize` under the
  constant `"stdio-session"`, and nothing reads it until the stdio work package
  lands. That write is deliberately stored-but-unused; it is not dead code and
  should not be removed as such.
- a write in `MetaMcp::handle_initialize`, and a read at each `CallerContext`
  construction site. Seven, enumerated from source and split by role: two
  production writes carrying a real declaration (`handlers.rs:705,1164`), and
  five passing `Declared::NONE` today (`invoke.rs:3816,3846,3881` — tests —
  and `server/mod.rs:1827,2619` — stdio). An earlier revision of this document
  said "five" while listing seven; the count was wrong, the list was right.
- `shape` threaded to each of those sites, and production implementations of
  the bridge's three traits, which today exist only as test fakes.
- `CallerContext::input_capabilities` currently documents itself as "what this
  caller declared on **this** request". That contract changes to the merged
  value; the comment changes with it.

### Decision table

| shape | declared | outcome |
|---|---|---|
| modern | yes | continuation minted, as today |
| modern | no | refused by MRTR.9, as today |
| legacy | yes (from `initialize`) | bridged |
| legacy | no | refused by MRTR.9, as today |

## Unknowns, scheduled

1. Does the gateway see `initialize` on every transport that can be bridged
   (stdio, SSE, streamable HTTP), or only some? — read the two production
   dispatch sites — RESOLVED: both reach one shared handler,
   `MetaMcp::handle_initialize` (`src/gateway/meta_mcp/mod.rs:1151`), from
   `src/gateway/server/mod.rs:1788` (stdio serve loop) and
   `src/gateway/router/handlers.rs:926` (HTTP router). It already receives both
   values a per-session store needs: the `initialize` `params`, which carry the
   client's `capabilities` object, and a `session_id` that both call sites pass
   as `Some(..)`, never `None`. Changed the design: option A's store goes
   inside that handler, one write site covering every bridgeable transport, not
   one per transport as the option feared.
2. Is the `NFR.OBS.4` counter name decided anywhere? — deferred. Owner: the
   readiness doc's owner. Resolves when a counter design exists. Nothing here
   depends on it: `BridgeObserver` is a trait, and production can pass a no-op
   until the name is chosen, which is honest rather than inventing a literal.

3. Which existing session state should carry the declarations? — RESOLVED, and
   the answer is not the one both reviewers assumed. `SessionStateStore`
   (`src/gateway/state.rs:22`) is the right shape to copy: keyed by session id,
   `Arc<RwLock<HashMap<..>>>`, cheaply cloneable. `SessionLifecycle`
   (`src/gateway/session_lifecycle.rs:22`) is the right owner in principle —
   named callbacks fired on disconnect and on a reclamation deadline, the
   deadline existing precisely because MCP 2026-07-28 removed protocol
   sessions.

   But **nothing registers with it in production.** `register` is called only
   from its own unit tests; `SessionStateStore::remove_session` has no
   production caller either. Three modules' doc comments instruct the reader to
   register via the hook — `src/security/firewall/anomaly.rs:187`,
   `src/security/firewall/mod.rs:680` — and `anomaly.rs:129` states in its own
   words that nothing reclaims a session.

   So "bind eviction to the existing session lifecycle", which both reviewers
   independently recommended and which this design accepted, would have written
   a comment claiming eviction while shipping the leak they flagged. The hook
   must be *wired* before anything can hang off it, and the leak is already
   shared: the firewall's anomaly tracker is waiting on the same callback.
   Wiring it is a prerequisite of this change and benefits more than this
   change. Verified by search on the write side, which is where an absent
   caller is visible: no non-test `register` call, no production
   `remove_session` call.

## What is not claimed

The 21 bridge rows are reported green by a peer session (21 passed, 0 failed,
0.50s). This session has not reproduced that run, so the evidence level is I —
one run, reported — not V.

The obstacle was disk, and it is fixed: the root filesystem stood at 4.4 GB
free (99% used), below the fail-fast threshold that halts the build. Cleaning
this worktree's `target/` returned 6.9 GB, leaving 10.9 GB. The test command
itself remains refused until 13:41 UTC by a circumvention latch recorded
against the earlier disk block, which expires on a four-hour timer. Re-running
both acceptance suites after that expiry is what raises this to V; nothing in
this design should be implemented on the strength of the reported run alone.
