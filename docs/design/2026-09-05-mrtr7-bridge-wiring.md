# MRTR.7 — wiring `InputBridge::run` into the production path

Status: design, not implemented. Change: `fix/mrtr2-continuation-handle`.

Reviewed twice, adversarially, by two vendors: `gpt-review` (Codex/GPT-5.x) and
`synthetic-review` (the open-weights leg, `glm-5.3` alias — the wrapper formerly
called `kimi-review`; earlier revisions of this file misattributed it to Kimi K2,
which did not run). Round 2 ran against `08c0b9c9` and both returned
SHIP-WITH-FIXES, each naming a doc-level fix inside this design. A third,
confirmation pass ran against `b645491e`: `gpt-review` returned SHIP-WITH-FIXES
naming three defects this wiring would activate rather than inherit, amended
below. The open-weights leg returned SHIP-WITH-FIXES on the same revision and is
amended alongside it. Its run file read as zero bytes while the process was
still running — the wrapper writes the file at completion, so an empty read is a
race, not a missing verdict, and this document briefly recorded it as the
latter. Findings disposed below.

## Problem

`src/gateway/input_bridge.rs` implements `InputBridge::run` and 18 acceptance
rows drive it green through trait fakes (mapped to their tests by name in the
companion test plan). It has **no production call site**, so
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

IN, not out: live delivery of the question over the client's own stream.
Release row 308 defers its own evidence with this commit as the trigger, which
defers *that row's evidence* and is **not** permission for this change to skip
delivery. A
legacy HTTP client that cannot actually receive the bridge's question has not
been bridged, so delivery over the live stream is inside FOR and
`MIK-7212.WIRE.8` is the row that finds out whether it works; the `NFR.OBS.4` counter name
(`RELEASE-4.0.0-cluster-a-readiness.md:44` — "No design, no counters"); any
change to the MRTR.9 refusal or to the continuation mint for modern callers; the
two defects the reviews raised inside `input_bridge.rs` itself: a pending entry
stranded when the outer timeout cancels registration (`:430`), and reply
projection that reads any result containing `action` as an elicitation reply
(`:454`). They are that file's bugs rather than this change's wiring, and they
are filed together as **MIK-7388**.

Two further findings were carried here as defects and **died at the
requirements**, which is why the count fell from four. A timed-out prompt
retrying the backend without an answer (`:433`) is what requirement row 320
specifies — "abandoned at `min(remaining, 30s)`, and the rounds still remaining
are unaffected" — and `ac_mrtr_7b_an_unanswered_prompt_ends_its_round_not_the_call`
pins `frames == 2, calls == 2` to prove the call does **not** end. Deserializing
prompt params into a typed `ServerRequest` (`:409`) is what row 308 forbids:
params must reach the client whole, "nothing dropped and nothing invented", and
a round-trip through a typed struct drops what the struct does not name. The
reviewer's underlying worry — a backend continuing without input a person never
gave — is real and unaddressed; changing either row is the **requester's** call,
not a repair, and it is raised as an open question rather than made here.

That deferral is scheduled, not merely recorded. Owner: MIK-7388, priority 2,
already related to MIK-7212 as `blocks`. What resolves it: the three acceptance
criteria on that ticket, each a test that fails against today's tree. When: it
merges **before** this wiring does — that is what the `blocks` edge means here,
because wiring is what first makes the defects reachable. If it resolves badly —
the defects prove deeper than a bounded fix, or the ticket stalls — this change
does not ship on its own; it waits, because a call site that activates two
known HIGH defects is worse than the UNWIRED row it replaces.

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

The tests this change needs are planned separately, in
`docs/design/2026-09-05-mrtr7-test-plan.md`, and reviewed as a plan before any
test code is written.

## Review findings, disposed

| finding | disposal |
|---|---|
| gate refuses before the bridge is reached (both vendors, HIGH) | confirmed as a **documentation** gap, not a mechanism one — see below |
| read side never verified: does the bridge site hold the session id (synthetic, HIGH) | **died at source.** The lookup belongs at `CallerContext` construction, where `session_id` is already in scope on both transports. Nothing new reaches `invoke.rs`, and the suggested fix — threading a store into the invoke path — is unnecessary |
| absent session capabilities leave the default unspecified (synthetic, HIGH) | confirmed. Pinned fail-closed below |
| store has no eviction or ownership (both vendors, HIGH) | confirmed. The answer given here first, `SessionLifecycle`, was superseded on the next round — see the re-raised row below for the owner that ships |
| no production `ClientChannel` / `BackendInvoker` / `BridgeObserver` (GPT, HIGH, CERTAIN) | confirmed. This design understated its own change surface; see below |
| stdio serial dispatch deadlocks a bridged call (GPT, HIGH, CERTAIN) | confirmed at source. Second blocker, above. **Filed as MIK-7387** with the three failing rows as its acceptance evidence; the requester decides include/exclude for the release there |
| reply projection is not request-kind-aware; params forwarded unvalidated (GPT) | out of this scope — defects in `input_bridge.rs` itself, not in wiring it. Filed rather than fixed here |
| store as an injected trait (Kimi) | declined. A trait with one implementation is an abstraction nothing asked for. `BridgeObserver` earns its trait because production genuinely passes a no-op; a capability store does not |
| two of MIK-7388's four defects contradict frozen acceptance rows (implementer, HIGH) | confirmed at source. `:433` is what row 320 specifies and `:409` is what row 308 forbids; both findings die at the requirement, and the ticket narrows to `:430` + `:454`. Whether row 320 is the behaviour the requester wants is open question 4, not a repair |
| store has no eviction or ownership (both vendors, HIGH) — **re-raised on the amended design** (GPT, HIGH) | confirmed twice. The first answer, `SessionLifecycle`, has no production caller at all; declarations live in the `NotificationMultiplexer` session map instead, the only session-keyed store whose removal runs in production. Superseded answer recorded at open question 3; the owner is fixed by amendment 3 |
| bridge retries invoke the backend outside cost accounting (GPT, HIGH, LIKELY) | confirmed at source: `invoke.rs:1246,1369,1394` each fire once around the single dispatch at :1327. In scope — this change creates the second invocation. One dispatch helper, change surface above |
| the merge widens MRTR.9 for modern callers while the table says it does not (synthetic, MEDIUM, CERTAIN) | confirmed at source: the gate at `invoke.rs:1518` is shape-blind. Merge scoped to `Legacy` only, option C above |
| construction-site census says five and lists seven (synthetic, LOW) | confirmed. Count was wrong, list was right; re-enumerated by role |
| timed-out client prompt discarded, backend retried without the answer (GPT, HIGH, LIKELY) | out of this scope — a defect inside `input_bridge.rs`, not fixed by a wiring change. **Filed as MIK-7388** with the pending-map growth, blocking MIK-7212 |
| pending-response map grows if the outer timeout cancels after registration (GPT, HIGH) | out of this scope, same file. **Filed as MIK-7388**, which blocks MIK-7212: neither defect is reachable until this wiring gives the bridge a caller |
| production-path HTTP test beyond trait fakes (GPT, MEDIUM) | accepted. The acceptance rows are fake-driven; one end-to-end HTTP test is the honest evidence and belongs in the test plan |
| compact legacy-or-modern discriminator instead of full `RequestShape` (GPT, both passes) | accepted. Recorded as the field's intended shape; `RequestShape` was shorthand, not a requirement |

### One capability value, two consumers

The gate at `invoke.rs:1514` reads `caller.input_capabilities`. So does the
bridge. Feeding that one field from the merged value — session store
authoritative, per-request slice narrowing — makes the gate consult the merged
set by construction, with no second consumer to keep in step. Stating it is the
fix; changing the gate would be the defect.

The merge happens where `CallerContext` is built, not where it is read:
`src/gateway/router/handlers.rs:705,1164` (HTTP, `session_id` in scope at :707)
and `src/gateway/server/mod.rs:1827` (stdio, `session_id` in scope from :1722,
constant `"stdio-session"` at :1579 — a key nothing ever writes under, so the
stdio read returns nothing and the caller is refused).

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
- stdio writes nothing. The store is written at the HTTP `initialize` call
  site only, so a stdio caller has no entry and the conjunction in amendment 1
  refuses it. An earlier revision had stdio capture under a `"stdio-session"`
  constant, on the rationale that one write site should cover every bridgeable
  transport; that rationale died when stdio left the bridgeable set, and a
  stored-but-unread declaration is a claim about permission that nothing
  checks.
- a write in `MetaMcp::handle_initialize`, and a read at each `CallerContext`
  construction site. Seven, enumerated from source and split by role: two
  production writes carrying a real declaration (`handlers.rs:705,1164`), and
  five passing `Declared::NONE` today (`invoke.rs:3816,3846,3881` — tests —
  and `server/mod.rs:1827,2619` — stdio). An earlier revision of this document
  said "five" while listing seven; the count was wrong, the list was right.
  The read is the *same* read at all seven, which is what makes it safe to add
  at the stdio sites: the store is written only at the HTTP `initialize` call
  site, so a stdio read finds no declaration and the conjunction in amendment 1
  refuses. Nothing at `server/mod.rs:1827,2619` needs a transport check, and
  the deadlock the descope exists to prevent stays unreachable.
- `shape` threaded to each of those sites, and production implementations of
  the bridge's three traits, which today exist only as test fakes.
- **one dispatch path, not two.** `record_invocation`
  (`invoke.rs:1246`), `record_error_budget` (:1369) and `record_spend` (:1394)
  each fire exactly once, around the single `dispatch_to_backend` at :1327. A
  bridged retry invokes the backend a *second* time, after all three — so
  without this, a paid backend is called twice and billed once, and a
  configured budget is exceeded with no record. Factor the backend attempt and
  its accounting into one helper that the initial invocation and every bridge
  retry both go through. Stated as elimination rather than patch: adding a
  second accounting call would leave "a dispatch path that is not accounted
  for" still describable; one path leaves it undescribable.
- `CallerContext::input_capabilities` currently documents itself as "what this
  caller declared on **this** request". That contract changes to the merged
  value; the comment changes with it.

### Decision table

Because the merge is conditional on shape, the two shapes do not read the same
value, and a row is only decidable once its source is named. The middle column
names it.

| shape | where `declared` is read | outcome |
|---|---|---|
| modern | this request's `_meta` — declared there | continuation minted, as today |
| modern | this request's `_meta` — absent there, and the session value is **not** merged in | refused by MRTR.9, as today |
| legacy | the session's `initialize` declaration — declared there | bridged |
| legacy | the session's `initialize` declaration — absent there | refused by MRTR.9, as today |

Row 2 is the one an unconditional merge would flip: a modern client that
declared at `initialize` and omitted `_meta` would start being asked, which is
the per-request gate MRTR.9 exists to enforce. It stays refused.

## Round-3 amendments — three defects the wiring would activate

The confirmation pass (`gpt-review`, `b645491e`, SHIP-WITH-FIXES) found three
things that are not bridge-internal and not out of scope: each one is created,
or first made reachable, by this change. All three verified at source before
being accepted. Each is eliminated rather than patched — after the amendment the
finding can no longer be stated.

**1. The bridge gate is a conjunction, and that is what makes it transport-safe.**
The reviewer read the design as "legacy shape -> bridge" and objected that every
stdio request is legacy-shaped, so the HTTP-only scope would not survive contact
with stdio. Correct about the shape, and the design did not say the second half
out loud. The gate is `Legacy` shape **and** a declaration present for this
session in the HTTP session store. Stdio never writes that store — the store is
owned by the streaming session manager and stdio has no session in it — so a
stdio request finds no declaration and takes the existing fail-closed refusal.
No transport enum, no `is_http` flag: the scope boundary is the store's
membership, which already had to be checked. Row 3 of the decision table is this
case and it stays refused.

**2. Post-dispatch verdicts are computed from the final result, not the first.**
`invoke.rs:1475` reads `stopped_to_ask` once, from the first dispatch result,
and two later gates depend on it: the idempotency settle at `:1499` and the
response gate at `:1769`. A bridge retry that succeeds leaves that verdict
saying the backend stopped to ask when it has since acted — the key is never
settled and the response is judged on a stale verdict. Confirmed at source.
The dispatch helper named in the change surface therefore returns the *settled*
result, and `interim` and `stopped_to_ask` are derived after it returns. One
result value in scope means a stale verdict has nowhere to live. The two uses
of "did it stop to ask" are distinct and neither name is reused:

```
let first = dispatch(...);                       // one attempt
let asked = InputRequired::claims_input_required(&first);   // authorizes bridging only
let result = if asked && bridgeable { bridge_and_retry(first) } else { first };
let stopped_to_ask = InputRequired::claims_input_required(&result);  // settles + gates
```

**3. The declaration store is owned by the session manager, not by `ClientSession`.**
Open question 3 answered "declarations live in `ClientSession`". `ClientSession`
is private to `src/gateway/streaming.rs:47` and constructed only there
(`:188`, `:202`), and that file never sees an `initialize` message — it builds
sessions from transport state. `MetaMcp::handle_initialize`
(`src/gateway/meta_mcp/mod.rs:1151`) is the only place the declaration exists,
and it already carries `session_id: Option<&str>`. So the writer and the owner
are real but in different modules, and the earlier answer would not have
compiled. Amended: the store is keyed by session id and owned by
`NotificationMultiplexer` (`src/gateway/streaming.rs:73`), which owns the
session map and is the only session-keyed store in this path with production
removal — `handlers.rs:354` on DELETE and `streaming.rs:578` on stream end. The
declaration is captured at the `initialize` call site in
`src/gateway/router/handlers.rs:926`, which holds both the params and
`state.multiplexer`; `handle_initialize` itself does not need to change.
`ClientSession` stays private.

Two stores were rejected on the same test, applied to each in turn — does
anything outside a test remove from it. `SessionProfileStore`
(`src/routing_profile/mod.rs:430`) is already owned by `MetaMcp` and keyed by
session id, so it looked like the obvious home; its `remove_session` has no
non-test caller, so it would have leaked exactly as `SessionLifecycle` would.
The stdio `initialize` path (`src/gateway/server/mod.rs:1788`) has no
multiplexer to write to, which is amendment 1's conjunction holding by
construction rather than by a transport check.

Not amended, still out of scope: the aggregate deadline not bounding backend
retries, prompt parameters forwarded without typed validation, and reply
projection ignoring request kind. All three are inside `input_bridge.rs`, none
is created by the call site, and MIK-7388 is where bridge-internal defects go.
MIK-7388 blocking MIK-7212 is what keeps them from shipping live.

## Round 4 review, disposed

Fourth pass, GPT on the amended design plus the test plan. Verdict
SHIP-WITH-FIXES. Three HIGH findings were the same defect: the amendments were
appended and the passages they overturned were left standing, so the document
stated both readings. Each is now eliminated rather than annotated — the
superseded sentence is gone, not footnoted.

| finding | disposal |
|---|---|
| stdio still captures a declaration while the amendment says it never writes (HIGH, CERTAIN) | confirmed in the text. The capture is deleted: the store is written at the HTTP `initialize` site only. Its rationale — one write site for every bridgeable transport — died when stdio left that set |
| the earlier resolution still assigns the store to `ClientSession` (HIGH, CERTAIN) | confirmed in the text, in the disposal table and in the open-question-3 answer. Both now name the `NotificationMultiplexer` session map and record `ClientSession` as the superseded answer |
| scope excludes live SSE delivery that the HTTP bridge requires (HIGH, CERTAIN) | confirmed in the text. The paragraph opened "Also out" and then argued the opposite; it now opens "IN, not out". Delivery is inside FOR and `MIK-7212.WIRE.8` is its evidence |
| no non-ignored case proves an initialized stdio caller stays refused (HIGH, LIKELY) | accepted. Added as `MIK-7212.WIRE.10`, deliberately not `#[ignore]`d: the refusal is stdio's behaviour until MIK-7387 lands |
| WIRE.5 checks one generic accounting record (HIGH, POSSIBLE) | accepted. The row now asserts the backend-call count and each sink — invocation metrics, error budget, cost tracker, spend — carries three |
| WIRE.9 does not test the cache gate (MEDIUM, CERTAIN) | accepted. The row now asserts the settled result is cached and a follow-up call is served without a further invocation |
| pseudocode for interim vs settled verdict (improvement) | accepted. Four lines under amendment 2 |
| make MIK-7388 a merge-before-wiring prerequisite, defects in one place (improvement) | already closed by the revision under review's successor: one list, one ticket, four schedule fields, `when` = merges before this wiring |
| stage both a permitted and a forbidden request in WIRE.4 (improvement) | accepted, row rewritten |
| map each of the 21 existing rows to its test name (improvement) | accepted, scheduled: done before implementation handoff, so an omission is mechanically visible rather than inferred from a count |

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
   When: at the counter design, which is `RELEASE-4.0.0-cluster-a-readiness.md`
   work, not this change's. If it resolves badly — no counter is ever named —
   the no-op observer ships permanently and the release row stays unmet on
   observability grounds alone, which is a reporting outcome, not a bridge one.

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

   So "bind eviction to the existing session lifecycle" — which both reviewers
   recommended and which an earlier revision of this design accepted — would
   have written a comment claiming eviction while shipping the leak they
   flagged. Verified on the write side, which is where an absent caller is
   visible: no non-test `register` call, no production `remove_session` call.

   **The declarations therefore live in the `NotificationMultiplexer` session
   map** (`src/gateway/streaming.rs:75`) — the only session-keyed store with a
   production removal path, on `DELETE` (`router/handlers.rs:354`) and at
   stream end (`streaming.rs:578`). This answer first named `ClientSession`
   itself; amendment 3 records why that owner cannot hold it — the struct is
   private, is built only at `streaming.rs:188,202`, and never sees
   `initialize`. Eviction is then not a mechanism this change adds; it is an
   entry removed by the path that already removes the session. Nothing hangs off the
   dead hook, so wiring `SessionLifecycle` is **not** a prerequisite of this
   change. Its absence stays recorded here because it is the reason the obvious
   answer was the wrong one, and because the firewall's anomaly tracker
   (`src/security/firewall/anomaly.rs:129`) is still waiting on that same
   callback — a leak this change neither causes nor fixes.

4. Should a prompt no human answers still retry the backend without that
   answer? — **deferred, and it is an ASK, not a check.** Requirement row 320
   says yes in terms ("abandoned at `min(remaining, 30s)`, and the rounds still
   remaining are unaffected"), and the frozen acceptance row pins it. GPT-5
   raised the same behaviour as a HIGH defect on the ground that a backend may
   then continue without input a person was required to give. Both readings are
   coherent; only the requester can choose. Owner: the release owner, with this
   design. What resolves it: the requester answering, in one line, whether an
   abandoned prompt ends the round (today) or the call (the reviewer's reading).
   When: before MIK-7388 is worked, since its `:433` item exists only under the
   second reading. If it resolves toward the reviewer: row 320 and its
   acceptance test change first, this wiring is unaffected, and `:433` returns
   to the ticket as a requirements change rather than a bug fix.

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
