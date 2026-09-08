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

Round 5 (2026-09-06) is reviewed by the pair the release board binds instead:
`grok-review` and `kimi-review`. Reviewer identity verified rather than assumed —
`~/.claude/bin/kimi-review` is a 1.1K transition shim that `exec`s
`synthetic-review --model "${KIMI_REVIEW_MODEL:-kimi-k3}"`. Same wrapper binary
as the round-2/3 open-weights leg, DIFFERENT model: that leg ran `glm-5.3`, this
one runs `kimi-k3`. The pair is therefore two distinct models, not one wrapper
counted twice. `gpt-review` is unavailable for this round (Codex usage-limited
until 2026-09-12; its ledger rows read `process_status=error, exit_code=1` since
2026-09-06T05:41Z) — an availability gap, recorded as such and never as a pass.

Round 6 (2026-09-08) is the closure re-check, per the repair protocol's rule that
a finding returns to the vendor that raised it. The open-weights leg (`kimi-k3`)
returned SHIP-WITH-FIXES and confirmed all four round-5 dispositions as RIGHT,
including the source-refutation of the `SessionProfileStore` finding. Its single
residual fix — that commit `8efa02c8` did not disclose edits it made to `WIRE.12`
and `WIRE.13` — is FALSIFIED AT SOURCE and closed without a repair: that commit
is `1 file changed, 1 insertion(+), 1 deletion(-)`, and the changed line is the
`WIRE.11` row. `WIRE.12` and `WIRE.13` appear in the submitted diff as context,
not as edits.
`gpt-review`'s finding against `WIRE.5` versus the recorded gate-once policy was
escalated by this round and is now RULED: `R8` takes per-round gating and
refuses the narrowing. BOTH halves land, and both cost edits: the policy below
is amended to per-round gating, the criterion stands unnarrowed, and `WIRE.5`
and `WIRE.13` were each repaired in
`docs/design/2026-09-05-mrtr7-test-plan.md` — the first to parameterize the
refusal position and state its staging conditions, the second to drop an
approval inference its spend count cannot support. It is named in full further
down, where the escalation was stated.

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

IN, added 2026-09-08 and stated here so the move costs a visible edit: the
governance gate is called before **every** bridged dispatch, not only the first.
Ruled at R8; what it deletes and what it leaves standing is the Policy section
below.

IN, not out: live delivery of the question over the client's own stream.
Release row 308 defers its own evidence with this commit as the trigger, which
defers *that row's evidence* and is **not** permission for this change to skip
delivery. A
legacy HTTP client that cannot actually receive the bridge's question has not
been bridged, so delivery over the live stream is inside FOR and
`MIK-7212.WIRE.8` is the row that finds out whether it works; the `NFR.OBS.4` counter name
(`RELEASE-4.0.0-cluster-a-readiness.md:44` — "No design, no counters"); any
change to the MRTR.9 refusal or to the continuation mint for modern callers; and
the reply projection that reads any result containing `action` as an elicitation
reply (`input_bridge.rs:454`) — that file's own bug rather than this change's
wiring, filed as **MIK-7388**.

### The other MIK-7388 defect is this change's, and BRIDGE.2 is satisfied here

MIK-7388's second defect — "a pending entry stranded when the outer timeout
cancels registration (`:430`)" — was filed against `input_bridge.rs` and is not
there. That file holds no pending state, as the findings table below already
records, so the OUT item points at a repair with nothing to repair. The
obligation it describes lands on whoever *implements* `ClientChannel`, and the
trait's own cancellation contract (`src/gateway/input_bridge.rs:268-287`) names
the owner verbatim: "The requirement is recorded as MIK-7388; the first
implementation obliged by it, and the test that proves it, arrive with
MIK-7212." This change writes that implementation, so this change carries the
obligation. Concretely: the production `ClientChannel` impl holds a
`PendingRequestGuard`-shaped RAII across the awaited send (the shape at
`src/transport/stdio.rs:517`), and `MIK-7212.WIRE.11` in the test plan pins it,
mirroring `cancelled_request_does_not_strand_pending_entry`
(`src/transport/stdio.rs:815`).

So the re-bound `MIK-7388.BRIDGE.2` — "Given the production `ClientChannel`
implementation that registers pending state keyed by request id" — is
**satisfied by this change**, not handed a surface and left open.

This is not a §P0 scope move. FOR is unchanged: one production caller for
`InputBridge::run` on the HTTP transports. OUT is unchanged: a repair to
`input_bridge.rs`'s own code at `:430` stays out, because there is nothing there
to repair. Cancellation safety in code this change *writes* is not the repair of
an existing defect; it is a correctness property of new code, mandated by the
trait it implements. The only edit the reading forces is the one above — the OUT
list previously described `:430` as a defect inside `input_bridge.rs` while the
findings table recorded that it is not, and those two lines disagreed.

Two further findings were carried here as defects and **died at the
requirements**, which is why the count fell from four. **One of the two has since
come back.** A timed-out prompt retrying the backend without an answer (`:433`)
was what requirement row 320 specified — "abandoned at `min(remaining, 30s)`, and
the rounds still remaining are unaffected" — and its acceptance test pinned
`frames == 2, calls == 2` to prove the call does **not** end. On 2026-09-08 the
release owner ruled the other way: an unanswered prompt fails the call, naming
the entry. The requirement moves and the finding stands. GPT was right about the
behaviour and wrong only about where the defect lived, which was in the row
rather than in the code — scheduled question 4 records the ruling and what it
costs. Deserializing prompt params into a typed `ServerRequest` (`:409`) is what
row 308 forbids: params must reach the client whole, "nothing dropped and nothing
invented", and a round-trip through a typed struct drops what the struct does not
name. That one is still dead.

The reviewer's underlying worry — a backend continuing without input a person
never gave — was real, was raised here as the requester's call rather than
repaired, and has now been answered in the reviewer's favour.

**The merge-before-wiring wait is DELETED.** An earlier revision made this
change wait for MIK-7388 to land first, on the ground that wiring is what makes
its defects reachable. Grok raised it in round 6 and it is confirmed: by the
time that sentence was written, every defect the wait was built on had already
been accounted for somewhere else in this document, and the wait had nothing
left to wait for.

| the defect the wait named | where it went |
|---|---|
| `:430`, cancellation safety in the awaited send | RE-BOUND to this change six paragraphs above. It is a correctness property of code this change WRITES, mandated by the trait it implements — not a repair of an existing defect, and the OUT list now says so |
| `:433`, a timed-out prompt retrying the backend without an answer | DIED AT THE REQUIREMENTS, THEN RESURRECTED BY THE RULING of 2026-09-08. Row 320 did specify that behaviour and its test did pin it; the release owner has since ruled the other way, so the row and the test move and the finding stands. Scheduled question 4 |
| `:454`, a reply projection that is not kind-aware | ALREADY IN THE TREE, fixed in `60a28464` and checked off as `MIK-7388.BRIDGE.5`. `project()` takes `kind` and branches on it (`input_bridge.rs:476-495`): everything but `Elicitation` returns the result whole, and the doc comment states the reason — reading an `action` member on a roots or sampling reply would drop the rest of the answer |

A blocking edge whose three grounds are one re-binding, one requirement and one
shipped function is not a schedule; it is a sentence nobody re-read after the
document around it moved. Deleting it is the repair. The ASK it left behind — whether row 320's
"abandoned at `min(remaining, 30s)`, rounds unaffected" is the behaviour the
requester wants, given that it lets a backend continue without input a person
never gave — has since been answered, and the answer is no. Scheduled question 4.

The ticket was read too, not only the tree, because a wait is drawn against a
ticket. MIK-7388 today carries one retired identifier, one met, and three live:
`BRIDGE.1` was RETIRED with the withdrawn `:433` defect, `BRIDGE.5` is CHECKED
and shipped in `60a28464` (the kind-aware projection), and `BRIDGE.2` — the
`:430` cancellation entry — is re-bound by the ticket itself, in its own words,
to “the change that creates the risk”, which is this one. What remains is
`BRIDGE.3`, that the MIK-7212 acceptance suite still passes whole, which this
change runs anyway, and `BRIDGE.4`, which IS the open question above. Not one
of the five is a thing this change could wait for someone else to do.

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
production write is the `MetaMcpCallerContext` construction in `router/handlers.rs`; the others
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

**Status, 2026-09-08 — half of the recommendation below has since shipped, and
the present tense above no longer separates the halves.** Option C is two
pieces: a shape discriminator on `CallerContext`, and the per-session store.
The discriminator LANDED, under the name `era`
(`src/gateway/meta_mcp/mod.rs:173`); its own doc comment forbids re-deriving the
era downstream, which is the drift this design argued for avoiding. The store
did NOT. `router/handlers.rs:835` still calls `shape.declared_capabilities()`
and passes that value straight into `input_capabilities` at `:1400`, so
production puts the per-request SLICE into the field rows 311 and 325 require to
hold the SESSION value. `handle_initialize` does write session-keyed state --
a negotiated-revision binding (`src/gateway/meta_mcp/mod.rs:1236`) and a routing
profile (`:1249`) -- but nothing about capabilities, so no declaration survives
the handshake. (`SessionProfileStore::remove_session`,
`src/routing_profile/mod.rs:462`, has no production caller either: the same
leak that disqualified `SessionLifecycle` for this job.) Consequence 1 --
a legacy client declares nothing, so the bridge can never fire for the only
client class it exists for — therefore still holds in the tree today.

The gate is where the two halves meet, and it is the edit this design implies
without ever saying so plainly: `era` does not change what the MRTR.9 gate
REFUSES, it changes what the gate is HANDED. A `Modern` caller declares per
request, so the slice is the whole truth about it. A `Legacy` caller declares
once at `initialize` and has no per-request channel at all, so the session store
is its only truth and the slice is silence, not denial — `Some(&[])` and `None`
are different claims, which is why `InputBridge::run` takes `declared` and
`slice` as two arguments rather than one merged value
(`src/gateway/input_bridge.rs:361-365`). The refusal PREDICATE is untouched in
both directions -- only the input to `undeclared()` moves -- but the two
directions are not symmetric in what that input may do, and flattening them is
the fail-open bug the section below warns about. For `Modern` the permitted set
must not move at all: a well-formed modern request whose `_meta`
`clientCapabilities` OMITS the asked capability is refused today and must stay
refused. The example is deliberately NOT *a modern caller that sent no
`_meta`*: a request declaring no protocol fields in body or header is
`RequestShape::Legacy` by construction (`src/protocol/meta.rs:85-89`,
`classify_request` `:150`), so that caller is already on the widening branch and
cannot illustrate the branch that must not move. For `Legacy` the
permitted set WIDENS, and that widening is the feature -- a legacy caller
refused today is bridged tomorrow, which is what consequence 1 above says the
bridge exists for.

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
gate is shape-blind — `interim.undeclared(caller.input_capabilities)` reads it with
no modern/legacy branch — so an unconditional merge would silently widen the
gate for modern callers too: one that declared `elicitation` at `initialize`
and sent a well-formed `_meta` whose `clientCapabilities` omits it is refused
today and would be minted a continuation after the change. That is a fail-open move on a security gate
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
| two of MIK-7388's four defects contradict frozen acceptance rows (implementer, HIGH) | confirmed at source. `:433` is what row 320 specifies and `:409` is what row 308 forbids; both findings die at the requirement, and the ticket narrowed to `:430` + `:454`. It has since narrowed again: `:454` was fixed in `60a28464` and checked off as `BRIDGE.5`, leaving `:430` alone. Whether row 320 is the behaviour the requester wants is open question 4, not a repair |
| store has no eviction or ownership (both vendors, HIGH) — **re-raised on the amended design** (GPT, HIGH) | confirmed twice. The first answer, `SessionLifecycle`, has no production caller at all; declarations live in the `NotificationMultiplexer` session map instead, the only session-keyed store whose removal runs in production. Superseded answer recorded at open question 3; the owner is fixed by amendment 3 |
| bridge retries invoke the backend outside cost accounting (GPT, HIGH, LIKELY) | confirmed at source: `invoke.rs:1246,1369,1394` each fire once around the single dispatch at :1327. In scope — this change creates the second invocation. One dispatch helper, change surface above |
| the merge widens MRTR.9 for modern callers while the table says it does not (synthetic, MEDIUM, CERTAIN) | confirmed at source: the gate `interim.undeclared(caller.input_capabilities)` is shape-blind. Merge scoped to `Legacy` only, option C above |
| construction-site census says five and lists seven (synthetic, LOW) | confirmed. Count was wrong, list was right; re-enumerated by role |
| timed-out client prompt discarded, backend retried without the answer (GPT, HIGH, LIKELY) | out of this scope — a defect inside `input_bridge.rs`, not fixed by a wiring change. **Filed as MIK-7388** with the pending-map growth, blocking MIK-7212. Both halves of that row are now superseded: the ticket WITHDREW this criterion (`BRIDGE.1`, retired) once row 320 was read at source, and round 6 deleted the blocking edge. Superseded once more on 2026-09-08: the ruling upholds the behaviour this finding asked for, so the withdrawal of `BRIDGE.1` rested on a row that has now moved |
| pending-response map grows if the outer timeout cancels after registration (GPT, HIGH) | out of this scope. **Filed as MIK-7388**, which blocks MIK-7212: neither defect is reachable until this wiring gives the bridge a caller. Recorded here as being in the same file as the row above, which it is not — `input_bridge.rs` holds no pending state, and `rg 'impl .*ClientChannel for' src/` returns nothing, so the map this names belongs to an implementor the UNWIRED decision means nobody has written. Re-bound on MIK-7388 to the production `ClientChannel` impl on 2026-09-05 — which is the impl THIS change writes, so `BRIDGE.2` is satisfied here and is not something to wait for |
| production-path HTTP test beyond trait fakes (GPT, MEDIUM) | accepted. The acceptance rows are fake-driven; one end-to-end HTTP test is the honest evidence and belongs in the test plan |
| compact legacy-or-modern discriminator instead of full `RequestShape` (GPT, both passes) | accepted. Recorded as the field's intended shape; `RequestShape` was shorthand, not a requirement |

### One capability value, two consumers

The gate `interim.undeclared(caller.input_capabilities)` reads it. So does the
bridge. Feeding that one field from the merged value — session store
authoritative, per-request slice narrowing — makes the gate consult the merged
set by construction, with no second consumer to keep in step. Stating it is the
fix; changing the gate would be the defect.

The merge happens where `CallerContext` is built, not where it is read:
the `MetaMcpCallerContext` construction in `router/handlers.rs` (HTTP, `session_id` in scope)
and the two in `server/mod.rs` (stdio, `session_id` in scope from :1722,
constant `"stdio-session"` at :1579 — a key nothing ever writes under, so the
stdio read returns nothing and the caller is refused).

**Absent is fail-closed.** No captured capabilities for a session — evicted,
pre-store, restarted — means the client declared nothing, and the question is
refused. The rejected option B is exactly what a fail-open default would
reintroduce through the back door.

**The store is not a store.** Declarations are co-owned by each transport's
existing session state. A declaration is removed from the map exactly once, on
session `DELETE` (`handlers.rs:354`), and replaced in place exactly once, on
`initialize`. There is no disconnect hook. There IS a reaper, and an
earlier revision of this paragraph denied it: `NotificationMultiplexer::spawn_reaper_on`
(`streaming.rs:105`) spawns a ticker whose `reap_expired_sessions` (:128)
`retain`s away every session that is past `session_ttl` AND has no active
receivers. Its doc comment records that `server.rs`, `webhooks.rs` and
`proxy.rs` all call it, so it runs in production.

A session id is client-supplied, and `get_or_create_session_for`
(`handlers.rs:300`) will CREATE a session under an id the client chose, so the
question "who may read this declaration" has exactly one honest answer: whoever
presents the session id.

An earlier revision of this paragraph invented a per-connection generation to
narrow that. It was removed rather than patched: on HTTP a client reattaches to
its session on a new connection without re-`initialize` (the SSE attach path at
`handlers.rs:290-300` is exactly that), so a per-connection generation either
fail-closes legitimate reattached traffic — the feature dead on the one
transport this design ships to — or is per-session, which is the rule below
under a longer name.

The rule, stated once: **a declaration is session-scoped.** Reattaching to a
session inherits its declaration, because that is what reattaching means. The
protection is the session id's secrecy, and it is exactly the protection every
other piece of session state in the gateway already has — this change adds no
new exposure and inherits the existing one. That inheritance is stated below
alongside the session lifetime, and it is not deferred: it is a property this
change reads off the gateway it is being wired into.

### Change surface, stated

Wiring one call is the smallest part of this.

- `Declared::parse` already takes a plain
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
- a write at the HTTP `initialize` dispatch arm in `router/handlers.rs` (the
  `"initialize" => state.meta_mcp.handle_initialize(` match arm), and a read at
  each `MetaMcpCallerContext` construction site.

  **The count is a budget, and the one this document carried was wrong.** It
  said seven and listed seven. Enumerated from source with
  `rg -n 'MetaMcpCallerContext\s*\{' src/`, the production sites are **three** —
  one in `router/handlers.rs` (the only one carrying a real declaration, fed by
  `RequestShape::declared_capabilities()`) and two in `server/mod.rs` (stdio,
  both passing `Declared::NONE`). The remainder are test-module sites: three in
  `meta_mcp/invoke.rs` past its `#[cfg(test)]`, and the rest across
  `router/tests.rs`, `meta_mcp/tests.rs`, `meta_mcp/trace_correlation_tests.rs`,
  `server/mod.rs`'s test module and `authz_tests.rs`. The two the old list named
  in `handlers.rs` besides the real one construct nothing.

  This matters because a new field on the struct touches every literal, test
  sites included: `rg -n 'input_capabilities:' src/` returned **twenty** at `5b0bdb82`, not seven.
  Sizing the change from "seven sites" underestimates it threefold.
  **Re-enumerate with those two greps at implementation HEAD** — the split that
  matters is production versus test, and both greps give it directly.

  The read is the *same* read at every production site, which is what makes it
  safe to add at the stdio ones: the store is written only at the HTTP
  `initialize` call site, so a stdio read finds no declaration and the
  conjunction in amendment 1 refuses. Neither `server/mod.rs` site needs a
  transport check, and the deadlock the descope exists to prevent stays
  unreachable.
- `shape` threaded to each of those sites, and production implementations of
  the bridge's three traits, which today exist only as test fakes.
- **one dispatch path, not two.** The budget gate and the accounting emissions
  around the single `dispatch_to_backend` are enumerated once, in the section 4
  table — this bullet deliberately does not restate them, because the earlier
  three-item copy here had already drifted from what the table lists, with stale
  line numbers. A bridged retry invokes the backend a *second* time, after all of
  them, so without this a paid backend is called twice and billed once and a
  configured budget is exceeded with no record. Factor the backend attempt and
  its accounting into one helper that the initial invocation and every bridge
  retry both go through. Elimination rather than patch: a second accounting
  call would leave "a dispatch path that is not accounted for" still
  describable; one path leaves it undescribable.
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
compiled. Amended: the declaration is a **field on `ClientSession`**, reached through
getter and setter methods on `NotificationMultiplexer`
(`src/gateway/streaming.rs:73`). The session map's value type is already
`Arc<ClientSession>` (`:75`), so a field cannot drift from the session the way
a second keyed map can, and it cannot outlive it: the declaration is dropped
with the session, by construction rather than by a removal call anyone has to
remember. `get_or_create_session` returns the existing session, so a stream
reconnect keeps the declaration instead of silently losing the client's
capabilities.

The sole production REMOVAL is `handlers.rs:354` on DELETE; `initialize`
replaces in place and removes nothing, which is why the two counts in this
document are one rule and not a contradiction. An earlier revision
of this paragraph also cited `streaming.rs:578` as a stream-end removal. It is
a line inside a test — the same defect that disqualified `SessionLifecycle`
four paragraphs down, made while writing the sentence that disqualified it.
A third removal exists that no `rg remove_session` can see, because it does not
call it: the reaper `retain`s. Grok raised it (round 6, MEDIUM, CERTAIN) and it
is confirmed at source — `streaming.rs:75` is the map the reaper walks and the
map that holds `ClientSession`, so the same eviction that ends a streaming
session ends its declaration.

This CLOSES the unknown rather than deferring it. It was parked first as a
"named residual", then as a DEFERRED unknown with four fields; both were wrong,
and wrong in the expensive direction — a deferral schedules work for a question
already answered in the tree.

```
resolved (checkable): does anything reclaim a session that is never DELETEd?
  — rg -n 'spawn_reaper_on|reap_expired_sessions' src/ then read streaming.rs:105-152
  — a production ticker retains away sessions past session_ttl with zero receivers,
    and it walks the same `sessions` map (:75) whose value type is Arc<ClientSession>
  — the four-field deferred table is deleted; a declaration's lifetime is DELETE,
    or the reaper, and the memory bound the deferral was going to measure is
    already enforced by session_ttl
```

The read-access property is NOT part of that answer and is not deferred either:
a declaration is readable by whoever presents the session id, exactly like every
other piece of session state in this gateway. That is inherited, not introduced,
and if it is judged unacceptable the fix is server-minted unguessable session
ids, which belong to the session store and not to this change.



Two stores were rejected on the same test, applied to each in turn — does
anything outside a test remove from it. `SessionProfileStore`
(`src/routing_profile/mod.rs:430`) is already owned by `MetaMcp` and keyed by
session id, so it looked like the obvious home; its `remove_session` has no
non-test caller, so it would have leaked exactly as `SessionLifecycle` would.
The stdio `initialize` path (`src/gateway/server/mod.rs:1788`) has no
multiplexer to write to, which is amendment 1's conjunction holding by
construction rather than by a transport check.

Not amended, still out of scope: the aggregate deadline not bounding backend
retries, and prompt parameters forwarded without typed validation. Both are
inside `input_bridge.rs`, neither is created by the call site, and MIK-7388 is
where bridge-internal defects go. The third item this sentence used to list —
reply projection ignoring request kind — left the list by being FIXED
(`60a28464`, `MIK-7388.BRIDGE.5`), not by being scoped out.

What keeps the remaining two from shipping live is the UNWIRED row, which is
what this change replaces, so the honest statement of the risk is that this
wiring makes them reachable and neither is a blocker: one is bounded by the
per-call deadline the bridge already carries, the other by the firewall the
call site puts in front of it. An earlier revision said instead that MIK-7388
blocking MIK-7212 held them back. That edge is deleted — see the round 6
disposal below.

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
| make MIK-7388 a merge-before-wiring prerequisite, defects in one place (improvement) | accepted then, REVERSED in round 6. It was closed by giving the deferral four schedule fields with `when` = merges before this wiring; grok showed that edge had nothing left to hold, and it is now deleted. The half that survives is the one this finding actually wanted: bridge-internal defects live on one ticket |
| stage both a permitted and a forbidden request in WIRE.4 (improvement) | accepted, row rewritten |
| map each of the 21 existing rows to its test name (improvement) | accepted, scheduled: done before implementation handoff, so an omission is mechanically visible rather than inferred from a count |

## Unknowns, scheduled

1. Does the gateway see `initialize` on every transport that can be bridged
   (stdio, SSE, streamable HTTP), or only some? — read the two production
   dispatch sites — RESOLVED: both reach one shared handler,
   `MetaMcp::handle_initialize` (`src/gateway/meta_mcp/mod.rs:1151`), from
   `src/gateway/server/mod.rs:1788` (stdio serve loop) and
   `router/handlers.rs`'s `"initialize"` dispatch arm (HTTP router). It already receives both
   values a per-session store needs: the `initialize` `params`, which carry the
   client's `capabilities` object, and a `session_id` that both call sites pass
   as `Some(..)`, never `None`. That answer is superseded by amendment 3: the store
   is written at the HTTP call site (the `"initialize"` dispatch arm in `router/handlers.rs`) only. One write
   site covering every bridgeable transport was the right shape while stdio was
   bridgeable; it left that set, and a declaration nothing reads is a claim
   about permission nobody checks.
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
   production removal path, on `DELETE` (`router/handlers.rs:354`) and in
   the session reaper (`streaming.rs:128`). An earlier revision of this answer
   cited `streaming.rs:578` as a stream-end removal; that line is inside a
   test, and the real second path is the reaper, which removes by `retain`
   rather than by calling `remove_session`. This answer first named `ClientSession`
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
   answer? — **RESOLVED by the release owner on 2026-09-08.** This was an ASK,
   not a check, and it stayed deferred here until the requester answered.

   Asked of: the release owner, directly, relayed through the team lead. The
   ruling confirms the criteria-row ruling of 2026-09-07 and is recorded as
   `BRIDGE.4` in `docs/release/2026-09-08-team-lead-rulings.md`.

   The answer: **the call fails, naming the unanswered entry.** Two
   alternatives were put and both rejected — re-invoking the backend with what
   arrived, and re-invoking it plus a wire field marking the gap.

   What it changed, and it is not small. Requirement row 320's "abandoned at
   `min(remaining, 30s)`, and the rounds still remaining are unaffected" is the
   losing reading, so the row and the single test asserting it move, not the
   ruling. That test is `tests/mik_7212_mrtr7_bridge_acs.rs:1117`
   `ac_mrtr_7b_an_unanswered_prompt_ends_its_round_not_the_call`: it stages
   `Reply::Silent` at `:1124` and asserts `outcome.is_ok()` at `:1148`, and it
   inverts. Its two elapsed assertions at `:1152-1163` survive unchanged —
   they pin that the wait ended at `per_prompt` rather than sooner or at a
   multiple of it, which stays true once the call then fails. No other test
   asserts the drop: `:1194` scripts twelve answered replies and expects
   `BridgeError::Deadline`, and `:1254` answers every prompt. Read that as a
   claim about ASSERTIONS, never as the blast radius: `:1194` reaches the
   edited line anyway, through the aggregate clamp sharing that same wait, and
   what keeps it green is the design event below — *the timeout arm has two
   causes and reports only one*.

   In the bridge the ruling costs one branch and no new type.
   `src/gateway/input_bridge.rs:486` is a bare `continue` in the `else` arm of
   the per-prompt `tokio::time::timeout` at `:484`; it becomes a
   `return Err(BridgeError::Delivery { key: prompt.key, error: DeliveryError::TimedOut })`.
   A new `BridgeError::Unanswered { key }` would duplicate what `:199` and
   `:185` already declare, and the enum's own doc at `:150-156` says those
   variants exist precisely so that "a client that never answered" stays a
   distinct fact rather than collapsing into one "failed". The asymmetry the
   ruling removes is visible across two adjacent arms of the same loop: the
   projection failure at `:490` already constructs `BridgeError::Delivery`,
   while the timeout arm dropped its entry in silence. `DeliveryError::TimedOut`
   has in fact never been constructed in this module — its one production
   construction is `src/gateway/proxy.rs:558`, whose comment a line above says
   the variant means "the bridge's own timeout arm". The repair is that
   variant's first use at the site it was written for.

   MIK-7388's clause claiming this requirement "is refuted at source and has
   been withdrawn" inverts the authority — a test is not the spec when an
   operator ruling says otherwise — and no longer stands. The team lead has
   posted the correction to the ticket.

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

## Closure re-check, disposed

The finder re-checked its own round-4 findings against the repaired text and
re-raised three. All three were verified at source before being touched; none
was taken on the reviewer's word.

| finding | disposal |
|---|---|
| the write site is still named twice, HTTP-only in one place and `MetaMcp::handle_initialize` in another (HIGH, CERTAIN) | confirmed. The round-4 repair fixed the stdio paragraph and left two passages carrying the old instruction — the change-surface bullet and the answer recorded against the first scheduled question. Both now name the `"initialize"` dispatch arm in `router/handlers.rs`, and the recorded answer says which amendment superseded it rather than being quietly rewritten |
| the store's owner is not concrete, and the cited stream-end removal does not exist (HIGH, LIKELY) | confirmed, and the citation was worse than the finding said. `streaming.rs:578` is a line inside a test; the only production removal is `handlers.rs:354` on DELETE (I: `rg -n 'remove_session' src/` returns those two and nothing else — one grep is one source, however carefully it was run). Eliminated rather than patched: the declaration becomes a field on `ClientSession`, which the map already holds as its value type, so it cannot drift from or outlive the session and no second keyed map needs removal wiring. The follow-on claim that no reaper exists was itself false, and round 6 killed it: `spawn_reaper_on` runs in production over the same map, so the unknown is RESOLVED rather than deferred |
| `WIRE.9`'s follow-up call is answered by the settled idempotency entry, so the cache gate never runs (MEDIUM, CERTAIN) | confirmed by reading the row: it reused the key it had just asserted settled, which is exactly the shape `test-plan-honesty` calls a case that cannot fail. The follow-up now carries a different idempotency key and the same response-cache key, and settlement is asserted separately |

Two improvements taken, both in the test plan: `WIRE.10` sat outside the
acceptance table as a detached row and is now inside it, and rows 312, 323 and
324 are mapped to their three stdio test names, with the stale sentence saying
the mapping was still scheduled removed — it had landed one commit earlier.

One improvement declined with its reason: splitting the normative plan from the
review-disposal history (MEDIUM). The history is what stops a superseded
decision being re-proposed, and this document has now had the same passage
re-raised twice; moving it to a second file is how it stops being read.

## Design event — the retry interface cannot carry a governance refusal

Named here per the development process: a decision the design did not make,
surfaced while the test plan was under review, changing an observable contract.

`BackendInvoker::invoke` yields a bare `Value` (`src/gateway/input_bridge.rs:299-302`),
and `InputBridge::run` returns that value to the caller unchanged once it is not
another interim (`src/gateway/input_bridge.rs:366-369`). The production path it will
wrap does not speak in values alone: the cost-governance check refuses a call with
`Err(Error::json_rpc(-32003, …))` before dispatch (`src/gateway/meta_mcp/invoke.rs:1290-1297`),
and every other pre-dispatch gate on that path refuses the same way.

An adapter bridging the two can therefore only flatten a refusal into
success-shaped data. The first attempt's refusal reaches the caller intact,
because it happens before the bridge is entered; the *retry's* refusal does not.
An operator's spend limit would be enforced on attempt one and silently discarded
on attempt two, which is the failure the limit exists to prevent.

**Decision**: `BackendInvoker::invoke` yields `Result<Value, Error>`, and
`BridgeError` gains a variant carrying a backend error so `InputBridge::run`
propagates it to `invoke_tool` rather than fabricating a result. The alternative —
encoding the refusal as an error-shaped `Value` and re-parsing it — was rejected:
it invents a second spelling for an error the path already types, and every
consumer would have to agree on the spelling.

**Who decided**: recorded here rather than settled in an implementation commit,
because it changes a public trait signature and the observable outcome of a
budget-blocked retry.

**Found by**: the GPT leg of the test-plan review, held across three rounds against
a decline that cited the trait's own signature as evidence the channel existed. The
decline was wrong: the signature is what removes the channel. Verified at source
before this was written.

**Cost of the alternative history**: the plan would have shipped a WIRE.5 whose
budget assertion could never go green, and the defect would have been found in
implementation, against code written to the wrong contract.

---

## Round 5 amendments — 2026-09-06, measured at source

Five measurements taken against `fix/mrtr2-continuation-handle` before this
round's review. Three change what the design claims; two close unknowns it left
open. The reviewers for this round are the pair the release board binds
(`grok-review` + `kimi-review`), neither of which reviewed rounds 2-4.

### 1. The stdio block is TWO blocks, not one

`## Second blocker — stdio` (line 188) says the answer arrives on a stdin nobody
is reading. That is true, and it is the smaller half.

Measured: `src/gateway/server/mod.rs` line 1606 is
`while let Ok(Some(line)) = reader.next_line().await {`, and its body awaits
`Self::dispatch_batch_with_sink(...)` (line 1629) and
`Self::dispatch_single_with_sink(...)` (line 1646) INLINE. No `tokio::spawn`
occurs in that path — the spawn sites in the file are 223, 897, 1321, 1401,
2081, 2135 and 3250, none in the read loop. Line 1598 is the sole gateway
consumer of stdin; the tree's other stdin reads are CLI prompts
(`src/cli/invoke.rs` lines 102 and 104, `src/commands/setup.rs` lines 47 and
241).

Second block, independent of the first: `let mut stdout = stdout;` at line 1601
is exclusively `&mut`-borrowed by the in-loop `Self::write_response(&mut stdout,
…)`. So on stdio the bridge cannot WRITE THE QUESTION either, not merely fail to
read the answer.

Why this earns a paragraph rather than a footnote: it kills a repair that looks
obvious and fixes half the problem. "Just `tokio::spawn` the dispatch" frees the
reader and leaves the writer contended — the question still cannot go out. Any
stdio concurrency design must own the reader and the writer together, and that
design is out of scope here by the requester's 2026-09-05 ruling.

The design's stale citation (line 1581) is corrected to 1606; the line moved,
the loop did not.

### 2. "No production `ClientChannel`" is true of the TRAIT and false of the MACHINERY

`## Blocker — capability store missing` and the change-surface section (line 269)
count a production `ClientChannel` implementation among the things that must be
built. The trait half is correct and re-verified: `pub trait ClientChannel: Send
+ Sync` at `src/gateway/input_bridge.rs` line 268 has exactly one implementation
repo-wide, `impl ClientChannel for FakeClient` at
`tests/mik_7212_mrtr7_bridge_acs.rs` line 145. Zero production implementations.

What the design does not say is that the request-response machinery such an
implementation would wrap is already in production, on the HTTP path, with
callers:

| piece | location | state |
|---|---|---|
| mint id + register waiter | `src/gateway/proxy.rs` line 128 `register_pending` | production |
| resolve waiter from a reply | `src/gateway/proxy.rs` line 151 `resolve_pending` | production |
| send-and-await, sampling | `src/gateway/proxy.rs` line 206 `forward_sampling_with_response` | production, called at `router/handlers.rs` line 1275 |
| send-and-await, elicitation | `src/gateway/proxy.rs` line 271 `forward_elicitation_with_response` | production, called at `router/handlers.rs` line 1294 and `destructive_confirmation.rs` line 241 |
| reply ingress | `router/handlers.rs` lines 627-642 | production: no `method`, has `result` or `error`, `input_bridge::is_bridge_reply_id(resp_id)` at line 630, then `resolve_pending` at line 635 |

Both forwarders mint `sampling-{uuid}` / `elicitation-{uuid}`, hold a
`PendingSampleGuard` across the await, deliver via
`multiplexer.send_to_session(session_id, …)`, and wrap the receiver in
`tokio::time::timeout`, returning Ok / Cancelled / Timeout. The id prefixes
MATCH the bridge's: `ServerRequestKind::prefix()` (`input_bridge.rs` lines 69-75)
mints `sampling-`, `elicitation-`, `roots-`, and `is_bridge_reply_id` (line 144)
admits exactly those back.

So the HTTP `ClientChannel` is an ADAPTER over machinery that already exists, is
already called from production, and already uses the same id space — not new
plumbing. This SHRINKS the change surface; it does not delete the blocker, and
the change-surface section is amended to say which of the two it is rather than
leaving a reader to size it as new machinery.

**WHICH LAYER THE ADAPTER SITS ON, corrected.** An earlier revision of this
section wrapped the two `*_with_response` forwarders. Grok raised it in round 6
and it is confirmed at source: that adapter cannot satisfy the trait it
implements.

| `ClientChannel::send_request` is given | `forward_*_with_response` does |
|---|---|
| `id: &str`, minted by the bridge (`input_bridge.rs:69-75`) | mints its OWN `sampling-{uuid}` / `elicitation-{uuid}` (`proxy.rs:212`, `:279`) and never sees the bridge's |
| `params: Option<Value>`, the backend's object verbatim | takes `&SamplingCreateMessageParams` / `&ElicitationCreateParams` and re-serializes with `serde_json::to_value` (`proxy.rs:225`, `:292`) |
| `method: &str` | is one method per function |

`SamplingCreateMessageParams` (`protocol/messages.rs:525-543`) is six named
fields with NO `#[serde(flatten)]` catch-all, so the round trip through it is
LOSSY BY CONSTRUCTION: every field a backend declared and this gateway does not
model is silently gone by the time the client sees the question. That is exactly
what row 308 forbids, and no amount of adapter code can put back what the type
dropped. The minted-id half is as bad in a quieter way — the bridge hands the
adapter an id and the forwarder discards it, so the id the client answers is not
the id the bridge is waiting on, and WIRE.11 cannot assert on a value that never
reached the wire.

The repair is not a patch to the adapter. It is one layer down, over the pieces
the forwarders are themselves built from — the same three lines, in the same
file, already exercised by the tests at `proxy.rs:503-561`:

```
register_pending(the BRIDGE-minted id, session_id)   -> proxy.rs:128
PendingSampleGuard held across the await             -> proxy.rs:97
send_to_session(session_id, raw method + raw params) -> streaming.rs:254
tokio::time::timeout on the receiver
```

Raw `Value` in, bridge id out, one function for all three methods. The typed
forwarders keep their existing callers (`handlers.rs:1275`, `:1294`,
`destructive_confirmation.rs:241`) and the bridge does not go through them.

Restating what is still owed, so the shrink is not read as a pass: the trait
implementation over those four lines, and the timeout translation from the
receiver's outcome to `DeliveryError` (the bridge's `Timeout` and
`ClientRefused` must stay distinguishable for NFR.OBS.4).

### 3. The gap the shrink appeared to expose, and why it is gone

`proxy.rs` line 396 is `pub fn forward_roots_list(&self, session_id: &str) ->
bool` — fire-and-forget. No `register_pending`, no receiver, no timeout, not
`async`. There is no roots counterpart to the two `*_with_response` forwarders.

> **Resolved.** `forward_roots_list_with_response` is that counterpart, and the
> fire-and-forget `forward_roots_list` no longer exists — it was deleted rather
> than repaired, because it had no callers and minting an `id` on a forward that
> registers nothing would have shipped a frame that only LOOKS answerable. The
> paragraph below is the design-time reading, kept for the record.

The design does not mention this, because it treated the whole channel as
unbuilt. While this section still wrapped the typed forwarders, the missing
third forwarder read as the concrete piece of new code the wiring needs.

Is it reachable? Yes, and it is one grep: `InputBridge::prompt`
(`input_bridge.rs`) maps a backend request to a kind through
`ServerRequestKind::from_method(method)`, and line 52 maps `"roots/list"` to
`Self::Roots`. A backend that names `roots/list` in an `input_required` produces
a `Roots` prompt, which `ask` sends by
`self.channel.send_request(session_id, &id, prompt.kind.method(), prompt.params)`
with `params` of `None` (line 127). Nothing in `plan` or `prompt` excludes the
kind. The gap is therefore live, not theoretical.

The reachability stands; the gap does not. Correcting section 2 to adapt over
`register_pending` + `send_to_session` DELETED this item rather than repairing
it. There is no third forwarder to write, because the adapter uses no forwarder:
`roots/list` is the same call with a different method string and `None` params,
and the bridge already mints its `roots-` id and admits it back
(`is_bridge_reply_id`, `input_bridge.rs:144`). A sibling
`forward_roots_list_with_response` would have been a fourth typed function whose
only caller was about to stop existing.

That is worth recording rather than quietly dropping: this section was a real
finding against a wrong mechanism, and fixing the mechanism removed the finding.
Grok raised both halves in one round — the layer error and the roots sibling it
implies — and the second was the cheaper tell.

Rejected alternative, still recorded because it is still available: refuse
`roots/list` at the bridge and let it fall to MRTR.9. That narrows what the
bridge is FOR by removing a declared capability from the answerable set, which is
a requester decision, not an engineering one (repair protocol, step 0). Not
taken, and now unnecessary.

### 4. MRTR.7b's accounting blocker: one gate and eight emissions around one dispatch, read at source (I)

The 7b criterion names two blockers. The first is already recorded as a design
event at line 546 (`BackendInvoker::invoke` returns a bare `Value`, so a
budget-refused retry has no way to propagate a refusal). The second was named but
never measured. Measured now, in `src/gateway/meta_mcp/invoke.rs`:

| step | line | condition |
|---|---|---|
| `enforcer.check(tool, api_key_name)` | 1289 | BEFORE dispatch, `cost-governance`. REFUSES with `-32003` when the budget is exceeded; otherwise returns the warnings the epilogue injects |
| `stats.record_invocation(server, tool)` | 1263 | unconditional, BEFORE dispatch |
| `ranker.record_use(server, tool)` | 1266 | unconditional, before dispatch |
| `dispatch_to_backend(...).await` | 1344 | the single paid call |
| `counter!("mcp_tool_invocations_total")` | after 1357 | unconditional, after |
| `histogram!("mcp_tool_invocation_duration_seconds")` | after 1357 | unconditional, after |
| `stats.record_cached_tokens(...)` | in the `Ok` arm | on success with cached tokens |
| `self.record_error_budget(server, tool, BudgetOutcome::of(&dispatch_result))` | 1384 | unconditional, after |
| `self.cost_tracker.record(sid, api_key_name, server, tool, 0, …)` | after 1386 | on success |
| `enforcer.record_spend(tool, api_key_name, cost)` | 1409 | on success, `cost-governance` |

Eight accounting and telemetry emissions and ONE GATE, none of them factored
into a function, arranged as a straight-line prologue and epilogue around ONE
awaited `dispatch_to_backend`. There is no "invoke the backend once, accounted"
callable in this file — the accounting IS the surrounding statements.

The gate is listed first because an earlier revision of this section did not
list it at all. That revision counted EMISSION POINTS, and `enforcer.check` is
not an emission: it is the one statement on this path that can REFUSE. Grok
raised the omission in round 6 and it is confirmed at source — `invoke.rs:1289`
returns `Err(-32003)` before `dispatch_to_backend` is ever awaited, and the
bridge module contains no reference to an enforcer at all (`rg enforcer
src/gateway/input_bridge.rs` is empty). A retry loop wired over a path extracted
from a count of emissions would therefore make every bridged round after the
first UNMETERED: the operator's per-tool spend limit is checked once, on the
call that entered the bridge, and never again on the `rounds + 1` backend
invocations `InputBridge::run` can drive.

So the invariant below is stated over the whole boundary, not over a list: what
the extraction factors is EVERY STATEMENT BETWEEN THE GATE AND THE EPILOGUE,
including the gate. A count is the wrong shape for this requirement, and
counting is what lost the gate.

That is what makes the 7b blocker structural rather than a missing call. A
bridged retry has exactly two shapes available today and both are wrong:

- call `dispatch_to_backend` again from inside the bridge's `BackendInvoker`: a
  second paid backend call that is invisible to the gate and to all eight
  emissions. Billed once, invoked twice, unmetered on the second pass, and a
  per-tool daily budget can be exceeded with no record that it happened.
- add a second copy of the accounted block around the retry: two owners of the
  same counter, which the repair protocol's own table calls the patch (a check
  detecting the disagreement) rather than the elimination (one owner).

What the design REQUIRES is the invariant, not the mechanism: every backend
invocation the gateway makes — initial or bridged — passes through exactly one
accounted path, exactly once. An earlier revision named a single mechanism as
REQUIRED without recording what else was available, which is the Definition of
Ready bar failed on the one item this round calls structural. Four shapes, with
their dispositions:

| shape | disposition |
|---|---|
| the bridge calls `dispatch_to_backend` directly | REJECTED. A second paid call invisible to the gate and to all eight emissions: invoked twice, billed once, unmetered on the second pass, a per-tool budget exceedable with no record that it happened. |
| a second copy of the accounted block around the retry | REJECTED. Two owners of one counter and two owners of one spend limit — the repair protocol's own table calls that the patch, not the elimination. |
| extract the accounted block; the bridge's `BackendInvoker` runs over the extraction | VIABLE. Costs a cross-cutting change to a path every invocation in the gateway uses. |
| the bridge RETURNS its answers and the invoke path re-enters its own prologue-dispatch-epilogue in a loop | VIABLE ON ACCOUNTING — every pass is accounted by code that already exists — but it fails on criteria; see below. |

The loop shape's cost is not accounting, it is MRTR.7a. `InputBridge::run` owns
the round count, the aggregate deadline and the request budget. Moving the loop
into the invoke path either bypasses `run` — and 7a's criterion is precisely
that `run` is reached from production, so bypassing it fails the criterion this
change exists to satisfy — or it duplicates the bounds, which is two owners of
one budget: the same defect class as two owners of one counter, one layer up.

That is a REASON, not a preference, and it is recorded so implementation
inherits the reasoning rather than the conclusion. If the requester would
rather relax 7a's wording than pay for the cross-cutting extraction, that is a
criteria decision and belongs beside the section 5 question, not inside an
implementation commit. On the criteria as they stand, the extraction is the
shape that survives: the gate and the eight emissions factored around the single
await, and the bridge's `BackendInvoker` implemented over that extraction rather
than over `dispatch_to_backend`.

What the accounted path receives from the bridge, stated because the two
adjacent shapes are both wrong. `Bridge::retry_params` (`mrtr.rs:477-489`)
returns a BARE OVERLAY — `{requestState, inputResponses}` and nothing else, with
each field omitted when it has no content. It is not a params object: it carries
no `name` and no `arguments`, so an implementation that hands it to a backend as
the call's params sends a call with no tool in it. The gateway already owns the
correct merge and it is not a new helper: `OutboundRetry::apply`
(`invoke.rs:455-465`) inserts both fields BESIDE `name` and `arguments` in the
existing object, which is what the specification makes them and what lets a tool
keep an argument of its own called `requestState`.

The accounted path must also NOT run `redeem_retry` (`invoke.rs:529`) on that
overlay. That function redeems a continuation handle this gateway minted for a
CLIENT to present later, and it refuses a handle replayed against another tool
by checking the digest sealed in the envelope. A bridged retry has no such
handle: the client never went away, the bridge is holding the call open, and the
`requestState` in the overlay is the BACKEND's own, echoed verbatim. Running the
redemption over it would refuse every honest bridged retry.

Consequence for sequencing, stated because it is easy to get wrong: this
extraction is a prerequisite of 7b, not a part of it. It changes the accounting
path for every invocation in the gateway, including the ones that never touch the
bridge, and its own regression evidence is the existing counter tests
(`record_error_budget` has arm-level tests at lines 4412-4681). It must land, and
be green, before a retry is wired through it.

### 5. What this round does NOT settle — one question for the requester

Both rulings this change stands on are recorded and neither answers the other.

- 2026-09-05, requester: the bridge lands on HTTP only; legacy stdio keeps the
  MRTR.9 refusal; stdio concurrency is a separate, lower-priority work package
  whose 4.0.0 membership is decided after its own design exists. Recorded as out
  of THIS CHANGE, explicitly not out of the RELEASE.
- 2026-09-06, operator (`RELEASE-4.0.0-readiness-board.md` lines 984-1008):
  `server.modern_protocol` stays true, and 4.0.0 is blocked until the
  legacy-client bridge is REACHABLE FROM PRODUCTION. The ruling names no
  transport.

An HTTP-only bridge makes the bridge reachable from production on one transport
and leaves legacy stdio callers refused. An earlier revision opened this
paragraph by asserting that stdio is the dominant MCP client transport. That
was an A-grade claim — no source — in the sentence that frames a question for
the requester, which is the worst place to put one. How much stdio matters is
the requester's weighing, and this design should not pre-argue it. Whether that satisfies the release gate is not checkable by running
anything, and it must not be assumed: nothing on the record shows the 09-06
ruling had the 09-05 descope in view.

**Question, scheduled per §P1 (askable, not checkable)**: does an HTTP-only
bridge satisfy the 4.0.0 gate, with legacy stdio callers keeping the MRTR.9
refusal?

- asked of: the requester, via team-lead
- what would resolve it: a recorded yes or no on the readiness board
- when: before implementation of 7a begins — it decides whether stdio
  concurrency is in the release, and a yes written after the code lands is a
  ruling with a sunk cost arguing for it
- if it resolves badly (HTTP-only does NOT satisfy the gate): the stdio
  concurrency design becomes a 4.0.0 blocker and must start now, against the
  two-block finding in section 1 above. 7a and 7b are unaffected in shape; the
  release date is not.

Nothing in sections 1-4 depends on the answer, so this amendment is reviewable
while the question is open. Implementation of 7a is not.

### Amendment provenance

Every claim in sections 1-4 was read at source on 2026-09-06 against
`fix/mrtr2-continuation-handle` — no claim here is carried from a previous
round's summary. Each is marked **I**, not V: one careful read of the tree is
one source, and nothing in this round was corroborated by a second independent
one. Line numbers are as of that revision and will drift; the
symbols are the durable anchors. Section 5 quotes two records rather than
measuring anything, and says so.

Inherited test evidence, unchanged and re-run 2026-09-06:
`cargo test --test mik_7212_mrtr7_bridge_acs` = 23 passed, 0 failed. Three
counts appear in this document — 18 acceptance rows, 21 bridge rows, 23
passing — and they are one suite at three moments, not three suites. The
current count is measured, not remembered: `rg -c '#\[tokio::test\]|#\[test\]'
tests/mik_7212_mrtr7_bridge_acs.rs` = 23 (I). The lower two are snapshots taken
while rows were still being added on 2026-09-05; where an earlier paragraph
quotes one, it is quoting its own moment. That suite
exercises the bridge through `FakeClient`; it is what makes the module live, and
it is not evidence of a production path. That distinction is the whole of
MRTR.7a.

## Round 6, disposed — 2026-09-06

Two reviewers, two shapes. The closure re-check went back to the finder that
raised round 5's findings; grok reviewed the whole document fresh. Every finding
below was read at source before it was touched, and two of them died there or
turned out to be worse than stated.

| finding | vendor | disposal |
|---|---|---|
| the round-5 repair invented a per-connection generation and asserted "readable only by the connection that made it" (HIGH) | closure finder | confirmed, and eliminated rather than patched. `handlers.rs:290-300` reattaches an SSE stream to an existing session with no re-`initialize`, so the generation either fail-closes legitimate reattached traffic on the one transport this design ships to, or is per-session under a longer name. The mechanism is deleted; the rule is stated once — a declaration is session-scoped |
| the removal count is stated in two vocabularies, "exactly two places" against "the sole production removal" (LOW) | closure finder | confirmed. One wording in both passages: removed from the map once on `DELETE`, replaced in place once on `initialize` |
| the deferred owner cell names no accountable party; §4 over-grades a count the same round marked I | closure finder | both taken. The team lead is accountable until the session-store work package has a name in it; the heading says "read at source (I)" |
| "nothing reaps a session that is never DELETEd" is false — `spawn_reaper_on` runs in production (MEDIUM, CERTAIN) | grok | confirmed and larger than stated. The reaper walks the same map (`streaming.rs:75`) that holds `ClientSession`, and it removes by `retain`, which is why the write-side grep could not see it. The four-field deferred table is DELETED and the unknown recorded as resolved |
| open question 3 still cites `streaming.rs:578` as a stream-end removal (MEDIUM, CERTAIN) | grok | confirmed. The main passage had been corrected and the recorded answer had not. It now names the reaper |
| the `ClientChannel` shrink wraps typed forwarders that re-serialize params and mint a second id (HIGH, CERTAIN) | grok | CONFIRMED at source and the approach changed, not patched. `send_request` is handed a bridge-minted id and raw `Value` params; `forward_sampling_with_response` mints its own uuid (`proxy.rs:212`) and re-serializes a six-field struct with no `serde(flatten)` (`messages.rs:525-543`), so the wrap is lossy by construction and WIRE.11 could never see the id it was given. The adapter now sits one layer down, on `register_pending` + `PendingSampleGuard` + `send_to_session` |
| the accounted helper omits `enforcer.check`, and the retry overlay's shape is unstated (HIGH, LIKELY) | grok | CONFIRMED at source and repaired. `invoke.rs:1289` refuses with `-32003` before the dispatch is awaited and `src/gateway/input_bridge.rs` names no enforcer at all, so a path extracted from a COUNT OF EMISSIONS would leave every bridged round after the first unmetered. §4 now states the invariant over the whole boundary — gate included — and states what the accounted path does with `retry_params`: merge it as siblings via the existing `OutboundRetry::apply`, and never run `redeem_retry` on a backend's own echoed state |
| the wait on MIK-7388 has nothing left to wait for (MEDIUM, CERTAIN) | grok | CONFIRMED at source. `:430` is re-bound to this change in the OUT list, `:433` is what row 320 specifies, and `:454` is already kind-aware — `project()` branches on `kind` at `input_bridge.rs:476-495`. The ticket agrees at every point: `BRIDGE.1` retired, `BRIDGE.5` checked (`60a28464`), `BRIDGE.2` re-bound by the ticket to “the change that creates the risk”. The merge-before-wiring edge is deleted; the ASK it travelled with survives as `BRIDGE.4` |
| WIRE.8 should assert elicitation params arrive whole on the production wire; record the invoke-loop as a rejected alternative | grok | the second is already in §4's shape table with its rejection reason. The first is a test-plan change and goes to the test plan, not here |

All three findings that this table first recorded as OPEN were read at source
afterwards and moved to repaired above, which is what the open state is FOR. All
three were confirmed, and none was a patch: a count of emissions that lost its
gate, an adapter one layer too high, and a blocking edge with nothing left to
block. Recording them open first was not caution for its own sake — a finding is
a lead until it is read at source, and this document has twice recorded what
closing one on the reviewer's word costs.

**Grok's verdict is recorded with a caveat about its own provenance.** The
ledger row exists with `process_status: ok` and verdict SHIP-WITH-FIXES, but its
`material_sha256` attests to a 134-byte stub, not to the 55KB material — the
wrapper passed the path and the reviewer read the document off disk itself. The
findings are real and cite real line numbers. The chain from verdict to material
is not, and the next round submits the material on stdin.

## Round 7 — the decisions this design has not made, named as decisions

Round 6 closed three findings and left the document reading as if wiring were a
transcription job. It is not. Five decisions stand between this design and code,
and none of them is an implementation detail. Naming them is the §P3 obligation
discharged at the moment the gap is visible, not after a helper has been written
against a bridge that cannot deliver. Each carries who decides and what breaks
if it resolves badly, per the four-field form for a deferred unknown.

### D-A `roots/list` has no response path — SCOPE, requester decides

`forward_roots_list` sends no request `id`. `resolve_pending` keys on the id of
the reply, so a `roots-` prefixed response can never be matched, and nothing
downstream of a roots forward can ever complete. One third of the bridge's
declared surface is undeliverable as the code stands.

> **Resolved — roots stays in scope, the id-bearing variant was funded.**
> `forward_roots_list_with_response` mints the id, registers the pending entry
> and rides the `message` envelope; MIK-7212.ROOTS.1-.5 assert it. The
> fire-and-forget forward was deleted, so the defect described here is no longer
> statable rather than merely fixed.

- **owner:** requester (this is what the bridge is FOR, not how it works)
- **resolves by:** a decision — descope `roots/list` from MRTR.7, or fund an
  id-bearing variant of the forward
- **when:** before any `ClientChannel` production adapter is written
- **if it resolves badly:** a wired bridge that advertises three client
  capabilities and silently hangs on one. Worse than not wiring it, because the
  hang is indistinguishable from a slow client.

### D-B `Declared` has no name-list projection — CONTRACT, author decides

`run` compares against capability name strings via its `slice` parameter.
`Declared` carries no `Vec<String>` projection and no `from_initialize`
constructor (line 330-336 is where one would go). The `run` doc comment cites a
session store that does not exist in this tree.

- **owner:** the implementing author, recorded here rather than decided silently
- **resolves by:** either add `Declared::from_initialize` and keep the `run`
  contract, or change `run` to take `&Declared` and drop the string slice
- **if it resolves badly:** a name list assembled at the call site, which is the
  two-owners-of-one-fact shape the repair protocol says to eliminate, not patch

### D-C the production `ClientChannel` source — COUPLING, requester decides

Two available sources, and the cost difference is not the point:

| option | cost | what it means |
|---|---|---|
| ride the `caller.confirmation` `&ProxyManager` | zero edits to the meta-MCP module root | the destructive-confirmation channel becomes a general client-request pipe |
| a dedicated channel | the module-root struct plus 22 literal call sites | the confirmation channel keeps its single purpose |

Either way the adapter is `register_pending` + `PendingSampleGuard` +
`send_to_session`, with `SamplingError -> DeliveryError` conversion. The
mechanism is settled; the **purpose of the channel** is not, and widening a
narrow safety channel is a design decision wearing a convenience edit costume.

- **owner:** requester
- **if it resolves badly:** a confirmation path whose blast radius now includes
  every bridge request, discovered the first time one of them wedges it

### D-D `accounted_dispatch` — SETTLED, recorded for the record

Committed at `aa601f58` in the meta-MCP invoke module. Behaviour-identical
extraction: the governance **gate is excluded**, six emissions plus a single
`dispatch_to_backend` are inside, and the helper is shared by the opening round
and every bridge retry.

**Correction, 2026-09-08.** This section also claimed
`BackendInvoker::invoke` returns `Result<Value, Error>`, and that half is
FALSE in the tree. `src/gateway/input_bridge.rs:334` still reads `async fn
invoke(&self, retry_params: Value) -> Value;` — a bare `Value`, with nowhere for
a dispatch or transport error to go. `aa601f58` touched exactly one file,
`src/gateway/meta_mcp/invoke.rs` (+105/-56); it never opened `input_bridge.rs`.
The widening was DECIDED at the round-3 design event above and recorded here as
if deciding it had shipped it. It remains this change's work. `accounted_dispatch`
(`invoke.rs:2464`) is real, so what exists is the metering, not the contract.

### D-E `cost_warnings` on first vs last round — OPEN (was D8)

Unresolved from round 5 and still unresolved. Named here so it stops being
carried as a footnote: a retry sequence emits warnings per round, and nothing
decides whether the caller sees the first round's or the last's.

### Policy — every bridge round is gated (design event, RULED 2026-09-08)

The governance gate is called **before every dispatch the exchange makes**, not
only the first. Ruled at `R8 — bridge-mrtr7: WIRE.5 takes per-round gating; the
criterion is not narrowed` (`docs/release/2026-09-08-team-lead-rulings.md`),
which took exit (A) of the escalation below on the elimination test: after (B)
an exchange that overspends an operator's limit stays describable and merely
untested; after (A) it cannot be stated at all. Eliminating a mechanism is this
lane's to do. Eliminating a criterion is not, and it was refused.

That elimination is bounded to the SEQUENTIAL exchange, and the bound is stated
rather than left to be discovered. The gate projects `current_usd + cost` and
reserves nothing (`src/cost_accounting/enforcer.rs:217`), so two exchanges in
flight read the same spent total and can each be admitted for a cost only one of
them could afford. Per-round gating eliminates overspend BY ROUNDS — that is the
claim, and it is the whole claim. Concurrent overspend across exchanges is
untouched by it, remains describable, and is a residual of the cost accounting's
read-then-add shape rather than of where this lane puts its gate.

**Where the gate sits, precisely.** Outside `accounted_dispatch` still — D-D's
extraction is unchanged, the helper keeps metering and the gate stays excluded
from it (`src/gateway/meta_mcp/invoke.rs:2464`). What moves is the CALLER: the
gate runs inside `for _ in 0..self.bounds.rounds`
(`src/gateway/input_bridge.rs:387`) ahead of each `self.backend.invoke(..)`, so a
refusal ends the exchange on the round it arrives on. **The invariant is ONE
GATE CALL PER DISPATCH, not one gate call somewhere in the loop.** The pre-loop
gate at `src/gateway/meta_mcp/invoke.rs:1413` is RETAINED — it is what admits the
first dispatch — and the loop ADDS one call per retry, so a fully funded exchange
under `BridgeBounds::DEFAULT` (`rounds: 3`) issues four dispatches and four gate
calls. Nothing is moved out of the pre-loop position; a gate call is added to
each round that did not have one. It must reach the caller as
itself — the same `-32003` and the same block reason — which stays unwritable
until `invoke` yields `Result<Value, Error>`. That widening was the round-3
design event and is still this change's work, per D-D.

**What this reversal DELETES, so nothing carries it forward by habit.** The
accepted residual — "a bridged round may not be budget-refused, so an exchange
CAN overspend by its rounds" — is gone, not mitigated. With it go the
`3 × cost_for(tool)` overspend ceiling and the arithmetic that reconciled that
number against four paid calls. **The four-dispatch ceiling clause R1 asked for
on the `WIRE.13` row is withdrawn by its author** (R8), because it was derived
from the single-gate fixture (A) deletes. It is removed rather than kept out of
deference to the ruling that requested it.

**What `WIRE.13` still asserts, and the one thing per-round gating adds.** Four
dispatches and four `record_spend` entries stand: that total counts from zero,
and where the gate sits does not change how many calls a fully funded exchange
makes. What the reversal adds is a PRECONDITION on the fixture — every round must
be inside budget for the fourth dispatch to be reachable, so an under-funded
fixture would now end in a governance refusal while the row asserted
`RoundsExhausted`, passing or failing for a reason it never names. The row says
so in its own evidence column rather than leaving it to whoever writes the test.

The `PendingSampleGuard` argument stays RETRACTED and must not return with the
gate. The guard is RAII, taken inside `send_request`
(`src/gateway/proxy.rs:532-533`), held across the await and dropped on return AND
on unwind, so a refusal arriving mid-exchange has nothing left to strand —
verified at source, and R1 verified it independently across `:219`, `:286` and
`:417`. Per-round gating does not reopen that question; the lifecycle objection
was never the reason the gate sat outside.

Capping rounds does not cap the asking, and the struct's own doc says why
(`:213-217`): one interim result may carry an arbitrary number of entries, so a
single round reaches the same abuse with a larger array. Three further ceilings
are on the original call rather than on a round — `requests: 8`, `aggregate:
120s`, `per_prompt: 30s`. The per-prompt value is deliberately NOT the 120s
elicitation constant in `destructive_confirmation`; reusing that would let one
unanswered prompt consume the whole aggregate budget.

Today every `BridgeBounds` construction site is a test
(`tests/mik_7212_mrtr7_bridge_acs.rs:306,430-450,1118,1195`). The production
wiring is what puts `DEFAULT` on the live path, and until it does, the ceilings
above are properties of a struct nothing constructs.

**Process status of this reversal.** It is a §P3 design event moving what an
acceptance criterion asserts, so §P0 reopened where Scope is stated — one added
line, above — and §P2 reopens at the `WIRE.5` and `WIRE.13` rows of
`docs/design/2026-09-05-mrtr7-test-plan.md`. The round count does NOT reset: the
spec moves, the history does not — `R8` and `R22` of
`docs/release/2026-09-08-team-lead-rulings.md` (2026-09-08) both rule so. The repair
takes no new `BridgeError` variant and no wire change — a call moved inside a
loop, the propagation the widening already owed, and the documentation delta.

### Round 6 escalation — `gpt-review` F1, `WIRE.5` versus gate-once — RULED (A), 2026-09-08

Stated in full here, because the header says it is and because a team lead
cannot rule on a summary of a finding. Everything below describes the policy
AS IT THEN READ, before `R8`. The gate-once statements it quotes have since
been amended above; they are preserved here in their pre-ruling form because a
ruling that cannot be read against the text it ruled on is unauditable.

- **the finding.** `WIRE.5`'s criterion reads "Every backend attempt is
  accounted exactly once, including bridge retries, **and governance is
  re-checked before each**", and its second fixture asserts a budget sized to
  admit the first attempt and reject the second, with the retry never reaching
  the backend (`docs/design/2026-09-05-mrtr7-test-plan.md:61`). The policy
  section above THEN SAID the opposite in this same design: the gate stays outside
  `accounted_dispatch` deliberately, an exchange is gated ONCE, and the residual
  — "a bridged round may not be budget-refused" — is ACCEPTED as metered
  overspend bounded at `3 × cost_for(tool)`. A plan row and a design event
  cannot both be met. The tree agrees with neither yet: `accounted_dispatch`
  (`src/gateway/meta_mcp/invoke.rs:2464-2560`) meters, it does not gate, so
  there is no pre-dispatch re-check to observe.
- **why this lane cannot settle it.** The two exits are not symmetric. (A) move
  the design to per-round gating: it ELIMINATES the residual, and takes with it
  the `3 × cost_for(tool)` ceiling and `WIRE.13`'s four-dispatch arithmetic. It
  is a §P3 design event that moves what an acceptance criterion asserts, so §P0
  and §P2 re-open on their own terms first. (B) narrow `WIRE.5`'s criterion to
  accounting alone: one row edit, but it DROPS an acceptance criterion, and the
  repair protocol requires the requester's recorded agreement BEFORE that
  happens, never after.
- **recommendation: (A).** The elimination test decides it. After (B) the
  finding can still be stated — an exchange that overspends a limit the operator
  set stays describable, merely untested. After (A) it cannot be stated at all.
  Eliminating a mechanism is always this lane's to do; eliminating a criterion
  is not.
- **RULED (A), 2026-09-08.** `R8` in `docs/release/2026-09-08-team-lead-rulings.md`
  takes per-round gating and refuses the narrowing, on the recommendation's own
  test. The freeze lifts: the Policy section above is amended to the ruled shape,
  and `WIRE.5` and `WIRE.13` are repaired in
  `docs/design/2026-09-05-mrtr7-test-plan.md`. No test code is written against
  either row until both review legs return on the amended material — the
  sequence the ruling reopens is §P0, then §P2, then §P4, with the round count
  carried rather than reset.
- **who re-checks the repair.** `gpt-review` returned this round with `rc=0`, so
  the finder is available and the ordinary path applies: F1 and F2 go back to
  `gpt-review`. The finder-unavailable clock drafted here on 2026-09-06, when
  that leg was erroring, is DELETED rather than kept dormant against a future
  outage. Its terms are owned by the repair protocol in
  `rules-source/workflows/development-process.md`, and a second copy of them in
  a lane document would drift from the one that decides.

### Review provenance for this round

The `gpt-review` ledger holds **no row** for this material. The most recent row
is a different repo, run and ticket (`mcp-v4-delivery`, MIK-7212 component
tests, 2026-09-06). The round-7 verdict is therefore `MISSING`, never a verdict
scraped from any output file. The round-6 recorded verdict reviewed the
**unamended** design and does not carry to this amendment; both legs re-run
against the material above, submitted on stdin.

That sentence binds the PACKAGE, not just the intent: no round may carry an
earlier round's PART A verbatim. PART A is the design and plan **as they stand
at submission**, read from the working tree when the package is assembled and
never copied forward from a previous one. A leg handed a stale copy returns a
verdict on a revision that no longer exists, which is an absence of review
wearing a verdict line.

An earlier version of this paragraph listed the three commits that had landed
since round 1 by hash. That list was already wrong by the time anyone read it,
and it could not have been otherwise: this branch is shared, so a commit from
another session goes into the enumeration's blind spot without touching the
enumeration. The rule needs a BASELINE, not an inventory. Round 1's package was
assembled at `7cfc16bd`; everything after it postdates that package. If a
diff-shaped section is wanted alongside PART A, it is
`git diff 7cfc16bd..HEAD -- <the two documents>` and the header says which
range it is, so the section stays accurate without anyone maintaining it.

An off-by-one on that baseline is possible in principle — a commit whose subject
records a round's OUTCOME postdates that round's submission, so the package may
have been assembled at its parent rather than at it — and here it is inert:
`7cfc16bd` touches only `docs/design/2026-08-31-sub-4-idempotency-wiring.md`, a
different change's document (`git show --stat 7cfc16bd`). Either endpoint yields
the same content for the two documents this range is filtered to, so the range
stands as written.

## Round 8 — two rulings recorded, and the roots defect is worse than round 7 said

Round 7 named five decisions. Two were the requester's and have been ruled.
Recorded in the askable form the design process requires: the question, who was
asked, the answer, and what it changed.

### D-A RESOLVED — `roots/list` stays in scope; fund the id-bearing forward

- **question:** descope `roots/list` from MRTR.7, or fund a forward that can be
  replied to?
- **asked of:** the team lead, standing on the operator's ask for this fleet —
  "get to the release ready state with all gaps fixed with the full scope"
- **the answer:** roots is NOT descoped. A surface that cannot deliver by
  construction is a GAP, and the ask says gaps are fixed, not narrowed.
  Descoping a declared capability because its delivery path was built wrong is
  precisely the move that sentence forbids.
- **what it changed:** the wiring now has to repair the forward before it can
  use it. Round 7 treated descoping as a live option and sized the work without
  it; that sizing is void.

Recorded, not confirmed: the lead is reporting this to the operator with the
reasoning exposed, in case "full scope" was meant more narrowly. Build against
roots being in; do not wait.

### D-C RESOLVED — a dedicated channel, and the 22 call sites get paid

- **question:** ride the destructive-confirmation `&ProxyManager`, or add a
  dedicated client-request channel?
- **asked of:** the team lead, who owns it — the requester has no stake in
  which struct carries an internal request pipe
- **the answer:** dedicated channel. The confirmation channel's NARROWNESS is
  its security property. Widening it means every later reader must ask "is this
  a confirmation or something else", and the first reader who gets that wrong
  writes a bug in the destructive path.
- **what it changed:** the module-root struct plus 22 literal call sites enter
  the change. Mechanical work, which is the cheap kind — paid once, against a
  channel whose purpose stays stateable in one sentence, which is paid at every
  later change.

### The roots defect has a second half, and it is the load-bearing one

Round 7 said the forward sends no request `id`, so nothing can be matched. True,
and incomplete. Reading the roots forward beside the sampling forward shows two
differences, not one:

| | sampling forward | roots forward |
|---|---|---|
| JSON-RPC `id` | minted as `sampling-<uuid>`, in the frame | absent |
| SSE envelope | `message` — "MCP-standard: raw JSON-RPC for compliant clients" | `proxy_request` |

Read that table precisely, because the obvious reading is wrong: the column is
the RESPONSE-BEARING sampling forward, not sampling in general. The
fire-and-forget `forward_sampling` emits `proxy_request` exactly as roots does.
So the envelope split is response-bearing versus fire-and-forget, and roots is
not uniquely malformed — it is a forward that must MOVE into the
response-bearing half, and the envelope has to move with it. The repair is
unchanged; the reason it is needed is one step narrower than first written.

The missing `id` makes the frame a **notification** rather than a request, and
its own doc comment says so. A conforming MCP client is not obliged to answer a
notification, and would not. The non-standard envelope compounds it: even with
an `id` bolted on, a compliant client reading only the standard `message` event
never sees the frame as a request at all.

So the repair is not "add an id". It is: mint `roots-<uuid>`, register it,
hold a `PendingSampleGuard` across the await, put the id in the frame, AND move
the envelope to `message`. Anything less leaves a surface that still cannot be
answered — the exact defect, one layer down, wearing a fix.

Two consequences that are not optional:

- **This is a wire-observable change.** A client that sees a notification today
  sees a request tomorrow. Protocol-first applies: the frame is the contract.
- **The two existing roots tests assert the current shape** and will fail. That
  is correct and expected — they encode the notification behaviour that is being
  repaired. They are updated as part of this change, not worked around.

### One naming defect this exposes, recorded rather than silently fixed

The pending map is named for sampling. Roots replies will land in the same map,
because it is a generic id-keyed registry that sampling merely happened to be
the first user of. The mechanism is right; the name will be a lie the moment
roots lands. Recorded here as an observation, not a ticket — the rename is
smaller than the ticket describing it would be, and it rides with this change.

### Still open after this round

- **D-B** `Declared` has no name-list projection — author's call, unchanged.
- **D-E** `cost_warnings` on first vs last round — open since round 5.

### Review provenance for round 8

Both legs were launched against the round-7 material and **killed mid-flight**
when these rulings arrived: that material froze while D-A and D-C were open, so
every finding would have been argued against a premise that no longer holds. Any
ledger row left by the kill carries a nonzero exit and is read as `ERROR`, never
as a verdict. Round 7 and round 8 are both `MISSING` by design, and the dual
review runs against the wiring — where the decisions are settled and the code
exists to argue about.

## Design event — the timeout arm has two causes and reports only one

Found while sweeping BRIDGE.4's repair across its sibling rows, and named here
because §P3 says a decision made during implementation gets named at the moment
it is made rather than discovered in review.

The ruling of 2026-09-08 says an unanswered prompt **fails the call, naming the
entry**. The obvious repair is to replace the bare `continue` at
`src/gateway/input_bridge.rs:486` with
`Err(BridgeError::Delivery { key, error: DeliveryError::TimedOut })`. That is
still the right shape. It is not the whole decision, because the branch it sits
in does not fire for one reason:

```rust
let left = self.bounds.aggregate.saturating_sub(started.elapsed());   // :481
let Ok(reply) = tokio::time::timeout(self.bounds.per_prompt.min(left), sent).await
else { continue };                                                     // :484-486
```

`left` is the **aggregate** remainder. The wait is therefore whichever bound
runs out first, and the branch cannot distinguish *this client went silent* from
*the call ran out of time while this client was answering*. A `continue`
discards both without comment, which is precisely why the ambiguity has been
invisible: the code never had to say which one happened.

Naming the failure removes that cover. Unrepaired, the aggregate's own
exhaustion would be reported as a named silent client — and worse,
`BridgeError::Deadline` would become unreachable from `ask`. Elapsed time can
only cross the aggregate *inside* a wait, so the clamp fires before the
top-of-round check at `:388-390` can ever see it. The variant the ruling did not
touch would be swallowed by the variant it did. The requirement carrying it
(`the aggregate budget ends a call whose rounds each answer in time`, plan row
321) would still be stated and no longer reachable.

**Recommended reading:** the branch reports which bound expired. An exhausted
aggregate is `BridgeError::Deadline`; a silent client inside a live budget is
`BridgeError::Delivery { key, error: DeliveryError::TimedOut }`. No new variant,
no new type, no wire change. An earlier revision of this paragraph reassured the
reader that "both are already constructed elsewhere" — half true, and the false
half is the interesting one. `DeliveryError::TimedOut` is constructed at
`src/gateway/proxy.rs:557-558` as `rx.await.map_err(|_| DeliveryError::TimedOut)`,
a DROPPED CHANNEL rather than an elapsed clock, under a comment that defines
itself as "what the bridge's own timeout arm means by `TimedOut`". That comment
points at an arm which has never constructed the value. The repair makes it true
for the first time; until then it is a §P4a casualty riding with this change,
recorded here so a reviewer who greps the reassurance meets the asymmetry
instead of rediscovering it.

Tie at the boundary, settled here so the implementation need not guess: when
`left == per_prompt` both bounds expire on the same instant and both readings
fit. The aggregate wins — the discriminator is `left <= per_prompt` ->
`Deadline`. At that instant the call has no budget left to start another wait,
so naming an entry would name one the call was never going to hear from.

**Who decides this?** Not the author. The ruling settled what happens to a
silent client and said nothing about the aggregate, because from outside the
loop the two do not look like the same code path. They are. And the error shape
on `ask()`'s failure path is the release owner's call in this lane — established
2026-09-08 by the ruling this section builds on, `R8a — BRIDGE.4: the lane's
error shape beats the one this document specified`. Deciding it here would take
back the authority that ruling asserted, one document later.

R8a is genuinely silent, and two readings survived it — the record below says
which was ruled:

- **recommended** — the aggregate expiring is `Deadline`, because the client was
  not silent, it was answering. Row 321 keeps its assertion unchanged and starts
  PINNING the distinction rather than merely exercising the deadline;
  `BridgeError::Deadline` stays reachable from `ask()`.
- **the other** — "fail the call, naming the entry" covers any entry the call
  abandons, including one the clamp cut short. The arm then always returns
  `Delivery { TimedOut }`, `Deadline` genuinely leaves `ask()`, and **row 321's
  assertion moves** — the same churn row 320's inversion has already cost.

**Question, scheduled per §P1 (askable, not checkable) — RESOLVED 2026-09-08**:
when the aggregate budget expires *inside* a prompt's wait, does the call fail
with `BridgeError::Deadline`, or with
`BridgeError::Delivery { key, error: DeliveryError::TimedOut }` naming the
prompt the clamp cut short?

- asked of: the release owner, via team-lead
- the answer: `BridgeError::Deadline`, ruled at `R21 — BRIDGE.4: aggregate
  expiry is Deadline, and the reason is attribution`
  (`docs/release/2026-09-08-team-lead-rulings.md`). The tie-break above stands
  as written: `left <= per_prompt` resolves to `Deadline`
- what it changed: nothing in this document's recommendation, and one thing in
  its REASON, which is the half worth keeping. The ruling does not rest on
  reachability. `Delivery { key, error }` names a key, and naming a key
  attributes the failure to that key's owner — a client that answered every
  prompt inside its own budget did not time out, the call did. Reporting that
  as a delivery timeout against the client's entry is a false statement about
  which party failed, and it is read later by someone deciding whether a
  backend is flaky. Reachability and row 321's unchanged assertion are
  consequences, not arguments: had attribution pointed the other way, row 321
  would have moved

Two riders the ruling carries, recorded here because they bind this change and
not the ruling's file: the `proxy.rs:557-558` comment becomes true for the
first time under the repair and ships with it per §P4a, and the arm takes no
new variant and no wire change — one branch and the documentation delta.

**What this section settles, and what it still does not.** Row 321 keeps
`Err(BridgeError::Deadline)` — now by ruling rather than by default, and it is
the row that pins the distinction. Nothing here narrows §P0's FOR or drops an
acceptance criterion. The plan correction sits beside row 320's inversion in
`2026-09-05-mrtr7-test-plan.md`, and that inversion is now unblocked.

One open item is not this lane's to close: R8a at
`docs/release/2026-09-08-team-lead-rulings.md:169` still spells the
silent-client shape `DeliveryError::Unanswered { key }`, and no such variant
exists — `enum DeliveryError` at `src/gateway/input_bridge.rs:158-186` carries
no `Unanswered`, and no inner variant carries `key` (it sits on the outer
`BridgeError::Delivery`). R21 says "no new variant", which is consistent with
`TimedOut` and never names it for that arm. This document implements
`DeliveryError::TimedOut`; the correction to the rulings file belongs to its
owner and has been reported.
