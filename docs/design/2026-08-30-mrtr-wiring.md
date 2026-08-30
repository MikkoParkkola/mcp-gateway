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

- `AppState` (`src/gateway/router/mod.rs:50`) gives a keyring an established place to live. It does
  **not** give it a construction path: `gateway_key_pair` is an ECDSA P-256 *signing* key generated
  at startup (`src/gateway/oauth/jwks.rs:103-113`), and `Keyring` holds AES `LessSafeKey` material
  (continuation.rs:206-208). They are different primitives for different jobs and neither derives
  from the other. The continuation keyring is therefore a **new, independently configured** item
  with its own key material and explicit key ids. Whether that material outlives the process is
  decided by the consumed-ledger, not by convenience — see decision 4.
- `Keyring::open` takes `now` explicitly, so time is injected rather than read, and
  `Payload::redeemable_by` (continuation.rs:122) already *compares* the two binding values in
  constant time. It does not produce them: both are caller-supplied `String`s and nothing in the
  tree constructs either. The comparison did not have to be designed here; the inputs did, and they
  are, below.
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

- more than one interim round trip per call. `Payload` carries **no** round counter, so the cap is
  not a configuration value in this release — it is one, enforced by construction: a result that
  comes back `input_required` on a *retry* dispatch is refused rather than minted again. A
  configurable cap needs a counter in the payload and is a later change.

## What binds a continuation, defined

Two values decide whether a token may be redeemed, and `Payload::redeemable_by`
(continuation.rs:122) compares both in constant time. The module compares them; it does not
construct them, and nothing else in the tree does either. Leaving them to the call site is the
whole security boundary left as an exercise, so they are defined here.

**`principal_fingerprint`** is `SHA-256` over a domain-separated, scheme-tagged encoding of the
authenticated caller. One scheme per authentication path the gateway already has, so that no two
schemes can collide and no scheme can be spoofed by choosing a value in another:

| caller | fingerprint input |
|---|---|
| API key | `apikey:` + SHA-256 of the presented credential — never the credential |
| agent JWT | `agent:` + validated `iss` + `\x00` + validated `sub`, both taken from the verified token, never from an unverified claim |
| mTLS | `mtls:` + SHA-256 of the DER client certificate |
| anonymous / no credential | **no fingerprint exists** |

The last row is a refusal, not a fallback value. A caller the gateway cannot name cannot be
re-identified on a retry, so an interim result for an unauthenticated caller is not minted at all —
the call fails as unsupported rather than minting a token any anonymous caller could redeem. A
shared fingerprint for all anonymous callers would satisfy `redeemable_by` while binding nothing,
which is the failure mode this row exists to prevent.

**`original_request_digest`** is `SHA-256` over `tool_name` + `\x00` + the **canonical** JSON of the
call's `arguments`, using the same canonicalisation `src/idempotency.rs` already applies for its
auto-generated key. It must be recomputable from the retry, so it is computed over the *original*
arguments only: the retry's `inputResponses` and `requestState` are excluded, because they do not
exist on the first call. Reusing the existing canonicaliser is deliberate — two spellings of the
same canonical form is how a digest silently stops matching.

Neither value is ever logged, and both are already `<redacted>` in `Payload`'s `Debug`
(continuation.rs:91-93).

## Scope moved, and why — 2026-08-30

**This design's FOR has widened. The two exclusions above are now in the release.** Recorded here
rather than edited away, because a scope that moves silently is how a limit becomes a surprise.

What forced it: the confirmation pass read the test plan's three NOT COVERED cells against the
requirements and found all three are written as **MUST** — MRTR.5 says single-use enforcement
"MUST hold across every replica that can receive the retry", MRTR.6 says a retry MUST reach the
replica holding a legacy backend's open exchange or fail explicitly, and MRTR.7 says the gateway
MUST bridge a modern backend's question to a legacy client. A stated limit is only honest against a
requirement written as SHOULD. Against three MUSTs it is an unmet requirement wearing a limit's
clothes, and the choice was the requester's: ship single-process and amend the criteria, or build
both. **Decision (operator, 2026-08-30): build both before 4.0.0.**

Neither piece starts from nothing, which is why the answer was not obviously the expensive one:

- `InFlight` (continuation.rs, `hold` and its routing) is already **replica-aware** — it records
  which replica holds each exchange and refuses at capacity. What it lacks is shared storage: the
  table lives in one process's memory. The same gap as `ConsumedLedger`, and the same fix, which is
  why MIK-7312's durable ledger covers MRTR.5 and MRTR.6 together rather than separately.
- `Bridge::to_legacy_client` (mrtr.rs:186) already turns an interim result into the outbound
  requests a pre-2026 client would understand. It has no caller anywhere in the tree. What is
  missing is the wiring: issuing those requests over the client's own transport mid-call, and
  collecting the answers.

Both are **design events in their own right**, not extensions of this one: a shared ledger picks a
storage dependency the gateway does not currently have, and the bridge holds a call open across a
server-initiated request. Each gets its own design, its own review, and its own test plan, ahead of
the wiring this document specifies — which is unchanged, and remains the first of the three.

## The shape

Two edits, one on each side of `dispatch_to_backend`.

**Response side (new).** After a backend result comes back on the `tools/call` path, read it with
`InputRequired::from_result`. `None` — the overwhelmingly common case, and every legacy backend —
falls straight through, unchanged. `Some` means: take `interim.request_state`, seal it in a
`Payload` bound to this caller, mint, and return the interim result to the client with the
gateway's token in `requestState`.

`InputRequired::request_state` is an `Option` (mrtr.rs:125) and `Payload::backend_request_state` is
not (continuation.rs:68). A backend that asks a question while keeping no state of its own is
compliant, so the payload field becomes optional too, and its absence is preserved when the retry
params are built. Forcing an empty string in its place would hand the backend a `requestState` it
never issued.

The questions pass through only after the client has been checked against them: each input request
carries a type, and a client that did not declare support for that type cannot answer it. An
unsupported type is refused before anything is minted, rather than minting a continuation for an
exchange that cannot complete.

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

1. **SUPERSEDED by the scope move above — the legacy bridge now ships too.** As written:  A 2026 client gets a working
   multi-round-trip call. A pre-2026 client gets what it gets today, and the release notes say so.
   Shipping half is what makes the other half's absence honest rather than hidden.
2. **SUPERSEDED by the scope move above — single-use becomes cross-replica.** As written:  The deployment is one
   process. A shared ledger is a real piece of work (a store, its failure mode when unreachable,
   and a decision about whether an unreachable store fails open or closed) and doing it badly under
   release pressure is worse than declaring the limit. MIK-7312 keeps it.
3. **An interim result leaves no idempotency trace at all.** Not writing `Completed` is
   insufficient: the flow marks the key `InFlight` *before* executing (`src/idempotency.rs:13-15`),
   so simply declining to complete it leaves a live `InFlight` entry that answers every other caller
   with `DuplicateRequest` until it times out. On recognising `input_required` the response side
   therefore **removes** the in-flight entry, and writes to neither the idempotency cache nor the
   response cache. The narrower repair (extending the key to include `inputResponses` and
   `requestState`, as RFC-0060:143 suggests) is rejected: it makes the retry miss the cache, which
   is right, while still caching the *interim* answer under the original key, which is the
   dangerous half. Storing nothing leaves the defect undescribable rather than unreachable.

4. **Key material does not outlive the process while the spent-list does not either.**
   `ConsumedLedger` (continuation.rs:437) is in-memory. A keyring whose material survived a restart
   while the spent-list did not would make every already-redeemed continuation redeemable again:
   single-use would hold only until the next deploy, and would fail *silently*, which is the worst
   way for it to fail. So for 4.0.0 the keyring is generated per run. A restart kills continuations
   in flight, every affected client gets an ordinary refusal, and nothing already spent becomes
   spendable. That trades a visible failure for a silent one, which is the right direction.
   Persistent keys are not an independent feature: they arrive **with** the durable ledger under
   MIK-7312, never before it.

   The keyring and the ledger therefore share **one owner and one lifecycle**: they are constructed
   together, held together in `AppState`, and there is no path that replaces one without replacing
   the other. That is the whole of the invariant — keys and the memory of what those keys spent
   belong to the same run — and stating it as a structural property rather than a convention is
   what keeps a later config-reload refactor from resetting the ledger while the keys live on.

   The continuation lifetime is **300 seconds**, and minting derives `expires_at` from the current
   time rather than accepting one, which is what the API does today (continuation.rs:475). Clamping
   an over-long request would be a silent narrowing, and the paragraph above spends its whole
   argument on preferring a visible failure to a silent one; so the lifetime is not a parameter at
   all. `Payload::mint` loses its `expires_at` argument, and an over-long lifetime stops being
   something to refuse because it stops being expressible. There is no external caller to
   disappoint: minting happens on the gateway's own response path, never at a client's request. The number bounds two things at once and both are now
   measurable: how long a stolen token is worth stealing, and how much work a restart destroys.

## Unknowns, scheduled

| unknown | how it is settled |
|---|---|
| Does any backend fixture actually return `input_required`? | **Resolved — no.** `rg 'input_required'` across the tree returns only `mrtr.rs`, `handlers.rs`, two AC test files and the A2A translator's unrelated `TaskState::InputRequired`. No fixture backend produces one, so the test plan must add a backend that does; without it every response-side test would be asserting against a shape nothing emits. |
| Does the 2026 specification put `requestState` on the interim *result*, or in `_meta`? | **Resolved — on the result.** Read at source 2026-08-30, `https://modelcontextprotocol.io/specification/2026-07-28/server/tools` §"Input Required Tool Results": `requestState` is a top-level sibling of `resultType` and `inputRequests` in the result object, and `inputResponses`/`requestState` are siblings of `name`/`arguments` on the retry. `InputRequired::from_result` reads exactly that, so the assumption it was written on is correct and the response side is unblocked. Confirmed in the same read: an ordinary 2026 result carries `"resultType": "complete"`, which `from_result` already falls through on. |
| Is one interim round trip enough for the release claim, or must the cap be greater than one? | **Askable — operator.** Changes the AC, not the mechanism. |
| The specification says the JSON-RPC `id` **MUST** differ between the initial call and the retry. Does the gateway enforce or preserve that? | Checkable, and not yet checked. The gateway forwards ids; whether a backend sees two different ones depends on how the retry is dispatched. Cheap to settle once the retry side exists, so it is a test-plan row rather than a mechanism, and it is now written as one. |

The first row changes what the release can claim: the response side no longer waits on anything,
and the retry side waits only on the review of this document.

A lifetime is a trade-off, not a fact about the code, so it was **asked, not measured**:

- *How long should a paused call stay resumable?* — asked of the operator, 2026-08-30 — **300
  seconds**, on the reading that the answering party is a client program or a person already at the
  screen, not someone who walks away. — Changed nothing: it confirmed the value already in decision
  4, which had been chosen without asking. Had the answer been fifteen minutes, the spent-token list
  would have had to hold roughly three times as many live entries and MRTR.8's capacity row would
  have moved with it.

## Test plan

Superseded. The sketch that stood here listed one row per behaviour before the plan existed; it has
been replaced by the detailed coverage map in `docs/requirements/RELEASE-4.0.0-test-plan.md`
(increment 5), which reviewed to SHIP-WITH-FIXES twice and no longer matches the sketch in two
places: the JSON-RPC id row was deleted, because every transport already allocates through
`next_id`, and the lifetime clamp became a constant, because there is no mint parameter to clamp.
An implementer following the sketch would have resurrected both. The map is the specification.


## Design events (increment 2)

Recorded per development-process §P3: decisions the design did not make, named at
the moment they were made.

### DE-1 — the response-side edit belongs in `invoke.rs`, not `handlers.rs`

The design says "two edits, one on each side of `dispatch_to_backend`", and the
brief says "thread the keyring into `dispatch_to_backend`". An earlier reading
put the mint in `handlers.rs`, where `AppState` already carries the keyring and
the edit is smaller.

That reading is wrong, and design decision 3 is what makes it wrong. Idempotency
and the response cache are written **inside** the invoke chain
(`src/gateway/meta_mcp/invoke.rs:793`, `:845`, `:1034`, `:1270`), before any
result reaches `handlers.rs`. Decision 3 requires that an `input_required`
result remove the in-flight entry and write neither cache — an interim answer
cached under the original key is the dangerous half. Recognising `input_required`
one layer up is too late: the write has already happened.

So both edits sit around `dispatch_to_backend` in `invoke.rs`, and the
continuation state reaches them on `MetaMcpCallerContext` rather than being read
from `AppState`. One seam instead of two, and the keyring is in scope for the
retry side in the same place.

### DE-2 — MRTR.9's source of truth is per request, not per session

MRTR.9 requires the gateway not to send an `inputRequest` of a type the client
has not declared support for.

The search that found "nothing records client capabilities" looked at the
**session** path and was right about it: `handle_initialize`
(`src/gateway/meta_mcp/mod.rs:1011`) takes `&self`, reads `params` for the
protocol version and a profile hint, and persists no capabilities; the
`capabilities` it emits at `:1003` are the server's own. There is no per-session
client-capability store, and building one is not increment 2's size.

**A per-session store is not what MRTR.9 needs.** On the modern path a client
declares its capabilities on *every request*, in `_meta`, and the gateway
already parses them: `RequestFields::declared_capabilities`
(`src/protocol/meta.rs:69`), populated at `:186`, with the predicate every
consumer would call at `:271` — `declares_capability(name)`. The parse runs in
production: `classify_request` is called at
`src/gateway/router/handlers.rs:578`, and the `Modern(ref fields)` branch
destructures the fields at `:595`, inside the function that dispatches.

The field has **zero readers** outside its own module. That is the same defect
as the rest of this increment — a path built, tested, and never wired — not a
missing subsystem. The distinction decides the size: consulting a predicate that
already exists on a struct already in hand is a rider on DE-1's seam, and
`MetaMcpCallerContext` (`src/gateway/meta_mcp/mod.rs:111`) is a borrowed
per-request struct that already carries `api_key_name` and `agent_id` across
exactly this boundary.

**MRTR.9 returns to increment 2's scope**, and test-plan rows 312 and 313 run
here. The withdrawal is itself withdrawn.

Where the check goes, unchanged from the earlier reasoning because that part was
right: immediately before the mint on the `input_required` path, so an interim
result naming an undeclared request type is refused **before** anything is
minted and a refusal cannot leave a live continuation behind.

Two things a per-request declaration settles that a session store would not:
a client may narrow what it accepts between calls, and a null or absent
`clientCapabilities` is not a declaration — `meta.rs:70-77` already states the
specification's rule that explicitly-absent is still absent. An implementation
must refuse on absence rather than default to permitted.

### Three unknowns closed by reading the source — 2026-08-31

The first was scheduled above as a condition on DE-2, and it came back **no**.
The other two were adjacent inferences of the same class, checked at the same
time so the answer arrives as one packet rather than three.

`Does the mint site hold MetaMcpCallerContext?` — read `invoke.rs:423-441`,
`:536-560`, `:930`, `:1788` — **no**. `MetaMcpCallerContext` arrives at
`invoke_tool` (`:423`) and is flattened into ten loose parameters at `:432`
before `invoke_tool_traced` (`:536`) is entered; that function calls
`dispatch_to_backend` (`:930`), which takes eleven loose parameters of its own.
The struct is one frame above the mint site and no parameter carries the
keyring. Decision 3 therefore cannot be implemented without a signature change,
which DE-2 said returns this to a design question. It has.

The `invoke.rs` line numbers in the paragraph above describe the tree as it was
when the question was asked, before DE-3 changed the signature. They are kept as
read rather than rewritten, because rewriting them would falsify the record of
what was found. Every other citation in this document points at the current tree.

`Is ContinuationState constructed on the production path, or only in tests?` —
searched the whole crate for `ContinuationState::new` — **production**, once, at
`server/mod.rs:1171`, into the field declared at `router/mod.rs:93`. Increment 1
landed it; increment 2 inherits a live store, not a type.

`Are the client's declared capabilities in scope where MetaMcpCallerContext is
built?` — searched `router/handlers.rs` for every use of the `fields` binding —
**no**. The `RequestShape::Modern(ref fields)` binding opens at
`handlers.rs:595` and its last use is `:690`; the context is built at `:1099`,
outside that block. MRTR.9 needs a capability answer carried out of the block —
the smallest form is the boolean the check already computes at `:690`, hoisted,
not the struct cloned. This is a second wiring gap, in the same increment, and
it was not in the plan.

### DE-3 — the caller context travels whole one frame further down

`invoke_tool_traced` now takes `caller: &MetaMcpCallerContext<'_>` in place of
the six caller fields `invoke_tool` used to flatten into it. The struct is
unpacked into locals at the top of the body, so the ~1,300 lines below read
unchanged; only the boundary moved.

This applies an existing decision rather than making a new one. The comment at
`invoke.rs:420-422` already states the rule for the frame above — the context
travels whole "rather than five loose parameters" so that "the authorizer
travels with the identity it authorizes, so no call site can pass one without
the other." `invoke_tool_traced` is private with exactly one call site, so the
same argument holds with none of the cost that would make it debatable.

The alternative was to add the keyring and continuation handle as two more loose
parameters. Rejected: it takes a signature the codebase already apologises for
with `#[allow(clippy::too_many_arguments)]` and makes it worse, and it
reproduces exactly the coupling the comment above exists to prevent. Both
`too_many_arguments` allows are now deleted, which is the measurable half of the
argument — the parameter count fell from nine to four.

`trace_id` stays a separate parameter. It is not caller identity and does not
belong on that struct.

### DE-4 — stdio callers cannot be asked for more input

`MetaMcpCallerContext` gains `may_request_input`, named for the question it
answers rather than for where the answer comes from. On HTTP it is read at
`handlers.rs:597`, alongside `is_modern`, so every shape-derived fact is read
once and carried the ~500 lines to the construction site rather than
re-classified there. The read is `RequestShape::may_request_input`, a named
method rather than an inline `matches!`, so the capability string it compares
against is covered by a test — a typo in it would otherwise compile and still
look like a no-op. It is not the per-method check at `:695`: that one answers "did the
client declare the capability THIS method needs", which is a different question
that happens to share a helper.

On stdio (`server/mod.rs:1733`) there is no per-request declaration to read, so
the value is `false`. That is a decision, not a default: the type already
states the specification's rule that explicitly-absent is still absent (the rule
is at `meta.rs:66-68`; `declares_capability`, which applies it, at `meta.rs:283-285`), and the
same reading applies to a transport that cannot declare at all. A stdio client
is therefore never sent a continuation. If stdio should be able to elicit, it
needs its own declaration mechanism, and that is a design question, not a
constant to flip.

Nothing reads the field yet. It is wired at both construction sites so the next
increment adds the refusal, not the plumbing.

**One boolean is deliberately not enough, and both review vendors said so.** It
cannot tell elicitation from sampling from roots, and it cannot tell a form
request from a URL-mode one. That is accepted here and closed in the increment
that first reads the field: MRTR.9 refuses per `inputRequest` method, which
needs the declared capability names on the context, not a bit. The bit is
correct for what it currently gates — nothing — and wrong for what will gate on
it, so it is replaced rather than extended when the reader lands. Recorded so
the next increment inherits the requirement instead of rediscovering it.

The same review raised the stdio half, claiming the gateway fails to persist
capabilities a legacy client declares at `initialize`. The weaker half of that
is true and the stronger half is worse: the gateway never reads them at all.
`handle_initialize` (`meta_mcp/mod.rs:1018-1037`) extracts the protocol version
and a profile hint and nothing else, and `client_capabilities` appears nowhere
in `src/`. So `false` at `server/mod.rs:1733` is the only answer available, not
merely the only one stored — reading and holding a legacy client's declaration
is new state, which is why it is not a constant to flip here. It belongs with
the legacy-client bridge increment, where a legacy client's capabilities first
matter.

### The seam, mapped

Line numbers against the current tree on `feat/MIK-7320-golden-fixture-fix`, so
a later reader can tell drift from error. The `invoke.rs` rows were re-read
after DE-3 changed those signatures; they are not the values 9f16fae8 carried.

| what | where |
|---|---|
| refusal to delete (the `if retry.is_retry()` arm only) | `router/handlers.rs:879-896` |
| the `if retry.is_malformed()` arm that STAYS | `router/handlers.rs:867-878` |
| `dispatch_to_backend` definition, 11 params | `meta_mcp/invoke.rs:1781` |
| its only call site | `meta_mcp/invoke.rs:923` |
| outbound params built here — siblings go here | `meta_mcp/invoke.rs:1902` |
| idempotency + cache writes, all AFTER the call site | `invoke.rs:793, 845, 1034, 1270` |

The four are not interchangeable, and decision 3 touches exactly one of them:

| site | what it does | under decision 3 |
|---|---|---|
| `:793` | `enforce` — cache read plus in-flight registration | untouched; runs before dispatch |
| `:845` | `mark_completed` on a response-cache hit | untouched; no backend call happened |
| `:1034` | `remove` on dispatch error | must also fire for `input_required` |
| `:1270` | `mark_completed` on success | the write that must be skipped |

An `input_required` result is neither a success nor an error today, so it falls
through `:1270` and would be cached as a final answer. That is the write
decision 3 suppresses.

The outbound shape is one line today:

```rust
let base_params = json!({ "name": tool, "arguments": arguments });
```

`inputResponses` and `requestState` are inserted into that object beside
`arguments`, never into it. That placement is the whole of MRTR.1's boundary
case: a tool whose own argument is named `requestState` is untouched, because
nothing ever writes inside `arguments`.

Two distinct shapes, easily conflated, and conflating them is the security
defect MRTR.2 names:

- `RetryFields` (`protocol/mrtr.rs:34`) is the **inbound** shape — what the
  client sent, including the gateway's own sealed token. Attacker-controlled.
- the **outbound** shape is the backend's own opaque state, recovered by opening
  that token. A second small struct, because reusing `RetryFields` here is what
  forwards a client-supplied string to a backend as if the gateway had issued it.

The mint belongs at the call site (`invoke.rs:923`), not inside
`dispatch_to_backend` and not in `handlers.rs`: it must run after the result
arrives and before the idempotency and cache writes below it, so an
`input_required` result can suppress both. That ordering is design decision 3,
and it is the reason for DE-1.
