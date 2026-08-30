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

- the legacy-client bridge (`Bridge::to_legacy_client`) — asking a pre-2026 client a question
  mid-call needs a server-initiated request over the client's own transport, which is a second
  design. `to_legacy_client` stays unwired and stays out of the release claim.
- multi-replica continuation state (MIK-7312). Addressed here only by *deciding* it, below.
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

1. **The response side ships; the legacy bridge does not.** A 2026 client gets a working
   multi-round-trip call. A pre-2026 client gets what it gets today, and the release notes say so.
   Shipping half is what makes the other half's absence honest rather than hidden.
2. **Single-use stays process-local for 4.0.0, and is documented as such.** The deployment is one
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
- a token minted before the keyring is regenerated is refused after it, rather than opening
- a mint asking for a lifetime beyond 300 seconds gets 300, not what it asked for
- a malformed retry is refused without dispatching (the existing behaviour, kept)
- an interim result for an unauthenticated caller is refused, and nothing is minted
- an interim result whose `requestState` is absent completes, and the retry carries no `requestState`
- an input request of a type the client did not declare is refused before minting
- the backend observes a *different* JSON-RPC id on the retry than on the initial call
- a backend returning `input_required` a second time, on the retry, is refused

