# CONFIRM.2 — a destructive meta-tool a modern client cannot confirm

Date: 2026-09-06 · Release: 4.0.0 · Status: DESIGN, **fork closed 2026-09-06** — Option I is the
branch. Q1 answered by the standing ruling, Q3 moot with it, Q2's build half settled and its
defer half still the operator's alone. See *Fork closed*, below.

## The requirement, verbatim

`docs/requirements/RELEASE-4.0.0-requirements.md:198`:

> | MIK-7246.CONFIRM.2 | The gate MUST be reachable through the MRTR path, so a modern client can confirm. | Depends on MIK-7212 | T, D |

The Source column on that row is **"Depends on MIK-7212"**; the Evidence column asks for a test
and a design.

## Problem

Every destructive meta-tool (`gateway_kill_server` and its siblings) is refused unless the
caller confirms. Confirmation is collected over one channel: elicitation, which needs a
session. A 2026-protocol ("modern") client is **sessionless** on this path, so the gate has
exactly one answer for it today — refuse. The requirement says the gate must instead be
*reachable*, "so a modern client can confirm".

Two readings of that sentence produce different releases. That is the design's central
question, and it was not the implementer's to settle (Q1, below) — it has since been settled by a
standing ruling, recorded in the next section.

## Fork closed — Option I is the branch (2026-09-06)

`docs/requirements/RELEASE-4.0.0-blocking-rollup.md:18-47` carries a standing ruling for the whole
release: where a row offers *build the mechanism* or *rewrite the criterion so what exists already
satisfies it*, the recorded operator agreement is to build. It answers Q1 in the negative — a
refusal does not count as the modern-path answer — and it answers it without a third asking,
because the instruction the release runs under ("implement the full 4.0.0 scope, with all gaps
fixed with the full scope") is the recorded agreement the repair protocol requires before a
requirement may be narrowed, and it points the other way. Everything below stands as reviewed; the
options are kept because the reasoning that chose between them is what makes the choice
auditable, not because either is still live.

What the ruling does NOT license, and what therefore stays where it was: dropping an acceptance
criterion, deferring the row, or judging the build not worth doing. Those remain operator calls.
So U1 — the client-ecosystem unknown — does not become a licence to defer; it becomes a scheduled
unknown on the critical path, and its bad-resolution field says who hears about it rather than
what the slice may do unilaterally.

## Measured constraints

Each row is a fact read out of the tree at the cited location, not an inference.

| # | Constraint | Citation |
|---|---|---|
| C1 | The modern path mints **no session**. The decision is recorded in source: minting one per request "grew a table of sessions nothing could reach, and handed the sequence-anomaly detector a fresh identity every call". | `src/gateway/router/handlers.rs:583-587` |
| C2 | The modern path **drops the subscription**, so there is no request-scoped channel back to the caller. The only send is `send_to_session`, which needs the session C1 does not create. | `src/gateway/router/handlers.rs:~604` |
| C3 | The gateway **does** know a modern client's declared input capabilities: `caller.input_capabilities`. | field: `src/gateway/meta_mcp/mod.rs:142`; value derived by `RequestShape::declared_capabilities`, `src/protocol/meta.rs:406-411` |
| C4 | The admin gate runs **before** the confirmation gate. Every governed tool is *today* admin-only — a **snapshot**, not an invariant: CONFIRM.3 derives the governed set from `destructiveHint`, so a future destructive tool outside the admin set would falsify it, and CONFIRM.3 must preserve destructive ⊆ admin for Option R's argument to keep holding. On the snapshot, the real access control is the credential and the confirmation is "the confirmation an honest client offers its user". | `src/gateway/meta_mcp/mod.rs:1578-1584`; module header of `src/gateway/destructive_confirmation.rs` |
| C5 | `ConfirmationChannel::Unavailable` transports (stdio) refuse unconditionally and must keep refusing — stdio cannot answer a question it is being asked. | refuse: `src/gateway/meta_mcp/mod.rs:1866`; stdio assignment: `src/gateway/server/mod.rs:1874` |
| C6 | The MRTR continuation machinery is **live for backend-originated exchanges on the invoke path**: `redeem_retry` is called at `invoke.rs:1327`, `mint_continuation` at `:1559`, both inside `invoke_tool`. It is not unwired. What this does *not* say: the confirmation case is gateway-originated at a meta-tool gate, and C9/C10 show that site reaches neither. Option I therefore reuses the **primitives** (`Keyring`, `InFlight`, `Payload`) and **none of the call sites**. | `src/gateway/meta_mcp/invoke.rs:376,529,1327,1559` |
| C7 | What *is* unwired for 4.0.0 is the **InputBridge** (MRTR.7a/7b, modern-backend → legacy-client), scored unwired in commit `f2bcbd1d`, blocked by MIK-7388, which blocks MIK-7212. | commit `f2bcbd1d`; MRTR.7a/7b rows in the requirements |
| C8 | A continuation `Payload` names **`backend_id`** — which backend holds the exchange — plus principal fingerprint, original-request digest, origin replica, jti, and the `InFlight` `hold_key`. `backend_id` is a `String`, so the type does not forbid a meta-tool name, but every consumer reads it as a backend. | `src/protocol/continuation.rs:64-98`, `:161-175` |
| C9 | The destructive-confirmation gate is a **free function**: `destructive_confirmation_gate(&id, tool_name, &arguments, session_id, &caller)`. It does not take `&self`, so it cannot reach `self.continuation` (`Arc<ContinuationState>`). Any mint/redeem at the gate is a signature change, not a call. | `src/gateway/meta_mcp/mod.rs:1830`; field `:230`; accessor `:508` |
| C10 | The gate fires on `tool_name` **before** `route_direct_backend_call`. A retry carrying a confirmation re-enters the gate and is refused again unless precedence changes. | `src/gateway/meta_mcp/mod.rs:1586-1596` |
| C11 | `InputRequired` has **public fields** (`requests`, `request_state`), so a gateway-authored one is constructible. But only `from_result` exists as a code path and the wire discriminator `RESULT_TYPE_INPUT_REQUIRED` is a private const — the emit side is unbuilt, not blocked. | `src/protocol/mrtr.rs:200-230` |
| C12 | Idempotency keys derive from `SHA-256(tool_name ‖ canonical_json(arguments))`, and **the invoke path already appends a retry discriminator** hashing `inputResponses` + `requestState`, so two continuations of one call cannot fingerprint alike. What is *not* built is a cache at the confirmation gate at all: the gate runs on a path with no idempotency entry of its own. MRTR.10a/10b are therefore satisfied where invoke owns the key and untouched where the gate does. | `src/idempotency.rs:10-11`; `src/gateway/meta_mcp/invoke.rs:1164-1168`; `src/protocol/mrtr.rs:182-192` |

C6 is the constraint that moved this design. The work it inherited assumed the whole MRTR
client-facing retry path was unwired. It is not — only the bridge is. That makes Option I
materially cheaper than it first appeared, and it is why the recommendation below is a
question to the requester rather than a flat "defer".

## Options

### Option R — refusal *is* the modern-path answer (NOT TAKEN — the ruling closed against it)

The gate stays as it is. A modern client asking for a destructive meta-tool gets a refusal
naming the reason and the channel that would work. §3.7's own preamble says "Each requirement
below therefore demands a *refusal*, not a computation". CONFIRM.1a/1b are **not** support for
this option, and the design does not claim them: 1a already mandates a refusal when confirmation
cannot be obtained and 1b already forbids proceeding on a warning, so a CONFIRM.2 that also meant
"refuse" would restate the two rows immediately above it. That adjacency is evidence *against*
this reading of the text. What carries Option R is the product argument: C4 says the security
posture does not regress — the admin credential is the control, and the confirmation is the
courtesy an honest client extends to its user.

If Option R is chosen, the refusal **text is part of the deliverable, not a message detail**.
Today's refusal names the action and no channel. What a modern caller actually receives is the
wire string built by `confirmation_refusal_response` on the `ConfirmationChannel::Unavailable`
branch — "Destructive action requires confirmation and none could be obtained: {action}"
(`src/gateway/meta_mcp/mod.rs:1852-1857`, reached at `:1866`). It says the confirmation could not
be obtained and not what would obtain one. (An earlier draft cited the `NoSession` log line in
`src/gateway/destructive_confirmation.rs:245-249` here. That line is a `warn!` the caller never
sees, and it belongs to the elicitation path whose session went away — not to the modern path,
which never had one. A test written against it would assert on a log, not on the wire.) The criterion's test needs a wire oracle rather than a shape, so
the exact string is specified with the option: it must name the tool, say that this request's
declared protocol version has no confirmation channel, and name the channel that does have one.
Whoever implements R writes that string into the test, not into the log line only.

Cost: a documentation change, one requirement-row edit, a test asserting the refusal shape on the
modern path — and a code edit, which the earlier costing of this option omitted. The wire string
is a `format!` literal inside the `refused` closure that the `Unavailable` arm and the `Elicit`
arm both call (`src/gateway/meta_mcp/mod.rs:1847-1859`), so a modern-path-specific string means
either a second message path or threading the caller's declared version into that closure. Still
the cheaper of the two options by a wide margin; a shared closure is not a message detail.

**Why this is not a ruling I can make.** The requirement's own words are "so a modern client
**can confirm**". Refusal is not confirming. Adopting Option R therefore *changes what CONFIRM.2
asks for*, and per the repair protocol, eliminating or narrowing a requirement needs the
requester's recorded agreement before it happens — not the implementer's reading. Q1 was that
request, and the standing ruling answered it against this option.

Consequence if adopted: **a modern client cannot kill a server at all** in 4.0.0. That is a
product decision (Q3), not an engineering one.

### Option I — a gateway-originated `InputRequired`, redeemed on retry

The gate, instead of refusing, returns an `input_required` result carrying the confirmation
question. The client shows it to its user and retries the same call with `inputResponses` plus
the `requestState` envelope. The retry is redeemed, the confirmation is read out of it, and the
destructive tool proceeds. This is the only mechanism that lets a modern client actually confirm
without a session, and C6 means most of it already runs in production.

What it needs, all measured:

1. An emit-side constructor and serializer for a gateway-authored `InputRequired` (C11).
2. Mint and redeem at the gate — which today cannot reach `ContinuationState` because the gate
   is a free function (C9). Signature change, or move the gate onto the server impl.
3. A typed origin on `Payload`, because a gateway-authored continuation has no backend. NOT
   `backend_id` carrying a meta-tool name: C8 records every consumer reading that field as a
   backend, and `retry_origin_backend` (`invoke.rs:497-513`) routes on it before dispatch, so an
   overloaded value is a routing input, not a label. The discriminator is the repair; enumerating
   the consumers to tolerate an overload is not.
4. Gate precedence: a valid retry must be redeemed *before* re-entering the gate, or it loops
   (C10).
5. The MRTR.9/9a capability check against `caller.input_capabilities` (C3) — refuse to ask a
   question the client never said it could answer. That refusal's wording is **constrained, not
   free**: `tests/mik_7215_acs.rs:743` and `:990` close CONFIRM.1a by asserting the message
   contains `none could be obtained`, and both fixtures send exactly this caller (an empty
   `clientCapabilities`). The C3 refusal must therefore be a SUPERSET — the existing sentence,
   plus the missing capability named — because loosening those assertions would re-open a closed
   criterion silently, which is worse than a red test. The test plan carries the reasoning.
6. MRTR.8a/8b bounds on the confirmation continuation. `InFlight::new(replica, capacity)` and
   `Keyring::with_mint_budget` already provide bounded primitives; a client that never retries
   (which the spec permits, and which is the expected case here) must not leak state.
7. MRTR.10a/10b: the retry discriminator that puts `inputResponses` + `requestState` in the
   key exists as CODE — `RetryFields::key_discriminator`, used on the invoke path at
   `invoke.rs:1164-1168` (C12). Option I reuses that function and **inherits nothing else**:
   the gate is not on the invoke path and has no idempotency entry of its own, because
   `gateway_kill_server` never enters the funnel that calls `enforce` (the out-of-scope section
   measures this: sole production call at `invoke.rs:1177`). So cache-first at the gate is
   something Option I must BUILD, not something it gets. What it also adds is the rule that an
   InputRequired-shaped result must never be cached as a completed call (C12). Ordering is part
   of the requirement, not an implementation detail: the idempotency cache must be consulted
   BEFORE the gate. At-least-once delivery means a client may retry a call whose confirmation
   was already redeemed and whose kill already succeeded; with the gate first, the continuation
   is spent, the second redemption fails, and the caller is refused an action that has already
   happened. Cache-first returns the recorded result instead. An implementer who reads this item
   as inherited ships the gate with no cache at all, which is exactly that refusal.

Cost: a protocol-surface addition late in the release, touching the continuation and idempotency
rows — and, per item 7, a cache-first check at the gate that has to be BUILT. This line costed
that as inherited for as long as item 7 said it was inherited; item 7 was repaired and this line
was not, which is the same free-lunch reading one paragraph down. Not rejected on merit — rejected, if it is rejected, on release timing (Q2).

### Option I′ — the same thing, stateless, by signed token (COLLAPSES INTO OPTION I)

Raised in review: bind the answer in a signed token over (tool, arguments digest, principal,
expiry), carry it in `requestState`, make it single-use via the idempotency key, and hold no
server-side state at all. Costed rather than politely listed, because if it held it would beat
Option I.

It does not survive contact with the code, for the good reason that **it is already what Option I
uses**. `Payload` (`continuation.rs:64-85`) carries `principal_fingerprint`,
`original_request_digest`, `issued_at` and `expires_at` — principal, arguments digest, expiry,
and the tool binding — and `Keyring::mint`/`open` (`continuation.rs:408,473`) seal and verify it.
The client holds the envelope; the gateway does not store its contents. Option I′ is a
description of Option I's existing mechanism, not an alternative to it.

Three things follow, and each matters more than the option did:

- **The single-use mechanism the review proposed would have replayed, not refused.** `enforce`
  (`src/idempotency.rs:568`) returns `GuardOutcome::CachedResult(value)` on
  `AdmitOutcome::Completed` (`:582`) — a second presentation of the same key and fingerprint is
  served the first call's stored result. It refuses only `InFlight` and `Mismatch` (409) and
  `AtCapacity` (503). A confirmation token made single-use that way would let a replayed
  confirmation hand back the first destruction's result as though it were its own, which is the
  opposite of the property the proposal wanted from it. The burn that does refuse is
  `ConsumedLedger::consume` (`continuation.rs:595-611`) — server-side state, which is the next
  bullet.
- **Statelessness is not available, from either option.** Single-use redemption needs a record of
  what has been spent: `ConsumedLedger` (`continuation.rs:552-631`), a fixed-capacity table of
  spent identifiers under one replica's mutex. Drop it and the envelope replays. So the honest
  claim is not "no state" but **no new state class** — the ledger exists, is bounded, and is
  reused.
- **MRTR.8a/8b do not mandate server-side state; they bound it** (requirements lines 182-183:
  bounded in count, bounded in lifetime, reclaimed on abandonment). They therefore neither block
  this shape nor distinguish it from Option I. Reusing the bounded primitives satisfies them; a
  hypothetical stateless variant would satisfy them vacuously. Either way they are not the
  constraint that decides.

**It does not flip Q2.** The hope was that a stateless shape would turn the protocol-surface
addition into a small in-shape change. It does not: `Payload.backend_id` is non-optional and
every mint today names a backend, so a gateway-authored continuation is a genuinely new shape
whatever seals it. Q2 stands exactly as asked.

### Option B — route the confirmation through `InputBridge::run` (REJECTED)

**Dead on arrival.** Three independent reasons, any one sufficient:

- The bridge is UNWIRED for 4.0.0 (C7), scored so in `f2bcbd1d`.
- It is blocked by MIK-7388, which blocks MIK-7212 — the very ticket CONFIRM.2's Source column
  names as its dependency.
- Its direction is **modern backend → legacy client**. CONFIRM.2 needs **gateway → modern
  client**. It is not the same wire pointed the other way; it is a different wire.

### Option S — mint a session for modern requests and reuse elicitation (REJECTED)

Rejected by a decision already recorded in the source, not re-litigated here: per-request
session minting "grew a table of sessions nothing could reach, and handed the sequence-anomaly
detector a fresh identity every call" (`src/gateway/router/handlers.rs:583-587`). Reversing that
to serve one confirmation would reintroduce both defects for the narrowest possible benefit.

## Reversibility (G17) — which branch is a one-way door

Option R is fully reversible: it is the status quo plus a specified refusal string and a test.
Deleting it later costs the deletion, and nothing outside the gateway has come to depend on it.

Option I is NOT, and that is the half Q2 is really asking about. A released gateway-authored
`InputRequired` is a protocol surface clients build against; once one has shipped a retry that
redeems our continuation, withdrawing the surface breaks it, and no version bump un-ships it.
That makes a YES on Q2 a one-way door owing an ADR under `docs/adr/`, written before the surface
is added rather than after. It is not a new schedule: the versioned-emit deferral below already
gates the affirmative branch on a schema decision, and the ADR is the same decision's other half
— the schema says what the emit looks like, the ADR records that we accepted living with it.

## Audit record — the repudiation cell

Named because a destructive action whose confirmation leaves no record fails the R of the STRIDE
short form, and the security pre-analysis below reaches it only to say it is open. (That gate is
lettered C6 in the DoR. The `C6` in this document's constraint table is the MRTR-machinery
measurement and is unrelated — the two letter spaces do not correspond, and this paragraph
previously read as though they did.)

Today: nothing is recorded beyond a log line naming the tool. `destructive_confirmation.rs`
contains no occurrence of `principal` or `audit` (V, this session); the refusal path emits
`warn!(tool = ...)` and the internal `confirmation_refusal` marker read by the accounting tail
(`mod.rs:1821-1827`). Who was asked, what they answered, and which action it authorised are not
persisted anywhere.

What each option owes:

| option | what must be recorded |
|---|---|
| R — refusal | principal, tool, arguments digest, and that the call was refused unconfirmable. Cheapest of the three, and the one most likely to be skipped precisely because "nothing happened" — a refused kill is exactly the event an operator later asks about |
| I / I′ — affirmative | the above, plus the answer given, the identity that gave it (`principal_fingerprint` is already in the envelope), and the redemption that authorised the kill. The envelope already carries the binding; the record is what makes it reviewable after the fact |
| legacy path | unchanged, and unchanged is not the same as adequate. Called out so a later reader does not read this table as saying the legacy era already does it |

This is a gap the design NAMES, not one it closes. Closing it is a change to the gate's logging,
not to the option chosen, and it applies whichever branch the requester rules for. Naming a gap is
not scheduling one, so it is carried as **U2** in the deferred unknowns below, with the four fields
a deferral owes. It blocks DEPLOYMENT, never the choice of branch — which is now made: the branch
was choosable without U2 and is shippable only with it. Read the cost lines above with that attached — Option
R's "cheapest of the three" is cheapest *given* U2 is answered, and a refusal nobody can later
evidence is not the control it looks like.

## Security pre-analysis — STRIDE short form

The DoR security gate wants this before implementation, not after, and a review leg was right
that the document answered Q2 without it. It is written here for **both** live options, because
the requester has not ruled and a pre-analysis that assumes the answer is not one.

Trust boundary: the caller of a destructive meta-tool is authenticated as a transport peer and is
not thereby authorised to destroy anything — that is what the gate is for. Data locality local,
partition CP: a confirmation that cannot be resolved must refuse, never proceed. Input surfaces
today are the tool name and its arguments on the invoke path; Option I adds two, the
`inputResponses` map and the `requestState` handle a caller returns at the gate.

| | the threat, at this gate | mitigation, and whose bill it is |
|---|---|---|
| S | a caller other than the one asked answers the confirmation | R: no channel exists, nothing to spoof. I: `Payload::principal_fingerprint` is bound at mint and compared in constant time at redemption (`continuation.rs:75`, `:202-224`), and that comparison is live on the production retry path (`invoke.rs:556-570`). Inherited on the redemption path, not newly owed — what Option I owes here is the same thing the T row names, that the gate sits *on* that path rather than beside it |
| T | the arguments confirmed are not the arguments executed | `original_request_digest` is bound at mint and re-checked by the same `redeemable_by` call (`invoke.rs:565-570`), so confirming a kill of server A cannot redeem against server B. Inherited on the redemption path, not newly owed — what Option I owes is that the gate sits *on* that path rather than beside it |
| R | nobody can later show who authorised the kill | SCHEDULED as **U2** (deferred unknowns, below) — owner, resolving ruling, trigger and bad-resolution path are there, and the audit-record section above says what each option owes. Open in every option, blocking deployment of whichever is chosen; the one row in this table whose mitigation is a date rather than a mechanism |
| I | the handle or the refusal leaks more than it must | the refusal string names the tool, the declared protocol version and the channel that works (Option R deliverable); a continuation handle must stay opaque and must not carry arguments in cleartext into a log line. The envelope's `Debug` already redacts the fingerprint, the backend state and the request digest (`continuation.rs:100-116`) |
| D | the gate becomes a denial-of-service surface | the gate IS a DoS control, which is exactly what Q3 asks about. Option I adds unredeemed continuations; `InFlight` already bounds that store, so the bound is inherited rather than newly owed |
| E | a confirmation widens what the caller may do | the admin gate runs first **today** (C4) — and C4 is a snapshot, not an invariant: if CONFIRM.3's derivation stops preserving destructive ⊆ admin, this mitigation lapses with it, which is the dependency CONFIRM.3 is being asked to carry. A continuation must be redeemable for the one tool it was minted for, and confirmation must never enlarge the governed set |

Crypto: none new. No key agreement, no signature primitive, so the PQC gate is N/A by the
symmetric-only fast path — the existing `principal_fingerprint` and digest machinery is reused
unchanged.

### If the requester rules for the affirmative branch, the emit is unversioned and that blocks

A gateway-authored `InputRequired` is a message the gateway sends that no gateway sends today
(C9/C10). That is a cross-boundary shape, and the protocol-first gate refuses an unversioned one
before implementation, not at review. This design does **not** write that schema, deliberately —
writing it would pick the branch the requester has not picked. Scheduled, with the four fields:

| field | |
|---|---|
| owner | the requester, as part of ruling Q2 — it is the same decision |
| what would resolve it | a versioned schema for the gateway-originated `InputRequired` and for the `inputResponses` shape accepted back at the gate, reviewed as a protocol change |
| when | **TRIGGERED 2026-09-06** — the standing ruling settled Q2's build half, which is what this row waited on. Before any Option I implementation begins, and the emit side is the first thing built, so this is the next artefact |
| if it resolves badly | if the shape cannot be versioned inside the 4.0.0 window, Option I is not available in 4.0.0 — and since neither refusal-as-answer nor deferral is the slice's to elect, that is a finding carried to the operator with the measurement, not a quiet fall back to Option R |

Nothing that depends on this is implemented, which is the condition a scheduled deferral has to meet.

## Explicitly out of scope

- **stdio and every other `ConfirmationChannel::Unavailable` transport.** They refuse today and
  keep refusing under every option here (C5). A transport that cannot carry a question cannot be
  made to answer one.
- **The admin gate.** Untouched. It runs first and stays first (C4).
- **MIK-7212 / MIK-7388 and the InputBridge.** Not unblocked, not partially wired, not worked
  around by this design.
- **The legacy (session-bearing) confirmation path.** Unchanged in all options.
- **Any change to which meta-tools are destructive.** The set is what
  `is_destructive_meta_tool` says it is.
- **Backend and capability tools — out of scope, and by an operator decision rather than a
  derivation.** Raised after the first dual review, so this is a §P0 scope touch and is recorded
  as one; the bullet above it presupposes meta-tools and therefore does not cover it. CONFIRM.3
  says "The governed tool set MUST derive from the `destructiveHint` annotation"
  (`docs/requirements/RELEASE-4.0.0-requirements.md:199`), and neither it nor CONFIRM.1a, 1b or 2
  says whether that set is meta-tools only — all four rows are textually silent on the question.
  The code answers it deliberately, with its reasons in the doc comment on the governed-tool
  table `DESTRUCTIVE_META_TOOLS` (`src/gateway/destructive_confirmation.rs:196-200`): "Backend
  and capability tools are deliberately absent: they are not part of `meta_mcp_tool_defs.rs`,
  `infer_destructive_tool()` only guesses their hints by substring match, and
  `ConfirmationPolicy::for_modern()` is an unconditional refusal — governing them here would
  refuse a large slice of the tool surface with no confirmation path." Two consequences belong
  to the requester, not to this design:
  - **The third reason was coupled to Q1, and Q1 is answered.** It held only while refusal *was*
    the modern-path answer; the ruling chose Option I, so a confirmation path will exist and the
    reason evaporates rather than calcifying. It is spent, not load-bearing. The exclusion still
    stands on the other two reasons — no annotation source, a substring guess — which survive
    either ruling and are the ones that would cost real work. Anyone revisiting the exclusion
    should argue against those two; quoting the third is quoting a dead clause.
  - **The gate/cache ordering hazard is unreachable today.** A tool that is both
    destructive-annotated and backend-routing would place the confirmation gate and the
    idempotency cache in an order this design has not specified. No such tool exists. Two
    meta-tools route a caller's arguments to a backend tool, and both are annotated
    `destructive_hint: Some(false)`: `gateway_invoke` (`src/gateway/meta_mcp_tool_defs.rs:156`)
    and Code Mode's `gateway_execute` (`:707` via `write_non_idempotent_open_world_annotations`,
    `:278-284`). Code Mode's two tools are fed into the **scan** that derives the governed set,
    deliberately, because Code Mode replaces the traditional tool list rather than adding to it —
    but scanning is not governing, and with `destructive_hint: Some(false)` the scan does not
    select them. The governed set is `{gateway_kill_server}` today: the sole
    `destructive_hint: Some(true)` in `meta_mcp_tool_defs.rs` (`:259`, via
    `destructive_idempotent_annotations`) plus the floor, which names the same tool. Neither
    routing tool reaches the gate. The one meta-tool that is destructive-annotated is
    `gateway_kill_server` (`:309` via
    `destructive_idempotent_annotations`, `:254-263`), and it acts on a backend rather than
    routing a call to one: it is dispatched straight to `kill_server`
    (`src/gateway/meta_mcp/mod.rs:1616` -> `src/gateway/meta_mcp/invoke.rs:2766`), which touches
    only the kill switch, and never enters the invoke funnel that consults the idempotency cache
    (the sole production call of `enforce`, `src/gateway/meta_mcp/invoke.rs:1177`). The hazard
    becomes real on the first tool that is both, and not before.

  Disposal per §P0: **operator decision**. Not fixed here, not filed as a ticket, and not narrowed
  by this design — CONFIRM.3's silence is the requester's to resolve. Naming the ambiguity is the
  closure available at this level; closing the gap is not.
- **Code.** Per §P1 this design contains none, and the option write-ups above are shapes, not
  signatures.

## Prior art (G16)

The question comparable systems have already answered: how does a protocol obtain a human
decision for a request whose caller holds no session? Asked late — this design was written
without it, and the omission is recorded rather than backfilled silently.

| source | shape | what it says here |
|---|---|---|
| RFC 9470, *OAuth 2.0 Step Up Authentication Challenge Protocol* (authoritative; §1 fetched and read 2026-09-06 — V) | the resource server refuses with an `insufficient_user_authentication` challenge carrying `acr_values`/`max_age`; the client obtains the stronger proof and re-issues. **Correction from the fetch**: the client reaches back to a *separate authorization server* in between — the challenger and the asker are two parties, where our gateway is one | Option I is this pattern in its load-bearing half: challenge-then-reissue, not a minted session, is the industry answer for a caller who cannot be asked in place. The correspondence is a shape, not an isomorphism, and the difference is named rather than glossed |
| RFC 8628, *OAuth 2.0 Device Authorization Grant* (authoritative; §1 fetched and read 2026-09-06 — V) | confirmed as written: the human decision is reached out-of-band on a secondary device while the client polls. §1 adds a detail worth having — the grant exists precisely for clients with *limited input capabilities*, and its answer to one is to route the decision elsewhere, not to refuse | the admin credential (C4) is our out-of-band surface, so refusal is defensible. The added detail cuts slightly against us: 8628's device is exactly Option I's caller that declared no input capabilities, and 8628 does not refuse it. Recorded because it is the strongest available argument against item 5's refusal branch, and it should be argued at, not discovered later |
| in-repo: `destructive_confirmation.rs`, `continuation.rs`, `invoke.rs` (V, read this session) | elicitation for the session-bearing era; sealed single-use continuations for the modern one | NIH check: the mechanism Option I needs is already built. Nothing new is invented here, which is the strongest argument for Option I on cost |

NIH verdict: **no new mechanism is warranted.** Both live options reuse what exists.

**RESOLVED 2026-09-06 — the check ran.** Recorded in the §P1 checkable form:

> *Do the two RFC rows' "shape" columns survive their own sources?* — fetched
> `rfc-editor.org/rfc/rfc9470.txt` and `rfc8628.txt` and read §1 of each — **8628 confirmed as
> written; 9470 confirmed in shape but not in parties**, because its client goes to a separate
> authorization server between the challenge and the re-issue — **what it changed**: both rows
> move from I to V, the 9470 row now states the one-party/two-party difference instead of
> implying an exact match, and the 8628 row carries a point that argues *against* item 5's
> refusal branch rather than for it.

This is the second trigger this unknown had. The first — "before Q1's answer is written into the
requirement row" — **fired unrun** when the standing ruling answered Q1 on 2026-09-06, and was
re-booked to "before the Option I test plan is reviewed" rather than quietly re-dated, because a
trigger that passes unnoticed is the failure mode scheduling exists to prevent. That second
trigger is what this discharge answers: the plan (`2026-09-06-confirm-2-destructive-confirmation-test-plan.md`)
now goes to review with these rows verified rather than asserted.

It did not resolve badly. Had it — the claim that challenge-then-reissue is the conventional
shape falling — Option I would have lost its prior-art argument but not its cost argument, which
rests on in-repo mechanisms read this session. Option R was unaffected either way, which is why
this scheduled rather than blocked.

## Assumptions, ranked by impact × uncertainty (G10)

| # | assumption | impact | uncertainty | rank | cheapest check |
|---|---|---|---|---|---|
| A1 | ~~The requester reads CONFIRM.2 as Reading A, refusal satisfies it~~ **FALSIFIED** | decided the whole change | resolved | **1** | asked and answered: the standing ruling (`blocking-rollup.md:18-47`) closes the fork toward build. Reading B holds |
| A2 | No client shipping in the 4.0.0 window both declares a modern version and exercises input responses | decides whether Option I has a consumer | high | **2** | U1, deferred with an owner |
| A3 | The continuation retry path is live on the production invoke path | turns Option I from a protocol build into a wiring job | low — measured | 3 | done: C6, `invoke.rs:1327,1559` |
| A4 | The admin credential is the real access control, so confirmation is courtesy | carries the security argument for Reading A | low | 4 | done: C4 |
| A5 | Every consumer of `Payload.backend_id` reads it as a backend | sizes Option I item 3 | low — measured, now repaired by a typed origin | 5 | done: C8 |

A1 outranked everything and was not the designer's to answer. It has been answered against the
recommendation, which is the outcome a question exists to allow. What remains ranked #1 in
practice is A2/U1, and it no longer decides *whether* to build — only what the build is worth if
no client walks the path.

## Exit criteria (G18)

| criterion | value |
|---|---|
| **kill-metric** | ~~Option I is killed if U1 returns no client...~~ **RETIRED by the standing ruling.** A U1 that returns no client is now a FINDING carried to the operator, not a kill the slice may take: killing the row and deferring it are exactly the two moves `blocking-rollup.md:18-47` withholds. The measurement is unchanged and still worth running — what changed is who acts on it |
| **pivot-trigger** | **FIRED.** The ruling answers Q1 as Reading B, which is the trigger this row named; the recommendation flipped from R to I on 2026-09-06 |
| **success-floor** | the criterion closes with a recorded requester ruling, named tests, and no regression to the legacy path's warn-and-proceed behaviour. The tests, each named with the branch it belongs to — a floor demanding a refusal test of the branch that does not refuse is not a floor: **refusal branch (Option R) only** — `modern_path_refuses_unconfirmable_destructive_call`, asserting the wire string carries all three required contents (the tool, that this request's declared protocol version has no confirmation channel, and which channel does). Under Option I that assertion is false by construction: the version *does* have a channel and this caller did not declare it, so the affirmative branch's refusal case is the C3 capability refusal, a different string. **Affirmative branch (Option I) only** — `retry_after_redeemed_confirmation_returns_recorded_result`, which drives item 7's at-least-once scenario end to end: a redeemed continuation, a successful kill, a duplicate delivery, and the recorded result rather than a refusal. That test is the one that fails if an implementer reads item 7 as inheriting a cache the gate does not have. **Either branch, conditional on U2** — a test that the record U2's ruling requires is emitted for a refused kill. Conditional on purpose: U2's bad-resolution field accepts "4.0.0 needs no record" as a recorded residual, so a floor making this test unconditional would have decided U2 by making it a gate. If the ruling owes a record, this test is what makes "a refused kill is exactly the event an operator later asks about" a fact rather than a hope; if it owes none, the floor loses this row and nothing else. A design that ships without the ruling has not met the floor, whatever code lands |
| **time-box** | met — the ruling landed 2026-09-06, before the 4.0.0 requirements freeze. The clause that followed it ("absent a ruling, CONFIRM.2 defers out of 4.0.0") is spent and would now be wrong twice over: there is a ruling, and deferral was never the slice's to elect |

## Unknowns — every one scheduled

Format per §P1: resolved unknowns carry a recorded ANSWER; deferred ones carry all four fields.

### Resolved (checkable)

| Question | Check run | What came back | What it changed |
|---|---|---|---|
| Is the modern path sessionless? | `rg` + read `src/gateway/router/handlers.rs:583-604` | Yes — no session minted, decision recorded in source with its rationale | Killed Option S outright and made "reuse elicitation" undiscussable |
| Is there a request-scoped channel back to a modern client? | read `handlers.rs:~604`, searched for send paths | No — subscription dropped; only `send_to_session` exists | Ruled out every out-of-band confirmation; forced Option I to be *in-band* (a result, not a push) |
| Does the gateway know a modern client's declared capabilities? | read `src/protocol/meta.rs:406-411` | Yes — `caller.input_capabilities` | Made the MRTR.9/9a check in Option I a lookup rather than new plumbing |
| Does the InputBridge reach this? | `rg` on bridge symbols; commit `f2bcbd1d`; MIK-7388/7212 links | No — unwired, blocked, and pointed the other way | Option B rejected with three reasons instead of one |
| **Is the continuation retry path (`redeem_retry`) live in production, or unwired like the bridge?** | `rg -n "redeem_retry\|mint_continuation"` then read `invoke.rs:1327,1559` | **Live.** Both are called inside `invoke_tool` on the production invoke path | The largest change to this design: Option I is a wiring-and-precedence job on live machinery, not a from-scratch protocol build. Without this the recommendation would have been "defer, too expensive" |
| Can a gateway-authored `InputRequired` be constructed at all? | read `src/protocol/mrtr.rs:200-230` | Yes — public fields; only the emit path and the wire discriminator const are missing | Downgraded item 1 of Option I from "blocker" to "small" |
| Can the gate reach `ContinuationState`? | read `mod.rs:1830` (gate signature) against `:230`/`:508` | No — free function, no `&self` | Item 2 of Option I is a signature change; named as a cost rather than discovered during implementation |

### Deferred

**U1 — Does a modern client that declares in-band `elicitation` actually exist, and would it
retry?** MRTR.8b already records that the spec *permits* a client never to retry. If no shipping
client answers a gateway-authored `InputRequired`, Option I builds a confirmation path nobody
walks, and every minted continuation expires unredeemed. **On the critical path since the fork
closed** — it no longer decides whether to build, only what the build delivers.

| field | value |
|---|---|
| owner | the requester (MIK-7212 owner) — this is a client-ecosystem fact, not a repo fact, and nothing in the repo can settle it |
| what would resolve it | name one 2026-protocol client that declares `elicitation` in its `initialize` capabilities *and* implements the multi-round retry; failing that, a recorded decision to ship the surface ahead of clients. Either is an answer; only silence is not |
| when | **before the redeem path is wired**, not before the branch is chosen — the branch is chosen. Concretely: the emit side (Option I items 1-3) and the MRTR.9/9a capability check (item 5) do not depend on U1 and start now; items 4, 6 and 7 — precedence, continuation bounds and cache-first — are the ones whose worth turns on a client that retries, and they are where this unknown lands |
| what if it resolves badly | Option I is built as spec conformance rather than as delivered capability, and that is a FINDING carried to the operator with the measurement attached — not a fallback the slice takes. Falling back to refusal is narrowing the criterion and deferring the row is deferring the row; the standing ruling (`blocking-rollup.md:18-47`) withholds both from the slice owner. The operator may still elect either; the slice may only report |

U1 was written when it gated the choice of branch. It no longer does: the fork is closed and the
build proceeds. What it gates now is narrower and further in — see the `when` row — and it sits on
the critical path rather than beside it, because the branch it qualifies is the branch being
built. A deferral inherited from a fork that has since closed is a stale caveat, and this is the
edit that stops it becoming one.

**U2 — What must a destructive confirmation, or a refusal, persist?** The audit-record section
above shows nothing is persisted today beyond a log line naming the tool. Every option owes a
record; no option's cost line prices one; and that is how the cheapest branch came to read as free.

| field | value |
|---|---|
| owner | the requester (MIK-7212 owner) — what an operator must be able to reconstruct after a kill is a policy call, not a repo fact, and the record's contents follow from it |
| what would resolve it | a ruling on the minimum record — at least principal, tool, arguments digest and outcome; on the affirmative branch also the answer given and the redemption that authorised the kill. The emission then joins the chosen option's deliverable and its cost line, and stops being free |
| when | before the chosen branch DEPLOYS. Not before the branch is chosen — that is done — and not before the test plan: Option I was choosable without this and is shippable only with it |
| what if it resolves badly | a ruling that 4.0.0 needs no record is an accepted residual, recorded here as one with its reason, rather than left as an unremarked silence. It is not a finding that dies by being ignored |

U2 blocks **deployment** and blocks nothing before that, so it did not sit on the path to closing the
fork and does not sit on the path to the test plan.

## Questions for the requester

**Answered 2026-09-06 by the standing ruling; kept as the record of what was asked and how the
answer propagates.** Sequenced so that an answer to Q1 discharges exactly one of the two that
follow — **not both**,
and which one depends on the answer. Reading A (refusal satisfies the criterion, the recommended
answer) makes Q2 moot and makes Q3 **required**, because refusal on the modern path is precisely
what Q3 asks the requester to accept. Reading B makes Q3 moot and makes Q2 required. An earlier
draft said an answer to Q1 "may make Q2 and Q3 unnecessary", which invited the requester to adopt
the recommendation while skipping the question the recommendation depends on. Corrected
2026-09-06 after a review finding.

**Q1 — Does CONFIRM.2 accept a *refusal* as the modern-path answer for 4.0.0?** — **ANSWERED: no**
(standing ruling, `docs/requirements/RELEASE-4.0.0-blocking-rollup.md:18-47`, 2026-09-06). Reading
B holds; Option I is the branch. The two readings are kept below as the record of what was
weighed, and the recommendation below is preserved unedited — a recommendation the requester
overruled is evidence about this design's judgment, and rewriting it to agree with the answer
would delete that evidence. Consequence for the rest of this section: **Q3 is moot** (it asks the
requester to accept refusal as the product behaviour, which is the branch not taken) and **Q2's
first half is settled** — build the gateway-originated `InputRequired`. Q2's second half, deferring
the row out of 4.0.0, is not settled and is not the slice's to elect either way.

- *Reading A — refusal satisfies it.* §3.7's preamble demands a refusal rather than a
  computation; the admin credential (C4) is the actual control, so the security posture is
  unchanged. Consequence: the criterion closes with a documentation and test change, no protocol
  work.
- *Reading B — the words "so a modern client can confirm" require an affirmative path.* Refusal
  is not confirming, and the row's neighbours argue for this reading: CONFIRM.1a already mandates
  refusal when confirmation cannot be obtained and 1b already forbids proceeding on a warning, so
  a third row meaning "refuse" would say nothing the first two do not. Consequence: Option I, a
  protocol-surface change late in the release.
- *A third reading a reviewer may raise — "reachable" means the gate must not be bypassed on the
  modern path*, already true since the gate moved ahead of dispatch (C10, `mod.rs:1586`). The
  Source column answers it: a criterion satisfied by work already done would not read
  "Depends on MIK-7212".

*Recommendation: Reading A, adopted explicitly as a requirement change rather than as an
interpretation.* Reason: the confirmation is courtesy, not access control, and shipping a
protocol surface no client is yet known to exercise (U1) buys spec conformance at release-timing
risk. But Reading A narrows what was asked for, so it needs the requester's recorded agreement —
which is exactly why this is a question and not a decision already taken.

**Q2 — if Reading B: is a gateway-originated `InputRequired` an acceptable 4.0.0 surface
addition, given MIK-7212 is blocked by MIK-7388?** Either ship it as a scoped new shape (the
continuation machinery is already live, C6), or defer CONFIRM.2 out of 4.0.0 with a recorded
deferral. CONFIRM.2's own Source column says it depends on a blocked ticket, so deferral is
consistent with the row as written.

**Q3 — is "a request declaring a modern protocol version can never kill a server" acceptable
product behaviour for 4.0.0?** This is the user-visible consequence of Reading A and it is a
product call. Note it is also the *current* behaviour, so answering no is a request for new
capability, not a regression report.

*Corrected 2026-09-06, after a review finding, verified at source.* An earlier wording said "a
modern client cannot kill a server at all". That is over-broad. The inability belongs to the
REQUEST, not to the client: `handlers.rs:574-588` computes `declares_modern_by_header` per
request and, when true, sets `session_id = String::new()` and discards the incoming
`mcp-session-id` header, so elicitation has nowhere to go; the legacy branch
(`handlers.rs:589-597`) reuses the caller's session as before. A client able to issue a legacy-era
request therefore keeps the session-bearing kill path, and only a client that can issue nothing
else is unable to kill a server at all. One edge for whoever answers: `handlers.rs:572` resolves a
request carrying BOTH version headers to modern, so the legacy path needs the legacy header
alone.

