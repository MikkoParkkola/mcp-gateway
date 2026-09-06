# CONFIRM.2 — a destructive meta-tool a modern client cannot confirm

Date: 2026-09-06 · Release: 4.0.0 · Status: DESIGN, awaiting requester answers (Q1-Q3)

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
question, and it is not the implementer's to settle (Q1, below).

## Measured constraints

Each row is a fact read out of the tree at the cited location, not an inference.

| # | Constraint | Citation |
|---|---|---|
| C1 | The modern path mints **no session**. The decision is recorded in source: minting one per request "grew a table of sessions nothing could reach, and handed the sequence-anomaly detector a fresh identity every call". | `src/gateway/router/handlers.rs:583-587` |
| C2 | The modern path **drops the subscription**, so there is no request-scoped channel back to the caller. The only send is `send_to_session`, which needs the session C1 does not create. | `src/gateway/router/handlers.rs:~604` |
| C3 | The gateway **does** know a modern client's declared input capabilities: `caller.input_capabilities`. | `src/protocol/meta.rs:406-411` |
| C4 | The admin gate runs **before** the confirmation gate. Every governed tool is *today* admin-only — a **snapshot**, not an invariant: CONFIRM.3 derives the governed set from `destructiveHint`, so a future destructive tool outside the admin set would falsify it, and CONFIRM.3 must preserve destructive ⊆ admin for Option R's argument to keep holding. On the snapshot, the real access control is the credential and the confirmation is "the confirmation an honest client offers its user". | `src/gateway/meta_mcp/mod.rs:1578-1584`; module header of `src/gateway/destructive_confirmation.rs` |
| C5 | `ConfirmationChannel::Unavailable` transports (stdio) refuse unconditionally and must keep refusing — stdio cannot answer a question it is being asked. | refuse: `src/gateway/meta_mcp/mod.rs:1866`; stdio assignment: `src/gateway/server/mod.rs:1874`, `:2656` |
| C6 | The MRTR continuation machinery is **live for backend-originated exchanges on the invoke path**: `redeem_retry` is called at `invoke.rs:1327`, `mint_continuation` at `:1559`, both inside `invoke_tool`. It is not unwired. What this does *not* say: the confirmation case is gateway-originated at a meta-tool gate, and C9/C10 show that site reaches neither. Option I therefore reuses the **primitives** (`Keyring`, `InFlight`, `Payload`) and **none of the call sites**. | `src/gateway/meta_mcp/invoke.rs:376,529,1327,1559` |
| C7 | What *is* unwired for 4.0.0 is the **InputBridge** (MRTR.7a/7b, modern-backend → legacy-client), scored unwired in commit `f2bcbd1d`, blocked by MIK-7388, which blocks MIK-7212. | commit `f2bcbd1d`; MRTR.7a/7b rows in the requirements |
| C8 | A continuation `Payload` names **`backend_id`** — which backend holds the exchange — plus principal fingerprint, original-request digest, origin replica, jti, and the `InFlight` `hold_key`. `backend_id` is a `String`, so the type does not forbid a meta-tool name, but every consumer reads it as a backend. | `src/protocol/continuation.rs:64-98`, `:161-175` |
| C9 | The destructive-confirmation gate is a **free function**: `destructive_confirmation_gate(&id, tool_name, &arguments, session_id, &caller)`. It does not take `&self`, so it cannot reach `self.continuation` (`Arc<ContinuationState>`). Any mint/redeem at the gate is a signature change, not a call. | `src/gateway/meta_mcp/mod.rs:1830`; field `:230`; accessor `:508` |
| C10 | The gate fires on `tool_name` **before** `route_direct_backend_call`. A retry carrying a confirmation re-enters the gate and is refused again unless precedence changes. | `src/gateway/meta_mcp/mod.rs:1586-1596` |
| C11 | `InputRequired` has **public fields** (`requests`, `request_state`), so a gateway-authored one is constructible. But only `from_result` exists as a code path and the wire discriminator `RESULT_TYPE_INPUT_REQUIRED` is a private const — the emit side is unbuilt, not blocked. | `src/protocol/mrtr.rs:200-230` |
| C12 | Idempotency keys derive from `SHA-256(tool_name ‖ canonical_json(arguments))`, and **the invoke path already appends a retry discriminator** hashing `inputResponses` + `requestState`, so two continuations of one call cannot fingerprint alike. What is *not* built is a cache at the confirmation gate at all: the gate runs on a path with no idempotency entry of its own. MRTR.10a/10b are therefore satisfied where invoke owns the key and untouched where the gate does. | `src/idempotency.rs:10-11`; `src/gateway/meta_mcp/invoke.rs:1164-1168`; `src/protocol/mrtr.rs:182-192`; `src/gateway/meta_mcp/support.rs:77` |

C6 is the constraint that moved this design. The work it inherited assumed the whole MRTR
client-facing retry path was unwired. It is not — only the bridge is. That makes Option I
materially cheaper than it first appeared, and it is why the recommendation below is a
question to the requester rather than a flat "defer".

## Options

### Option R — refusal *is* the modern-path answer (RECOMMENDED, conditional on Q1)

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
Today's refusal names the action and no channel: `destructive_confirmation.rs:246` emits
"Destructive meta-tool invoked without active SSE session", which tells a modern caller what it
lacks and not what would work. The criterion's test needs a wire oracle rather than a shape, so
the exact string is specified with the option: it must name the tool, say that this request's
declared protocol version has no confirmation channel, and name the channel that does have one.
Whoever implements R writes that string into the test, not into the log line only.

Cost: a documentation change, a test asserting the refusal shape on the modern path, and one
requirement-row edit.

**Why this is not a ruling I can make.** The requirement's own words are "so a modern client
**can confirm**". Refusal is not confirming. Adopting Option R therefore *changes what CONFIRM.2
asks for*, and per the repair protocol, eliminating or narrowing a requirement needs the
requester's recorded agreement before it happens — not the implementer's reading. Q1 is that
request.

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
   question the client never said it could answer.
6. MRTR.8a/8b bounds on the confirmation continuation. `InFlight::new(replica, capacity)` and
   `Keyring::with_mint_budget` already provide bounded primitives; a client that never retries
   (which the spec permits, and which is the expected case here) must not leak state.
7. MRTR.10a/10b: the retry discriminator that puts `inputResponses` + `requestState` in the
   key already exists on the invoke path (C12, `invoke.rs:1164-1168`) — this item inherits it
   rather than building it. What Option I adds is the rule that an
   InputRequired-shaped result must never be cached as a completed call (C12). Ordering is part
   of the requirement, not an implementation detail: the idempotency cache is consulted BEFORE
   the gate. At-least-once delivery means a client may retry a call whose confirmation was
   already redeemed and whose kill already succeeded; with the gate first, the continuation is
   spent, the second redemption fails, and the caller is refused an action that has already
   happened. Cache-first returns the recorded result instead.

Cost: a protocol-surface addition late in the release, touching the continuation and idempotency
rows. Not rejected on merit — rejected, if it is rejected, on release timing (Q2).

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

Two things follow, and both matter more than the option did:

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

## Audit record — the repudiation cell

Named because a destructive action whose confirmation leaves no record fails the R of the STRIDE
short-form, and the security pre-analysis (C6) did not cover it.

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
not to the option chosen, and it applies whichever branch the requester rules for.

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
- **Code.** Per §P1 this design contains none, and the option write-ups above are shapes, not
  signatures.

## Prior art (G16)

The question comparable systems have already answered: how does a protocol obtain a human
decision for a request whose caller holds no session? Asked late — this design was written
without it, and the omission is recorded rather than backfilled silently.

| source | shape | what it says here |
|---|---|---|
| RFC 9470, *OAuth 2.0 Step Up Authentication Challenge Protocol* (authoritative; cited by identifier, not fetched this session — I) | the server refuses with a challenge; the client re-issues the SAME request carrying the elevated proof | Option I is this pattern. The industry answer to "sessionless caller needs a stronger act" is challenge-then-reissue, not a minted session |
| RFC 8628, *OAuth 2.0 Device Authorization Grant* (authoritative; same caveat — I) | a human decision reached out-of-band while the client polls | the admin credential (C4) is our out-of-band surface; it is why refusal is defensible |
| in-repo: `destructive_confirmation.rs`, `continuation.rs`, `invoke.rs` (V, read this session) | elicitation for the session-bearing era; sealed single-use continuations for the modern one | NIH check: the mechanism Option I needs is already built. Nothing new is invented here, which is the strongest argument for Option I on cost |

NIH verdict: **no new mechanism is warranted.** Both live options reuse what exists.
Honest limit: the two RFCs are cited from knowledge, not fetched in this session, so they are
marked I. If either is misdescribed, the claim they support — that challenge-then-reissue is the
conventional shape — is the part to re-check.

## Assumptions, ranked by impact × uncertainty (G10)

| # | assumption | impact | uncertainty | rank | cheapest check |
|---|---|---|---|---|---|
| A1 | The requester reads CONFIRM.2 as Reading A, refusal satisfies it | decides the whole change | high — a question of intent, not fact | **1** | ask. It is Q1, outstanding |
| A2 | No client shipping in the 4.0.0 window both declares a modern version and exercises input responses | decides whether Option I has a consumer | high | **2** | U1, deferred with an owner |
| A3 | The continuation retry path is live on the production invoke path | turns Option I from a protocol build into a wiring job | low — measured | 3 | done: C6, `invoke.rs:1327,1559` |
| A4 | The admin credential is the real access control, so confirmation is courtesy | carries the security argument for Reading A | low | 4 | done: C4 |
| A5 | Every consumer of `Payload.backend_id` reads it as a backend | sizes Option I item 3 | low — measured, now repaired by a typed origin | 5 | done: C8 |

A1 outranks everything and is not the designer's to answer. That is why this design ends in a
question rather than a decision.

## Exit criteria (G18)

| criterion | value |
|---|---|
| **kill-metric** | Option I is killed if U1 returns no client that both declares a modern version and declares input capabilities within the 4.0.0 window. An affirmative path no client can walk is the cost this criterion exists to refuse |
| **pivot-trigger** | the requester answers Reading B on Q1, or answers Q3 that a version-scoped inability to kill is unacceptable product behaviour. Either flips the recommendation from R to I |
| **success-floor** | the criterion closes with a recorded requester ruling, a test proving the modern path cannot proceed unconfirmed, and no regression to the legacy path's warn-and-proceed behaviour. A design that ships without the ruling has not met the floor, whatever code lands |
| **time-box** | the ruling is wanted before the 4.0.0 requirements freeze; absent it, CONFIRM.2 defers out of 4.0.0 with a recorded deferral, which its own Source column already contemplates ("Depends on MIK-7212", itself blocked by MIK-7388) |

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
walks, and every minted continuation expires unredeemed.

| field | value |
|---|---|
| owner | the requester (MIK-7212 owner) — this is a client-ecosystem fact, not a repo fact |
| what would resolve it | name one 2026-protocol client that declares `elicitation` in its `initialize` capabilities *and* implements the multi-round retry; failing that, a decision to ship the surface ahead of clients |
| when | before any Option I implementation begins — it is the gate on Option I, not a parallel task |
| what if it resolves badly | Option I is worth building only as spec conformance, not as capability. Fall back to Option R and record CONFIRM.2 as met-by-refusal, or defer the row out of 4.0.0 |

U1 **blocks Option I**. Nothing depending on it may be implemented while it is open. Option R
does not depend on it and may proceed the moment Q1 is answered.

## Questions for the requester

Sequenced so that an answer to Q1 discharges exactly one of the two that follow — **not both**,
and which one depends on the answer. Reading A (refusal satisfies the criterion, the recommended
answer) makes Q2 moot and makes Q3 **required**, because refusal on the modern path is precisely
what Q3 asks the requester to accept. Reading B makes Q3 moot and makes Q2 required. An earlier
draft said an answer to Q1 "may make Q2 and Q3 unnecessary", which invited the requester to adopt
the recommendation while skipping the question the recommendation depends on. Corrected
2026-09-06 after a review finding.

**Q1 — Does CONFIRM.2 accept a *refusal* as the modern-path answer for 4.0.0?**

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

