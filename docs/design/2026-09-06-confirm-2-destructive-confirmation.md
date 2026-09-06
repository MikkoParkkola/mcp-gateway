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
| C4 | The admin gate runs **before** the confirmation gate. Every governed tool is already admin-only, so the real access control is the credential; the confirmation is "the confirmation an honest client offers its user". | `src/gateway/meta_mcp/mod.rs:1578-1584`; module header of `src/gateway/destructive_confirmation.rs` |
| C5 | `ConfirmationChannel::Unavailable` transports (stdio) refuse unconditionally and must keep refusing — stdio cannot answer a question it is being asked. | `src/gateway/meta_mcp/mod.rs:1874`, `:2656`; `src/gateway/meta_mcp/invoke.rs:3908,3938,3973` |
| C6 | **The MRTR continuation machinery is LIVE, not unwired.** `redeem_retry` is called on the production invoke path at `invoke.rs:1327`; `mint_continuation` at `invoke.rs:1559`. Both sit inside `invoke_tool`. | `src/gateway/meta_mcp/invoke.rs:376,529,1327,1559` |
| C7 | What *is* unwired for 4.0.0 is the **InputBridge** (MRTR.7a/7b, modern-backend → legacy-client), scored unwired in commit `f2bcbd1d`, blocked by MIK-7388, which blocks MIK-7212. | commit `f2bcbd1d`; MRTR.7a/7b rows in the requirements |
| C8 | A continuation `Payload` names **`backend_id`** — which backend holds the exchange — plus principal fingerprint, original-request digest, origin replica, jti, and the `InFlight` `hold_key`. `backend_id` is a `String`, so the type does not forbid a meta-tool name, but every consumer reads it as a backend. | `src/protocol/continuation.rs:64-98`, `:161-175` |
| C9 | The destructive-confirmation gate is a **free function**: `destructive_confirmation_gate(&id, tool_name, &arguments, session_id, &caller)`. It does not take `&self`, so it cannot reach `self.continuation` (`Arc<ContinuationState>`). Any mint/redeem at the gate is a signature change, not a call. | `src/gateway/meta_mcp/mod.rs:1830`; field `:230`; accessor `:508` |
| C10 | The gate fires on `tool_name` **before** `route_direct_backend_call`. A retry carrying a confirmation re-enters the gate and is refused again unless precedence changes. | `src/gateway/meta_mcp/mod.rs:1586-1596` |
| C11 | `InputRequired` has **public fields** (`requests`, `request_state`), so a gateway-authored one is constructible. But only `from_result` exists as a code path and the wire discriminator `RESULT_TYPE_INPUT_REQUIRED` is a private const — the emit side is unbuilt, not blocked. | `src/protocol/mrtr.rs:200-230` |
| C12 | Idempotency keys on `server:tool:hash(arguments)`. An InputRequired-shaped confirmation must not be cached as a completed call, and the key would have to include `inputResponses` + `requestState`. | `src/idempotency.rs:10` |

C6 is the constraint that moved this design. The work it inherited assumed the whole MRTR
client-facing retry path was unwired. It is not — only the bridge is. That makes Option I
materially cheaper than it first appeared, and it is why the recommendation below is a
question to the requester rather than a flat "defer".

## Options

### Option R — refusal *is* the modern-path answer (RECOMMENDED, conditional on Q1)

The gate stays as it is. A modern client asking for a destructive meta-tool gets a refusal
naming the reason and the channel that would work. §3.7's own preamble says "Each requirement
below therefore demands a *refusal*, not a computation", and CONFIRM.1a/1b read as
refusal-sufficient. C4 says the security posture does not regress: the admin credential is the
control, and the confirmation is courtesy an honest client extends to its user.

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
3. A `Payload` whose `backend_id` names a gateway meta-tool rather than a backend, and consumers
   that tolerate it (C8).
4. Gate precedence: a valid retry must be redeemed *before* re-entering the gate, or it loops
   (C10).
5. The MRTR.9/9a capability check against `caller.input_capabilities` (C3) — refuse to ask a
   question the client never said it could answer.
6. MRTR.8a/8b bounds on the confirmation continuation. `InFlight::new(replica, capacity)` and
   `Keyring::with_mint_budget` already provide bounded primitives; a client that never retries
   (which the spec permits, and which is the expected case here) must not leak state.
7. MRTR.10a/10b: the idempotency key must include `inputResponses` + `requestState`, and an
   InputRequired-shaped result must never be cached as a completed call (C12).

Cost: a protocol-surface addition late in the release, touching the continuation and idempotency
rows. Not rejected on merit — rejected, if it is rejected, on release timing (Q2).

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

Sequenced so that an answer to Q1 may make Q2 and Q3 unnecessary.

**Q1 — Does CONFIRM.2 accept a *refusal* as the modern-path answer for 4.0.0?**

- *Reading A — refusal satisfies it.* §3.7's preamble demands a refusal rather than a
  computation; CONFIRM.1a/1b read the same way; the admin credential (C4) is the actual control,
  so the security posture is unchanged. Consequence: the criterion closes with a documentation
  and test change, no protocol work.
- *Reading B — the words "so a modern client can confirm" require an affirmative path.* Refusal
  is not confirming. Consequence: Option I, a protocol-surface change late in the release.

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

**Q3 — is "a modern client cannot kill a server at all" acceptable product behaviour for
4.0.0?** This is the user-visible consequence of Reading A and it is a product call. Note it is
also the *current* behaviour, so answering no is a request for new capability, not a regression
report.

