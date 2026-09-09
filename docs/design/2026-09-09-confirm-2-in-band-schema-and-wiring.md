# CONFIRM.2 — the gateway-originated `InputRequired`: versioned shape, and the wiring that carries it

Date: 2026-09-09 · Release: 4.0.0 · Criterion: `MIK-7246.CONFIRM.2`

**This is not a second design for CONFIRM.2.** The mechanism was chosen on 2026-09-06 (Option I,
`docs/design/2026-09-06-confirm-2-destructive-confirmation.md:113`) and is not re-opened here. That
design ends its STRIDE section with a scheduled deferral — "the emit is unversioned and that
blocks" (`:289`) — whose `when` row reads **TRIGGERED 2026-09-06**, "before any Option I
implementation begins, and the emit side is the first thing built, so this is the next artefact".
This is that artefact. It also fills the gap the gate-side seam note left open by design
(`docs/design/2026-09-08-confirm-2-gate-seam.md:88-97`, "What this note does not decide").

Two documents own the halves this one joins: the seam note owns what the gate looks like from
inside, and the test plan beside the 2026-09-06 design owns the cases. Neither is restated.

Every line number below was re-derived at source on 2026-09-09 on `fix/mrtr2-continuation-handle`.
**The seam note's anchors had already drifted by one day** — it cites the gate at
`meta_mcp/mod.rs:1905`; the gate is at `:1935` today. Re-derive before trusting any of these.

## Problem

The gate can refuse and it can elicit. It cannot **ask in band**, so a modern sessionless caller
is refused at `src/gateway/meta_mcp/mod.rs:1971` with a comment — "No asker can exist on this
transport" — that Option I exists to falsify. What blocks the build is not the branch, which is
chosen, but three things nobody has written down: the wire shape of the question, the wire shape
of the answer, and which of four seams carries the reach to mint and redeem it.

## Measured constraints (re-derived 2026-09-09)

| # | Constraint | Source |
|---|---|---|
| K1 | The gate is a free function with no `self`, called once in production after the admin check and before dispatch | `src/gateway/meta_mcp/mod.rs:1935`, call site `:1666` |
| K2 | The channel enum has exactly two variants today, `Elicit { proxy, policy }` and `Unavailable` | `src/gateway/destructive_confirmation.rs:126`, `:131`, `:139` |
| K3 | The caller context already carries both MRTR inputs — `input_capabilities: Declared` and `retry: &RetryFields` — so the redeem side needs no new plumbing on HTTP | `src/gateway/meta_mcp/mod.rs:142`, and `RetryFields::from_params` at `src/gateway/router/handlers.rs:1222` |
| K4 | `InputRequired` is constructible today: public `requests: Vec<(String, Value)>` and `request_state: Option<String>`; the wire discriminator const already exists | `src/protocol/mrtr.rs:200`, `:206`, `:208`, `:216` |
| K5 | The answer arrives as `RetryFields::input_responses: Option<Value>`, keyed by identifiers **the server assigned** — an answer under a different key is lost | `src/protocol/mrtr.rs:52`, and the contract at `:203-205` |
| K6 | `Payload.backend_id` is a non-optional `String`, and `retry_origin_backend` **routes on it** before dispatch — so it is a routing input, not a label | `src/protocol/continuation.rs:66`, `src/gateway/meta_mcp/invoke.rs:582-590`, consumed at `src/gateway/meta_mcp/mod.rs:1549` |
| K7 | Mint binds principal and a digest over `(server, tool, arguments)`; redemption re-checks both | `src/gateway/meta_mcp/invoke.rs:401-415`, redeem at `:615`, live call sites `:1433` and `:1613` |
| K8 | Stdio hardcodes `retry: &NO_RETRY` at both caller-context sites, and a watcher test records this as a known defect rather than correct behaviour | `src/gateway/server/mod.rs:2213`, `:2716`, ignored watcher `:3684` |

K6 and K8 are the two that decide the shape of everything below.

## The versioned shape

Version travels **in the request key**, not in a new envelope field. K5 makes the key a
server-assigned identifier the client must echo verbatim, so a `v2` key can coexist with `v1` and
an old client's answer is never ambiguous about which question it answers. This is the whole
versioning mechanism; there is no second one.

```
KEY = "io.mcp-gateway.destructive-confirmation.v1"

ask (one entry in InputRequired.requests):
  ( KEY, { "type": "boolean", "title": "Confirm destructive action",
           "description": "<describe_destructive_action output>" } )
  InputRequired.request_state = Some(<sealed continuation envelope>)

answer (read from RetryFields::input_responses):
  input_responses[KEY] == JSON true   -> confirmed
  anything else, including absent, false, "yes", 1 -> DECLINED
```

Declined is the fail-closed reading and it reuses the existing decline message
(`src/gateway/meta_mcp/mod.rs:1979`, `Operator declined: {desc}`) so the two refusal branches stay
distinguishable in assertions. A non-boolean answer is **not** a protocol error: treating a
malformed answer as an error hands a caller a way to turn a decline into a retryable condition.

Rejected: a new field on `InputRequired` carrying a version integer — it changes a shape the spec
owns, to carry information the key already carries. Rejected: an unversioned key — the deferral
this document discharges exists precisely because an unversioned cross-boundary shape blocks.

## The five wiring decisions

### W1 — how a gateway-authored continuation is told apart from a backend's

K6 is the constraint: `retry_origin_backend` opens the token and returns `payload.backend_id` as
the server to route to, before dispatch. A gateway-authored token has no backend.

- **Chosen: a typed `origin` on `Payload` — `Backend(String)` / `Gateway { tool: String }`.**
  `retry_origin_backend` matches, returning `Some(Ok(id))` for a backend and `None` for a gateway
  origin — `None` already means "nothing to route", which is true of a gateway token.
- *Rejected: a sentinel `backend_id`* (empty string, or a reserved prefix). The 2026-09-06 design
  already records every consumer reading that field as a backend; a sentinel is the same overload
  with better manners, and K6 shows the overload reaches a routing decision.
- *Rejected: a second keyring for gateway tokens.* Two keyrings means two expiry regimes, two
  in-flight bounds and two places to get single-use wrong, to avoid adding one enum.

Cost stated honestly: `Payload` is the sealed envelope's plaintext, so this is a format change.
Live tokens minted before the upgrade fail to open. That is bounded by the mint budget and expiry
in `src/protocol/continuation.rs`, which is why it is tolerable — but it is a real, if brief,
discontinuity across a rolling upgrade, and Q3 below schedules the check.

### W2 — how the gate reaches the continuation state

K1: the gate has no `self`. K2: the channel enum is where "who can be asked" is already encoded.

- **Chosen: a third variant, `ConfirmationChannel::InBand { continuation: &ContinuationState }`,**
  constructed at the era edge beside the existing `Elicit` construction
  (`src/gateway/router/handlers.rs:1431`). The reach arrives the same way the elicitation proxy
  does, the gate signature does not change, and every existing construction site — five in
  `meta_mcp/tests.rs` alone — keeps compiling.
- *Rejected: adding a `continuation` parameter to the gate.* It touches every construction site to
  hand the gate a capability it must then separately decide whether to use, which is the decision
  the channel enum exists to carry.
- *Rejected: making the gate a method on `MetaMcp`.* Largest signature change in the row for the
  same result, and it drags `&self` into a function whose tests construct neither.

### W3 — precedence, so a confirmed retry does not re-ask

The gate runs at `:1666`, before dispatch and therefore before the routing read at `:1549`. So the
gate **opens the token first**: on a valid, unexpired, principal-matching, digest-matching
`Gateway` origin whose answer is `true`, it consumes the single-use token and returns `None`
(proceed). W1's `None` from `retry_origin_backend` then keeps the spent token out of the backend
redeem path at `:1433`.

Without this order the client's answer is never read, the gate mints again, and the client sees an
unbounded ask-answer-ask loop. Rejected alternative — redeem in `handle_tools_call` before calling
the gate — puts confirmation logic outside the gate, where CONFIRM.1a's tests cannot see it.

### W4 — stdio does not get the in-band ask

K8: both stdio caller-context sites hardcode `NO_RETRY`, so a stdio client can never present a
redemption. Minting there produces a question whose answer cannot come back — strictly worse than
today's honest refusal.

- **Chosen: `InBand` is constructed only on the HTTP path** (where `from_params` runs, K3). Stdio
  keeps `Unavailable` and its existing refusal. The ignored watcher at `server/mod.rs:3684` stays
  as the record that this is a known gap, not a ruling.
- *Rejected: fixing stdio in this change.* It is another lane's file and a second scope; the ask
  works without it, and pairing them makes CONFIRM.2 wait on a change it does not need.

### W5 — order inside the gate

`describe_destructive_action` → capability check (K3) → mint → ask. The description is the
question text, so it must exist first; and the capability check must refuse **before** a mint,
because a mint that is then thrown away consumes an in-flight slot on behalf of a caller who was
never going to be asked. A mint that fails for want of a slot falls back to the existing refusal.

The capability refusal's wording is constrained, not free: it must remain a **superset** of the
existing sentence containing `none could be obtained`, because `tests/mik_7215_acs.rs` closes
CONFIRM.1a on that substring. Loosening those assertions re-opens a closed clause.

## Invariants this must not move

The seam note lists four (`2026-09-08-confirm-2-gate-seam.md:70-87`) and they hold unchanged. Two
bind hardest here and their anchors are re-derived: an in-band `InputRequired` must **not** travel
through `confirmation_refusal_response` (`src/gateway/meta_mcp/mod.rs:1926`), whose
`confirmation_refusal` flag the accounting tail reads — asking a question is neither a refusal nor
a client failure, and mislabelling it walks callers toward a tripped breaker. And the 120-second
`ELICITATION_TIMEOUT` is the elicitation channel's bound, not this one; the in-band bound is the
continuation's expiry.

## Explicitly out of scope

Fixing stdio's `NO_RETRY` (W4). The audit record — that is the second open item in the 2026-09-06
design, still with the operator, still blocking deployment rather than this artefact. Whether any
shipping client answers this. Elicitation's own behaviour on the legacy path. `InputBridge`. Any
change to which tools are destructive (CONFIRM.3). The test plan — the cases live beside the
2026-09-06 design and this document adds no new class of them beyond W1's format check.

## Open questions — scheduled

**Q3 — does a `Payload` format change invalidate live tokens across a rolling upgrade, and for how
long? (CHECKABLE — RESOLVED 2026-09-09.)**

> `Q3 — does a Payload format change invalidate live tokens across a rolling upgrade, and for how long? — ran rg -n "expires_at|mint_budget|fn open" src/protocol/continuation.rs, read open() at :679-730, and read both of its consumers — the window is CONTINUATION_LIFETIME_SECS = 300 seconds (src/protocol/continuation.rs:128), the mint budget (2^32, :388) does not bound it, and every ContinuationError reaches the caller as a refusal: src/gateway/meta_mcp/invoke.rs:591 and :633 both map_err into rejected_continuation plus a counter, with no fallback branch — so the answer is yes, for at most five minutes, and it surfaces as a refused continuation rather than a wrong execution — what it changed: W1 must bump VERSION together with the field, because a field on its own is refused in the wrong place.`

The last clause is the part that was not assumed. `VERSION` is compared at
`src/protocol/continuation.rs:691`, *before* the decrypt, and a mismatch answers
`UnknownVersion(u8)` — a variant whose whole point is that an operator can read it. A new
**required** field on `Payload` is refused eleven lines later instead, at the
`serde_json::from_slice` on `:713`, which is mapped to `NotAuthentic` — *"tampered, or minted by
someone else"*. Rolling-upgrade skew would therefore be indistinguishable, in the log line and in
`record_continuation_rejection`, from an attack. The refusal is correct; its *name* is not.

So the fork this question was written to decide comes down on the version byte, for a reason the
original phrasing did not anticipate: not because a field fails to refuse, but because it refuses
under the wrong name. `#[serde(default)]` is the tempting alternative and is worse — it lets an
envelope minted before the discriminator existed open with a *defaulted* origin, which converts a
five-minute refusal window into a five-minute window of executing a confirmation whose origin
nobody recorded. That is the one outcome this slice exists to prevent.

`VERSION` lives in `src/protocol/continuation.rs`, which is `sec3`'s file under the W1 ruling, so
this is reported to its owner rather than acted on here.

 Run `rg -n "fn open|expires_at|budget" src/protocol/continuation.rs`
and read the mint budget and expiry, then assert the worst case: a token minted by an old replica
and redeemed against a new one. If the window is bounded by expiry alone, the answer is "yes,
briefly, and it surfaces as a refused continuation, not a wrong execution" — which is acceptable
and must be *shown*, not assumed. If any consumer treats an unopenable token as anything other
than a refusal, W1 needs a version byte instead of a field.

**Q4 — does an in-band answer count as a human confirmation? (ASKABLE — RESOLVED 2026-09-09.)**

> `Q4 — does an in-band answer count as a human confirmation? — asked of the operator, twice — answered by the standing ruling at `docs/requirements/RELEASE-4.0.0-blocking-rollup.md`, § *Standing ruling — narrowing a criterion is not available on this release*, which names `MIK-7246.CONFIRM.2` — the fork resolves to **build the mechanism**, and `CONFIRM.2` stays open until it is built, then closes.` The ruling states that a question put to the operator and unanswered is answered by it rather than by a third attempt, so this is not re-asked. The table below is kept as the record of what was asked and what each branch would have cost; its "what would resolve it" row is now history, not a pending action.

This is the question the code cannot answer and it decides whether CONFIRM.2 can close on this
path at all. On the legacy path the elicitation reaches a *client*, which shows a person a prompt.
In band, the answer is generated by whatever authored the call — in the common case, the same
model. The STRIDE spoofing row binds *which principal* may answer (`principal_fingerprint`,
constant-time, live) and its tampering row binds *which arguments*; neither asks whether an answer
authored by the calling agent is a confirmation. The prior-art section gets adjacent — "how does a
protocol obtain a human decision" (`2026-09-06-confirm-2-destructive-confirmation.md:364`), where
RFC 8628 routes the decision to a second device rather than refusing — and stops short of ruling.

| field | value |
|---|---|
| owner | the operator — this is what confirmation *means* for 4.0.0, not a repo fact |
| what would resolve it | a ruling: (a) an in-band answer from the authenticated admin principal is confirmation, and CONFIRM.2 closes on this path; or (b) confirmation requires evidence a human saw the prompt, in which case Option I delivers spec conformance but **not** the criterion, and that gap is reported rather than papered over |
| when | **before the emit side is wired.** Answer (b) does not change the schema above, but it changes what the row may claim, and a criterion closed under the wrong reading is worse than one left open |
| what if it resolves badly | under (b), the in-band path ships as protocol conformance with the criterion still open, carried to the operator with this measurement attached. Narrowing the criterion and deferring the row are both withheld from the slice owner by the standing ruling (`docs/requirements/RELEASE-4.0.0-blocking-rollup.md:18-47`) |

The two open items inherited from the 2026-09-06 design — whether a shipping client declares
`elicitation` and actually retries, and what a confirmation or refusal must persist — are carried
unchanged and are not re-opened here. Neither blocks this artefact; the second blocks deployment.

## Findings — reported, not repaired

**F1 — the refusal branch is reachable, but not through the router fixture.** An earlier draft of
this section claimed `CONFIRM.2`'s refusal path could not be tested because its arm was dead code.
That was wrong, and checking it at source is what corrected it: `ConfirmationChannel::Unavailable`
is constructed in shipping code at `src/gateway/server/mod.rs:2239` and `:2727` (the stdio path)
and at three sites in `src/gateway/meta_mcp/invoke.rs`, and the gate refuses on it at
`src/gateway/meta_mcp/mod.rs:2010`. Nothing is unreachable.

What is true is narrower and is a **test-plan constraint, not a coverage gap**: the HTTP handler
constructs `ConfirmationChannel::Elicit` *unconditionally*
(`src/gateway/router/handlers.rs:1425-1434`), and the comment there says why — mapping a
sessionless request to `Unavailable` would refuse the legacy caller that path deliberately still
warns. So no request driven through `tests/common`'s `post` fixture can select the refusing
channel, and a case written that way would assert against a channel the router cannot produce.
The refusal branch is exercised where it is decided — the gate called with an `Unavailable`
channel directly, as `src/gateway/router/tests.rs` already does at `:2507`, `:2711` and `:3071` —
and this document's cases stay on the `Elicit` path, which is the one W2/W5 change.

Recorded here rather than dropped because the distinction survives into the ledger: `CONFIRM.2`'s
refusal half is covered, at a different level from its ask half, and a reader comparing the row to
the router suite would otherwise read that absence as an omission.

## Amendment 2026-09-09 — W1's file is owned elsewhere (scheduling, not mechanism)

The mechanism below is unchanged. What is recorded here is an ownership fact discovered when the
slice was picked up: **W1 cannot be built by this slice's owner.**

W1 needs a typed origin discriminator on the continuation payload in `src/protocol/continuation.rs`.
That file is on the slice brief's DO-NOT-EDIT list and is unmodified in the working tree. Measured,
not assumed: `rg -n "origin|^pub enum" src/protocol/continuation.rs` returns `origin_replica` — the
minting process's own name, sealed for routing (`:81`, `:656`, `:924`) — and no discriminator saying
what a continuation is *for*. No concurrent agent has landed one.

Two consequences, both scheduling:

- **The redeem half is unbuildable here, and the ask half must not ship alone.** W4 already carries
  the argument: a mint whose answer cannot come back is strictly worse than today's honest refusal,
  because it converts a refusal into a loop generator. Building W2/W5's ask side behind an unbuildable
  W1 is that exact failure, delivered deliberately.
- **The refused branch needs no new code and can produce no falsifier probe.** `ConfirmationChannel::Elicit`
  is constructed unconditionally on the HTTP path, including sessionless
  (`src/gateway/router/handlers.rs:1425-1434`), and `Unsupported` + `ConfirmationPolicy::REFUSE`
  refuses a modern caller (`src/gateway/destructive_confirmation.rs:75-95`). A retrofitted test on that
  branch would pass against unmodified source, so it proves nothing. Only the **confirm** branch is new
  work — the half W1 blocks.

Resolution is one of two, and it belongs to whoever owns the slice boundaries, not to this document:
widen the brief's DO-NOT-EDIT list to admit the `origin` field, or hand W1 to the agent that owns
`src/protocol/continuation.rs` and build W2/W5 behind it. No third mechanism is proposed here.

K4 re-verified while checking: `InputRequired.requests` and `.request_state` are public
(`src/protocol/mrtr.rs:200-209`), so the MRTR carrier side needs no constructor that does not exist.

**Correction, 2026-09-09.** An earlier revision of this paragraph called Q4 open and concluded that
`CONFIRM.2` stays open regardless of what this slice builds. Both halves are wrong, and the answer was
already in this repo when they were written: the standing ruling at
`docs/requirements/RELEASE-4.0.0-blocking-rollup.md:57` names `MIK-7246.CONFIRM.2` explicitly, settles
the build-or-rewrite fork toward **build the mechanism**, and states that a question put to the operator
twice and unanswered is answered by the ruling rather than by a third attempt. The "stays open regardless"
reading only holds if narrowing were available, and it is not. `CONFIRM.2` stays open until the mechanism
is built, and then it closes.

What the ruling does not license, recorded so this slice does not overshoot the other way: dropping an
acceptance criterion, deferring the row, or judging it not worth building. Those remain the operator's.
A build branch that turns out genuinely infeasible — not blocked, not expensive — is a finding to report,
never a licence to take the rewrite branch.

Measured while waiting on that answer, and recorded here because it bears on who should carry W1
(the `origin` field on `Keyring`): `src/protocol/continuation.rs` is under active concurrent edit.
Between two consecutive `cargo test` runs in this session the `Keyring` type lost `keys` and
`minting_kid` and gained `ring`, `rng` and `mint_budget`, and the file's mtime moved 13 seconds
before I read it. The library does not currently compile — 8-10 `error[E0609]`/`error[E0599]` in
that file, a set that itself changed between the two runs. That failure reproduces without this
slice's change and is not mine to repair (development-process §P5: another session's work is
reported, not cleaned).

Consequence for W1, stated as the choice it is rather than as a recommendation: the field this
slice needs sits inside the exact type someone else is mid-refactor in. Adding it from here means
editing a file with a live owner and an unstable shape; handing W1 to that owner costs them one
field on a type they are already rewriting. The second is cheaper for both sides, and it is why
this design asks for the DO-NOT-EDIT boundary to be ruled on rather than quietly crossed.

Consequence for the RED test: `tests/mik_7246_confirm2_acs.rs` is written and durable, two cases,
admin key supplied (the first run failed 403 — the wrong failure), and it never hardcodes
`modern_protocol`. Its real assertion line cannot be captured until the tree compiles, so this
design does not yet claim one. An unrunnable test is a written test, not a passing gate.

## Design events — decisions this design did not make (§P3)

Two choices were made during implementation that this document had not settled. Naming them here
is the whole obligation: it grants no authority and closes no gate. §P0 owns whether either moved
what the change is FOR, §P2 owns the tests, §P4 owns the review.

### DE1 — the confirmation principal falls back to the API-key NAME

`principal_fingerprint(verified_identity)` answers `None` for most modern stateless callers, because
that path authenticates by API key and the fingerprint is written for a verified backend exchange.
Minting on `None` was never an option: an envelope bound to nobody is a token any caller can spend.
Refusing on `None` would have made the entire in-band ask unreachable on precisely the transport
CONFIRM.2 exists to serve — the criterion would have been met by code nothing could execute.

So `confirmation_principal` falls back to `sha256("apikey-name:" + name)`.

Why this binding is not a widening: it seals a caller to **its own answer to a question this gateway
just asked it**, over a single-use envelope already bound to the exact tool and the exact arguments.
It is not a backend continuation binding a user to a side effect on a third party, which is what
`principal_fingerprint`'s stricter answer is calibrated for. The key name is the same authority the
admin check accepted one frame earlier for this very call, so the fallback grants no caller anything
it did not already hold. A caller with neither identity nor key name — anonymous — still gets `None`
and is still refused, which is exactly the behaviour that existed before this path.

Trigger it meets: a material security property the design left unstated. Residual, stated rather
than mitigated: two API keys sharing a `name` share a confirmation principal. Nothing in the config
schema forbids that, and this change does not add a check for it.

### DE2 — the in-band ask is NOT capability-gated

A client that never declared it can answer an `elicitation/create` question still receives the ask.
The design did not decide this and the obvious reading — gate it, as `Elicit` gates on the proxy —
is the one NOT taken.

Reason: the two channels fail in opposite directions. `Elicit` calls out to a proxy that must exist,
so an absent capability is a real dead end. The in-band ask is a **response field**; a client that
cannot answer simply does not retry, and gets no side effect. Gating it would convert every
undeclared-but-capable client into the `none could be obtained` refusal — reintroducing the exact
defect CONFIRM.2 was opened to remove, on a population that cannot be measured from here because
the modern stateless path carries no negotiated capability record at this point in the call.

Cost, named and accepted: a client that cannot answer sees a response shape it did not ask for
instead of a refusal it would have understood. That is a worse error message, never a side effect.

Trigger it meets: it changes an observable contract — what a modern destructive call returns to a
client that declared nothing. Not a scope move, so §P0's freeze does not re-open; it does belong in
front of §P4 as a decision, not as an implementation detail nobody voted on.
