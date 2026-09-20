<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# MRTR.12: stopping a `gateway_execute` chain at an interim round

## The defect

`execute_chain` (`src/gateway/meta_mcp/search.rs:505-555`) treats every `Ok`
as a completed step:

```rust
Ok(result) => results.push(json!({"step": idx, "tool": tool_ref, "result": result})),
```

A tool that comes back asking a question — `resultType: "input_required"` —
returns `Ok`, because a question is a successful result and not an error. Only
`Err` stops a chain. So the chain records the question as a completed step and
runs step `idx + 1`.

The worst case is a step held at the destructive-operation confirmation gate.
That step does not perform its action, and its successors execute as if it had.
Nothing in the response tells the caller which of the two happened.

This is not fixed by MRTR.11a. That row changes how a round is *presented*; it
does not change whether the loop continues.

## What the fix must do

1. Stop the chain at the first step whose result validates as an interim round.
2. Surface that round at the top level of the chain response, so the caller can
   answer it.
3. Let the caller answer and resume — running the steps that have not run, and
   **not** re-running the steps that have.

Point 3 is the whole difficulty. Re-running is not a conservative fallback: a
chain stops precisely when a step needs a human decision, and the steps before
it are exactly the ones most likely to have had effects.

## Design

### Reuse the sealed continuation envelope

`src/protocol/continuation.rs` already provides everything a resume needs, and
it is already the mechanism a single-tool interim round uses:

| Existing field | What it gives the chain |
|---|---|
| `principal_fingerprint` | only the caller who started the chain may resume it |
| `original_request_digest` | the resume must present the same chain, or it fails |
| `jti` + `ConsumedLedger` | single-use: a resume token cannot be replayed |
| `expires_at` | a stalled chain does not stay resumable forever |
| `backend_request_state` | the asking backend's own opaque state, verbatim |
| `hold_key` → `InFlight` | which exchange is open, carried not looked up |
| `purpose` | domain separation; a confirmation grant cannot resume a chain |

The chain adds **one** field to `Payload` and **one** variant to
`ContinuationPurpose`:

```rust
pub enum ContinuationPurpose {
    BackendInput,
    DestructiveConfirm,
    ChainResume,          // new
}

pub struct Payload {
    // …
    /// Index of the chain step that asked. Steps `0..next_step` have run.
    /// Absent on every envelope that is not a `ChainResume`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_step: Option<usize>,
}
```

`next_step` is sealed, like everything else in the payload. A caller cannot
move it, so a caller cannot make the gateway skip a step that never ran.

### What a resume may skip, and why that is safe

A resume skips steps `0..next_step` and runs `next_step..n`.

That is safe on three bindings, all of which already exist:

- `original_request_digest` covers **the whole `chain` array**, so a resume
  presenting a different chain — reordered, shortened, a substituted tool —
  does not redeem. Skipping is only ever relative to the chain that produced
  the token.
- `principal_fingerprint` binds the resume to the caller who ran those steps.
- `jti` is consumed on redemption, so a resume runs `next_step..n` once.

What the design deliberately does **not** do: it does not store the results of
steps `0..next_step` server-side. They are returned to the caller in the
stopping response (below), so nothing needs holding and the envelope does not
grow with the size of a tool's output.

### The stopping response

The chain stops and returns, at the top level of the tool result:

```json
{
  "steps": 2,
  "results": [ {"step": 0, …}, {"step": 1, …} ],
  "resultType": "input_required",
  "inputRequests": { "<id>": { … }, … },
  "requestState": "<sealed continuation token>",
  "pendingStep": 2,
  "pendingTool": "server:tool_name"
}
```

`inputRequests` is re-serialised as the keyed object the backend sent, not as
an array. `InputRequired::requests` holds `Vec<(String, Value)>`
(`src/protocol/mrtr.rs:206`) because the keys are the server's own and it looks
for exactly those again on the retry — its doc comment says an answer returned
under a different key "is lost as surely as one that was never collected"
(`:201-205`). A pair list serialised positionally would reach the client as
`[[id, request], …]`, from which no valid answer can be constructed.

`results` carries the steps that genuinely ran. `pendingStep` names the step
that asked — without it a caller reading `steps: 2` cannot tell whether step 2
failed, was skipped, or is waiting. The resumed call returns the same shape for
`next_step..n`; a caller that wants the whole chain concatenates the two. No
server-side result storage, no stitching in the gateway.

### One token, not two: the handoff from the step-scoped envelope

By the time `execute_chain` sees an interim result, a continuation has already
been minted for that step. `src/gateway/meta_mcp/invoke.rs:2348` calls
`mint_continuation(...)` with the backend's `request_state` and overwrites
`result["requestState"]` with the sealed envelope, so the backend's own opaque
string never reaches the client. The chain must not mint a second envelope
beside it: two redeemable tokens for one stop means a client can answer the
step without resuming the chain, and the chain without answering the step.

The chain re-seals that envelope rather than adding one. The `ChainResume`
token carries the same backend `request_state` the step-scoped one held, plus
the chain identity, `next_step`, `rounds_used` and the deadline. Exactly one
token is redeemable, and the step-scoped envelope is never emitted on the chain
path.

Redemption applies the caller's answers to the pending step **only**. The
retry context — the answers and the backend `requestState` — is cleared before
step `next_step + 1` runs, so a successor cannot inherit an answer collected
for its predecessor. A chain whose pending step is held at the
destructive-confirmation gate is the same case: the held state travels in the
one envelope and is redeemed once, at that step.

### Validation before promotion (the MRTR.11b rule, applied here)

A step's result becomes an interim round only if `InputRequired::from_result`
(`src/protocol/mrtr.rs:225`) accepts it. A backend that merely writes
`resultType: "input_required"` into its output does **not** get to stop a
chain or mint a continuation; that result is answered with an upstream tool
error naming the step. Two independent review seats rated the unvalidated
discriminator HIGH on the single-tool path, and a chain is the more valuable
target: stopping a chain mid-way is more disruptive than returning one bad
result.

### Bounding

A chain of `n` steps can stop at most `n` times *at distinct steps*, because
each stop seals a strictly larger `next_step`. That is not the whole bound: a
single step may ask again after being answered, sealing the same `next_step`
each time, and the per-exchange round bound that would otherwise stop it lives
inside the legacy bridge's `run` (`src/gateway/meta_mcp/invoke.rs:2158,2255`).
A native chain resume never enters the bridge, so it inherits nothing.

The envelope therefore seals two more fields: `rounds_used`, incremented on
every mint including a re-ask at an unchanged `next_step`, and the original
exchange deadline. A resume is refused once `rounds_used` reaches the
per-exchange cap or the deadline has passed, and a replacement envelope may
never reset either — both are copied forward, never re-initialised. Without
that, a backend that asks one question forever sustains an unbounded
continuation sequence at a single step.

### Interaction with the destructive-confirmation gate

`ContinuationPurpose` keeps the two apart. A `DestructiveConfirm` grant cannot
be presented as a chain resume, and a `ChainResume` token cannot stand in for a
confirmation. A step held at the gate stops the chain like any other interim
round; answering it resumes at that step, which then runs its confirmation
redemption normally.

## Failing tests this design owes

1. A chain whose step 1 of 3 asks: step 2 does not run, and the response
   carries `pendingStep: 1`.
2. A resume with a valid token runs steps 1..3 and does not re-run step 0.
3. A resume presenting a *different* chain is refused (digest binding).
4. A resume presented by a different caller is refused (fingerprint binding).
5. A resume presented twice is refused the second time (`jti` consumed).
6. A step whose result claims `input_required` but fails
   `InputRequired::from_result` **aborts** the chain: no token is minted, no
   successor step runs, and the caller gets an upstream tool error naming the
   failing step. The malformed claim is a fail-closed stop, not a resumable
   one — the earlier wording of this row read as licence to continue past it,
   which would let an untrusted backend run a chain's tail behind a control
   result nobody validated.
7. A step held at the destructive-confirmation gate stops the chain; its
   successors do not run.
8. Redemption invariants, one assertion each: `next_step` is present and in
   range for the sealed chain; the purpose is `ChainResume` and no other; the
   envelope matches the held exchange it claims. A redemption re-enters the
   pending step through its existing hold rather than invoking it afresh.
9. A destructive-gated step resumed across a chain performs its action exactly
   once. The `ChainResume` token resumes transport only; the confirmation grant
   stays independently bound and redeems normally. This pins the design's most
   dangerous interaction from both sides — no bypass, and no double execution.
10. A single step that asks again after being answered is refused once
    `rounds_used` reaches the per-exchange cap, with `next_step` unchanged
    across every one of those rounds.

## The three open questions, answered

1. **Completed results travel in the stopping response**, rather than being
   held for one array at the end. Holding them needs server-side storage keyed
   by continuation, an eviction policy, and a size bound on a value the gateway
   does not control; returning them needs none of those. The cost is that a
   caller wanting the whole chain concatenates two segments, which the
   `pendingStep` field makes unambiguous. Both review seats endorsed keeping
   accumulation on the caller's side. The consequence is a contract, not an
   inconvenience: the stopping response is the **only** durable carrier of the
   completed steps, so a caller must persist them before it redeems the
   continuation. The gateway cannot re-serve them.

2. **A resume may not shorten the tail.** The sealed
   `original_request_digest` covers the whole chain array, so a resume that
   dropped step 3 would be a different chain than the one authorised. Allowing
   it would mean re-authorising at redemption time — a second authorisation
   path on the resume route, which is precisely where a replay defence is
   cheapest to get wrong. A caller that no longer wants the tail abandons the
   envelope and issues a new chain; abandonment costs nothing, because the
   gateway stores no results.

3. **A legacy client never receives a top-level interim chain response.** The
   rule is the MRTR.11b rule applied to chains, with one addition. Where the
   client has the elicitation bridge, the question goes through the bridge as
   it does today and the chain continues in-process. Where it does not, the
   chain returns a step-scoped upstream error naming `pendingStep` and
   `pendingTool`, mints **no** `ChainResume` token, and runs **no** successor
   step. The failure mode this forecloses is the dangerous one: a legacy caller
   reading an apparently complete chain whose tail silently never ran.

## Where this stands

Design reviewed 2026-09-16 and amended for the findings. Every claim the review
disputed was re-checked against source before it was accepted; the citations
above are that check, not the reviewer's word. Next: the failing tests,
reviewed as tests, then implementation.

---

## Revision 2 — the resume half (proposed 2026-09-16, built 2026-09-17)

Revision 1 shipped the stop. Wiring the call site (`eba5a492`) exposed that the
resume half, as designed, cannot complete a stopped chain. Three independent
readings agree — the two review seats on the series and a re-read of the call
site — so this is a design gap, not a missing test.

### What is wrong

1. **The resume cannot complete the chain at all.** `ChainResumePlan` carries
   `next_step` and `rounds_used` and discards the redeemed envelope's
   `backend_request_state`. Worse, `execute_chain` hands each step the caller
   *verbatim* (`search.rs:551`), so the pending step re-presents the
   **chain-scoped** handle to `redeem_retry`: bound to `chain_digest`, and
   already spent by `plan_chain_resume`. Observed live — a resume returns
   `Chain step 0 (srv:ask) failed: continuation rejected`, pinned by the
   falsifier row below. Even reading past that refusal, the answers would not
   arrive: `run_step` builds `{server, tool, arguments}` only. The caller cannot
   route them through the chain array either — `chain_digest` binds the whole
   array, so a modified step is refused.
2. **The deadline resets on every re-ask.** `seal_chain_stop` is documented to
   copy the deadline, never re-initialise it. Its only caller hands it the
   *freshly minted step envelope* and patches `rounds_used` back in, so
   `expires_at` and `hold_key` come from that fresh mint each round. The rounds
   cap is the only real bound. Either the comment or the wiring was false; this
   revision makes the wiring true.
3. **Holds accumulate.** `plan_chain_resume` checks the held exchange is still
   open and never closes it, while the next `invoke_tool` opens a fresh one.
   Eight re-asks leave eight in-flight slots for one exchange, and a full
   in-flight table is a documented mint refusal (`invoke.rs:405`).
4. **A dead-end token is still minted.** The stop whose seal would set
   `rounds_used` to `MAX_CHAIN_ROUNDS` hands back a handle the next
   `plan_chain_resume` must refuse. The caller learns this one round later than
   it could.

### What changes

**Translate the chain handle into a step handle, then reuse the redemption path
verbatim.** The gateway already has one correct redemption: `redeem_retry`
checks purpose, binding, hold and ledger, and lifts `backend_request_state` into
the `OutboundRetry` that travels to the backend. The chain driver should feed
that path rather than grow a second one.

- `ChainResumePlan` gains `backend_request_state`, `hold_key` and `expires_at`.
- For the **pending step only**, `execute_chain` mints a `BackendInput` envelope
  bound to that step — digest `original_request_digest(server, tool, arguments)`
  — carrying the chain payload's `hold_key`, `expires_at` and
  `backend_request_state`. Carried, not re-opened: the exchange the backend is
  holding is the one `plan_chain_resume` just verified.
- The pending step is invoked with a substituted `RetryFields`:
  `request_state` = that envelope, `input_responses` =
  `caller.retry.input_responses` verbatim. **Successors get `NO_RETRY`**, which
  makes "answers apply to the pending step only" structural rather than
  asserted.
- `seal_chain_stop` carries `expires_at` from the *chain* payload on **every**
  seal after the first stop, not only on a re-ask of the same step: the deadline
  belongs to the exchange, so a chain that stops at two distinct steps must not
  extend it at the second. Its `backend_request_state` parameter is dropped —
  the only caller passes the field back unchanged, so it is carried like every
  other field.
- **`hold_key` is carried into the minted step envelope and nowhere else.**
  `redeem_retry` needs the hold open at its own route check
  (`invoke.rs:716`) and then closes it itself (`invoke.rs:747`) before the step
  runs. Every later stop therefore opens its own fresh hold through the ordinary
  mint. Carrying the key past redemption would seal a successor against a hold
  already `Gone`, and the next resume would be refused.
- A seal that would reach `MAX_CHAIN_ROUNDS` refuses with the cap's own named
  message instead of minting. `rounds_used` is read from the plan, never from
  the fresh mint.
- The minted step envelope, field by field: **fresh `jti`** (the chain payload's
  is spent at plan time, so a copy would fail the ledger on every resume); the
  caller's principal fingerprint; `backend_id` from the chain payload, which is
  what `retry_origin_backend` routes on; `next_step` cleared; `hold_key`,
  `expires_at`, `backend_request_state` carried.
- `NO_RETRY` means a fully empty `RetryFields` — `request_state` *and*
  `input_responses` cleared. Leaving the answers in place would forward them to
  every successor, which is the leak this bullet claims to close.

**Rejected:** dispatching the pending step through `accounted_dispatch` with a
hand-built `OutboundRetry`, the way the input bridge does. It reaches the
backend with the right fields and skips the firewall and authorization that
`invoke_tool` runs — a security regression for a shorter diff.

### What pins it

Seven rows. Three LIVE against a stub transport, four against the driver:

- a resume applies the answers to the pending step and not to its successor;
- exactly one redeemable handle exists per stop — read as "the stop response
  carries exactly one `requestState` and no other envelope token", since at a
  stop two unspent envelopes name the same hold;
- the successor did not execute;
- the deadline of a re-ask is the first stop's, not the re-ask's;
- a chain that stops at two *distinct* steps keeps the first stop's deadline at
  the second, and the answers reach the second step;
- two resumes in succession report `rounds_used = 2` at the second seal, and a
  seal at `MAX_CHAIN_ROUNDS - 1` refuses with the cap's named message;
- the same chain handle presented twice is refused on the second presentation.

The first is the falsifier: written against the current code it must fail.

### Review of this revision (2026-09-16)

Both seats returned SHIP-WITH-FIXES. The fixes above are theirs, with one
correction: both ranked "the hold leaks, because it is closed only at the next
seal" as the top finding, reasoning statically from the design text — one of
them recorded that it could not read `redeem_retry`'s tail. It closes the hold
itself (`invoke.rs:747`), so a resume routed through it frees the slot before
the step runs, and it is the design's own carry-the-key-onward rule that was
wrong. That rule is now inverted above.

### What shipped (2026-09-17)

The resume half is built, on the seven rows above. What the code names:

- `PendingChainInterim::with_retry` carries the redeemable handle into the
  step-scoped envelope that the retry mints, and nothing past redemption —
  `redeem_retry` closes the hold at `src/gateway/meta_mcp/invoke.rs:747`, so
  every later stop opens its own.
- `presented_resume` is the single reader of the presented handle: it validates,
  binds the chain digest, and refuses a second presentation of the same handle.
- `step_retry_for` mints a fresh `jti` per step and freezes `expires_at` at the
  first stop, so a re-ask inherits the exchange deadline instead of re-arming
  the 300s TTL.
- `chain_digest` widened to `pub(crate)` so the live rows bind the digest
  production binds, rather than a copy of it.
- `seal_chain_stop` keeps its `backend_request_state` parameter. The design said
  drop it; dropping it is a wider diff than the fix needs, and it is inert.

Two of the rows were mutation-checked rather than merely green:
`previous.rounds_used = 0` is caught by the two-stop row, and commenting out the
frozen-expiry carry is caught by `mrtr_12_a_later_stop_keeps_the_exchange_deadline`
(289s of re-armed TTL). That deadline row mints its handle by hand with
`deadline = now + 11`: two live stops mint inside the same second, so a row that
compares one live stop's `expires_at` to the next asserts nothing.
