# MIK-7272.SUB.4 — idempotency protection for reissued side-effecting calls

Status: proposed, revision 9. Route 1 is built (`7851736d`); route 2's carrier is built and
uncommitted (rev 7); route 3 is unbuilt and acquires its design section in rev 8.
Revisions 1 and 2 were reviewed by GPT-5.x and Grok; both returned `SHIP-WITH-FIXES` on revision 2.
Revision 3 was the repair. Revision 4 settles the last question a check could settle, and records
what happens to the two that need a person.

§P4 REVIEW OF REVISION 6 (2026-09-08) — BOTH LEGS BACK, BOTH `SHIP-WITH-FIXES` (rc=0 each, verdict
read from the ledger trailer, never scraped from the body — §PA). `gpt-review`'s headline: *the
design mistakes an already reachable idempotency guard for dormant machinery*; confirmed at source,
and the dormancy paragraph is retracted above. `kimi-review` named P7's decided fix having no
test-plan row and the TTL assumption deferred without §P1's four fields. Both are repaired in
`8e1cd764` together with the route-1-outran-the-gate precedent, and none of the three moved a
decision. An earlier draft of this paragraph recorded kimi PENDING: that leg had produced zero bytes
and had not exited when the sentence was written. True then, false now — corrected here rather than
left to be read as the current state.

GATE OUTPUT FOR THIS ROUND, pinned to commits, so the verdicts above rest on evidence a reader can
re-run rather than on the assertion that they were run.

- Code: `3549d7d9` (the retry key carries the caller), `b8ded618`, `7f836088` (the first commit's own
  fmt debris), `4645998b` (`CallerIdentity::select` — one spelling of which identity a key belongs
  to). Documents: `8e1cd764`, `9ceaeb54`, and this commit.
- `cargo test --lib`: 4083 passed, 0 failed, 4 ignored, 30.02s.
- `cargo fmt --check`: clean.
- `cargo clippy --all-targets -- -D warnings`: RED, and NOT on this change. The single error is
  `more than 3 bools in a struct` in `tests/nfr_sec1_controls`, whose owner is `ext1-otel1` per R26.
  Recorded as inherited rather than reported as green: `tests/nfr_sec1_controls.rs` was last
  written by `1b0393c8`, which is an ancestor of `3549d7d9`, so the error stands without any of
  these commits.
- Mutation evidence is two hand-run falsifier probes, not a mutation tool: removing the length prefix
  from the key turns three forgery tests red, and unwiring the verified identity at the production
  call site turns the production-path test red on *bob was served alice's stored result*.

Two of that review's findings DIED AT SOURCE and produce no repair, recorded here so the next round
does not re-raise them. Both leaned on an acceptance criterion `MIK-7272.SUB4.STDIO.OWNER.1/3/5`
(cited in the Axis 3 CRITICAL and the Axis 4 HIGH). No `.OWNER.` criterion exists anywhere in
`docs/`; the `MIK-7272.SUB` family stops at `SUB.4` with no such children; and `gpt-review` reads
the tree, not Linear, so it had nowhere to read one. The reviewer invented the authority it faulted
the design against. The underlying question — should a keyless write execute? — is answered
deliberately at Axis 3 and is the trade the review was explicitly asked to attack; attacking it by
inventing a criterion that forbids it is not an attack on the trade.

Revision 5 is NOT reviewed. It is P8, P9, the "Risks that fire on activation" section and the
test-plan transfer, which arrived 2026-09-06 from the MRTR.8b/10a design when that change withdrew
its Change B, plus the reference corrections of the same date. No reviewer has seen any of it: the
`SHIP-WITH-FIXES` above is a verdict on revision 2 and says nothing about this material. It rides
the next dual-vendor design review.

Revision 6 (2026-09-08) folds in `docs/design/2026-09-08-sub4-idempotency-wiring.md`, deleted in
the same commit (H2 UPDATE > CREATE). That document was a narrower re-derivation of this one's
Axis-1 conclusion, written without knowledge of it. What came across: the boot-path wiring landed
as `7851736d`, the config-gate ruling of 2026-09-08, the stdio route as a route of its own, the
two landed test rows with their falsifier-probe evidence, and the MRTR.10b ledger coupling. What
did NOT come across is its arithmetic: it said "two changes", and there are three routes. Its line
references were re-anchored against the tree at `8889e270` rather than copied — five of them were
stale, and one ("stdio hardcodes an absent retry at `:2633` and `:3671`") would have cited a test
as evidence about production. Revision 6 is also unreviewed, and rides the same review as
revision 5; the code for route 1 landed ahead of it, which is recorded as an open item below
rather than smoothed over.

## Scope

FOR: deciding how a side-effecting call, reissued after a broken stream with a new request id,
becomes protected — which is what MIK-7272.SUB.4 requires. There are THREE routes into the
gateway, not two, and the criterion goes MET only when all three are covered: the generic
`tools/call` meta route (wired 2026-09-08, `7851736d`), stdio, and the direct `POST /mcp/{name}`
backend route. The folded document said "two changes"; that was a route short by one, corrected
here as it was folded.

OUT:
- the tasks extension (MIK-7272.TASK.1, ABSENT). It is the criterion's other branch and a far
  larger surface; this design neither builds it nor depends on it.
- idempotency key *derivation* as an algorithm. `derive_key` and `RetryFields` exist and are
  tested. What is in scope is *when a key is derived at all*, and *what it is bound to*.
- gateway-derived keys. The key is client-supplied BY DESIGN
  (`src/gateway/meta_mcp/support.rs:21-34`): a key the client never chose cannot express which
  repeats are deliberate, so deriving one would make an identical second call — a retry the user
  asked for — silently return the first result. The JSON-RPC request id plays no part either;
  the fingerprint is over server, tool and arguments plus the retry discriminator
  (`invoke.rs:1234-1238`), so a fresh request id is already transparent. Axis 3 below already
  rejects automatic derivation; this bullet adds only the request-id half.

## Problem

The idempotency machinery was complete and unreachable, and it had no way in. As written below
this was true of every build that had ever shipped; route 1 was repaired on 2026-09-08
(`7851736d`) and the tense is kept so the reasoning stays readable, with the state after the
repair stated at the end of the section.

- `MetaMcp::idempotency_cache` is initialised to `None` in `MetaMcp`'s constructor
  (`src/gateway/meta_mcp/mod.rs:464`), and that was its only initialiser.
- Its only populator, `MetaMcp::enable_idempotency` (`src/gateway/meta_mcp/mod.rs:685`), had zero
  PRODUCTION callers: `rg --hidden --no-ignore 'enable_idempotency' .` returned its own definition
  and one call from `src/gateway/meta_mcp/tests.rs`.
- No configuration key gates it: `rg -n 'idempotency' src/config/mod.rs` returns nothing.
- It carried `#[allow(dead_code)]`, which silenced the warning the `-D warnings` gate would
  otherwise have raised. That the attribute is *why* it survived is inferred (I), not read.

So the enforcement site in `invoke_tool` took the `None` branch in every build that had ever
shipped.

**State after `7851736d`.** `Gateway::build_meta_mcp` — the ONLY production construction site,
every other `MetaMcp::new` sitting inside `mod tests` (`src/gateway/server/mod.rs:2222`) — now
calls `enable_idempotency` unconditionally at `src/gateway/server/mod.rs:742`, and
`#[allow(dead_code)]` is gone. Both HTTP and stdio entry points route through that builder (`run`
at `:809`, `run_stdio` at `:1545`), so "inert in every deployment" is falsified for both
transports. That does NOT protect stdio, for the separate reason below: its client's key never
reaches the funnel.

Two further gaps compound it, both found in review and verified at source.

**Undocumented, but NOT unreachable — corrected 2026-09-08 against source.** The
carrier is UNDISCOVERABLE, and revision 6 wrongly read that as UNREACHABLE. It is not.
On route 1 a client that knows the field can send a key TODAY and be protected by it. The
whole chain is read at source, no hop inferred:

```
POST /mcp  tools/call        src/gateway/router/handlers.rs:1220
  RetryFields::from_params   src/protocol/mrtr.rs:117  <- reads params["_meta"][IDEMPOTENCY_KEY_META]
  retry: &retry             src/gateway/router/handlers.rs:1401
  handle_tools_call          src/gateway/meta_mcp/mod.rs:1599
  "gateway_invoke" => invoke_tool   src/gateway/meta_mcp/mod.rs:1682
  invoke_tool -> invoke_tool_traced src/gateway/meta_mcp/invoke.rs:831,840
  idempotency_key_for        src/gateway/meta_mcp/invoke.rs:1218, support.rs:35-44
```

`from_params` reads the key straight off the client's own `tools/call` params, and since
`7851736d` made the cache `Some`, the enforcement site no longer takes the `None` branch. So
the guard is LIVE IN PRODUCTION on route 1 as of that commit. What is missing is DISCOVERY —
the field appears in no tool schema — not reachability.

Two consequences the previous wording hid, and they are the reason this correction is a §P0
scope move rather than a typo fix:

1. This change is no longer *activating dormant machinery*. It is *finishing a live path*.
   Every ordering argument below that rests on "nothing is protected yet, so order is free"
   is void and re-decided on its own terms.
2. Defects on that path are shipped defects, not pre-activation concerns. There is no
   pre-activation window left in which to fix them quietly, and no operator disable switch
   to reach for. The gate on any defect found in `invoke_tool_traced`'s idempotency handling
   moves from BEFORE-PRODUCTION to NOW.

"Enforce only on an explicit client key" IS therefore an available option on route 1 — it is
in force. It remains unavailable on stdio and on the direct route, which is a statement about
those two routes and not, as revision 6 had it, about the design as a whole.

**The direct route bypasses the machinery entirely.** `POST /mcp/{name}`
(`backend_handler`, `src/gateway/router/backend_handlers.rs:434`) does not go through
`invoke_tool_traced` and never reaches `idempotency_key_for`, whose sole call site is
`src/gateway/meta_mcp/invoke.rs:1218`. CORRECTED 2026-09-08, against source: those two
references were re-anchored, and the bypass is now acknowledged in the route's own code —
`backend_handlers.rs:739` carries an ADR-008 INV-2 comment stating that the direct backend route
bypasses `invoke_tool_traced`. Revision 1 attributed the bypass to "ADR-008 rung 2"; that was a
misreading. ADR-008 rung 2 is client-native OAuth passthrough and says nothing about HTTP
routing. No ADR sanctions the bypass; INV-2 records it, which is not the same thing.

**stdio discards the client's key before dispatch.** The stdio caller context hardcodes
`retry: &crate::protocol::mrtr::NO_RETRY` (`src/gateway/server/mod.rs:2200`), so
`caller.retry.idempotency_key` is absent by construction and a key the client did send is thrown
away before the funnel ever sees it. ONE production site, corrected against source 2026-09-08:
the folded document said `:2633` and `:3671`, and neither was ever production — the tree's only
sibling `NO_RETRY` context is `:2703`, inside `mod tests` (`#[cfg(test)]` at `:2221`), and
`:3671` is the `#[ignore]` attribute on the watchdog
`stdio_should_present_a_retry_when_the_context_declares_one` (`:3672`), the row that un-ignores
when this route lands. A two-site claim would have cited a test as evidence about production.
This seam has its own design — `docs/design/2026-09-02-cluster-g-stdio-dispatch-parity.md` §P3 —
and before starting it, establish whether that lane already builds `RetryFields` at the
convergence point; if it does, we consume its work rather than duplicating it.

**Out of scope, found while rebasing the above (two disposals, §P0).** Seven other documents
still cite `resolve_idempotency_key` by name. The function does not exist in `src/`.

`RELEASE-4.0.0-gap-plan.md` and `RELEASE-4.0.0-execution-plan.md` get the **ticket** disposal, on
the existing MIK-7408 rather than a new one: they are planning documents that feed what gets built
next, so a human has to decide whether the work they describe against a deleted function still
exists. That is a decision, which is what separates the fourth disposal from the third.

`audit-notes/criteria-mrtr.md` and the four sibling designs get the **observation** disposal.
They are records of what was true when written; nothing is decided from them, so the repair is a
mechanical staleness sweep and recording it here is enough. It is recorded rather than fixed
because editing four other designs to repair this one is the second hop §P0a exists to stop.
Stale citations of a deleted symbol are model input, so the cost of leaving them is not zero.

## The cache cannot simply be turned on — seven prerequisites

Review found seven defects in the existing implementation. Each was verified at source. Wiring
the cache without fixing them ships a regression, so they are prerequisites, not follow-ups.

**P1 — enforcement is not atomic.** `enforce` (`src/idempotency.rs:337`) calls `cache.check(key)`
then `cache.mark_in_flight(key)` as two separate `DashMap` operations. Two concurrent retries can
both observe `Proceed` and both execute — the exact duplication SUB.4 exists to prevent. Fix: one
atomic entry transition, with a concurrent same-key falsifier proving the old code fails it.

**P2 — a keyless call gets an automatic key. LANDED.** The automatic derivation is gone:
`idempotency_key_for` (`src/gateway/meta_mcp/support.rs:35-44`) returns `None` when the client
sent no key (`let key = client_key?`), so a keyless call is not deduplicated at all. This
prerequisite therefore needs REGRESSION COVERAGE, not a repair — a red test would be red against
a defect nobody can reach. What survives is the *other* half of the same concern, and it is not
P2: a keyless side-effecting call is now unprotected rather than wrongly protected, which is the
gap gpt's rev-4 verdict named and the carrier decision below answers.

**P3 — the entry map is unbounded.** `IdempotencyCache { entries: DashMap<...> }`
(`src/idempotency.rs:93`) has no capacity policy and `COMPLETED_TTL` is 24 hours. RESOLVED: take
the response cache's bound, `DEFAULT_MAX_ENTRIES = 10_000` (`src/config/features/cache.rs:12`), and
reject its policy. `ResponseCache::enforce_max_entries` evicts the oldest
(`src/cache.rs:185-204`), which for a side-effect guard would silently re-admit a duplicate.
Fail closed instead: refuse a new protected side effect at the bound.

  AMENDED, rev-5 review: a *global* fail-closed bound is a cross-tenant denial of service. One
  principal issuing 10,000 distinct keyed calls refuses protected side effects to every other
  principal for the full 24-hour TTL, and fail-closed is what makes that a denial rather than a
  degradation — the strictness is the weapon. The bound must therefore be PER PRINCIPAL, not
  global. This is decidable where the key is derived: `identity_suffix` and `caller_principal`
  are already in hand at `invoke.rs:1140-1152`, so the partition key is the one the binding
  already uses. The global 10,000 stays as the total ceiling; what changes is that one principal
  cannot consume all of it. The per-principal figure is an implementation choice, not a design
  commitment — what this decides is that a single caller's exhaustion must not be another
  caller's refusal. Marked overrulable.

**P4 — `_full` calls are unprotected. LANDED.** The suppression is gone, and the code says why
in its own comment: "`want_full` no longer suppresses the key. It selects the shape of the
*reply*, not whether the backend acts, and a directive that switches off duplicate protection is
a bypass any client can set" (`src/gateway/meta_mcp/invoke.rs:1144-1147`). The replay payload is
isolated by `projection_key_suffix` exactly as this prerequisite prescribed. Regression coverage,
not a repair.

**P5 — an explicit key is not bound to the request. LANDED, with a residue that is R6.** The
key is no longer verbatim: `idempotency_key_for` appends the projection and identity suffixes,
and `invoke.rs:1163-1175` derives a request fingerprint carrying the MRTR.10 retry discriminator.
Mismatched reuse is rejected, not replayed. The residue is HOW the suffixes are appended — raw
and unlength-prefixed — which is R6 below, and R6 is live. Regression coverage for the binding;
a real repair for the spelling.

**P6 — a reservation can be abandoned.** `enforce` marks in-flight before dispatch, but
post-dispatch early returns exist — the contract-gate block at
`src/gateway/meta_mcp/invoke.rs:1149` returns `Err` without reaching `mark_completed`. The entry
then sits `InFlight` until it times out, locking the caller out and afterwards admitting a
duplicate of work that already ran. Fix: an owned reservation that reaches a terminal state on
every exit after dispatch.

**Landed status of P1, P3 and P6.** All three are fixed in `src/idempotency.rs` and guarded by
`tests/idem_p1_p3_p6_acs.rs` (commits `b92205ad`, `76ef3ac8`). Four of that file's five tests have a
recorded honest red against the pre-fix code: P1 admitted 2 of 8 concurrent callers where 1 is
allowed, P3 admitted a new key at the bound, P6a left an abandoned reservation in-flight, and P6b
re-admitted a committed side effect. The fifth,
`completed_entries_are_still_served_at_the_entry_bound`, has no honest red — the assertion it makes
was already true before the fix, so it is a regression guard on P3's fail-closed path and an
insensitive control for anything else. Four falsifiers, not five.

**P7 — the in-flight window is a fixed five minutes.** `IN_FLIGHT_TIMEOUT`
(`src/idempotency.rs:50`) expires a reservation after 5 minutes regardless of whether the original
call is still running. RESOLVED: the premise was that a backend call could outlive the window, and
it cannot at any default. The per-backend request timeout defaults to 30 seconds
(`src/config/mod.rs:1383`) and is enforced on the HTTP client (`src/transport/http/mod.rs:305`);
the server's own `request_timeout` is also 30 seconds (`src/config/mod.rs:1178`). The window is
therefore ten times the longest call a default deployment can make. It is configurable, so the
defect is reachable by configuration alone: an operator who sets a backend `timeout` above five
minutes gets a reservation that expires mid-call. Fix is a config-load validation that rejects a
backend timeout at or above `IN_FLIGHT_TIMEOUT`, not a reservation tied to the invocation
lifecycle — the expensive mechanism buys nothing the cheap check does not.

**P8 — the idempotency key is not bound to the caller, and P9 is why fixing the derivation is not
enough.** Both arrived 2026-09-06 from `docs/design/2026-09-06-mrtr-8b-10a-lifetime-and-idempotency-wiring.md`
when that change withdrew its own idempotency wiring (Change B) and transferred what it had found;
**found by Kimi K3** in that document's round-1 review and verified at source there. `identity_suffix`
(`src/gateway/meta_mcp/invoke.rs:1128-1132`) is `caller_credential.cache_binding` alone, therefore
EMPTY whenever identity propagation is off — which the adjacent comment at `:1133-1139` calls the
shipped default. Two authenticated callers issuing the same tool with the same arguments and the
same key string collide on one fingerprint (`:1164-1168`), and `AdmitOutcome::Completed` replays the
first caller's stored response to the second (`:1178-1199`). The response cache does *not* have this
defect: `caller_principal` (`:1140-1142`) already falls back to `VerifiedIdentity::stable_actor_id`.
Fix: `identity_suffix` adopts the same fallback chain, twelve lines away. That does not merge the
two — the separation the comment at `:1133-1139` records survives — but it does falsify that
comment's account of why binding-alone keying was acceptable here, so the repair updates it in the
same commit. A stale comment is model input, not neutral documentation.

**P9 — the relocation in "Constraints, measured" does not subsume P8.** Moving the binding into
`derive_key` (this document, "Constraints, measured", the ADR-008 INV-3 bullet — cited by section, not
line, because a line reference inside the document it points into is invalidated by the next edit
to that document, which is how both references in this material arrived wrong; the same conclusion
reached independently) *relocates*
`identity_suffix`; it does not make it non-empty. With identity propagation off — the shipped
default — the relocated suffix is still empty and two authenticated callers still share a
fingerprint. SUB.4 needs the fallback chain **and** the relocation; satisfying only the second
closes the ADR-008 finding while leaving the replay. Dormant while no key can reach the guard — which
`7851736d` did not change, it populated the cache and left the carrier absent — and live the
moment the remaining routes deliver one, which is what makes it blocking for activation rather than a
follow-up.

## Risks that fire on activation

R4 and R5 arrived 2026-09-06 from the MRTR.8b/10a design when Change B was withdrawn. They were
risks *of activating the cache*; that change activates nothing, so they are this one's from the
moment it does. R6 was found 2026-09-06 while source-verifying this document's own ADR-008 bullet.
It is not inherited, but it is the same kind of risk: it fires when the cache is activated, and
not before.

- **R4 — loose key reuse starts returning 409.** A caller that today reuses one key string across
  different `(server, tool, arguments)` gets no protection at all, because the cache is unwired;
  on activation it gets `Mismatch`, since P5's binding has already landed in the derivation. That
  is the intended behaviour and it is still a client-visible change, so it belongs
  in this change's release note rather than being discovered in production.
- **R5 — an unverifiable identity leaves the key unbound.** When neither `cache_binding` nor a
  stable actor id resolves, the *key* carries no principal at all — the fingerprint never carries
  one by design (the fingerprint in `invoke_tool` is `derive_key(server:tool, arguments)` plus the
  retry discriminator). The choice is this
  change's to make and to state: refuse to protect the call, or protect it with an unbound key and
  accept cross-caller replay. Left unstated it defaults to the second by accident.
  The two options are NOT symmetric, and R6 is why: after P8's fallback chain lands, the callers
  whose `identity_suffix` is still empty are exactly this population, so "protect it with an unbound
  key" is the option that keeps R6's spoofable-suffix population alive.

  **DECIDED: refuse the call, not the protection.** Neither option the bullet names is acceptable:
  protecting with an unbound key is cross-caller replay by construction, and declining to protect
  while executing the call anyway means a client that asked for protection silently does not get
  it, which is the criterion's MUST failing quietly. So a request that carries a client key and
  resolves to no principal is REFUSED — the call does not execute. That is the same fail-closed
  posture this design already took at the capacity bound, and it is decidable at the derivation
  site, where both the key and the identity are in hand. A caller with no resolvable identity that
  sends no key is unaffected: protection applies when a key is present and never otherwise, so
  no client reaching this today starts failing. The caller who DOES start failing is the
  unbindable one that sends a key, and that set is empty only because no client can discover the
  field to send it (the carrier gap above) — a reason the claim holds today, not a reason it
  holds. Stated in the narrow form, it stays true once a carrier is advertised. Recorded here so the operator can overrule it in one
  line rather than discover it in code.
- **R6 — the idempotency suffix is appended raw after a client-supplied prefix, so a caller can
  spell another caller's binding.** Dormant, for the same reason everything else here is: with
  `idempotency_cache` always `None`, `idempotency_key_for` returns `None` before it formats
  anything, so no deployed build derives this key at all. Activation is what makes it reachable —
  which is why it sits with R4 and R5 rather than in a defect report. The response key's first
  field is `{server}:{tool}:{args_hash}` — a digest the caller cannot spell — and its principal is
  HASHED into `|sub:{digest}`, for the reason `cache.rs` states: "a subject is caller-supplied text,
  and appending it raw lets one spell another's suffix." The idempotency key's first field is the
  CLIENT-SUPPLIED key, free text in prefix position, and everything after it is appended raw and
  unlength-prefixed: `idempotency_key_for` returns
  `format!("{key}{projection_key_suffix}{identity_suffix}")`.
  `projection_key_suffix` is EMPTY except in `ProjectionMode::Experimental`, so on the shipped path
  the middle field is not a separator.
  `cache_binding` is PLAINTEXT — `idp:{len}:{subject_key}:{len}:{audience}` in
  `identity_propagation`'s `cache_binding` — length-prefixed INSIDE itself but not against what
  precedes it. So an unbound caller (`identity_suffix` empty) sending client key
  `X|idp:<victim binding>` derives the same final key as a bound victim sending `X`. The spoof runs
  one way only: a bound caller's own suffix always lands last, so it cannot impersonate anyone.
  A mixed bound/unbound population in ONE deployment is not hypothetical: on a non-`required`
  propagation backend, a caller with no verified end-user identity falls to
  `Ok(CallerCredential::default())` — `cache_binding: None` (the local `CallerCredential`'s
  `cache_binding` is `Option<String>`, distinct from `PropagatedCredential.cache_binding: String`)
  — while a verified caller on the same backend gets `Some(binding)`.
  `idempotency_key_for`'s own doc comment claims the opposite of this ("They stay part of the key so
  one caller's stored result is never served to another under the same client key") and is
  therefore a stale comment to fix in the same commit as the mechanism.

  Axis 4 bounds this at the derivation site rather than in the format string: the spoof needs an
  attacker whose own `identity_suffix` is empty, and that is exactly the caller Axis 4 refuses. The
  raw append remains a real defect in `idempotency_key_for` — a function that will outlive this
  design's refusal — and is tracked on MIK-7408 with the three repair options: hash the suffix as
  `response_key` does, length-prefix it, or move the client-supplied key to the tail. Whether P8's
  fallback chain may land while the append is still raw is the one question MIK-7408 puts to a
  human, and this design answers it in neither direction. What this design does assert is narrower:
  relax Axis 4 to admit an unbound keyed caller and the spoof is live again, P8 or no P8.
  R6's disposal is the second of §P0's four — *write it into the design* — and this bullet is it,
  riding this document's rev-5 review rather than a round of its own. Whether it ALSO warrants a
  ticket is the team lead's call, put to them 2026-09-06 and unanswered as this is written. That
  leaves one outcome §P0 does not offer, silence, so the escalation is written down rather than
  remembered: **if rev-5's review opens with no ruling, file it.** It opened 2026-09-06 with no
  ruling, so it was filed: **MIK-7408**, carrying the three acceptance criteria the repair must meet
  and putting the one decision that is genuinely a human's — *is P8 blocked on the suffix repair, or
  may P8 land first with this tracked behind it?* — where a human will see it. The escalation is
  therefore closed, not pending. Not a competing disposal — the
  same one, escalated, because the repair constraint binds whoever lands P8, and P8's landing does
  not wait on this review. FALSIFIED 2026-09-08 by this document's own §P4 review (gpt-review, SHIP-WITH-FIXES,
  raised as CRITICAL and confirmed at source here). The paragraph used to read: *nothing is exposed
  in a running deployment today, the defect is dormant, activation is SUB.4's own act, so the only
  timeline at stake is the ordering of the repair against the activation, not production exposure.*
  Every clause of that is now wrong, and it was wrong the moment `7851736d` landed. The chain, each
  link read at source rather than inferred:
  `RetryFields::from_params` extracts `_meta[IDEMPOTENCY_KEY_META]` from an ordinary `tools/call`
  (`src/protocol/mrtr.rs:117-127`); the HTTP route calls it on every such request
  (`src/gateway/router/handlers.rs:1220`); the key travels to the shared invoke funnel as
  `caller.retry.idempotency_key` and is consumed there (`src/gateway/meta_mcp/invoke.rs:1218`);
  and the cache it is consumed against is `Some` on the production boot path since `7851736d`
  (`src/gateway/server/mod.rs:742`). Activation was not a future act of SUB.4's — SUB.4 performed
  it for route 1 and this document did not notice.
  What that exposes is the suffix defect itself, not a hypothetical one. The key is salted with
  `identity_suffix`, which is the identity-propagation binding *or the empty string*
  (`src/gateway/meta_mcp/invoke.rs:1198-1202`, consumed at `src/gateway/meta_mcp/support.rs:43`),
  and propagation off is the shipped default — the comment eleven lines below the derivation says
  so in terms, while fixing exactly this bug class for the neighbouring `caller_principal` and
  leaving the idempotency key behind. So on a multi-user gateway with the default configuration,
  two callers issuing the same tool with the same arguments under the same client-chosen key
  collide in one namespace, and the second is served the first's stored result. The fingerprint
  binding narrows the blast radius to same-tool/same-arguments calls; it does not close it.
  What this changes: MIK-7408's human question was *is P8 blocked on the suffix repair, or may P8
  land first with this tracked behind it?* — a question about ordering. That question is void. The
  activation half already landed, so the suffix repair is no longer an ordering preference but a
  live-defect repair on a shipped path, and it is a §11 stop-the-line, not a backlog row. Reported
  to the team lead 2026-09-08. ISSUE-DOR then applies: acceptance criteria, ROI,
  fail-fast, and a source. The source is commit `a1578b81`, the ADR-008 bullet repair this was
  found during; the derivation is the P8 transfer blockquote in the MRTR.8b/10a lifetime-and-
  idempotency-wiring design, which records the same three repairs and leaves the choice here.


## Constraints, measured

- The response cache is `Option<Arc<ResponseCache>>` (`src/gateway/meta_mcp/mod.rs:185`), `None`
  when `config.cache.enabled` is false (`src/gateway/server/mod.rs:465-475`), and enabled by
  default (`src/config/features/cache.rs:32`). Idempotency cannot lean on it for correctness.
- `cache.set` runs immediately after the backend result and *before* the client stream
  (`src/gateway/meta_mcp/invoke.rs:1260-1268`). Revision 2 claimed a post-execution abort leaves no
  cached response; that is wrong. It leaves a cache hit that serves the reissue and holds a
  mutation counter at 1 with idempotency entirely unwired. Every SUB.4 test must therefore run
  with the response cache OFF — see the fixture invariant below.
- TTLs already exist: `COMPLETED_TTL` 24h and `IN_FLIGHT_TIMEOUT` 5m (`src/idempotency.rs:44` and `:50`).
  Copying `config.cache.default_ttl` instead would shrink protection to a minute.
  The 24h itself is a DEFERRED UNKNOWN, not a settled decision — `COMPLETED_TTL` is a module
  constant (`src/idempotency.rs:44`, rationale in the doc comment at `:31-43`), not a config
  field, and "there is no config field" is not "there is no assumption to record". §P1's
  four fields, so it is deferred rather than merely regretted:
  - **owner**: the team lead, folded into the same ruling that decides the (a)/(b) config gate.
  - **what would resolve it**: that ruling — asked of the team lead, not checkable by running
    anything, since it is a policy choice about what an operator may tune.
  - **when**: at that ruling, which blocks routes 2 and 3; not after they land.
  - **what if it resolves badly**: if 24h is wrong for a real deployment, the constant becomes a
    config field with 24h as its default — additive, no behaviour change at the shipped
    default, and no stored entry is invalidated by widening the window.
  NOTHING IN THIS CHANGE DEPENDS ON THE ANSWER: route 1 is correct at any TTL, and the cases
  above assert replay and refusal, never a duration.
- ADR-008 INV-3 requires the `cache_binding` (user + audience) in both cache keys, and it is — but
  the two keys get it in opposite ways. The RESPONSE key takes the principal as a PARAMETER of its
  derivation: `ResponseCache::response_key` (`src/cache.rs:279-294`) receives `principal` and mixes
  it in itself, and both call sites reach it through the one helper `response_cache_key_for`
  (`support.rs:60-78`) — the function's own comment says why, verbatim: "Both call sites go through
  here, because a key built in two places is two keys the day one of them is edited." The
  IDEMPOTENCY key gets it at the CALL SITE: `invoke.rs:1128` builds an `identity_suffix` and `:1151`
  passes it to `idempotency_key_for`, which concatenates it (`support.rs:43`). DECIDED: extending
  coverage pushes the binding INTO the derivation — and the response cache is the in-repo precedent
  for exactly that, so this aligns the idempotency key with a pattern already shipped here rather
  than inventing one.
  CORRECTED 2026-09-06, twice, both against source. (1) The bullet cited `:773`, `:789`, `:831` and
  `:1263` — written against 08-31 source and false against current source. The "copying to a second
  call site" argument is WITHDRAWN, not restated: `caller_principal` does reach two call sites, but
  both funnel into one derivation that owns the mixing. (2) The clause "Neither `derive_key` nor
  `ResponseCache::build_key` knows about it" NAMED THE WRONG FUNCTION and was half false.
  `build_key` (`cache.rs:253`) is the three-input base helper with exactly one non-test caller
  (`cache.rs:287`, inside `response_key`); the derivation is `response_key`, and it does know the
  principal — it hashes it. The DECIDED line is unchanged by both corrections and stronger for the
  second.
- `IdempotencyCache::check` evicts on access (`src/idempotency.rs:147-176`), so the background
  cleanup task is an optimisation, not a correctness requirement.
- MIK-7212.MRTR.10a (continuation fields inside the key) is promoted from a noted dependency to a
  PREREQUISITE. Wiring SUB.4 on a key that omits those fields makes continuation collisions live
  rather than dormant. RE-DATED 2026-09-08: "makes live" was already the wrong tense. Route 1
  reaches `idempotency_key_for` with a client-supplied key today (Problem section, chain read at
  source), so a continuation collision on that route is live NOW, not on some future wiring. The
  prerequisite stands; what changes is that it is overdue rather than upcoming.

## Two decisions, plus four the review created

**Axis 1 — activation. DECIDED: mandatory, no kill switch.** Off by default cannot satisfy a
criterion that says a reissue MUST be protected, so it is rejected on the requirement, not on
cost. Between on-by-default-with-an-opt-out and mandatory, the criterion decides: an operator
switch makes the criterion unverifiable in the deployments that matter, because the shipped
default and the running configuration can disagree and only the running one executes side effects.
This is an engineering reading of a MUST, not an operator preference, and it is recorded here so
the operator can overrule it in one line rather than discover it in code.

**Axis 2 — coverage.** THREE routes, not two, and each is uncovered by its own mechanism:

| route | why the key does not take effect | state |
|---|---|---|
| generic `tools/call` (meta route) | the cache was `None` on every boot, so `idempotency_key_for` short-circuited | FIXED 2026-09-08, `7851736d` |
| stdio | the caller context hardcodes `NO_RETRY` (`server/mod.rs:2200`), so the client's key is discarded before dispatch | UNWIRED |
| direct `POST /mcp/{name}` | `backend_handler` (`backend_handlers.rs:434`) has no call site for `idempotency_key_for` at all | UNWIRED |

Covering one is not covering the criterion: any route left out is a documented ingress the
criterion does not permit to be unprotected. Placement is settled above — the binding goes in the
derivation — and that placement is what lets the three routes share one key shape instead of
three.

**Axis 3 — the key carrier.** Protection needs a key a client can actually send, on both
CARRIERS — the meta route's `_meta` and the direct route's raw JSON-RPC `_meta`; stdio shares the
meta route's carrier and is a separate *route* in Axis 2, not a third carrier — advertised and
validated. Nothing in the tree advertises one. This axis is upstream of the other
two. CORRECTED 2026-09-08: "unsatisfiable as things stand" was true only of stdio and the direct
route. Route 1 satisfies it already — an undocumented carrier is still a carrier, and source shows
a client's `_meta` key reaching the funnel (Problem section). The axis is decided rather than
deferred because the criterion needs ALL THREE routes, not because nothing carries a key today.

DECIDED 2026-08-31. Asked of the operator, four options put with their costs, answered
**`_meta` on both routes** (`RELEASE-4.0.0-operator-decisions.md` row 7).
An earlier revision recorded this axis as already
settled by an operator instruction the session record does not contain; that attribution was
withdrawn and the question re-put. The reasoning below is the design's, the choice is the
operator's.

The specification is not silent. `_meta` is the protocol's own field for out-of-band data on a
request, so the meta route carries the key at `params._meta["io.mcp-gateway/idempotency-key"]`.
That is protocol-native, survives over stdio where a client has no HTTP layer at all, and adds
nothing to the tool schema, so the compact-surface decision in `CLAUDE.md` is untouched. The
direct route `POST /mcp/{name}` carries the key in the same place, which is new plumbing: it is
raw JSON-RPC passthrough that forwards the request body without inspecting it, and no client
sends the field today. That cost was put to the operator with the option and accepted, because
one carrier on both routes means one extraction site, one validation rule, and one thing for a
client to learn.

Rejected: an `idempotency_key` tool argument, because it puts a gateway-internal concern into
every backend tool's advertised surface. Rejected: a header on both routes, because a stdio
client has no headers and would be left unprotected. Rejected: a hybrid — `_meta` on the meta
route, an `Idempotency-Key` header on the direct route — cheaper to build on the HTTP side and
the industry spelling there, but it splits the carrier in two and leaves both to maintain.
Rejected: keeping automatic derivation as a
fallback, because that would REINSTATE defect P2, already removed from the tree — deriving a key
for a client that never asked for one silently collapses deliberate repeats for 24 hours. Protection applies when a key is present and never
otherwise.

**Axis 4 — an unresolvable principal under a client key. DECIDED: refuse the call.** Created by the
rev-5 review the same way Axis 3 was, and stated in full where the risk that raises it lives (R5,
"Risks that fire on activation") rather than restated here. Named in this section because a reader
auditing what this design decided reads THIS list, and a decision recorded only next to its risk is
one nobody counts. That was R5's original defect and it should not be reintroduced by filing the
answer somewhere the question is not asked.

**Axis 5 — how the capacity bound is partitioned. DECIDED: per principal, not globally.** Created
by the rev-5 review, which observed that a global fail-closed bound turns one principal's traffic
into every other principal's denial. Stated in full in prerequisite P3 above, beside the bound it
amends; counted here because a decision recorded only next to its risk is a decision nobody counts
— the defect Axis 4 exists because of.

**Axis 6 — what the cache stores, as distinct from what carries the key. DECIDED: the
route-neutral result, never an envelope.** Follows from Axis 3 rather than competing with it: once
both routes are covered, something must say what a replay hands back to a caller whose request id
is not the one that filled the entry. Stated in the open-questions table, first row.

## Open questions — each scheduled, none assumed

| question | how it is settled | state |
|---|---|---|
| What is CACHED, as distinct from what carries the key? | DECIDED with Axis 3 and following from it: the stored value is the route-neutral *result*, never a serialised envelope. Each route rebuilds its own reply around it — the direct route with the retrying call's own JSON-RPC id, the meta route with its projection. Caching an envelope would replay the first caller's request id to the second, which a retrying client cannot correlate; and it would let a meta-route-shaped payload be served to a raw passthrough caller. The projection shape is already bound into the key by `projection_key_suffix`, so the two routes cannot collide on one entry. | RESOLVED — overrulable |
| What carries a retry key, on both routes? | ASKED 2026-08-31, four options put, ANSWERED: **`_meta` on both routes** (`RELEASE-4.0.0-operator-decisions.md` row 7). Rejected in the ask: an HTTP header alone (a stdio client has no HTTP layer, so protection stays unreachable for local setups), a hybrid of the two (industry-spelled on the HTTP side, but two carriers to build and two spellings to learn), and keeping automatic derivation (ships fastest, keeps P2's silent 24-hour collapse of deliberate repeats). The chosen option's own cost was stated in the ask and accepted: the direct route is raw JSON-RPC passthrough needing new `_meta` extraction, and no client sends the field today. | RESOLVED — single carrier, spelled out in Axis 3; code unblocked |
| May an operator disable protection a criterion states as MUST? | ASKED of the team lead, and RULED 2026-09-08: no config field, idempotency enabled unconditionally. That ruling SUPERSEDES the 2026-09-07 one recorded at `docs/requirements/RELEASE-4.0.0-criteria-status.md:227` (*"idempotency defaults ON … the config gate exists so an operator can DISABLE it, never as the default posture. The TTL takes CONTROL.4's shape — a config field with a defensible default"*) — this row invited an overrule and got one, arriving from the other direction. The reasoning the design owes on its own account: a guarantee that holds only while nobody opts out is the same defect as one that holds only when someone opts in, one rung down the same ladder; nobody has asked for the switch; adding a config field later costs two lines, while removing a shipped one is a compatibility event. CHANGED: the `#[allow(dead_code)]` comes off and the cache is populated for every gateway, with the TTL left as a stated assumption (above) rather than a config field. | RESOLVED — ruled |
| Does ADR-008 bear on the direct route's bypass? | CHECKED end to end. It does not; rung 2 is client-native OAuth passthrough. What it does bind is INV-3. CHANGED: the bypass loses its justification and axis 2 gains a placement constraint. | RESOLVED |
| What capacity bound, and what happens at the bound? | CHECKED `src/config/features/cache.rs:12` and `src/cache.rs:185-204`: bound 10_000, policy evict-oldest. CHANGED: take the number, reject the policy, fail closed. | RESOLVED |
| Does a configured backend timeout exceed `IN_FLIGHT_TIMEOUT`? | CHECKED. Per-backend `timeout` defaults to 30s (`src/config/mod.rs:1383`), enforced at `src/transport/http/mod.rs:305`; the server's `request_timeout` is also 30s (`src/config/mod.rs:1178`). CHANGED: P7 is out of reach at defaults and reachable only by configuration, so its fix shrinks to a config-load validation. | RESOLVED |

| When neither `cache_binding` nor a stable actor id resolves, is a client-keyed call protected with an unbound key, left unprotected, or refused? | DECIDED on the requirement, with R6 in hand: refused. Protecting unbound is cross-caller replay; executing unprotected fails the MUST silently. Recorded so it can be overruled, not so it can be confirmed. | RESOLVED — overrulable |

Two items remain open, and they are open in different ways.

**(a) The unreviewed-revision gate — a STATUS, not an unknown.** Revisions 5 and 6 carry no
reviewer verdict; the `SHIP-WITH-FIXES` at the top is a verdict on revision 2. Code for route 1
landed ahead of that review (`7851736d`). Nothing here is unknown — a reviewer has simply not
looked yet. The team lead ruled the repair is review-now rather than deletion of the landed code,
so this is tracked as an outstanding review, not as a deferred question.
ROUTES 2 AND 3 DO NOT LAND BEFORE THIS REVISION HAS A VERDICT. Route 1 outran the gate once;
saying "the gate applies from here" is the only thing that stops that from being a precedent,
and it is cheap to say and checkable afterwards — the remaining two routes have no commit
until a verdict on revision 6 exists.

**(b) MIK-7408 — genuinely deferred, four fields.**

| field | value |
|---|---|
| owner | the team lead, on MIK-7408 |
| what would resolve it | a ruling on *is P8 blocked on the raw-append suffix repair, or may P8 land first with the repair tracked behind it?* |
| when | before P8's fallback chain lands |
| what if it resolves badly | P8 blocks on the raw-append repair — hash the suffix the way `response_key` does, length-prefix it, or move the client-supplied key to the tail |

It constrains the ORDERING of that repair, not route 1's wiring: as stated above, P8's landing
does not wait on this review.

## Test plan

**Fixture invariant, applying to every row: `config.cache.enabled = false`.** Three reviewers
independently found rows that pass through the response cache rather than the code under test.
The response cache stores before transmission, so no argument about *when* a stream aborts can
defeat it. Turning it off in the fixture is the only mechanism that does, and stating it once as
an invariant is what stops the defect returning row by row.

| criterion | case | how it fails today |
|---|---|---|
| SUB.4, meta route | abort after the backend executed, reissue with a new request id and the same retry key, assert a mutation counter on a `destructiveHint` tool reads 1 | STILL RED after `7851736d`, for a different reason than when this row was written. The cache is populated now; what is missing is the key. The meta route advertises no `_meta` carrier (Axis 3), so `idempotency_key_for` returns `None`, the guard never sees a key, and the counter reaches 2. Re-stated 2026-09-08 — the verdict did not move, the mechanism did |
| SUB.4, concurrency (P1) | two same-key requests in flight together; exactly one executes, the other gets `409` or the stored result | non-atomic `enforce` lets both proceed |
| SUB.4, direct route | the same post-execution reissue through `POST /mcp/{name}` | that route never resolves a key |
| no false dedup (P2) | the *identical* keyless call issued twice, both backends must run | GREEN TODAY — regression coverage. `idempotency_key_for` returns `None` without a client key, so the row guards against reinstating the derivation, and it is the falsifier for the Axis 3 rejection above |
| `_full` protection (P4) | the meta-route case again with `_full` requested | GREEN TODAY — regression coverage. The suppression was removed and `invoke.rs:1144-1147` records why; the row is what makes putting it back go red |
| key/request binding (P5) | one key reused for a different `(server, tool, arguments)`; the second call must be refused, not replayed | GREEN ONCE WIRED — the binding is derived today but unreachable, so this row goes red only against a build that delivers a key without it. Re-stated 2026-09-08: `7851736d` closed the `None` half — the cache is `Some` — and the carrier of Axis 3 is what still holds the key away from the binding |
| reservation release (P6) | a call that trips the contract gate after dispatch; a later same-key call must not be locked out | the entry stays `InFlight` until timeout |
| backend timeout vs in-flight lease (P7) | config load with a backend `timeout` >= `IN_FLIGHT_TIMEOUT` must be REJECTED at load time, and one below it accepted | GREEN ONCE THE VALIDATION LANDS — today the config loads either value silently, so a backend can outlive its own reservation. Asserted at CONFIG LOAD, not through an invoke fixture: a fixture that builds the config in memory can be made to pass without the check existing, a load-time case cannot |
| bound (P3) | fill to 10_000, assert a new protected side effect is refused rather than admitted | unbounded map admits it |
| bound is per-principal (P3, rev-5 amendment) | principal A fills its share; principal B's first protected call must still be admitted | a global bound refuses B, so B's protection is denied by A's traffic for the full 24-hour TTL — the row goes red against exactly the shape P3 originally specified |
| direct-route replay is route-neutral (Axis 3) | a call made through `POST /mcp/{name}`, then reissued with a DIFFERENT JSON-RPC id; the replay must carry the new id and the direct route's own envelope, not the first call's id or the meta route's projected shape | nothing stores a route-neutral result, so a replay would hand back whatever the first caller's envelope happened to be, and a retrying client cannot correlate it |
| MRTR.10b regression | a non-final `InputRequired` result through the newly wired path must leave the call retryable, not stored as completed | `7851736d` populated the cache, so this guard is reachable in production for the first time — and it has still never RUN there, because no key reaches it. Its only coverage calls `mark_completed` directly |
| SUB.4, boot path (route 1) | `sub4_boot_populates_the_idempotency_cache` (`src/gateway/server/mod.rs:3120`): default config, `build_meta_mcp`, the field must be `Some` | LANDED GREEN (`7851736d`). Honest red recorded by the §P2 falsifier probe 2026-09-08: pre-fix source restored under a trap from `git show 7851736d^:src/gateway/server/mod.rs`, the test FAILED at `server/mod.rs:3104` in that pre-fix file — `:3120` in the tree as it stands, the repair moved it — on its intended assertion — *"the boot path must populate the idempotency cache; an unpopulated one makes every client-supplied idempotency key inert"* — not a compile error; repair copied back, re-run passed |
| SUB.4, invoke path (route 1) | `a_reissued_idempotency_key_is_served_from_the_stored_result` (`src/gateway/meta_mcp/tests.rs:5705`): counting backend, response cache deliberately OFF, two invokes under one key, the backend is asked once, both replies carry the backend's body | characterization of a mechanism previously reachable only from tests, so no free red was available. It can fail: the response cache is left out, so a second identical call reaches the backend unless the idempotency guard stops it |

The assertion is a mutation counter on the tool, never the response body: two identical bodies
are also what executing twice produces.

**2026-09-09 — direct route (`POST /mcp/{name}`): gap CONFIRMED at source, unimplemented.** The row
above says "that route never resolves a key"; that is now verified rather than asserted. `rg` over
`src/gateway/router/` returns ZERO occurrences of `idempot`, `derive_key`, `GuardOutcome` or
`RetryFields` in `backend_handlers.rs` (the two `_meta` hits are `prepare_tool_metadata`, a substring,
not a carrier read). The `tools/call` branch (`backend_handlers.rs:762`) runs
`apply_backend_tool_call_security` and dispatches straight to `backend.request*`; no key is parsed,
no guard is called, so a client's retry key is inert on this transport exactly as it was on stdio
before R1. The row stays RED and the fix is NOT in the tree.

Shape for whoever lands it, and the two ways to land it wrongly:
- **Access.** `idempotency_cache` is `pub(super)` on `MetaMcp` (`src/gateway/meta_mcp/mod.rs:251`);
  `AppState.meta_mcp: Arc<MetaMcp>` is in reach at `router/mod.rs:54` but the field is not. PREFERRED:
  a method on `MetaMcp` that OWNS the guard and which the router calls — no field or accessor is
  widened, so no VISIBILITY-IS-DESIGN event. A read accessor is the fallback, not the default.
- **The fingerprint trap.** Route 1 keys with `idempotency_key_for`
  (`src/gateway/meta_mcp/support.rs:48`, shape `{len}:{key}{projection}{identity}{step}`) and
  fingerprints with `derive_key(&format!("{server}:{tool}"), &arguments)` plus
  `retry.key_discriminator()` (`invoke.rs:1340-1412`). A direct-route guard that drops the
  `{server}:` prefix, the length prefix or the identity suffix produces keys that CAN NEVER COLLIDE
  with route 1's — a silent no-op that passes a same-route test while leaving the criterion open,
  and the `:452` row's continuation collision live.
- **The test must count.** Counting backend, `config.cache.enabled = false`, assert the backend was
  asked ONCE — not merely that a guard ran, and never the response body.

The fixture invariant meets the two landed rows differently, and neither case sets
`config.cache.enabled = false`. The boot row runs `Gateway::new(Config::default())` ON PURPOSE —
its doc comment makes the default load-bearing, because there is no section for an operator to
write — and it asserts a construction fact no response cache can fake, so the invariant is
satisfied vacuously rather than waived. The invoke row satisfies it in letter, with the response
cache deliberately off.

**Two constraints and one case, transferred 2026-09-06 from the MRTR.8b/10a design when Change B was
withdrawn.** The table below also carries rows that are NOT transferred — R6's
falsifier and R5's, both this design's own, added when those risks were written into it. That change's plan had written them for a wiring that no longer exists; they are
constraints on *this* plan because this is the change that activates the cache.

- **The activation test constructs through the production builder, not a hand-assembled server.**
  A fixture that builds the idempotency layer directly proves the layer works and says nothing
  about whether the shipped configuration path reaches it — which is precisely the `enable_idempotency`
  failure mode (`src/gateway/meta_mcp/mod.rs:685`, formerly `#[allow(dead_code)]`, field
  initialised `None` at `:464` — re-anchored 2026-09-08; this bullet carried `:657` and `:437`)
  that a test could have caught and did not. The boot row now in the plan is that test.
- **A negative case for the absent section is transferred NOWHERE, deliberately.** There is no
  optional `idempotency.enabled` key here — activation is mandatory ("Two decisions, plus four the review created", Axis 1) — so a row
  asserting behaviour when the section is absent could only be written by reintroducing the kill
  switch this design refused. Recorded so its absence reads as a decision rather than a gap.

| criterion | case | how it fails today |
|---|---|---|
| cross-principal binding (P8/P9) | two *different* authenticated callers issue the same tool, same arguments and the same key string, with identity propagation OFF; the second must execute rather than receive the first's stored response | **CLOSED 2026-09-08 by `3403a53b`.** It failed exactly as described: `identity_suffix` was empty at that default, so both callers derived the same *key*, `admit` found the entry by key (`idempotency.rs:256`) and `matches` (`:130-131`) compared fingerprints that are identical because the two calls genuinely are the same `(server, tool, arguments)` — `AdmitOutcome::Completed`, replayed. `retry_identity_suffix` now falls back to the verified subject, tagged `sub:`, so the suffix is empty only for a caller the operator left unattributed. Same commit closes a second defect this row never saw: the client key was concatenated RAW and FIRST, so a caller could spell another caller's suffix inside its own key and derive that caller's entry outright (MIK-7408). It is now length-prefixed |
| unresolvable principal under a client key (R5 / Axis 4) | on a non-`required` propagation backend, a caller with neither a `cache_binding` nor a stable actor id sends a client key for a `destructiveHint` tool; the call must be REFUSED — neither executed unprotected nor admitted under an unbound key | **STILL FAILS — NOT closed. Cause corrected 2026-09-08 against source; the criterion itself is open.** This cell read "no key is derived at all (`idempotency_cache` is `None`)", which stopped being true at `7851736d`: `enable_idempotency` (`src/gateway/server/mod.rs:742`) is the only production construction site and every route through `run`/`run_stdio` passes it, so route 1 derives a key today. The row still FAILS, for a different reason: such a caller now derives a key with an EMPTY identity suffix (`retry_identity_suffix`, both arms `None`) and is admitted under it, which is the second of the two states the criterion forbids rather than the first. The refusal itself is still unbuilt |

---

## Revision 7, 2026-09-09 — the stdio route acquires an owner and two test rows

Nothing decided above is reopened. Axis 1 (mandatory, no kill switch), Axis 2 (three routes),
Axis 3 (`_meta` on both carriers) and Axis 4 (identity binding) stand as written. This revision
closes a hole in the *plan*, not in the design: Axis 2 names stdio as one of three routes and the
test plan carries no stdio row, so the route this design calls UNWIRED had nothing that would go
red if it stayed that way.

### The seam has no owner, and rev 6 said it did

Rev 6 states, at "stdio discards the client's key before dispatch": *"This seam has its own design
— `docs/design/2026-09-02-cluster-g-stdio-dispatch-parity.md` §P3."* **That is wrong and is
corrected here.** §P3 of that note is about where the stdio *negotiated protocol revision* lives
and says nothing about retry fields. The section that does — "`NO_RETRY` on stdio — declared OUT,
with something watching it" — declares the seam **out of scope for cluster G**, for a stated and
good reason (closing it moves that change's `FOR` after its §P0 freeze), and names no successor
owner. Cluster G owns a watcher, not the work.

So the seam was cited as owned by a document that had explicitly disowned it. That is how a route
this design lists as one of three ends up with zero test rows: each side could read the other as
covering it.

**Ownership transfers to this design, effective this revision.** The justification is not
availability, it is fit: SUB.4's criterion is *the same tool call, reissued after an abort, must
not execute twice*, and Axis 2 already commits to answering that on all three routes. A route
named in an axis and owned by nobody is a decision this design failed to make (§P3 of
`development-process.md`), and naming it is the whole obligation.

What transfers with it: cluster G's own account of the cost. Closing the seam requires building
`RetryFields` at the stdio convergence point **and** refusing malformed retry fields pre-dispatch
on both transports. That is a behaviour change, it is larger than wiring, and it is why the two
rows below are written as RED rows in this plan rather than as a repair claimed in passing.

### Anchor by content, because the line numbers have drifted three times

The production discard is one site: the stdio caller context that passes
`retry: &crate::protocol::mrtr::NO_RETRY`. Rev 6 cites `server/mod.rs:2200`, cluster G cites
`:1853`, and the tree today has it at `:2213`, with the only sibling occurrence at `:2716` inside
`mod tests`. Three documents, three numbers, one site. Cite it as **the sole `NO_RETRY` caller
context outside `#[cfg(test)]` in `src/gateway/server/mod.rs`** and let `rg` find the line; a
number that is wrong in every document that carries it is not an anchor.

### The `#[ignore]`d watcher is disposed of, not inherited

`stdio_should_present_a_retry_when_the_context_declares_one` is a source-grep test: it reads
`include_str!("mod.rs")` and asserts the file does not contain `concat!("retry: &","NO_RETRY")`.
It watches the *text*, so it goes green the moment someone spells the constant differently and
stays green if the client's key is still discarded by another mechanism. As a placeholder under
cluster G's explicit OUT it was honest — better than prose. As this design's coverage of a route
it owns, it is not enough.

Disposal, one of the two, decided here: **it is replaced by the behavioural row below, and
un-ignored only as that row's implementation lands.** It is not deleted first — deleting the
watcher before the behavioural row exists is the one move that leaves the defect pinned by
nothing at all, which is precisely what cluster G wrote it to prevent. Order: behavioural row goes
red, implementation lands, behavioural row goes green, source-grep watcher is deleted in the same
commit as its replacement's first green run.

### Two rows, added to the test plan above

The fixture invariant applies unchanged: `config.cache.enabled = false`.

| criterion | case | how it fails today |
|---|---|---|
| SUB.4, stdio route (Axis 2, third route) | drive `run_stdio` end-to-end: send `tools/call` for a `destructiveHint` tool carrying a client retry key in `_meta`, abort after the backend executed, reissue over the same stdio session with a new request id and the same key; assert a mutation counter reads 1 | RED, by construction rather than by accident. The sole `NO_RETRY` caller context outside `#[cfg(test)]` makes `caller.retry.idempotency_key` absent before dispatch, so `idempotency_key_for` (`src/gateway/meta_mcp/support.rs:48`) returns `None`, the route-1 guard (`src/gateway/meta_mcp/invoke.rs:1253`) never fires, and the counter reaches 2. Note the cache itself IS populated on this path — `enable_idempotency` (`src/gateway/server/mod.rs:742`) is reached by `run_stdio` as well as `run` — so this row fails for want of a *key*, not for want of a cache, and a fixture that asserts `idempotency_cache.is_some()` on stdio will pass while the defect stands |
| SUB.4, stdio malformed retry fields (the second half of the cost) | over stdio, send a retry key that violates the field's constraints (empty, or over the length bound the HTTP route enforces); the call must be REFUSED pre-dispatch, identically to the HTTP route | RED. There is no stdio pre-dispatch validation to refuse anything: the field is discarded before it reaches the point that would validate it, so "malformed" and "absent" are the same state on this transport. Written as its own row because closing the first row without this one buys parity on the happy path and a divergence on the failure path — cluster G named both halves as the cost, and a plan that carries only the first would let half the work look done |

Both rows are **plan rows, not implementations**. They are red until the stdio convergence point
builds `RetryFields`; this revision changes who owns making them green, and nothing else.

**2026-09-09 — the stdio carrier now exists (R1, LANDED).** The convergence point named above,
`stdio_caller_context` (`src/gateway/server/mod.rs`), pinned `retry: &crate::protocol::mrtr::NO_RETRY`
in its struct literal, so every stdio caller's idempotency key was discarded before
`invoke_tool_traced` could read it while the HTTP route kept the guard. The dispatch arm now builds
`RetryFields::from_params(params.as_ref())` and passes it through. Two tests landed:
`stdio_caller_context_carries_the_clients_idempotency_key` and
`stdio_dispatch_builds_its_retry_fields_from_the_request` (the previously `#[ignore]`d row,
unignored and renamed). §P2 falsifier probe, defect hand-edited back under a `trap ... EXIT INT TERM`
with a `cp` restore (NOT `git stash`/`git checkout --`: the file carries a peer's concurrent
uncommitted edits, and a full-file restore would destroy them): both tests FAILED on their intended
assertions — `mod.rs:3716` *"the stdio caller context must carry the client's idempotency key; an
absent one makes the duplicate-suppression guard inert on this transport"* (`left: None`,
`right: Some("stdio-key-1")`) and `mod.rs:3739` *"the stdio context must take its retry fields from
the request instead of pinning an absent retry"* — not compile errors; repair copied back, re-run
`cargo test --lib stdio_` = 28 passed, 0 failed. The two plan rows above stay RED: a carrier is not
an end-to-end drive, and neither row's fixture has been built.

### What this revision does NOT do

- It does not decide the representation of the retry fields at the stdio convergence point. That
  is §II.5-shaped work shared with cluster A, and rev 6's instruction stands: before starting,
  establish whether that lane already builds `RetryFields` there and consume its work rather than
  duplicating it.
- It does not move the release scope. Whether the stdio rows must be green for v4.0.0 is a
  criteria-status question, not a design one; this plan says what "done" looks like on that route,
  not when it is owed.

## Revision 8, 2026-09-09 — route 3, the direct backend route, acquires its design

Nothing decided above is reopened. This revision does for route 3 what rev 7 did for route 2: it
says what the route must do, where the code goes, and which rows go red until it does. Rev 7's
own note that the stdio carrier has landed stands; the two stdio end-to-end rows remain RED.

### The route, and why it is not covered by route 1

Route 1 guards `invoke_tool_traced` — the meta-MCP path a client reaches through `gateway_execute`.
Route 3 is `handle_backend_request` in `src/gateway/router/backend_handlers.rs`, the *direct*
route: a client addressing a backend by name, whose `tools/call` never enters `invoke_tool_traced`
at all. A key presented on that route is read by nothing. The same tool, reissued after an abort,
executes twice.

This is not a new observation and the file already says it, in prose, about a different guard:

> ADR-008 INV-2: the direct backend route bypasses `invoke_tool_traced`, so it must enforce the
> same fail-closed OAuth-isolation guard.

**INV-2 is this route's precedent, not its obstacle.** The invariant does not say the direct route
must stay thin; it says the direct route owes the same guarantees as the meta route and must
enforce them itself. An idempotency guard is a second instance of exactly that obligation. A
reviewer who reads INV-2 as a reason to leave route 3 unguarded has it backwards — INV-2 is the
sentence that makes leaving it unguarded a violation.

### One guard, sited before the branch, because there are two forward paths

`handle_backend_request` forwards to the backend in two places:

1. the sanitized-params return inside `if method == "tools/call"`, after
   `apply_backend_tool_call_security` yields `Some(Ok(Some(sanitized_params)))`;
2. the general forward below that block, reached when the request carries no tool name or is not
   `tools/call` at all.

A guard placed on (1) alone passes a test that drives (1) and does nothing for (2). The guard goes
**before the `if method == "tools/call"` block**, immediately after the INV-2 isolation guard —
the same site, for the same reason, in the same shape. One site, both paths, no branch to keep in
sync. Anchor it by content — *the statement following the `enforce_oauth_isolation` refusal in
`handle_backend_request`* — not by a line number; rev 7 records what line numbers are worth in
this tree.

### Visibility: a method on `MetaMcp`, never a widened field

The guard needs two things that live inside `meta_mcp` and are `pub(super)`:
`idempotency_cache` (the field, `src/gateway/meta_mcp/mod.rs:251`) and `idempotency_key_for`
(`src/gateway/meta_mcp/support.rs:48`). Widening either to `pub(crate)` is a design shift, not a
convenience edit, and this design refuses it.

**Decided here:** route 3's guard is a `pub(crate)` method ON `MetaMcp`, living inside `meta_mcp`,
that takes the tool name and params and answers whether this call is a replay. The cache and the
key helper stay private; the method is the only thing that crosses the module boundary. The
precedent is in the same file and already called from the same function:
`enforce_oauth_isolation` (`src/gateway/meta_mcp/mod.rs:882`) is `pub(crate)`, wraps private state,
and `backend_handlers.rs:749` calls it as `state.meta_mcp.enforce_oauth_isolation(...)`. Route 3
adds a sibling to it and copies its shape exactly. `stamp_direct_provenance`, already called on
this route, is the same pattern again.

No public signature changes. No architectural invariant moves. This is the reason the route can be
built without the stop this design's brief reserves for signature and invariant changes.

### The Axis-4 identity question — RESOLVED, and the answer is a design event

*checkable:* **does the direct route have the two inputs `retry_identity_suffix` takes, and do they
mean the same thing there?** — read `retry_identity_suffix`
(`src/gateway/meta_mcp/support.rs:80`) and its call site (`src/gateway/meta_mcp/invoke.rs:1329`)
against what `handle_backend_request` has in scope at the guard site — **both inputs exist and
BOTH are spelled differently enough that passing them through raw would be wrong** — so the guard
adapts them, and the adaptation is named below rather than made silently.

Route 1 calls `retry_identity_suffix(caller_credential.cache_binding, verified_actor)`, both
`Option<&str>`, and `(None, None)` yields the empty suffix — a deliberate single bucket for callers
the operator left unattributed, pinned by the test
`retry_identity_suffix_pools_callers_the_operator_left_unattributed`.

The direct route has an analog for each, in scope before the `enforce_oauth_isolation` refusal:

| route 1 input | direct-route analog | why it is not a drop-in |
|---|---|---|
| `cache_binding` (`idp:`-prefixed, minted by identity propagation) | `identity_key`, `Option<String>` | when it is set by the passthrough rung it is `passthrough_identity_key(credential)` — a bare SHA-256 hex of the caller's OWN credential, which the function's own comment states is deliberately disjoint from the minting path's `idp:` bindings. Passing it as `cache_binding` tags a passthrough digest `\|idp:`, which is a mislabel: correct partitioning, wrong provenance in the key |
| `verified_actor` (`Option<String>`; `None` = unattributed) | `audit_subject(verified_identity)`, `String` | it NEVER returns `None`. An unverified caller gets the literal `"unauthenticated"`. Passed straight through, every anonymous direct-route caller lands in a bucket spelled `\|sub:unauthenticated` instead of route 1's empty bucket — the same pooling behaviour under a second spelling, which is exactly the drift the `CallerIdentity` doc comment says must not happen |

**DESIGN EVENT, named here (§P3).** The guard does not pass either value raw. It maps
`"unauthenticated"` back to `None` so the unattributed bucket has ONE spelling across routes, and
it does not present a passthrough digest as a minted binding. Which arm a passthrough digest
belongs in — a third `CallerIdentity` variant with its own tag, or the `Subject` arm — changes what
a key means and is the requester's call, not one to be made while writing the guard.

Consequence worth stating plainly: because the two routes derive the binding from different
material, the same caller reissuing the same key across route 1 and route 3 will NOT deduplicate
against each other. Within-route protection is what Axis 2 promises and what these rows test;
cross-route deduplication is not promised, and now says so out loud instead of being assumed.

### What is NOT decided here, and is named rather than assumed

- **What a replay returns.** Route 1's behaviour is the default and no divergence is intended, but
  route 3 builds its HTTP response by a different path (`build_http_response`), so the shape is an
  implementation question the tests below pin rather than a design choice made here.

### Test plan rows for route 3

Fixture invariant unchanged: `config.cache.enabled = false`.

| criterion | case | can it fail? — how it fails today |
|---|---|---|
| SUB.4, direct route (Axis 2, second route) | drive `handle_backend_request` for a `tools/call` naming a `destructiveHint` tool, with a client retry key in `_meta`; issue it twice with different request ids and the same key; assert the backend saw ONE call | YES, RED today. The function forwards to the backend with no idempotency read anywhere between entry and `backend.request`; the key rides through in `params` and is never consulted. Counter reads 2. The row cannot pass by accident: the assertion is on a backend-side call counter, not on a response field the gateway could synthesise |
| SUB.4, direct route — the second forward path | same key and tool, but shaped so the request takes the general forward below the `tools/call` block rather than the sanitized-params return; assert the backend still saw ONE call | YES, RED today, and it is the row that catches the likely wrong fix. A guard sited inside the `tools/call` arm makes the first row green and leaves this one red. Its only purpose is to fail if the guard is sited on a branch instead of before it |
| SUB.4, direct route — caller binding (Axis 4) | two DIFFERENT authenticated callers present the SAME idempotency key for the same tool; assert the backend saw TWO calls | YES — and it can fail in BOTH directions, which is why it is written before the guard exists. Today it passes vacuously (no guard, so nothing pools) and it is the row that goes red if the guard is built with an unbound key. A vacuous pass is recorded as such in the evidence cell until the guard lands; a green cell here before implementation is not evidence |
| SUB.4, direct route — malformed retry field | over the direct route, present a retry key violating the field's constraints; the call is REFUSED pre-dispatch | NOT YET WRITABLE — and the empty evidence cell is the finding. The HTTP meta route's refusal is the reference behaviour; whether the direct route owes the same refusal is the scope question flagged to the requester alongside rev 7's stdio half. Row exists so the gap is visible; it is not claimed as covered |

The last row's empty cell is deliberate per §P2: a plan that quietly omits a row it cannot yet
write reports better coverage than it has.

### What this revision does NOT do

- It does not implement anything. Every row above is RED or unwritable, and the guard does not exist.
- It does not settle the malformed-retry-field scope on either transport. Rev 7 raised it for stdio,
  this raises it for the direct route, and it is one question for the requester, not two.


## Revision 9, 2026-09-09 — the rev-8 repair: the guard site was wrong

§P4 REVIEW OF REVISION 8 (2026-09-09). `gpt-review` returned `SHIP-WITH-FIXES` (rc=0,
`process_status: ok`, verdict read from the ledger row, never scraped from the body — §PA).
Headline: *the proposed replay site bypasses tool authorization*. Three findings, two CRITICAL and
one HIGH, all confirmed at source before repair. Four IMPROVEMENTs, all accepted.

The second leg did NOT return a verdict. `kimi-review` was run twice on identical material and
both rows read `process_status: error`, `verdict: ""` — the first run returned a review of an
unrelated GPU-fuzzing paper, the second emitted raw tool-call control tokens. Per §PA that is
`ERROR`, not a verdict, and it is NOT recorded as agreement. `grok-review` was launched as the
substitute second leg on the same material; its verdict is recorded when its ledger row lands, and
this revision is not final until it does.

### F1 (CRITICAL, confirmed) — the guard cannot sit before authorization

Rev 8 sites the guard before the `if method == "tools/call"` block. `apply_backend_tool_call_security`
— tool policy, name validation, input sanitization — runs INSIDE that block. So a replay would be
served from cache without the retrying caller's *current* permissions being checked. A caller whose
access was revoked between the original call and the reissue would still be handed the protected
result. That is a privilege-escalation path introduced by a feature meant to be conservative.

**Repair — the guard moves after the security decision, and rev 8's siting argument is retracted.**
What survives from rev 8 is the *requirement* the siting was chosen to satisfy — ONE guard, both
forward paths — and it is now met the other way round: rather than hoisting the guard above the
branch, both forwards must converge below the security decision so a single guard sees them. Order
is fixed and is the design: resolve identity → INV-2 isolation refusal → `apply_backend_tool_call_security`
→ **idempotency guard** → forward. A guard that runs before authorization is not a lazier version
of this one; it is a different and worse feature.

### F2 (CRITICAL, confirmed) — the key must carry the backend name

Rev 8's proposed method takes the tool name and params. The direct route is addressed per backend
(`/mcp/{name}`), and two backends may expose the same tool name. Without the backend in the
fingerprint, a key reused across backends returns the wrong backend's result. **Repair: the backend
name is part of the request fingerprint, and the method takes it explicitly.** Reuse the existing
server/tool/arguments fingerprint construction rather than inventing a second one — a second
spelling of a key is the drift the `CallerIdentity` comment already warns about.

### F3 (HIGH, confirmed) — the reservation lifecycle was left undefined

Rev 8 specified admission and stopped. `src/idempotency.rs` already defines the contract:
`GuardOutcome::Proceed(IdempotencyReservation)` or `GuardOutcome::CachedResult(Value)`, with commit,
completion and release settling the reservation. Leaving that unstated lets an implementer release
protection early or strand a completed call marked in flight — a defect with the same symptom as
the one the guard removes.

**Repair, stated as the contract:** the `pub(crate)` method returns the existing `GuardOutcome`.
`CachedResult` returns to the client without dispatch. `Proceed` hands the handler a reservation it
holds ACROSS dispatch and settles on every exit — success, backend error, and the early returns —
using the existing commit/complete/release semantics unchanged. No new lifecycle is invented here;
route 3 adopts route 1's.

