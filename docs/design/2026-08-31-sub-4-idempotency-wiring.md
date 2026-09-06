# MIK-7272.SUB.4 — idempotency protection for reissued side-effecting calls

Status: proposed, revision 5. No code written. Revisions 1 and 2 were reviewed by GPT-5.x and
Grok; both returned `SHIP-WITH-FIXES` on revision 2. Revision 3 was the repair. Revision 4 settles
the last question a check could settle, and records what happens to the two that need a person.

Revision 5 is NOT reviewed. It is P8, P9, the "Risks that fire on activation" section and the
test-plan transfer, which arrived 2026-09-06 from the MRTR.8b/10a design when that change withdrew
its Change B, plus the reference corrections of the same date. No reviewer has seen any of it: the
`SHIP-WITH-FIXES` above is a verdict on revision 2 and says nothing about this material. It rides
the next dual-vendor design review, before SUB.4 writes code.

## Scope

FOR: deciding how a side-effecting call, reissued after a broken stream with a new request id,
becomes protected — which is what MIK-7272.SUB.4 requires.

OUT:
- the tasks extension (MIK-7272.TASK.1, ABSENT). It is the criterion's other branch and a far
  larger surface; this design neither builds it nor depends on it.
- idempotency key *derivation* as an algorithm. `derive_key` and `RetryFields` exist and are
  tested. What is in scope is *when a key is derived at all*, and *what it is bound to*.

## Problem

The idempotency machinery is complete and unreachable, and it has no way in.

- `MetaMcp::idempotency_cache` is initialised to `None` in `MetaMcp`'s constructor, and that is
  its only initialiser.
- Its only populator, `MetaMcp::enable_idempotency`, has zero PRODUCTION callers:
  `rg --hidden --no-ignore 'enable_idempotency' .` returns its own definition and one call from
  `src/gateway/meta_mcp/tests.rs`.
- No configuration key gates it: `rg -n 'idempotency' src/config/mod.rs` returns nothing.
- It carries `#[allow(dead_code)]`, which silences the warning the `-D warnings` gate would
  otherwise have raised. That the attribute is *why* it survived is inferred (I), not read.

So the enforcement site in `invoke_tool` takes the `None` branch in every
build that has ever shipped.

Two further gaps compound it, both found in review and verified at source.

**No advertised way for a client to send a key.** The carrier plumbing exists — the meta
route reads `caller.retry.idempotency_key` (the MRTR retry envelope, `src/protocol/mrtr.rs`)
and passes it to `idempotency_key_for` (`src/gateway/meta_mcp/support.rs:35-44`,
`invoke.rs:1148`). What does not exist is any way for a client to *learn* that it may send one:
the field is in no tool schema. A client cannot discover it, so today the *only* reachable protection
is the automatic derivation — which is itself defect P2 below. This is the finding that
reshapes the design: "enforce only on an explicit client key" is not an available option until
a carrier exists on both routes.

**The direct route bypasses the machinery entirely.** `POST /mcp/{name}`
(`src/gateway/router/backend_handlers.rs:338-353`) does not go through `invoke_tool_traced` and
never reaches `idempotency_key_for`, whose sole call site is `meta_mcp/invoke.rs:1148`.
Revision 1 attributed that bypass to "ADR-008 rung 2"; that was a misreading. ADR-008 rung 2 is
client-native OAuth passthrough and says nothing about HTTP routing. No ADR sanctions the
bypass.

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
(`src/idempotency.rs:37`) expires a reservation after 5 minutes regardless of whether the original
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
closes the ADR-008 finding while leaving the replay. Dormant while the cache is unreachable, live
the moment this change wires it on, which is what makes it blocking for activation rather than a
follow-up.

## Risks that fire on activation

R4 and R5 arrived 2026-09-06 from the MRTR.8b/10a design when Change B was withdrawn. They were
risks *of activating the cache*; that change activates nothing, so they are this one's from the
moment it does. R6 was found 2026-09-06 while source-verifying this document's own ADR-008 bullet.
It is not inherited, but it is the same kind of risk: it fires when the cache is activated, and
not before.

- **R4 — loose key reuse starts returning 409.** A caller that today reuses one key string across
  different `(server, tool, arguments)` gets a silent replay; once P5's binding check lands it gets
  `Mismatch`. That is the intended behaviour and it is still a client-visible change, so it belongs
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
  nothing that works today starts failing. Recorded here so the operator can overrule it in one
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
  Consequence for the SUB.4 design, not a separate ticket: whatever fixes P8 must ALSO make the
  suffix unspellable — hash it as `response_key` does, length-prefix it, or move the client-supplied
  key to the tail. Landing P8's fallback chain while the append stays raw reintroduces the exact
  class the response cache hashes to prevent.
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
  not wait on this review. Nothing is exposed in a running deployment today — the bullet above says
  why, and that WEAKENS the ticket case rather than carrying it: the defect is dormant, activation
  is SUB.4's own act, so the only timeline at stake is the ordering of the repair against the
  activation, not production exposure. ISSUE-DOR then applies: acceptance criteria, ROI,
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
- TTLs already exist: `COMPLETED_TTL` 24h and `IN_FLIGHT_TIMEOUT` 5m (`src/idempotency.rs:30-37`).
  Copying `config.cache.default_ttl` instead would shrink protection to a minute.
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
  rather than dormant.

## Two decisions, plus two the review created

**Axis 1 — activation. DECIDED: mandatory, no kill switch.** Off by default cannot satisfy a
criterion that says a reissue MUST be protected, so it is rejected on the requirement, not on
cost. Between on-by-default-with-an-opt-out and mandatory, the criterion decides: an operator
switch makes the criterion unverifiable in the deployments that matter, because the shipped
default and the running configuration can disagree and only the running one executes side effects.
This is an engineering reading of a MUST, not an operator preference, and it is recorded here so
the operator can overrule it in one line rather than discover it in code.

**Axis 2 — coverage.** Meta route alone | both routes. Meta-only leaves a documented ingress
unprotected, which the criterion does not permit. Both routes is the requirement's answer, and
placement is settled above: the binding goes in the derivation.

**Axis 3 — the key carrier.** Protection needs a key a client can actually send, on both routes,
advertised and validated. Nothing in the tree advertises one. This axis is upstream of the other
two: deleting the automatic derivation with no carrier leaves the criterion unsatisfiable, and
keeping it leaves the silent-dedup defect P2.

DECIDED 2026-08-31. Asked of the operator, four options put with their costs, answered:
the key travels in `_meta` on the meta route and an `Idempotency-Key` header on the direct route.
An earlier revision recorded this axis as already
settled by an operator instruction the session record does not contain; that attribution was
withdrawn and the question re-put. The reasoning below is the design's, the choice is the
operator's.

The specification is not silent. `_meta` is the protocol's own field for out-of-band data on a
request, so the meta route carries the key at `params._meta["io.mcp-gateway/idempotency-key"]`.
That is protocol-native, survives over stdio where a client has no HTTP layer at all, and adds
nothing to the tool schema, so the compact-surface decision in `CLAUDE.md` is untouched. The
direct route `POST /mcp/{name}` has no schema to advertise into and is raw JSON-RPC passthrough,
so it takes the key from an `Idempotency-Key` HTTP header, which is the industry spelling.

Rejected: an `idempotency_key` tool argument, because it puts a gateway-internal concern into
every backend tool's advertised surface. Rejected: a header on both routes, because a stdio
client has no headers and would be left unprotected. Rejected: keeping automatic derivation as a
fallback, because it is defect P2 — deriving a key for a client that never asked for one silently
collapses deliberate repeats for 24 hours. Protection applies when a key is present and never
otherwise.

**Axis 4 — an unresolvable principal under a client key. DECIDED: refuse the call.** Created by the
rev-5 review the same way Axis 3 was, and stated in full where the risk that raises it lives (R5,
"Risks that fire on activation") rather than restated here. Named in this section because a reader
auditing what this design decided reads THIS list, and a decision recorded only next to its risk is
one nobody counts. That was R5's original defect and it should not be reintroduced by filing the
answer somewhere the question is not asked.

## Open questions — each scheduled, none assumed

| question | how it is settled | state |
|---|---|---|
| What carries a retry key, on both routes? | ASKED 2026-08-31, four options put, ANSWERED: `_meta` on the meta route, an `Idempotency-Key` header on the direct route. Rejected in the ask: an HTTP header alone (a stdio client has no HTTP layer, so protection stays unreachable for local setups), `_meta` alone (spec-native and stdio-safe, but the direct route is raw JSON-RPC passthrough needing new plumbing, and no client sends it today), and keeping automatic derivation (ships fastest, keeps P2's silent 24-hour collapse of deliberate repeats). | RESOLVED — hybrid carrier, spelled out in Axis 3; code unblocked |
| May an operator disable protection a criterion states as MUST? | DECIDED on the requirement rather than asked: no. A switch makes the criterion unverifiable wherever the running configuration differs from the shipped default. Recorded so it can be overruled, not so it can be confirmed. | RESOLVED — overrulable |
| Does ADR-008 bear on the direct route's bypass? | CHECKED end to end. It does not; rung 2 is client-native OAuth passthrough. What it does bind is INV-3. CHANGED: the bypass loses its justification and axis 2 gains a placement constraint. | RESOLVED |
| What capacity bound, and what happens at the bound? | CHECKED `src/config/features/cache.rs:12` and `src/cache.rs:185-204`: bound 10_000, policy evict-oldest. CHANGED: take the number, reject the policy, fail closed. | RESOLVED |
| Does a configured backend timeout exceed `IN_FLIGHT_TIMEOUT`? | CHECKED. Per-backend `timeout` defaults to 30s (`src/config/mod.rs:1383`), enforced at `src/transport/http/mod.rs:305`; the server's `request_timeout` is also 30s (`src/config/mod.rs:1178`). CHANGED: P7 is out of reach at defaults and reachable only by configuration, so its fix shrinks to a config-load validation. | RESOLVED |

| When neither `cache_binding` nor a stable actor id resolves, is a client-keyed call protected with an unbound key, left unprotected, or refused? | DECIDED on the requirement, with R6 in hand: refused. Protecting unbound is cross-caller replay; executing unprotected fails the MUST silently. Recorded so it can be overruled, not so it can be confirmed. | RESOLVED — overrulable |

Nothing is deferred, and nothing is open. Every row above is RESOLVED; the first was answered on
2026-08-31 and the code it gated is unblocked. A paragraph here used to record the state before that
answer arrived, and read as a live block on a row the table calls settled. It is deleted rather than
amended, because a reader who reached it first stopped there.

## Test plan

**Fixture invariant, applying to every row: `config.cache.enabled = false`.** Three reviewers
independently found rows that pass through the response cache rather than the code under test.
The response cache stores before transmission, so no argument about *when* a stream aborts can
defeat it. Turning it off in the fixture is the only mechanism that does, and stating it once as
an invariant is what stops the defect returning row by row.

| criterion | case | how it fails today |
|---|---|---|
| SUB.4, meta route | abort after the backend executed, reissue with a new request id and the same retry key, assert a mutation counter on a `destructiveHint` tool reads 1 | unwired: the counter reaches 2 |
| SUB.4, concurrency (P1) | two same-key requests in flight together; exactly one executes, the other gets `409` or the stored result | non-atomic `enforce` lets both proceed |
| SUB.4, direct route | the same post-execution reissue through `POST /mcp/{name}` | that route never resolves a key |
| no false dedup (P2) | the *identical* keyless call issued twice, both backends must run | red once the cache is wired with auto-derivation intact — which is the point of the row |
| `_full` protection (P4) | the meta-route case again with `_full` requested | `want_full` forces the key to `None` |
| key/request binding (P5) | one key reused for a different `(server, tool, arguments)`; the second call must be refused, not replayed | the key is used verbatim, so the first result is replayed |
| reservation release (P6) | a call that trips the contract gate after dispatch; a later same-key call must not be locked out | the entry stays `InFlight` until timeout |
| bound (P3) | fill to 10_000, assert a new protected side effect is refused rather than admitted | unbounded map admits it |
| MRTR.10b regression | a non-final `InputRequired` result through the newly wired path must leave the call retryable, not stored as completed | SUB.4 is the change that first populates the cache, so this guard has never run in production; its only coverage calls `mark_completed` directly |

The assertion is a mutation counter on the tool, never the response body: two identical bodies
are also what executing twice produces.

**Two constraints and one case, transferred 2026-09-06 from the MRTR.8b/10a design when Change B was
withdrawn.** The table below also carries rows that are NOT transferred — R6's
falsifier and R5's, both this design's own, added when those risks were written into it. That change's plan had written them for a wiring that no longer exists; they are
constraints on *this* plan because this is the change that activates the cache.

- **The activation test constructs through the production builder, not a hand-assembled server.**
  A fixture that builds the idempotency layer directly proves the layer works and says nothing
  about whether the shipped configuration path reaches it — which is precisely the `enable_idempotency`
  failure mode (`src/gateway/meta_mcp/mod.rs:657`, `#[allow(dead_code)]`, field initialised `None`
  at `:437`) that a test could have caught and did not.
- **A negative case for the absent section is transferred NOWHERE, deliberately.** There is no
  optional `idempotency.enabled` key here — activation is mandatory ("Two decisions, plus two the review created", Axis 1) — so a row
  asserting behaviour when the section is absent could only be written by reintroducing the kill
  switch this design refused. Recorded so its absence reads as a decision rather than a gap.

| criterion | case | how it fails today |
|---|---|---|
| cross-principal binding (P8/P9) | two *different* authenticated callers issue the same tool, same arguments and the same key string, with identity propagation OFF; the second must execute rather than receive the first's stored response | `identity_suffix` is empty at that default, so both callers derive the same *key* (`support.rs:43`); `admit` looks the entry up by key (`idempotency.rs:256`) and `matches` (`:130-131`) then compares fingerprints, which are identical because the two calls genuinely are the same `(server, tool, arguments)` — so it returns `AdmitOutcome::Completed` and replays |
| unresolvable principal under a client key (R5 / Axis 4) | on a non-`required` propagation backend, a caller with neither a `cache_binding` nor a stable actor id sends a client key for a `destructiveHint` tool; the call must be REFUSED — neither executed unprotected nor admitted under an unbound key | no key is derived at all (`idempotency_cache` is `None`), so the call executes unprotected and the criterion's MUST fails silently. That silent branch is the whole reason Axis 4 decides rather than defers: without this row the decision is a paragraph, and a paragraph cannot go red |
| suffix unspellability (R6's repair constraint) | in one deployment, a bound caller sends client key `X` and an unbound caller on the same non-`required` backend sends `X|idp:<the bound caller's binding>`; the two must derive DIFFERENT keys, so the unbound caller is admitted rather than served the bound caller's stored result | the suffix is appended raw and unlength-prefixed against what precedes it (`format!("{key}{projection_key_suffix}{identity_suffix}")`), so the two spellings collide exactly. This row is what stops P8's fallback chain landing while the append stays raw: a chain that resolves more principals but still concatenates plaintext turns this case red rather than green, and only a test says so out loud |
