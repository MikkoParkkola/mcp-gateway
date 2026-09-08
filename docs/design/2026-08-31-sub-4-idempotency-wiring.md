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

**Carrier and current baseline.** The old `resolve_idempotency_key` description
was stale at takeover: that function no longer exists, and automatic key derivation
is not current behavior. The active design uses the operator-selected
`params._meta["io.mcp-gateway/idempotency-key"]` on both public routes. Production
builder wiring and direct-route admission remain required; no invented auto-key
baseline may be used to claim a red test.

**The direct route bypasses the machinery entirely.** `POST /mcp/{name}`
(`src/gateway/router/backend_handlers.rs:338-353`) does not go through `invoke_tool_traced` and
does not currently share the mandatory production idempotency admission boundary.
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

**P2 — explicit operations, mandatory write protection.** No key is automatically
derived from an otherwise identical body. A call explicitly classified read-only
by gateway-controlled policy may execute keylessly and repeated
calls both run. Any modern-protocol tools/call not affirmatively classified read-only must
supply a valid explicit key and stable verified principal or be refused BEFORE
dispatch. Downstream annotations alone, including readOnlyHint=true, are not authority for this exemption. Deliberate
repeated modern writes use different keys. SUB.4 applies to the modern protocol's
reissue semantics. Legacy 3.5-compatible requests retain their existing unkeyed
synchronous behavior (NFR.COMPAT.2), including existing auth-disabled and stdio
clients without configuration changes. A legacy call explicitly opting into the
reserved retry-key carrier uses the same protected admission/owner checks; it cannot
bypass an existing modern guard merely by changing era. A modern call omitting a
key never silently falls back to the legacy path. Era comes from the existing
validated request negotiation, never arguments or a new client override. No
protection is claimed for a legacy request without an operation key. Document
that existing legacy boundary and the modern mandatory-key contract together.

**P3 — bound entries AND retained bytes.** The existing map intends a 10,000-entry bound but checks len before the per-key lock, so concurrent distinct keys can overfill it. Enforce a STRICT global slot reservation in the one shared admission map transaction, then add a 512 KiB
maximum secured result per entry and a 128 MiB aggregate result budget. Reserve
metadata capacity before dispatch; reserve exact serialized result bytes atomically
before storing. If a completed result exceeds either byte bound, store a compact
completed/no-result marker using the already reserved metadata slot. Retries get
an explicit retained-result-unavailable tool error and NEVER redispatch the effect.
Do not evict unexpired guards to make room. Same-key retrieval remains available
at capacity. Budget markers and metadata also count toward bounded total memory;
set a 4 KiB serialized metadata/key/fingerprint envelope per entry, rejecting
oversized keys before reservation. The wire-independent accounting encoding is
compact UTF-8 JSON of this fixed-order tuple: `[1, principal, explicit_key,
operation_sha256_hex, representation_sha256_hex, mode, expires_unix_secs,
state_tag, task_id_or_null]`. Strings use serde_json escaping, no whitespace;
mode/state are bounded enums, hashes are lowercase64hex, task IDs are bounded
to36bytes, and expiry is a checked u64 integer. Reserve the largest permitted
state/task-ID representation at admission, so a settlement never exceeds its
reserved metadata budget. Envelope bytes include quotes, escaping, commas,
brackets and null; neither raw arguments nor result bytes are in this envelope.
Result bytes have their separate stated budget. Require exact4096byte and4097byte
independent fixture vectors with quote/backslash/Unicode keys, not only ASCII length. Counts and bytes release only on expiry/removal. Use one parking_lot mutex around the admission map/counters for these short synchronous transactions; no await or backend/disk I/O while held. Task creation retains its reserved slot across unlocked disk commit. Store completed results as canonical serialized bytes (Arc<[u8]>) with exact accounting, not unbounded heap-expanded Values; parsing for delivery is bounded by the per-result cap.

**P4 — one execution identity across representations.** `_full`, projection arm,
session and response format NEVER partition admission identity. Preserve the
principal+explicit-key guard for every output mode. Store the requested
representation descriptor beside the canonical operation fingerprint; a retry
asking for a different descriptor receives 409/Mismatch without new dispatch.
If experimental projection selects an arm, derive it deterministically from the
stable admission identity, not session ID. This scope chooses mismatch refusal,
not a new raw-result reprojection store. Replays recheck current authorization and
response policy and receive fresh delivery signing; no stored signature is reused.

**P5 — an explicit key is not bound to the request.** The client key is used verbatim
(`src/gateway/meta_mcp/support.rs:40`) with no fingerprint of `(server, tool, arguments)`. Reusing
one key across two different calls replays the first result and silently skips the second
mutation. Fix: store the canonical request fingerprint with the entry and reject mismatched reuse
rather than replaying.

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
- **R5 — resolved: no unbound protected execution.** If no stable verified
  principal can be constructed, refuse before protected admission/dispatch. Apply
  this to task and synchronous routes, including auth-disabled HTTP; never share
  a placeholder, display name, session ID or empty suffix as a protection owner.
  Supported trusted stdio identity must come from its server-owned authorizer,
  never client-supplied arguments. Keyless read-only behavior remains P2's separate
  path. Document this compatibility boundary with the key requirement.
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
  remembered: **if rev-5's review opens with no ruling, file it.** Not a competing disposal — the
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

## Two decisions, plus one the review created

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
the key travels in `_meta` on both routes. An earlier revision recorded this axis as already
settled by an operator instruction the session record does not contain; that attribution was
withdrawn and the question re-put. The reasoning below is the design's, the choice is the
operator's.

The specification is not silent. `_meta` is the protocol's own field for out-of-band data on a
request, so the meta route carries the key at `params._meta["io.mcp-gateway/idempotency-key"]`.
That is protocol-native, survives over stdio where a client has no HTTP layer at all, and adds
nothing to the tool schema, so the compact-surface decision in `CLAUDE.md` is untouched. The
direct route `POST /mcp/{name}` uses that same request `_meta` field. It must parse
and validate the carrier before forwarding the call; an HTTP header is not an
alternative authority, and is not used to override a payload key.

Rejected: an `idempotency_key` tool argument, because it puts a gateway-internal concern into
every backend tool's advertised surface. Rejected: a header on both routes, because a stdio
client has no headers and would be left unprotected. Rejected: keeping automatic derivation as a
fallback, because it is defect P2 — deriving a key for a client that never asked for one silently
collapses deliberate repeats for 24 hours. Protected operations require a valid explicit key before dispatch; the read-only exemption is defined by trusted policy below.

## Open questions — each scheduled, none assumed

| question | how it is settled | state |
|---|---|---|
| What carries a retry key, on both routes? | ASKED 2026-08-31, four options put, ANSWERED: `_meta` on both routes. Rejected in the ask: an HTTP header alone (a stdio client has no HTTP layer, so protection stays unreachable for local setups), keeping automatic derivation (ships fastest, keeps P2's silent 24-hour collapse of deliberate repeats). | RESOLVED — `_meta` on both routes; code unblocked |
| May an operator disable protection a criterion states as MUST? | DECIDED on the requirement rather than asked: no. A switch makes the criterion unverifiable wherever the running configuration differs from the shipped default. Recorded so it can be overruled, not so it can be confirmed. | RESOLVED — overrulable |
| Does ADR-008 bear on the direct route's bypass? | CHECKED end to end. It does not; rung 2 is client-native OAuth passthrough. What it does bind is INV-3. CHANGED: the bypass loses its justification and axis 2 gains a placement constraint. | RESOLVED |
| What capacity bound, and what happens at the bound? | CHECKED `src/config/features/cache.rs:12` and `src/cache.rs:185-204`: bound 10_000, policy evict-oldest. CHANGED: take the number, reject the policy, fail closed. | RESOLVED |
| Does a configured backend timeout exceed `IN_FLIGHT_TIMEOUT`? | CHECKED. Per-backend `timeout` defaults to 30s (`src/config/mod.rs:1383`), enforced at `src/transport/http/mod.rs:305`; the server's `request_timeout` is also 30s (`src/config/mod.rs:1178`). CHANGED: P7 is out of reach at defaults and reachable only by configuration, so its fix shrinks to a config-load validation. | RESOLVED |

Nothing is deferred, and nothing is open. Every row above is RESOLVED; the first was answered on
2026-08-31 and the code it gated is unblocked. A paragraph here used to record the state before that
answer arrived, and read as a live block on a row the table calls settled. It is deleted rather than
amended, because a reader who reached it first stopped there.

## Test plan

**Fixture invariant: `config.cache.enabled = false`, except the explicit SUB4.SYNC.CACHE.1 cache-ON discriminator in the [owner-transfer amendment](2026-09-07-sub4-continuation-owner-transfer.md).** Three reviewers
independently found rows that pass through the response cache rather than the code under test.
The response cache stores before transmission, so no argument about *when* a stream aborts can
defeat it. Turning it off in the fixture is the only mechanism that does, and stating it once as
an invariant is what stops the defect returning row by row.

| criterion | case | how it fails today |
|---|---|---|
| SUB.4, meta route | abort after the backend executed, reissue with a new request id and the same retry key, assert a mutation counter on a `destructiveHint` tool reads 1 | unwired: the counter reaches 2 |
| SUB.4, concurrency (P1) | two same-key requests in flight together; exactly one executes, the other gets `409` or the stored result | non-atomic `enforce` lets both proceed |
| SUB.4, direct route | the same post-execution reissue through `POST /mcp/{name}` | that route never resolves a key |
| no false dedup / mandatory write guard (P2) | identical explicitly read-only keyless calls both execute; external write/unknown mutability missing key refuses before dispatch; two distinct valid keys deliberately execute twice | missing-key write gate currently absent; no-auto-dedupe control stays independent |
| `_full` protection (P4) | the meta-route case again with `_full` requested | `want_full` forces the key to `None` |
| key/request binding (P5) | one key reused for a different `(server, tool, arguments)`; the second call must be refused, not replayed | the key is used verbatim, so the first result is replayed |
| reservation window (P7) | Through production config load and reload, effective protected non-task execution timeout strictly below `IN_FLIGHT_TIMEOUT` loads; equality and one-above refuse before activation. Exercise server, backend and bridge aggregate timeout surfaces, with cache OFF. Task-owned dispatch uses its durable reservation and does not inherit this volatile expiry. | rejects unsafe configuration rather than allowing a reservation to expire while work still runs; include valid below-bound positive control |
| completed effect before refusal (P6) | backend commits one effect, final response contract/firewall refuses, then same key is retried; count remains one and retry gets secured retained outcome/refusal | removing reservation on post-effect refusal permits duplicate execution; BRIDGE owns per-attempt ordering |
| count and byte bounds (P3) | keep 10,000 guard cap; independently hit per-result/aggregate byte limits and assert compact completed marker, no eviction, no duplicate dispatch on retry; exact limits and one-over | existing entry bound is a regression control; result bytes and completed no-result settlement are new guards |
| MRTR.10b regression | a usable authenticated continuation preserves the same owner and permits one validated next phase; it is not stored as completed. A dispatched malformed/capability-refused interim with no usable continuation retains unavailable ownership under the same key, without a no-effects claim or automatic redispatch. A new deliberate key is a new operation, not a guarantee about prior effects. | See [the owner-transfer amendment](2026-09-07-sub4-continuation-owner-transfer.md): both HTTP routes must use authenticated single-use claims and preserve explicit-key ownership through final secured settlement. |

The assertion is a mutation counter on the tool, never the response body: two identical bodies
are also what executing twice produces.

**Two constraints and one case, transferred 2026-09-06 from the MRTR.8b/10a design when Change B was
withdrawn.** That change's plan had written them for a wiring that no longer exists; they are
constraints on *this* plan because this is the change that activates the cache.

- **The activation test constructs through the production builder, not a hand-assembled server.**
  A fixture that builds the idempotency layer directly proves the layer works and says nothing
  about whether the shipped configuration path reaches it — which is precisely the `enable_idempotency`
  failure mode (`src/gateway/meta_mcp/mod.rs:657`, `#[allow(dead_code)]`, field initialised `None`
  at `:437`) that a test could have caught and did not.
- **A negative case for the absent section is transferred NOWHERE, deliberately.** There is no
  optional `idempotency.enabled` key here — activation is mandatory ("Two decisions, plus one the review created", Axis 1) — so a row
  asserting behaviour when the section is absent could only be written by reintroducing the kill
  switch this design refused. Recorded so its absence reads as a decision rather than a gap.

| criterion | case | how it fails today |
|---|---|---|
| cross-principal binding (P8/P9) | two *different* authenticated callers issue the same tool, same arguments and the same key string, with identity propagation OFF; the second must execute rather than receive the first's stored response | `identity_suffix` is empty at that default, so both callers derive the same *key* (`support.rs:43`); `admit` looks the entry up by key (`idempotency.rs:256`) and `matches` (`:130-131`) then compares fingerprints, which are identical because the two calls genuinely are the same `(server, tool, arguments)` — so it returns `AdmitOutcome::Completed` and replays |

## Current TASKS/SUB.4 admission contract — 2026-09-06

One `ExecutionAdmission` service owns `(stable verified principal, explicit key)`
for BOTH task and synchronous execution. Compute its identity with domain-separated
SHA256 over a canonical structured tuple (use existing hashing::sha256_hex).
Never concatenate an attacker-supplied prefix with a raw principal suffix. The
operation fingerprint is stored beside it, not included in the lookup identity.
Canonical operation fingerprint covers the secured backend target/name/arguments
and semantic MRTR retry discriminator. Exclude transport ID, session ID, task
capability declaration and presentation controls; include every value actually
forwarded as backend arguments, after ordinary gateway control removal/sanitization.
Credentials and nonce/signature material are not fingerprint fields. Preserve
MRTR answers/state so a changed retry cannot masquerade as the original request.

Implementation checkpoint (2026-09-07): keyed code-mode and playbook admission
checks every planned target through the existing authorization chokepoint before
retained-state lookup, including requests that would otherwise mismatch. Legacy
unkeyed admission retains its existing per-step behavior. Playbook preflight
checks definition arguments; ordinary dispatch still checks interpolated arguments.
The complete cloned definition is hashed into the bounded operation descriptor
and held by its request owner for dispatch. An engine replacement must not switch
the admitted operation; a fresh key uses the new definition. This makes the
definition ownership explicit without changing the shared admission identity or
waiving current checks. The six current-policy/semantic-identity component tests
pass. The deterministic engine-replacement dispatch test independently received
P2 SHIP (`mcp-v4-sub4-snapshot-tests-20260907-r1`) after proving that the previous
runtime selected the replacement definition. Dispatch now reads its owner's
snapshot, and all 71 focused policy/playbook/code-mode checks pass. Code review,
quantitative evidence, full transport integration and final DoD remain open.

The first runtime review confirmed two further gaps: preflight must apply the
current routing profile as well as credential/tool policy, and HTTP admission
must preserve a typed authorization refusal's status. Added P2 regressions cover
playbook/code-mode/single-target profile revocation before mismatch, restoration
of the same owner's replay, and real modern/legacy-keyed HTTP 403 with permitted
dispatch and ordinary-400 controls. All five reproduce their intended defects;
their test review is pending. Reuse the existing replay-applicable invocation
policy checks with the actual session context; do not infer HTTP status solely
from a JSON-RPC error code. No broader authorization contract is changed.

Current-profile/HTTP checkpoint (2026-09-07): Grok runtime now passes the
session through keyed playbook and code-mode target checks, uses the existing
`check_invocation_policy` for unprepared single-target admission, and preserves
`Error::Forbidden`'s HTTP status while JSON-RPC 409 stays 409 and ordinary
errors stay 400. Snapshot/fingerprint ownership and the legacy unkeyed bypass
are unchanged. P2 finder SHIP (`grok-sub4-profile-status-p2-closure-20260907`).
Behavioral RED was actual 101 on the three profile tests (409 instead of
profile denial) and the two HTTP tests (400 instead of 403). Supervised Spark
GREEN, runner actual 0: HTTP 2 pass; related library 74 pass (including the
three new profile tests and the immutable snapshot tests); public regressions
59 pass (`message_signing_delivery` 5 + `sub4_execution_admission` 54).
Approved tests observe a registered forbidden backend at count 0 and a broader
credential at count 1. Strict library Clippy remains the same 76 inherited
diagnostics as the root baseline; none in the three owned files; not a
whole-clippy, whole-SUB.4, DoD, or release claim. Source is local/uncommitted.
Commands, logs, and hashes:
`/Users/mikko/Documents/Codex/2026-09-06/mcp-gateway-v4-scope-review/grok-sub4-profile-status-20260907`.
Both finders returned SHIP on that original profile and HTTP checkpoint. Claude
then preserved the original `gateway_invoke` attestation envelope rather than
reshaping it: the newly embedded Enforce HTTP 4, plus 2 HTTP, 74 library and 59
public, are 139 GREEN. Strict library Clippy is 72 inherited against the root
baseline's 76, exactly 4 root mechanical diagnostics removed and none in the
owned files. P2 SHIP and both P4 legs SHIP, runner actual 0, run
`grok-sub4-attestation-code-closure-20260907`, binding
`7dbfaf2c5d10a7b39eccec390303001b78b26623a638fd029af6cb810c739808/26966`; the
preceding evidence folder is `grok-sub4-policy-envelope-20260907`. The existing
SDK Enforce surfacing and discovery limitations remain separately recorded,
neither fixed nor supported in 4.0, and no CLI Enforce rollout is claimed.

After ordinary current authorization and key/identity validation, one atomic map
transition chooses Sync or Task for a previously unseen identity. The task path
reserves CreatingTask before disk I/O, blocks same-key callers, commits its durable
record/index, then publishes its task handle. No acknowledgement or dispatch before
durability. A failed pre-publication task creation releases only its own reserved
entry and has performed no backend work. Sync uses the existing atomic reservation
and settlement guard behind that SAME owner service; no independent competing
lookup permits dispatch. Existing ownership is checked before current per-request
eligibility is allowed to choose a path. A same-key different-mode retry gets
409/Mismatch, in either direction, including after task-store restart rebuild;
it cannot fall through to synchronous execution or create a second task. A
same-mode matching task retry returns its one handle; matching Sync returns its
in-flight/secured completed outcome. Fingerprint or representation mismatch always
refuses. Different keys remain independent operations.

Startup restores Task ownership into this service from durable records before
HTTP/stdio admission begins. Synchronous guards retain their documented process
lifetime; no cross-restart synchronous-write replay guarantee is invented. A
persisted task cannot be bypassed by reconnecting without tasks declaration.
CreateTaskResult is not stored as completed synchronous output. Bound admission
metadata for Sync and Task together, while task records retain their separate
256-record/128 MiB storage caps. One owner, two settlement kinds, no duplicate
execution owner and no per-request mode switch after reservation.

Required added cases, cache OFF on both routes:

| ID | Decisive assertion |
|---|---|
| SUB4.MODE.1 | Barrier-race same principal/key/body with one contender through /mcp gateway_invoke and the other through /mcp/{backend}, task declaration present/absent; one backend start at most, one chosen mode; loser gets conflict. Reverse winning order. Persist Task winner, restart, retry without declaration: zero new starts. |
| SUB4.REPR.1 | Same principal/key/body across sessions, experimental arms and `_full` choices never repeats effect; matching stable descriptor replays, changed descriptor conflicts. Positive different-key control executes twice. |
| SUB4.SPOOF.1 | Victim key `X` and unverified attacker key `X|idp:<victim binding>`: attacker refused before dispatch/lookup; victim result never exposed. Also two verified distinct owners with DIFFERENT crafted prefix/suffix keys cannot collide; each gets its own counted result. Directly falsify structured derivation with ambiguous raw concatenation. |
| SUB4.BYTES.1 | Exact and one-over 4 KiB serialized key/metadata envelopes on both routes (reject before lookup/reservation/dispatch), 512 KiB per-result and 128 MiB aggregate bytes, concurrent settlements, compact marker retry, TTL release and positive small-result replay. No unexpired eviction or backend redispatch. |
| SUB4.CARRIER.1 | Both routes use payload `_meta` key, reject malformed values, and ignore conflicting HTTP key header as authority; backend never receives gateway retry metadata. |

### Authoritative read-only and nested work rules

`idempotency.read_only_tools` is an operator-controlled list of exact structured
{server, tool} targets, empty by default. It has no activation switch. Configuration
validates target names and size limits before use; no wildcard or client `_meta`
override. Only this list or the gateway's compiled, audited read-only built-in
classification permits keyless execution. Remote annotations, injected tool
names, response content and caller claims never add to the list. A backend
falsely advertising readOnlyHint=true with no policy entry must refuse keyless
execution; its keyed positive control executes once. Add a valid policy-listed
read-only positive control. Wire the same policy on meta, direct and stdio routes.

Every potentially mutating modern-protocol tools/call takes shared admission, including
`gateway_run_playbook`, `gateway_execute` and mutating gateway management tools.
For orchestration, one outer lease protects the whole logical invocation; internal
steps carry its unforgeable server-owned execution context and cannot bypass the
outer owner through client metadata. Per-step backend authorization/response
controls still run. Completed effect/refusal retains a completed guard. Test
post-effect disconnect/reissue of each orchestration tool, effect counter one,
and distinct-key intentional repeat counter two. Ordinary core protocol methods
outside tools/call are not silently promoted into this work-operation API.

| ID | Decisive additional assertion |
|---|---|
| SUB4.READONLY.1 | A malicious remote readOnlyHint alone never permits keyless execution; exact operator policy target and compiled read-only built-in do. Modern unknown/mutating built-ins refuse without key; legacy behavior remains compatible. |
| SUB4.ORCHESTRATE.1 | Real gateway_run_playbook and gateway_execute each commit a counted backend write, lose response, receive same-key retry: one effect. Fresh-key control produces two. Internal steps retain ordinary security checks. |
| SUB4.SLOTS.1 | With one slot remaining, barrier-release many DISTINCT new keys across meta/direct routes and task/sync modes. Exactly one admission succeeds, global map never exceeds 10,000 and losers never dispatch; same-key existing retrieval still works at capacity. |

Verified-owner raw-concatenation collision fixture (R6) uses two actual
`VerifiedIdentity` values from validated signed OIDC tokens, one configured issuer
`https://idp.example` and the SAME configured backend audience `https://svc/a`.
Derive every binding through `stable_actor_id()` and the production signed-assertion
identity-propagation builder. The fixture construction is executable and avoids
assuming that raw subjects themselves are cache bindings:

```python
issuer = "https://idp.example"
audience = "https://svc/a"
def actor(subject):
    return f"oidc:{len(issuer)}:{issuer}:{len(subject)}:{subject}"
def binding(subject):
    value = actor(subject)
    return f"idp:{len(value)}:{value}:{len(audience)}:{audience}"
subject_a = "alice"
trailer = f":{len(audience)}:{audience}"
binding_a = binding(subject_a)
subject_b = "bob|idp:" + binding_a[:-len(trailer)]
binding_b = binding(subject_b)
suffix_a, suffix_b = "|idp:" + binding_a, "|idp:" + binding_b
assert suffix_b.endswith(suffix_a)
key_a, key_b = "X" + suffix_b[:-len(suffix_a)], "X"
assert key_a != key_b and key_a + suffix_a == key_b + suffix_b
```

The test obtains both real verified identities through the production HTTP builder,
checks its propagated binding bytes against this independent ASCII fixture, then
asserts the two OLD concatenations are byte-identical before testing the new
structured identities and owner-specific counted outputs. The opaque OIDC subject
containing delimiters is signed by the fixture issuer; it is not injected as an
unverified caller argument. Keep the unverified-attacker R5 vector separate.

### r4 finder repairs: compatibility and complete mutation paths

The exact compiled read-only meta-tool allowlist is `gateway_search`,
`gateway_list_servers`, `gateway_list_tools`, `gateway_search_tools`,
`gateway_get_stats`, `gateway_cost_report`, `gateway_webhook_status`,
`gateway_list_disabled_capabilities`, `gateway_get_profile`, and
`gateway_list_profiles`. Audit those real handlers before implementation. Tests
compare the classification domain with the production dispatch/exposure registry
and require every new name to be explicitly classified; unknown names default to
requires-key on the modern path. `gateway_invoke` and surfaced/direct backend
calls use exact trusted target policy instead. Orchestration and management
never inherit a downstream untrusted readOnlyHint exemption.

| ID | Decisive additional assertion |
|---|---|
| SUB4.COMPAT.1 | Real 3.5-era HTTP and stdio clients with unchanged config, no key and no new principal requirement execute the same supported mutation as before; two intentional calls still execute twice. Modern matched controls refuse without key and dispatch zero times. Modern keyed call followed by same-owner/key legacy opt-in replay cannot repeat the effect. |
| SUB4.MANAGEMENT.1 | Independently drive each actual mutation branch: gateway_kill_server, gateway_revive_server, gateway_set_profile, gateway_set_state, gateway_reload_config, gateway_reload_capabilities. With required existing admin/session config, commit effect then drop response before delivery; same-key reissue reaches the handler only once and returns retained secured result. Observe real method entry/effect revision through a server-owned test counter, plus the resulting live state; do not accept idempotent final state alone. New-key control reaches the same handler twice. Both HTTP meta and actual stdio dispatch, cache OFF; same-key representation mismatch does not execute again. |
| SUB4.CONTENTION.1 | On the fixed Spark host record admission-wait P50/P99 and throughput under a mixed Sync/Task workload at1/16/64concurrency, same-key and distinct-key cases. No I/O under map lock; compare no-contention and contended runs, retain all samples. This is diagnostic evidence alongside the release NFR latency thresholds, not an invented standalone pass threshold. |


Design closure receipt (2026-09-06): GPT r5 SHIP, actualexit0/processok,
run mcp-v4-tasks-design-20260906-r5; bound SHA256
bd1e78c214242a7a8c6bbc0310293ccdb56351a2d7d1fd9bfd18f7c00d60eeb7,
210396bytes. Grok r2 SHIP retained under development-process item6. No source or
acceptance pass is claimed. Small reviewer improvements adopted before tests:
reserved retry keys are nonempty JSON strings, exact decoded Unicode scalar
sequence, with no normalization, trimming or delimiter restrictions; the complete
metadata-envelope cap bounds them. Null/nonstring/empty values reject. Crafted
R6 ASCII delimiter keys are valid positive fixtures. Derive the management test
matrix from the production dispatch registry/classification and compare it with
the explicit six-name baseline so a new branch cannot silently escape coverage.

The [owner-transfer amendment](2026-09-07-sub4-continuation-owner-transfer.md) is the controlling continuation/stdio invariant. Its typed StdioLocalOperator is created only by actual stdio dispatch, never by ToolPolicyAuthorizer; no HTTP credential or caller metadata can construct or alias it. Its ticket-qualified OWNER cases also appear in the canonical test plan.
