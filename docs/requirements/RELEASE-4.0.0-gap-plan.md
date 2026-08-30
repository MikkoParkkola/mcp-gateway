<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# 4.0.0 release: gap assessment and plan to shippable

Assessed 2026-08-30 by four independent audits (requirements-vs-code, unwired production paths,
test-plan coverage, docs and release mechanics). Every gap below was verified by reading source,
never inferred from a document. The requirements sweep has not run to completion;
its remaining batches amend section 1 and add increments, they do not invalidate the sequence.

A second audit died on an output ceiling partway through emitting its rows. What
it had produced is recovered in `RELEASE-4.0.0-audit-partial.md` and is a floor
on the blocking count, not a total: at least eight of its findings sit outside
MRTR entirely, which is the first measured evidence of how far section 2 was
undersized. Section 2 now carries them as increments 10-17.

## 1. Where the release actually stands

The 2026 protocol surface is **advertised but not reachable**. `discover_document` announces
`MODERN_VERSIONS` once `modern_protocol=true`, and the retry that the announcement invites is
refused at the door.

| gap | evidence | blocks |
|---|---|---|
| MRTR is unwired end to end | `handlers.rs:879-895` returns -32602 "retry forwarding is not available on this build" for every retry | MRTR.1-.10 |
| Legacy-client bridge never called | `Bridge::to_legacy_client` has no caller | MRTR.7 |
| Outbound era probing unwired | `EraCache::resolve_with`/`classify` implemented and tested, zero callers in `src/backend` or `src/transport` | outbound modern/legacy negotiation |
| Tasks extension is dead code | `protocol::tasks::Task`/`TaskStatus` have no production call site; `tasks/get`/`tasks/update` fall through to method-not-found honestly | nothing — needs a keep/delete decision |
| Header/result/error/cache/order criteria | six gaps found, six criteria confirmed clean | see requirements sweep |
| Blocking criteria outside MRTR | at least eight, in tenancy, stateless confirmation, session expiry, log correlation, cache invalidation, error codes, tasks and extensions | increments 10-17; source rows in `RELEASE-4.0.0-audit-partial.md` |
| Diff coverage under floor | 61 branch-touched files average 77.40% lines against an 80% Standard floor; mutation coverage unmeasured. Measured before increments 1 and 2a landed their tests, so it is a starting point, not the current number | DoD §4 |

Test position, separately: six acceptance criteria have no case at any level, two cases cannot fail
against the defect they are attached to, and the existing `tests/mik_7212_acs.rs` exercises
primitives directly rather than the dispatcher — so it stays green whatever the wiring does. The
test plan says this itself at lines 327-330.

Re-verified on 2026-08-31 against the current tree: the retry refusal, the uncalled
`Bridge::to_legacy_client`, the zero-caller `EraCache` and the dead tasks extension all still hold
exactly as the audit described. Only the continuation-state row had gone stale, and it is removed
above. One in five of the section 1 rows re-read that day
had moved, and it moved because the work was done, not because the reading was wrong. That is a rate
over five rows, not over the audit.

## 2. The sequence

Each increment is independently reviewable and mergeable. Delivery order within every increment is
the standing one: failing tests first, then implementation, then dual-vendor review.

**1 — Continuation state has one owner (S). DONE — closed MIK-7312.** Re-read of the source on
2026-08-31 found this already landed, so the audit row that reported no production owner was written
against an earlier tree and has been removed from section 1. `ContinuationState`
(`protocol/continuation.rs:664-742`) owns the keyring, ledger and in-flight table behind one
lifecycle, generates its key material and replica name per process, and is constructed in the
production `AppState` builder at `gateway/server/mod.rs:1171` — not under `cfg(test)`. Both test rows
this increment asked for exist in `tests/mik_7312_continuation_state.rs`: reachability from an
`AppState`, and a token minted by one `AppState` refused by another. The reachability test builds its
own `AppState` with the same `ContinuationState::new()` call the server makes rather than invoking
the server's builder, so it proves the state is usable through the struct, not that production
constructs it. That second half is evidence from reading `server/mod.rs:1171`, and a test could only
carry it by driving `serve` itself. Design recorded in
`docs/design/2026-08-30-shared-continuation-state.md`. Nothing is left to do here; increment 2b is
the next open item.

**2a — The mint site can see who is calling (S).** No behaviour change, so the existing suite
green before and after is the evidence. Review added four tests anyway, on the capability string the
new `RequestShape::may_request_input` compares against: a typo there compiles and reads as a
correct no-op, so the string needs a test even when the caller of the method does nothing yet. `invoke_tool_traced`
takes `caller: &MetaMcpCallerContext<'_>` in place of its six flattened caller fields, and the
client's declared capabilities reach the scope where that context is built. Two source facts make
this mechanical rather than a design question: `invoke_tool` already takes the context whole, and
the comment at `invoke.rs:419-421` gives the reason in the codebase's own words — the authorizer
travels with the identity it authorizes. `invoke_tool_traced` is private with exactly one call
site. The alternative, two more loose parameters taking it from eleven to thirteen, is rejected by
that same comment.

**2b — Retry reaches the backend (M).** Closes MRTR.1, .2, .3, .9, .10. Delete the `is_retry` arm at
`handlers.rs:879-895` and leave the malformed-envelope arm above it alone; open the envelope, forward
retry fields to the backend as siblings of `arguments` rather than merged into them, mint at the
call site after the result, pass `complete` and legacy results through unchanged. Inbound
`RetryFields` is attacker-controlled client shape and the outbound state is the backend's own
opaque value recovered from the token — conflating the two is the MRTR.2 defect, so they stay
separate types. One defect drives the increment: an `input_required` result is today neither a
success nor an error, so it falls through the `mark_completed` at `invoke.rs:1276` and is cached as
a final answer. MRTR.10 has a second half on the same path: `resolve_idempotency_key`
(`support.rs:31-46`, called from `invoke.rs:779-790`) derives the key from server, tool and
arguments alone, so two retries carrying different `inputResponses` collide on one key and the
second is answered from cache. A sweep note calls that a different call path from `tools/call`;
reading the call site shows it is the same one. The fix must cover both branches of that helper:
an explicit client-supplied `idempotency_key` returns at `support.rs:38-43` before the derivation
runs, so extending the derivation alone leaves a client that reuses its own key colliding exactly
as before. Either both branches carry the continuation fields, or the plan says a reused client
key is the client's problem — it cannot leave the question open. Tests: the integration rows the plan already names, plus a pass-through row and a
fresh-JSON-RPC-id row that a fixture transport can fail. Pass-through asserts value equality and
that no `requestState` key was added, not byte identity — the crate does not preserve key order.

**3 — Single-use and expiry hold across replicas (S).** Closes MRTR.5. Origin refusal precedes any
key lookup; typed and distinct from expired and already-spent. Tests: expiry on redeem with an
injected clock, two `AppState`s racing one token, redeem after the minting process is replaced.

**4 — No second exchange with a legacy backend (M).** Closes MRTR.6. Pin the continuation to a live
`InFlight` hold where the mint recorded one; a missing hold is a refusal. Tests: minted against a
live hold, redeemed on the origin after the hold is gone.

**5 — Legacy-client bridge (M).** Closes MRTR.7 — currently `NOT YET` by design with no test row at
all. Wire `Bridge::to_legacy_client`; decide and record what a legacy client sees when a modern
backend asks. Tests: the whole row set, which does not exist yet.

**6 — Outbound era negotiation (M).** Wire `EraCache` into backend connection setup so outbound
calls probe rather than assuming legacy. Not previously tracked; found by the wiring audit.

**7 — Request binding and per-scheme fingerprint (S).** Closes MRTR.4 properly: same tool with
different arguments is refused, and the fingerprint distinguishes API key, agent JWT and mTLS
callers. The current binding test is generic and one row cannot fail against a short-circuiting
comparison, by its own comment.

**8 — Tasks extension decision (S).** Keep as a documented placeholder or delete. A design event,
not a wiring fix — it needs an owner's call, not an implementation.

**9 — Gate and release mechanics (S).** Raise diff coverage over the 80% floor on branch-touched
files, run mutation coverage and record it, reconcile the three disagreeing clippy invocations
across docs and CI, and add a local guard for the npm version rather than relying on the publish
step to overwrite it. Put the two operational consequences in the release notes: a retry against a
round-robin service is refused on every replica but the minting one, and a rolling restart
invalidates every outstanding continuation. The `docs/DEPLOYMENT.md` rewrite this increment
originally carried is already committed — its "Replica Count and `server.modern_protocol`" section
states the refusal, names the per-process key material as the mechanism, and rules out a
sticky-session workaround. Nothing is left to do there.

**Increments 10-17 come from the recovered audit rows**, which sit outside MRTR entirely. Each row
is the killed agent's claim with a file:line, verified here only as far as the cited location
existing — so re-reading the source is the first step of every increment below, not an optional
check. Sizes differ by more than an order of magnitude and that difference is the point: 10 is
plausibly a one-line change, 16 is a subsystem that does not exist.

**10 — Resource-not-found returns the code the spec names (XS).** Closes MIK-7272.ERROR.2.
`resources.rs:276-280` returns -32002 where the row says the spec requires -32602. Confirm the spec
text before editing — the requirement is the claim under test here, not the code. Tests: one row per
error path, and a check that no existing client contract asserts -32002.

**11 — The gateway declares its own extensions (S).** Closes EXT.1.
`ExtensionSet::gateway_declares()` at `protocol/extensions.rs:59-64` has zero callers, so the
gateway advertises nothing about itself while requiring declarations from clients. Wire it into the
initialize response; deciding what the set actually contains is a design question with a short
answer, not a wiring fix.

**12 — Transparency-log correlation is a real request id (S).** Closes MIK-7215.CONTROL.3. The
correlation key is the literal string it falls back to on every stateless request, because the live
`trace_id` is never passed in (`invoke.rs:1299-1314,429`). This lands next to increment 2a, which
already moves caller identity into that scope — sequence it after 2b so the two do not collide on
the same signatures. Tests: a stateless request whose log entry carries the request's own id.

**13 — Session expiry is reachable (M).** Closes MIK-7215.CONTROL.4. The `session_lifecycle` module
is declared at `gateway/mod.rs:19` and referenced nowhere else. Either wire expiry into the session
path or delete the module and record why — a declared-but-unreferenced lifecycle is worse than an
absent one, because it reads as coverage.

**14 — Cache invalidation on policy change (M).** Closes MIK-7213.CACHE.4. Invalidation is TTL-only
at `invoke.rs:835-839`, so a revoked grant keeps being honoured until the entry ages out. Needs a
policy epoch that participates in the cache key. Overlaps increment 2b, which already touches the
key derivation in that file; do 2b first and extend the same key rather than adding a second
mechanism beside it.

**15 — Destructive-op confirmation on the stateless path (M, design first).** Closes
MIK-7215.CONFIRM.2. Confirmation requires an SSE session today (`proxy.rs:213-260`) and the modern
stateless path has no session to hold one in. That is a design event, not a wiring gap: the question
is what a confirmation *is* without a session, and the continuation machinery from increments 1-4 is
the obvious candidate to carry it. Design reviewed before any code.

**16 — Cross-tenant data minimisation (L, requirements first).** Closes MIK-7215.TENANT.1. The audit
found no guard anywhere in `src/`. This is the only item in the plan with nothing to read, so it
starts with requirements rather than a design: what a tenant boundary means here, what crosses it
today, and what the criterion is actually asking for. It is the largest item and the one most likely
to move the release date — sizing it honestly is the first deliverable, not a commitment to build it
in this release.

**17 — NFR.SEC.6 owner decision (S, owner call).** MIK-7262 is open: the
`registers_external_callback` override is silently skipped for read-only, non-mutating and no-schema
methods (`capability/definition/mod.rs:1113-1152`). Shipping with a known bypass of an
external-callback declaration is an owner's decision in the same shape as increment 8, not something
an increment can close on its own authority.

**All eight cited locations re-read on 2026-08-31.** Six hold as the rows describe: the -32002
return, `gateway_declares` with its single definition and no caller, `session_lifecycle` declared at
`gateway/mod.rs:19` and referenced nowhere else, a cache key built only from server, tool, arguments,
projection and identity, `forward_elicitation_with_response` taking a `session_id`, and the
`registers_external_callback` check at `capability/definition/mod.rs:1150`. Two moved:

- **12 is smaller than S.** The live `trace_id` is in scope at the log call (`invoke.rs:1298`) — the
  `warn!` three lines below already uses it. The correlation key is the session id with a literal
  fallback, so the fix is an argument, not plumbing. Size XS.
- **16 is not a blank page.** Per-user backend pooling exists with stated isolation invariants
  (`backend/pool.rs`, IDP.3 and IDP.5) and cross-tenant isolation tests. The audit row's "no guard
  anywhere in `src/`" is wrong as stated. What the criterion asks — data minimisation across
  tenants — is a different question from backend isolation, and separating the two is now the first
  deliverable rather than writing requirements from nothing.

Two of ten rows checked across both passes were stale, both in the direction of the work being
further along than the audit recorded.

**18 — The destructive-confirmation gate governs every annotated tool (S, one design question open).** Closes
MIK-7246.CONF.3. `destructive_tools_from_annotations()` (`gateway/destructive_confirmation.rs:117`)
derives destructive tools from the `destructiveHint` annotation, is unit-tested, and has no
production caller — verified 2026-08-31, the only references in `src/` are its own doc comment and
its own tests. The live gate at `router/handlers.rs:1024` calls `is_destructive_meta_tool()`, which
is `matches!(tool_name, "gateway_kill_server")`. A backend tool shipping tomorrow with
`destructiveHint: true` inherits no gate.

The design decision this needs is already written down and does not have to be made again: the
doc comment at `destructive_confirmation.rs:143-147` says the two checks compose rather than
replace — the annotation is the source of truth for tools the gateway did not write, the match arm
is the floor for the one it did, so an annotation dropped by accident cannot quietly ungovern it.
So the shape of the fix is an `||` at the call
site rather than a redesign.

What that leaves open is availability, not semantics, and it is why this is not the XS it first
looked like. Checked on 2026-08-31: the gate at `handlers.rs:1024` has only `tool_name: &str` in
scope. `destructive_tools_from_annotations()` takes a whole `tools/list` payload, and `tools/list` is
served from a different match arm (`handlers.rs:834`, via `state.meta_mcp`). There is no derived set
at the gate to ask. So the increment carries a design question before it carries code: **where does
the annotation-derived set live, who populates it at list time, and what invalidates it when a
backend re-lists?** That is new state, the same class of question as the stdio-capability one
deferred out of increment 2a — and it is a cache over a security decision, so a stale entry
ungoverns a tool rather than merely slowing something down.

This is still the plan's cleanest example of DoD D7: the mechanism exists, the tests pass, and
production does not call it.

**19 — The unconfirmable-refusal test drives the router (XS).** Closes MIK-7246.CONF.4 properly.
The current test asserts `ConfirmationPolicy::for_modern().on_unconfirmable() == REFUSE` at the
struct level. That satisfies the criterion's literal text and cannot catch a call site that never
consults the policy — the same shape as increment 18's defect, one layer down. MIK-7214's suite
already has the pattern worth copying: real axum-router integration tests under its `mod http`.

**20 — The header contract's two open halves (S).** Closes MIK-7214.HDR.2 and HDR.4. Inbound
validation is done and green (`protocol/headers.rs:148-213`, wired at `handlers.rs:600-687`,
mismatch to -32020, 32 tests). Two halves are absent, both verified by search on 2026-08-31:
outbound `Mcp-Method`/`Mcp-Name` emission has zero hits in `src/backend` or `src/transport`, and
`x-mcp-header` has zero hits anywhere in `src/`. HDR.4 may be closeable by a recorded declination
rather than code — the criterion asks for support or an explicit decision, and which one it gets is
an owner call, not an implementation detail.

MIK-7214's own ticket comment dated 2026-08-30 says "no code implementing any part of the header
contract" and cites a search returning nothing. The code is there, wired and tested. That comment is
stale in the same direction as the two audit rows above, and it is the third such case: a written
record of absence has now been wrong three times in this plan's evidence base, always by claiming
less had shipped than had. The rows claiming something is *missing* are the ones to re-read first.

Increment 18 runs the other way and is worth naming as the opposite failure: there, the record says
a mechanism exists and the tests agree, and only the call site tells the truth.

### Still open, and it will not resolve itself

The recovered audit is a floor, not a total. One row (SCHEMA.1, concerning `gateway_execute`'s
`chain` parameter) was truncated mid-emit and its finding is unrecoverable. Some criterion groups
were never reached at all, and the four-group sweep in `RELEASE-4.0.0-criteria-status.md` covers a
different, also partial, slice. Re-running the sweep to completion is a prerequisite for calling this
plan sized — not an increment, because its output changes what the increments are.

## 3. Not blocking the release

- Stale npm version in `npm/package.json:3` — CI syncs it at publish; the guard is hygiene.
- Homebrew formula staleness — `release.yml` regenerates it in the tap repo.
- Clippy invocation drift — cosmetic until a gate disagreement actually lets something through.
