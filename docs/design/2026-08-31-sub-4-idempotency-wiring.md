# MIK-7272.SUB.4 — idempotency protection for reissued side-effecting calls

Status: proposed, revision 4. No code written. Revisions 1 and 2 were reviewed by GPT-5.x and
Grok; both returned `SHIP-WITH-FIXES` on revision 2. Revision 3 was the repair. Revision 4 settles
the last question a check could settle, and records what happens to the two that need a person.

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

- `MetaMcp::idempotency_cache` is initialised to `None` (`src/gateway/meta_mcp/mod.rs:393`).
- Its only populator, `MetaMcp::enable_idempotency` (`src/gateway/meta_mcp/mod.rs:580`), has
  zero callers: `rg --hidden --no-ignore 'enable_idempotency' .` returns its own definition.
- No configuration key gates it: `rg -n 'idempotency' src/config/mod.rs` returns nothing.
- It carries `#[allow(dead_code)]`, which silences the warning the `-D warnings` gate would
  otherwise have raised. That the attribute is *why* it survived is inferred (I), not read.

So the enforcement site (`src/gateway/meta_mcp/invoke.rs:792`) takes the `None` branch in every
build that has ever shipped.

Two further gaps compound it, both found in review and verified at source.

**No advertised way for a client to send a key.** `resolve_idempotency_key` reads
`args["idempotency_key"]` (`src/gateway/meta_mcp/support.rs:40`), and that string appears in
exactly six places in the tree, all internal: the module doc, the function, and its call site.
It is in no tool schema. A client cannot discover it, so today the *only* reachable protection
is the automatic derivation — which is itself defect P2 below. This is the finding that
reshapes the design: "enforce only on an explicit client key" is not an available option until
a carrier exists on both routes.

**The direct route bypasses the machinery entirely.** `POST /mcp/{name}`
(`src/gateway/router/backend_handlers.rs:338-353`) does not go through `invoke_tool_traced` and
never calls `resolve_idempotency_key`, whose sole call site is `meta_mcp/invoke.rs:782`.
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

**P2 — a keyless call gets an automatic key.** `resolve_idempotency_key`
(`src/gateway/meta_mcp/support.rs:26-45`) derives a key from `(server, tool, arguments)` whenever a
cache is active, whether or not the client supplied one. Turning the cache on therefore silently
deduplicates *intentional* identical side effects for 24 hours. Fix depends on the carrier
question below: deleting the derivation is only safe once clients can send a key.

**P3 — the entry map is unbounded.** `IdempotencyCache { entries: DashMap<...> }`
(`src/idempotency.rs:93`) has no capacity policy and `COMPLETED_TTL` is 24 hours. RESOLVED: take
the response cache's bound, `DEFAULT_MAX_ENTRIES = 10_000` (`src/config/features/cache.rs:12`), and
reject its policy. `ResponseCache::enforce_max_entries` evicts the oldest
(`src/cache.rs:185-204`), which for a side-effect guard would silently re-admit a duplicate.
Fail closed instead: refuse a new protected side effect at the bound.

**P4 — `_full` calls are unprotected.** `let idem_key = if want_full { None }`
(`src/gateway/meta_mcp/invoke.rs:779`) forces the key to `None` for every raw-output call, so an
irreversible tool invoked through that path can execute twice however the rest is wired. Fix:
keep idempotency active and isolate the replay payload with an explicit key suffix, as the
projection suffix already does.

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
- ADR-008 INV-3 requires the `cache_binding` (user + audience) in both cache keys, and it is —
  but at the CALL SITE. `invoke.rs:773` builds an `identity_suffix` and appends it at `:789`,
  `:831` and `:1263`. Neither `derive_key` nor `ResponseCache::build_key` knows about it. DECIDED:
  extending coverage pushes the binding INTO the derivation. Copying the suffix to a second call
  site is exactly the shape ADR-008:117 already records failing.
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

ASKED of the operator on 2026-08-31 with four options; no answer within the turn. WORKING
ASSUMPTION, not an answer — an optional `idempotency_key` argument on the `gateway_invoke` schema
for the meta route, and an `Idempotency-Key` HTTP header on `POST /mcp/{name}`. Reasons: it covers
both ingresses, it adds no meta-tool so the compact-surface decision in `CLAUDE.md` is untouched,
and the header spelling is the industry convention. The rejected alternatives and their costs are
in the questions table. This assumption is what the rest of the design is written against; it is
NOT settled, and no code lands on it until the operator confirms, because it changes the
advertised tool surface, which this repo treats as a locked decision.

## Open questions — each scheduled, none assumed

| question | how it is settled | state |
|---|---|---|
| What carries a retry key, on both routes? | ASKED 2026-08-31, four options put, no answer within the turn. Rejected in the ask: an HTTP header alone (a stdio client has no HTTP layer, so protection stays unreachable for local setups), `_meta` alone (spec-native and stdio-safe, but the direct route is raw JSON-RPC passthrough needing new plumbing, and no client sends it today), and keeping automatic derivation (ships fastest, keeps P2's silent 24-hour collapse of deliberate repeats). | ASKED, UNANSWERED — a working assumption is recorded above; blocks all code |
| May an operator disable protection a criterion states as MUST? | DECIDED on the requirement rather than asked: no. A switch makes the criterion unverifiable wherever the running configuration differs from the shipped default. Recorded so it can be overruled, not so it can be confirmed. | RESOLVED — overrulable |
| Does ADR-008 bear on the direct route's bypass? | CHECKED end to end. It does not; rung 2 is client-native OAuth passthrough. What it does bind is INV-3. CHANGED: the bypass loses its justification and axis 2 gains a placement constraint. | RESOLVED |
| What capacity bound, and what happens at the bound? | CHECKED `src/config/features/cache.rs:12` and `src/cache.rs:185-204`: bound 10_000, policy evict-oldest. CHANGED: take the number, reject the policy, fail closed. | RESOLVED |
| Does a configured backend timeout exceed `IN_FLIGHT_TIMEOUT`? | CHECKED. Per-backend `timeout` defaults to 30s (`src/config/mod.rs:1383`), enforced at `src/transport/http/mod.rs:305`; the server's `request_timeout` is also 30s (`src/config/mod.rs:1178`). CHANGED: P7 is out of reach at defaults and reachable only by configuration, so its fix shrinks to a config-load validation. | RESOLVED |

Nothing is deferred. One question is asked and unanswered; the assumption standing in for it is
labelled as an assumption everywhere it is used, and no code lands until it is confirmed. That row
is blocked, not deferred - deferral would need the four fields the process demands, and the honest
position is that it is simply waiting on a person.

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
