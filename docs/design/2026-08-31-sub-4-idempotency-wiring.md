# MIK-7272.SUB.4 — idempotency protection for reissued side-effecting calls

Status: proposed, revision 2. No code written. Revision 1 was reviewed by GPT-5.x and Grok,
both `SHIP-WITH-FIXES`; this revision is the repair. Awaiting re-review.

## Scope

FOR: deciding how a side-effecting call, reissued after a broken stream with a new request
id, becomes protected — which is what MIK-7272.SUB.4 requires.

OUT:
- the tasks extension (MIK-7272.TASK.1, ABSENT). It is the criterion's other branch and a far
  larger surface; this design neither builds it nor depends on it.
- idempotency key *derivation* as an algorithm. `derive_key` and `RetryFields` exist and are
  tested. What is in scope is *when a key is derived at all* — see prerequisite 2.
- MIK-7212.MRTR.10a (`inputResponses`/`requestState` inside the key), a separate ABSENT
  criterion. Noted as a dependency: enforcing on a key that omits them protects the wrong set.

## Problem

The idempotency machinery is complete and unreachable.

- `MetaMcp::idempotency_cache` is initialised to `None` (`src/gateway/meta_mcp/mod.rs:393`).
- Its only populator, `MetaMcp::enable_idempotency` (`src/gateway/meta_mcp/mod.rs:580`), is
  marked `#[allow(dead_code)]` and has zero callers: `rg --hidden --no-ignore
  'enable_idempotency' .` returns one hit, its own definition.
- No configuration key gates it: `rg -n 'idempotency' src/config/mod.rs` returns nothing.

So the enforcement site (`src/gateway/meta_mcp/invoke.rs:792`) takes the `None` branch in every
build that has ever shipped. `resolve_idempotency_key` runs, derives a key, and nothing
consumes it. The `#[allow(dead_code)]` attribute is why this survived the `-D warnings` gate:
it silences the exact warning that would have reported the unused setter.

A second gap compounds it. `POST /mcp/{name}` — the direct backend route,
`src/gateway/router/backend_handlers.rs:338-353` — does not go through `invoke_tool_traced`. It
re-enforces OAuth isolation and tool policy locally but never calls `resolve_idempotency_key`,
whose sole call site is `meta_mcp/invoke.rs:782`. Revision 1 attributed that bypass to "ADR-008
rung 2"; that was a misreading, corrected below, and no ADR sanctions it.

## The cache cannot simply be turned on

Review found three defects in the existing implementation. Each was verified at source. Wiring
the cache without fixing them ships a regression, so they are prerequisites, not follow-ups.

**P1 — enforcement is not atomic.** `enforce` (`src/idempotency.rs:337`) calls `cache.check(key)`
and then `cache.mark_in_flight(key)` as two separate `DashMap` operations. Two concurrent
retries can both observe `Proceed` and both execute the side effect — the exact duplication
SUB.4 exists to prevent. Fix: one atomic entry transition, with a concurrent same-key
falsifier proving the old code fails it.

**P2 — a keyless call gets an automatic key.** `resolve_idempotency_key`
(`src/gateway/meta_mcp/support.rs:26-45`) derives a key from `(server, tool, arguments)`
whenever a cache is active, whether or not the client supplied one. Turning the cache on
therefore silently deduplicates *intentional* identical side effects for 24 hours. This is not
a footnote: it makes revision 1's own third test row unsatisfiable. Fix: enforce only on an
explicit retry key, or gate the automatic derivation on a declared-retry signal.

**P3 — the entry map is unbounded.** `IdempotencyCache { entries: DashMap<...> }`
(`src/idempotency.rs:93`) has no capacity policy, and `COMPLETED_TTL` is 24 hours
(`src/idempotency.rs:31`). Ordinary volume, or attacker-chosen unique keys, retains entries
for a day. Fix: a bounded capacity that fails closed for new protected side effects when full.

## Constraints, measured

- The response cache is `Option<Arc<ResponseCache>>` (`src/gateway/meta_mcp/mod.rs:185`) and is
  `None` when `config.cache.enabled` is false (`src/gateway/server/mod.rs:465-475`). Revision 1
  claimed it was non-optional; that was inferred from initializer shorthand and is wrong. The
  consequence matters twice: idempotency cannot lean on the response cache for correctness,
  and MIK-7212.MRTR.10b's evidence — which rests on the response-cache guard — is conditional
  on that flag and needs its status re-checked.
- The response cache already collapses two identical sequential calls before the backend runs
  (`src/gateway/meta_mcp/invoke.rs:828-833`), so any test asserting "the backend ran once"
  passes today, unwired. Every test in this design must defeat that.
- TTLs already exist: `COMPLETED_TTL` 24h and `IN_FLIGHT_TIMEOUT` 5m (`src/idempotency.rs:30-37`).
  They are the defaults. Copying `config.cache.default_ttl` instead would shrink the protection
  window to a minute.
- ADR-008 INV-3 requires the `cache_binding` (user + audience) to be mixed into both cache
  keys, and it is — but at the CALL SITE. `invoke.rs:773` builds an `identity_suffix` from the
  resolved credential and appends it to the idempotency key at `:789` and to the response-cache
  key at `:831`/`:1263`. Neither `derive_key` nor `ResponseCache::build_key` knows about it.
  That placement is the whole reason the direct route is a security question and not just a
  coverage gap: a second call site must re-apply the binding by hand, which is the shape ADR-008
  itself records going wrong once (`CapabilityExecutor::fetch_oauth_token` bypassing the guard,
  ADR-008:117). Extending coverage should push the binding INTO the derivation, not copy the
  suffix to a second site.
- `IdempotencyCache::check` evicts on access (`src/idempotency.rs:147-176`), so the background
  cleanup task that `enable_idempotency` spawns is an optimisation, not a correctness
  requirement. Revision 1 priced it as an unavoidable cost of enabling. It is not.

## Two decisions, not three options

Revision 1 offered options A/B/C. Both reviewers found they were not a spanning set: C is B
plus a second axis, and the axes are independent. They are separated here, and neither is
decided in this document — see the open questions.

**Axis 1 — activation.** Off by default and opt-in | on by default and opt-out | mandatory,
not disableable. Off-by-default cannot satisfy a criterion that says a reissue MUST be
protected, so it is rejected on the requirement, not on cost. The choice is between
on-by-default and mandatory, and it turns on whether an operator may switch off a MUST.

**Axis 2 — coverage.** The meta route alone | both routes. Meta-only leaves a documented
ingress a client can reach unprotected, which the criterion does not permit. Both routes is
therefore the requirement's answer, and the open part is *placement*: INV-3 says the binding
must be in the key, and it currently reaches the key from the call site. Duplicating the suffix
at a second site satisfies the criterion and reproduces a failure ADR-008 has already recorded.

Revision 1's recommendation is withdrawn — it was made while the ADR question was open, which
both reviewers named. The ADR has now been read; what replaces the recommendation is the
placement question above, which is an engineering choice, not an operator one.

## Open questions — each scheduled, none assumed

| question | how it is settled | state |
|---|---|---|
| May an operator disable protection a criterion states as MUST? | ASK the operator. Only they can weigh a MUST against an escape hatch. | OPEN — blocks axis 1, blocks all code |
| Does ADR-008 bear on the direct route's bypass? | CHECKED: read end to end. It does not. Rung 2 is client-native OAuth passthrough — the client holds the token and attaches it per request — and says nothing about HTTP routing. What ADR-008 *does* bind is INV-3, above. CHANGED: the bypass loses its justification, and axis 2 gains a placement constraint. | RESOLVED |
| Should P2's automatic key be deleted or gated on a declared retry? | ASK the operator: deleting it narrows protection to clients that send a key; gating it keeps protection and needs a signal that does not exist yet. | OPEN — blocks P2, blocks all code |
| What capacity bound, and what happens at the bound? | CHECK what `ResponseCache::with_max_entries` uses, then decide fail-closed vs evict-oldest. Fail-closed is the safe default for a side-effect guard. | OPEN — blocks P3 |

Nothing is deferred; nothing is implemented while any of the open ones is open.

## Test plan — one row per criterion, each able to fail today

Every row states what defeats the response cache, because a row it can satisfy proves nothing.

| criterion | case | how it fails today | defeats the response cache |
|---|---|---|---|
| SUB.4, meta route | abort the first response *after* the backend executed, reissue with a new request id and the same retry key, assert a mutation counter on a `destructiveHint` tool increments once | unwired: the counter reaches 2 | the abort happens post-execution, so no cached response exists to serve |
| SUB.4, concurrency (P1) | two same-key requests in flight together; exactly one executes, the other gets `409` or the cached result | non-atomic `enforce` lets both proceed | both are in flight, so neither can be a cache hit |
| SUB.4, direct route | the same post-execution reissue through `POST /mcp/{name}` | that route never resolves a key | the direct route is outside the meta response cache |
| no false dedup (P2) | two *unrelated* `(server, tool, arguments)` tuples with no client key; both backends run | if the automatic key survives unchanged, this stays red after the fix, which is the signal | different arguments give different cache keys |
| bound (P3) | fill to capacity, assert a new protected side effect is refused rather than admitted | unbounded map admits it | not a caching question |

The assertion is a mutation counter on the tool, not the response body: two identical bodies
are also what executing twice produces.
