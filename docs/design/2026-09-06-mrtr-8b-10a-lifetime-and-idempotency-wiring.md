# MRTR.8b in-flight lifetime, MRTR.10a idempotency wiring

Status: draft for dual-vendor review (grok + kimi). No code written.
Criteria source: `docs/requirements/RELEASE-4.0.0-criteria-status.md:140` (MRTR.8b PARTIAL),
`:143` (MRTR.10a UNWIRED). `:359` (NFR.PERF.3 ABSENT) depends on both and is OUT of scope here.

## §P0 SCOPE — two changes, one document

These are not one change and must not be reviewed as one.

**Change A — FOR:** make an abandoned in-flight exchange unobservable once its deadline has
passed, so MRTR.8b's lifetime bound holds without a reclaimer anyone must remember to call.
**Change B — FOR:** make the idempotency key path reachable from a production deployment, so
MRTR.10a's derivation stops being tests-only code.

OUT (both):
- NFR.PERF.3 soak. It depends on A and B landing; it is its own slice.
- The confirmation gate's ordering against the idempotency cache. Settled at source this session:
  the gate governs only meta-tools annotated `destructiveHint: true`
  (`src/gateway/destructive_confirmation.rs:160-220`), `gateway_invoke` is annotated
  `destructive_hint: Some(false)` (`src/gateway/meta_mcp_tool_defs.rs:135,155`), and backend tools
  are never in the meta-tool set at all. Gate and cache cannot interleave at any tool that exists
  today. Owned by the destructive-confirmation slice, not by this one.
- `enable_message_signing`, which has the same no-production-caller shape as
  `enable_idempotency` (`src/gateway/meta_mcp/authz_tests.rs` is its only caller). Recorded as an
  observation, not filed: the fix is the same shape as Change B and belongs with whoever owns
  message signing.
- Any change to `ConsumedLedger`, envelope minting, or replica affinity.

## Problem A — what MRTR.8b actually still fails

The criterion: *in-flight exchange state MUST be bounded in lifetime and reclaimed on abandonment.*

Verified at source, and the finding is NARROWER than the criteria row states:

1. `Keyring::open` refuses a past-deadline envelope with `ContinuationError::Expired`
   (`src/protocol/continuation.rs:509`), and the retry path calls it FIRST
   (`src/gateway/meta_mcp/invoke.rs:546`) — before `redeemable_by`, before `route`, before the
   ledger. `redeemable_by` (`continuation.rs:202-224`) checks only principal fingerprint and
   request digest; it does not check expiry, and does not need to.
2. The hold's deadline and the envelope's `expires_at` are the same value: `begin_exchange` passes
   `expiry_for(now)` to `hold` and the same `now` to `Payload::mint`
   (`continuation.rs:860-873`, `expiry_for` at `:136`).

Therefore **no past-deadline exchange can be dispatched.** `route` answering from presence alone
(`continuation.rs:735-742`) is not reachable with a stale key by a retry, because the envelope
carrying that key was already refused. The gpt-review finding of 2026-09-04 is right about the
mechanism and overstates the exposure; that correction is recorded here because a reviewer reading
only the criteria row will look for a dispatch defect that does not exist.

What DOES still fail, and fails the criterion's second clause exactly:

`reclaim_abandoned` runs only inside the `held.len() >= self.capacity` branch of `hold`
(`continuation.rs:695-710`). Below capacity, an abandoned hold is retained past its deadline for
an unbounded time — until some later `hold` happens to hit capacity, which on a quiet gateway is
never. Consequences, in order of weight:

- `len()` (`:757`) over-reports: it counts records the deadline has already killed. Anything
  built on it — admission accounting, a future metric, an operator's read of how many exchanges
  are open — reads a number that includes the dead.
- `route` answers `Here` for such a key. Unreachable from the retry path today, as established
  above; reachable by any future caller that consults the table without an envelope. The defect is
  latent, not live, and a latent defect in a bound is still a bound that does not hold.
- Memory is bounded (`IN_FLIGHT_CAPACITY` caps the map) so the memory half of the criterion holds.
  The lifetime half does not.

`InFlight::reap` was deleted in `ec11dcec` and must not come back: a reclaimer someone must
remember to call is the defect, not the fix. The doc comment in `hold` already says so.

## Design A — the deadline owns every read

Repair-protocol step 0: the mechanism (`InFlight`) is sound; what is wrong is that ONE of its four
entry points enforces the deadline and the other three do not. Elimination, not patching: give the
table exactly one place where the lock is taken, and reclaim there.

```
InFlight::guard(&self, now: u64) -> MutexGuard<'_, HashMap<String,(String,u64)>>
    // takes the lock, calls reclaim_abandoned(&mut held, now), returns the guard
```

`hold`, `route`, `complete` and `len` all go through it. `route`, `complete` and `len` gain a
`now: u64` parameter — the same clock the rest of the module reads
(`continuation::now_unix_secs`, `:140`), passed in rather than read internally so a test can drive
the deadline without sleeping. `reclaim_abandoned` stops being called from inside `hold`'s
capacity branch and `hold` keeps only its capacity refusal.

Test of the repair, per the protocol: **after the fix, can the finding still be stated?** No. There
is no code path that observes the map without having just reclaimed it, so "an expired hold is
retained" and "an expired hold routes `Here`" are not statements anyone can make about the type.
The alternative — teaching `route` to compare deadlines — leaves the finding stateable about
`len` and about the next reader added; that is a patch, and it is rejected for that reason.

Cost: `retain` over a map bounded by `IN_FLIGHT_CAPACITY` on every read. The lock was already
being taken; this adds an O(capacity) walk under it. Accepted because the capacity is the bound
that makes it O(1) in the size of the table, whose bound is `IN_FLIGHT_CAPACITY = 4_096`
(`src/protocol/continuation.rs:811`) — a client can drive occupancy up to that ceiling but no
further, and `hold` refuses past it. Stated as a number rather than as "anything a client
controls" so that a future capacity bump is visibly a change to every reader's cost, not a silent
one. `SpentLedger::consume` (`src/idempotency.rs:600-611`) already pays exactly this price for
exactly this reason — same shape, deliberately.

**The guarantee is relative to the supplied `now`, and that is the whole contract.** After this
change the table holds no record whose deadline is at or before the `now` most recently passed in.
It does *not* hold that the table is free of records expired against the wall clock at the instant
a caller reads the result: `invoke.rs` captures `now` once at `:545` and reuses it at `:584` and
`:613`, so an exchange expiring inside that window survives the reclaim and still routes. That is
correct — a dispatch decided against a single consistent instant is the property the call path
wants, and re-reading the clock per call would make one request observe two different presents.
It is stated because an absolute reading of the elimination claim would be false, and `guard`'s
doc comment carries the same sentence so a future call site cannot inherit the absolute reading.

`complete` takes `now` for its own reasons, not to satisfy a "every path goes through the guard"
convention — a convention is what this repair is replacing. `complete` returns `bool`, meaning
*an entry was there*. Without the reclaim it returns `true` for an exchange whose deadline passed
while it was in flight, telling the caller it completed something the table should no longer have
been holding. With it, that call returns `false`. The return value is an observable contract and
the reclaim is what makes it honest; the uniform routing is the consequence, not the reason.

Call sites to update: `invoke.rs:584` (`route`), `invoke.rs:613` (`complete`), both of which
already have `now` in scope from `:545`. Tests in `continuation.rs`, `tests/mik_7212_acs.rs`, and
any that call `len`.

### Alternatives rejected

- **A second reaper task.** Rejected: this is `InFlight::reap` returning under a new name, and the
  deleted-reaper comment in `hold` is the record of why it went. A background task also introduces
  a clock the tests cannot drive deterministically.
- **Deadline check in `route` only.** Rejected above: patch, leaves the finding stateable.
- **Read `now_unix_secs()` inside `guard`, inject a test clock behind `#[cfg(test)]`.** Raised in
  review as the way to make R1 unstateable at the type level, and it would — but it is not
  available here. `hold` is already `pub async fn hold(&self, backend_id: &str, expires_at: u64,
  now: u64)` (`src/protocol/continuation.rs:696`): the clock is *already* a public parameter of
  this type, so narrowing the three siblings would leave the surface inconsistent rather than
  narrow. Worse, `InFlight` is driven from `tests/mik_7212_acs.rs`, an external integration crate,
  where a `#[cfg(test)]` seam in the library is invisible — the option removes the tests that
  prove the behaviour in order to remove the parameter that lets them.
- **Store no deadline; rely on the envelope's `Expired`.** Rejected: it makes the table's
  correctness depend on every future reader holding an envelope, which is the coupling that
  produced this finding. It also loses `len`'s meaning entirely.

### Risks

- **R1** — a caller that passes a stale or attacker-influenced `now` reclaims live exchanges, or
  fails to reclaim dead ones. The clock is process-local (`now_unix_secs`, `:147`) and no caller
  derives it from input; the parameter is reachable only from gateway code, and it is already
  public on `hold` (`:696`), so this change widens no surface. Named because passing `now` in is
  what makes it possible at all. Mitigation is the freshness sentence above living in `guard`'s
  doc comment, not a reviewer remembering.
- **R2** — a wall-clock jump backwards makes `now <= deadline` true for records that had expired,
  briefly resurrecting them in `len`. Pre-existing (the same comparison already gates `hold` and
  the envelope check); not made worse; not fixed here.

## Problem B — what MRTR.10a actually fails

The criterion: *the idempotency key MUST include `inputResponses`/`requestState`.*

The derivation is correct and tested. `RetryFields::key_discriminator`
(`src/protocol/mrtr.rs:182`) separates the two fields rather than concatenating them; it folds
into the fingerprint at `src/gateway/meta_mcp/invoke.rs:1147-1164` as
`derive_key("{server}:{tool}", arguments)` + discriminator, and into the response-cache key at
`src/gateway/meta_mcp/support.rs:56`.

What fails is reachability. `MetaMcpServer::enable_idempotency`
(`src/gateway/meta_mcp/mod.rs:654`) carries `#[allow(dead_code)]` and has **zero non-test
callers** — `src/gateway/meta_mcp/tests.rs:3515` is the only one. The field is declared at
`mod.rs:221` and initialised `None` at `mod.rs:437`; the key path at `invoke.rs:1158` is gated on
`Some`. Production builds `MetaMcp` at `src/gateway/server/mod.rs:539-580` and never calls it. So
no deployed retry reaches the key at all, and the criterion is met only by tests that construct
the cache themselves. `#[allow(dead_code)]` is the compiler having already reported this.

Note the semantics, because they are load-bearing elsewhere: the key is a **de-duplication
identity that replays**, not a single-use token. `enforce` (`src/idempotency.rs:568`) returns
`GuardOutcome::CachedResult(value)` on `AdmitOutcome::Completed` — the second presentation is
served the first call's stored result. It refuses only `InFlight` (409) and `Mismatch` (409, same
key bound to a different fingerprint). Burn-on-redemption is `ConsumedLedger::consume(jti, ...)` on
the continuation path, a different primitive. Anything that needs "usable once" must ride the
ledger, never this key.

### The key is not bound to the caller, and wiring it on is what makes that reachable

Found in review, verified at source, and it changes what Change B has to do.

The idempotency key is `format!("{client_key}{projection_key_suffix}{identity_suffix}")`
(`src/gateway/meta_mcp/support.rs:35-44`). `identity_suffix` is built at `invoke.rs:1128-1132`
from `caller_credential.cache_binding` **and nothing else** — it is the empty string whenever
identity propagation is off, which `invoke.rs:1133-1139` states is the shipped default. The
fingerprint that would otherwise separate two callers is
`derive_key("{server}:{tool}", &arguments)` + the retry discriminator (`invoke.rs:1164-1168`):
same tool, same arguments, same key string ⇒ same fingerprint ⇒ `AdmitOutcome::Completed` ⇒
`GuardOutcome::CachedResult`, and `invoke.rs:1178-1199` returns that stored response. Two
authenticated callers who happen to choose the same opaque key string are served each other's
results.

The response cache does not have this hole, and the code says why in its own comment: the
`caller_principal` it keys on (`invoke.rs:1140-1142`) falls back to
`VerifiedIdentity::stable_actor_id` when the binding is absent, precisely because "keying on the
binding alone let two authenticated callers share one entry whenever propagation was off, which is
the shipped default" (`invoke.rs:1133-1139`). The idempotency key was left on the binding alone
with the reason "a different contract with a different lifetime" — which is true of the *lifetime*
and says nothing about the *identity*. The fix already exists twelve lines away.

**§P3 design event.** This is a decision the design did not make, named at the moment of making
it: it changes a material security property, and it widens Change B beyond the reachability repair
§P0 declared. Disposal per §P0 is *fix it in this change* — the repair is `identity_suffix`
adopting the same verified-subject fallback `caller_principal` already has, which is smaller than
the ticket describing it would be, and this change is the one that makes the path reachable at
all. Shipping the wiring without it would be turning on a cross-principal replay.

**Change B does not enable the flag until the key binds the principal.** The order is not
negotiable and it is not a sequencing preference: default-OFF does not make it safe either, since
the first operator to set `enabled: true` gets the defect. The binding lands in the same change,
with its own acceptance row.

## Design B — one config section, one construction site

`enable_idempotency` becomes a builder method in the style of every other feature on this struct
(`with_cost_governance`, `with_attestation`, `with_secret_injector`), called on
`meta_mcp_builder` before `Arc::new` at `src/gateway/server/mod.rs:580` — it takes `&mut self`, so
it cannot be called after the `Arc` the way `set_context_integrity_kernel` is. `#[allow(dead_code)]`
comes off; if the wiring is ever removed again the compiler says so.

New config section, shaped like the existing `error_budget:` and `cache:` sections:

```
idempotency:
  enabled: <bool>                # default settled by U4
  cleanup_interval: <duration>   # passed to spawn_cleanup_task; default 60s
```

Absent section keeps whatever the default is, exactly as `error_budget:` does. No other knob:
`MAX_ENTRIES` and `IN_FLIGHT_TIMEOUT` are existing constants and stay constants until an operator
has a reason to move them, and inventing a knob for a value nobody has needed to change is the
config-for-a-constant this repo already refuses.

`want_full` deliberately does not suppress the key (`src/gateway/meta_mcp/invoke.rs:1120-1145`);
that stays.

### Alternatives rejected

- **Enable unconditionally, no config key.** Rejected: it changes an observable contract for every
  existing client that already sends a key (today a repeat does nothing; after, it replays or
  409s), and a release-criteria fix is the wrong place to ship that silently.
- **Delete `enable_idempotency` and the key path.** The honest elimination, and it is available:
  the finding "the derivation is unwired" cannot be stated about code that does not exist. Rejected
  because MRTR.10a is a REQUIREMENT, and dropping it needs the requester's recorded agreement
  (repair protocol), not an engineering preference. Named here so the option is on the record
  rather than assumed away.

### Risks

- **R3** — with the cache on, `MAX_ENTRIES` capacity turns into a live 503 refusal path nobody has
  operated. It refuses rather than evicts on purpose (eviction readmits a duplicate,
  `src/idempotency.rs:590-596`), so the failure is loud and correct, but it is new.
- **R4** — a client that reuses one key loosely across different calls now gets 409 `Mismatch`
  where it previously got a second execution. That is the criterion working, and it is still a
  behaviour change a release note must carry.
- **R5** — binding the idempotency key to the verified subject means a caller whose identity the
  gateway cannot verify at all gets an unbound key, exactly as today. That case is narrower than
  it sounds — an unauthenticated caller on a single-tenant gateway is the only principal there is
  — but it is the residual, and it is the reason the binding is a *fallback chain* rather than a
  refusal: refusing a key for want of an identity would break every single-tenant deployment to
  close a multi-tenant hole.

## §P1 scheduled open questions

Each is resolved by a recorded ANSWER or carries the four deferral fields. None is deferred.

| # | question | state |
|---|---|---|
| U1 | Is any past-deadline exchange dispatchable today? | **resolved** — checkable — read `src/protocol/continuation.rs:495-515` and `src/gateway/meta_mcp/invoke.rs:540-620` — `keyring().open` refuses `Expired` at `:509` and is called at `invoke.rs:546`, before `route` at `:584`; the hold deadline is the same `expiry_for(now)` (`:864`) — **changed the design**: A became a lifetime/observability repair, not a dispatch repair, so its failing test asserts on `len`/`route` under a driven clock rather than on a dispatched retry. |
| U2 | Does MRTR.10a own the idempotency-vs-confirmation ordering? | **resolved** — checkable — read `src/gateway/destructive_confirmation.rs:160-220` and `src/gateway/meta_mcp_tool_defs.rs:135-160,254-262` — the gate governs only meta-tools annotated `destructiveHint: true`, `gateway_invoke` is annotated false, backend tools are never in the set — **changed the design**: the ordering left this document's scope and stays with the destructive-confirmation slice. |
| U3 | Does the idempotency key carry single-use semantics? | **resolved** — checkable — read `src/idempotency.rs:547-600` — `enforce` replays `CachedResult` on `Completed` and refuses only `InFlight`/`Mismatch` — **changed the design**: recorded explicitly in Problem B, because a stateless-confirmation option elsewhere was about to hang single-use on this key. |
| U4 | Default ON or OFF for `idempotency.enabled`, **and does a default-OFF wiring satisfy MRTR.10a's acceptance**? | **deferred** — the second half was missing until review pointed out that §P4a flips `:143` to wired on the strength of an answer that may not cover the criterion's acceptance semantics. Both halves now travel in one ask. Fields below. |

U4's four deferral fields, because it is deferred and a recommendation is not a schedule:

| field | value |
|---|---|
| owner | the team lead; asked 2026-09-06, ask widened the same day to carry the acceptance half |
| what would resolve it | the recorded answer to both halves — the default, and whether reachable-but-off meets MRTR.10a |
| when | before the config default line is written and before `:143`'s status is edited; the builder method, the config section, the principal binding and every test are identical either way and are not waiting on it |
| what if it resolves badly | *ON* — the release note carries R4's 409 as a behaviour change and the change needs a migration line, which is why OFF is recommended. *Reachable-but-off does not satisfy MRTR.10a* — `:143` stays UNWIRED, Change B ships as the mechanism and the criterion closes when an operator default flips, which is a scope call for the requester, not a repair |

## §P4 review record

| leg | vendor | verdict | evidence |
|---|---|---|---|
| 1 | Kimi K3 (`synthetic-review`) | SHIP-WITH-FIXES | `~/.claude/data/reviews/runs/synthetic-20260906T065936Z-43480.md`, rc=0 |
| 2 | Grok (`grok-review`) | *in flight at the time of this revision* | recorded when the run exits |
| — | Codex/GPT (`gpt-review`) | **MISSING** | rc=0 but no verdict and no run file: `ERROR: You've hit your usage limit … try again at Sep 12th, 2026`. Per §PA a nonzero-or-absent row is `MISSING`, never a scraped verdict |

**Stated deviation.** The shared pair for a Claude-authored change is `gpt-review` + `grok-review`.
Codex is usage-limited until 2026-09-12, so leg 1 is Kimi. This is a substitution recorded before
ratification rather than discovered at it; `ratify` requires a SHIP from each vendor and will read
these rows, not this paragraph.

Findings incorporated this round: the caller-binding hole in the idempotency key (verified at
source, promoted into Change B), the freshness precondition on Design A's elimination claim, the
widened U4 ask, and the three test-plan constraints above. The `#[cfg(test)]` clock improvement was
rejected with its reason in Alternatives. One finding died at source: nothing was found to support
the *response*-cache half of the cross-principal claim — `caller_principal` already carries the
verified-subject fallback (`invoke.rs:1140-1142`); only the idempotency key was unbound.

## §P4a documentation delta

- `docs/requirements/RELEASE-4.0.0-criteria-status.md:140` — MRTR.8b PARTIAL, and its note asserts
  a dispatch defect U1 disproved. Both the status and the note change with Change A.
- `docs/requirements/RELEASE-4.0.0-criteria-status.md:143` — MRTR.10a UNWIRED. Changes with B
  **only if** U4's second half comes back saying reachable-but-off satisfies the criterion. Until
  that answer is recorded the row is not edited; writing it first would be the certification
  flipping on a pending answer, which is the finding that widened U4.
- Operator config reference — the new `idempotency:` section.
- Release notes — R4's behaviour change, in whichever direction U4 lands.
- `docs/design/2026-08-30-shared-continuation-state.md:116` is cited by `route`'s doc comment and
  stays true: nothing here touches the no-affinity bargain.

## Test plan

Follows as a separate document, one row per clause, before any test code is written. Three
constraints on it are settled here rather than left to the plan, because each one is a way the
plan could pass while proving nothing:

- **Change B's acceptance row builds `MetaMcp` through the production builder**
  (`src/gateway/server/mod.rs:539-580`) with an idempotency-enabled config fixture. A test that
  constructs the cache itself is exactly what `tests.rs:3515` already does, and it is why the
  criterion reads as met while no deployed retry reaches the key. A fixture that reproduces the
  defect cannot be the proof it is fixed.
- **A negative case with the section absent**, asserting the default the way the code computes it.
  The assertion's *value* waits on U4; the row does not — it is written now and marked blocked on
  the recorded answer, rather than written later against a guessed default.
- **A cross-principal case for the key binding**: two callers, distinct verified subjects,
  identity propagation off, same client-chosen key, same tool, same arguments. Today's code serves
  the second caller the first's stored response; after the binding it admits the second call. The
  old behaviour is what makes the case able to fail, so the falsifier probe is available without
  reconstructing anything.

Change A's rows assert on `len` and `route` under a driven clock, per U1 — not on a dispatched
retry, which U1 showed cannot happen.
