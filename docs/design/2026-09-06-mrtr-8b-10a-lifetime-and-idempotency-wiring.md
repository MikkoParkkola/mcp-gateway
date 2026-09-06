# MRTR.8b in-flight lifetime (MRTR.10a wiring withdrawn to SUB.4)

Status: revision 2, repaired after round 1. No code written. Round 1 withdrew Change B entirely;
what remains for implementation is Change A, and the MRTR.10a material is retained as the evidence
and the prerequisite that travel to `2026-08-31-sub-4-idempotency-wiring.md`.
Criteria source: `docs/requirements/RELEASE-4.0.0-criteria-status.md:140` (MRTR.8b PARTIAL),
`:143` (MRTR.10a UNWIRED). `:359` (NFR.PERF.3 ABSENT) depends on both and is OUT of scope here.

## §P0 SCOPE — two changes, one document

These are not one change and must not be reviewed as one.

**Change A — FOR:** make an abandoned in-flight exchange unobservable once its deadline has
passed, so MRTR.8b's lifetime bound holds without a reclaimer anyone must remember to call.
**Change B — WITHDRAWN 2026-09-06, before any code.** It was FOR making the idempotency key
path reachable from a production deployment. A sibling design already owns that decision and
already had it answered by the operator; the mechanism this document proposed is one that design
explicitly rejected. Removal, not repair — see *Design B, withdrawn* below. What survives is one
transferred prerequisite, and this document's remaining FOR is Change A alone.

OUT (both):
- NFR.PERF.3 soak. It depends on Change A landing and on SUB.4 activating the cache; it is its
  own slice.
- The confirmation gate's ordering against the idempotency cache. Settled at source this session:
  the gate governs only meta-tools annotated `destructiveHint: true`
  (`src/gateway/destructive_confirmation.rs:160-220`), `gateway_invoke` is annotated
  `destructive_hint: Some(false)` (`src/gateway/meta_mcp_tool_defs.rs:135,155`), and backend tools
  are never in the meta-tool set at all. Gate and cache cannot interleave at any tool that exists
  today. Owned by the destructive-confirmation slice, not by this one.
- `enable_message_signing`, which has the same no-production-caller shape as
  `enable_idempotency` (`src/gateway/meta_mcp/authz_tests.rs` is its only caller). Recorded as an
  observation — the third disposal in §P0's table, chosen because it is worth remembering and
  nobody must act. It belongs with whoever owns message signing, and round 1's lesson applies to it
  first: search `docs/design/` for a slice that already owns it before designing one.
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

Test of the repair, per the protocol: **after the fix, can the finding still be stated, relative to
the `now` a reader supplies?** No — and the qualifier is part of the answer, not a footnote to it
(the freshness paragraph below is where it is spelled out). There
is no code path that observes the map without having just reclaimed it against that `now`, so "an expired hold is
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
a caller reads the result: `invoke.rs` captures `now` once at `:546` and reuses it at `:584` and
`:613`, so an exchange expiring inside that window survives the reclaim and still routes. That is
correct — a dispatch decided against a single consistent instant is the property the call path
wants, and re-reading the clock per call would make one request observe two different presents.
It is stated because an absolute reading of the elimination claim would be false, and `guard`'s
doc comment carries the same sentence so a future call site cannot inherit the absolute reading.

**What the reclaim actually buys, and what it does not.** Found while writing the test plan, not
raised by a reviewer: MRTR.8b's reclaim is **unobservable through the retry path**. `invoke.rs`
captures `now` at `:546` and hands it to `Keyring::open` at `:547`, which refuses with `Expired`
exactly when `now > payload.expires_at` (`continuation.rs:508`); only if that succeeds does control
reach the `route` call at `:584`. The two deadlines are the same number — `hold(&backend_id,
expiry_for(now), now)` feeds `expiry_for(now)` to the table and to the minted envelope in one
expression (`continuation.rs:864`). So on every retry the envelope refuses first, and no caller can
tell a reclaimed table from an unreclaimed one.

Named here rather than left in the plan because it is a design event by §P3's test: it changes what
the criterion's observable surface *is*. It does not weaken the change — the payoff was never
routing behaviour, it is **capacity**. An abandoned exchange that keeps its slot is what drives
`hold` into the refusal branch at `:694-710`; the observable consequence of the reclaim is that
`hold` admits where it used to refuse. Two things follow. The criterion has no honest integration
row, and the test plan records that with its reason instead of carrying one that cannot fail. And
`len`'s enumeration below stops being only a cost footnote: `len` is the reader through which the
reclaim is most directly visible, which is why the first production consumer to call it deserves
the sentence it will find there.

`complete` takes `now` for its own reasons, not to satisfy a "every path goes through the guard"
convention — a convention is what this repair is replacing. `complete` returns `bool`, meaning
*an entry was there*. Without the reclaim it returns `true` for an exchange whose deadline passed
while it was in flight, telling the caller it completed something the table should no longer have
been holding. With it, that call returns `false`. The return value is an observable contract and
the reclaim is what makes it honest; the uniform routing is the consequence, not the reason.

Call sites to update: `invoke.rs:584` (`route`), `invoke.rs:613` (`complete`), both of which
already have `now` in scope from `:546`. Tests in `continuation.rs` and
`tests/mik_7212_mrtr_component_acs.rs`.

`len` deserves its own line, because this change turns a passive counter into a mutating,
O(`IN_FLIGHT_CAPACITY`) read and anything downstream inherits that cost. Its callers, enumerated:
`InFlight::is_empty` (`continuation.rs:762`), and four assertions in
`tests/mik_7212_mrtr_component_acs.rs` (`:1107`, `:1131`, `:1234`, `:1304`). **There is no
production consumer today** — which is why the cost is affordable now, and why the enumeration is
recorded: the first metric or admission check to call `len` is the one that makes the walk matter,
and it should find this sentence rather than discover the cost in a profile.

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
  narrow. Worse, `InFlight` is driven from `tests/mik_7212_mrtr_component_acs.rs` (`:1107`,
  `:1131`, `:1234`, `:1304`), an external integration crate,
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
- **R2a** — the bound A delivers is *observability-relative*, not absolute: an expired hold stays
  in the map until the next call through `guard`, so on an idle gateway a dead entry can occupy a
  slot indefinitely in memory while being unobservable through every public reader. That is the
  bargain deliberately taken over a clock-driven reaper (Alternatives), and `IN_FLIGHT_CAPACITY`
  bounds the residue at 4 096 entries. It is stated because "lifetime is bounded" and "lifetime is
  bounded *to a reader*" are different claims and the criterion is met by the second one.
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

Found in review, verified at source. It was the reason Change B could not ship as drafted; with
Change B withdrawn it is a **prerequisite transferred to SUB.4**, and the paragraphs below are kept
verbatim as the evidence that travels with it.

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

**§P3 design event, and its disposal changed with the withdrawal.** Naming it was correct and the
name stands: it changes a material security property. Its §P0 disposal was *fix it in this change*
while this change was the one making the path reachable. It no longer is. The disposal is now
*write it into the design* — SUB.4's, which owns activation and independently decided the binding
belongs inside the derivation (`:125-128`). A fix here would repair a path nothing reaches, and the
guarantee that matters — **no activation before the key binds the principal** — is enforced where
activation happens, not where it doesn't. Default-OFF was never the safety here either: the first
operator to flip a switch gets the defect, which is one more reason the switch is gone.

## Design B — withdrawn, and why removal was the response

The proposed mechanism was: `enable_idempotency` becomes a builder method called on
`meta_mcp_builder` before `Arc::new` (`src/gateway/server/mod.rs:580`), gated by a new
`idempotency: { enabled, cleanup_interval }` config section, with the shipped default recommended
OFF.

**Every load-bearing part of that is already decided elsewhere, differently, by the operator.**
`docs/design/2026-08-31-sub-4-idempotency-wiring.md` (MIK-7272.SUB.4, proposed revision 4, two
vendor reviews returning SHIP-WITH-FIXES on revision 2) opens on the identical finding — "its only
populator, `MetaMcp::enable_idempotency` … has zero callers" (`:23-24`) — and settles three axes
this document reopened without knowing they were closed:

| axis | SUB.4's recorded decision | what Design B proposed |
|---|---|---|
| activation | **mandatory, no kill switch** (`:137-143`). Decided on the requirement: a switch makes a MUST unverifiable wherever the running configuration differs from the shipped default | an `enabled` config key, recommended default OFF |
| coverage | **both routes** (`:145-147`). Meta-only leaves `POST /mcp/{name}` unprotected, which the criterion does not permit | the meta route's builder only; the direct route was never considered |
| the key carrier | **client-carried, ASKED and ANSWERED by the operator 2026-08-31** (`:154-176`): `_meta["io.mcp-gateway/idempotency-key"]` on the meta route, `Idempotency-Key` header on the direct route. Automatic derivation is rejected *by name* as defect P2 — "deriving a key for a client that never asked for one silently collapses deliberate repeats for 24 hours. Protection applies when a key is present and never otherwise" | flip on the existing automatic derivation, which is precisely P2 |

Repair-protocol step 0 asks what the finding killed. It killed the mechanism's purpose, not its
implementation: switching on automatic derivation is the behaviour SUB.4 rejected, and a config
kill switch is the shape SUB.4 refused. **Removal, not repair.** A repaired Design B — mandatory,
both routes, client-carried key — is not a repaired Design B; it is SUB.4, rewritten in a second
document, which is the duplicate-change failure this design already caught once in the other
direction (`2026-09-01-nfr-perf3-reclamation.md:375`).

**This does not drop MRTR.10a.** The criterion reads *"idempotency key MUST include
`inputResponses`/`requestState`"* and its status row says the derivation is correct and folded in;
UNWIRED is on REACHABILITY alone. SUB.4 already names MRTR.10a as its own **prerequisite**
(`:131-133`) and owns the reachability it is blocked on. Nothing is eliminated — one criterion's
open half moves to the slice that holds the operator's answer about it. That is a re-assignment, not
the requirement-elimination the repair protocol gates on the requester's recorded agreement.

### The one thing that transfers, not evaporates

The caller-binding hole in the idempotency key is real, verified at source, and now belongs to
SUB.4 as a **blocking prerequisite of its activation**, recorded here so it travels rather than
dying with this section:

> `identity_suffix` (`src/gateway/meta_mcp/invoke.rs:1128-1132`) is `caller_credential.cache_binding`
> alone, therefore EMPTY whenever identity propagation is off — which the adjacent comment at
> `:1133-1139` calls the shipped default. Two authenticated callers issuing the same tool with the
> same arguments and the same key string collide on one fingerprint (`:1164-1168`), and
> `AdmitOutcome::Completed` replays the first caller's stored response to the second
> (`:1178-1199`). The response cache does *not* have this defect: `caller_principal` (`:1140-1142`)
> already falls back to `VerifiedIdentity::stable_actor_id`. The fix is for `identity_suffix` to
> adopt the same fallback chain, twelve lines away. SUB.4 `:125-128` independently decided the
> binding belongs *inside* the derivation rather than at the call site — the same conclusion, and
> the place to implement it.
>
> These are **two prerequisites, not one.** Moving the binding into `derive_key` relocates
> `identity_suffix`; it does not make it non-empty. With identity propagation off — the shipped
> default — the relocated suffix is still empty and two authenticated callers still share a
> fingerprint. SUB.4 needs the fallback chain AND the relocation; satisfying only the second closes
> the ADR-008 finding while leaving the replay.

Dormant while the cache is unreachable, live the moment SUB.4 wires it on. Fixing it here would
repair a path nothing reaches, in a change whose remaining scope is Change A.

### Alternatives rejected

- **Repair Design B to match SUB.4** (mandatory, both routes, `_meta` carrier). Rejected: that is
  SUB.4's design, and writing it twice produces two documents that must agree forever.
- **Keep the builder plumbing here and leave activation to SUB.4.** Rejected: a builder method with
  no caller is the exact defect this document opened by describing. Plumbing that nothing switches
  on is `enable_idempotency` again, one layer out.
- **Supersede SUB.4.** Available and rejected: its activation and carrier decisions are the
  operator's, recorded with the options that were put and the reasons the others lost. Overruling
  them is the requester's call, in one line, not this document's.

### Risks retired with the section

R3 (`MAX_ENTRIES` becoming a live 503 path), R4 (loose key reuse getting 409 `Mismatch`) and R5
(unverifiable identity leaving an unbound key) were risks *of activating the cache*. Nothing here
activates it, so none of them is this change's. R4 and R5 are restated in the transfer above,
because they are SUB.4's the moment it activates; R3 is a capacity policy SUB.4 already re-decided
at source (`:181`, bound 10 000, fail closed).

## §P1 scheduled open questions

Each is resolved by a recorded ANSWER or carries the four deferral fields. None is deferred.

| # | question | state |
|---|---|---|
| U1 | Is any past-deadline exchange dispatchable today? | **resolved** — checkable — read `src/protocol/continuation.rs:495-515` and `src/gateway/meta_mcp/invoke.rs:540-620` — `keyring().open` refuses `Expired` at `:509` and is called at `invoke.rs:546`, before `route` at `:584`; the hold deadline is the same `expiry_for(now)` (`:864`) — **changed the design**: A became a lifetime/observability repair, not a dispatch repair, so its failing test asserts on `len`/`route` under a driven clock rather than on a dispatched retry. |
| U2 | Does MRTR.10a own the idempotency-vs-confirmation ordering? | **resolved** — checkable — read `src/gateway/destructive_confirmation.rs:160-220` and `src/gateway/meta_mcp_tool_defs.rs:135-160,254-262` — the gate governs only meta-tools annotated `destructiveHint: true`, `gateway_invoke` is annotated false, backend tools are never in the set — **changed the design**: the ordering left this document's scope and stays with the destructive-confirmation slice. |
| U3 | Does the idempotency key carry single-use semantics? | **resolved** — checkable — read `src/idempotency.rs:547-600` — `enforce` replays `CachedResult` on `Completed` and refuses only `InFlight`/`Mismatch` — **changed the design**: recorded explicitly in Problem B, because a stateless-confirmation option elsewhere was about to hang single-use on this key. |
| U4 | Default ON or OFF for `idempotency.enabled`, **and does a default-OFF wiring satisfy MRTR.10a's acceptance**? | **resolved — askable, and the answer already existed** — asked of the team lead 2026-09-06 and widened the same day; before it returned, review pointed at `docs/design/2026-08-31-sub-4-idempotency-wiring.md`, where the operator had already answered both halves on 2026-08-31: there is no `enabled` key to give a default to (activation is mandatory, `:137-143`), and reachable-but-off does not satisfy a MUST (`:139-142`, in terms) — **changed the design**: Change B was withdrawn rather than defaulted, and `:143` is not edited by this change at all. The question was not merely deferred to the wrong owner; it was answered before it was asked, in a document this design had not read. |

The deferral table U4 carried is deleted with the deferral. What replaces it is a check that
should have run first: **before deferring a question about a criterion, search the design corpus
for a slice that already owns it.** `rg -l 'idempotency' docs/design/` returns SUB.4 in one call.
This design ran that search against `src/` and not against `docs/design/`, which is how it spent a
round designing an answer the operator had already given.

## §P4 review record

| round | leg | vendor | verdict | evidence |
|---|---|---|---|---|
| 1 | 1 | Kimi K3 (`synthetic-review`) | SHIP-WITH-FIXES | `~/.claude/data/reviews/runs/synthetic-20260906T065936Z-43480.md`, rc=0 |
| 1 | 2 | Grok (`grok-review`) | SHIP-WITH-FIXES | `~/.claude/data/reviews/runs/grok-20260906T065932Z-42426.md`, rc=0 |
| 2 | 1 | Kimi K3 | SHIP-WITH-FIXES | `~/.claude/data/reviews/runs/synthetic-20260906T072511Z-35490.md`, rc=0 — K1-K4 all **CLOSED**; one new finding on the repair |
| 2 | 2 | Grok | **SHIP** | `~/.claude/data/reviews/runs/grok-20260906T072510Z-35222.md`, rc=0 — F1 and F2 **CLOSED**, no new finding |
| 1-2 | — | Codex/GPT (`gpt-review`) | **MISSING** | rc=0 but no verdict and no run file: `ERROR: You've hit your usage limit … try again at Sep 12th, 2026`. Per §PA a nonzero-or-absent row is `MISSING`, never a scraped verdict |

**Stated deviation.** The shared pair for a Claude-authored change is `gpt-review` + `grok-review`.
Codex is usage-limited until 2026-09-12, so leg 1 is Kimi. This is a substitution recorded before
ratification rather than discovered at it; `ratify` requires a SHIP from each vendor and will read
these rows, not this paragraph.

**Round 1, Kimi.** Incorporated: the caller-binding hole in the idempotency key (verified at
source), the freshness precondition on Design A's elimination claim, the widened U4 ask, the real
`IN_FLIGHT_CAPACITY` value, and three test-plan constraints. The `#[cfg(test)]` clock improvement
was rejected with its reason in Alternatives. The startup-log-when-disabled improvement is
**moot, not dropped**: it applied to Change B's config section, which no longer exists — if SUB.4
wants that signal it is SUB.4's to want. One finding **died at source**: nothing supports the
*response*-cache half of the cross-principal claim — `caller_principal` already carries the
verified-subject fallback (`invoke.rs:1140-1142`); only the idempotency key was unbound. No round
spent on it.

**Round 1, Grok.** Two findings, both HIGH, opposite fates:

| finding | source verification | outcome |
|---|---|---|
| F1 — Change B's kill switch contradicts SUB.4, which decided activation is mandatory and coverage is both routes | **CONFIRMED**, and worse than stated: SUB.4 also rejects automatic derivation by name as defect P2, which is the path Change B would have switched on | Change B **withdrawn**. The single most valuable finding of either round: it removed a change rather than repairing one |
| F2 — lazy reclaim-on-next-lock is not an elimination, *and* rejecting the reaper silently reverses PERF.3's accepted reclamation | first half **CONFIRMED** → recorded as R2a. Second half **died at source**: `2026-09-01-nfr-perf3-reclamation.md:375-388` is a same-day correction by that document's own author, withdrawing its reaper and its interval task explicitly in favour of *this* design's `guard(now)` — "reclamation on a clock is then reclamation nobody has to schedule" | half repaired, half closed with no round spent |

The PERF.3 correction also **transfers an obligation inbound**, recorded here so it is not lost:
its earliest-deadline guard on `hold` moves to this slice, raised against Design A on the grounds
that reclaim-on-every-read makes an unguarded capacity walk *more* frequent, not less
(`:375-388`). Change A's test plan carries it.

**Round 2 — closure re-check.** Per the repair protocol, each vendor re-checked only the findings
it raised, under the narrow closure mandate.

Grok returned **SHIP**: F1 cannot be restated once Change B is deleted (it judged the withdrawal a
re-assignment to a live blocker, not a dropped requirement needing recorded agreement), and F2's
overclaim is now R2a with the reaper half dead at source. It raised no finding and three
improvements, all three applied: distinguish the two SUB.4 activation prerequisites (the fallback
chain is not the relocation); stop calling the transferred-in PERF.3 obligation an
"earliest-deadline guard" when what this design accepted is *admit-when-expired plus a bounded
walk*; and drop the absent-section negative from the SUB.4 transfer, because SUB.4 has no optional
section for it to be absent from.

Kimi returned **SHIP-WITH-FIXES**, closing K1-K4 and raising one finding on the repair itself: the
SUB.4 transfer, now the sole vehicle carrying K1 and K3, existed only as an assertion in the
sending document. Repaired by citing the artifact. Its two improvements — the freshness qualifier
inside the elimination self-test, and an enumeration of `len`'s callers now that it mutates — are
applied above.

**One finding neither vendor raised, found in the confirmation pass** and repaired here: the
message id was the *only* record of the transfer, and a message id resolves to a session
transcript. A prerequisite recorded where nobody will look is the inertness the withdrawal
diagnoses, one level up. The durable record is now a cluster-C note in
`RELEASE-4.0.0-blocking-rollup.md`; the message stays as the notification, not as the evidence.

**Provenance note, recorded because the repair protocol requires a commit per finding and this
change did not get one.** The three round-2 repair commits were written but never landed as
themselves: a concurrent session in this shared checkout ran `git commit` against the shared index
while these files were staged, so all three diffs were swept into `38db0dff`
("docs(otel.1): eliminate the second copy of the source correction") and one rollup hunk into
`498fc415`. The content is intact and on the branch; only the attribution is wrong, and history is
not being rewritten to fix it while another session is committing to the same branch. Later commits
here use `git commit -- <path>`, which ignores the index.

**One defect in the test plan, found in the same pass**, before either vendor saw the plan: C1 was
written as "deadline at or before the supplied `now`" while `reclaim_abandoned` retains on
`now <= *deadline` (`continuation.rs:676`) — the two disagree at `deadline == now`, and no row sat
on that boundary, so the plan could not have caught its own ambiguity. C1 restated to the source
predicate and row .04a added.

### §P2 plan review — the test plan, revision 1

A separate review of a separate artifact (`docs/design/2026-09-06-mrtr-8b-lifetime-test-plan.md`),
recorded here because this is where a verdict lives. **Not** a third design round: the design was
supplied as context only and neither leg was asked to re-review it.

| leg | vendor | verdict | evidence |
|---|---|---|---|
| 1 | Kimi K3 (`kimi-review`) | SHIP-WITH-FIXES | `~/.claude/data/reviews/runs/synthetic-20260906T073535Z-21028.md`, rc=0 |
| 2 | Grok (`grok-review`) | SHIP-WITH-FIXES | `~/.claude/data/reviews/runs/grok-20260906T073535Z-20881.md`, rc=0 |
| — | Codex/GPT (`gpt-review`) | **MISSING** | still usage-limited until 2026-09-12; same deviation as the design rounds above |

**Q1 compliance, stated rather than assumed.** §P2 requires a plan review to answer both its
questions, and an unanswered Q1 is not compliant. Grok answered both: it audited the clause map
directly (its C2 finding on row .06 and its re-mapping of .09) as well as falsifiability. Kimi
answered Q2 only — its three findings are all falsifiability, and it never states whether every
clause has a case. **Kimi's leg is recorded as Q2-only**; Q1 rests on Grok's leg alone, which is one
vendor, not two. Recording that is cheaper than pretending a SHIP-WITH-FIXES verdict covered a
question nobody asked.

**Both vendors independently found the same two defects**, which is the strongest signal either
produced: row .11 could not fail for the reason it named (the envelope refuses before the retry path
reaches the table), and row .07's named falsifier — a `guard` reading the wall clock — was
unreachable from its own real-clock fixture. Both rows were eliminated or re-anchored rather than
patched, per the repair protocol's default on a test-plan finding.

Disposition of every finding, in the plan's own commits (`0cdd280b`, `a0e88234`, `ea2723b6`,
`4f4bc869`):

| finding | vendor | disposal |
|---|---|---|
| .11 cannot fail — envelope refuses first | both | row DELETED; the consequence promoted to this design (capacity, not routing) |
| .07's falsifier unreachable from its fixture | both | fixture re-anchored to a synthetic epoch T = 1_000; every row now shares it |
| .10 pins a walk length no reader can observe | grok | row DELETED; the 4_096 bound pinned by a literal assertion instead |
| .06 mis-mapped to C2 / green anyway | grok | **REFUSED at source**: .06's second half — residency ends at the first `guard` — is precisely what the pass-through does not do, so .06 fails on its assertion. Its C2 mapping stands |
| the never-RED enumeration miscounts | kimi | recounted to four with a mechanical membership rule; `.06` moved to the honest-RED list |
| V/I/A marks absent | kimi | evidence block added; boundary predicate and envelope ordering marked **V**, single-file reads **I** |
| `tests/mik_7212_acs.rs` wrongly excluded | grok | **CONFIRMED at source**: `mod inflight` at `:434` holds MRTR.8's own cases at `:491`/`:509`; revision 1 grepped `in_flight` and the module is `inflight`. Both suites now named as call sites to update |
| identity on .04/.04a, table-driven .05, capacity 4 on .08/.09, .09 → C2 | grok | all four adopted |

## §P4a documentation delta

- `docs/requirements/RELEASE-4.0.0-criteria-status.md:140` — MRTR.8b PARTIAL, and its note asserts
  a dispatch defect U1 disproved. Both the status and the note change with Change A.
- `docs/requirements/RELEASE-4.0.0-criteria-status.md:143` — MRTR.10a UNWIRED. **Not edited by this
  change.** With Change B withdrawn nothing here makes the row untrue; it closes when SUB.4 lands.
  The earlier revision made this edit conditional on U4; the answer that arrived removes the
  condition and the edit together.
- Operator config reference — **no delta.** The `idempotency:` section went with Change B.
- Release notes — **no delta.** R4's behaviour change belongs to whichever change activates the
  cache, and that is SUB.4.
- `docs/requirements/RELEASE-4.0.0-blocking-rollup.md:26` — cluster C names SUB.4 without the
  activation prerequisite this change hands it. **Updated by this change**: a cluster-C note
  records the caller-binding prerequisite, with this document as provenance. That note, not the
  team-lead message, is the durable artifact — a message id resolves to a transcript, and the next
  SUB.4 implementer greps the repository.
- `docs/requirements/RELEASE-4.0.0-execution-plan.md:206` — step 8 orders SUB.4's activation.
  **No delta.** The prerequisite constrains what step 8 must contain, not where it sits.
- `docs/design/2026-08-30-shared-continuation-state.md:116` is cited by `route`'s doc comment and
  stays true: nothing here touches the no-affinity bargain.
- This document's own filename still names MRTR.10a and idempotency wiring. **Kept deliberately**:
  `2026-09-01-nfr-perf3-reclamation.md:375` cites it by path, and renaming a file to tidy a title
  breaks a live citation to save nothing. The title line carries the withdrawal instead.

## Test plan

Follows as a separate document, one row per clause, before any test code is written. With Change B
withdrawn the plan covers Change A only, and three constraints are settled here rather than left to
it:

- **Change A's rows assert on `len` and `route` under a driven clock**, per U1 — not on a
  dispatched retry, which U1 showed cannot happen.
- **A case for R2a's bargain**: after a deadline passes with no intervening call, the entry is
  still resident; the first call through `guard` is what makes it gone. The test states the bound
  the design actually delivers, so a future reader cannot mistake it for an absolute one.
- **A case for what PERF.3's reclamation obligation actually became here**: `hold` at capacity,
  with expired entries present, admits rather than refuses — and the walk it does is bounded by
  `IN_FLIGHT_CAPACITY`, not by anything a client sizes.

Two of the three constraints the previous revision recorded for Change B (production-builder
construction, a cross-principal binding case) are **not deleted, they are transferred**: the first
is SUB.4's activation test, the second travels with the caller-binding prerequisite above. The
third — an absent-section negative — is transferred NOWHERE, and that is the correct disposal, not
an oversight: SUB.4 has no optional `idempotency.enabled` section, so a test asserting behaviour
when the section is absent could only be implemented there by reintroducing the kill switch the
withdrawal removed. A test plan for a withdrawn change would be the duplicate this
withdrawal exists to avoid.

### The transfer is a request, not a note (BLOCKING for this document's closure)

Four items leave this document for SUB.4: the caller-binding prerequisite on the idempotency key,
R4 and R5, and the three constraints above. **Recorded only here, they are inert** — SUB.4's author
has no reason to re-read a design that withdrew its own change. So this withdrawal is handed to the
team lead as an explicit transfer request naming the four, and is not closed until SUB.4 carries
them or the lead reassigns them.

The request is an artifact, not an intention: message `127f088c-c180-473a-aeed-1d34347d75fd` to
`team-lead`, 2026-09-06, naming all four items, the withdrawal, and the operator answer that forces
it. Round 2 raised exactly this — a hand-off asserted in the sending document has the same inertness
the withdrawal diagnoses — so the identifier is here rather than in a session transcript nobody
will re-read.

Transfer target liveness, checked rather than assumed: SUB.4 is `proposed, revision 4, no code`,
but it is not stalled — it is a named blocker in cluster C of
`docs/requirements/RELEASE-4.0.0-blocking-rollup.md:26` and holds a position in step 8 of
`docs/requirements/RELEASE-4.0.0-execution-plan.md:206`. A criterion moved to an unowned document
would be a narrowing of scope needing the requester's recorded agreement; a criterion moved to a
release blocker with a plan position is a re-assignment. That distinction is why the check was
run.
